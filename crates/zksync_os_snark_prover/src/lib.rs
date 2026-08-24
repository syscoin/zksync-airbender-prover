use anyhow::Context as _;
use protocol_version::{ProgramCommitment, SupportedProtocolVersions};
use std::time::{Duration, Instant};
use std::{
    fs::File,
    io::Write as _,
    path::{Path, PathBuf},
};
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use zkos_wrapper::{
    calculate_verification_key_hash, CompressionProof, SnarkWrapper, SnarkWrapperConfig,
    SnarkWrapperHostCache, SnarkWrapperProof,
};
#[cfg(not(feature = "gpu"))]
use zksync_airbender_cli::prover_utils::CpuConfig;
#[cfg(feature = "gpu")]
use zksync_airbender_cli::prover_utils::GpuConfig;
use zksync_airbender_cli::prover_utils::{
    CarriedChainCombiner, ProgramSource, ProofArtifact, ProofCounts, ProofTarget, ProofTimingsMs,
    ProverBackend, SecurityLevel,
};
use zksync_airbender_execution_utils::unrolled::UnrolledProgramProof;
use zksync_sequencer_proof_client::{
    error_follows_job_acquisition, ordered_client_indices, JobQueueStage, ProofClient,
    ProofRunOutcome, SnarkProofInputs, MAX_FRIS_PER_SNARK_JOB, STATUS_PROBE_CONCURRENCY,
};

use crate::metrics::{SnarkProofTimeStats, SnarkStage, SNARK_PROVER_METRICS};

pub mod metrics;

// SYSCOIN: Stock Airbender's canonical combine/wrap path requires a real multi-proof range.
const MIN_FRIS_PER_REAL_SNARK: usize = 2;

fn ensure_real_snark_proof_count(proof_count: usize) -> anyhow::Result<()> {
    anyhow::ensure!(
        (MIN_FRIS_PER_REAL_SNARK..=MAX_FRIS_PER_SNARK_JOB).contains(&proof_count),
        "real SNARK jobs require {MIN_FRIS_PER_REAL_SNARK}..={MAX_FRIS_PER_SNARK_JOB} FRI proofs; got {proof_count}"
    );
    Ok(())
}

pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    FmtSubscriber::builder().with_env_filter(filter).init();
}

/// SYSCOIN: Lazily materialized SNARK wrapper state shared by standalone and combined services.
///
/// The FRI-proof combiner sizes its GPU pool from essentially all free VRAM. The wrapper
/// therefore must not be resident while a range is merged, even in the standalone SNARK
/// process. Each job constructs the wrapper after merging, then retires it back into the
/// host-only cache below. This is the single canonical lifecycle for every deployment.
pub struct WrapperSource {
    trusted_setup_file: String,
    /// App binary whose commitment is bound into the wrapper VK via `check_aux_params`.
    app_bin_path: PathBuf,
    /// Setup caches carried between jobs. Validated construction populates this before polling;
    /// it is temporarily `None` only while one job owns the materialized wrapper.
    /// The cache holds no GPU memory (see [`SnarkWrapperHostCache`]).
    host_cache: Option<Box<SnarkWrapperHostCache>>,
}

impl WrapperSource {
    /// SYSCOIN: Initialize and authenticate a worker's app-bound wrapper before its
    /// first queue claim. The final VK commits to `app_bin_path` through `check_aux_params`, so an
    /// exact supported-VK match proves that the configured program commitment is registered by
    /// [`SupportedProtocolVersions`]. Retiring the initialized wrapper into its host-only cache
    /// prevents this pre-lease gate from repeating the expensive setup on the first job.
    pub fn new_validated(
        trusted_setup_file: String,
        app_bin_path: PathBuf,
        supported_versions: &SupportedProtocolVersions,
    ) -> anyhow::Result<Self> {
        let mut wrapper = create_snark_wrapper(trusted_setup_file.clone(), &app_bin_path)
            .context("initialize app-bound SNARK wrapper before queue polling")?;
        let vk_hash = format!(
            "{:?}",
            calculate_verification_key_hash(
                wrapper
                    .snark_vk()
                    .context("derive app-bound SNARK VK before queue polling")?
                    .clone(),
            )
        );
        ensure_supported_wrapper_vk(&vk_hash, &app_bin_path, supported_versions)?;

        Ok(Self {
            trusted_setup_file,
            app_bin_path,
            host_cache: Some(Box::new(wrapper.into_host_cache())),
        })
    }
}

// SYSCOIN: Keep the actual wrapper VK (and therefore its `check_aux_params` app commitment) in
// lockstep with the exact versions advertised to the sequencer before a lease can be acquired.
fn ensure_supported_wrapper_vk(
    vk_hash: &str,
    app_bin_path: &Path,
    supported_versions: &SupportedProtocolVersions,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        supported_versions.contains(vk_hash),
        "configured app {app_bin_path:?} produces SNARK VK hash {vk_hash}, which is not registered by any supported protocol version"
    );
    Ok(())
}

/// SYSCOIN: Build the app-bound SNARK wrapper session used for proving and VK generation.
///
/// The wrapper runs with `check_aux_params` enabled, which binds the app program into the
/// verification key: the RISC-wrapper circuit constrains the FRI proof's final registers
/// 18..=25 (the blake2s recursion-chain commitment of the app binary) to the `aux_params`
/// derived from `app_bin_path`, and takes the settlement public input directly from
/// registers 10..=16. A FRI proof of any other program then fails the in-circuit check
/// instead of producing a wrappable proof, so a wrong-program proof can no longer be
/// wrapped into a valid SNARK.
///
/// Because the commitment is a circuit constant, the VK is app-specific: it must be
/// regenerated — and the new hash re-registered on L1 and re-published by the sequencer —
/// whenever the app binary changes.
pub fn create_snark_wrapper(
    trusted_setup_file: String,
    app_bin_path: &Path,
) -> anyhow::Result<SnarkWrapper> {
    create_snark_wrapper_with_cache(trusted_setup_file, app_bin_path, None)
}

/// Like [`create_snark_wrapper`], but adopt the setup caches of a retired wrapper
/// (see [`SnarkWrapper::into_host_cache`]) so the chain derivation is skipped.
///
/// The cache carries the retired session's whole configuration, including its trusted
/// setup path and bound app binary, so `trusted_setup_file` and `app_bin_path` only apply
/// to cache-less (first) builds.
pub fn create_snark_wrapper_with_cache(
    trusted_setup_file: String,
    app_bin_path: &Path,
    host_cache: Option<SnarkWrapperHostCache>,
) -> anyhow::Result<SnarkWrapper> {
    #[cfg_attr(not(feature = "gpu"), allow(unused_mut))]
    let mut wrapper = match host_cache {
        Some(cache) => SnarkWrapper::from_host_cache(cache)?,
        None => SnarkWrapper::new(build_wrapper_config(trusted_setup_file, app_bin_path)?)?,
    };

    // Mirror the old eager GPU precomputation: derive the full VK/setup chain up front so
    // that setup problems surface at startup rather than on the first picked job (and the
    // startup-time metric keeps its meaning). Skipped on CPU, as before. With a warm
    // host cache this returns the cached VK and derives nothing.
    #[cfg(feature = "gpu")]
    {
        tracing::info!("Computing SNARK precomputations");
        wrapper.snark_vk()?;
        tracing::info!("Finished computing SNARK precomputations");
    }

    Ok(wrapper)
}

/// SYSCOIN: Build the wrapper config that binds the app program at `app_bin_path` into the VK via
/// `check_aux_params`.
///
/// The `.text` section path is derived from the `.bin` path exactly as the FRI prover does
/// ([`ProgramSource::from_paths`]), so the `aux_params` the wrapper bakes in are computed
/// over the same binary the FRI proof executed and match the commitment it carries in
/// registers 18..=25.
fn build_wrapper_config(
    trusted_setup_file: String,
    app_bin_path: &Path,
) -> anyhow::Result<SnarkWrapperConfig> {
    let bin_path = app_bin_path
        .to_str()
        .with_context(|| format!("non-UTF8 app binary path {app_bin_path:?}"))?
        .to_string();
    let source = ProgramSource::from_paths(bin_path, None);
    // Fail fast on a missing binary/text instead of erroring deep in VK derivation.
    for path in [&source.bin_path, &source.text_path] {
        anyhow::ensure!(Path::new(path).is_file(), "program file not found: {path}");
    }
    Ok(SnarkWrapperConfig {
        trusted_setup: Some(trusted_setup_file.into()),
        bin: Some(source.bin_path.into()),
        text: Some(source.text_path.into()),
        check_aux_params: true,
        ..Default::default()
    })
}

/// SYSCOIN: The app-program chain commitment a FRI proof (combined multi-batch ones included)
/// carries in its final registers 18..=25 — the value the settlement side checks the
/// SNARK public input against. NOT the proof's `recursion_chain_hash`, which is the
/// prover-internal layer chain and varies with the number of unified passes.
fn carried_program_commitment(proof: &UnrolledProgramProof) -> ProgramCommitment {
    let mut words = [0u32; 8];
    for (i, word) in words.iter_mut().enumerate() {
        *word = proof.register_final_values[18 + i].value;
    }
    ProgramCommitment(words)
}

/// SYSCOIN: End params of the active security level's unified-recursion verifier binary, needed
/// to continue a carried chain the way the next unified pass would. Derived once per
/// process (one unified-layer setup computation on the host).
fn unified_verifier_end_params() -> &'static [u32; 8] {
    static EP: std::sync::OnceLock<[u32; 8]> = std::sync::OnceLock::new();
    EP.get_or_init(|| zkos_wrapper::circuits::BinaryCommitment::default().end_params)
}

/// SYSCOIN: The program commitment this proof's verification OUTPUTS: its carried chain continued
/// with the unified verifier's end params unless it already ends there — the same
/// carry-or-continue rule `CarriedChainCombiner::combine` applies. A proof that converged
/// on its first unified pass carries only the unrolled-level chain in registers 18..=25,
/// one fold short of the recorded per-version commitment; a merged proof (or one that took
/// a second unified pass) carries the full chain. Falls back to the raw carried value when
/// the proof has no chain pair or it disagrees with the registers (the merge validates and
/// rejects such proofs properly).
fn output_program_commitment(proof: &UnrolledProgramProof) -> ProgramCommitment {
    let carried = carried_program_commitment(proof);
    let (Some(hash), Some(preimage)) = (proof.recursion_chain_hash, proof.recursion_chain_preimage)
    else {
        return carried;
    };
    if hash != carried.0 {
        return carried;
    }
    let (continued, _) =
        zksync_airbender_execution_utils::unrolled::UnrolledProgramSetup::continue_recursion_chain(
            unified_verifier_end_params(),
            &hash,
            &preimage,
        );
    ProgramCommitment(continued)
}

/// SYSCOIN: Build the FRI-proof combiner used by [`merge_fris`] for multi-proof jobs.
///
/// The combiner caches everything that survives across jobs — the unified recursion
/// program's setup data and, on `gpu` builds, the GPU prover's host state (pinned host
/// memory pools and circuit precomputations). Construct it once per process next to the
/// SNARK wrapper; per job only the CUDA contexts and device memory pool are created and
/// they are released when the merge finishes, so the GPU is free for the wrap phases.
///
/// The caches build lazily on the first multi-proof job; call
/// [`CarriedChainCombiner::warm_up`] to pay that cost at startup instead. Note the GPU
/// host state pins tens of gigabytes of host RAM for the lifetime of the combiner.
pub fn create_combiner() -> CarriedChainCombiner {
    // Must match the level the FRI prover proves at - the level selects the recursion
    // verifier binaries, so a mismatch produces proofs the combine cannot verify. Both
    // map the same per-version record, so they cannot drift apart.
    let security_level = proving_security_level();
    #[cfg(feature = "gpu")]
    {
        CarriedChainCombiner::new_gpu(security_level, GpuConfig::default())
    }
    #[cfg(not(feature = "gpu"))]
    {
        CarriedChainCombiner::new_cpu(security_level, CpuConfig::default())
    }
}

/// The level this process proves at, from the supported protocol versions' record,
/// mapped to airbender's type — the same mapping `zksync_os_fri_prover` applies (kept
/// as two four-line matches rather than a crate dependency between the two provers).
/// Errors if no supported version records a level.
// SYSCOIN: A fresh V32 deployment supports exactly one Security100 proving lane.
fn proving_security_level() -> SecurityLevel {
    match SupportedProtocolVersions::default().proving_security_level() {
        protocol_version::SecurityLevel::Security100 => SecurityLevel::Security100,
    }
}

/// SYSCOIN: Merge the job's FRI proofs into the single unified-layer proof the SNARK wrapper expects.
///
/// Multi-proof jobs are combined via airbender's combined-recursion-layers flow:
/// every input proof is verified against the recursion chain it carries (all proofs of a
/// job must resolve to one chain), the combined statement is proved with the unified-layer
/// recursion
/// program and shrunk back to a converged unified-layer proof whose output words 0..8 are
/// the keccak rolling hash of the batch outputs (words 8..16 carry the shared recursion
/// chain through unchanged). This keeps the SNARK prover detached from the app binary:
/// the chain is bound to the expected program by the downstream verifier of the wrapped
/// proof, not by local files. On `gpu` builds the unified-layer proving passes run on the
/// GPU; verification and witness building stay on the host either way.
pub fn merge_fris(
    snark_proof_input: SnarkProofInputs,
    combiner: &mut CarriedChainCombiner,
) -> anyhow::Result<UnrolledProgramProof> {
    SNARK_PROVER_METRICS
        .fri_proofs_merged
        .set(snark_proof_input.fri_proofs.len() as i64);

    let SnarkProofInputs {
        from_batch_number,
        to_batch_number,
        fri_proofs,
        ..
    } = snark_proof_input;

    ensure_real_snark_proof_count(fri_proofs.len()).with_context(|| {
        format!("invalid server range for batches {from_batch_number} to {to_batch_number}")
    })?;

    tracing::info!(
        "Combining {} FRI proofs for batches {from_batch_number} to {to_batch_number} into one",
        fri_proofs.len()
    );

    let security_level = combiner.security_level();

    // The sequencer sends bare proofs; wrap them into the artifact form the combine
    // expects. The program keccaks are informational metadata (the proofs are bound to
    // their program by the recursion chain they carry, not by these fields), and the
    // producing program's files are unknown here.
    let (program_bin_keccak, program_text_keccak) = ([0u8; 32], [0u8; 32]);
    let artifacts: Vec<ProofArtifact> = fri_proofs
        .into_iter()
        .enumerate()
        .map(|(i, proof)| {
            let (family, inits_and_teardowns, delegation) = proof.get_proof_counts();
            ProofArtifact {
                schema_version: 1,
                security_level,
                target: ProofTarget::RecursionUnified,
                // The fields below are informational: the producing backend, cycle count
                // and timings of a sequencer-supplied proof are unknown here.
                backend: ProverBackend::Cpu,
                batch_id: from_batch_number.0 as u64 + i as u64,
                cycles: 0,
                program_bin_keccak,
                program_text_keccak,
                timings_ms: ProofTimingsMs::default(),
                proof_counts: ProofCounts {
                    family_proof_count: family,
                    inits_and_teardowns_proof_count: inits_and_teardowns,
                    delegation_proof_count: delegation,
                    delegation_proof_count_by_type: Vec::new(),
                },
                proof,
            }
        })
        .collect();

    // First multi-proof job on a cold combiner also builds its caches; measure that
    // separately so per-job pass timings stay comparable across jobs.
    let warm_up_started_at = Instant::now();
    combiner.warm_up();
    let warm_up = warm_up_started_at.elapsed();
    if warm_up > Duration::from_millis(100) {
        tracing::info!("Combiner warm-up took {warm_up:?}");
        SNARK_PROVER_METRICS
            .time_taken_merge_warm_up
            .observe(warm_up.as_secs_f64());
    }

    let combined = combiner.combine(&artifacts).map_err(|e| {
        anyhow::anyhow!(
            "failed to combine FRI proofs for batches {from_batch_number} to \
             {to_batch_number}: {e}"
        )
    })?;

    let pass_ms = &combined.timings_ms.unified_recursion_ms;
    tracing::info!(
        "Combined {} FRI proofs in {} unified proving passes ({:?} ms per pass, {} ms total)",
        artifacts.len(),
        pass_ms.len(),
        pass_ms,
        pass_ms.iter().sum::<u64>(),
    );
    SNARK_PROVER_METRICS
        .merge_unified_passes
        .set(pass_ms.len() as i64);

    Ok(combined.proof)
}

/// SYSCOIN: Run the dedicated wrapper lane while retaining exact aggregate authority across
/// retries and honoring cooperative shutdown only at durable ownership boundaries.
pub async fn run_linking_fri_snark(
    clients: Vec<Box<dyn ProofClient + Send + Sync>>,
    output_dir: String,
    trusted_setup_file: String,
    app_bin_path: PathBuf,
    iterations: Option<usize>,
    disable_zk: bool,
    mut stop_receiver: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let startup_started_at = Instant::now();

    tracing::info!(
        "Initializing SNARK prover with {} sequencer(s):",
        clients.len()
    );
    for client in clients.iter() {
        tracing::info!("  - {}", client.sequencer_url());
    }

    let supported_versions = SupportedProtocolVersions::default();
    // SYSCOIN: Refuse to prove before the generated app-bound VK replaces the sentinel.
    supported_versions
        .ensure_syscoin_release_constants()
        .map_err(anyhow::Error::msg)?;
    tracing::info!("{:#?}", supported_versions);

    // SYSCOIN: Authenticate the configured app-bound wrapper and retain its setup cache before
    // the polling loop below can acquire any SNARK lease.
    let mut wrapper_source =
        WrapperSource::new_validated(trusted_setup_file, app_bin_path, &supported_versions)?;

    // SYSCOIN: Warm the combiner eagerly, mirroring the SNARK precomputation above: setup
    // problems surface at startup and the first multi-proof job doesn't pay for it.
    let mut combiner = create_combiner();
    combiner.warm_up();

    SNARK_PROVER_METRICS
        .time_taken_startup
        .observe(startup_started_at.elapsed().as_secs_f64());

    let mut proof_count = 0;

    // SYSCOIN: Probe all configured sequencers while allowing cooperative shutdown between jobs.
    loop {
        if *stop_receiver.borrow() {
            tracing::info!("SNARK prover stop requested between jobs");
            return Ok(());
        }
        // SYSCOIN: Retained auth/path/redirect/config envelopes must resolve or fail startup/run;
        // never hide them behind continued queue polling or a newly acquired proving lease.
        zksync_sequencer_proof_client::resume_pending_submissions(&clients)
            .await
            .context("durable submission replay blocks new SNARK picks")?;

        let mut proof_generated = false;
        let client_order =
            ordered_client_indices(&clients, JobQueueStage::Snark, STATUS_PROBE_CONCURRENCY).await;
        for client_idx in client_order {
            if *stop_receiver.borrow() {
                tracing::info!("SNARK prover stop requested before claiming another job");
                return Ok(());
            }
            let client = &clients[client_idx];
            tracing::debug!("Polling sequencer: {}", client.sequencer_url());
            // SYSCOIN: Preserve typed no-job/endpoint outcomes while propagating every acquired-
            // lease or durable-submission error; only a submitted proof advances iterations.
            match run_inner(
                client.as_ref(),
                &mut wrapper_source,
                &mut combiner,
                output_dir.clone(),
                disable_zk,
                &supported_versions,
            )
            .await?
            {
                ProofRunOutcome::ProofSubmitted => {
                    proof_generated = true;
                    break;
                }
                ProofRunOutcome::NoJob | ProofRunOutcome::EndpointUnavailable => {}
            }
        }

        if proof_generated {
            proof_count += 1;

            if let Some(max_proofs_generated) = iterations {
                if proof_count >= max_proofs_generated {
                    tracing::info!(
                        "Reached maximum iterations ({max_proofs_generated}), exiting..."
                    );
                    return Ok(());
                }
            }
        } else {
            // If no task was found, wait before trying again
            tracing::info!("No pending SNARK jobs from sequencer, retrying in 5s...");
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                changed = stop_receiver.changed() => {
                    if changed.is_err() || *stop_receiver.borrow() {
                        tracing::info!("SNARK prover stop requested while polling");
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// SYSCOIN: Return a typed acquisition outcome so endpoint fallback is possible only before a
/// lease exists; every acquired SNARK range remains bound to one combiner/disposition path.
pub async fn run_inner(
    client: &dyn ProofClient,
    wrapper_source: &mut WrapperSource,
    combiner: &mut CarriedChainCombiner,
    output_dir: String,
    disable_zk: bool,
    supported_protocol_versions: &SupportedProtocolVersions,
) -> anyhow::Result<ProofRunOutcome> {
    tracing::debug!("Picking job from sequencer {}", client.sequencer_url());
    let snark_proof_input = match client.pick_snark_job().await {
        Ok(Some(snark_proof_input)) => {
            // SYSCOIN: Fail closed before setup if the server violates the multi-FRI contract.
            if let Err(error) = ensure_real_snark_proof_count(snark_proof_input.fri_proofs.len()) {
                let error = error.context(format!(
                    "sequencer {} returned an invalid real SNARK range for batches [{} to {}]",
                    client.sequencer_url(),
                    snark_proof_input.from_batch_number.0,
                    snark_proof_input.to_batch_number.0,
                ));
                tracing::error!("{error:#}");
                return Err(error);
            }
            if !supported_protocol_versions.contains(&snark_proof_input.vk_hash) {
                // SYSCOIN: A supported-version mismatch follows lease acquisition and is fatal.
                anyhow::bail!(
                    "received unsupported protocol version with vk_hash {} for leased batches [{} and {}] from sequencer {}",
                    snark_proof_input.vk_hash,
                    snark_proof_input.from_batch_number.0,
                    snark_proof_input.to_batch_number.0,
                    client.sequencer_url()
                );
            }
            // SYSCOIN: Reject wrong-program proofs up front with a clear error. The wrapper VK now
            // binds the app program (check_aux_params constrains registers 18..=25 to the
            // version's commitment), so such a proof would otherwise fail deep in wrap
            // proving as an unsatisfiable circuit, after the GPU time is already spent.
            if let Some(expected) =
                supported_protocol_versions.program_commitment_for(&snark_proof_input.vk_hash)
            {
                for (i, proof) in snark_proof_input.fri_proofs.iter().enumerate() {
                    let output = output_program_commitment(proof);
                    if output != expected {
                        // SYSCOIN: Never abandon an exact aggregate lease after validating proofs.
                        anyhow::bail!(
                            "FRI proof {i} of batches [{} to {}] from sequencer {} proves \
                             program commitment {output}, but protocol version {} proves \
                             {expected}",
                            snark_proof_input.from_batch_number.0,
                            snark_proof_input.to_batch_number.0,
                            client.sequencer_url(),
                            snark_proof_input.vk_hash,
                        );
                    }
                }
            }
            snark_proof_input
        }
        Ok(None) => {
            tracing::debug!(
                "No SNARK jobs found from sequencer {}",
                client.sequencer_url()
            );
            return Ok(ProofRunOutcome::NoJob);
        }
        Err(e) => {
            // SYSCOIN: The pick acquired or may have acquired a range lease; endpoint fallback
            // could create two live assignments for this worker.
            if error_follows_job_acquisition(&e) {
                return Err(e).context(
                    "SNARK pick may have acquired a lease; no endpoint fallback is allowed",
                );
            }
            // Check if the error is a timeout error
            if e.downcast_ref::<reqwest::Error>()
                .map(|err| err.is_timeout())
                .unwrap_or(false)
            {
                tracing::error!(
                    "Timeout waiting for response from sequencer {}: {e:?}",
                    client.sequencer_url()
                );
                tracing::error!("Exiting prover due to timeout");
                SNARK_PROVER_METRICS.timeout_errors.inc();
                return Ok(ProofRunOutcome::EndpointUnavailable);
            }
            tracing::error!(
                "Failed to pick SNARK job from sequencer {}: {e:?}",
                client.sequencer_url()
            );
            return Ok(ProofRunOutcome::EndpointUnavailable);
        }
    };
    let start_batch = snark_proof_input.from_batch_number;
    let end_batch = snark_proof_input.to_batch_number;
    let vk_hash = snark_proof_input.vk_hash.clone();
    // SYSCOIN: Preserve the exact-range capability before consuming the picked FRI inputs.
    let lease_token = snark_proof_input.lease_token.clone();
    tracing::info!(
        "Finished picking job from sequencer {} with VK hash {}, will aggregate from {} to {} inclusive",
        client.sequencer_url(),
        vk_hash,
        start_batch,
        end_batch,
    );

    let mut stats = SnarkProofTimeStats::new();

    // A job whose proofs fail to combine would be re-picked forever, so treat merge
    // failures as fatal rather than skipping the job.
    let proof = stats.measure_step(SnarkStage::MergeFri, || {
        merge_fris(snark_proof_input, combiner)
    })?;

    // SYSCOIN: Materialize the wrapper only after the merge: the merge's GPU prover sizes its
    // device pool to all free VRAM, so the wrapper's device-resident state must not
    // be alive yet. With the canonical per-job lifecycle, the wrapper (and any VRAM it touches)
    // lives exactly from here until this job's proving is done; its host-side setup caches
    // carry over from the previous job, so only the first job of the process pays the
    // full setup derivation in the `wrapper_setup` stage.
    tracing::info!("Building per-job SNARK wrapper");
    let cache = wrapper_source.host_cache.take().map(|cache| *cache);
    let mut snark_wrapper = stats.measure_step(SnarkStage::WrapperSetup, || {
        create_snark_wrapper_with_cache(
            wrapper_source.trusted_setup_file.clone(),
            &wrapper_source.app_bin_path,
            cache,
        )
    })?;

    tracing::info!("Wrapping and compressing FRI proof");

    // Proving failures are fatal: silently skipping would re-pick the same job forever, and a
    // failed attempt can leave the wrapper's cached GPU state unusable for the FRI phase of the
    // zksync_os_prover_service service that runs FRI and SNARK on the same process.
    let compression_proof: CompressionProof = stats
        .measure_step(SnarkStage::FinalProof, || {
            let risc_wrapper_proof = snark_wrapper.prove_risc_wrapper(proof)?;
            snark_wrapper.prove_compression(risc_wrapper_proof)
        })
        .map_err(|e| anyhow::anyhow!("failed to wrap/compress FRI proof: {e:?}"))?;

    tracing::info!("SNARKifying proof");
    // note that the API is use_zk, so we invert the disable_zk flag
    let snark_proof: SnarkWrapperProof = stats
        .measure_step(SnarkStage::Snark, || {
            snark_wrapper.prove_snark(compression_proof, !disable_zk)
        })
        .map_err(|e| anyhow::anyhow!("failed to SNARKify proof: {e:?}"))?;
    stats.observe_full();
    tracing::info!("Finished generating proof, time stats: {}", stats);

    // SYSCOIN: The per-job wrapper is done with the GPU; retire it but keep its host-side setup
    // caches so the next job's wrapper build is a cheap rehydration instead of a full
    // re-derivation.
    wrapper_source.host_cache = Some(Box::new(snark_wrapper.into_host_cache()));

    // SYSCOIN: Retain a pure in-memory copy for the historical operator artifact; all fallible
    // serialization and filesystem work stays after the canonical durable submission boundary.
    let snark_proof_path = Path::new(&output_dir).join("snark_proof.json");
    let snark_proof_for_artifact = snark_proof.clone();

    // SYSCOIN: Return the exact aggregate capability with the wrapper generated from its picked
    // FRI set; the client's retry loop keeps these same serialized proof bytes and token together.
    client
        .submit_snark_proof(
            start_batch,
            end_batch,
            vk_hash.clone(),
            snark_proof,
            lease_token,
        )
        .await
        .with_context(|| {
            format!(
                "generated SNARK proof for leased batches {start_batch}-{end_batch} could not reach a definitive manager disposition; no fresh pick is allowed"
            )
        })?;
    // SYSCOIN: A bad output directory must not destroy a generated wrapper before the exact lease
    // is durably resolved. Preserve the historical artifact as best-effort after submit.
    let write_result = serde_json::to_vec_pretty(&snark_proof_for_artifact)
        .context("serialize optional SNARK proof artifact")
        .and_then(|bytes| {
            let mut file = File::create(&snark_proof_path).with_context(|| {
                format!("create optional SNARK proof artifact {snark_proof_path:?}")
            })?;
            file.write_all(&bytes)
                .context("write optional SNARK proof artifact")?;
            file.sync_all()
                .context("fsync optional SNARK proof artifact")
        });
    if let Err(error) = write_result {
        tracing::warn!(
            output_path = ?snark_proof_path,
            "failed to persist optional SNARK proof artifact after submission: {error:#}"
        );
    }
    tracing::info!(
        "Successfully submitted SNARK proof for batches {} to {} with vk hash {} to sequencer {}",
        start_batch,
        end_batch,
        vk_hash,
        client.sequencer_url()
    );

    SNARK_PROVER_METRICS
        .latest_proven_batch
        .set(end_batch.0 as i64);

    Ok(ProofRunOutcome::ProofSubmitted)
}

// SYSCOIN: Lock the stock-Airbender minimum-two range requirement.
#[cfg(test)]
mod tests {
    use std::path::Path;

    use protocol_version::SupportedProtocolVersions;

    use super::{ensure_real_snark_proof_count, ensure_supported_wrapper_vk};

    #[test]
    fn real_snark_range_requires_at_least_two_fris() {
        for count in [0, 1] {
            let error = ensure_real_snark_proof_count(count)
                .expect_err("an empty or singleton real SNARK range must fail closed");
            assert!(error.to_string().contains("2..=100 FRI proofs"));
        }
        for count in [2, 100] {
            ensure_real_snark_proof_count(count)
                .expect("a multi-FRI real SNARK range must be accepted");
        }
        assert!(ensure_real_snark_proof_count(101).is_err());
    }

    // SYSCOIN: Every worker may advertise only the exact app-bound wrapper VK it derived before
    // polling; a different configured app must fail before any SNARK lease can be picked.
    #[test]
    fn wrapper_vk_must_match_supported_protocol_registry() {
        let versions = SupportedProtocolVersions::default();
        let registered = versions
            .vk_hashes()
            .into_iter()
            .next()
            .expect("one canonical protocol version");
        let app_path = Path::new("configured-app.bin");

        ensure_supported_wrapper_vk(&registered, app_path, &versions)
            .expect("the registered app-bound wrapper VK must be accepted");

        let unsupported = format!("0x{}", "ff".repeat(32));
        let error = ensure_supported_wrapper_vk(&unsupported, app_path, &versions)
            .expect_err("a wrapper VK for another app must fail closed");
        let message = error.to_string();
        assert!(message.contains("configured-app.bin"));
        assert!(message.contains("not registered by any supported protocol version"));
    }

    // SYSCOIN: The validated constructor is the sole WrapperSource construction path, so a
    // missing setup must fail before a worker can hold an empty cache and begin queue polling.
    #[test]
    fn validated_wrapper_source_rejects_missing_setup_before_polling() {
        let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let app_path = crate_dir.join("../../multiblock_batch.bin");
        let missing_setup = crate_dir.join("missing-trusted-setup-for-wrapper-source-test.key");
        assert!(!missing_setup.exists(), "test setup path must stay absent");

        let error = match super::WrapperSource::new_validated(
            missing_setup.to_string_lossy().into_owned(),
            app_path,
            &SupportedProtocolVersions::default(),
        ) {
            Ok(_) => panic!("missing trusted setup must fail before polling"),
            Err(error) => error,
        };
        let message = format!("{error:#}");
        assert!(message.contains("initialize app-bound SNARK wrapper before queue polling"));
        assert!(message.contains("trusted setup metadata"));
    }
}
