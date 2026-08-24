use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::Context as _;
use base64::{engine::general_purpose::STANDARD, Engine as _};

use clap::Parser;
use protocol_version::{ProgramCommitment, SupportedProtocolVersions};
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use zksync_airbender_cli::prover_utils::{
    ProgramProver, ProgramProverConfig, ProgramSource, ProofTarget, SecurityLevel,
};
use zksync_airbender_execution_utils::unrolled::UnrolledProgramProof;
use zksync_sequencer_proof_client::{
    error_follows_job_acquisition, ordered_client_indices, parse_configured_sequencer_endpoints,
    resume_pending_submissions, FriJobInputs, JobQueueStage, OpaqueSequencerEndpoint, ProofClient,
    ProofRunOutcome, SequencerProofClient, STATUS_PROBE_CONCURRENCY,
};

use crate::metrics::FRI_PROVER_METRICS;

pub mod metrics;

/// Command-line arguments for the Zksync OS prover
#[derive(Parser, Debug)]
#[command(name = "Zksync OS Prover")]
#[command(version = "1.0")]
#[command(about = "Prover for Zksync OS", long_about = None)]
pub struct Args {
    /// SYSCOIN: Sequencer URL(s) for oldest-unassigned-head scheduling. Comma-separated.
    ///
    /// Format: http[s]://[username:password@]host:port. Do not put credentials on argv; set
    /// `ZKSYNC_SEQUENCER_URLS` from an owner-only secret file instead.
    ///
    /// Credentials are extracted and sent via HTTP Authorization headers.
    #[arg(
        short,
        long,
        alias = "base-url",
        value_delimiter = ',',
        num_args = 1..,
        env = "ZKSYNC_SEQUENCER_URLS",
        hide_env_values = true,
        default_value = "http://localhost:3124"
    )]
    pub sequencer_urls: Vec<OpaqueSequencerEndpoint>,
    /// Path to `app.bin`
    #[arg(long)]
    pub app_bin_path: Option<PathBuf>,
    /// Number of iterations before exiting. Only successfully generated proofs count. If not specified, runs indefinitely
    #[arg(long)]
    pub iterations: Option<usize>,
    /// Path to the output file
    #[arg(short, long)]
    pub path: Option<PathBuf>,

    /// SYSCOIN: Explicit absolute owner-only durable proof/capability spool. Run one worker per
    /// directory; startup fails if another process owns it or the path is relative.
    #[arg(long)]
    pub submission_dir: PathBuf,

    /// SYSCOIN: Explicit isolated-network escape hatch. Production remote sequencers must use HTTPS.
    #[arg(long, default_value_t = false)]
    pub allow_insecure_sequencer_http: bool,

    /// SYSCOIN: Dedicated default metrics port for parallel GPU workers.
    #[arg(long, default_value = "3125")]
    pub prometheus_port: u16,

    /// SYSCOIN: Total HTTP request backstop in seconds. Connect timeout is 5s and
    /// read-inactivity timeout is 10s.
    #[arg(long, default_value = "600")]
    pub request_timeout_secs: u64,

    /// Name of the prover for identification in the sequencer's prover api
    #[arg(long, default_value = "unknown_prover")]
    pub prover_name: String,
}

pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    FmtSubscriber::builder().with_env_filter(filter).init();
}

/// The level this process proves at, from the supported protocol versions' record,
/// mapped to airbender's type. Every stage must agree on it — the FRI prover here, the
/// combiner and the SNARK wrapper in `zksync_os_snark_prover` (which maps the same
/// record) — since it selects the recursion verifier binaries. Errors if no supported
/// version records a level.
// SYSCOIN: A fresh V32 deployment supports exactly one Security100 proving lane.
fn proving_security_level() -> SecurityLevel {
    match SupportedProtocolVersions::default().proving_security_level() {
        protocol_version::SecurityLevel::Security100 => SecurityLevel::Security100,
    }
}

/// Create a new prover for the given program binary.
///
/// The prover holds all precomputed setup data (and, with the `gpu` feature, the GPU
/// context), so it should be constructed once and reused across batches.
pub fn create_prover(binary_path: &Path) -> anyhow::Result<ProgramProver> {
    let source = ProgramSource::from_paths(
        binary_path
            .to_str()
            .with_context(|| format!("non-UTF8 binary path {binary_path:?}"))?
            .to_string(),
        // The matching `.text` section path is derived from the `.bin` path.
        None,
    );
    // Fail fast on a bad path instead of erroring only when the first job is picked.
    for path in [&source.bin_path, &source.text_path] {
        anyhow::ensure!(Path::new(path).is_file(), "program file not found: {path}");
    }
    let config = ProgramProverConfig {
        // Recursion up to the unified layer: the compact form expected by the SNARK wrapper.
        target: ProofTarget::RecursionUnified,
        // The level changes the recursion chain, and so the program commitment and the VK -
        // not a knob that can be flipped independently of those constants.
        // SYSCOIN: The fresh-only registry makes this canonical Security100 selection infallible.
        security_level: proving_security_level(),
        // `gpu` defaults to `GpuMemoryPreset::Auto`: 28 GiB arena, falling back to 21.5 GiB.
        ..Default::default()
    };
    ProgramProver::new(source, config).map_err(|e| anyhow::anyhow!("failed to create prover: {e}"))
}

/// Compute the [`ProgramCommitment`] of the app program at `binary_path` (`.text`
/// sibling derived like [`create_prover`] does).
///
/// Uses zkos-wrapper's own `BinaryCommitment`, so the value is byte-identical to what
/// the wrapper chain enforces — but that recomputes the program's setup caps, which
/// takes on the order of a minute. Call once at startup.
///
/// The app program commitment, read off the prover's own setups (a map lookup).
///
/// Previously recomputed from the binary via `BinaryCommitment::from_base_binary`, which
/// rebuilt all three setups (~159s on an L4) right before `create_prover` derived them again.
/// `None` on the CPU backend.
pub fn program_commitment(prover: &ProgramProver) -> Option<ProgramCommitment> {
    prover.program_commitment().map(ProgramCommitment)
}

pub fn create_proof(
    prover: &ProgramProver,
    batch_id: u64,
    prover_input: Vec<u32>,
) -> anyhow::Result<UnrolledProgramProof> {
    let artifact = prover
        .prove_words(batch_id, prover_input)
        .map_err(|e| anyhow::anyhow!("failed to prove batch {batch_id}: {e}"))?;
    Ok(artifact.proof)
}

// SYSCOIN: Cooperative shutdown is carried into submission retries so any generated proof is
// fsynced with its exact lease before this long-lived worker may exit.
pub async fn run(
    mut args: Args,
    mut stop_receiver: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let timeout = Duration::from_secs(args.request_timeout_secs);
    // SYSCOIN: Parse opaque secret-backed env values only after Clap has completed, so malformed
    // credentials can never be reflected by Clap's error renderer.
    let sequencer_urls =
        parse_configured_sequencer_endpoints(std::mem::take(&mut args.sequencer_urls))?;

    tracing::info!(
        "Creating {} sequencer proof clients for urls: {:?}",
        sequencer_urls.len(),
        sequencer_urls
    );

    let supported_versions = SupportedProtocolVersions::default();
    // SYSCOIN: Refuse to prove before the generated app-bound VK replaces the sentinel.
    supported_versions
        .ensure_syscoin_release_constants()
        .map_err(anyhow::Error::msg)?;
    tracing::info!("{:#?}", supported_versions);

    // SYSCOIN: Replace upstream in-memory clients with one process-locked, crash-durable spool.
    let clients = SequencerProofClient::new_durable_clients(
        sequencer_urls,
        args.prover_name,
        Some(timeout),
        supported_versions.vk_hashes(),
        args.submission_dir,
        stop_receiver.clone(),
        args.allow_insecure_sequencer_http,
    )
    .context("failed to create sequencer proof clients")?;
    // SYSCOIN: Drain crash-retained exact submissions before GPU setup or any new lease pick.
    resume_pending_submissions(&clients)
        .await
        .context("failed to resume durable prover submissions")?;

    let manifest_path = if let Ok(manifest_path) = std::env::var("CARGO_MANIFEST_DIR") {
        manifest_path
    } else {
        ".".to_string()
    };

    let binary_path = args
        .app_bin_path
        .unwrap_or_else(|| Path::new(&manifest_path).join("../../multiblock_batch.bin"));

    let prover = create_prover(&binary_path)?;

    // Fail fast on a binary no supported version proves. Free now, so it runs after
    // construction rather than before it.
    let program_commitment = program_commitment(&prover)
        .context("program commitment unavailable (CPU backend); cannot verify the app binary")?;
    tracing::info!("App program commitment: {program_commitment}");
    anyhow::ensure!(
        supported_versions.supports_program(&program_commitment),
        "program {binary_path:?} (commitment {program_commitment}) is not proven by any \
         supported protocol version"
    );

    tracing::info!(
        "Starting Zksync OS FRI prover with request timeout of {}s",
        args.request_timeout_secs
    );

    let mut proof_count = 0;

    let mut retrying_since = Instant::now();

    let retry_interval = Duration::from_millis(100);
    // If no proof is generated for 10 seconds, log a message
    let retry_log_interval = Duration::from_secs(10);

    // SYSCOIN: Probe all configured sequencers in oldest-head order while retaining every
    // endpoint as a fail-open claim fallback.
    loop {
        if *stop_receiver.borrow() {
            tracing::info!("FRI prover stop requested before acquiring another job");
            return Ok(());
        }
        // SYSCOIN: A retained auth/path/redirect/config envelope is process-blocking: replay it or
        // fail the service rather than silently polling/picking new work behind unresolved proof.
        resume_pending_submissions(&clients)
            .await
            .context("durable submission replay blocks new FRI picks")?;
        let mut proof_generated = false;
        let client_order =
            ordered_client_indices(&clients, JobQueueStage::Fri, STATUS_PROBE_CONCURRENCY).await;
        for client_idx in client_order {
            if *stop_receiver.borrow() {
                return Ok(());
            }
            let client = &clients[client_idx];
            tracing::debug!("Polling sequencer: {}", client.sequencer_url());
            match run_inner(
                client.as_ref(),
                &prover,
                args.path.clone(),
                &supported_versions,
                &program_commitment,
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

            // Check if we've reached the iteration limit
            if let Some(max_proofs_generated) = args.iterations {
                if proof_count >= max_proofs_generated {
                    tracing::info!(
                        "Reached maximum iterations ({max_proofs_generated}), exiting...",
                    );
                    return Ok(());
                }
            }
            retrying_since = Instant::now();
        } else {
            // If no task was found, wait before trying again

            if retrying_since.elapsed() >= retry_log_interval {
                tracing::info!(
                    "No pending batches to prove from sequencer for {} seconds",
                    retrying_since.elapsed().as_secs()
                );
                retrying_since = Instant::now();
            }
            tracing::debug!(
                "No pending batches to prove from sequencer, retrying in {} ms",
                retry_interval.as_millis()
            );
            // SYSCOIN: Wake idle polling on shutdown without cancelling an acquired run_inner.
            tokio::select! {
                _ = tokio::time::sleep(retry_interval) => {}
                changed = stop_receiver.changed() => {
                    if changed.is_err() || *stop_receiver.borrow() {
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// SYSCOIN: Return a typed acquisition outcome so endpoint fallback is possible only before a
/// lease exists; every acquired lease remains bound to exactly one proof/disposition path.
pub async fn run_inner(
    client: &dyn ProofClient,
    prover: &ProgramProver,
    path: Option<PathBuf>,
    supported_versions: &SupportedProtocolVersions,
    program_commitment: &ProgramCommitment,
) -> anyhow::Result<ProofRunOutcome> {
    let FriJobInputs {
        batch_number,
        vk_hash,
        prover_input,
        lease_token,
    } = match client.pick_fri_job().await {
        Err(err) => {
            // SYSCOIN: The pick acquired or may have acquired a lease; endpoint fallback could
            // create two live assignments for this worker.
            if error_follows_job_acquisition(&err) {
                return Err(err).context(
                    "FRI pick may have acquired a lease; no endpoint fallback is allowed",
                );
            }
            // Check if the error is a timeout error
            if err
                .downcast_ref::<reqwest::Error>()
                .map(|e| e.is_timeout())
                .unwrap_or(false)
            {
                tracing::error!(
                    "Timeout waiting for response from sequencer {}: {err}",
                    client.sequencer_url()
                );
                tracing::error!("Exiting prover due to timeout");
                FRI_PROVER_METRICS.timeout_errors.inc();
                return Ok(ProofRunOutcome::EndpointUnavailable);
            }
            tracing::error!(
                "Error fetching next prover job from sequencer {}: {err}",
                client.sequencer_url()
            );
            return Ok(ProofRunOutcome::EndpointUnavailable);
        }
        Ok(Some(fri_job_input)) => {
            if !supported_versions.contains(&fri_job_input.vk_hash) {
                // SYSCOIN: The pick already transferred an exact lease. Treat an unsupported VK
                // as fatal instead of falling through to another endpoint and abandoning it.
                anyhow::bail!(
                    "unsupported protocol version with vk_hash {} for leased batch {} from sequencer {}",
                    fri_job_input.vk_hash,
                    fri_job_input.batch_number,
                    client.sequencer_url()
                );
            }
            // The job's version must prove the loaded program — a mismatched proof
            // would be rejected downstream, after the GPU time is spent.
            let expected = supported_versions.program_commitment_for(&fri_job_input.vk_hash);
            if expected != Some(*program_commitment) {
                // SYSCOIN: A leased wrong-program job is a fatal server/configuration fault.
                anyhow::bail!(
                    "protocol version with vk_hash {} for leased batch {} from sequencer {} \
                     proves a different app program (version's commitment: {}, loaded binary: {program_commitment})",
                    fri_job_input.vk_hash,
                    fri_job_input.batch_number,
                    client.sequencer_url(),
                    expected.map_or_else(|| "none".to_string(), |c| c.to_string()),
                );
            }
            fri_job_input
        }

        Ok(None) => {
            tracing::debug!(
                "No pending batches to prove from sequencer {}",
                client.sequencer_url()
            );
            return Ok(ProofRunOutcome::NoJob);
        }
    };

    let started_at = Instant::now();

    // make prover_input (Vec<u8>) into Vec<u32>, rejecting malformed input instead of
    // silently truncating trailing bytes:
    anyhow::ensure!(
        prover_input.len() % 4 == 0,
        "prover input for batch {batch_number} has {} bytes, expected a multiple of 4",
        prover_input.len()
    );
    let prover_input: Vec<u32> = prover_input
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect();

    tracing::info!(
        "Starting proving batch number {} with vk hash {} from sequencer {}",
        batch_number,
        vk_hash,
        client.sequencer_url()
    );

    let proof = create_proof(prover, batch_number as u64, prover_input)?;

    tracing::info!(
        "Finished proving batch number {} with vk hash {}",
        batch_number,
        vk_hash
    );

    let proof_bytes: Vec<u8> = bincode::serde::encode_to_vec(&proof, bincode::config::standard())
        .expect("failed to bincode-serialize proof");

    // 2) base64-encode that binary blob
    let proof_b64 = STANDARD.encode(&proof_bytes);

    FRI_PROVER_METRICS
        .latest_proven_batch
        .set(batch_number as i64);

    let proof_time = started_at.elapsed().as_secs_f64();

    FRI_PROVER_METRICS.time_taken.observe(proof_time);

    // SYSCOIN: Retain a second in-memory copy only when the optional post-submission artifact is
    // requested; the canonical copy moves directly into the durable submission boundary.
    let optional_proof = path.as_ref().map(|_| proof_b64.clone());
    client
        // SYSCOIN: Return the opaque capability from this exact pick; the public prover name is
        // diagnostic only and cannot authorize or revoke another worker's lease.
        .submit_fri_proof(batch_number, vk_hash.clone(), proof_b64, lease_token)
        .await
        .with_context(|| {
            format!(
                "generated FRI proof for batch {batch_number} could not reach a definitive manager disposition; no fresh pick is allowed"
            )
        })?;
    if let (Some(path), Some(proof_b64)) = (path.as_ref(), optional_proof.as_ref()) {
        // SYSCOIN: Write this optional operator artifact only after the proof/capability reached a
        // definitive manager disposition. Upstream's helper unwraps filesystem/JSON errors; keep
        // them best-effort so an output-disk fault cannot destroy or invalidate submitted work.
        let write_result = std::fs::File::create(path)
            .with_context(|| format!("create optional FRI proof artifact {path:?}"))
            .and_then(|mut file| {
                serde_json::to_writer_pretty(&mut file, &proof_b64)
                    .context("serialize optional FRI proof artifact")?;
                file.sync_all().context("fsync optional FRI proof artifact")
            });
        if let Err(error) = write_result {
            tracing::warn!(
                output_path = ?path,
                "failed to persist optional FRI proof artifact after submission: {error:#}"
            );
        }
    }
    tracing::info!(
        "Successfully submitted proof for batch number {} with vk hash {} to sequencer {}, generated in {} seconds",
        batch_number,
        vk_hash,
        client.sequencer_url(),
        proof_time
    );
    Ok(ProofRunOutcome::ProofSubmitted)
}

#[cfg(test)]
mod cli_security_tests {
    use super::*;
    use clap::CommandFactory as _;

    // SYSCOIN: Secret-backed endpoint text is opaque to Clap and hidden from generated help.
    #[test]
    fn sequencer_endpoint_validation_is_deferred_and_env_help_is_redacted() {
        let secret = "fri-clap-password-secret";
        let mut args = Args::try_parse_from([
            "fri-prover",
            "--submission-dir",
            "/tmp/fri-prover-test-submissions",
            "--sequencer-urls",
            &format!("https://:{secret}@sequencer.example/"),
        ])
        .expect("opaque endpoint must not fail inside Clap");
        let error = parse_configured_sequencer_endpoints(std::mem::take(&mut args.sequencer_urls))
            .unwrap_err();
        assert!(!format!("{error:#}").contains(secret));

        let command = Args::command();
        let endpoint = command
            .get_arguments()
            .find(|argument| argument.get_id() == "sequencer_urls")
            .expect("sequencer_urls argument");
        assert!(endpoint.is_hide_env_values_set());
    }
}
