// TODO!: This code base should be moved in a single binary.
// SNARK & FRI should be libs only and expose no binaries themselves.
// We'll need slightly more "involved" CLI args, but nothing too complex.
use std::{
    cell::RefCell,
    future::Future,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::Context;
use clap::Parser;
use protocol_version::SupportedProtocolVersions;
use tokio::sync::watch;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use zksync_sequencer_proof_client::{
    ordered_client_indices, parse_configured_sequencer_endpoints, resume_pending_submissions,
    JobQueueStage, OpaqueSequencerEndpoint, ProofRunOutcome, SequencerProofClient,
    STATUS_PROBE_CONCURRENCY,
};

pub mod metrics;

/// Command-line arguments for the Zksync OS prover
#[derive(Parser, Debug)]
#[command(name = "Zksync OS Prover")]
#[command(version = "1.0")]
#[command(about = "Prover for Zksync OS", long_about = None)]
pub struct Args {
    /// SYSCOIN: Max SNARK latency in seconds (default value - 1 hour).
    #[arg(long, default_value = "3600")]
    pub max_snark_latency: Option<u64>,
    /// SYSCOIN: Max amount of FRI proofs per SNARK (default value - 100).
    #[arg(long, default_value = "100")]
    pub max_fris_per_snark: Option<usize>,
    /// SYSCOIN: Max time to wait for a SNARK job after switching away from FRI proving.
    #[arg(long, default_value = "60")]
    pub snark_acquire_timeout_secs: u64,
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
    /// Directory to store the output files for SNARK prover
    #[arg(long)]
    pub output_dir: String,
    /// SYSCOIN: Explicit absolute owner-only durable exact proof/capability spool. It is
    /// exclusively locked so two worker processes cannot replay one envelope.
    #[arg(long)]
    pub submission_dir: PathBuf,
    /// SYSCOIN: Explicit isolated-network escape hatch. Production remote sequencers must use HTTPS.
    #[arg(long, default_value_t = false)]
    pub allow_insecure_sequencer_http: bool,
    /// Path to the trusted setup file for SNARK prover
    #[arg(long)]
    pub trusted_setup_file: String,
    /// Number of iterations before exiting. Only successfully generated SNARK proofs count. If not specified, runs indefinitely
    #[arg(long)]
    pub iterations: Option<usize>,
    /// Path to the output file for FRI proofs
    #[arg(short, long)]
    pub fri_path: Option<PathBuf>,
    /// SYSCOIN: Dedicated default metrics port for parallel GPU workers.
    #[arg(long, default_value = "3127")]
    pub prometheus_port: u16,
    /// SYSCOIN: Total HTTP request backstop in seconds. Connect timeout is 5s and
    /// read-inactivity timeout is 10s.
    #[arg(long, default_value = "600")]
    pub request_timeout_secs: u64,
    /// Disable ZK for SNARK proofs
    #[arg(long, default_value_t = false)]
    pub disable_zk: bool,
}

// SYSCOIN: Explicit phase polling and OR-based 100-proof / one-hour controls.
const SNARK_POLL_INTERVAL: Duration = Duration::from_secs(1);
const FRI_POLL_INTERVAL: Duration = Duration::from_millis(100);

fn fri_phase_limit_reached(
    elapsed: Duration,
    fri_proof_count: usize,
    max_snark_latency: Option<u64>,
    max_fris_per_snark: Option<usize>,
) -> bool {
    max_snark_latency.is_some_and(|max| elapsed.as_secs() >= max)
        || max_fris_per_snark.is_some_and(|max| fri_proof_count >= max)
}

async fn acquire_snark_proof<F, Fut>(
    snark_acquire_timeout: Duration,
    poll_interval: Duration,
    stop_receiver: &mut watch::Receiver<bool>,
    mut run_snark_attempt: F,
) -> anyhow::Result<bool>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<bool>>,
{
    let started_at = Instant::now();
    loop {
        if shutdown_requested(stop_receiver) {
            return Ok(false);
        }

        // SYSCOIN: Once an attempt starts it may own a sequencer lease. Let it finish and
        // submit before observing shutdown so operator Ctrl-C cannot discard paid proving work.
        if run_snark_attempt().await? {
            return Ok(true);
        }

        if shutdown_requested(stop_receiver) || started_at.elapsed() >= snark_acquire_timeout {
            return Ok(false);
        }

        if wait_for_shutdown(poll_interval, stop_receiver).await {
            return Ok(false);
        }
    }
}

fn shutdown_requested(stop_receiver: &watch::Receiver<bool>) -> bool {
    *stop_receiver.borrow()
}

async fn wait_for_shutdown(duration: Duration, stop_receiver: &mut watch::Receiver<bool>) -> bool {
    if shutdown_requested(stop_receiver) {
        return true;
    }

    tokio::select! {
        _ = tokio::time::sleep(duration) => false,
        changed = stop_receiver.changed() => {
            // SYSCOIN: A dropped shutdown controller is terminal too; never leave an
            // unattended prover polling for fresh work.
            changed.is_err() || shutdown_requested(stop_receiver)
        }
    }
}

pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    FmtSubscriber::builder().with_env_filter(filter).init();
}

// SYSCOIN: The combined worker retains every acquired lease through durable handoff or definitive
// manager disposition and observes one cooperative stop signal between phases.
pub async fn run(mut args: Args, mut stop_receiver: watch::Receiver<bool>) -> anyhow::Result<()> {
    // SYSCOIN: Defer semantic URL parsing until after Clap has consumed the secret-backed env
    // value, preventing malformed credentials from being echoed in a typed-parser error.
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

    // SYSCOIN: Combined workers share one process-locked durable submission namespace.
    let clients = SequencerProofClient::new_durable_clients(
        sequencer_urls,
        "prover_service".to_string(),
        Some(Duration::from_secs(args.request_timeout_secs)),
        supported_versions.vk_hashes(),
        args.submission_dir.clone(),
        stop_receiver.clone(),
        args.allow_insecure_sequencer_http,
    )
    .context("failed to create sequencer proof clients")?;
    // SYSCOIN: Resolve crash-retained exact submissions before GPU setup or any fresh pick.
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

    // The FRI prover and the FRI-proof combiner each size their device pool to "all
    // free VRAM" and need essentially the whole card (on prod-shaped L4s a resident
    // SNARK wrapper starves the FRI prover into OOM). So the wrapper is built per
    // SNARK job — after the job's proofs are merged — and dropped with the job,
    // mirroring how `fri_prover` is dropped before SNARKing. Its host-side setup
    // caches are authenticated and initialized below before polling, then survive between jobs,
    // so no leased job pays the full setup derivation. It is kept in a RefCell so the retry
    // closure below can borrow it mutably.
    // SYSCOIN: Use the dedicated worker's authenticated pre-lease initialization, then retain
    // only its host cache. Missing/corrupt setup and an app-bound VK mismatch must fail before the
    // combined service can acquire either FRI or SNARK work.
    let wrapper_source = RefCell::new(
        zksync_os_snark_prover::WrapperSource::new_validated(
            args.trusted_setup_file.clone(),
            binary_path.clone(),
            &supported_versions,
        )
        .context("initialize combined-service app-bound SNARK wrapper before queue polling")?,
    );

    // SYSCOIN: The FRI-proof combiner likewise caches its setup data (and, on `gpu` builds, the
    // GPU prover's host state — pinned host RAM only, no VRAM) across jobs and across
    // the FRI/SNARK phase alternation. Its caches build lazily on the first multi-proof
    // SNARK job rather than at startup, so a service that never sees multi-proof jobs
    // doesn't pin tens of gigabytes of host RAM for nothing.
    let combiner = RefCell::new(zksync_os_snark_prover::create_combiner());

    tracing::info!("Starting Zksync OS Prover Service");

    let mut snark_proof_count = 0;
    let mut snark_latency = Instant::now();

    // SYSCOIN: Schedule each phase independently across every configured sequencer.
    loop {
        // SYSCOIN: Honor shutdown before either phase can acquire a new lease.
        if shutdown_requested(&stop_receiver) {
            tracing::info!("Shutdown requested before acquiring another prover job");
            return Ok(());
        }

        let mut fri_proof_count = 0;

        // The FRI prover holds the program setups (and the GPU context when built with the
        // `gpu` feature); it is recreated each cycle so the GPU is released before SNARKing.
        let fri_prover = zksync_os_fri_prover::create_prover(&binary_path)?;

        // Fail fast on a binary no supported version proves; free, from the prover's setups.
        let program_commitment = zksync_os_fri_prover::program_commitment(&fri_prover).context(
            "program commitment unavailable (CPU backend); cannot verify the app binary",
        )?;
        anyhow::ensure!(
            supported_versions.supports_program(&program_commitment),
            "program {binary_path:?} (commitment {program_commitment}) is not proven by any \
             supported protocol version"
        );
        tracing::info!("App program commitment: {program_commitment}");

        // Run FRI prover until we hit one of the limits
        tracing::info!("Running FRI prover across {} sequencer(s)", clients.len());
        loop {
            // SYSCOIN: Retained config/auth envelopes block the whole worker before another lease.
            resume_pending_submissions(&clients)
                .await
                .context("durable submission replay blocks new combined-service picks")?;
            let mut proof_generated = false;
            let client_order =
                ordered_client_indices(&clients, JobQueueStage::Fri, STATUS_PROBE_CONCURRENCY)
                    .await;
            for client_idx in client_order {
                if shutdown_requested(&stop_receiver) {
                    tracing::info!("Shutdown requested before acquiring another FRI job");
                    return Ok(());
                }
                let client = &clients[client_idx];
                match zksync_os_fri_prover::run_inner(
                    client.as_ref(),
                    &fri_prover,
                    args.fri_path.clone(),
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

            // SYSCOIN: `run_inner` owns any claimed lease until proof submission returns.
            // Observe shutdown only after that durable handoff has completed.
            if shutdown_requested(&stop_receiver) {
                tracing::info!("Shutdown requested after completing the in-flight FRI attempt");
                return Ok(());
            }

            fri_proof_count += proof_generated as usize;

            if fri_phase_limit_reached(
                snark_latency.elapsed(),
                fri_proof_count,
                args.max_snark_latency,
                args.max_fris_per_snark,
            ) {
                tracing::info!(
                    "FRI phase limit reached ({} proof(s), {} seconds); switching to SNARK",
                    fri_proof_count,
                    snark_latency.elapsed().as_secs()
                );
                break;
            }
            if !proof_generated && wait_for_shutdown(FRI_POLL_INTERVAL, &mut stop_receiver).await {
                return Ok(());
            }
        }
        // SYSCOIN: Release only FRI GPU state at the phase boundary; retained host caches let the
        // sequential SNARK phase reuse setup without concurrent VRAM ownership.
        drop(fri_prover);

        // SYSCOIN: Never re-enter FRI acquisition after an in-flight SNARK attempt if shutdown won.
        if shutdown_requested(&stop_receiver) {
            return Ok(());
        }

        // Here we do exactly one SNARK proof
        tracing::info!("Running SNARK prover across {} sequencer(s)", clients.len());
        // Holding the RefCell guard across the await is fine here: `run` executes as a
        // single (non-Send) future and SNARK attempts run strictly sequentially, so no
        // concurrent borrow of the wrapper can occur.
        let snark_attempt_stop = stop_receiver.clone();
        #[allow(clippy::await_holding_refcell_ref)]
        let proof_generated = acquire_snark_proof(
            Duration::from_secs(args.snark_acquire_timeout_secs),
            SNARK_POLL_INTERVAL,
            &mut stop_receiver,
            || async {
                // SYSCOIN: Do not switch stages or acquire a SNARK lease behind a retained FRI or
                // SNARK envelope; unresolved config responses fail the service visibly.
                resume_pending_submissions(&clients)
                    .await
                    .context("durable submission replay blocks new SNARK picks")?;
                let client_order = ordered_client_indices(
                    &clients,
                    JobQueueStage::Snark,
                    STATUS_PROBE_CONCURRENCY,
                )
                .await;
                for client_idx in client_order {
                    if shutdown_requested(&snark_attempt_stop) {
                        return Ok(false);
                    }
                    let client = &clients[client_idx];
                    match zksync_os_snark_prover::run_inner(
                        client.as_ref(),
                        &mut wrapper_source.borrow_mut(),
                        &mut combiner.borrow_mut(),
                        args.output_dir.clone(),
                        args.disable_zk,
                        &supported_versions,
                    )
                    .await?
                    {
                        ProofRunOutcome::ProofSubmitted => return Ok(true),
                        ProofRunOutcome::NoJob | ProofRunOutcome::EndpointUnavailable => {}
                    }
                }
                Ok(false)
            },
        )
        .await
        // SYSCOIN: Propagate a post-lease/proof failure through normal service shutdown; panicking
        // obscures the durable-envelope diagnostic and skips orderly auxiliary-task cleanup.
        .context("failed to run SNARK prover")?;

        if proof_generated {
            // Increment SNARK proof counter
            tracing::info!("Successfully run SNARK prover");
            snark_proof_count += proof_generated as usize;
            snark_latency = Instant::now();
        } else {
            tracing::info!(
                "No SNARK proof was generated within snark_acquire_timeout_secs ({} seconds), returning to FRI prover",
                args.snark_acquire_timeout_secs
            );
            snark_latency = Instant::now();
        }

        // SYSCOIN: After the acquired SNARK attempt resolves, honor shutdown before any new FRI
        // lease can be claimed by the next phase.
        if shutdown_requested(&stop_receiver) {
            tracing::info!("Shutdown requested after completing the in-flight SNARK attempt");
            return Ok(());
        }

        // Check if we've reached the iteration limit
        if let Some(max_iterations) = args.iterations {
            if snark_proof_count >= max_iterations {
                tracing::info!("Reached maximum iterations ({max_iterations}), exiting...",);
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use super::*;
    use clap::CommandFactory as _;

    #[tokio::test]
    async fn snark_acquire_times_out_instead_of_looping_forever() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_for_closure = attempts.clone();
        let (_stop_sender, mut stop_receiver) = watch::channel(false);

        let acquired = tokio::time::timeout(
            Duration::from_millis(100),
            acquire_snark_proof(
                Duration::from_millis(20),
                Duration::from_millis(1),
                &mut stop_receiver,
                move || {
                    let attempts = attempts_for_closure.clone();
                    async move {
                        attempts.fetch_add(1, Ordering::Relaxed);
                        Ok(false)
                    }
                },
            ),
        )
        .await
        .expect("snark acquisition should time out rather than loop forever")
        .expect("snark acquisition should not error");

        assert!(!acquired);
        assert!(attempts.load(Ordering::Relaxed) >= 1);
    }

    #[tokio::test]
    async fn snark_acquire_succeeds_before_timeout() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_for_closure = attempts.clone();
        let (_stop_sender, mut stop_receiver) = watch::channel(false);

        let acquired = acquire_snark_proof(
            Duration::from_millis(100),
            Duration::from_millis(1),
            &mut stop_receiver,
            move || {
                let attempts = attempts_for_closure.clone();
                async move {
                    let attempt = attempts.fetch_add(1, Ordering::Relaxed);
                    Ok(attempt >= 2)
                }
            },
        )
        .await
        .expect("snark acquisition should not error");

        assert!(acquired);
        assert!(attempts.load(Ordering::Relaxed) >= 3);
    }

    // SYSCOIN: Ctrl-C must not cancel an attempt that may already own a sequencer lease.
    #[tokio::test]
    async fn shutdown_waits_for_in_flight_snark_attempt() {
        let (stop_sender, mut stop_receiver) = watch::channel(false);
        let (started_sender, mut started_receiver) = tokio::sync::oneshot::channel();
        let (finish_sender, finish_receiver) = tokio::sync::oneshot::channel();
        let mut started_sender = Some(started_sender);
        let mut finish_receiver = Some(finish_receiver);

        let acquire = acquire_snark_proof(
            Duration::from_secs(1),
            Duration::from_millis(1),
            &mut stop_receiver,
            move || {
                let started_sender = started_sender
                    .take()
                    .expect("the test attempt must run exactly once");
                let finish_receiver = finish_receiver
                    .take()
                    .expect("the test attempt must run exactly once");
                async move {
                    started_sender.send(()).expect("test observer must remain");
                    finish_receiver
                        .await
                        .expect("test must release the attempt");
                    Ok(true)
                }
            },
        );
        tokio::pin!(acquire);

        tokio::select! {
            result = &mut started_receiver => result.expect("attempt must start"),
            result = &mut acquire => panic!("attempt returned before it was released: {result:?}"),
        }
        stop_sender.send_replace(true);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut acquire)
                .await
                .is_err(),
            "shutdown must wait for an acquired proof"
        );

        finish_sender.send(()).expect("attempt must still be alive");
        assert!(acquire.await.expect("attempt must succeed"));
    }

    // SYSCOIN: After an in-flight attempt completes without a proof, shutdown prevents
    // another queue claim rather than leaving a fresh lease behind.
    #[tokio::test]
    async fn shutdown_prevents_next_snark_attempt() {
        let (stop_sender, mut stop_receiver) = watch::channel(false);
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_for_closure = attempts.clone();

        let acquired = acquire_snark_proof(
            Duration::from_secs(1),
            Duration::from_millis(1),
            &mut stop_receiver,
            move || {
                let attempts = attempts_for_closure.clone();
                let stop_sender = stop_sender.clone();
                async move {
                    attempts.fetch_add(1, Ordering::Relaxed);
                    stop_sender.send_replace(true);
                    Ok(false)
                }
            },
        )
        .await
        .expect("shutdown should be graceful");

        assert!(!acquired);
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
    }

    // SYSCOIN: Lock the combined service's target-or-latency phase transition policy.
    #[test]
    fn fri_phase_limits_have_or_semantics() {
        assert!(fri_phase_limit_reached(
            Duration::from_secs(1),
            100,
            Some(3600),
            Some(100)
        ));
        assert!(fri_phase_limit_reached(
            Duration::from_secs(3600),
            1,
            Some(3600),
            Some(100)
        ));
        assert!(!fri_phase_limit_reached(
            Duration::from_secs(3599),
            99,
            Some(3600),
            Some(100)
        ));
    }

    #[test]
    fn cli_accepts_both_fri_phase_limits() {
        let args = Args::try_parse_from([
            "prover-service",
            "--output-dir",
            "out",
            "--trusted-setup-file",
            "setup.key",
            "--submission-dir",
            "/tmp/combined-prover-limit-test-submissions",
            "--max-snark-latency",
            "3600",
            "--max-fris-per-snark",
            "100",
        ])
        .expect("both OR limits must be accepted");
        assert_eq!(args.max_snark_latency, Some(3600));
        assert_eq!(args.max_fris_per_snark, Some(100));
    }

    // SYSCOIN: Malformed credential text is rejected only after Clap, and live env values are
    // hidden from the help renderer for the combined worker too.
    #[test]
    fn cli_endpoint_validation_is_deferred_and_env_help_is_redacted() {
        let secret = "combined-clap-password-secret";
        let mut args = Args::try_parse_from([
            "prover-service",
            "--output-dir",
            "out",
            "--trusted-setup-file",
            "setup.key",
            "--submission-dir",
            "/tmp/combined-prover-test-submissions",
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
