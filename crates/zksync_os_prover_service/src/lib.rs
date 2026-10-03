// TODO!: This code base should be moved in a single binary.
// SNARK & FRI should be libs only and expose no binaries themselves.
// We'll need slightly more "involved" CLI args, but nothing too complex.
use std::{
    future::Future,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::Context;
use clap::Parser;
use protocol_version::SupportedProtocolVersions;
use tokio::sync::watch;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use zksync_os_fri_prover::FriSetupPolicy;
use zksync_os_snark_prover::{BinaryCommitmentPolicy, WrapperCachePolicy};
use zksync_sequencer_proof_client::{
    claim_first_snark_job, hinted_client_indices, ordered_client_indices,
    parse_configured_sequencer_endpoints, resume_pending_submissions, JobQueueStage,
    OpaqueSequencerEndpoint, ProofRunOutcome, SequencerProofClient, STATUS_PROBE_CONCURRENCY,
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
    /// SYSCOIN: Max time to wait for a SNARK job when a FRI phase limit is reached.
    #[arg(long, default_value = "60")]
    pub snark_acquire_timeout_secs: u64,
    /// Maximum time between direct SNARK queue probes when status hints are empty or unavailable.
    /// In-flight proofs always finish before another queue claim.
    #[arg(long, default_value = "5")]
    pub snark_probe_interval_secs: u64,
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

const SNARK_POLL_INTERVAL: Duration = Duration::from_secs(1);
const FRI_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnarkProbe {
    Hinted,
    AllClients,
    PhaseLimit,
}

struct PriorityScheduler {
    phase_started: Instant,
    fri_proof_count: usize,
    last_full_probe: Option<Instant>,
}

impl PriorityScheduler {
    fn new(now: Instant) -> Self {
        Self {
            phase_started: now,
            fri_proof_count: 0,
            last_full_probe: None,
        }
    }

    fn next_probe(
        &self,
        now: Instant,
        probe_interval: Duration,
        max_snark_latency: Option<u64>,
        max_fris_per_snark: Option<usize>,
    ) -> SnarkProbe {
        if fri_phase_limit_reached(
            now.duration_since(self.phase_started),
            self.fri_proof_count,
            max_snark_latency,
            max_fris_per_snark,
        ) {
            SnarkProbe::PhaseLimit
        } else if self
            .last_full_probe
            .is_none_or(|last| now.duration_since(last) >= probe_interval)
        {
            SnarkProbe::AllClients
        } else {
            SnarkProbe::Hinted
        }
    }

    fn probed(&mut self, now: Instant, probe: SnarkProbe) {
        if probe != SnarkProbe::Hinted {
            self.last_full_probe = Some(now);
        }
        if probe == SnarkProbe::PhaseLimit {
            self.phase_started = now;
            self.fri_proof_count = 0;
        }
    }

    fn submitted_snark(&mut self, now: Instant) {
        // A queued wrap backlog must drain before warming FRI again, including when status is
        // unavailable. A subsequent empty native pick restarts the bounded fallback interval.
        *self = Self::new(now);
    }

    fn submitted_fri(&mut self) {
        self.fri_proof_count = self.fri_proof_count.saturating_add(1);
    }
}

fn fri_phase_limit_reached(
    elapsed: Duration,
    fri_proof_count: usize,
    max_snark_latency: Option<u64>,
    max_fris_per_snark: Option<usize>,
) -> bool {
    max_snark_latency.is_some_and(|max| elapsed.as_secs() >= max)
        || max_fris_per_snark.is_some_and(|max| fri_proof_count >= max)
}

async fn acquire_snark_job<F, Fut, T>(
    snark_acquire_timeout: Duration,
    poll_interval: Duration,
    stop_receiver: &mut watch::Receiver<bool>,
    mut run_snark_attempt: F,
) -> anyhow::Result<Option<T>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<Option<T>>>,
{
    let started_at = Instant::now();
    loop {
        if shutdown_requested(stop_receiver) {
            return Ok(None);
        }

        // A pick can transfer a lease while shutdown arrives. Return that owned input for
        // processing; cancellation is only safe before the next acquisition attempt.
        if let Some(job) = run_snark_attempt().await? {
            return Ok(Some(job));
        }

        if shutdown_requested(stop_receiver) || started_at.elapsed() >= snark_acquire_timeout {
            return Ok(None);
        }

        if wait_for_shutdown(poll_interval, stop_receiver).await {
            return Ok(None);
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
pub async fn run(args: Args, stop_receiver: watch::Receiver<bool>) -> anyhow::Result<()> {
    run_with_binary_commitment_policy(args, stop_receiver, BinaryCommitmentPolicy::default()).await
}

/// Run the combined worker with an explicit fixed-commitment policy. Existing callers of
/// [`run`] use the checked-in commitment by default; recomputation is an operator opt-in.
pub async fn run_with_binary_commitment_policy(
    args: Args,
    stop_receiver: watch::Receiver<bool>,
    binary_commitment_policy: BinaryCommitmentPolicy,
) -> anyhow::Result<()> {
    run_with_setup_policies(
        args,
        stop_receiver,
        binary_commitment_policy,
        FriSetupPolicy::default(),
    )
    .await
}

/// Select FRI summaries independently from the SNARK fixed-commitment policy.
/// Both compatibility entry points retain authenticated bundled FRI setup by default.
pub async fn run_with_setup_policies(
    mut args: Args,
    mut stop_receiver: watch::Receiver<bool>,
    binary_commitment_policy: BinaryCommitmentPolicy,
    fri_setup_policy: FriSetupPolicy,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        args.snark_probe_interval_secs > 0,
        "SNARK probe interval must be positive"
    );
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
    // so no leased job pays the full setup derivation.
    // SYSCOIN: Use the dedicated worker's authenticated pre-lease initialization, then retain
    // only its host cache. Missing/corrupt setup and an app-bound VK mismatch must fail before the
    // combined service can acquire either FRI or SNARK work.
    let mut wrapper_source = zksync_os_snark_prover::WrapperSource::new_validated_with_policies(
        args.trusted_setup_file.clone(),
        binary_path.clone(),
        &supported_versions,
        WrapperCachePolicy::Warm,
        binary_commitment_policy,
    )
    .context("initialize combined-service app-bound SNARK wrapper before queue polling")?;

    // SYSCOIN: The FRI-proof combiner likewise caches its setup data (and, on `gpu` builds, the
    // GPU prover's host state — pinned host RAM only, no VRAM) across jobs and across
    // the FRI/SNARK phase alternation. Its caches build lazily on the first multi-proof
    // SNARK job rather than at startup, so a service that never sees multi-proof jobs
    // doesn't pin tens of gigabytes of host RAM for nothing.
    let mut combiner = zksync_os_snark_prover::create_combiner();

    tracing::info!("Starting Zksync OS Prover Service");

    let mut snark_proof_count = 0;
    let mut scheduler = PriorityScheduler::new(Instant::now());
    let mut fri_prover = None;
    let mut fri_program_commitment = None;
    let probe_interval = Duration::from_secs(args.snark_probe_interval_secs);

    loop {
        if shutdown_requested(&stop_receiver) {
            return Ok(());
        }
        resume_pending_submissions(&clients)
            .await
            .context("durable submission replay blocks new combined-service picks")?;

        let probe = scheduler.next_probe(
            Instant::now(),
            probe_interval,
            args.max_snark_latency,
            args.max_fris_per_snark,
        );
        let claimed = if probe == SnarkProbe::PhaseLimit {
            let claim_stop = stop_receiver.clone();
            acquire_snark_job(
                Duration::from_secs(args.snark_acquire_timeout_secs),
                SNARK_POLL_INTERVAL,
                &mut stop_receiver,
                || async {
                    let candidates = ordered_client_indices(
                        &clients,
                        JobQueueStage::Snark,
                        STATUS_PROBE_CONCURRENCY,
                    )
                    .await;
                    claim_first_snark_job(&clients, &candidates, &claim_stop).await
                },
            )
            .await?
        } else {
            let candidates = if probe == SnarkProbe::AllClients {
                ordered_client_indices(&clients, JobQueueStage::Snark, STATUS_PROBE_CONCURRENCY)
                    .await
            } else {
                hinted_client_indices(&clients, JobQueueStage::Snark, STATUS_PROBE_CONCURRENCY)
                    .await
            };
            claim_first_snark_job(&clients, &candidates, &stop_receiver).await?
        };
        scheduler.probed(Instant::now(), probe);

        if let Some(claimed) = claimed {
            // Status exposes queued FRIs, not the server's target/age/eligibility decision.
            // Keep the expensive FRI setup until a native pick actually transfers a SNARK lease.
            drop(fri_prover.take());
            fri_program_commitment = None;
            // The retained client consumes exactly the preclaimed input. Even a shutdown arriving
            // during that pick must finish this owned attempt before another phase can start.
            let outcome = zksync_os_snark_prover::run_inner(
                &claimed,
                &mut wrapper_source,
                &mut combiner,
                args.output_dir.clone(),
                args.disable_zk,
                &supported_versions,
            )
            .await
            .context("failed to process the retained SNARK lease")?;
            anyhow::ensure!(
                outcome == ProofRunOutcome::ProofSubmitted,
                "retained SNARK lease did not reach its proof submission path"
            );
            snark_proof_count += 1;
            scheduler.submitted_snark(Instant::now());
            if args
                .iterations
                .is_some_and(|limit| snark_proof_count >= limit)
            {
                return Ok(());
            }
            continue;
        }

        if shutdown_requested(&stop_receiver) {
            return Ok(());
        }
        if fri_prover.is_none() {
            let prover = zksync_os_fri_prover::create_prover_with_setup_policy(
                &binary_path,
                fri_setup_policy,
            )?;
            let program_commitment = zksync_os_fri_prover::program_commitment(&prover).context(
                "program commitment unavailable (CPU backend); cannot verify the app binary",
            )?;
            anyhow::ensure!(
                supported_versions.supports_program(&program_commitment),
                "program {binary_path:?} (commitment {program_commitment}) is not proven by any \
                 supported protocol version"
            );
            tracing::info!("App program commitment: {program_commitment}");
            fri_program_commitment = Some(program_commitment);
            fri_prover = Some(prover);
            // Initial setup can outlast the queue hint. Recheck wrapping work before acquiring
            // the first FRI lease, without recreating this resident setup on an empty response.
            continue;
        }

        let prover = fri_prover.as_ref().expect("FRI setup was initialized");
        let program_commitment = fri_program_commitment
            .as_ref()
            .expect("resident FRI setup has its authenticated app commitment");
        let mut proof_generated = false;
        let client_order =
            ordered_client_indices(&clients, JobQueueStage::Fri, STATUS_PROBE_CONCURRENCY).await;
        for client_idx in client_order {
            if shutdown_requested(&stop_receiver) {
                return Ok(());
            }
            match zksync_os_fri_prover::run_inner(
                clients[client_idx].as_ref(),
                prover,
                args.fri_path.clone(),
                &supported_versions,
                program_commitment,
            )
            .await?
            {
                ProofRunOutcome::ProofSubmitted => {
                    scheduler.submitted_fri();
                    proof_generated = true;
                    break;
                }
                ProofRunOutcome::NoJob | ProofRunOutcome::EndpointUnavailable => {}
            }
        }
        if !proof_generated && wait_for_shutdown(FRI_POLL_INTERVAL, &mut stop_receiver).await {
            return Ok(());
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
    async fn commitment_policy_entrypoints_keep_shared_validation_before_network_or_setup() {
        let invalid_args = || {
            Args::try_parse_from([
                "prover-service",
                "--output-dir",
                "out",
                "--trusted-setup-file",
                "missing-setup.key",
                "--submission-dir",
                "/tmp/combined-prover-commitment-test-submissions",
                "--snark-probe-interval-secs",
                "0",
                "--sequencer-urls",
                "http://127.0.0.1:1",
            ])
            .expect("invalid interval must parse before shared semantic validation")
        };
        let (_stop_sender, stop_receiver) = watch::channel(false);
        let error = run(invalid_args(), stop_receiver.clone())
            .await
            .expect_err("legacy entrypoint must retain early validation");
        assert_eq!(error.to_string(), "SNARK probe interval must be positive");
        for policy in [
            BinaryCommitmentPolicy::Bundled,
            BinaryCommitmentPolicy::Recompute,
        ] {
            let error =
                run_with_binary_commitment_policy(invalid_args(), stop_receiver.clone(), policy)
                    .await
                    .expect_err("explicit policy must use the same validation before any setup");
            assert_eq!(error.to_string(), "SNARK probe interval must be positive");
            for fri_policy in [FriSetupPolicy::Bundled, FriSetupPolicy::Recompute] {
                let error = run_with_setup_policies(
                    invalid_args(),
                    stop_receiver.clone(),
                    policy,
                    fri_policy,
                )
                .await
                .expect_err("both policies retain validation before setup");
                assert_eq!(error.to_string(), "SNARK probe interval must be positive");
            }
        }
    }

    #[tokio::test]
    async fn snark_acquire_times_out_instead_of_looping_forever() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_for_closure = attempts.clone();
        let (_stop_sender, mut stop_receiver) = watch::channel(false);

        let acquired = tokio::time::timeout(
            Duration::from_millis(100),
            acquire_snark_job(
                Duration::from_millis(20),
                Duration::from_millis(1),
                &mut stop_receiver,
                move || {
                    let attempts = attempts_for_closure.clone();
                    async move {
                        attempts.fetch_add(1, Ordering::Relaxed);
                        Ok(None::<()>)
                    }
                },
            ),
        )
        .await
        .expect("snark acquisition should time out rather than loop forever")
        .expect("snark acquisition should not error");

        assert!(acquired.is_none());
        assert!(attempts.load(Ordering::Relaxed) >= 1);
    }

    #[tokio::test]
    async fn snark_acquire_succeeds_before_timeout() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_for_closure = attempts.clone();
        let (_stop_sender, mut stop_receiver) = watch::channel(false);

        let acquired = acquire_snark_job(
            Duration::from_millis(100),
            Duration::from_millis(1),
            &mut stop_receiver,
            move || {
                let attempts = attempts_for_closure.clone();
                async move {
                    let attempt = attempts.fetch_add(1, Ordering::Relaxed);
                    Ok((attempt >= 2).then_some(()))
                }
            },
        )
        .await
        .expect("snark acquisition should not error");

        assert!(acquired.is_some());
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

        let acquire = acquire_snark_job(
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
                    Ok(Some(()))
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
        assert!(acquire.await.expect("attempt must succeed").is_some());
    }

    // SYSCOIN: After an in-flight attempt completes without a proof, shutdown prevents
    // another queue claim rather than leaving a fresh lease behind.
    #[tokio::test]
    async fn shutdown_prevents_next_snark_attempt() {
        let (stop_sender, mut stop_receiver) = watch::channel(false);
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_for_closure = attempts.clone();

        let acquired = acquire_snark_job(
            Duration::from_secs(1),
            Duration::from_millis(1),
            &mut stop_receiver,
            move || {
                let attempts = attempts_for_closure.clone();
                let stop_sender = stop_sender.clone();
                async move {
                    attempts.fetch_add(1, Ordering::Relaxed);
                    stop_sender.send_replace(true);
                    Ok(None::<()>)
                }
            },
        )
        .await
        .expect("shutdown should be graceful");

        assert!(acquired.is_none());
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
    fn wrap_priority_checks_all_clients_on_startup_and_after_each_wrap() {
        let now = Instant::now();
        let mut scheduler = PriorityScheduler::new(now);
        let interval = Duration::from_secs(5);
        assert_eq!(
            scheduler.next_probe(now, interval, Some(3600), Some(100)),
            SnarkProbe::AllClients
        );
        scheduler.probed(now, SnarkProbe::AllClients);
        scheduler.submitted_fri();
        assert_eq!(
            scheduler.next_probe(now, interval, Some(3600), Some(100)),
            SnarkProbe::Hinted
        );
        scheduler.submitted_snark(now);
        assert_eq!(
            scheduler.next_probe(now, interval, Some(3600), Some(100)),
            SnarkProbe::AllClients,
            "a wrapping backlog must get another native pick before FRI setup"
        );
        assert_eq!(scheduler.fri_proof_count, 0);
    }

    #[test]
    fn missing_or_misleading_hints_cannot_defer_snark_for_the_full_phase() {
        let now = Instant::now();
        let mut scheduler = PriorityScheduler::new(now);
        let interval = Duration::from_secs(5);
        scheduler.probed(now, SnarkProbe::AllClients);
        scheduler.submitted_fri();
        scheduler.probed(now + Duration::from_secs(4), SnarkProbe::Hinted);
        assert_eq!(
            scheduler.next_probe(now + Duration::from_secs(4), interval, None, None),
            SnarkProbe::Hinted
        );
        assert_eq!(
            scheduler.next_probe(now + interval, interval, None, None),
            SnarkProbe::AllClients
        );
        scheduler.probed(now + interval, SnarkProbe::AllClients);
        assert_eq!(scheduler.fri_proof_count, 1);
        assert_eq!(
            scheduler.next_probe(now + interval, interval, Some(3600), Some(100)),
            SnarkProbe::Hinted,
            "an empty native probe must permit FRI work without resetting its phase"
        );
    }

    #[test]
    fn phase_limits_keep_the_bounded_native_acquisition_fallback() {
        let now = Instant::now();
        let interval = Duration::from_secs(5);
        let mut scheduler = PriorityScheduler::new(now);
        scheduler.probed(now, SnarkProbe::AllClients);
        scheduler.submitted_fri();
        scheduler.submitted_fri();
        assert_eq!(
            scheduler.next_probe(now, interval, Some(3600), Some(2)),
            SnarkProbe::PhaseLimit
        );
        scheduler.probed(now, SnarkProbe::PhaseLimit);
        assert_eq!(scheduler.fri_proof_count, 0);
        assert_eq!(
            scheduler.next_probe(now, interval, Some(3600), Some(2)),
            SnarkProbe::Hinted
        );
        assert_eq!(
            scheduler.next_probe(now + Duration::from_secs(3600), interval, Some(3600), None),
            SnarkProbe::PhaseLimit
        );
    }

    #[tokio::test]
    async fn uncertain_snark_claim_stops_acquisition_without_retrying() {
        let attempts = AtomicUsize::new(0);
        let (_stop_sender, mut stop_receiver) = watch::channel(false);
        let error = acquire_snark_job(
            Duration::from_secs(60),
            Duration::from_millis(1),
            &mut stop_receiver,
            || async {
                attempts.fetch_add(1, Ordering::SeqCst);
                Err::<Option<()>, _>(anyhow::anyhow!("uncertain native lease"))
            },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("uncertain native lease"));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
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
        assert_eq!(args.snark_probe_interval_secs, 5);
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
