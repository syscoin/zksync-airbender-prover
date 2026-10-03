use std::future::Future;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use protocol_version::SupportedProtocolVersions;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use zksync_os_snark_prover::{
    init_tracing, metrics, run_linking_fri_snark_with_policies, BinaryCommitmentPolicy,
    WrapperCachePolicy,
};
use zksync_sequencer_proof_client::{
    parse_configured_sequencer_endpoints, resume_pending_submissions, wait_for_operator_shutdown,
    OpaqueSequencerEndpoint, SequencerProofClient,
};

mod cpu_startup;

#[derive(Default, Debug, Serialize, Deserialize, Parser, Clone)]
pub struct SetupOptions {
    #[arg(long)]
    output_dir: String,

    #[arg(long)]
    trusted_setup_file: String,
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Verify a frozen native V32/V8 FRI range on CPU against trusted statements.
    VerifyFri {
        #[arg(long)]
        payload: PathBuf,
        #[arg(long)]
        expected: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    RunProver {
        /// CPU startup policy: auto tunes only the measured unrestricted Linux GPU
        /// 24-core/48-thread topology; bounded opts other hosts in; inherit disables tuning.
        #[arg(long, env = "ZKSYNC_SNARK_CPU_POLICY", default_value = "auto", value_parser = ["auto", "bounded", "inherit"])]
        cpu_policy: String,
        /// Maximum allowed logical CPUs when tuning; physical cores are selected before SMT.
        #[arg(long, env = "ZKSYNC_SNARK_CPU_MAX_LOGICAL", default_value = "31")]
        cpu_max_logical: NonZeroUsize,
        /// Default Rayon/Bellman/OMP thread environment, unless explicitly set by the operator.
        /// This does not override explicitly sized Airbender pools.
        #[arg(long, env = "ZKSYNC_SNARK_CPU_DEFAULT_THREADS", default_value = "16")]
        cpu_default_threads: NonZeroUsize,
        /// SYSCOIN: Sequencer URL(s) for oldest-unassigned-head scheduling. Comma-separated.
        ///
        /// Format: http[s]://[username:password@]host:port. Do not put credentials on argv; set
        /// `ZKSYNC_SEQUENCER_URLS` from an owner-only secret file instead.
        ///
        /// Credentials are extracted and sent via HTTP Authorization headers.
        #[arg(
            short,
            long,
            alias = "sequencer-url",
            value_delimiter = ',',
            num_args = 1..,
            env = "ZKSYNC_SEQUENCER_URLS",
            hide_env_values = true,
            default_value = "http://localhost:3124"
        )]
        sequencer_urls: Vec<OpaqueSequencerEndpoint>,
        #[clap(flatten)]
        setup: SetupOptions,
        /// Path to `app.bin` bound into the SNARK VK (its `.text` sibling is derived).
        /// Must be the same binary the FRI provers run. Defaults to the repo's
        /// `multiblock_batch.bin`.
        #[arg(long)]
        app_bin_path: Option<PathBuf>,
        /// Host wrapper caches: warm (default), or cpu-cold to release caches between jobs.
        /// cpu-cold is rejected by GPU builds and repeats setup to reduce live host memory.
        #[arg(long, value_enum, default_value_t = WrapperCachePolicy::Warm)]
        wrapper_cache_policy: WrapperCachePolicy,
        /// Load the checked-in commitment by default; recompute is for artifact validation/upgrades.
        #[arg(long, env = "ZKSYNC_SNARK_BINARY_COMMITMENT_POLICY", value_enum, default_value_t = BinaryCommitmentPolicy::Bundled)]
        binary_commitment_policy: BinaryCommitmentPolicy,
        /// Number of iterations before exiting. Only successfully generated proofs count. If not specified, runs indefinitely
        #[arg(long)]
        iterations: Option<usize>,
        /// SYSCOIN: Dedicated default metrics port for parallel GPU workers.
        #[arg(long, default_value = "3126")]
        prometheus_port: u16,
        /// Metrics listener IP. Use 127.0.0.1 for private SSH-forwarded monitoring.
        #[arg(long, default_value = "0.0.0.0")]
        prometheus_bind_address: std::net::IpAddr,
        /// SYSCOIN: Total HTTP request backstop in seconds. Connect timeout is 5s and
        /// read-inactivity timeout is 10s.
        #[arg(long, default_value = "600")]
        request_timeout_secs: u64,
        /// Disable ZK for SNARK proofs
        #[arg(long, default_value_t = false)]
        disable_zk: bool,
        /// Name of the prover for identification in the sequencer
        #[arg(long, default_value = "unknown_prover")]
        prover_name: String,
        /// SYSCOIN: Explicit absolute owner-only durable exact proof/capability spool.
        #[arg(long)]
        submission_dir: PathBuf,
        /// SYSCOIN: Explicit isolated-network escape hatch. Remote production uses HTTPS.
        #[arg(long, default_value_t = false)]
        allow_insecure_sequencer_http: bool,
    },
}

// SYSCOIN: Startup replay owns a crash-retained proof and may retry indefinitely. Race it with the
// process signal before any wrapper task exists; on shutdown, wake and await the replay so its
// already-fsynced envelope remains intact, then tell the caller not to initialize proving state.
async fn replay_before_wrapper<R, S>(
    replay: R,
    shutdown: S,
    stop_sender: &watch::Sender<bool>,
) -> anyhow::Result<bool>
where
    R: Future<Output = anyhow::Result<usize>>,
    S: Future<Output = anyhow::Result<()>>,
{
    tokio::pin!(replay);
    tokio::pin!(shutdown);
    tokio::select! {
        biased;
        signal = &mut shutdown => {
            signal.context("failed to listen for SNARK prover shutdown")?;
            stop_sender.send_replace(true);
            // SYSCOIN: A definitive rejection may retire the envelope concurrently with Ctrl-C.
            // Propagate replay's result so that race cannot be reported as a clean retained exit.
            replay.await.context("startup replay failed during shutdown")?;
            Ok(false)
        }
        result = &mut replay => {
            result.context("failed to resume durable prover submissions")?;
            Ok(true)
        }
    }
}

// SYSCOIN: Every startup/prover exit signals and drains the auxiliary exporter. A stuck exporter is
// explicitly aborted after the bounded grace period instead of being detached during runtime drop.
async fn stop_metrics(
    stop_sender: &watch::Sender<bool>,
    metrics_handle: &mut tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    stop_sender.send_replace(true);
    match tokio::time::timeout(Duration::from_secs(10), &mut *metrics_handle).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => {
            tracing::warn!("metrics exporter failed during shutdown: {error:#}");
        }
        Ok(Err(join_error)) => {
            tracing::warn!("metrics task panicked or was cancelled: {join_error}");
        }
        Err(error) => {
            tracing::error!("metrics exporter timed out while shutting down, aborting: {error}");
            metrics_handle.abort();
            let _ = metrics_handle.await;
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // SYSCOIN: Apply process affinity/environment before tracing, Tokio, Rayon or
    // any proving thread can be created. Docker, native releases and rentals all
    // enter here. Verification and the shared library do not acquire this policy.
    let cpu_startup = if let Commands::RunProver {
        cpu_policy,
        cpu_max_logical,
        cpu_default_threads,
        ..
    } = &cli.command
    {
        let config = cpu_startup::Config {
            policy: cpu_policy.parse().map_err(anyhow::Error::msg)?,
            max_logical: cpu_max_logical.get(),
            default_threads: cpu_default_threads.get(),
        };
        // SAFETY: This executable has not spawned any threads or initialized
        // tracing/runtime/proving libraries. Cli::parse is synchronous.
        Some(
            unsafe { cpu_startup::apply(config, cfg!(feature = "gpu")) }
                .context("failed to apply SNARK CPU startup policy")?,
        )
    } else {
        None
    };
    init_tracing();
    if let Some(policy) = cpu_startup {
        tracing::info!("SNARK CPU startup: {policy}");
    }

    // Verification must remain available without initializing proving, GPU, or CRS state.
    if let Commands::VerifyFri {
        payload,
        expected,
        output,
    } = &cli.command
    {
        let paths = (payload.clone(), expected.clone(), output.clone());
        return std::thread::Builder::new()
            .name("native-fri-verifier".into())
            .stack_size(256 * 1024 * 1024)
            .spawn(move || {
                zksync_os_snark_prover::fri_verify::verify_files(&paths.0, &paths.1, &paths.2)
            })?
            .join()
            .map_err(|_| anyhow::anyhow!("native FRI verifier panicked"))?;
    }

    // Circuit synthesis in the SNARK wrapper chain exhausts the default stack, and the
    // main thread's size is fixed by the OS. Give every thread the runtime spawns
    // (workers and blocking threads alike) an explicit stack size: it only limits
    // how far the stack may grow, nothing is allocated up front. RUST_MIN_STACK, when set,
    // is used as-is (so constrained environments can also lower it); otherwise 256 MiB.
    let stack_size = std::env::var("RUST_MIN_STACK")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(256 * 1024 * 1024);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(stack_size)
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    match cli.command {
        Commands::VerifyFri { .. } => unreachable!("verification returned before prover startup"),
        Commands::RunProver {
            cpu_policy: _,
            cpu_max_logical: _,
            cpu_default_threads: _,
            sequencer_urls,
            setup:
                SetupOptions {
                    output_dir,
                    trusted_setup_file,
                },
            app_bin_path,
            wrapper_cache_policy,
            binary_commitment_policy,
            iterations,
            prometheus_port,
            prometheus_bind_address,
            request_timeout_secs,
            disable_zk,
            prover_name,
            submission_dir,
            allow_insecure_sequencer_http,
        } => {
            // Fail before clients, replay, metrics or any wrapper initialization.
            wrapper_cache_policy.validate_supported()?;
            // SYSCOIN: Keep secret-backed endpoint values opaque to Clap's diagnostic renderer;
            // semantic validation runs here with index-only context.
            let sequencer_urls = parse_configured_sequencer_endpoints(sequencer_urls)?;
            // Default to the repo's app binary, mirroring the FRI prover / prover service.
            let manifest_path =
                std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
            let app_bin_path = app_bin_path
                .unwrap_or_else(|| Path::new(&manifest_path).join("../../multiblock_batch.bin"));
            let (stop_sender, stop_receiver) = watch::channel(false);
            let metrics_stop_receiver = stop_receiver.clone();

            runtime.block_on(async move {
                let timeout = Duration::from_secs(request_timeout_secs);

                tracing::info!(
                    "Creating {} sequencer proof clients for urls: {:?}",
                    sequencer_urls.len(),
                    sequencer_urls
                );
                let supported_versions = SupportedProtocolVersions::default();
                // SYSCOIN: Refuse to start before the app-bound release VK is generated.
                supported_versions
                    .ensure_syscoin_release_constants()
                    .map_err(anyhow::Error::msg)?;
                // SYSCOIN: Standalone SNARK workers use the same exclusively locked durable
                // proof/capability spool as the combined service before any wrapper setup.
                let clients = SequencerProofClient::new_durable_clients(
                    sequencer_urls,
                    prover_name,
                    Some(timeout),
                    supported_versions.vk_hashes(),
                    submission_dir,
                    stop_receiver.clone(),
                    allow_insecure_sequencer_http,
                )
                .context("failed to create sequencer proof clients")?;

                let mut metrics_handle = tokio::spawn(async move {
                    metrics::start_metrics_exporter_at(
                        prometheus_bind_address,
                        prometheus_port,
                        metrics_stop_receiver,
                    )
                    .await
                });
                // SYSCOIN: Keep one signal listener alive across replay and proving so no Ctrl-C
                // can fall into a registration gap between the two phases.
                // SYSCOIN: One registered future spans replay and proving for both SIGINT and the
                // SIGTERM used by service managers/containers, with no signal-registration gap.
                let mut shutdown = Box::pin(wait_for_operator_shutdown());

                // SYSCOIN: Drain crash-retained exact submissions before wrapper setup/new picks,
                // while Ctrl-C can still retain that envelope and exit without starting a wrapper.
                let startup = replay_before_wrapper(
                    resume_pending_submissions(&clients),
                    shutdown.as_mut(),
                    &stop_sender,
                )
                .await;
                let should_start_wrapper = match startup {
                    Ok(should_start_wrapper) => should_start_wrapper,
                    Err(error) => {
                        stop_metrics(&stop_sender, &mut metrics_handle).await;
                        return Err(error);
                    }
                };
                if !should_start_wrapper {
                    tracing::info!("SNARK prover stopped during durable startup replay");
                    stop_metrics(&stop_sender, &mut metrics_handle).await;
                    return Ok::<(), anyhow::Error>(());
                }

                tracing::info!(
                    "Starting zksync_os_snark_prover with request timeout of {}s",
                    request_timeout_secs
                );

                // SYSCOIN: The proving chain is synchronous and stack-hungry; drive it from a
                // runtime blocking thread (which gets the explicit stack size above)
                // rather than polling it on the OS-sized main thread via `block_on`.
                let runtime_handle = tokio::runtime::Handle::current();
                let mut prover_task = tokio::task::spawn_blocking(move || {
                    runtime_handle.block_on(run_linking_fri_snark_with_policies(
                        clients,
                        output_dir,
                        trusted_setup_file,
                        app_bin_path,
                        iterations,
                        disable_zk,
                        stop_receiver,
                        wrapper_cache_policy,
                        binary_commitment_policy,
                    ))
                });

                let prover_result = tokio::select! {
                    result = &mut prover_task => {
                        tracing::info!("SNARK prover finished");
                        match result {
                            Ok(result) => result.context("SNARK prover finished with error"),
                            Err(error) => Err(anyhow::anyhow!("SNARK prover task panicked: {error}")),
                        }
                    }
                    signal = shutdown.as_mut() => {
                        tracing::info!("Stop request received; waiting for any in-flight proof to finish");
                        // SYSCOIN: Do not abandon an acquired proof during operator shutdown.
                        stop_sender.send_replace(true);
                        let task_result = match prover_task.await {
                            Ok(result) => result.context("SNARK prover finished with error during shutdown"),
                            Err(error) => Err(anyhow::anyhow!("SNARK prover task panicked during shutdown: {error}")),
                        };
                        match signal {
                            Ok(()) => task_result,
                            Err(error) => Err(error).context("failed to listen for SNARK prover shutdown"),
                        }
                    },
                };

                stop_metrics(&stop_sender, &mut metrics_handle).await;
                prover_result
            })?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn bundled_commitment_is_default_with_explicit_recompute_option() {
        let command = || {
            Cli::command().mut_subcommand("run-prover", |cmd| {
                cmd.mut_arg("binary_commitment_policy", |arg| arg.env(None::<&str>))
            })
        };
        let base = [
            "snark-prover",
            "run-prover",
            "--output-dir",
            "out",
            "--trusted-setup-file",
            "setup.key",
            "--submission-dir",
            "/tmp/snark-commitment-test-spool",
        ];
        let matches = command().try_get_matches_from(base).unwrap();
        assert_eq!(
            matches
                .subcommand_matches("run-prover")
                .unwrap()
                .get_one::<BinaryCommitmentPolicy>("binary_commitment_policy"),
            Some(&BinaryCommitmentPolicy::Bundled)
        );
        for (value, expected) in [
            ("bundled", BinaryCommitmentPolicy::Bundled),
            ("recompute", BinaryCommitmentPolicy::Recompute),
        ] {
            let matches = command()
                .try_get_matches_from(
                    base.into_iter()
                        .chain(["--binary-commitment-policy", value]),
                )
                .unwrap();
            assert_eq!(
                matches
                    .subcommand_matches("run-prover")
                    .unwrap()
                    .get_one::<BinaryCommitmentPolicy>("binary_commitment_policy"),
                Some(&expected)
            );
        }
        assert!(command()
            .try_get_matches_from(
                base.into_iter()
                    .chain(["--binary-commitment-policy", "unknown"])
            )
            .is_err());
    }

    #[test]
    fn cpu_startup_policy_defaults_and_limits_are_explicit() {
        // Clear only these Clap argument environment sources, not process-global
        // environment, so parallel tests also work in an operator's configured shell.
        let command = || {
            Cli::command().mut_subcommand("run-prover", |cmd| {
                cmd.mut_arg("cpu_policy", |arg| arg.env(None::<&str>))
                    .mut_arg("cpu_max_logical", |arg| arg.env(None::<&str>))
                    .mut_arg("cpu_default_threads", |arg| arg.env(None::<&str>))
            })
        };
        let base = [
            "snark-prover",
            "run-prover",
            "--output-dir",
            "out",
            "--trusted-setup-file",
            "setup.key",
            "--submission-dir",
            "/tmp/snark-test-spool",
        ];
        let matches = command().try_get_matches_from(base).unwrap();
        let args = matches.subcommand_matches("run-prover").unwrap();
        assert_eq!(args.get_one::<String>("cpu_policy").unwrap(), "auto");
        assert_eq!(
            args.get_one::<NonZeroUsize>("cpu_max_logical")
                .unwrap()
                .get(),
            31
        );
        assert_eq!(
            args.get_one::<NonZeroUsize>("cpu_default_threads")
                .unwrap()
                .get(),
            16
        );
        for flag in ["--cpu-max-logical", "--cpu-default-threads"] {
            for bad in ["0", "-1", "not-a-number"] {
                assert!(command()
                    .try_get_matches_from(base.into_iter().chain([flag, bad]))
                    .is_err());
            }
        }
        assert!(command()
            .try_get_matches_from(base.into_iter().chain(["--cpu-policy", "unknown"]))
            .is_err());
        for policy in ["bounded", "inherit"] {
            assert!(command()
                .try_get_matches_from(base.into_iter().chain(["--cpu-policy", policy]))
                .is_ok());
        }
    }

    #[test]
    fn wrapper_cache_policy_is_typed_opt_in() {
        let base = [
            "snark-prover",
            "run-prover",
            "--output-dir",
            "out",
            "--trusted-setup-file",
            "setup.key",
            "--submission-dir",
            "/tmp/snark-test-spool",
        ];
        let Commands::RunProver {
            wrapper_cache_policy,
            ..
        } = Cli::try_parse_from(base).unwrap().command
        else {
            panic!("expected run-prover command");
        };
        assert_eq!(wrapper_cache_policy, WrapperCachePolicy::Warm);
        let Commands::RunProver {
            wrapper_cache_policy,
            ..
        } = Cli::try_parse_from(
            base.into_iter()
                .chain(["--wrapper-cache-policy", "cpu-cold"]),
        )
        .unwrap()
        .command
        else {
            panic!("expected run-prover command");
        };
        assert_eq!(wrapper_cache_policy, WrapperCachePolicy::CpuCold);
        assert!(Cli::try_parse_from(
            base.into_iter()
                .chain(["--wrapper-cache-policy", "unbounded"])
        )
        .is_err());
        assert_eq!(
            wrapper_cache_policy.validate_supported().is_ok(),
            !cfg!(feature = "gpu") && cfg!(unix)
        );
    }

    #[test]
    fn prometheus_bind_address_is_explicit_and_preserves_default() {
        let base = [
            "snark-prover",
            "run-prover",
            "--output-dir",
            "out",
            "--trusted-setup-file",
            "setup.key",
            "--submission-dir",
            "/tmp/snark-test-spool",
        ];
        let defaults = Cli::try_parse_from(base).unwrap();
        let Commands::RunProver {
            prometheus_bind_address,
            prometheus_port,
            ..
        } = defaults.command
        else {
            panic!("expected run-prover command");
        };
        assert_eq!(prometheus_bind_address.to_string(), "0.0.0.0");
        assert_eq!(prometheus_port, 3126);
        for ip in ["127.0.0.1", "::1"] {
            let cli = Cli::try_parse_from(base.into_iter().chain([
                "--prometheus-bind-address",
                ip,
                "--prometheus-port",
                "43126",
            ]))
            .unwrap();
            let Commands::RunProver {
                prometheus_bind_address,
                prometheus_port,
                ..
            } = cli.command
            else {
                panic!("expected run-prover command");
            };
            assert_eq!(prometheus_bind_address.to_string(), ip);
            assert_eq!(prometheus_port, 43126);
        }
        assert!(Cli::try_parse_from(
            base.into_iter()
                .chain(["--prometheus-bind-address", "not-an-ip"])
        )
        .is_err());
    }

    // SYSCOIN: A shutdown that arrives during retained-envelope replay signals the HTTP retry,
    // awaits its durable exit, and returns false so the wrapper/spawn path cannot run.
    #[tokio::test]
    async fn startup_shutdown_propagates_replay_failure() {
        let (stop_sender, mut stop_receiver) = watch::channel(false);
        let replay = async move {
            stop_receiver.changed().await.unwrap();
            anyhow::bail!("submission deferred by shutdown; durable envelope retained")
        };
        let error = replay_before_wrapper(replay, std::future::ready(Ok(())), &stop_sender)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("startup replay failed"));
        assert!(*stop_sender.borrow());
    }

    // SYSCOIN: Standalone wrapping keeps credential text opaque to Clap and hides env values in
    // subcommand help, matching the FRI and combined binaries.
    #[test]
    fn cli_endpoint_validation_is_deferred_and_env_help_is_redacted() {
        let secret = "snark-clap-password-secret";
        let cli = Cli::try_parse_from([
            "snark-prover",
            "run-prover",
            "--output-dir",
            "out",
            "--trusted-setup-file",
            "setup.key",
            "--submission-dir",
            "/tmp/snark-prover-test-submissions",
            "--sequencer-urls",
            &format!("https://:{secret}@sequencer.example/"),
        ])
        .expect("opaque endpoint must not fail inside Clap");
        let Commands::RunProver { sequencer_urls, .. } = cli.command else {
            panic!("expected run-prover command");
        };
        let error = parse_configured_sequencer_endpoints(sequencer_urls).unwrap_err();
        assert!(!format!("{error:#}").contains(secret));

        let command = Cli::command();
        let run = command
            .find_subcommand("run-prover")
            .expect("run-prover subcommand");
        let endpoint = run
            .get_arguments()
            .find(|argument| argument.get_id() == "sequencer_urls")
            .expect("sequencer_urls argument");
        assert!(endpoint.is_hide_env_values_set());
    }

    #[test]
    fn cpu_verification_needs_no_prover_setup_or_endpoint_arguments() {
        let cli = Cli::try_parse_from([
            "snark-prover",
            "verify-fri",
            "--payload",
            "/tmp/payload.json",
            "--expected",
            "/tmp/expected.json",
            "--output",
            "/tmp/result.json",
        ])
        .unwrap();
        assert!(matches!(cli.command, Commands::VerifyFri { .. }));
    }
}
