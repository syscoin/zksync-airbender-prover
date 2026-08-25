use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use protocol_version::SupportedProtocolVersions;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use zksync_os_snark_prover::{init_tracing, metrics, run_linking_fri_snark};
use zksync_sequencer_proof_client::{
    parse_configured_sequencer_endpoints, resume_pending_submissions, wait_for_operator_shutdown,
    OpaqueSequencerEndpoint, SequencerProofClient,
};

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
    RunProver {
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
        /// Number of iterations before exiting. Only successfully generated proofs count. If not specified, runs indefinitely
        #[arg(long)]
        iterations: Option<usize>,
        /// SYSCOIN: Dedicated default metrics port for parallel GPU workers.
        #[arg(long, default_value = "3126")]
        prometheus_port: u16,
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
    init_tracing();
    let cli = Cli::parse();

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
        Commands::RunProver {
            sequencer_urls,
            setup:
                SetupOptions {
                    output_dir,
                    trusted_setup_file,
                },
            app_bin_path,
            iterations,
            prometheus_port,
            request_timeout_secs,
            disable_zk,
            prover_name,
            submission_dir,
            allow_insecure_sequencer_http,
        } => {
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
                    metrics::start_metrics_exporter(prometheus_port, metrics_stop_receiver).await
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
                    runtime_handle.block_on(run_linking_fri_snark(
                        clients,
                        output_dir,
                        trusted_setup_file,
                        app_bin_path,
                        iterations,
                        disable_zk,
                        stop_receiver,
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
        let Commands::RunProver { sequencer_urls, .. } = cli.command;
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
}
