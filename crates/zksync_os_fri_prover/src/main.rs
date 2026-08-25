use std::time::Duration;

use clap::Parser;
use tokio::sync::watch;
use zksync_os_fri_prover::{init_tracing, metrics};
use zksync_sequencer_proof_client::wait_for_operator_shutdown;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    init_tracing();
    let args = zksync_os_fri_prover::Args::parse();

    let (stop_sender, stop_receiver) = watch::channel(false);
    // SYSCOIN: Metrics and proving need independent receivers so one shutdown signal can wake
    // both while the prover future remains owned until any acquired lease is durably handed off.
    let metrics_stop_receiver = stop_receiver.clone();

    let prometheus_port = args.prometheus_port;

    let metrics_handle = tokio::spawn(async move {
        metrics::start_metrics_exporter(prometheus_port, metrics_stop_receiver).await
    });

    // SYSCOIN: Retain and await the in-flight prover future across Ctrl-C instead of dropping it.
    let mut prover = Box::pin(zksync_os_fri_prover::run(args, stop_receiver));
    let result = tokio::select! {
        err = &mut prover => {
            match err {
                Ok(_) => tracing::info!("Zksync OS FRI prover finished successfully"),
                Err(ref e) => tracing::error!("Zksync OS FRI prover finished with error: {e}"),
            }
            // SYSCOIN: The metrics task may already have stopped and dropped its receiver.
            stop_sender.send_replace(true);
            err
        }
        // SYSCOIN: Production supervisors stop with SIGTERM; interactive terminals use SIGINT.
        signal = wait_for_operator_shutdown() => {
            tracing::info!("Operator stop request received; retaining any generated submission envelope");
            // SYSCOIN: Submission HTTP/retry waits observe this signal and return promptly with the
            // fsynced envelope retained; the worker then exits before acquiring another lease.
            stop_sender.send_replace(true);
            let prover_result = prover.await;
            match signal {
                Ok(()) => prover_result,
                Err(error) => Err(error),
            }
        },
    };

    match tokio::time::timeout(Duration::from_secs(10), metrics_handle).await {
        Ok(join_result) => {
            if let Err(join_err) = join_result {
                tracing::warn!("metrics task panicked or was cancelled: {join_err}");
            }
        }
        Err(e) => {
            tracing::error!("Metrics exporter timed out, aborting: {e}");
        }
    }

    // SYSCOIN: Propagate a retained-envelope/prover failure to the supervisor instead of turning
    // a failed worker into a clean exit after metrics shutdown.
    result
}
