use std::time::Duration;

use anyhow::Context as _;
use clap::Parser;
use tokio::sync::watch;
use zksync_os_prover_service::{init_tracing, metrics};

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    init_tracing();
    let args = zksync_os_prover_service::Args::parse();

    let (stop_sender, stop_receiver) = watch::channel(false);
    let service_stop_receiver = stop_receiver.clone();

    let prometheus_port = args.prometheus_port;

    let mut metrics_handle = tokio::spawn(async move {
        metrics::start_metrics_exporter(prometheus_port, stop_receiver).await
    });
    let mut service = Box::pin(zksync_os_prover_service::run(args, service_stop_receiver));

    let (service_result, metrics_task_finished) = tokio::select! {
        result = &mut service => {
            match &result {
                Ok(_) => tracing::info!("Zksync OS Prover Service finished successfully"),
                Err(e) => tracing::error!("Zksync OS Prover Service finished with error: {e:#}"),
            }
            stop_sender.send_replace(true);
            (result, false)
        }
        metrics_result = &mut metrics_handle => {
            let result = match metrics_result {
                Ok(Ok(())) => Err(anyhow::anyhow!("metrics exporter stopped unexpectedly")),
                Ok(Err(e)) => Err(e).context("metrics exporter failed"),
                Err(join_err) => Err(anyhow::anyhow!(
                    "metrics task panicked or was cancelled: {join_err}"
                )),
            };
            stop_sender.send_replace(true);
            // SYSCOIN: Stop queue polling cooperatively and retain any currently leased proof
            // through submission even when the auxiliary exporter fails.
            if let Err(service_err) = service.await {
                tracing::error!("Prover service also failed during metrics shutdown: {service_err:#}");
            }
            (result, true)
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Stop request received; waiting for any in-flight proof to finish");
            stop_sender.send_replace(true);
            // SYSCOIN: Dropping `run` here could abandon an acquired FRI or SNARK lease.
            (service.await, false)
        },
    };

    if !metrics_task_finished {
        match tokio::time::timeout(Duration::from_secs(10), &mut metrics_handle).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => {
                tracing::error!("Metrics exporter failed while shutting down: {e:#}");
            }
            Ok(Err(join_err)) => {
                tracing::warn!("metrics task panicked or was cancelled: {join_err}");
            }
            Err(e) => {
                tracing::error!("Metrics exporter timed out while shutting down, aborting: {e}");
                metrics_handle.abort();
            }
        }
    }

    service_result
}
