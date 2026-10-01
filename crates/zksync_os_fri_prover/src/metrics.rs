use std::net::{IpAddr, Ipv4Addr};

use tokio::sync::watch;
use vise::{Counter, Gauge, Histogram, Metrics, MetricsCollection};
use vise_exporter::MetricsExporter;

pub async fn start_metrics_exporter(
    port: u16,
    stop_receiver: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    start_metrics_exporter_at(Ipv4Addr::UNSPECIFIED.into(), port, stop_receiver).await
}

/// SYSCOIN: Keep private validation listeners on loopback without changing the
/// legacy all-interface exporter API or remote-monitoring default.
pub async fn start_metrics_exporter_at(
    bind_address: IpAddr,
    port: u16,
    mut stop_receiver: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let prom_bind_address = (bind_address, port).into();
    tracing::info!("Starting metrics exporter on {prom_bind_address}");
    let registry = MetricsCollection::lazy().collect();
    let metrics_exporter =
        MetricsExporter::new(registry.into()).with_graceful_shutdown(async move {
            stop_receiver.changed().await.ok();
        });

    metrics_exporter
        .start(prom_bind_address)
        .await
        .map_err(|e| anyhow::anyhow!("Failed starting metrics server: {e}"))?;

    Ok(())
}

const PROVING_LATENCIES: vise::Buckets = vise::Buckets::values(&[
    0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0, 1000.0,
    2000.0, 5000.0, 10_000.0,
]);

#[derive(Debug, Clone, Metrics)]
#[metrics(prefix = "fri_prover")]
pub struct FriProverMetrics {
    #[metrics(buckets = PROVING_LATENCIES, unit = vise::Unit::Seconds)]
    pub time_taken: Histogram,
    pub latest_proven_batch: Gauge,
    /// Number of timeout errors when communicating with sequencer
    pub timeout_errors: Counter,
}

#[vise::register]
pub(crate) static FRI_PROVER_METRICS: vise::Global<FriProverMetrics> = vise::Global::new();
