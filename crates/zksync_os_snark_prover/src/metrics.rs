use core::fmt;
use std::{collections::HashMap, net::Ipv4Addr, time::Duration};

use tokio::{sync::watch, time::Instant};
use vise::{Counter, Gauge, Histogram, Metrics, MetricsCollection};
use vise_exporter::MetricsExporter;

pub async fn start_metrics_exporter(
    port: u16,
    mut stop_receiver: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    tracing::info!("Starting metrics exporter on port {port}");
    let registry = MetricsCollection::lazy().collect();
    let metrics_exporter =
        MetricsExporter::new(registry.into()).with_graceful_shutdown(async move {
            stop_receiver.changed().await.ok();
        });

    let prom_bind_address = (Ipv4Addr::UNSPECIFIED, port).into();
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
#[metrics(prefix = "snark_prover")]
pub struct SnarkProverMetrics {
    #[metrics(buckets = vise::Buckets::linear(50.0..=200.0, 25.0), unit = vise::Unit::Seconds)]
    pub time_taken_startup: Histogram,
    #[metrics(buckets = PROVING_LATENCIES, unit = vise::Unit::Seconds)]
    pub time_taken_merge_fri: Histogram,
    /// SYSCOIN: Time spent building the per-job SNARK wrapper. Both standalone and combined
    /// services drop the wrapper between jobs so it cannot compete with FRI merging
    /// for the GPU (see `WrapperSource`).
    /// The full setup-chain derivation is
    /// paid only by the process's first job; later jobs rehydrate from the host-side
    /// cache in negligible time.
    #[metrics(buckets = vise::Buckets::linear(30.0..=300.0, 30.0), unit = vise::Unit::Seconds)]
    pub time_taken_wrapper_setup: Histogram,
    #[metrics(buckets = vise::Buckets::linear(5.0..=20.0, 2.5), unit = vise::Unit::Seconds)]
    pub time_taken_final_proof: Histogram,
    #[metrics(buckets = PROVING_LATENCIES, unit = vise::Unit::Seconds)]
    pub time_taken_snark: Histogram,
    #[metrics(buckets = PROVING_LATENCIES, unit = vise::Unit::Seconds)]
    pub time_taken_full: Histogram,
    /// Time spent building the merge combiner's caches (unified-level setup and, on
    /// GPU builds, the prover host state). Observed only when a merge found them cold,
    /// normally once per process on the first multi-proof job.
    #[metrics(buckets = vise::Buckets::linear(10.0..=300.0, 30.0), unit = vise::Unit::Seconds)]
    pub time_taken_merge_warm_up: Histogram,
    pub fri_proofs_merged: Gauge,
    /// Number of unified proving passes (combined pass + shrink passes) of the last merge.
    pub merge_unified_passes: Gauge,
    pub latest_proven_batch: Gauge,
    /// Number of timeout errors when communicating with sequencer
    pub timeout_errors: Counter,
}

#[vise::register]
pub(crate) static SNARK_PROVER_METRICS: vise::Global<SnarkProverMetrics> = vise::Global::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SnarkStage {
    MergeFri,
    WrapperSetup,
    FinalProof,
    Snark,
    Full,
}

impl fmt::Display for SnarkStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                SnarkStage::MergeFri => "merge_fri",
                SnarkStage::WrapperSetup => "wrapper_setup",
                SnarkStage::FinalProof => "final_proof",
                SnarkStage::Snark => "snark",
                SnarkStage::Full => "full",
            }
        )
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SnarkProofTimeStats {
    time_taken: HashMap<SnarkStage, Duration>,
}

impl fmt::Display for SnarkProofTimeStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SnarkProofTimeStats {{")?;
        for (stage, duration) in &self.time_taken {
            write!(f, "{stage}: {duration:?}, ")?;
        }
        write!(f, "}}")
    }
}

impl SnarkProofTimeStats {
    pub fn new() -> Self {
        Self {
            time_taken: HashMap::new(),
        }
    }

    pub fn observe_step(&mut self, stage: SnarkStage, duration: Duration) {
        self.time_taken.insert(stage, duration);
        match stage {
            SnarkStage::MergeFri => SNARK_PROVER_METRICS
                .time_taken_merge_fri
                .observe(duration.as_secs_f64()),
            SnarkStage::WrapperSetup => SNARK_PROVER_METRICS
                .time_taken_wrapper_setup
                .observe(duration.as_secs_f64()),
            SnarkStage::FinalProof => SNARK_PROVER_METRICS
                .time_taken_final_proof
                .observe(duration.as_secs_f64()),
            SnarkStage::Snark => SNARK_PROVER_METRICS
                .time_taken_snark
                .observe(duration.as_secs_f64()),
            SnarkStage::Full => SNARK_PROVER_METRICS
                .time_taken_full
                .observe(duration.as_secs_f64()),
        }
    }

    pub fn observe_full(&mut self) {
        let merge_fri = self.time_taken.get(&SnarkStage::MergeFri);
        // SYSCOIN: Wrapper construction moved into the per-job lifecycle, so its cold-cache
        // cost is part of the end-to-end latency used to tune production job leases.
        let wrapper_setup = self.time_taken.get(&SnarkStage::WrapperSetup);
        let final_proof = self.time_taken.get(&SnarkStage::FinalProof);
        let snark = self.time_taken.get(&SnarkStage::Snark);

        if let (Some(merge_fri), Some(wrapper_setup), Some(final_proof), Some(snark)) =
            (merge_fri, wrapper_setup, final_proof, snark)
        {
            let full_duration = *merge_fri + *wrapper_setup + *final_proof + *snark;
            self.observe_step(SnarkStage::Full, full_duration);
        } else {
            tracing::error!("Failed to observe full duration of snark proof, some of the items are missing: {:?}", self.time_taken);
        }
    }

    pub fn measure_step<F, T>(&mut self, stage: SnarkStage, step: F) -> T
    where
        F: FnOnce() -> T,
    {
        let start = Instant::now();
        let result = step();
        self.observe_step(stage, start.elapsed());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_duration_includes_per_job_wrapper_setup() {
        let mut stats = SnarkProofTimeStats::new();
        stats
            .time_taken
            .insert(SnarkStage::MergeFri, Duration::from_secs(1));
        stats
            .time_taken
            .insert(SnarkStage::WrapperSetup, Duration::from_secs(2));
        stats
            .time_taken
            .insert(SnarkStage::FinalProof, Duration::from_secs(3));
        stats
            .time_taken
            .insert(SnarkStage::Snark, Duration::from_secs(4));

        stats.observe_full();

        // SYSCOIN: A regression here would understate cold-wrapper P99 latency and make the
        // sequencer's SNARK lease shorter than the prover's actual end-to-end work.
        assert_eq!(
            stats.time_taken.get(&SnarkStage::Full),
            Some(&Duration::from_secs(10))
        );
    }
}
