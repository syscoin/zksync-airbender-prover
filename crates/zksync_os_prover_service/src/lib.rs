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
use tracing_subscriber::{EnvFilter, FmtSubscriber};
#[cfg(feature = "gpu")]
use zkos_wrapper::gpu::snark::gpu_create_snark_setup_data;
use zksync_airbender_cli::prover_utils::load_binary_from_path;
#[cfg(not(feature = "gpu"))]
use zksync_airbender_cli::prover_utils::GpuSharedState;
#[cfg(feature = "gpu")]
use zksync_airbender_cli::prover_utils::GpuSharedState;
use zksync_airbender_execution_utils::{get_padded_binary, UNIVERSAL_CIRCUIT_VERIFIER};
#[cfg(feature = "gpu")]
use zksync_os_snark_prover::compute_compression_vk;
use zksync_sequencer_proof_client::{JobQueueStage, SequencerEndpoint, SequencerProofClient};

/// Command-line arguments for the Zksync OS prover
#[derive(Parser, Debug)]
#[command(name = "Zksync OS Prover")]
#[command(version = "1.0")]
#[command(about = "Prover for Zksync OS", long_about = None)]
pub struct Args {
    /// Max SNARK latency in seconds (default value - 1 hour)
    #[arg(long, default_value = "3600", conflicts_with = "max_fris_per_snark")]
    pub max_snark_latency: Option<u64>,
    /// Max amount of FRI proofs per SNARK (default value - 100)
    #[arg(long, default_value = "100", conflicts_with = "max_snark_latency")]
    pub max_fris_per_snark: Option<usize>,
    /// Max time to wait for a SNARK job after switching away from FRI proving
    #[arg(long, default_value = "60")]
    pub snark_acquire_timeout_secs: u64,
    /// Sequencer URL(s) for polling tasks. Comma-separated for round-robin.
    ///
    /// Format: http[s]://[username:password@]host:port
    ///
    /// Examples:
    ///   --sequencer-urls http://localhost:3124,https://user1:pass1@sequencer1.com:3124,https://user2:pass2@sequencer2.com
    ///
    /// Credentials are extracted and sent via HTTP Authorization headers.
    #[arg(
        short,
        long,
        alias = "base-url",
        value_delimiter = ',',
        num_args = 1..,
        default_value = "http://localhost:3124"
    )]
    pub sequencer_urls: Vec<SequencerEndpoint>,
    /// Path to `app.bin`
    #[arg(long)]
    pub app_bin_path: Option<PathBuf>,
    /// Circuit limit - max number of MainVM circuits to instantiate to run the batch fully
    #[arg(long, default_value = "10000")]
    pub circuit_limit: usize,
    /// Directory to store the output files for SNARK prover
    #[arg(long)]
    pub output_dir: String,
    /// Path to the trusted setup file for SNARK prover
    #[arg(long)]
    pub trusted_setup_file: String,
    /// Number of iterations before exiting. Only successfully generated SNARK proofs count. If not specified, runs indefinitely
    #[arg(long)]
    pub iterations: Option<usize>,
    /// Path to the output file for FRI proofs
    #[arg(short, long)]
    pub fri_path: Option<PathBuf>,
    /// Disable ZK for SNARK proofs
    #[arg(long, default_value_t = false)]
    pub disable_zk: bool,
}

const SNARK_POLL_INTERVAL: Duration = Duration::from_secs(1);

async fn acquire_snark_proof<F, Fut>(
    snark_acquire_timeout: Duration,
    poll_interval: Duration,
    mut run_snark_attempt: F,
) -> anyhow::Result<bool>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<bool>>,
{
    let started_at = Instant::now();
    loop {
        if run_snark_attempt().await? {
            return Ok(true);
        }

        if started_at.elapsed() >= snark_acquire_timeout {
            return Ok(false);
        }

        tokio::time::sleep(poll_interval).await;
    }
}
// SYSCOIN
async fn pick_oldest_unassigned_client(
    clients: &[Box<dyn zksync_sequencer_proof_client::ProofClient + Send + Sync>],
    stage: JobQueueStage,
) -> Option<usize> {
    let mut best: Option<(usize, u64, u32)> = None;
    for (idx, client) in clients.iter().enumerate() {
        let Ok(statuses) = client.status(stage).await else {
            continue;
        };
        let oldest_unassigned = statuses
            .iter()
            .filter(|s| s.assigned_seconds_ago.is_none())
            .max_by_key(|s| s.added_seconds_ago);
        let Some(oldest_unassigned) = oldest_unassigned else {
            continue;
        };

        let candidate = (idx, oldest_unassigned.added_seconds_ago, oldest_unassigned.batch_number);
        best = match best {
            Some(current) => {
                if (candidate.1, std::cmp::Reverse(candidate.2))
                    > (current.1, std::cmp::Reverse(current.2))
                {
                    Some(candidate)
                } else {
                    Some(current)
                }
            }
            None => Some(candidate),
        };
    }
    best.map(|(idx, _, _)| idx)
}

async fn ordered_client_indices_for_stage(
    clients: &[Box<dyn zksync_sequencer_proof_client::ProofClient + Send + Sync>],
    stage: JobQueueStage,
) -> Vec<usize> {
    let mut scored: Vec<(usize, u64, u32)> = Vec::new();
    for (idx, client) in clients.iter().enumerate() {
        let best = client
            .status(stage)
            .await
            .ok()
            .and_then(|statuses| {
                statuses
                    .iter()
                    .filter(|s| s.assigned_seconds_ago.is_none())
                    .max_by_key(|s| s.added_seconds_ago)
                    .map(|s| (s.added_seconds_ago, s.batch_number))
            })
            .unwrap_or((0, u32::MAX));
        scored.push((idx, best.0, best.1));
    }
    scored.sort_by_key(|(idx, age, batch)| (std::cmp::Reverse(*age), *batch, *idx));
    scored.into_iter().map(|(idx, _, _)| idx).collect()
}

pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    FmtSubscriber::builder().with_env_filter(filter).init();
}

pub async fn run(args: Args) -> anyhow::Result<()> {
    tracing::info!(
        "Creating {} sequencer proof clients for urls: {:?}",
        args.sequencer_urls.len(),
        args.sequencer_urls
    );
    let clients =
        SequencerProofClient::new_clients(args.sequencer_urls, "prover_service".to_string(), None)
            .context("failed to create sequencer proof clients")?;

    let manifest_path = if let Ok(manifest_path) = std::env::var("CARGO_MANIFEST_DIR") {
        manifest_path
    } else {
        ".".to_string()
    };
    let binary_path = args
        .app_bin_path
        .unwrap_or_else(|| Path::new(&manifest_path).join("../../multiblock_batch.bin"));
    let binary = load_binary_from_path(&binary_path.to_str().unwrap().to_string());
    let verifier_binary = get_padded_binary(UNIVERSAL_CIRCUIT_VERIFIER);

    let supported_versions = SupportedProtocolVersions::default();
    tracing::info!("{:#?}", supported_versions);

    #[cfg(feature = "gpu")]
    let precomputations = {
        tracing::info!("Computing SNARK precomputations");
        let compression_vk = compute_compression_vk(binary_path.to_str().unwrap().to_string());
        let precomputations =
            gpu_create_snark_setup_data(&compression_vk, &args.trusted_setup_file);
        tracing::info!("Finished computing SNARK precomputations");
        precomputations
    };

    tracing::info!("Starting Zksync OS Prover Service");
    // SYSCOIN
    let mut snark_proof_count = 0;
    let mut snark_latency = Instant::now();
    let mut fri_proof_count = 0usize;
    let retry_interval = Duration::from_millis(100);

    // Keep FRI GPU state warm across the entire service lifetime.
    #[cfg(feature = "gpu")]
    let mut gpu_state = GpuSharedState::new(
        &binary,
        zksync_airbender_cli::prover_utils::MainCircuitType::ReducedRiscVMachine,
    );
    #[cfg(not(feature = "gpu"))]
    let mut gpu_state = GpuSharedState::new(&binary);

    loop {
        // Run FRI until one of the configured handoff conditions is met.
        loop {
            let Some(client_idx) =
                pick_oldest_unassigned_client(&clients, JobQueueStage::Fri).await
            else {
                tokio::time::sleep(retry_interval).await;
                if let Some(max_snark_latency) = args.max_snark_latency
                    && snark_latency.elapsed().as_secs() >= max_snark_latency
                {
                    tracing::info!(
                        "SNARK latency reached max_snark_latency ({max_snark_latency} seconds), switching to SNARK phase"
                    );
                    break;
                }
                continue;
            };
            let client = &clients[client_idx];

            let proof_generated = zksync_os_fri_prover::run_inner(
                client.as_ref(),
                &binary,
                args.circuit_limit,
                &mut gpu_state,
                args.fri_path.clone(),
                &supported_versions,
            )
            .await
            .expect("Failed to run FRI prover");

            fri_proof_count += proof_generated as usize;

            if let Some(max_snark_latency) = args.max_snark_latency
                && snark_latency.elapsed().as_secs() >= max_snark_latency
            {
                tracing::info!(
                    "SNARK latency reached max_snark_latency ({max_snark_latency} seconds), switching to SNARK phase"
                );
                break;
            }
            if let Some(max_fris_per_snark) = args.max_fris_per_snark
                && fri_proof_count >= max_fris_per_snark
            {
                tracing::info!(
                    "FRI proof count reached max_fris_per_snark ({max_fris_per_snark}), switching to SNARK phase"
                );
                break;
            }
        }

        let proof_generated = acquire_snark_proof(
            Duration::from_secs(args.snark_acquire_timeout_secs),
            SNARK_POLL_INTERVAL,
            || async {
                let ordered_indices =
                    ordered_client_indices_for_stage(&clients, JobQueueStage::Snark).await;
                for idx in ordered_indices {
                    let client = &clients[idx];
                    if zksync_os_snark_prover::run_inner(
                        client.as_ref(),
                        &verifier_binary,
                        args.output_dir.clone(),
                        args.trusted_setup_file.clone(),
                        #[cfg(feature = "gpu")]
                        &precomputations,
                        args.disable_zk,
                        &supported_versions,
                    )
                    .await
                    .expect("Failed to run SNARK prover")
                    {
                        return Ok(true);
                    }
                }
                Ok(false)
            },
        )
        .await
        .expect("Failed to run SNARK prover");

        if proof_generated {
            tracing::info!("Successfully generated a SNARK proof");
            snark_proof_count += 1;
        } else {
            tracing::info!(
                "No SNARK proof was generated within snark_acquire_timeout_secs ({} seconds), returning to FRI phase",
                args.snark_acquire_timeout_secs
            );
        }

        // Reset phase counters.
        snark_latency = Instant::now();
        fri_proof_count = 0;

        if let Some(max_iterations) = args.iterations
            && snark_proof_count >= max_iterations
        {
            tracing::info!("Reached maximum iterations ({max_iterations}), exiting...");
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

    #[tokio::test]
    async fn snark_acquire_times_out_instead_of_looping_forever() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_for_closure = attempts.clone();

        let acquired = tokio::time::timeout(
            Duration::from_millis(100),
            acquire_snark_proof(
                Duration::from_millis(20),
                Duration::from_millis(1),
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
}

