// TODO: Currently disabled as it's not used anywhere. Needs a rework anyways.
// pub mod file_based_proof_client;

pub mod sequencer_endpoint;
pub mod sequencer_proof_client;

pub use sequencer_endpoint::SequencerEndpoint;
pub use sequencer_proof_client::SequencerProofClient;

use crate::metrics::SEQUENCER_CLIENT_METRICS;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::fmt;
// SYSCOIN: Bound concurrent queue-status hints without delaying normal pick fallbacks.
use std::num::NonZeroUsize;
use std::time::Duration;
use url::Url;
use zkos_wrapper::SnarkWrapperProof;
use zksync_airbender_execution_utils::unrolled::UnrolledProgramProof;

mod metrics;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash, PartialOrd, Ord)]
pub struct L2BatchNumber(pub u32);

impl fmt::Display for L2BatchNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct NextFriProverJobPayload {
    batch_number: u32,
    vk_hash: String,
    prover_input: String, // base64-encoded
}

#[derive(Debug, Serialize, Deserialize)]
struct SubmitFriProofPayload {
    batch_number: u64,
    vk_hash: String,
    proof: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct GetSnarkProofPayload {
    from_batch_number: u64,
    to_batch_number: u64,
    vk_hash: String,
    fri_proofs: Vec<String>, // base64‑encoded FRI proofs
}

#[derive(Debug, Serialize, Deserialize)]
struct SubmitSnarkProofPayload {
    from_batch_number: u64,
    to_batch_number: u64,
    vk_hash: String,
    proof: String, // base64‑encoded SNARK proof
}

// SYSCOIN: Mirror the server's read-only queue status payload for multi-sequencer scheduling.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JobStatusPayload {
    fri_job: JobMetaPayload,
    added_seconds_ago: u64,
    assigned_seconds_ago: Option<u64>,
    assigned_to_prover_id: Option<String>,
    current_attempt: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JobMetaPayload {
    batch_number: u32,
    vk_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FailedFriProofPayload {
    pub batch_number: u64,
    pub last_block_timestamp: u64,
    pub expected_hash_u32s: [u32; 8],
    pub proof_final_register_values: [u32; 16],
    pub vk_hash: String,
    pub proof: String, // base64‑encoded FRI proof
}

impl TryInto<SnarkProofInputs> for GetSnarkProofPayload {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<SnarkProofInputs, Self::Error> {
        let mut fri_proofs = vec![];
        for encoded_proof in self.fri_proofs {
            let (fri_proof, _) = bincode::serde::decode_from_slice(
                &STANDARD.decode(encoded_proof)?,
                bincode::config::standard(),
            )?;
            fri_proofs.push(fri_proof);
        }

        Ok(SnarkProofInputs {
            from_batch_number: L2BatchNumber(
                self.from_batch_number
                    .try_into()
                    .expect("from_batch_number should fit into L2BatchNumber(u32)"),
            ),
            to_batch_number: L2BatchNumber(
                self.to_batch_number
                    .try_into()
                    .expect("to_batch_number should fit into L2BatchNumber(u32)"),
            ),
            vk_hash: self.vk_hash,
            fri_proofs,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SnarkProofInputs {
    pub from_batch_number: L2BatchNumber,
    pub to_batch_number: L2BatchNumber,
    pub vk_hash: String,
    pub fri_proofs: Vec<UnrolledProgramProof>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FriJobInputs {
    pub batch_number: u32,
    pub vk_hash: String,
    pub prover_input: Vec<u8>,
}

/// SYSCOIN: Queue information exposed by the sequencer's read-only status endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueJobStatus {
    pub batch_number: u32,
    pub vk_hash: String,
    pub added_seconds_ago: u64,
    pub assigned_seconds_ago: Option<u64>,
    pub assigned_to_prover_id: Option<String>,
    pub current_attempt: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobQueueStage {
    Fri,
    Snark,
}

/// SYSCOIN: Maximum simultaneous status requests from one prover process.
pub const STATUS_PROBE_CONCURRENCY: NonZeroUsize = NonZeroUsize::new(8).unwrap();
/// Status is only a scheduling hint; never let it block real pick attempts for a healthy peer.
pub const STATUS_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

#[async_trait]
pub trait ProofClient: Send + Sync {
    /// Returns the sequencer URL for logging purposes.
    fn sequencer_url(&self) -> &Url;

    /// Fetch the next FRI batch to prove.
    /// Returns `Ok(None)` if there's no batch pending (204 No Content).
    async fn pick_fri_job(&self) -> anyhow::Result<Option<FriJobInputs>>;

    /// Submit a FRI proof for the processed batch.
    async fn submit_fri_proof(
        &self,
        batch_number: u32,
        vk_hash: String,
        proof: String,
    ) -> anyhow::Result<()>;

    /// SYSCOIN: Read the queue without claiming a job. Scheduling treats this as a hint:
    /// status failures never remove a client from the subsequent pick fallback.
    async fn status(&self, stage: JobQueueStage) -> anyhow::Result<Vec<QueueJobStatus>>;

    /// Fetch the next SNARK job to prove.
    /// Returns `Ok(None)` if there's no job pending (204 No Content).
    async fn pick_snark_job(&self) -> anyhow::Result<Option<SnarkProofInputs>>;

    /// Submit a SNARK proof for the processed batch range.
    async fn submit_snark_proof(
        &self,
        from_batch_number: L2BatchNumber,
        to_batch_number: L2BatchNumber,
        vk_hash: String,
        proof: SnarkWrapperProof,
    ) -> anyhow::Result<()>;
}

/// SYSCOIN: Score all sequencers concurrently and return every client exactly once.
///
/// Sequencers whose oldest unassigned head is older are tried first. Empty or
/// failed status responses are appended in stable input order, so an older or
/// partially deployed server that lacks the status endpoint still receives a
/// normal pick request. `max_concurrency` bounds status fan-out.
pub async fn ordered_client_indices(
    clients: &[Box<dyn ProofClient + Send + Sync>],
    stage: JobQueueStage,
    max_concurrency: NonZeroUsize,
) -> Vec<usize> {
    ordered_client_indices_with_timeout(clients, stage, max_concurrency, STATUS_PROBE_TIMEOUT).await
}

async fn ordered_client_indices_with_timeout(
    clients: &[Box<dyn ProofClient + Send + Sync>],
    stage: JobQueueStage,
    max_concurrency: NonZeroUsize,
    probe_timeout: Duration,
) -> Vec<usize> {
    use futures_util::{stream, StreamExt};

    let probes = stream::iter(clients.iter().enumerate().map(|(idx, client)| async move {
        let score = tokio::time::timeout(probe_timeout, client.status(stage))
            .await
            .ok()
            .and_then(Result::ok)
            .and_then(|statuses| {
                statuses
                    .into_iter()
                    .filter(|status| status.assigned_seconds_ago.is_none())
                    .min_by_key(|status| status.batch_number)
                    .map(|head| (head.added_seconds_ago, head.batch_number))
            });
        (idx, score)
    }))
    .buffer_unordered(max_concurrency.get())
    .collect::<Vec<_>>()
    .await;

    let mut scored = probes;
    scored.sort_by_key(|(idx, score)| match score {
        Some((age, batch)) => (false, std::cmp::Reverse(*age), *batch, *idx),
        None => (true, std::cmp::Reverse(0), 0, *idx),
    });
    scored.into_iter().map(|(idx, _)| idx).collect()
}

#[async_trait]
pub trait PeekableProofClient {
    /// Peek at a FRI job by batch number.
    /// Note: you can only peek failed jobs as successful ones are removed.
    async fn peek_fri_job(&self, batch_number: u32) -> anyhow::Result<Option<(u32, Vec<u8>)>>;

    /// Peek at a SNARK job by batch range.
    async fn peek_snark_job(
        &self,
        from_batch_number: u32,
        to_batch_number: u32,
    ) -> anyhow::Result<Option<SnarkProofInputs>>;

    /// Get a failed FRI proof by batch number.
    async fn get_failed_fri_proof(
        &self,
        batch_number: u32,
    ) -> anyhow::Result<Option<FailedFriProofPayload>>;
}

// SYSCOIN: Lock bounded, fail-open queue-hint scheduling behavior.
#[cfg(test)]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    use super::*;

    struct MockClient {
        url: Url,
        statuses: Vec<QueueJobStatus>,
        status_fails: bool,
        status_delay: Duration,
        active: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ProofClient for MockClient {
        fn sequencer_url(&self) -> &Url {
            &self.url
        }

        async fn pick_fri_job(&self) -> anyhow::Result<Option<FriJobInputs>> {
            Ok(None)
        }

        async fn submit_fri_proof(
            &self,
            _batch_number: u32,
            _vk_hash: String,
            _proof: String,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn status(&self, _stage: JobQueueStage) -> anyhow::Result<Vec<QueueJobStatus>> {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(active, Ordering::SeqCst);
            tokio::time::sleep(self.status_delay).await;
            self.active.fetch_sub(1, Ordering::SeqCst);
            if self.status_fails {
                anyhow::bail!("status unavailable")
            }
            Ok(self.statuses.clone())
        }

        async fn pick_snark_job(&self) -> anyhow::Result<Option<SnarkProofInputs>> {
            Ok(None)
        }

        async fn submit_snark_proof(
            &self,
            _from_batch_number: L2BatchNumber,
            _to_batch_number: L2BatchNumber,
            _vk_hash: String,
            _proof: SnarkWrapperProof,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn status(batch_number: u32, age: u64, assigned: bool) -> QueueJobStatus {
        QueueJobStatus {
            batch_number,
            vk_hash: "vk".to_owned(),
            added_seconds_ago: age,
            assigned_seconds_ago: assigned.then_some(1),
            assigned_to_prover_id: assigned.then(|| "other".to_owned()),
            current_attempt: 0,
        }
    }

    fn client(
        index: usize,
        statuses: Vec<QueueJobStatus>,
        status_fails: bool,
        active: &Arc<AtomicUsize>,
        peak: &Arc<AtomicUsize>,
    ) -> Box<dyn ProofClient + Send + Sync> {
        Box::new(MockClient {
            url: Url::parse(&format!("http://sequencer-{index}.invalid")).unwrap(),
            statuses,
            status_fails,
            status_delay: Duration::from_millis(5),
            active: active.clone(),
            peak: peak.clone(),
        })
    }

    #[tokio::test]
    async fn scheduling_uses_oldest_unassigned_head_and_keeps_fallbacks() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let clients = vec![
            // The old tail must not outrank another sequencer's older head.
            client(
                0,
                vec![status(10, 10, false), status(11, 10_000, false)],
                false,
                &active,
                &peak,
            ),
            client(1, vec![status(20, 20, false)], false, &active, &peak),
            // Failed and empty status endpoints remain in the pick fallback.
            client(2, vec![], true, &active, &peak),
            client(3, vec![status(1, 50_000, true)], false, &active, &peak),
        ];

        let ordered =
            ordered_client_indices(&clients, JobQueueStage::Fri, NonZeroUsize::new(2).unwrap())
                .await;

        assert_eq!(ordered, vec![1, 0, 2, 3]);
        assert_eq!(peak.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn slow_status_is_only_a_hint_and_cannot_stall_pick_fallback() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let slow: Box<dyn ProofClient + Send + Sync> = Box::new(MockClient {
            url: Url::parse("http://sequencer-0.invalid").unwrap(),
            statuses: vec![status(1, 10_000, false)],
            status_fails: false,
            status_delay: Duration::from_millis(100),
            active: active.clone(),
            peak: peak.clone(),
        });
        let clients = vec![
            slow,
            client(1, vec![status(2, 20, false)], false, &active, &peak),
        ];

        let started_at = tokio::time::Instant::now();
        let ordered = ordered_client_indices_with_timeout(
            &clients,
            JobQueueStage::Fri,
            NonZeroUsize::new(2).unwrap(),
            Duration::from_millis(20),
        )
        .await;

        assert!(started_at.elapsed() < Duration::from_millis(80));
        // Healthy scored client first; timed-out endpoint is still tried as a fallback.
        assert_eq!(ordered, vec![1, 0]);
    }
}
