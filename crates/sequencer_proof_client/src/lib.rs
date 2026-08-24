// TODO: Currently disabled as it's not used anywhere. Needs a rework anyways.
// SYSCOIN: Do not re-enable the stale file client until it implements opaque leases and
// owner-only capability artifacts; production, mock, and manual CLI paths below are covered.
// pub mod file_based_proof_client;

pub mod sequencer_endpoint;
pub mod sequencer_proof_client;
// SYSCOIN: Durable exact proof/capability ownership is implemented at the HTTP client boundary.
mod durable_submission;

// SYSCOIN: Binaries defer secret-bearing endpoint validation until after Clap has finished.
pub use sequencer_endpoint::{
    parse_configured_sequencer_endpoints, OpaqueSequencerEndpoint, SequencerEndpoint,
};
// SYSCOIN: Manual artifacts and the durable spool share one credential-free endpoint identity
// validator so legacy userinfo can never reach diagnostics or submission routing.
pub use sequencer_proof_client::validate_canonical_endpoint_identity;
// SYSCOIN: Every prover process replays an owned proof/capability before acquiring fresh work.
pub use sequencer_proof_client::resume_pending_submissions;
pub use sequencer_proof_client::SequencerProofClient;

/// SYSCOIN: The server and prover share an explicit application-level disposition contract.
/// Generic proxy/parser responses must never retire an expensive proof or its lease.
pub const PROVER_DISPOSITION_HEADER: &str = "x-syscoin-prover-disposition";
pub const PROVER_DISPOSITION_ACCEPTED: &str = "accepted";
pub const PROVER_DISPOSITION_REJECTED: &str = "rejected";
/// SYSCOIN: A trusted sequencer marks only enumerated failures known to precede pick assignment.
/// Missing, duplicated, or rewritten markers remain acquisition-ambiguous at the client.
pub const PROVER_PICK_OUTCOME_HEADER: &str = "x-syscoin-prover-pick-outcome";
pub const PROVER_PICK_OUTCOME_UNLEASED: &str = "unleased";

/// SYSCOIN: Match the server's exact decompressed request-body ceiling before publishing a
/// durable envelope. A proof that cannot fit is fatal and must not be followed by a fresh pick.
pub const MAX_PROOF_SUBMISSION_BODY_BYTES: usize = 10 * 1024 * 1024;
/// SYSCOIN: Advertise and enforce the current production host/proxy response budget. This is not
/// a canonical V8 witness bound: a larger job stays unleased until fleet capacity is raised.
pub const MAX_FRI_PICK_RESPONSE_BYTES: usize = 384 * 1024 * 1024;
/// SYSCOIN: Authority-free diagnostics retain their smaller independent defensive ceiling.
pub const MAX_FRI_PEEK_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_SNARK_JOB_RESPONSE_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_STATUS_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_FRI_DIAGNOSTIC_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_FRIS_PER_SNARK_JOB: usize = 100;
/// SYSCOIN: Canonical credential-free endpoint identities are persisted beside bearer capabilities.
/// Bound them during client construction so no deterministic identity error can occur after proving.
pub const MAX_CANONICAL_ENDPOINT_IDENTITY_BYTES: usize = 2048;

// SYSCOIN: Select one operator shutdown source behind a testable primitive. Both branches return
// value-free diagnostics, and callers retain ownership of their in-flight prover future afterward.
async fn first_operator_shutdown<Interrupt, Terminate>(
    interrupt: Interrupt,
    terminate: Terminate,
) -> anyhow::Result<()>
where
    Interrupt: std::future::Future<Output = anyhow::Result<()>>,
    Terminate: std::future::Future<Output = anyhow::Result<()>>,
{
    tokio::pin!(interrupt);
    tokio::pin!(terminate);
    tokio::select! {
        result = &mut interrupt => result,
        result = &mut terminate => result,
    }
}

/// SYSCOIN: Wait for the normal production stop signals. Unix service managers and container
/// runtimes use SIGTERM; interactive terminals use SIGINT. Non-Unix platforms retain Ctrl-C.
pub async fn wait_for_operator_shutdown() -> anyhow::Result<()> {
    let interrupt = async {
        tokio::signal::ctrl_c()
            .await
            .map_err(anyhow::Error::from)
            .context("failed to listen for Ctrl-C/SIGINT")
    };

    #[cfg(unix)]
    let terminate = {
        let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .context("failed to register SIGTERM listener")?;
        async move {
            signal
                .recv()
                .await
                .context("SIGTERM listener closed unexpectedly")?;
            Ok(())
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<anyhow::Result<()>>();

    first_operator_shutdown(interrupt, terminate).await
}

use crate::metrics::SEQUENCER_CLIENT_METRICS;
use anyhow::Context as _;
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

/// SYSCOIN: Opaque sequencer-issued capability authorizing one exact prover submission.
///
/// Its wire representation is transparent JSON, while `Debug` is redacted to keep routine
/// diagnostics from leaking a live lease.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProverLeaseToken(String);

impl From<String> for ProverLeaseToken {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl ProverLeaseToken {
    // SYSCOIN: V32 leases are exactly one B256 wire value. Validate authority before allocating
    // proof inputs so a hostile sequencer cannot hide malformed capability data behind huge blobs.
    fn validate_wire_value(&self) -> anyhow::Result<()> {
        validate_b256_wire_value(&self.0, "prover lease token")
    }
}

impl fmt::Debug for ProverLeaseToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProverLeaseToken([REDACTED])")
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct NextFriProverJobPayload {
    batch_number: u32,
    vk_hash: String,
    prover_input: String, // base64-encoded
    // SYSCOIN: Returned only by pick; status and peek responses never carry authority.
    lease_token: ProverLeaseToken,
}

// SYSCOIN: Peek remains deliberately incapable of authorizing a submit.
#[derive(Debug, Serialize, Deserialize)]
struct PeekFriProverJobPayload {
    batch_number: u32,
    vk_hash: String,
    prover_input: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SubmitFriProofPayload {
    batch_number: u64,
    vk_hash: String,
    proof: String,
    // SYSCOIN: Echo the capability from the matching FRI pick.
    lease_token: ProverLeaseToken,
}

#[derive(Debug, Serialize, Deserialize)]
struct GetSnarkProofPayload {
    from_batch_number: u64,
    to_batch_number: u64,
    vk_hash: String,
    fri_proofs: Vec<String>, // base64‑encoded FRI proofs
    // SYSCOIN: One opaque capability is bound to this exact aggregate range.
    lease_token: ProverLeaseToken,
}

// SYSCOIN: SNARK peek returns proof material without an aggregate capability.
#[derive(Debug, Serialize, Deserialize)]
struct PeekSnarkProofPayload {
    from_batch_number: u64,
    to_batch_number: u64,
    vk_hash: String,
    fri_proofs: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SubmitSnarkProofPayload {
    from_batch_number: u64,
    to_batch_number: u64,
    vk_hash: String,
    proof: String, // base64‑encoded SNARK proof
    // SYSCOIN: Echo the capability from the matching exact-range pick.
    lease_token: ProverLeaseToken,
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
        // SYSCOIN: Validate all scalar authority/range fields and the exact inclusive proof count
        // before any base64 or bincode allocation.
        let (from_batch_number, to_batch_number) = validate_snark_payload_shape(
            self.from_batch_number,
            self.to_batch_number,
            &self.vk_hash,
            Some(&self.lease_token),
            self.fri_proofs.len(),
        )?;
        let mut fri_proofs = Vec::with_capacity(self.fri_proofs.len());
        for encoded_proof in self.fri_proofs {
            fri_proofs.push(decode_canonical_fri_proof(&encoded_proof)?);
        }

        Ok(SnarkProofInputs {
            from_batch_number: L2BatchNumber(from_batch_number),
            to_batch_number: L2BatchNumber(to_batch_number),
            vk_hash: self.vk_hash,
            fri_proofs,
            lease_token: self.lease_token,
        })
    }
}

// SYSCOIN: Keep read-only peek material in a type that cannot be submitted accidentally.
impl TryInto<PeekSnarkProofInputs> for PeekSnarkProofPayload {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<PeekSnarkProofInputs, Self::Error> {
        // SYSCOIN: Peek is authority-free but still obeys the same exact bounded range contract.
        let (from_batch_number, to_batch_number) = validate_snark_payload_shape(
            self.from_batch_number,
            self.to_batch_number,
            &self.vk_hash,
            None,
            self.fri_proofs.len(),
        )?;
        let mut fri_proofs = Vec::with_capacity(self.fri_proofs.len());
        for encoded_proof in self.fri_proofs {
            fri_proofs.push(decode_canonical_fri_proof(&encoded_proof)?);
        }
        Ok(PeekSnarkProofInputs {
            from_batch_number: L2BatchNumber(from_batch_number),
            to_batch_number: L2BatchNumber(to_batch_number),
            vk_hash: self.vk_hash,
            fri_proofs,
        })
    }
}

// SYSCOIN: Server storage and the SNARK combiner use one canonical bincode proof per entry. Reject
// a valid prefix plus trailing bytes so a remote endpoint cannot amplify unverified suffix data.
fn decode_canonical_fri_proof(encoded: &str) -> anyhow::Result<UnrolledProgramProof> {
    anyhow::ensure!(
        encoded.len() <= MAX_PROOF_SUBMISSION_BODY_BYTES,
        "encoded FRI proof exceeds {} bytes",
        MAX_PROOF_SUBMISSION_BODY_BYTES
    );
    let bytes = STANDARD.decode(encoded)?;
    anyhow::ensure!(
        bytes.len() <= MAX_PROOF_SUBMISSION_BODY_BYTES,
        "decoded FRI proof exceeds {} bytes",
        MAX_PROOF_SUBMISSION_BODY_BYTES
    );
    decode_canonical_bincode(&bytes)
}

// SYSCOIN: Keep full-consumption enforcement independently testable without a large proof
// fixture; the production wrapper above fixes `T` to `UnrolledProgramProof`.
fn decode_canonical_bincode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> anyhow::Result<T> {
    let (proof, consumed) = bincode::serde::decode_from_slice(
        bytes,
        bincode::config::standard().with_limit::<MAX_PROOF_SUBMISSION_BODY_BYTES>(),
    )?;
    anyhow::ensure!(
        consumed == bytes.len(),
        "FRI proof contains {} trailing bytes",
        bytes.len().saturating_sub(consumed)
    );
    Ok(proof)
}

// SYSCOIN: VK hashes and lease tokens are fixed B256 values throughout the V32 protocol.
fn validate_b256_wire_value(value: &str, field: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        value.len() == 66
            && value.starts_with("0x")
            && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{field} must be a 0x-prefixed 32-byte hex value"
    );
    Ok(())
}

// SYSCOIN: An aggregate response is exactly one proof per inclusive u32 batch, with a hard
// protocol ceiling. Checked arithmetic prevents remote u64 ranges from panicking or wrapping.
fn validate_snark_payload_shape(
    from_batch_number: u64,
    to_batch_number: u64,
    vk_hash: &str,
    lease_token: Option<&ProverLeaseToken>,
    proof_count: usize,
) -> anyhow::Result<(u32, u32)> {
    validate_b256_wire_value(vk_hash, "verification-key hash")?;
    if let Some(lease_token) = lease_token {
        lease_token.validate_wire_value()?;
    }
    let from_batch_number = u32::try_from(from_batch_number)
        .map_err(|_| anyhow::anyhow!("SNARK from_batch_number does not fit u32"))?;
    let to_batch_number = u32::try_from(to_batch_number)
        .map_err(|_| anyhow::anyhow!("SNARK to_batch_number does not fit u32"))?;
    let expected_count = to_batch_number
        .checked_sub(from_batch_number)
        .and_then(|delta| delta.checked_add(1))
        .ok_or_else(|| anyhow::anyhow!("SNARK batch range is inverted or overflows"))?;
    let expected_count = usize::try_from(expected_count)?;
    // SYSCOIN: The real Airbender recursive wrapper is defined over a multi-FRI aggregate; reject
    // a singleton response immediately after lease acquisition instead of failing after proving.
    anyhow::ensure!(
        expected_count >= 2,
        "SNARK batch range must contain at least 2 proofs"
    );
    anyhow::ensure!(
        expected_count <= MAX_FRIS_PER_SNARK_JOB,
        "SNARK batch range contains {expected_count} proofs; maximum is {MAX_FRIS_PER_SNARK_JOB}"
    );
    anyhow::ensure!(
        proof_count == expected_count,
        "SNARK payload has {proof_count} proofs, expected exactly {expected_count} for its inclusive range"
    );
    Ok((from_batch_number, to_batch_number))
}

/// SYSCOIN: Typed worker outcome prevents post-acquisition failures from masquerading as an empty
/// queue and falling through to another endpoint. Only these pre-acquisition states are skippable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofRunOutcome {
    NoJob,
    EndpointUnavailable,
    ProofSubmitted,
}

/// SYSCOIN: Marks failures for which a state-changing pick is known or may have transferred lease
/// ownership. Worker loops must terminate rather than treating an ambiguous outcome as absence.
#[derive(Debug)]
pub struct LeasedJobResponseError(anyhow::Error);

impl fmt::Display for LeasedJobResponseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "pick may have acquired a lease: {}", self.0)
    }
}

impl std::error::Error for LeasedJobResponseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

pub(crate) fn job_acquisition_error(error: anyhow::Error) -> anyhow::Error {
    LeasedJobResponseError(error).into()
}

/// SYSCOIN: `true` means a lease is known or conservatively presumed to exist, so workers must
/// fail closed instead of trying another endpoint.
pub fn error_follows_job_acquisition(error: &anyhow::Error) -> bool {
    error.downcast_ref::<LeasedJobResponseError>().is_some()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SnarkProofInputs {
    pub from_batch_number: L2BatchNumber,
    pub to_batch_number: L2BatchNumber,
    pub vk_hash: String,
    pub fri_proofs: Vec<UnrolledProgramProof>,
    // SYSCOIN: Must travel unchanged from pick to the exact-range submit call.
    pub lease_token: ProverLeaseToken,
}

/// SYSCOIN: Read-only SNARK proof material returned by peek; it deliberately has no lease.
#[derive(Debug, Serialize, Deserialize)]
pub struct PeekSnarkProofInputs {
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
    // SYSCOIN: Must travel unchanged from pick to FRI submission.
    pub lease_token: ProverLeaseToken,
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

    /// SYSCOIN: Replay every crash-retained exact submission for this configured endpoint before
    /// acquiring new work. Test and in-memory clients have no durable queue by default.
    async fn resume_pending_submissions(&self) -> anyhow::Result<usize> {
        Ok(0)
    }

    /// Fetch the next FRI batch to prove.
    /// Returns `Ok(None)` if there's no batch pending (204 No Content).
    async fn pick_fri_job(&self) -> anyhow::Result<Option<FriJobInputs>>;

    /// SYSCOIN: Submit a FRI proof with the opaque capability returned by its pick.
    async fn submit_fri_proof(
        &self,
        batch_number: u32,
        vk_hash: String,
        proof: String,
        lease_token: ProverLeaseToken,
    ) -> anyhow::Result<()>;

    /// SYSCOIN: Read the queue without claiming a job. Scheduling treats this as a hint:
    /// status failures never remove a client from the subsequent pick fallback.
    async fn status(&self, stage: JobQueueStage) -> anyhow::Result<Vec<QueueJobStatus>>;

    /// Fetch the next SNARK job to prove.
    /// Returns `Ok(None)` if there's no job pending (204 No Content).
    async fn pick_snark_job(&self) -> anyhow::Result<Option<SnarkProofInputs>>;

    /// SYSCOIN: Submit a SNARK proof with the capability for this exact picked range.
    async fn submit_snark_proof(
        &self,
        from_batch_number: L2BatchNumber,
        to_batch_number: L2BatchNumber,
        vk_hash: String,
        proof: SnarkWrapperProof,
        lease_token: ProverLeaseToken,
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

    /// SYSCOIN: Peek at a SNARK job by batch range without returning submission authority.
    async fn peek_snark_job(
        &self,
        from_batch_number: u32,
        to_batch_number: u32,
    ) -> anyhow::Result<Option<PeekSnarkProofInputs>>;

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

    // SYSCOIN: The shared production shutdown selector wakes for either interactive SIGINT or
    // supervisor SIGTERM without requiring process-global signals in a unit test.
    #[tokio::test]
    async fn operator_shutdown_selector_accepts_either_source_and_propagates_errors() {
        first_operator_shutdown(std::future::pending(), std::future::ready(Ok(())))
            .await
            .unwrap();
        first_operator_shutdown(std::future::ready(Ok(())), std::future::pending())
            .await
            .unwrap();

        let error = first_operator_shutdown(
            std::future::ready(Err(anyhow::anyhow!("signal-listener-failed"))),
            std::future::pending(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("signal-listener-failed"));
    }

    // SYSCOIN: A remote sequencer cannot append arbitrary data to an otherwise-valid FRI proof.
    #[test]
    fn canonical_fri_decoder_rejects_trailing_bincode_bytes() {
        let mut encoded = bincode::serde::encode_to_vec(42_u64, bincode::config::standard())
            .expect("u64 encoding succeeds");
        assert_eq!(decode_canonical_bincode::<u64>(&encoded).unwrap(), 42);
        encoded.push(0xaa);
        assert!(decode_canonical_bincode::<u64>(&encoded)
            .unwrap_err()
            .to_string()
            .contains("trailing bytes"));
    }

    #[test]
    fn fri_pick_capability_maps_unchanged_to_submit_payload() {
        let wire_token = "0x1111111111111111111111111111111111111111111111111111111111111111";
        let picked: NextFriProverJobPayload = serde_json::from_value(serde_json::json!({
            "batch_number": 7,
            "vk_hash": "vk",
            "prover_input": "",
            "lease_token": wire_token,
        }))
        .unwrap();
        let job = FriJobInputs {
            batch_number: picked.batch_number,
            vk_hash: picked.vk_hash,
            prover_input: STANDARD.decode(picked.prover_input).unwrap(),
            lease_token: picked.lease_token,
        };
        assert!(!format!("{job:?}").contains(wire_token));
        let submitted = SubmitFriProofPayload {
            batch_number: u64::from(job.batch_number),
            vk_hash: job.vk_hash,
            proof: "proof".to_owned(),
            lease_token: job.lease_token,
        };
        assert!(!format!("{submitted:?}").contains(wire_token));

        assert_eq!(
            serde_json::to_value(submitted).unwrap()["lease_token"],
            wire_token
        );
    }

    #[test]
    fn snark_pick_capability_maps_unchanged_to_submit_payload() {
        let wire_token = "0x2222222222222222222222222222222222222222222222222222222222222222";
        let vk_hash = format!("0x{}", "ab".repeat(32));
        let lease_token = ProverLeaseToken::from(wire_token.to_owned());
        validate_snark_payload_shape(10, 11, &vk_hash, Some(&lease_token), 2).unwrap();
        let job = SnarkProofInputs {
            from_batch_number: L2BatchNumber(10),
            to_batch_number: L2BatchNumber(11),
            vk_hash,
            fri_proofs: vec![],
            lease_token,
        };
        assert!(!format!("{job:?}").contains(wire_token));
        let submitted = SubmitSnarkProofPayload {
            from_batch_number: u64::from(job.from_batch_number.0),
            to_batch_number: u64::from(job.to_batch_number.0),
            vk_hash: job.vk_hash,
            proof: "proof".to_owned(),
            lease_token: job.lease_token,
        };
        assert!(!format!("{submitted:?}").contains(wire_token));

        assert_eq!(
            serde_json::to_value(submitted).unwrap()["lease_token"],
            wire_token
        );
        assert_eq!(
            format!("{:?}", ProverLeaseToken::from(wire_token.to_owned())),
            "ProverLeaseToken([REDACTED])"
        );
    }

    // SYSCOIN: Range/count/capability validation runs before base64/bincode proof decoding.
    #[test]
    fn malicious_snark_ranges_counts_and_authority_fail_before_proof_decode() {
        let vk_hash = format!("0x{}", "11".repeat(32));
        let token = ProverLeaseToken::from(format!("0x{}", "22".repeat(32)));
        for (from, to, count, expected) in [
            (
                u64::from(u32::MAX) + 1,
                u64::from(u32::MAX) + 1,
                1,
                "fit u32",
            ),
            (2, 1, 0, "inverted"),
            (1, 1, 1, "at least 2"),
            (1, 101, 101, "maximum"),
            (10, 11, 1, "expected exactly 2"),
        ] {
            let error =
                validate_snark_payload_shape(from, to, &vk_hash, Some(&token), count).unwrap_err();
            assert!(
                error.to_string().contains(expected),
                "unexpected error: {error:#}"
            );
        }

        let bad_token = ProverLeaseToken::from("short".to_owned());
        assert!(
            validate_snark_payload_shape(1, 1, &vk_hash, Some(&bad_token), 1)
                .unwrap_err()
                .to_string()
                .contains("lease token")
        );
        assert!(
            validate_snark_payload_shape(1, 1, "not-a-vk", Some(&token), 1)
                .unwrap_err()
                .to_string()
                .contains("verification-key hash")
        );
    }

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
            _lease_token: ProverLeaseToken,
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
            _lease_token: ProverLeaseToken,
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
