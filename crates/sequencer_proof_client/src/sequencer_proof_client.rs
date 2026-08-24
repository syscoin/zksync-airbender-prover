// SYSCOIN: Extend the upstream HTTP client with bounded transport, durable exact-capability
// replay, and cooperative shutdown primitives used by production FRI and SNARK workers.
use std::{
    collections::HashSet,
    future::pending,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::durable_submission::{
    DurableSubmission, DurableSubmissionEnvelope, DurableSubmissionStore, PendingSubmission,
};
use crate::metrics::Method;
use crate::sequencer_endpoint::SequencerEndpoint;
use crate::{
    FailedFriProofPayload, FriJobInputs, GetSnarkProofPayload, JobQueueStage, JobStatusPayload,
    NextFriProverJobPayload, PeekFriProverJobPayload, PeekSnarkProofInputs, PeekSnarkProofPayload,
    PeekableProofClient, ProofClient, ProverLeaseToken, QueueJobStatus, SnarkProofInputs,
    MAX_FRI_DIAGNOSTIC_RESPONSE_BYTES, MAX_FRI_JOB_RESPONSE_BYTES, MAX_PROOF_SUBMISSION_BODY_BYTES,
    MAX_SNARK_JOB_RESPONSE_BYTES, MAX_STATUS_RESPONSE_BYTES, PROVER_DISPOSITION_ACCEPTED,
    PROVER_DISPOSITION_HEADER, PROVER_DISPOSITION_REJECTED,
};
use crate::{L2BatchNumber, SEQUENCER_CLIENT_METRICS};
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use futures_util::StreamExt as _;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::StatusCode;
use tokio::sync::watch;
use url::{Host, Url};
use zkos_wrapper::SnarkWrapperProof;

// SYSCOIN: Large compressed prover payloads need separate connect, inactivity, and total limits.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(600);
// SYSCOIN: Preserve already-generated FRI/SNARK proofs while bounded downstream capacity is busy.
#[cfg(not(test))]
const PROOF_SUBMISSION_RETRY_INITIAL_DELAY: Duration = Duration::from_secs(1);
#[cfg(test)]
const PROOF_SUBMISSION_RETRY_INITIAL_DELAY: Duration = Duration::from_millis(10);
#[cfg(not(test))]
const PROOF_SUBMISSION_RETRY_MAX_DELAY: Duration = Duration::from_secs(30);
#[cfg(test)]
const PROOF_SUBMISSION_RETRY_MAX_DELAY: Duration = Duration::from_millis(40);

// SYSCOIN: One stage discriminator keeps FRI/SNARK retry and terminal-disposition handling exact.
#[derive(Clone, Copy)]
enum SubmissionStage {
    Fri,
    Snark,
}

impl SubmissionStage {
    const fn label(self) -> &'static str {
        match self {
            Self::Fri => "FRI",
            Self::Snark => "SNARK",
        }
    }

    // SYSCOIN: 408/425/429 explicitly retain or ambiguously transport the lease, and every 5xx
    // (including reverse-proxy 520-524 extensions) can occur after upstream accepted the body.
    // Replaying identical bytes is safe and converges to a definitive exact-capability response.
    fn should_retry_same_submission(self, status: StatusCode) -> bool {
        status == StatusCode::REQUEST_TIMEOUT
            || status == StatusCode::TOO_EARLY
            || status == StatusCode::TOO_MANY_REQUESTS
            || status.is_server_error()
    }
}

#[derive(Debug)]
pub struct SequencerProofClient {
    client: reqwest::Client,
    // SYSCOIN: Proof verification may legitimately produce no response bytes for minutes; keep
    // submission reads separate from short pick/status inactivity detection.
    submission_client: reqwest::Client,
    endpoint: Url,
    prover_name: String,
    supported_vk_hashes: Vec<String>,
    // SYSCOIN: Production clients durably own exact proof/capability envelopes across crashes.
    submission_store: Option<Arc<DurableSubmissionStore>>,
    // SYSCOIN: Submission retries observe the process stop signal without discarding the envelope.
    shutdown: Option<watch::Receiver<bool>>,
}

impl SequencerProofClient {
    /// Create a new proof sequencer client.
    ///
    /// # Arguments
    /// * `endpoint` - The sequencer endpoint (URL + optional credentials)
    /// * `prover_name` - The name of the prover (used for identification in sequencer prover api)
    /// * `timeout` - SYSCOIN: Optional total request backstop (None defaults to 600 seconds so a
    ///   valid large proof response is not truncated by the old two-second client default).
    ///   Connect timeout is 5 seconds and read-inactivity timeout is 10 seconds.
    /// * `supported_vk_hashes` - VK hashes this prover supports; sent on pick requests so the
    ///   sequencer only assigns jobs of these versions. Empty means no declaration - the
    ///   sequencer will offer jobs of any version.
    ///
    /// # Errors
    /// * if building the reqwest client fails
    // SYSCOIN: Preserve the upstream constructor while routing it through hardened timeout,
    // endpoint-identity, and body-validation configuration.
    pub fn new(
        endpoint: SequencerEndpoint,
        prover_name: String,
        timeout: Option<Duration>,
        supported_vk_hashes: Vec<String>,
    ) -> anyhow::Result<Self> {
        Self::new_with_timeouts(
            endpoint,
            prover_name,
            timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT),
            DEFAULT_READ_TIMEOUT,
            supported_vk_hashes,
        )
    }

    // SYSCOIN: Tests exercise distinct read/total timeouts through the same production builder.
    fn new_with_timeouts(
        endpoint: SequencerEndpoint,
        prover_name: String,
        request_timeout: Duration,
        read_timeout: Duration,
        supported_vk_hashes: Vec<String>,
    ) -> anyhow::Result<Self> {
        Self::new_configured(
            endpoint,
            prover_name,
            request_timeout,
            read_timeout,
            supported_vk_hashes,
            None,
            None,
            false,
        )
    }

    // SYSCOIN: Centralize credential redaction, canonical routing, TLS policy, VK bounds, durable
    // ownership, and shutdown behavior so no constructor can bypass a production invariant.
    #[allow(clippy::too_many_arguments)]
    fn new_configured(
        endpoint: SequencerEndpoint,
        prover_name: String,
        request_timeout: Duration,
        read_timeout: Duration,
        supported_vk_hashes: Vec<String>,
        submission_store: Option<Arc<DurableSubmissionStore>>,
        shutdown: Option<watch::Receiver<bool>>,
        allow_insecure_http: bool,
    ) -> anyhow::Result<Self> {
        // SYSCOIN: Match the sequencer's bounded diagnostic-ID grammar before constructing query
        // strings or logs. The server uses a fixed metrics label; IDs are never proof authority.
        anyhow::ensure!(
            !prover_name.is_empty()
                && prover_name.len() <= 64
                && prover_name.bytes().all(|byte| byte.is_ascii_alphanumeric()
                    || matches!(byte, b'-' | b'_' | b'.' | b':')),
            "prover name must be 1-64 ASCII alphanumeric, '-', '_', '.', or ':' characters"
        );
        anyhow::ensure!(
            !request_timeout.is_zero() && !read_timeout.is_zero(),
            "sequencer request/read timeouts must be greater than zero"
        );
        // SYSCOIN: VK declarations become a query parameter and later authorize expensive decode.
        // Require bounded, unique B256 values before any client or URL is constructed.
        anyhow::ensure!(
            supported_vk_hashes.len() <= 16,
            "at most 16 supported VK hashes may be advertised"
        );
        let mut unique_vk_hashes = HashSet::with_capacity(supported_vk_hashes.len());
        for vk_hash in &supported_vk_hashes {
            crate::validate_b256_wire_value(vk_hash, "supported verification-key hash")?;
            anyhow::ensure!(
                unique_vk_hashes.insert(vk_hash),
                "duplicate supported VK hash"
            );
        }
        // SYSCOIN: Basic Auth and lease tokens must not traverse a non-loopback plaintext link
        // accidentally. Production uses HTTPS; the explicit override is for isolated container
        // networks whose transport security is enforced outside this process.
        validate_endpoint_transport(&endpoint.url, allow_insecure_http)?;
        let endpoint_identity = canonical_endpoint_identity(&endpoint.url)?;
        let mut headers = HeaderMap::new();

        // Add Basic Auth header if credentials are present
        if let Some(creds) = &endpoint.credentials {
            use secrecy::ExposeSecret;
            let auth_value = format!(
                "Basic {}",
                STANDARD.encode(format!(
                    "{}:{}",
                    creds.username,
                    creds.password.expose_secret()
                ))
            );
            headers.insert(AUTHORIZATION, sensitive_authorization_value(&auth_value)?);
        }

        let client_builder = reqwest::Client::builder()
            .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
            .read_timeout(read_timeout)
            .timeout(request_timeout)
            // SYSCOIN: Sequencer endpoint changes are explicit configuration. Never follow an
            // HTTP redirect that could replay credentials or a proof capability to another host.
            .redirect(reqwest::redirect::Policy::none())
            .default_headers(headers.clone());
        // SYSCOIN: A request-level total timeout does not override reqwest's shorter read
        // inactivity timeout. Use the total proof-submission budget for both so native verifier
        // and SNARK preflight work cannot trigger a false transport retry while still running.
        let submission_client_builder = reqwest::Client::builder()
            .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
            .read_timeout(request_timeout)
            .timeout(request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .default_headers(headers);
        // SYSCOIN: macOS CI may not have a SystemConfiguration dynamic store. Tests do
        // not make network requests, so avoid querying system proxy settings.
        #[cfg(test)]
        let client_builder = client_builder.no_proxy();
        #[cfg(test)]
        let submission_client_builder = submission_client_builder.no_proxy();
        let client = client_builder
            .build()
            .context("Failed to build reqwest client")?;
        let submission_client = submission_client_builder
            .build()
            .context("Failed to build submission reqwest client")?;

        Ok(Self {
            client,
            submission_client,
            endpoint: endpoint_identity,
            prover_name,
            supported_vk_hashes,
            submission_store,
            shutdown,
        })
    }

    /// SYSCOIN: Create multiple sequencer proof clients with a proof-sized request backstop.
    ///
    /// # Arguments
    /// * `endpoints` - A vector of sequencer endpoints
    /// * `prover_name` - The name of the prover (used for identification in sequencer prover api)
    /// * `timeout` - Optional total request backstop (None defaults to 600 seconds, replacing the
    ///   upstream two-second default that can truncate a valid large proof response).
    /// * `supported_vk_hashes` - VK hashes this prover supports; sent on pick requests so the
    ///   sequencer only assigns jobs of these versions. Empty means no declaration - the
    ///   sequencer will offer jobs of any version.
    ///
    /// # Errors
    /// * if there are no endpoints provided (empty vector)
    /// * if creating any of the clients fails
    pub fn new_clients(
        endpoints: Vec<SequencerEndpoint>,
        prover_name: String,
        timeout: Option<Duration>,
        supported_vk_hashes: Vec<String>,
    ) -> anyhow::Result<Vec<Box<dyn ProofClient + Send + Sync>>> {
        if endpoints.is_empty() {
            return Err(anyhow!("No sequencer endpoints provided"));
        }

        endpoints
            .into_iter()
            .enumerate()
            .map(|(i, endpoint)| {
                let url = endpoint.url.clone();
                let client = SequencerProofClient::new(
                    endpoint,
                    prover_name.clone(),
                    timeout,
                    supported_vk_hashes.clone(),
                )
                .with_context(|| {
                    format!("Failed to create sequencer client #{i} at url {url:?}")
                })?;

                Ok(Box::new(client) as Box<dyn ProofClient + Send + Sync>)
            })
            .collect()
    }

    /// SYSCOIN: Construct production clients sharing one exclusively locked durable submission
    /// spool and one cooperative shutdown signal. A pending endpoint identity must match the
    /// sanitized configured endpoint exactly before any worker can acquire new work.
    #[allow(clippy::too_many_arguments)]
    pub fn new_durable_clients(
        endpoints: Vec<SequencerEndpoint>,
        prover_name: String,
        timeout: Option<Duration>,
        supported_vk_hashes: Vec<String>,
        submission_directory: PathBuf,
        shutdown: watch::Receiver<bool>,
        allow_insecure_http: bool,
    ) -> anyhow::Result<Vec<Box<dyn ProofClient + Send + Sync>>> {
        anyhow::ensure!(!endpoints.is_empty(), "No sequencer endpoints provided");
        let store = DurableSubmissionStore::open(submission_directory)?;
        let configured_identities = endpoints
            .iter()
            .map(|endpoint| {
                validate_endpoint_transport(&endpoint.url, allow_insecure_http)?;
                canonical_endpoint_identity(&endpoint.url).map(|url| url.to_string())
            })
            .collect::<anyhow::Result<HashSet<_>>>()?;
        anyhow::ensure!(
            configured_identities.len() == endpoints.len(),
            "duplicate canonical sequencer endpoint identities are not allowed"
        );
        store.validate_configured_endpoints(&configured_identities)?;

        endpoints
            .into_iter()
            .enumerate()
            .map(|(index, endpoint)| {
                let safe_url = canonical_endpoint_identity(&endpoint.url)?;
                let client = Self::new_configured(
                    endpoint,
                    prover_name.clone(),
                    timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT),
                    DEFAULT_READ_TIMEOUT,
                    supported_vk_hashes.clone(),
                    Some(Arc::clone(&store)),
                    Some(shutdown.clone()),
                    allow_insecure_http,
                )
                .with_context(|| {
                    format!("Failed to create sequencer client #{index} at {safe_url}")
                })?;
                Ok(Box::new(client) as Box<dyn ProofClient + Send + Sync>)
            })
            .collect()
    }

    /// Serialize a SNARK proof into a base64-encoded string suitable for submission.
    ///
    /// # Arguments
    /// * `proof` - The SNARK proof to serialize
    ///
    /// # Errors
    /// * if serialization/deserialization fails (needed for conversion)
    pub fn serialize_snark_proof(&self, proof: &SnarkWrapperProof) -> anyhow::Result<String> {
        let (_, serialized_proof) = crypto_codegen::serialize_proof(proof);

        let byte_serialized_proof = serialized_proof
            .iter()
            .flat_map(|chunk| {
                let mut buf = [0u8; 32];
                chunk.to_big_endian(&mut buf);
                buf
            })
            .collect::<Vec<u8>>();

        Ok(STANDARD.encode(byte_serialized_proof))
    }

    /// Constructs a prover API endpoint URL.
    fn build_url(&self, path: &str) -> anyhow::Result<Url> {
        let url = self
            .endpoint
            .join("prover-jobs/v1/")?
            .join(path)
            .with_context(|| format!("Failed to build URL for path: {path}"))?;
        Ok(url)
    }

    /// Query string for pick requests: prover id plus, if declared, the supported VK hashes.
    /// Sequencers aware of `supported_vk_hashes` only assign jobs of these versions;
    /// older sequencers ignore the parameter.
    fn pick_query(&self) -> String {
        if self.supported_vk_hashes.is_empty() {
            format!("id={}", self.prover_name)
        } else {
            format!(
                "id={}&supported_vk_hashes={}",
                self.prover_name,
                self.supported_vk_hashes.join(",")
            )
        }
    }

    async fn submit_envelope(
        &self,
        envelope: DurableSubmissionEnvelope,
    ) -> anyhow::Result<reqwest::Response> {
        // SYSCOIN: Apply the same exact scalar/range/body validation to manual in-memory clients
        // and durable workers before either publication or the first network byte. Check endpoint
        // ownership before fsync too, so an internal routing bug cannot poison the restart spool.
        anyhow::ensure!(
            envelope.endpoint() == self.endpoint.as_str(),
            "submission endpoint identity does not match configured client"
        );
        envelope.validate()?;
        if let Some(store) = &self.submission_store {
            // SYSCOIN: Publish and fsync the exact proof/capability record before the first byte is
            // sent. Any cancellation or process crash from this point is restart-resumable.
            let pending = store.persist(envelope).await?;
            self.send_envelope(&pending.envelope, Some(&pending)).await
        } else {
            // SYSCOIN: Unit/manual clients retain legacy in-memory behavior; production binaries
            // always construct durable clients through new_durable_clients.
            self.send_envelope(&envelope, None).await
        }
    }

    // SYSCOIN: Build and size the exact immutable stage-specific bytes before retry or transport.
    fn envelope_url_and_body(
        &self,
        envelope: &DurableSubmissionEnvelope,
    ) -> anyhow::Result<(Url, Vec<u8>, SubmissionStage)> {
        let body = envelope.wire_body()?;
        anyhow::ensure!(
            body.len() <= MAX_PROOF_SUBMISSION_BODY_BYTES,
            "proof submission body exceeds server maximum"
        );
        match envelope.submission() {
            DurableSubmission::Fri { .. } => Ok((
                self.build_url(&format!("FRI/submit?id={}", self.prover_name))?,
                body,
                SubmissionStage::Fri,
            )),
            DurableSubmission::Snark { .. } => Ok((
                self.build_url(&format!("SNARK/submit?id={}", self.prover_name))?,
                body,
                SubmissionStage::Snark,
            )),
        }
    }

    /// SYSCOIN: Send one canonical body across every retry. Only the exact manager disposition
    /// header/status contract retires the fsynced envelope; every proxy/parser response preserves it.
    async fn send_envelope(
        &self,
        envelope: &DurableSubmissionEnvelope,
        pending_submission: Option<&PendingSubmission>,
    ) -> anyhow::Result<reqwest::Response> {
        anyhow::ensure!(
            envelope.endpoint() == self.endpoint.as_str(),
            "durable submission endpoint identity does not match configured client"
        );
        let (url, body, stage) = self.envelope_url_and_body(envelope)?;
        let mut retry_count = 0_u32;
        loop {
            if self
                .shutdown
                .as_ref()
                .is_some_and(|shutdown| *shutdown.borrow())
            {
                return Err(anyhow!(
                    "{} submission deferred by shutdown; durable envelope retained",
                    stage.label()
                ));
            }
            let request = self
                .submission_client
                .post(url.clone())
                .header(CONTENT_TYPE, "application/json")
                .body(body.clone())
                .send();
            let response = tokio::select! {
                response = request => response,
                _ = wait_for_shutdown(self.shutdown.clone()) => {
                    return Err(anyhow!(
                        "{} submission deferred by shutdown; durable envelope retained",
                        stage.label()
                    ));
                }
            };
            let retry_reason = match response {
                Ok(response) if stage.should_retry_same_submission(response.status()) => {
                    format!("HTTP {}", response.status())
                }
                Ok(response) if submission_response_is_definitive(&response) => {
                    if let (Some(store), Some(pending)) =
                        (&self.submission_store, pending_submission)
                    {
                        store
                            .retire(pending)
                            .await
                            .context("retire definitive durable submission")?;
                    }
                    return Ok(response);
                }
                Ok(response) => {
                    return Err(anyhow!(
                        "{} submission returned non-definitive HTTP {}; durable envelope retained",
                        stage.label(),
                        response.status()
                    ));
                }
                Err(error) if submission_transport_error_is_retryable(&error) => {
                    // Do not format the request error: keeping logs to a fixed classification
                    // ensures future reqwest changes cannot accidentally expose request data.
                    "transport or timeout error".to_owned()
                }
                Err(error) => {
                    return Err(error).context("proof submission request failed");
                }
            };

            let delay = proof_submission_retry_delay(retry_count);
            retry_count = retry_count.saturating_add(1);
            tracing::warn!(
                stage = stage.label(),
                retry_attempt = retry_count,
                retry_delay_seconds = delay.as_secs_f64(),
                reason = retry_reason,
                "sequencer submission is retryable or ambiguous; retrying identical proof bytes"
            );
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = wait_for_shutdown(self.shutdown.clone()) => {
                    return Err(anyhow!(
                        "{} submission retry deferred by shutdown; durable envelope retained",
                        stage.label()
                    ));
                }
            }
        }
    }

    // SYSCOIN: Resolve only this canonical endpoint's fsynced envelope before permitting new work.
    async fn resume_durable_submissions(&self) -> anyhow::Result<usize> {
        let Some(store) = &self.submission_store else {
            return Ok(0);
        };
        let pending = store.load_for_endpoint(self.endpoint.as_str()).await?;
        let mut resolved = 0_usize;
        for submission in pending {
            let stage = submission.envelope.stage();
            let (from, to) = submission.envelope.range();
            let response = self
                .send_envelope(&submission.envelope, Some(&submission))
                .await
                .with_context(|| {
                    format!(
                        "resume durable {stage} submission for non-secret batch range {from}-{to}"
                    )
                })?;
            if !response.status().is_success() {
                // SYSCOIN: Retirement means the exact manager has reached a terminal outcome; it
                // does not make malformed/stale production work successful. Surface the rejection
                // after retirement so a supervisor/operator sees it and this run cannot fresh-pick.
                return Err(anyhow!(
                    "durable {stage} submission for non-secret batch range {from}-{to} reached definitive HTTP {} rejection and was retired",
                    response.status()
                ));
            }
            resolved = resolved.saturating_add(1);
        }
        Ok(resolved)
    }

    // SYSCOIN: A client may replay only its endpoint's record, but every fresh pick is blocked by
    // any unresolved record in the process-wide spool, including one owned by another endpoint.
    async fn gate_new_pick(&self) -> anyhow::Result<()> {
        self.resume_durable_submissions().await?;
        if let Some(store) = &self.submission_store {
            store.ensure_empty().await?;
        }
        Ok(())
    }
}

/// SYSCOIN: Production binaries call this immediately after constructing every configured client,
/// before expensive prover setup or any new pick, so crash-retained ownership always drains first.
pub async fn resume_pending_submissions(
    clients: &[Box<dyn ProofClient + Send + Sync>],
) -> anyhow::Result<usize> {
    let mut resolved = 0_usize;
    for client in clients {
        resolved = resolved.saturating_add(client.resume_pending_submissions().await?);
    }
    Ok(resolved)
}

// SYSCOIN: Basic Auth is a secret at every HTTP layer. Mark it sensitive before insertion so
// header Debug output is redacted and HTTP/2 implementations avoid indexing it.
fn sensitive_authorization_value(value: &str) -> anyhow::Result<HeaderValue> {
    let mut header = HeaderValue::from_str(value).context("Failed to create auth header value")?;
    header.set_sensitive(true);
    Ok(header)
}

// SYSCOIN: Durable identity intentionally excludes credentials, query values, and fragments. URL
// parsing has already normalized scheme/host/port/path, so restart matching is exact and stable.
fn canonical_endpoint_identity(url: &Url) -> anyhow::Result<Url> {
    let mut identity = url.clone();
    identity
        .set_username("")
        .map_err(|_| anyhow!("sequencer endpoint scheme does not support sanitized identity"))?;
    identity
        .set_password(None)
        .map_err(|_| anyhow!("sequencer endpoint scheme does not support sanitized identity"))?;
    identity.set_query(None);
    identity.set_fragment(None);
    anyhow::ensure!(
        identity.host().is_some(),
        "sequencer endpoint must have a host"
    );
    // SYSCOIN: `Url::join` treats a non-trailing path as a file and replaces it when building the
    // API root. Reject that ambiguous spelling so two distinct durable identities cannot route to
    // the same sequencer or cross a path-scoped tenant / credential boundary.
    anyhow::ensure!(
        identity.path() == "/" || identity.path().ends_with('/'),
        "non-root sequencer endpoint paths must end with '/'"
    );
    // SYSCOIN: This exact identity is later fsynced with a generated proof. Reject oversized
    // configuration before any pick so envelope validation cannot become a post-proof failure.
    anyhow::ensure!(
        identity.as_str().len() <= crate::MAX_CANONICAL_ENDPOINT_IDENTITY_BYTES,
        "canonical sequencer endpoint identity exceeds {} bytes",
        crate::MAX_CANONICAL_ENDPOINT_IDENTITY_BYTES
    );
    Ok(identity)
}

// SYSCOIN: Recovered envelopes must already contain the exact canonical identity produced during
// client construction; canonicalization is validation here, never a silent on-disk rewrite.
pub fn validate_canonical_endpoint_identity(value: &str) -> anyhow::Result<Url> {
    let parsed = Url::parse(value).context("invalid envelope endpoint")?;
    let canonical = canonical_endpoint_identity(&parsed)?;
    anyhow::ensure!(
        canonical.as_str() == value,
        "durable submission endpoint identity is non-canonical or contains userinfo, query, or fragment"
    );
    Ok(canonical)
}

// SYSCOIN: Plain HTTP is confined to a syntactically verified loopback host unless the operator
// explicitly acknowledges external transport security.
fn endpoint_host_is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

fn validate_endpoint_transport(url: &Url, allow_insecure_http: bool) -> anyhow::Result<()> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if endpoint_host_is_loopback(url) => Ok(()),
        "http" if allow_insecure_http => {
            tracing::warn!(
                host = url.host_str().unwrap_or("unknown"),
                "explicitly allowing non-loopback plaintext sequencer HTTP; credentials and proof capabilities are not transport-encrypted"
            );
            Ok(())
        }
        "http" => Err(anyhow!(
            "refusing non-loopback plaintext sequencer endpoint {}; use HTTPS or explicitly acknowledge insecure HTTP",
            canonical_endpoint_identity(url)?
        )),
        scheme => Err(anyhow!(
            "unsupported sequencer endpoint scheme {scheme:?}; expected https or loopback http"
        )),
    }
}

// SYSCOIN: At this point URL construction and JSON serialization are deterministic and already
// completed by reqwest's request builder. Request/body/connect failures and timeouts are therefore
// transport failures for which replaying the same idempotency capability is the safe operation.
fn submission_transport_error_is_retryable(error: &reqwest::Error) -> bool {
    error.is_timeout() || error.is_connect() || error.is_request() || error.is_body()
}

// SYSCOIN: A status code alone can be emitted by a proxy, JSON extractor, or body limiter. Retire
// only an exact single application marker paired with the manager's enumerated terminal status.
fn submission_response_is_definitive(response: &reqwest::Response) -> bool {
    let mut dispositions = response.headers().get_all(PROVER_DISPOSITION_HEADER).iter();
    let Some(disposition) = dispositions.next().and_then(|value| value.to_str().ok()) else {
        return false;
    };
    if dispositions.next().is_some() {
        return false;
    }
    match disposition {
        PROVER_DISPOSITION_ACCEPTED => response.status() == StatusCode::NO_CONTENT,
        PROVER_DISPOSITION_REJECTED => submission_rejection_status_is_terminal(response.status()),
        _ => false,
    }
}

// SYSCOIN: Keep the rejection matrix narrow and duplicated in server tests. A marker on any other
// status is a protocol/configuration fault and retains the exact envelope for operator recovery.
fn submission_rejection_status_is_terminal(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::BAD_REQUEST
            | StatusCode::CONFLICT
            | StatusCode::PAYLOAD_TOO_LARGE
            | StatusCode::UNPROCESSABLE_ENTITY
    )
}

// SYSCOIN: Stream the transparently decompressed body under a hard class-specific cap. Never trust
// Content-Length alone: compressed and chunked responses can otherwise allocate without bound.
async fn read_json_bounded<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
    maximum_bytes: usize,
    response_kind: &str,
) -> anyhow::Result<T> {
    if let Some(content_length) = response.content_length() {
        anyhow::ensure!(
            content_length <= maximum_bytes as u64,
            "{response_kind} Content-Length {content_length} exceeds {maximum_bytes} bytes"
        );
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.with_context(|| format!("read {response_kind} response body"))?;
        let next_length = body
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow!("{response_kind} response length overflow"))?;
        anyhow::ensure!(
            next_length <= maximum_bytes,
            "{response_kind} decompressed body exceeds {maximum_bytes} bytes"
        );
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).with_context(|| format!("decode {response_kind} JSON"))
}

// SYSCOIN: Fixed B256 fields are rejected before decoding potentially large base64 job material.
fn validate_pick_authority(vk_hash: &str, lease_token: &ProverLeaseToken) -> anyhow::Result<()> {
    crate::validate_b256_wire_value(vk_hash, "verification-key hash")?;
    lease_token.validate_wire_value()
}

// SYSCOIN: Status hints must carry the same exact B256 VK grammar as lease-bearing picks.
fn validate_peek_vk(vk_hash: &str) -> anyhow::Result<()> {
    crate::validate_b256_wire_value(vk_hash, "verification-key hash")
}

// SYSCOIN: Bound decoded FRI execution input independently of JSON/base64 expansion.
fn decode_fri_input_bounded(encoded: &str) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        encoded.len() <= MAX_FRI_JOB_RESPONSE_BYTES,
        "encoded FRI prover input exceeds {} bytes",
        MAX_FRI_JOB_RESPONSE_BYTES
    );
    let data = STANDARD
        .decode(encoded)
        .map_err(|error| anyhow!("Failed to decode batch data: {error}"))?;
    anyhow::ensure!(
        data.len() <= MAX_FRI_JOB_RESPONSE_BYTES,
        "decoded FRI prover input exceeds {} bytes",
        MAX_FRI_JOB_RESPONSE_BYTES
    );
    Ok(data)
}

// SYSCOIN: Retry sleeps and active submissions observe the same stop signal without retiring the
// durable proof/capability; exponential delay remains bounded for recovery liveness.
async fn wait_for_shutdown(mut shutdown: Option<watch::Receiver<bool>>) {
    let Some(receiver) = shutdown.as_mut() else {
        pending::<()>().await;
        return;
    };
    if *receiver.borrow() {
        return;
    }
    let _ = receiver.changed().await;
}

fn proof_submission_retry_delay(retry_count: u32) -> Duration {
    let multiplier = 1_u32 << retry_count.min(5);
    PROOF_SUBMISSION_RETRY_INITIAL_DELAY
        .saturating_mul(multiplier)
        .min(PROOF_SUBMISSION_RETRY_MAX_DELAY)
}

#[async_trait]
impl ProofClient for SequencerProofClient {
    fn sequencer_url(&self) -> &Url {
        &self.endpoint
    }

    // SYSCOIN: Expose the concrete client's durable replay gate through the shared worker trait.
    async fn resume_pending_submissions(&self) -> anyhow::Result<usize> {
        self.resume_durable_submissions().await
    }

    async fn pick_fri_job(&self) -> anyhow::Result<Option<FriJobInputs>> {
        // SYSCOIN: Client-level fail-closed gate backs up the service startup/loop replay gate.
        self.gate_new_pick().await?;
        let url = self.build_url(&format!("FRI/pick?{}", self.pick_query()))?;

        let started_at = Instant::now();

        let resp = self
            .client
            .post(url.clone())
            .send()
            .await
            .context("Pick Fri Job request failed")?;

        SEQUENCER_CLIENT_METRICS.time_taken[&Method::PickFri]
            .observe(started_at.elapsed().as_secs_f64());

        match resp.status() {
            StatusCode::OK => {
                // SYSCOIN: HTTP 200 means the server already assigned a lease. Mark every parse,
                // authority, version, and allocation failure so worker loops cannot try endpoint B.
                let parsed = async {
                    let body: NextFriProverJobPayload =
                        read_json_bounded(resp, MAX_FRI_JOB_RESPONSE_BYTES, "FRI pick").await?;
                    validate_pick_authority(&body.vk_hash, &body.lease_token)?;
                    anyhow::ensure!(
                        self.supported_vk_hashes.is_empty()
                            || self.supported_vk_hashes.contains(&body.vk_hash),
                        "FRI pick returned a VK hash this prover did not advertise"
                    );
                    let data = decode_fri_input_bounded(&body.prover_input)?;
                    Ok::<_, anyhow::Error>(FriJobInputs {
                        batch_number: body.batch_number,
                        vk_hash: body.vk_hash,
                        prover_input: data,
                        lease_token: body.lease_token,
                    })
                }
                .await;
                parsed.map(Some).map_err(crate::leased_job_response_error)
            }
            StatusCode::NO_CONTENT => Ok(None),
            s => Err(anyhow!(
                "Unexpected status {s} when fetching next batch at address {url}"
            )),
        }
    }

    async fn submit_fri_proof(
        &self,
        batch_number: u32,
        vk_hash: String,
        proof: String,
        lease_token: ProverLeaseToken,
    ) -> anyhow::Result<()> {
        // SYSCOIN: The sequencer authenticates this capability, never the public prover label.
        // Persist the complete exact submission before its first request.
        let envelope = DurableSubmissionEnvelope::fri(
            self.endpoint.to_string(),
            batch_number as u64,
            vk_hash,
            proof,
            lease_token,
        );

        let started_at = Instant::now();

        // SYSCOIN: Preserve the same proof/capability through verifier backpressure and request
        // transport failures. The V32 server returns 503 only before FRI completion (shutdown or
        // temporary persistence failure); any post-completion rollback returns definitive 409.
        let resp = self
            .submit_envelope(envelope)
            .await
            .context("Submit Fri Proof request failed")?;

        SEQUENCER_CLIENT_METRICS.time_taken[&Method::SubmitFri]
            .observe(started_at.elapsed().as_secs_f64());

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(anyhow!(
                "Server returned {} when submitting proof to {}",
                resp.status(),
                self.endpoint
            ))
        }
    }

    // SYSCOIN: Read the queue without acquiring a lease; callers use it only as a hint.
    async fn status(&self, stage: JobQueueStage) -> anyhow::Result<Vec<QueueJobStatus>> {
        let stage = match stage {
            JobQueueStage::Fri => "fri",
            JobQueueStage::Snark => "snark",
        };
        let url = self.build_url(&format!("status/{stage}"))?;
        let started_at = Instant::now();
        let resp = self
            .client
            .get(url.clone())
            .send()
            .await
            .context("Queue status request failed")?;

        SEQUENCER_CLIENT_METRICS.time_taken[&Method::StatusQueue]
            .observe(started_at.elapsed().as_secs_f64());

        let resp = resp
            .error_for_status()
            .with_context(|| format!("Queue status request returned an error status from {url}"))?;
        Ok(read_json_bounded::<Vec<JobStatusPayload>>(
            resp,
            MAX_STATUS_RESPONSE_BYTES,
            "queue status",
        )
        .await?
        .into_iter()
        .map(|payload| QueueJobStatus {
            batch_number: payload.fri_job.batch_number,
            vk_hash: payload.fri_job.vk_hash,
            added_seconds_ago: payload.added_seconds_ago,
            assigned_seconds_ago: payload.assigned_seconds_ago,
            assigned_to_prover_id: payload.assigned_to_prover_id,
            current_attempt: payload.current_attempt,
        })
        .collect())
    }

    async fn pick_snark_job(&self) -> anyhow::Result<Option<SnarkProofInputs>> {
        // SYSCOIN: Never acquire a new range behind an unresolved retained FRI/SNARK envelope.
        self.gate_new_pick().await?;
        let url = self.build_url(&format!("SNARK/pick?{}", self.pick_query()))?;

        let started_at = Instant::now();

        let resp = self
            .client
            .post(url.clone())
            .send()
            .await
            .context("Pick Snark Job request failed")?;

        SEQUENCER_CLIENT_METRICS.time_taken[&Method::PickSnark]
            .observe(started_at.elapsed().as_secs_f64());

        match resp.status() {
            StatusCode::OK => {
                // SYSCOIN: SNARK HTTP 200 has already leased an exact aggregate range; any invalid
                // bounded payload is fatal and cannot be downgraded to an endpoint fallback.
                let parsed = async {
                    let payload = read_json_bounded::<GetSnarkProofPayload>(
                        resp,
                        MAX_SNARK_JOB_RESPONSE_BYTES,
                        "SNARK pick",
                    )
                    .await?;
                    anyhow::ensure!(
                        self.supported_vk_hashes.is_empty()
                            || self.supported_vk_hashes.contains(&payload.vk_hash),
                        "SNARK pick returned a VK hash this prover did not advertise"
                    );
                    payload
                        .try_into()
                        .context("failed to parse SnarkProofPayload")
                }
                .await;
                parsed.map(Some).map_err(crate::leased_job_response_error)
            }
            StatusCode::NO_CONTENT => Ok(None),
            s => Err(anyhow!("Failed to pick SNARK job: status {s} from {url}")),
        }
    }

    async fn submit_snark_proof(
        &self,
        from_batch_number: L2BatchNumber,
        to_batch_number: L2BatchNumber,
        vk_hash: String,
        proof: SnarkWrapperProof,
        lease_token: ProverLeaseToken,
    ) -> anyhow::Result<()> {
        let started_at = Instant::now();

        let serialized_proof = self
            .serialize_snark_proof(&proof)
            .context("Failed to serialize SNARK proof")?;

        // SYSCOIN: Return the exact aggregate capability unchanged with the wrapper proof and
        // durably couple it to the already-serialized proof before the first request.
        let envelope = DurableSubmissionEnvelope::snark(
            self.endpoint.to_string(),
            from_batch_number.0 as u64,
            to_batch_number.0 as u64,
            vk_hash,
            serialized_proof,
            lease_token,
        );
        // SYSCOIN: Both 429 capacity and the lease-releasing 503 shutdown response retain the exact
        // aggregate lease. Transport/proxy failures replay these same bytes and safely converge.
        let resp = self
            .submit_envelope(envelope)
            .await
            .context("Submit Snark Proof request failed")?;
        resp.error_for_status()
            .context("Request returned error status")?;

        SEQUENCER_CLIENT_METRICS.time_taken[&Method::SubmitSnark]
            .observe(started_at.elapsed().as_secs_f64());
        Ok(())
    }
}

#[async_trait]
// SYSCOIN: Every authority-free diagnostic/peek response is bounded and cross-checked against the
// requested batch or range before decoded material reaches callers.
impl PeekableProofClient for SequencerProofClient {
    async fn peek_fri_job(&self, batch_number: u32) -> anyhow::Result<Option<(u32, Vec<u8>)>> {
        let url = self.build_url(&format!("FRI/{batch_number}/peek"))?;
        let resp = self
            .client
            .get(url.clone())
            .send()
            .await
            .context("Peek Fri Job request failed")?;

        match resp.status() {
            StatusCode::OK => {
                let body: PeekFriProverJobPayload =
                    read_json_bounded(resp, MAX_FRI_JOB_RESPONSE_BYTES, "FRI peek").await?;
                validate_peek_vk(&body.vk_hash)?;
                anyhow::ensure!(
                    body.batch_number == batch_number,
                    "FRI peek returned batch {}, expected {batch_number}",
                    body.batch_number
                );
                let data = decode_fri_input_bounded(&body.prover_input)?;
                Ok(Some((body.batch_number, data)))
            }
            StatusCode::NO_CONTENT => Ok(None),
            s => Err(anyhow!(
                "Unexpected status {s} when peeking the batch {batch_number} at {url}",
            )),
        }
    }

    async fn peek_snark_job(
        &self,
        from_batch_number: u32,
        to_batch_number: u32,
    ) -> anyhow::Result<Option<PeekSnarkProofInputs>> {
        let url = self.build_url(&format!("SNARK/{from_batch_number}/{to_batch_number}/peek"))?;
        let resp = self
            .client
            .get(url.clone())
            .send()
            .await
            .context("Peek Snark Job request failed")?;

        match resp.status() {
            StatusCode::OK => {
                let get_snark_proof_payload = read_json_bounded::<PeekSnarkProofPayload>(
                    resp,
                    MAX_SNARK_JOB_RESPONSE_BYTES,
                    "SNARK peek",
                )
                .await?;
                anyhow::ensure!(
                    get_snark_proof_payload.from_batch_number == u64::from(from_batch_number)
                        && get_snark_proof_payload.to_batch_number == u64::from(to_batch_number),
                    "SNARK peek response range does not match requested range"
                );
                Ok(Some(
                    get_snark_proof_payload
                        .try_into()
                        .context("failed to parse SnarkProofPayload")?,
                ))
            }
            StatusCode::NO_CONTENT => Ok(None),
            s => Err(anyhow!(
                "Unexpected status {s} when peeking FRI proofs from {from_batch_number} to {to_batch_number} at {url}",
            )),
        }
    }

    async fn get_failed_fri_proof(
        &self,
        batch_number: u32,
    ) -> anyhow::Result<Option<FailedFriProofPayload>> {
        let url = self.build_url(&format!("FRI/{batch_number}/failed"))?;
        let resp = self
            .client
            .get(url.clone())
            .send()
            .await
            .context("Get Failed Fri Proof request failed")?;

        match resp.status() {
            StatusCode::OK => {
                let body: FailedFriProofPayload = read_json_bounded(
                    resp,
                    MAX_FRI_DIAGNOSTIC_RESPONSE_BYTES,
                    "failed FRI proof",
                )
                .await?;
                anyhow::ensure!(
                    body.batch_number == u64::from(batch_number),
                    "failed FRI proof response batch does not match requested batch"
                );
                Ok(Some(body))
            }
            StatusCode::NO_CONTENT => Ok(None),
            s => Err(anyhow!(
                "Unexpected status {s} when peeking failed FRI proof for batch {batch_number} at {url}",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::path::{Path, PathBuf};
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    };
    use std::thread::JoinHandle;
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn valid_vk_hash() -> String {
        format!("0x{}", "ab".repeat(32))
    }

    fn valid_lease_token() -> ProverLeaseToken {
        ProverLeaseToken::from(format!("0x{}", "cd".repeat(32)))
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let counter = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "zksync-sequencer-client-test-{}-{nanos}-{counter}",
                std::process::id()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    enum ScriptedHttpReply {
        DropConnection,
        Status(&'static str),
        Disposition(&'static str, &'static str),
        DelayedDisposition(Duration, &'static str, &'static str),
        DeclaredBody(&'static str, usize),
        Redirect(String),
    }

    type ScriptedServer = (SequencerEndpoint, Arc<Mutex<Vec<Vec<u8>>>>, JoinHandle<()>);

    fn read_http_request_body(stream: &mut TcpStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let bytes_read = stream.read(&mut buffer).unwrap();
            assert!(bytes_read > 0, "client closed before completing request");
            request.extend_from_slice(&buffer[..bytes_read]);

            let Some(header_end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") else {
                continue;
            };
            let body_start = header_end + 4;
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if request.len() >= body_start + content_length {
                return request[body_start..body_start + content_length].to_vec();
            }
        }
    }

    fn scripted_http_server(replies: Vec<ScriptedHttpReply>) -> ScriptedServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let request_bodies = Arc::new(Mutex::new(Vec::new()));
        let captured_bodies = Arc::clone(&request_bodies);
        let server = std::thread::spawn(move || {
            for reply in replies {
                let (mut stream, _) = listener.accept().unwrap();
                let body = read_http_request_body(&mut stream);
                captured_bodies.lock().unwrap().push(body);
                match reply {
                    ScriptedHttpReply::DropConnection => {
                        stream.shutdown(Shutdown::Both).unwrap();
                    }
                    ScriptedHttpReply::Status(status) => {
                        let response = format!(
                            "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        stream.write_all(response.as_bytes()).unwrap();
                        stream.flush().unwrap();
                    }
                    ScriptedHttpReply::Disposition(status, disposition) => {
                        let response = format!(
                            "HTTP/1.1 {status}\r\n{PROVER_DISPOSITION_HEADER}: {disposition}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        stream.write_all(response.as_bytes()).unwrap();
                        stream.flush().unwrap();
                    }
                    ScriptedHttpReply::DelayedDisposition(delay, status, disposition) => {
                        std::thread::sleep(delay);
                        let response = format!(
                            "HTTP/1.1 {status}\r\n{PROVER_DISPOSITION_HEADER}: {disposition}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        stream.write_all(response.as_bytes()).unwrap();
                        stream.flush().unwrap();
                    }
                    ScriptedHttpReply::DeclaredBody(status, content_length) => {
                        let response = format!(
                            "HTTP/1.1 {status}\r\nContent-Length: {content_length}\r\nConnection: close\r\n\r\n"
                        );
                        stream.write_all(response.as_bytes()).unwrap();
                        stream.flush().unwrap();
                    }
                    ScriptedHttpReply::Redirect(location) => {
                        let response = format!(
                            "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        stream.write_all(response.as_bytes()).unwrap();
                        stream.flush().unwrap();
                    }
                }
            }
        });
        let endpoint =
            SequencerEndpoint::parse(&format!("http://{address}")).expect("valid test endpoint");
        (endpoint, request_bodies, server)
    }

    #[test]
    fn test_client_strips_credentials() {
        let endpoint = SequencerEndpoint::parse("http://user:password123@localhost:3124").unwrap();

        let client = SequencerProofClient::new(endpoint, "test_prover".to_string(), None, vec![])
            .expect("failed to create client");

        // URL should be clean (no credentials)
        let url = client.sequencer_url();
        assert_eq!(url.username(), "");
        assert_eq!(url.password(), None);
        assert_eq!(url.as_str(), "http://localhost:3124/");
    }

    #[test]
    fn non_loopback_plaintext_endpoint_fails_closed_by_default() {
        let endpoint = SequencerEndpoint::parse("http://user:password123@192.0.2.10:3124").unwrap();
        let error = SequencerProofClient::new(endpoint, "test_prover".to_owned(), None, vec![])
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("refusing non-loopback plaintext"));
    }

    // SYSCOIN: The escape hatch is explicit and construction-only for isolated private networks.
    #[test]
    fn non_loopback_plaintext_endpoint_requires_explicit_override() {
        let endpoint = SequencerEndpoint::parse("http://192.0.2.10:3124").unwrap();
        SequencerProofClient::new_configured(
            endpoint,
            "test_prover".to_owned(),
            DEFAULT_REQUEST_TIMEOUT,
            DEFAULT_READ_TIMEOUT,
            vec![],
            None,
            None,
            true,
        )
        .unwrap();
    }

    // SYSCOIN: Endpoint identity bounds are a construction-time invariant, never a failure first
    // discovered after a lease has been proved and its durable envelope is being created.
    #[test]
    fn canonical_endpoint_identity_limit_is_enforced_before_picks() {
        let prefix = "https://sequencer.example/";
        let maximum = format!(
            "{prefix}{}/",
            "a".repeat(crate::MAX_CANONICAL_ENDPOINT_IDENTITY_BYTES - prefix.len() - 1)
        );
        let endpoint = SequencerEndpoint::parse(&maximum).unwrap();
        SequencerProofClient::new(endpoint, "test-prover".to_owned(), None, vec![]).unwrap();

        let oversized = format!("{}a/", maximum.trim_end_matches('/'));
        let endpoint = SequencerEndpoint::parse(&oversized).unwrap();
        let error = SequencerProofClient::new(endpoint, "test-prover".to_owned(), None, vec![])
            .unwrap_err();
        assert!(error.to_string().contains("exceeds 2048 bytes"));
    }

    // SYSCOIN: Distinct non-trailing path identities must never collapse to the same effective
    // `prover-jobs/v1/` URL. Explicit directory-style bases remain distinct and routable.
    #[test]
    fn endpoint_identity_rejects_file_style_base_paths() {
        for url in [
            "https://sequencer.example/foo",
            "https://sequencer.example/bar",
        ] {
            let endpoint = SequencerEndpoint::parse(url).unwrap();
            let error = SequencerProofClient::new(endpoint, "test-prover".to_owned(), None, vec![])
                .unwrap_err();
            assert!(error.to_string().contains("must end with '/'"));
        }

        let first = SequencerProofClient::new(
            SequencerEndpoint::parse("https://sequencer.example/foo/").unwrap(),
            "test-prover".to_owned(),
            None,
            vec![],
        )
        .unwrap();
        let second = SequencerProofClient::new(
            SequencerEndpoint::parse("https://sequencer.example/bar/").unwrap(),
            "test-prover".to_owned(),
            None,
            vec![],
        )
        .unwrap();
        assert_eq!(
            first.build_url("FRI/pick").unwrap().as_str(),
            "https://sequencer.example/foo/prover-jobs/v1/FRI/pick"
        );
        assert_eq!(
            second.build_url("FRI/pick").unwrap().as_str(),
            "https://sequencer.example/bar/prover-jobs/v1/FRI/pick"
        );
    }

    // SYSCOIN: Lock retry/retention parity with server and proxy status semantics.
    #[test]
    fn submission_status_matrix_preserves_ambiguous_and_configuration_failures() {
        for status in [408, 425, 429, 500, 520, 521, 522, 523, 524, 599] {
            let status = StatusCode::from_u16(status).unwrap();
            assert!(SubmissionStage::Fri.should_retry_same_submission(status));
        }
        for status in [400, 409, 413, 422] {
            assert!(submission_rejection_status_is_terminal(
                StatusCode::from_u16(status).unwrap()
            ));
        }
        for status in [301, 307, 401, 403, 404, 405] {
            let status = StatusCode::from_u16(status).unwrap();
            assert!(!SubmissionStage::Fri.should_retry_same_submission(status));
            assert!(!submission_rejection_status_is_terminal(status));
        }
    }

    #[test]
    fn authorization_header_is_sensitive_before_client_storage() {
        let header = sensitive_authorization_value("Basic test-secret").unwrap();
        assert!(header.is_sensitive());
        assert!(!format!("{header:?}").contains("test-secret"));
    }

    #[test]
    fn test_pick_query_without_supported_vk_hashes() {
        let endpoint = SequencerEndpoint::parse("http://localhost:3124").unwrap();
        let client = SequencerProofClient::new(endpoint, "test_prover".to_string(), None, vec![])
            .expect("failed to create client");

        assert_eq!(client.pick_query(), "id=test_prover");
    }

    #[test]
    fn test_pick_query_with_supported_vk_hashes() {
        let endpoint = SequencerEndpoint::parse("http://localhost:3124").unwrap();
        let first = format!("0x{}", "aa".repeat(32));
        let second = format!("0x{}", "bb".repeat(32));
        let client = SequencerProofClient::new(
            endpoint,
            "test_prover".to_string(),
            None,
            vec![first.clone(), second.clone()],
        )
        .expect("failed to create client");

        assert_eq!(
            client.pick_query(),
            format!("id=test_prover&supported_vk_hashes={first},{second}")
        );
    }

    #[test]
    fn rejects_unbounded_or_query_injecting_prover_names() {
        for prover_name in [
            "",
            "contains space",
            "query&injection",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            let endpoint = SequencerEndpoint::parse("http://localhost:3124").unwrap();
            assert!(
                SequencerProofClient::new(endpoint, prover_name.to_owned(), None, vec![]).is_err()
            );
        }
    }

    #[test]
    fn test_client_without_credentials() {
        let endpoint = SequencerEndpoint::parse("http://localhost:3124").unwrap();

        let client = SequencerProofClient::new(endpoint, "test_prover".to_string(), None, vec![])
            .expect("failed to create client");

        let url = client.sequencer_url();
        assert_eq!(url.as_str(), "http://localhost:3124/");
    }

    #[tokio::test]
    async fn fri_submission_retries_transient_proxy_statuses_with_identical_proof_and_lease() {
        let (endpoint, request_bodies, server) = scripted_http_server(vec![
            ScriptedHttpReply::Status("408 Request Timeout"),
            ScriptedHttpReply::Status("425 Too Early"),
            ScriptedHttpReply::Status("429 Too Many Requests"),
            ScriptedHttpReply::Status("502 Bad Gateway"),
            ScriptedHttpReply::Status("503 Service Unavailable"),
            ScriptedHttpReply::Status("504 Gateway Timeout"),
            ScriptedHttpReply::Status("500 Internal Server Error"),
            ScriptedHttpReply::Status("520 Web Server Returned an Unknown Error"),
            ScriptedHttpReply::Disposition("204 No Content", PROVER_DISPOSITION_ACCEPTED),
        ]);
        let client =
            SequencerProofClient::new(endpoint, "fri-prover".to_owned(), None, vec![]).unwrap();
        let token = "0x1111111111111111111111111111111111111111111111111111111111111111";

        client
            .submit_fri_proof(
                7,
                valid_vk_hash(),
                "expensive-proof".to_owned(),
                ProverLeaseToken::from(token.to_owned()),
            )
            .await
            .unwrap();
        server.join().unwrap();

        let bodies = request_bodies.lock().unwrap();
        assert_eq!(bodies.len(), 9);
        assert!(
            bodies.windows(2).all(|pair| pair[0] == pair[1]),
            "replayed request bodies differ"
        );
        let submitted: serde_json::Value = serde_json::from_slice(&bodies[0]).unwrap();
        assert_eq!(submitted["lease_token"], token);
        assert_eq!(submitted["proof"], "expensive-proof");
    }

    #[tokio::test]
    async fn snark_submission_retries_transport_and_503_with_identical_body() {
        let (endpoint, request_bodies, server) = scripted_http_server(vec![
            ScriptedHttpReply::DropConnection,
            ScriptedHttpReply::Status("503 Service Unavailable"),
            ScriptedHttpReply::Disposition("204 No Content", PROVER_DISPOSITION_ACCEPTED),
        ]);
        let client =
            SequencerProofClient::new(endpoint, "snark-prover".to_owned(), None, vec![]).unwrap();
        let token = "0x2222222222222222222222222222222222222222222222222222222222222222";
        let envelope = DurableSubmissionEnvelope::snark(
            client.endpoint.to_string(),
            10,
            11,
            valid_vk_hash(),
            "expensive-wrapper-proof".to_owned(),
            ProverLeaseToken::from(token.to_owned()),
        );

        let response = client.submit_envelope(envelope).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        server.join().unwrap();

        let bodies = request_bodies.lock().unwrap();
        assert_eq!(bodies.len(), 3);
        assert!(
            bodies.windows(2).all(|pair| pair[0] == pair[1]),
            "replayed request bodies differ"
        );
        let submitted: serde_json::Value = serde_json::from_slice(&bodies[0]).unwrap();
        assert_eq!(submitted["lease_token"], token);
        assert_eq!(submitted["proof"], "expensive-wrapper-proof");
    }

    #[tokio::test]
    async fn submission_response_may_exceed_short_pick_read_timeout() {
        let (endpoint, request_bodies, server) =
            scripted_http_server(vec![ScriptedHttpReply::DelayedDisposition(
                Duration::from_millis(75),
                "204 No Content",
                PROVER_DISPOSITION_ACCEPTED,
            )]);
        let client = SequencerProofClient::new_with_timeouts(
            endpoint,
            "fri-prover".to_owned(),
            Duration::from_millis(500),
            Duration::from_millis(10),
            vec![],
        )
        .unwrap();

        tokio::time::timeout(
            Duration::from_millis(300),
            client.submit_fri_proof(
                7,
                valid_vk_hash(),
                "proof".to_owned(),
                ProverLeaseToken::from(
                    "0x3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
                ),
            ),
        )
        .await
        .expect("submission must use the long verifier response timeout")
        .unwrap();
        server.join().unwrap();
        assert_eq!(request_bodies.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn submission_redirect_never_replays_capability_to_second_origin() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        target.set_nonblocking(true).unwrap();
        let target_url = format!("http://{}/exfiltrate", target.local_addr().unwrap());
        let (endpoint, request_bodies, server) =
            scripted_http_server(vec![ScriptedHttpReply::Redirect(target_url)]);
        let client =
            SequencerProofClient::new(endpoint, "fri-prover".to_owned(), None, vec![]).unwrap();

        let error = client
            .submit_fri_proof(
                7,
                valid_vk_hash(),
                "proof".to_owned(),
                ProverLeaseToken::from(
                    "0x4444444444444444444444444444444444444444444444444444444444444444".to_owned(),
                ),
            )
            .await
            .expect_err("redirect must be returned as a definitive error");
        assert!(format!("{error:#}").contains("307"));
        server.join().unwrap();
        assert_eq!(request_bodies.lock().unwrap().len(), 1);
        assert!(matches!(
            target.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    // SYSCOIN: A generated proof is fsynced before shutdown wins and is replayed after the next
    // process exclusively acquires the same owner-only spool.
    #[tokio::test]
    async fn shutdown_retains_envelope_and_restart_replays_before_new_work() {
        let temporary = TestDirectory::new();
        let submission_directory = temporary.path().join("submissions");
        let (endpoint, request_bodies, server) =
            scripted_http_server(vec![ScriptedHttpReply::Disposition(
                "204 No Content",
                PROVER_DISPOSITION_ACCEPTED,
            )]);
        let (stop_sender, stop_receiver) = watch::channel(false);
        stop_sender.send_replace(true);
        let clients = SequencerProofClient::new_durable_clients(
            vec![endpoint.clone()],
            "fri-prover".to_owned(),
            None,
            vec![],
            submission_directory.clone(),
            stop_receiver,
            false,
        )
        .unwrap();
        let token = "0x5555555555555555555555555555555555555555555555555555555555555555";
        let error = clients[0]
            .submit_fri_proof(
                9,
                valid_vk_hash(),
                "restart-proof".to_owned(),
                ProverLeaseToken::from(token.to_owned()),
            )
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("deferred by shutdown"));
        assert_eq!(
            std::fs::read_dir(&submission_directory)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name == "pending.json")
                })
                .count(),
            1
        );
        drop(clients);

        let (_stop_sender, stop_receiver) = watch::channel(false);
        let clients = SequencerProofClient::new_durable_clients(
            vec![endpoint],
            "fri-prover".to_owned(),
            None,
            vec![],
            submission_directory.clone(),
            stop_receiver,
            false,
        )
        .unwrap();
        assert_eq!(resume_pending_submissions(&clients).await.unwrap(), 1);
        server.join().unwrap();
        let bodies = request_bodies.lock().unwrap();
        assert_eq!(bodies.len(), 1);
        let submitted: serde_json::Value = serde_json::from_slice(&bodies[0]).unwrap();
        assert_eq!(submitted["lease_token"], token);
        assert_eq!(submitted["proof"], "restart-proof");
        assert_eq!(
            std::fs::read_dir(&submission_directory)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name == "pending.json")
                })
                .count(),
            0
        );
    }

    // SYSCOIN: Authentication/routing responses are not proof-definitive. Keep the envelope and
    // make the next pick fail on replay rather than silently proving another leased batch.
    #[tokio::test]
    async fn retained_auth_error_blocks_new_pick_without_spinning() {
        let temporary = TestDirectory::new();
        let submission_directory = temporary.path().join("submissions");
        let (endpoint, request_bodies, server) = scripted_http_server(vec![
            ScriptedHttpReply::Status("401 Unauthorized"),
            ScriptedHttpReply::Status("401 Unauthorized"),
        ]);
        let (_stop_sender, stop_receiver) = watch::channel(false);
        let clients = SequencerProofClient::new_durable_clients(
            vec![endpoint],
            "fri-prover".to_owned(),
            None,
            vec![],
            submission_directory,
            stop_receiver,
            false,
        )
        .unwrap();
        clients[0]
            .submit_fri_proof(
                10,
                valid_vk_hash(),
                "retained-proof".to_owned(),
                valid_lease_token(),
            )
            .await
            .unwrap_err();
        let error = clients[0].pick_fri_job().await.unwrap_err();
        assert!(format!("{error:#}").contains("401"));
        server.join().unwrap();
        let bodies = request_bodies.lock().unwrap();
        assert_eq!(
            bodies.len(),
            2,
            "a third request would be a forbidden new pick"
        );
        assert_eq!(bodies[0], bodies[1]);
    }

    // SYSCOIN: Status codes from proxies/parsers are never proof dispositions without the exact
    // application marker, including otherwise-successful 2xx and familiar terminal 4xx values.
    #[tokio::test]
    async fn unmarked_proxy_statuses_retain_durable_submission() {
        for (index, status) in [
            "200 OK",
            "204 No Content",
            "400 Bad Request",
            "413 Payload Too Large",
            "422 Unprocessable Entity",
        ]
        .into_iter()
        .enumerate()
        {
            let temporary = TestDirectory::new();
            let submission_directory = temporary.path().join(format!("submissions-{index}"));
            let (endpoint, _request_bodies, server) =
                scripted_http_server(vec![ScriptedHttpReply::Status(status)]);
            let (_stop_sender, stop_receiver) = watch::channel(false);
            let clients = SequencerProofClient::new_durable_clients(
                vec![endpoint],
                "fri-prover".to_owned(),
                None,
                vec![],
                submission_directory.clone(),
                stop_receiver,
                false,
            )
            .unwrap();
            clients[0]
                .submit_fri_proof(1, valid_vk_hash(), "proof".to_owned(), valid_lease_token())
                .await
                .expect_err("unmarked response must retain the envelope");
            server.join().unwrap();
            assert_eq!(
                std::fs::read_dir(&submission_directory)
                    .unwrap()
                    .filter_map(Result::ok)
                    .filter(|entry| entry.file_name().to_string_lossy() == "pending.json")
                    .count(),
                1,
                "unmarked {status} retired an expensive proof"
            );
        }
    }

    #[tokio::test]
    async fn marked_terminal_rejection_retires_but_wrong_marker_pair_retains() {
        let temporary = TestDirectory::new();
        let submission_directory = temporary.path().join("rejected");
        let (endpoint, _request_bodies, server) =
            scripted_http_server(vec![ScriptedHttpReply::Disposition(
                "409 Conflict",
                PROVER_DISPOSITION_REJECTED,
            )]);
        let (_stop_sender, stop_receiver) = watch::channel(false);
        let clients = SequencerProofClient::new_durable_clients(
            vec![endpoint],
            "fri-prover".to_owned(),
            None,
            vec![],
            submission_directory.clone(),
            stop_receiver,
            false,
        )
        .unwrap();
        clients[0]
            .submit_fri_proof(1, valid_vk_hash(), "proof".to_owned(), valid_lease_token())
            .await
            .expect_err("manager rejection remains a submission error");
        server.join().unwrap();
        assert_eq!(
            std::fs::read_dir(&submission_directory)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy() == "pending.json")
                .count(),
            0
        );

        drop(clients);
        let wrong_directory = temporary.path().join("wrong-pair");
        let (endpoint, _request_bodies, server) =
            scripted_http_server(vec![ScriptedHttpReply::Disposition(
                "200 OK",
                PROVER_DISPOSITION_ACCEPTED,
            )]);
        let (_stop_sender, stop_receiver) = watch::channel(false);
        let clients = SequencerProofClient::new_durable_clients(
            vec![endpoint],
            "fri-prover".to_owned(),
            None,
            vec![],
            wrong_directory.clone(),
            stop_receiver,
            false,
        )
        .unwrap();
        clients[0]
            .submit_fri_proof(2, valid_vk_hash(), "proof".to_owned(), valid_lease_token())
            .await
            .expect_err("accepted marker on 200 must retain");
        server.join().unwrap();
        assert_eq!(
            std::fs::read_dir(wrong_directory)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy() == "pending.json")
                .count(),
            1
        );
    }

    // SYSCOIN: A crash-replayed terminal rejection retires the exact envelope but remains a
    // visible worker failure; startup must not reinterpret bad/stale production work as success.
    #[tokio::test]
    async fn replayed_terminal_rejection_is_retired_and_returned_as_error() {
        let temporary = TestDirectory::new();
        let submission_directory = temporary.path().join("replayed-rejection");
        let (endpoint, request_bodies, server) =
            scripted_http_server(vec![ScriptedHttpReply::Disposition(
                "400 Bad Request",
                PROVER_DISPOSITION_REJECTED,
            )]);

        let (stop_sender, stop_receiver) = watch::channel(false);
        stop_sender.send_replace(true);
        let clients = SequencerProofClient::new_durable_clients(
            vec![endpoint.clone()],
            "fri-prover".to_owned(),
            None,
            vec![],
            submission_directory.clone(),
            stop_receiver,
            false,
        )
        .unwrap();
        clients[0]
            .submit_fri_proof(
                3,
                valid_vk_hash(),
                "bad-proof".to_owned(),
                valid_lease_token(),
            )
            .await
            .expect_err("shutdown must retain the exact envelope without sending");
        drop(clients);

        let (_stop_sender, stop_receiver) = watch::channel(false);
        let clients = SequencerProofClient::new_durable_clients(
            vec![endpoint],
            "fri-prover".to_owned(),
            None,
            vec![],
            submission_directory.clone(),
            stop_receiver,
            false,
        )
        .unwrap();
        let error = resume_pending_submissions(&clients)
            .await
            .expect_err("replayed marked rejection must remain visible");
        assert!(format!("{error:#}").contains("definitive HTTP 400"));
        server.join().unwrap();
        assert_eq!(request_bodies.lock().unwrap().len(), 1);
        assert_eq!(
            std::fs::read_dir(submission_directory)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy() == "pending.json")
                .count(),
            0,
            "terminal replay rejection must retire exactly once"
        );
    }

    #[tokio::test]
    async fn oversized_decompressed_pick_is_marked_as_post_acquisition_failure() {
        let (endpoint, _request_bodies, server) =
            scripted_http_server(vec![ScriptedHttpReply::DeclaredBody(
                "200 OK",
                MAX_FRI_JOB_RESPONSE_BYTES + 1,
            )]);
        let client =
            SequencerProofClient::new(endpoint, "fri-prover".to_owned(), None, vec![]).unwrap();
        let error = client.pick_fri_job().await.unwrap_err();
        assert!(crate::error_follows_job_acquisition(&error));
        assert!(format!("{error:#}").contains("exceeds"));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn pending_endpoint_a_globally_blocks_endpoint_b_pick() {
        let temporary = TestDirectory::new();
        let submission_directory = temporary.path().join("global-gate");
        let endpoints = ["http://127.0.0.1:1", "http://127.0.0.1:2"]
            .into_iter()
            .map(SequencerEndpoint::parse)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let (stop_sender, stop_receiver) = watch::channel(false);
        stop_sender.send_replace(true);
        let clients = SequencerProofClient::new_durable_clients(
            endpoints,
            "fri-prover".to_owned(),
            None,
            vec![],
            submission_directory,
            stop_receiver,
            false,
        )
        .unwrap();
        clients[0]
            .submit_fri_proof(1, valid_vk_hash(), "proof".to_owned(), valid_lease_token())
            .await
            .expect_err("shutdown must retain endpoint A envelope");
        let error = clients[1].pick_fri_job().await.unwrap_err();
        assert!(error
            .to_string()
            .contains("unresolved envelope for another endpoint"));
    }

    // SYSCOIN: A post-proof disk failure returns a fatal error before any request can leave the
    // process; typed worker propagation then prevents endpoint-B fallback/fresh work.
    #[cfg(unix)]
    #[tokio::test]
    async fn durable_persist_failure_happens_before_first_submission_byte() {
        use std::os::unix::fs::PermissionsExt as _;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint =
            SequencerEndpoint::parse(&format!("http://{}", listener.local_addr().unwrap()))
                .unwrap();
        let temporary = TestDirectory::new();
        let submission_directory = temporary.path().join("read-only-spool");
        let (_stop_sender, stop_receiver) = watch::channel(false);
        let clients = SequencerProofClient::new_durable_clients(
            vec![endpoint],
            "fri-prover".to_owned(),
            None,
            vec![],
            submission_directory.clone(),
            stop_receiver,
            false,
        )
        .unwrap();
        std::fs::set_permissions(
            &submission_directory,
            std::fs::Permissions::from_mode(0o500),
        )
        .unwrap();
        let error = clients[0]
            .submit_fri_proof(1, valid_vk_hash(), "proof".to_owned(), valid_lease_token())
            .await
            .unwrap_err();
        std::fs::set_permissions(
            &submission_directory,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert!(format!("{error:#}").contains("create durable submission temporary file"));
        assert!(matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }
}
