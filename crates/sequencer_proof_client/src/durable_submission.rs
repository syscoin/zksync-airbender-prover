//! SYSCOIN: Crash-durable, owner-only ownership of one exact proof/capability submission.

use std::{
    collections::HashSet,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};

use crate::{
    ProverLeaseToken, SubmitFriProofPayload, SubmitSnarkProofPayload, MAX_FRIS_PER_SNARK_JOB,
    MAX_PROOF_SUBMISSION_BODY_BYTES,
};

const ENVELOPE_VERSION: u32 = 1;
// SYSCOIN: The endpoint/version wrapper is bounded separately, while `wire_body` enforces the
// server's exact 10 MiB body contract before publication and again on recovery.
const MAX_ENVELOPE_BYTES: u64 = (MAX_PROOF_SUBMISSION_BODY_BYTES + 64 * 1024) as u64;
static NEXT_FILE_ID: AtomicU64 = AtomicU64::new(0);

/// SYSCOIN: Versioned owner-only record coupling one proof to the exact capability and endpoint
/// that own it. Its Debug implementation deliberately exposes neither proof nor token.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct DurableSubmissionEnvelope {
    version: u32,
    endpoint: String,
    #[serde(flatten)]
    submission: DurableSubmission,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "stage", rename_all = "snake_case")]
pub(crate) enum DurableSubmission {
    Fri {
        batch_number: u64,
        vk_hash: String,
        proof: String,
        lease_token: ProverLeaseToken,
    },
    Snark {
        from_batch_number: u64,
        to_batch_number: u64,
        vk_hash: String,
        proof: String,
        lease_token: ProverLeaseToken,
    },
}

impl DurableSubmissionEnvelope {
    pub(crate) fn fri(
        endpoint: String,
        batch_number: u64,
        vk_hash: String,
        proof: String,
        lease_token: ProverLeaseToken,
    ) -> Self {
        Self {
            version: ENVELOPE_VERSION,
            endpoint,
            submission: DurableSubmission::Fri {
                batch_number,
                vk_hash,
                proof,
                lease_token,
            },
        }
    }

    pub(crate) fn snark(
        endpoint: String,
        from_batch_number: u64,
        to_batch_number: u64,
        vk_hash: String,
        proof: String,
        lease_token: ProverLeaseToken,
    ) -> Self {
        Self {
            version: ENVELOPE_VERSION,
            endpoint,
            submission: DurableSubmission::Snark {
                from_batch_number,
                to_batch_number,
                vk_hash,
                proof,
                lease_token,
            },
        }
    }

    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub(crate) fn stage(&self) -> &'static str {
        match &self.submission {
            DurableSubmission::Fri { .. } => "FRI",
            DurableSubmission::Snark { .. } => "SNARK",
        }
    }

    pub(crate) fn range(&self) -> (u64, u64) {
        match &self.submission {
            DurableSubmission::Fri { batch_number, .. } => (*batch_number, *batch_number),
            DurableSubmission::Snark {
                from_batch_number,
                to_batch_number,
                ..
            } => (*from_batch_number, *to_batch_number),
        }
    }

    pub(crate) fn submission(&self) -> &DurableSubmission {
        &self.submission
    }

    // SYSCOIN: Serialize the exact HTTP body, not an estimate based on proof length. JSON escaping
    // and capability/VK fields count toward the same server limit as the proof itself.
    pub(crate) fn wire_body(&self) -> anyhow::Result<Vec<u8>> {
        let body = match self.submission() {
            DurableSubmission::Fri {
                batch_number,
                vk_hash,
                proof,
                lease_token,
            } => serde_json::to_vec(&SubmitFriProofPayload {
                batch_number: *batch_number,
                vk_hash: vk_hash.clone(),
                proof: proof.clone(),
                lease_token: lease_token.clone(),
            })?,
            DurableSubmission::Snark {
                from_batch_number,
                to_batch_number,
                vk_hash,
                proof,
                lease_token,
            } => serde_json::to_vec(&SubmitSnarkProofPayload {
                from_batch_number: *from_batch_number,
                to_batch_number: *to_batch_number,
                vk_hash: vk_hash.clone(),
                proof: proof.clone(),
                lease_token: lease_token.clone(),
            })?,
        };
        anyhow::ensure!(
            body.len() <= MAX_PROOF_SUBMISSION_BODY_BYTES,
            "proof submission body is {} bytes; server maximum is {MAX_PROOF_SUBMISSION_BODY_BYTES}",
            body.len()
        );
        Ok(body)
    }

    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.version == ENVELOPE_VERSION,
            "unsupported durable submission envelope version {}",
            self.version
        );
        // SYSCOIN: Share the construction-time canonical/length contract so a configuration that
        // can pick work can never fail deterministically only after an expensive proof exists.
        crate::sequencer_proof_client::validate_canonical_endpoint_identity(&self.endpoint)?;
        match &self.submission {
            DurableSubmission::Fri {
                batch_number,
                vk_hash,
                proof,
                lease_token,
            } => {
                u32::try_from(*batch_number)
                    .context("FRI envelope batch number does not fit u32")?;
                crate::validate_b256_wire_value(vk_hash, "FRI envelope verification-key hash")?;
                lease_token.validate_wire_value()?;
                anyhow::ensure!(!proof.is_empty(), "FRI envelope has an empty proof");
            }
            DurableSubmission::Snark {
                from_batch_number,
                to_batch_number,
                vk_hash,
                proof,
                lease_token,
            } => {
                let from = u32::try_from(*from_batch_number)
                    .context("SNARK envelope start batch does not fit u32")?;
                let to = u32::try_from(*to_batch_number)
                    .context("SNARK envelope end batch does not fit u32")?;
                let count = to
                    .checked_sub(from)
                    .and_then(|difference| difference.checked_add(1))
                    .context("SNARK envelope has an inverted or overflowing range")?;
                anyhow::ensure!(
                    (2..=u32::try_from(MAX_FRIS_PER_SNARK_JOB)?).contains(&count),
                    "SNARK envelope range must contain 2..={MAX_FRIS_PER_SNARK_JOB} batches"
                );
                crate::validate_b256_wire_value(vk_hash, "SNARK envelope verification-key hash")?;
                lease_token.validate_wire_value()?;
                anyhow::ensure!(!proof.is_empty(), "SNARK envelope has an empty proof");
            }
        }
        self.wire_body()?;
        Ok(())
    }
}

impl fmt::Debug for DurableSubmissionEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableSubmissionEnvelope")
            .field("version", &self.version)
            .field("endpoint", &self.endpoint)
            .field("stage", &self.stage())
            .field("range", &self.range())
            .field("proof", &"[REDACTED]")
            .field("lease_token", &"[REDACTED]")
            .finish()
    }
}

/// SYSCOIN: One process owns a spool lock for its lifetime. All configured endpoint clients share
/// this object, so a second worker cannot replay or retire the same capability concurrently.
pub(crate) struct DurableSubmissionStore {
    directory: PathBuf,
    // SYSCOIN: Keep the validated directory inode open for identity checks and fsync. Path-based
    // operations are permitted only because the complete canonical ancestry is non-replaceable by
    // another uid; every operation also revalidates that this configured name still reaches it.
    directory_handle: File,
    _lock: File,
    operation_lock: tokio::sync::Mutex<()>,
}

impl fmt::Debug for DurableSubmissionStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableSubmissionStore")
            .field("directory", &self.directory)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub(crate) struct PendingSubmission {
    path: PathBuf,
    pub(crate) envelope: DurableSubmissionEnvelope,
}

impl DurableSubmissionStore {
    pub(crate) fn open(directory: PathBuf) -> anyhow::Result<Arc<Self>> {
        let (directory, directory_handle) = prepare_owner_only_directory(&directory)?;
        let lock_path = directory.join(".spool.lock");
        let lock = owner_only_open(&lock_path, false).with_context(|| {
            format!("failed to open prover submission spool lock {lock_path:?}")
        })?;
        try_lock_exclusive(&lock).with_context(|| {
            format!("prover submission spool {directory:?} is already owned by another process")
        })?;
        ensure_owner_only_file(&lock_path, &lock.metadata()?)?;
        lock.sync_all()
            .context("fsync prover submission spool lock")?;
        sync_directory_handle(&directory_handle, &directory)?;
        // SYSCOIN: A crash after file fsync but before/after no-replace publication leaves a valid
        // temporary record. Recover it while the process-wide spool lock is exclusively held.
        recover_temporary_records(&directory, &directory_handle)?;
        Ok(Arc::new(Self {
            directory,
            directory_handle,
            _lock: lock,
            operation_lock: tokio::sync::Mutex::new(()),
        }))
    }

    pub(crate) fn validate_configured_endpoints(
        &self,
        configured_endpoints: &HashSet<String>,
    ) -> anyhow::Result<()> {
        let pending_submissions = self.load_all_sync()?;
        // SYSCOIN: `persist()` permits exactly one global unresolved capability. More than one
        // final record can only mean manual/corrupt state; do not choose an automatic replay order.
        anyhow::ensure!(
            pending_submissions.len() <= 1,
            "durable submission spool contains multiple unresolved envelopes"
        );
        for pending in pending_submissions {
            anyhow::ensure!(
                configured_endpoints.contains(pending.envelope.endpoint()),
                "durable submission for endpoint {} has no exact configured endpoint identity",
                pending.envelope.endpoint()
            );
        }
        Ok(())
    }

    pub(crate) async fn persist(
        &self,
        envelope: DurableSubmissionEnvelope,
    ) -> anyhow::Result<PendingSubmission> {
        envelope.validate()?;
        let _guard = self.operation_lock.lock().await;
        // SYSCOIN: Exactly one unresolved envelope is allowed across every configured endpoint.
        // This makes a post-proof disk/config failure globally fail closed before any fresh pick.
        anyhow::ensure!(
            self.load_all_sync()?.is_empty(),
            "durable submission spool already has an unresolved envelope"
        );
        let bytes =
            serde_json::to_vec(&envelope).context("serialize durable submission envelope")?;
        anyhow::ensure!(
            bytes.len() as u64 <= MAX_ENVELOPE_BYTES,
            "durable submission envelope exceeds {MAX_ENVELOPE_BYTES} bytes"
        );

        let file_id = unique_file_id();
        let temporary_path = self.directory.join(format!(".pending-{file_id}.tmp"));
        let final_path = self.directory.join(format!("pending-{file_id}.json"));
        let mut cleanup_is_safe = true;
        let mut temporary_identity = None;
        let result = (|| -> anyhow::Result<()> {
            let mut file = owner_only_open(&temporary_path, true).with_context(|| {
                format!("create durable submission temporary file {temporary_path:?}")
            })?;
            temporary_identity = Some(file.metadata()?);
            file.write_all(&bytes)
                .context("write durable submission envelope")?;
            // SYSCOIN: Once complete proof/token bytes exist, even an fsync error is ambiguous.
            // Retain this exact inode and block fresh work rather than deleting the only copy.
            cleanup_is_safe = false;
            file.sync_all()
                .context("fsync durable submission envelope")?;
            ensure_stable_directory_identity(&self.directory, &self.directory_handle)?;
            // SYSCOIN: First make the temporary name crash-durable. It is now the recovery anchor
            // for every subsequent publication error.
            sync_directory_handle(&self.directory_handle, &self.directory)?;
            // A hard link is an atomic no-replace publication on the same filesystem.
            fs::hard_link(&temporary_path, &final_path)
                .context("publish durable submission envelope without overwrite")?;
            ensure_same_file(&temporary_path, &final_path, 2)?;
            // SYSCOIN: Persist the final name while the temporary recovery anchor still exists.
            sync_directory_handle(&self.directory_handle, &self.directory)?;
            fs::remove_file(&temporary_path)
                .context("remove published durable submission temporary name")?;
            ensure_file_link_count(&final_path, 1)?;
            // SYSCOIN: Only this final fsync makes the one-name state durable.
            sync_directory_handle(&self.directory_handle, &self.directory)?;
            ensure_stable_directory_identity(&self.directory, &self.directory_handle)?;
            Ok(())
        })();
        if result.is_err() && cleanup_is_safe {
            // SYSCOIN: Make failed temporary creation cleanup durable too; otherwise a partial
            // record could be resurrected after power loss. Never unlink a replaced pathname.
            if temporary_identity.as_ref().is_some_and(|identity| {
                remove_file_if_same_inode(&temporary_path, identity).unwrap_or(false)
            }) {
                let _ = sync_directory_handle(&self.directory_handle, &self.directory);
            }
        }
        result?;
        Ok(PendingSubmission {
            path: final_path,
            envelope,
        })
    }

    pub(crate) async fn load_for_endpoint(
        &self,
        endpoint: &str,
    ) -> anyhow::Result<Vec<PendingSubmission>> {
        let _guard = self.operation_lock.lock().await;
        Ok(self
            .load_all_sync()?
            .into_iter()
            .filter(|pending| pending.envelope.endpoint() == endpoint)
            .collect())
    }

    pub(crate) async fn retire(&self, pending: &PendingSubmission) -> anyhow::Result<()> {
        let _guard = self.operation_lock.lock().await;
        ensure_stable_directory_identity(&self.directory, &self.directory_handle)?;
        fs::remove_file(&pending.path)
            .with_context(|| format!("retire durable submission envelope {:?}", pending.path))?;
        sync_directory_handle(&self.directory_handle, &self.directory)?;
        ensure_stable_directory_identity(&self.directory, &self.directory_handle)
    }

    pub(crate) async fn ensure_empty(&self) -> anyhow::Result<()> {
        let _guard = self.operation_lock.lock().await;
        anyhow::ensure!(
            self.load_all_sync()?.is_empty(),
            "durable submission spool has an unresolved envelope for another endpoint"
        );
        Ok(())
    }

    fn load_all_sync(&self) -> anyhow::Result<Vec<PendingSubmission>> {
        let inventory = inspect_spool_inventory(&self.directory, &self.directory_handle)?;
        // SYSCOIN: Temporary records are reconciled only while opening the exclusively locked
        // store. A new runtime temporary means an interrupted/corrupt write and blocks fresh work.
        anyhow::ensure!(
            inventory.temporary_paths.is_empty(),
            "durable submission spool contains an unrecovered temporary envelope"
        );
        let pending_paths = inventory.pending_paths;
        // SYSCOIN: Reject multiplicity before reading any proof-sized records, avoiding an
        // attacker/corruption-controlled aggregate allocation during startup validation.
        anyhow::ensure!(
            pending_paths.len() <= 1,
            "durable submission spool contains multiple unresolved envelopes"
        );
        pending_paths
            .into_iter()
            .map(|path| {
                ensure_file_link_count(&path, 1)?;
                load_pending_file(path)
            })
            .collect()
    }
}

struct SpoolInventory {
    pending_paths: Vec<PathBuf>,
    temporary_paths: Vec<PathBuf>,
}

// SYSCOIN: This directory is dedicated to bearer capabilities. Reject every non-UTF8 or unknown
// entry rather than silently orphaning a proof and later acquiring fresh work behind it. The only
// legal names are the exact process lock and versioned temporary/final envelope forms.
fn inspect_spool_inventory(
    directory: &Path,
    directory_handle: &File,
) -> anyhow::Result<SpoolInventory> {
    ensure_stable_directory_identity(directory, directory_handle)?;
    let mut paths = fs::read_dir(directory)
        .with_context(|| format!("read durable submission spool {directory:?}"))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();

    let mut lock_seen = false;
    let mut pending_paths = Vec::new();
    let mut temporary_paths = Vec::new();
    for path in paths {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .with_context(|| format!("non-UTF8 entry in dedicated submission spool: {path:?}"))?;
        if name == ".spool.lock" {
            anyhow::ensure!(!lock_seen, "duplicate durable submission spool lock entry");
            lock_seen = true;
            let metadata = fs::symlink_metadata(&path)?;
            ensure_owner_only_file(&path, &metadata)?;
            ensure_file_link_count(&path, 1)?;
            continue;
        }
        if let Some(file_id) = name
            .strip_prefix(".pending-")
            .and_then(|name| name.strip_suffix(".tmp"))
        {
            anyhow::ensure!(
                !file_id.is_empty(),
                "empty durable submission file identifier"
            );
            temporary_paths.push(path);
            continue;
        }
        if let Some(file_id) = name
            .strip_prefix("pending-")
            .and_then(|name| name.strip_suffix(".json"))
        {
            anyhow::ensure!(
                !file_id.is_empty(),
                "empty durable submission file identifier"
            );
            pending_paths.push(path);
            continue;
        }
        anyhow::bail!("unknown entry in dedicated submission spool: {path:?}");
    }
    anyhow::ensure!(lock_seen, "durable submission spool lock entry is missing");
    ensure_stable_directory_identity(directory, directory_handle)?;
    Ok(SpoolInventory {
        pending_paths,
        temporary_paths,
    })
}

// SYSCOIN: Reconcile every fsynced `.pending-*.tmp` under the exclusive spool lock. Equivalent
// published records are idempotent; malformed or conflicting records stop startup for inspection.
fn recover_temporary_records(directory: &Path, directory_handle: &File) -> anyhow::Result<()> {
    let inventory = inspect_spool_inventory(directory, directory_handle)?;
    let mut record_ids = HashSet::new();
    for path in inventory
        .temporary_paths
        .iter()
        .chain(&inventory.pending_paths)
    {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("validated spool filename became non-UTF8")?;
        let file_id = name
            .strip_prefix(".pending-")
            .and_then(|name| name.strip_suffix(".tmp"))
            .or_else(|| {
                name.strip_prefix("pending-")
                    .and_then(|name| name.strip_suffix(".json"))
            })
            .context("validated spool filename has an invalid form")?;
        record_ids.insert(file_id.to_owned());
    }
    // SYSCOIN: One crash window may leave two names for the same inode/record ID. Distinct IDs
    // violate the global single-envelope invariant, so reject before publishing or deleting any.
    anyhow::ensure!(
        record_ids.len() <= 1,
        "durable submission spool contains multiple unresolved record identifiers"
    );
    for temporary_path in inventory.temporary_paths {
        let name = temporary_path
            .file_name()
            .and_then(|name| name.to_str())
            .context("non-UTF8 durable submission temporary filename")?;
        let file_id = name
            .strip_prefix(".pending-")
            .and_then(|name| name.strip_suffix(".tmp"))
            .context("invalid durable submission temporary filename")?;
        anyhow::ensure!(
            !file_id.is_empty(),
            "empty durable submission file identifier"
        );
        let temporary = load_pending_file(temporary_path.clone())?;
        let final_path = directory.join(format!("pending-{file_id}.json"));
        if final_path.exists() {
            let published = load_pending_file(final_path.clone())?;
            anyhow::ensure!(
                published.envelope == temporary.envelope,
                "conflicting durable submission temporary and published records for {file_id}"
            );
            // SYSCOIN: The writer can create two names only by hard-linking one inode. Separate
            // equal files are manual/corrupt state and must never authorize automatic deletion.
            ensure_same_file(&temporary_path, &final_path, 2)?;
        } else {
            fs::hard_link(&temporary_path, &final_path).with_context(|| {
                format!("recover durable submission temporary record {temporary_path:?}")
            })?;
            ensure_same_file(&temporary_path, &final_path, 2)?;
        }
        // SYSCOIN: Whether the final name was found or recreated, anchor it while the temporary
        // name still survives. Removing first can lose both names under crash/writeback ordering.
        sync_directory_handle(directory_handle, directory)?;
        fs::remove_file(&temporary_path).with_context(|| {
            format!("remove recovered durable submission temporary record {temporary_path:?}")
        })?;
        ensure_file_link_count(&final_path, 1)?;
        sync_directory_handle(directory_handle, directory)?;
    }
    ensure_stable_directory_identity(directory, directory_handle)?;
    Ok(())
}

fn load_pending_file(path: PathBuf) -> anyhow::Result<PendingSubmission> {
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("inspect durable submission envelope {path:?}"))?;
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "submission envelope is not a file: {path:?}"
    );
    anyhow::ensure!(
        metadata.len() <= MAX_ENVELOPE_BYTES,
        "submission envelope is oversized: {path:?}"
    );
    ensure_owner_only_file(&path, &metadata)?;
    // SYSCOIN: Refuse symlink traversal and close the metadata/open replacement window before
    // reading a bearer capability from the private spool.
    let file = owner_only_read(&path)
        .with_context(|| format!("open durable submission envelope {path:?}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let opened = file.metadata()?;
        anyhow::ensure!(
            opened.dev() == metadata.dev() && opened.ino() == metadata.ino(),
            "submission envelope changed while opening: {path:?}"
        );
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_ENVELOPE_BYTES + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_ENVELOPE_BYTES,
        "submission envelope grew while reading: {path:?}"
    );
    let envelope: DurableSubmissionEnvelope = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse durable submission envelope {path:?}"))?;
    envelope
        .validate()
        .with_context(|| format!("validate durable submission envelope {path:?}"))?;
    Ok(PendingSubmission { path, envelope })
}

fn unique_file_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let counter = NEXT_FILE_ID.fetch_add(1, Ordering::Relaxed);
    format!("{}-{nanos}-{counter}", std::process::id())
}

#[cfg(unix)]
fn prepare_owner_only_directory(path: &Path) -> anyhow::Result<(PathBuf, File)> {
    use std::os::unix::fs::{
        DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
    };

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    ensure_stable_symlink_aliases(&absolute)?;
    // SYSCOIN: Record the nearest pre-existing ancestor so every newly created directory entry can
    // be fsynced before a proof/token is written below it.
    let existing_ancestor = absolute
        .ancestors()
        .find(|ancestor| fs::symlink_metadata(ancestor).is_ok())
        .context("submission spool has no existing ancestor")?;
    let existing_ancestor = fs::canonicalize(existing_ancestor)?;

    match fs::symlink_metadata(&absolute) {
        Ok(metadata) => anyhow::ensure!(
            metadata.file_type().is_dir(),
            "submission spool is not a directory: {absolute:?}"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700).create(&absolute)?;
        }
        Err(error) => return Err(error.into()),
    }

    let canonical = fs::canonicalize(&absolute)?;
    ensure_stable_symlink_aliases(&absolute)?;
    ensure_stable_directory_ancestry(&canonical)?;
    let before = fs::symlink_metadata(&canonical)?;
    anyhow::ensure!(
        before.file_type().is_dir() && before.uid() == unsafe { libc::geteuid() },
        "submission spool must be a current-user-owned directory: {canonical:?}"
    );

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let directory = options.open(&canonical)?;
    let opened = directory.metadata()?;
    anyhow::ensure!(
        opened.is_dir()
            && opened.dev() == before.dev()
            && opened.ino() == before.ino()
            && opened.uid() == unsafe { libc::geteuid() },
        "submission spool changed while validating ownership: {canonical:?}"
    );
    // SYSCOIN: Ownership is authorization to tighten only this dedicated capability namespace.
    directory.set_permissions(fs::Permissions::from_mode(0o700))?;
    ensure_stable_directory_identity(&canonical, &directory)?;
    sync_created_directory_chain(&canonical, &existing_ancestor)?;
    Ok((canonical, directory))
}

#[cfg(not(unix))]
fn prepare_owner_only_directory(_path: &Path) -> anyhow::Result<(PathBuf, File)> {
    anyhow::bail!("durable prover submission spools require Unix filesystem semantics")
}

/// SYSCOIN: A pathname remains restart-stable only if no other uid can rename any component.
/// A root/current-user-owned sticky directory (for example `/tmp`) may contain a current-user-owned
/// child; every other group/world-writable ancestor is rejected.
#[cfg(unix)]
fn ensure_stable_directory_ancestry(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let effective_uid = unsafe { libc::geteuid() };
    for child in path
        .ancestors()
        .take_while(|ancestor| ancestor.parent().is_some())
    {
        let parent = child.parent().expect("non-root ancestor has a parent");
        let parent_metadata = fs::symlink_metadata(parent)?;
        let child_metadata = fs::symlink_metadata(child)?;
        anyhow::ensure!(
            parent_metadata.file_type().is_dir() && child_metadata.file_type().is_dir(),
            "submission spool ancestry contains a non-directory component: {child:?}"
        );
        // SYSCOIN: Mode bits are mutable by the owner. Trust only root or this process' uid for
        // every ancestor, otherwise another uid could chmod and replace a checked component after
        // startup while path-based publication still holds the old directory descriptor.
        anyhow::ensure!(
            parent_metadata.uid() == 0 || parent_metadata.uid() == effective_uid,
            "submission spool has an ancestor owned by an untrusted uid: {parent:?}"
        );
        let parent_mode = parent_metadata.permissions().mode();
        if parent_mode & 0o022 != 0 {
            anyhow::ensure!(
                parent_mode & 0o1000 != 0
                    && (parent_metadata.uid() == 0 || parent_metadata.uid() == effective_uid)
                    && child_metadata.uid() == effective_uid,
                "submission spool has a group/world-writable replaceable ancestor: {parent:?}"
            );
        }
    }
    Ok(())
}

/// SYSCOIN: Canonical descriptor/path checks do not by themselves protect a configured alias on
/// the next restart. Every symlink component must live in a parent where another uid cannot replace
/// that link. Canonical target ancestry is validated separately above.
#[cfg(unix)]
fn ensure_stable_symlink_aliases(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let effective_uid = unsafe { libc::geteuid() };
    for component in path
        .ancestors()
        .filter(|component| component.parent().is_some())
    {
        let metadata = match fs::symlink_metadata(component) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if !metadata.file_type().is_symlink() {
            continue;
        }
        let parent = fs::canonicalize(component.parent().expect("non-root path has a parent"))?;
        let parent_metadata = fs::symlink_metadata(&parent)?;
        let parent_mode = parent_metadata.permissions().mode();
        anyhow::ensure!(
            (parent_metadata.uid() == 0 || parent_metadata.uid() == effective_uid)
                && (parent_mode & 0o022 == 0
                    || (parent_mode & 0o1000 != 0
                        && (parent_metadata.uid() == 0 || parent_metadata.uid() == effective_uid)
                        && metadata.uid() == effective_uid)),
            "submission spool uses a replaceable symlink alias: {component:?}"
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_stable_symlink_aliases(_path: &Path) -> anyhow::Result<()> {
    anyhow::bail!("stable prover spool aliases require Unix filesystem semantics")
}

#[cfg(not(unix))]
fn ensure_stable_directory_ancestry(_path: &Path) -> anyhow::Result<()> {
    anyhow::bail!("stable prover spool ancestry requires Unix filesystem semantics")
}

#[cfg(unix)]
fn ensure_stable_directory_identity(path: &Path, directory: &File) -> anyhow::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let named = fs::symlink_metadata(path)?;
    let opened = directory.metadata()?;
    anyhow::ensure!(
        named.file_type().is_dir()
            && named.dev() == opened.dev()
            && named.ino() == opened.ino()
            && opened.uid() == unsafe { libc::geteuid() }
            && opened.permissions().mode() & 0o077 == 0,
        "submission spool path changed or lost owner-only identity: {path:?}"
    );
    Ok(())
}

#[cfg(not(unix))]
fn ensure_stable_directory_identity(_path: &Path, _directory: &File) -> anyhow::Result<()> {
    anyhow::bail!("stable prover spool identity requires Unix filesystem semantics")
}

// SYSCOIN: Persist the dedicated directory and every newly created parent link before storing
// bearer authority. Syncing a pre-existing leaf and its parent is harmless and closes a prior
// unclean-creation window as well.
fn sync_created_directory_chain(path: &Path, existing_ancestor: &Path) -> anyhow::Result<()> {
    let mut current = path;
    loop {
        File::open(current)?.sync_all()?;
        if let Some(parent) = current.parent() {
            File::open(parent)?.sync_all()?;
        }
        if current == existing_ancestor {
            return Ok(());
        }
        current = current.parent().with_context(|| {
            format!("pre-existing directory {existing_ancestor:?} is not an ancestor of {path:?}")
        })?;
    }
}

fn owner_only_open(path: &Path, create_new: bool) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn owner_only_read(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn ensure_owner_only_file(path: &Path, metadata: &fs::Metadata) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        anyhow::ensure!(
            metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.permissions().mode() & 0o077 == 0
                && (1..=2).contains(&metadata.nlink()),
            "durable submission file is not regular, current-user-owned, owner-only, and singly or recovery-linked: {path:?}"
        );
    }
    Ok(())
}

fn sync_directory_handle(directory: &File, display_path: &Path) -> anyhow::Result<()> {
    directory
        .sync_all()
        .with_context(|| format!("fsync durable submission spool {display_path:?}"))
}

#[cfg(unix)]
fn ensure_file_link_count(path: &Path, expected_links: u64) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = fs::symlink_metadata(path)?;
    ensure_owner_only_file(path, &metadata)?;
    anyhow::ensure!(
        metadata.nlink() == expected_links,
        "durable submission file has {} links, expected {expected_links}: {path:?}",
        metadata.nlink()
    );
    Ok(())
}

#[cfg(not(unix))]
fn ensure_file_link_count(_path: &Path, _expected_links: u64) -> anyhow::Result<()> {
    anyhow::bail!("durable submission link checks require Unix filesystem semantics")
}

#[cfg(unix)]
fn ensure_same_file(first: &Path, second: &Path, expected_links: u64) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let first_metadata = fs::symlink_metadata(first)?;
    let second_metadata = fs::symlink_metadata(second)?;
    ensure_owner_only_file(first, &first_metadata)?;
    ensure_owner_only_file(second, &second_metadata)?;
    anyhow::ensure!(
        first_metadata.dev() == second_metadata.dev()
            && first_metadata.ino() == second_metadata.ino()
            && first_metadata.nlink() == expected_links
            && second_metadata.nlink() == expected_links,
        "durable submission publication names do not identify one {expected_links}-link inode"
    );
    Ok(())
}

#[cfg(not(unix))]
fn ensure_same_file(_first: &Path, _second: &Path, _expected_links: u64) -> anyhow::Result<()> {
    anyhow::bail!("durable submission identity checks require Unix filesystem semantics")
}

#[cfg(unix)]
fn remove_file_if_same_inode(path: &Path, expected: &fs::Metadata) -> anyhow::Result<bool> {
    use std::os::unix::fs::MetadataExt as _;

    let current = match fs::symlink_metadata(path) {
        Ok(current) => current,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    ensure_owner_only_file(path, &current)?;
    if current.dev() != expected.dev() || current.ino() != expected.ino() {
        return Ok(false);
    }
    fs::remove_file(path)?;
    Ok(true)
}

#[cfg(not(unix))]
fn remove_file_if_same_inode(_path: &Path, _expected: &fs::Metadata) -> anyhow::Result<bool> {
    anyhow::bail!("durable submission identity checks require Unix filesystem semantics")
}

#[cfg(unix)]
fn try_lock_exclusive(file: &File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;
    // SYSCOIN: flock ownership follows the open file description and is released by close/crash.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn try_lock_exclusive(_file: &File) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "durable prover submission spools require Unix advisory locks",
    ))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        fs,
        path::{Path, PathBuf},
        sync::Arc,
    };

    use super::{DurableSubmissionEnvelope, DurableSubmissionStore};
    use crate::ProverLeaseToken;

    fn b256(byte: u8) -> String {
        format!("0x{}", format!("{byte:02x}").repeat(32))
    }

    fn lease(byte: u8) -> ProverLeaseToken {
        ProverLeaseToken::from(b256(byte))
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "zksync-prover-submission-test-{}",
                super::unique_file_id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn durable_envelope_round_trip_is_owner_only_and_redacted() {
        let temporary = TestDirectory::new();
        let directory = temporary.path().join("spool");
        let store = DurableSubmissionStore::open(directory.clone()).unwrap();
        let vk_hash = b256(0x11);
        let lease_token = b256(0x22);
        let pending = store
            .persist(DurableSubmissionEnvelope::fri(
                "https://sequencer.example/".to_owned(),
                7,
                vk_hash,
                "proof-secret".to_owned(),
                ProverLeaseToken::from(lease_token.clone()),
            ))
            .await
            .unwrap();
        let debug = format!("{:?}", pending.envelope);
        assert!(!debug.contains("proof-secret"));
        assert!(!debug.contains(&lease_token));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&pending.path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        drop(pending);
        let loaded = store
            .load_for_endpoint("https://sequencer.example/")
            .await
            .unwrap();
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn spool_rejects_second_live_owner() {
        let temporary = TestDirectory::new();
        let directory = temporary.path().join("spool");
        let first = DurableSubmissionStore::open(directory.clone()).unwrap();
        let error = DurableSubmissionStore::open(directory).unwrap_err();
        assert!(error.to_string().contains("already owned"));
        drop(first);
    }

    // SYSCOIN: The spool is a dedicated capability namespace. Unknown and non-UTF8 names must
    // block startup instead of being ignored and allowing a fresh lease behind an orphaned proof.
    #[cfg(unix)]
    #[test]
    fn startup_inventory_rejects_unknown_and_non_utf8_entries() {
        let temporary = TestDirectory::new();
        let unknown_directory = temporary.path().join("unknown-spool");
        fs::create_dir(&unknown_directory).unwrap();
        fs::write(unknown_directory.join("operator-note"), b"unexpected").unwrap();
        let error = DurableSubmissionStore::open(unknown_directory).unwrap_err();
        assert!(error.to_string().contains("unknown entry"));

        // SYSCOIN: APFS rejects arbitrary non-UTF8 names in this sandbox; Linux CI exercises the
        // raw-byte filename branch that production Linux filesystems permit.
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::ffi::OsStringExt as _;

            let non_utf8_directory = temporary.path().join("non-utf8-spool");
            fs::create_dir(&non_utf8_directory).unwrap();
            let non_utf8 = std::ffi::OsString::from_vec(vec![b'p', b'e', b'n', b'd', 0xff]);
            fs::write(non_utf8_directory.join(non_utf8), b"unexpected").unwrap();
            let error = DurableSubmissionStore::open(non_utf8_directory).unwrap_err();
            assert!(format!("{error:#}").contains("non-UTF8 entry"));
        }
    }

    // SYSCOIN: Runtime inventory is held to the same closed namespace, and a temporary envelope
    // that appears after startup is never silently skipped or recovered behind active work.
    #[cfg(unix)]
    #[tokio::test]
    async fn runtime_inventory_rejects_unknown_non_utf8_and_temporary_entries() {
        let temporary = TestDirectory::new();
        let directory = temporary.path().join("runtime-spool");
        let store = DurableSubmissionStore::open(directory.clone()).unwrap();

        let unknown = directory.join("operator-note");
        fs::write(&unknown, b"unexpected").unwrap();
        assert!(store
            .ensure_empty()
            .await
            .unwrap_err()
            .to_string()
            .contains("unknown entry"));
        fs::remove_file(unknown).unwrap();

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::ffi::OsStringExt as _;

            let non_utf8 = directory.join(std::ffi::OsString::from_vec(vec![b'x', 0xff]));
            fs::write(&non_utf8, b"unexpected").unwrap();
            assert!(format!("{:#}", store.ensure_empty().await.unwrap_err()).contains("non-UTF8"));
            fs::remove_file(non_utf8).unwrap();
        }

        let runtime_temporary = directory.join(".pending-runtime.tmp");
        fs::write(&runtime_temporary, b"incomplete").unwrap();
        assert!(store
            .ensure_empty()
            .await
            .unwrap_err()
            .to_string()
            .contains("unrecovered temporary"));
    }

    // SYSCOIN: Directory ownership is checked through a no-follow descriptor before chmod. A
    // symlink target is rejected without mutation, while a current-user directory is tightened.
    #[cfg(unix)]
    #[test]
    fn spool_directory_is_tightened_only_after_safe_identity_validation() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let temporary = TestDirectory::new();
        let target = temporary.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        let link = temporary.path().join("linked-spool");
        symlink(&target, &link).unwrap();
        assert!(DurableSubmissionStore::open(link).is_err());
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o755
        );

        let owned = temporary.path().join("owned-spool");
        fs::create_dir(&owned).unwrap();
        fs::set_permissions(&owned, fs::Permissions::from_mode(0o777)).unwrap();
        let store = DurableSubmissionStore::open(owned.clone()).unwrap();
        assert_eq!(
            fs::metadata(&owned).unwrap().permissions().mode() & 0o777,
            0o700
        );
        drop(store);
    }

    #[tokio::test]
    async fn malformed_truncated_and_unknown_endpoint_records_fail_closed() {
        let temporary = TestDirectory::new();
        let directory = temporary.path().join("spool");
        let store = DurableSubmissionStore::open(directory.clone()).unwrap();
        let malformed = directory.join("pending-bad.json");
        fs::write(&malformed, b"{\"version\":1").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&malformed, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(store
            .load_for_endpoint("https://sequencer.example/")
            .await
            .is_err());
        fs::remove_file(malformed).unwrap();

        store
            .persist(DurableSubmissionEnvelope::fri(
                "https://other.example/".to_owned(),
                1,
                b256(0x11),
                "proof".to_owned(),
                lease(0x22),
            ))
            .await
            .unwrap();
        let configured = HashSet::from(["https://sequencer.example/".to_owned()]);
        assert!(store.validate_configured_endpoints(&configured).is_err());
    }

    #[tokio::test]
    async fn unknown_envelope_version_fails_closed() {
        let temporary = TestDirectory::new();
        let directory = temporary.path().join("spool");
        let store = DurableSubmissionStore::open(directory.clone()).unwrap();
        let path = directory.join("pending-future.json");
        fs::write(
            &path,
            format!(
                r#"{{"version":99,"endpoint":"https://sequencer.example/","stage":"fri","batch_number":1,"vk_hash":"{}","proof":"proof","lease_token":"{}"}}"#,
                b256(0x11),
                b256(0x22)
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let error = store
            .load_for_endpoint("https://sequencer.example/")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("validate durable submission"));
    }

    // SYSCOIN: A recovered or manual envelope must satisfy the same V32 scalar and aggregate
    // shape contract as a freshly decoded sequencer job before any network byte can leave.
    #[test]
    fn invalid_envelope_scalars_and_ranges_fail_closed() {
        let oversized_fri = DurableSubmissionEnvelope::fri(
            "https://sequencer.example/".to_owned(),
            u64::from(u32::MAX) + 1,
            b256(0x11),
            "proof".to_owned(),
            lease(0x22),
        );
        assert!(oversized_fri
            .validate()
            .unwrap_err()
            .to_string()
            .contains("fit u32"));

        let malformed_authority = DurableSubmissionEnvelope::fri(
            "https://sequencer.example/".to_owned(),
            1,
            b256(0x11),
            "proof".to_owned(),
            ProverLeaseToken::from("not-a-token".to_owned()),
        );
        assert!(malformed_authority
            .validate()
            .unwrap_err()
            .to_string()
            .contains("lease token"));

        let malformed_vk = DurableSubmissionEnvelope::fri(
            "https://sequencer.example/".to_owned(),
            1,
            "not-a-vk".to_owned(),
            "proof".to_owned(),
            lease(0x22),
        );
        assert!(malformed_vk
            .validate()
            .unwrap_err()
            .to_string()
            .contains("verification-key hash"));

        for (from, to) in [(7, 7), (7, 107), (8, 7)] {
            let malformed_range = DurableSubmissionEnvelope::snark(
                "https://sequencer.example/".to_owned(),
                from,
                to,
                b256(0x11),
                "proof".to_owned(),
                lease(0x22),
            );
            assert!(
                malformed_range.validate().is_err(),
                "accepted {from}..={to}"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn group_readable_envelope_is_rejected() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = TestDirectory::new();
        let directory = temporary.path().join("spool");
        let store = DurableSubmissionStore::open(directory.clone()).unwrap();
        let path = directory.join("pending-insecure.json");
        fs::write(
            &path,
            format!(
                r#"{{"version":1,"endpoint":"https://sequencer.example/","stage":"fri","batch_number":1,"vk_hash":"{}","proof":"proof","lease_token":"{}"}}"#,
                b256(0x11),
                b256(0x22)
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let error = store
            .load_for_endpoint("https://sequencer.example/")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("current-user-owned"));
    }

    #[test]
    fn store_is_shared_inside_one_process() {
        let temporary = TestDirectory::new();
        let directory = temporary.path().join("spool");
        let store = DurableSubmissionStore::open(directory).unwrap();
        let clone = Arc::clone(&store);
        assert!(Arc::ptr_eq(&store, &clone));
    }

    // SYSCOIN: Recover the exact crash window between temporary-file fsync and publication.
    #[tokio::test]
    async fn valid_fsynced_temporary_record_is_published_on_open() {
        let temporary = TestDirectory::new();
        let directory = temporary.path().join("spool");
        fs::create_dir(&directory).unwrap();
        let envelope = DurableSubmissionEnvelope::fri(
            "https://sequencer.example/".to_owned(),
            7,
            b256(0x11),
            "proof".to_owned(),
            lease(0x22),
        );
        let path = directory.join(".pending-crash.tmp");
        fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let store = DurableSubmissionStore::open(directory.clone()).unwrap();
        assert!(!path.exists());
        assert!(directory.join("pending-crash.json").is_file());
        assert_eq!(
            store
                .load_for_endpoint("https://sequencer.example/")
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn malformed_temporary_record_fails_closed_on_open() {
        let temporary = TestDirectory::new();
        let directory = temporary.path().join("spool");
        fs::create_dir(&directory).unwrap();
        let path = directory.join(".pending-malformed.tmp");
        fs::write(&path, b"{truncated").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let error = DurableSubmissionStore::open(directory).unwrap_err();
        assert!(format!("{error:#}").contains("parse durable submission envelope"));
    }

    #[test]
    fn multiple_temporary_record_ids_fail_before_publication() {
        let temporary = TestDirectory::new();
        let directory = temporary.path().join("spool");
        fs::create_dir(&directory).unwrap();
        let envelope = DurableSubmissionEnvelope::fri(
            "https://sequencer.example/".to_owned(),
            7,
            b256(0x11),
            "proof".to_owned(),
            lease(0x22),
        );
        let serialized = serde_json::to_vec(&envelope).unwrap();
        for id in ["first", "second"] {
            let path = directory.join(format!(".pending-{id}.tmp"));
            fs::write(&path, &serialized).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }

        let error = DurableSubmissionStore::open(directory.clone()).unwrap_err();
        assert!(format!("{error:#}").contains("multiple unresolved record identifiers"));
        assert!(!directory.join("pending-first.json").exists());
        assert!(!directory.join("pending-second.json").exists());
    }

    // SYSCOIN: Only the writer's two hard links authorize recovery cleanup. Equal JSON copied into
    // separate inodes is ambiguous/manual state and must remain untouched for operator inspection.
    #[cfg(unix)]
    #[test]
    fn equal_temporary_and_final_records_on_distinct_inodes_fail_without_mutation() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let temporary = TestDirectory::new();
        let directory = temporary.path().join("spool");
        fs::create_dir(&directory).unwrap();
        let envelope = DurableSubmissionEnvelope::fri(
            "https://sequencer.example/".to_owned(),
            7,
            b256(0x11),
            "proof".to_owned(),
            lease(0x22),
        );
        let serialized = serde_json::to_vec(&envelope).unwrap();
        let temporary_path = directory.join(".pending-crash.tmp");
        let final_path = directory.join("pending-crash.json");
        fs::write(&temporary_path, &serialized).unwrap();
        fs::write(&final_path, &serialized).unwrap();
        fs::set_permissions(&temporary_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&final_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_ne!(
            fs::metadata(&temporary_path).unwrap().ino(),
            fs::metadata(&final_path).unwrap().ino()
        );

        let error = DurableSubmissionStore::open(directory).unwrap_err();
        assert!(format!("{error:#}").contains("do not identify one 2-link inode"));
        assert_eq!(fs::read(&temporary_path).unwrap(), serialized);
        assert_eq!(fs::read(&final_path).unwrap(), serialized);
    }

    #[tokio::test]
    async fn spool_allows_only_one_unresolved_envelope_globally() {
        let temporary = TestDirectory::new();
        let store = DurableSubmissionStore::open(temporary.path().join("spool")).unwrap();
        store
            .persist(DurableSubmissionEnvelope::fri(
                "https://a.example/".to_owned(),
                1,
                b256(0x11),
                "proof-a".to_owned(),
                lease(0xaa),
            ))
            .await
            .unwrap();
        let error = store
            .persist(DurableSubmissionEnvelope::fri(
                "https://b.example/".to_owned(),
                2,
                b256(0x11),
                "proof-b".to_owned(),
                lease(0xbb),
            ))
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("already has an unresolved envelope"));
    }

    #[tokio::test]
    async fn startup_rejects_multiple_final_envelopes_instead_of_ordering_them() {
        let temporary = TestDirectory::new();
        let directory = temporary.path().join("spool");
        let store = DurableSubmissionStore::open(directory.clone()).unwrap();
        let pending = store
            .persist(DurableSubmissionEnvelope::fri(
                "https://sequencer.example/".to_owned(),
                1,
                b256(0x11),
                "proof".to_owned(),
                lease(0x22),
            ))
            .await
            .unwrap();
        fs::copy(&pending.path, directory.join("pending-duplicate.json")).unwrap();

        let configured = HashSet::from(["https://sequencer.example/".to_owned()]);
        let error = store
            .validate_configured_endpoints(&configured)
            .unwrap_err();
        assert!(error.to_string().contains("multiple unresolved envelopes"));
    }

    #[tokio::test]
    async fn exact_wire_body_limit_is_enforced_before_publication() {
        let temporary = TestDirectory::new();
        let directory = temporary.path().join("spool");
        let store = DurableSubmissionStore::open(directory.clone()).unwrap();
        let error = store
            .persist(DurableSubmissionEnvelope::fri(
                "https://sequencer.example/".to_owned(),
                1,
                b256(0x11),
                "x".repeat(crate::MAX_PROOF_SUBMISSION_BODY_BYTES),
                lease(0x22),
            ))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("server maximum"));
        assert_eq!(
            fs::read_dir(directory)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("pending-"))
                .count(),
            0
        );
    }
}
