//! SYSCOIN: Crash-durable ownership of one exact proof/capability submission.

use std::{
    collections::HashSet,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Arc,
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
const LOCK_FILE_NAME: &str = ".spool.lock";
const TEMPORARY_FILE_NAME: &str = "pending.tmp";
const PENDING_FILE_NAME: &str = "pending.json";

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
#[serde(tag = "stage", rename_all = "snake_case", deny_unknown_fields)]
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

/// SYSCOIN: One process owns a private, absolute spool for its lifetime. Other configured
/// endpoint clients share this object, so only one unresolved exact capability exists globally.
pub(crate) struct DurableSubmissionStore {
    directory: PathBuf,
    // SYSCOIN: Keep the validated directory inode open for identity checks and fsync. Path-based
    // operations are permitted only because canonical ancestry is non-replaceable by another uid;
    // every operation also revalidates that the configured name still reaches this inode.
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
        let lock_path = directory.join(LOCK_FILE_NAME);
        let lock = owner_only_open(&lock_path, false)
            .with_context(|| format!("open prover submission spool lock {lock_path:?}"))?;
        ensure_open_file_identity(&lock_path, &lock, None)?;
        try_lock_exclusive(&lock).with_context(|| {
            format!("prover submission spool {directory:?} is already owned by another process")
        })?;
        lock.sync_all()
            .context("fsync prover submission spool lock")?;
        sync_directory(&directory_handle, &directory)?;

        // SYSCOIN: Resolve the sole normal crash window while the lifetime lock is held. A valid,
        // file-fsynced temporary record is atomically promoted; malformed or dual state is retained
        // and fails startup without permitting a fresh lease.
        recover_temporary_record(&directory, &directory_handle)?;

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
        if let Some(pending) = self.load_pending_sync()? {
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
        anyhow::ensure!(
            self.load_pending_sync()?.is_none(),
            "durable submission spool already has an unresolved envelope"
        );

        let bytes =
            serde_json::to_vec(&envelope).context("serialize durable submission envelope")?;
        anyhow::ensure!(
            bytes.len() as u64 <= MAX_ENVELOPE_BYTES,
            "durable submission envelope exceeds {MAX_ENVELOPE_BYTES} bytes"
        );

        let temporary_path = self.temporary_path();
        let pending_path = self.pending_path();
        // SYSCOIN: The globally locked fixed temporary name makes create-new sufficient to detect
        // any unresolved prior write without dynamic IDs, inode policing, or hard-link recovery.
        let mut file = owner_only_open(&temporary_path, true).with_context(|| {
            format!("create durable submission temporary file {temporary_path:?}")
        })?;
        ensure_open_file_identity(&temporary_path, &file, Some(MAX_ENVELOPE_BYTES))?;
        // Retain every created temporary file on error. Even a partial record must block fresh work
        // until restart recovery validates it or an operator retires the expired lease explicitly.
        file.write_all(&bytes)
            .context("write durable submission envelope")?;
        file.sync_all()
            .context("fsync durable submission envelope")?;
        ensure_stable_directory_identity(&self.directory, &self.directory_handle)?;
        // SYSCOIN: First persist the temporary recovery anchor, then atomically rename it, then
        // persist the final name. A crash can expose temp or final, never an accepted unfsynced body.
        sync_directory(&self.directory_handle, &self.directory)?;
        fs::rename(&temporary_path, &pending_path)
            .context("atomically publish durable submission envelope")?;
        sync_directory(&self.directory_handle, &self.directory)?;
        ensure_stable_directory_identity(&self.directory, &self.directory_handle)?;

        Ok(PendingSubmission {
            path: pending_path,
            envelope,
        })
    }

    pub(crate) async fn load_for_endpoint(
        &self,
        endpoint: &str,
    ) -> anyhow::Result<Vec<PendingSubmission>> {
        let _guard = self.operation_lock.lock().await;
        Ok(self
            .load_pending_sync()?
            .filter(|pending| pending.envelope.endpoint() == endpoint)
            .into_iter()
            .collect())
    }

    pub(crate) async fn retire(&self, pending: &PendingSubmission) -> anyhow::Result<()> {
        let _guard = self.operation_lock.lock().await;
        ensure_stable_directory_identity(&self.directory, &self.directory_handle)?;
        anyhow::ensure!(
            pending.path == self.pending_path(),
            "durable submission retirement did not target the canonical pending record"
        );
        // SYSCOIN: Retire only the exact envelope that received a definitive manager disposition.
        // Disk corruption or an internal stale handle remains fail-closed for operator inspection.
        let current = self
            .load_pending_sync()?
            .context("durable submission disappeared before definitive retirement")?;
        anyhow::ensure!(
            current.envelope == pending.envelope,
            "durable submission changed before definitive retirement"
        );
        fs::remove_file(&pending.path)
            .with_context(|| format!("retire durable submission envelope {:?}", pending.path))?;
        sync_directory(&self.directory_handle, &self.directory)?;
        ensure_stable_directory_identity(&self.directory, &self.directory_handle)
    }

    pub(crate) async fn ensure_empty(&self) -> anyhow::Result<()> {
        let _guard = self.operation_lock.lock().await;
        anyhow::ensure!(
            self.load_pending_sync()?.is_none(),
            "durable submission spool has an unresolved envelope for another endpoint"
        );
        Ok(())
    }

    fn load_pending_sync(&self) -> anyhow::Result<Option<PendingSubmission>> {
        let inventory = inspect_spool(&self.directory, &self.directory_handle)?;
        anyhow::ensure!(
            !inventory.temporary,
            "durable submission spool contains an unrecovered temporary envelope"
        );
        inventory
            .pending
            .then(|| load_pending_file(self.pending_path()))
            .transpose()
    }

    fn temporary_path(&self) -> PathBuf {
        self.directory.join(TEMPORARY_FILE_NAME)
    }

    fn pending_path(&self) -> PathBuf {
        self.directory.join(PENDING_FILE_NAME)
    }
}

#[derive(Debug, Default)]
struct SpoolInventory {
    temporary: bool,
    pending: bool,
}

// SYSCOIN: This is a dedicated capability directory. The lifetime lock and at most one fixed
// temporary/final record are its complete state machine; every other entry is ambiguous and blocks.
fn inspect_spool(directory: &Path, directory_handle: &File) -> anyhow::Result<SpoolInventory> {
    ensure_stable_directory_identity(directory, directory_handle)?;
    let mut inventory = SpoolInventory::default();
    let mut lock_seen = false;
    for entry in fs::read_dir(directory)
        .with_context(|| format!("read durable submission spool {directory:?}"))?
    {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("non-UTF8 entry in dedicated submission spool"))?;
        match name.as_str() {
            LOCK_FILE_NAME => {
                lock_seen = true;
                ensure_private_file(&entry.path(), &fs::symlink_metadata(entry.path())?, None)?;
            }
            TEMPORARY_FILE_NAME => {
                inventory.temporary = true;
                ensure_private_file(
                    &entry.path(),
                    &fs::symlink_metadata(entry.path())?,
                    Some(MAX_ENVELOPE_BYTES),
                )?;
            }
            PENDING_FILE_NAME => {
                inventory.pending = true;
                ensure_private_file(
                    &entry.path(),
                    &fs::symlink_metadata(entry.path())?,
                    Some(MAX_ENVELOPE_BYTES),
                )?;
            }
            _ => anyhow::bail!("unknown entry in dedicated submission spool: {name:?}"),
        }
    }
    anyhow::ensure!(lock_seen, "durable submission spool lock entry is missing");
    ensure_stable_directory_identity(directory, directory_handle)?;
    Ok(inventory)
}

fn recover_temporary_record(directory: &Path, directory_handle: &File) -> anyhow::Result<()> {
    let inventory = inspect_spool(directory, directory_handle)?;
    anyhow::ensure!(
        !(inventory.temporary && inventory.pending),
        "durable submission spool contains ambiguous temporary and pending envelopes"
    );
    if !inventory.temporary {
        if inventory.pending {
            load_pending_file(directory.join(PENDING_FILE_NAME))?;
        }
        return Ok(());
    }

    let temporary_path = directory.join(TEMPORARY_FILE_NAME);
    let pending_path = directory.join(PENDING_FILE_NAME);
    // SYSCOIN: A normal process kill may expose a complete page-cache-visible temporary record
    // before its data or name reached stable storage. Hold the exact validated inode, fsync its
    // body, parse that same inode, and anchor the temporary name before the atomic promotion.
    let mut temporary_file = owner_only_read_write(&temporary_path)
        .with_context(|| format!("open crash-retained temporary record {temporary_path:?}"))?;
    ensure_open_file_identity(&temporary_path, &temporary_file, Some(MAX_ENVELOPE_BYTES))?;
    temporary_file
        .sync_all()
        .context("fsync crash-retained durable submission temporary record")?;
    ensure_open_file_identity(&temporary_path, &temporary_file, Some(MAX_ENVELOPE_BYTES))?;
    read_pending_envelope(&temporary_path, &mut temporary_file)?;
    ensure_open_file_identity(&temporary_path, &temporary_file, Some(MAX_ENVELOPE_BYTES))?;
    sync_directory(directory_handle, directory)?;
    ensure_stable_directory_identity(directory, directory_handle)?;
    ensure_open_file_identity(&temporary_path, &temporary_file, Some(MAX_ENVELOPE_BYTES))?;
    fs::rename(&temporary_path, &pending_path)
        .context("promote crash-retained durable submission temporary record")?;
    ensure_open_file_identity(&pending_path, &temporary_file, Some(MAX_ENVELOPE_BYTES))?;
    sync_directory(directory_handle, directory)?;
    ensure_stable_directory_identity(directory, directory_handle)?;
    ensure_open_file_identity(&pending_path, &temporary_file, Some(MAX_ENVELOPE_BYTES))
}

fn load_pending_file(path: PathBuf) -> anyhow::Result<PendingSubmission> {
    let before = fs::symlink_metadata(&path)
        .with_context(|| format!("inspect durable submission envelope {path:?}"))?;
    ensure_private_file(&path, &before, Some(MAX_ENVELOPE_BYTES))?;
    let mut file = owner_only_read(&path)
        .with_context(|| format!("open durable submission envelope {path:?}"))?;
    ensure_open_file_identity(&path, &file, Some(MAX_ENVELOPE_BYTES))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let opened = file.metadata()?;
        anyhow::ensure!(
            before.dev() == opened.dev() && before.ino() == opened.ino(),
            "submission envelope changed while opening: {path:?}"
        );
    }

    let envelope = read_pending_envelope(&path, &mut file)?;
    ensure_open_file_identity(&path, &file, Some(MAX_ENVELOPE_BYTES))?;
    Ok(PendingSubmission { path, envelope })
}

fn read_pending_envelope(
    path: &Path,
    file: &mut File,
) -> anyhow::Result<DurableSubmissionEnvelope> {
    let length = file.metadata()?.len();
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(length as usize);
    file.take(MAX_ENVELOPE_BYTES + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_ENVELOPE_BYTES,
        "submission envelope grew beyond {MAX_ENVELOPE_BYTES} bytes while reading: {path:?}"
    );
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    let envelope = DurableSubmissionEnvelope::deserialize(&mut deserializer)
        .with_context(|| format!("parse durable submission envelope {path:?}"))?;
    deserializer
        .end()
        .with_context(|| format!("reject trailing durable submission data {path:?}"))?;
    envelope
        .validate()
        .with_context(|| format!("validate durable submission envelope {path:?}"))?;
    Ok(envelope)
}

#[cfg(unix)]
fn prepare_owner_only_directory(path: &Path) -> anyhow::Result<(PathBuf, File)> {
    use std::os::unix::fs::{
        DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
    };

    anyhow::ensure!(
        path.is_absolute(),
        "durable submission directory must be an explicit absolute path"
    );
    ensure_stable_symlink_aliases(path)?;
    // SYSCOIN: Record the nearest pre-existing ancestor so every newly created directory entry can
    // be fsynced before a proof/token is written below it.
    let existing_ancestor = path
        .ancestors()
        .find(|ancestor| fs::symlink_metadata(ancestor).is_ok())
        .context("submission spool has no existing ancestor")?;
    let existing_ancestor = fs::canonicalize(existing_ancestor)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => anyhow::ensure!(
            metadata.file_type().is_dir(),
            "submission spool is not a directory: {path:?}"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700).create(path)?;
        }
        Err(error) => return Err(error.into()),
    }

    let canonical = fs::canonicalize(path)?;
    ensure_stable_symlink_aliases(path)?;
    ensure_stable_directory_ancestry(&canonical)?;
    let metadata = fs::symlink_metadata(&canonical)?;
    anyhow::ensure!(
        metadata.file_type().is_dir() && metadata.uid() == unsafe { libc::geteuid() },
        "submission spool must be a current-service-user-owned directory: {canonical:?}"
    );

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let directory = options.open(&canonical)?;
    let opened = directory.metadata()?;
    anyhow::ensure!(
        opened.is_dir()
            && opened.dev() == metadata.dev()
            && opened.ino() == metadata.ino()
            && opened.uid() == unsafe { libc::geteuid() }
            && metadata.uid() == opened.uid(),
        "submission spool changed while validating ownership: {canonical:?}"
    );
    // SYSCOIN: Ownership authorizes tightening only this dedicated capability namespace.
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
        // every ancestor; otherwise another uid could replace a checked component after startup.
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

fn owner_only_read_write(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn ensure_private_file(
    path: &Path,
    metadata: &fs::Metadata,
    maximum_bytes: Option<u64>,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        anyhow::ensure!(
            metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.permissions().mode() & 0o777 == 0o600
                && metadata.nlink() == 1,
            "durable submission file must be regular, current-service-user-owned, mode 0600, and singly linked: {path:?}"
        );
    }
    if let Some(maximum_bytes) = maximum_bytes {
        anyhow::ensure!(
            metadata.len() <= maximum_bytes,
            "durable submission file exceeds {maximum_bytes} bytes: {path:?}"
        );
    }
    Ok(())
}

fn ensure_open_file_identity(
    path: &Path,
    file: &File,
    maximum_bytes: Option<u64>,
) -> anyhow::Result<()> {
    let named = fs::symlink_metadata(path)?;
    let opened = file.metadata()?;
    ensure_private_file(path, &named, maximum_bytes)?;
    ensure_private_file(path, &opened, maximum_bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        anyhow::ensure!(
            named.dev() == opened.dev() && named.ino() == opened.ino(),
            "durable submission file changed while opening: {path:?}"
        );
    }
    Ok(())
}

// SYSCOIN: Persist the dedicated directory and every newly created parent link before storing
// bearer authority. Syncing a pre-existing leaf and its parent is harmless and closes an unclean
// creation window as well.
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
            format!("existing directory {existing_ancestor:?} is not an ancestor of {path:?}")
        })?;
    }
}

fn sync_directory(directory: &File, display_path: &Path) -> anyhow::Result<()> {
    directory
        .sync_all()
        .with_context(|| format!("fsync durable submission spool {display_path:?}"))
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
        fs::{self, File},
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{
        DurableSubmissionEnvelope, DurableSubmissionStore, ENVELOPE_VERSION, MAX_ENVELOPE_BYTES,
        PENDING_FILE_NAME, TEMPORARY_FILE_NAME,
    };
    use crate::ProverLeaseToken;

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(0);

    fn b256(byte: u8) -> String {
        format!("0x{}", format!("{byte:02x}").repeat(32))
    }

    fn lease(byte: u8) -> ProverLeaseToken {
        ProverLeaseToken::from(b256(byte))
    }

    fn envelope(endpoint: &str) -> DurableSubmissionEnvelope {
        DurableSubmissionEnvelope::fri(
            endpoint.to_owned(),
            7,
            b256(0x11),
            "proof-secret".to_owned(),
            lease(0x22),
        )
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let unique = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "zksync-prover-submission-test-{}-{nanos}-{unique}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn spool(&self, name: &str) -> PathBuf {
            self.path().join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        File::open(path).unwrap().sync_all().unwrap();
    }

    fn write_private_without_sync(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn relative_spool_is_rejected() {
        let error = DurableSubmissionStore::open(PathBuf::from("relative-spool")).unwrap_err();
        assert!(error.to_string().contains("explicit absolute path"));
    }

    #[cfg(unix)]
    #[test]
    fn leaf_symlink_is_rejected_without_mutation_and_owned_directory_is_tightened() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let temporary = TestDirectory::new();
        let target = temporary.spool("target");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        let link = temporary.spool("linked-spool");
        symlink(&target, &link).unwrap();
        assert!(DurableSubmissionStore::open(link).is_err());
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o755
        );

        let owned = temporary.spool("owned-spool");
        fs::create_dir(&owned).unwrap();
        fs::set_permissions(&owned, fs::Permissions::from_mode(0o777)).unwrap();
        let store = DurableSubmissionStore::open(owned.clone()).unwrap();
        assert_eq!(
            fs::metadata(owned).unwrap().permissions().mode() & 0o777,
            0o700
        );
        drop(store);
    }

    // SYSCOIN: Path-based capability operations are safe only when another uid cannot rename a
    // checked ancestor and redirect publication away from the directory descriptor we fsync.
    #[cfg(unix)]
    #[test]
    fn group_or_world_writable_non_sticky_ancestor_is_rejected() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = TestDirectory::new();
        let replaceable = temporary.spool("replaceable");
        let spool = replaceable.join("spool");
        fs::create_dir_all(&spool).unwrap();
        fs::set_permissions(&spool, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&replaceable, fs::Permissions::from_mode(0o777)).unwrap();

        let error = DurableSubmissionStore::open(spool).unwrap_err();
        assert!(format!("{error:#}").contains("replaceable ancestor"));
    }

    // SYSCOIN: A held descriptor must never be used to fsync one directory while path-based
    // reads or mutations silently move to a replacement bearing the configured name.
    #[cfg(unix)]
    #[tokio::test]
    async fn runtime_directory_replacement_fails_closed() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = TestDirectory::new();
        let directory = temporary.spool("spool");
        let detached = temporary.spool("detached-spool");
        let store = DurableSubmissionStore::open(directory.clone()).unwrap();
        fs::rename(&directory, &detached).unwrap();
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();

        let error = store.ensure_empty().await.unwrap_err();
        assert!(format!("{error:#}").contains("path changed"));
    }

    #[tokio::test]
    async fn durable_envelope_round_trip_is_private_redacted_and_exactly_retired() {
        let temporary = TestDirectory::new();
        let directory = temporary.spool("spool");
        let store = DurableSubmissionStore::open(directory.clone()).unwrap();
        let pending = store
            .persist(envelope("https://sequencer.example/"))
            .await
            .unwrap();
        let debug = format!("{:?}", pending.envelope);
        assert!(!debug.contains("proof-secret"));
        assert!(!debug.contains(&b256(0x22)));

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
        assert_eq!(
            store
                .load_for_endpoint("https://sequencer.example/")
                .await
                .unwrap()
                .len(),
            1
        );
        store.retire(&pending).await.unwrap();
        store.ensure_empty().await.unwrap();
        assert!(!directory.join(PENDING_FILE_NAME).exists());
    }

    #[test]
    fn spool_rejects_second_live_owner() {
        let temporary = TestDirectory::new();
        let directory = temporary.spool("spool");
        let first = DurableSubmissionStore::open(directory.clone()).unwrap();
        let error = DurableSubmissionStore::open(directory).unwrap_err();
        assert!(error.to_string().contains("already owned"));
        drop(first);
    }

    #[tokio::test]
    async fn valid_fsynced_temporary_record_is_promoted_on_restart() {
        let temporary = TestDirectory::new();
        let directory = temporary.spool("recover");
        fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let temporary_path = directory.join(TEMPORARY_FILE_NAME);
        write_private(
            &temporary_path,
            &serde_json::to_vec(&envelope("https://sequencer.example/")).unwrap(),
        );
        File::open(&directory).unwrap().sync_all().unwrap();

        let store = DurableSubmissionStore::open(directory.clone()).unwrap();
        assert!(!temporary_path.exists());
        assert!(directory.join(PENDING_FILE_NAME).is_file());
        assert_eq!(
            store
                .load_for_endpoint("https://sequencer.example/")
                .await
                .unwrap()
                .len(),
            1
        );
    }

    // SYSCOIN: A process may die after writing a complete temporary record but before either the
    // file or its directory entry is fsynced. Recovery must durably anchor both before replay.
    #[tokio::test]
    async fn complete_unfsynced_temporary_record_is_durably_promoted_on_restart() {
        let temporary = TestDirectory::new();
        let directory = temporary.spool("recover-unsynced");
        fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let temporary_path = directory.join(TEMPORARY_FILE_NAME);
        write_private_without_sync(
            &temporary_path,
            &serde_json::to_vec(&envelope("https://sequencer.example/")).unwrap(),
        );

        let store = DurableSubmissionStore::open(directory.clone()).unwrap();
        assert!(!temporary_path.exists());
        assert!(directory.join(PENDING_FILE_NAME).is_file());
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
    fn ambiguous_temporary_and_pending_records_fail_without_mutation() {
        let temporary = TestDirectory::new();
        let directory = temporary.spool("ambiguous");
        fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let bytes = serde_json::to_vec(&envelope("https://sequencer.example/")).unwrap();
        write_private(&directory.join(TEMPORARY_FILE_NAME), &bytes);
        write_private(&directory.join(PENDING_FILE_NAME), &bytes);

        let error = DurableSubmissionStore::open(directory.clone()).unwrap_err();
        assert!(format!("{error:#}").contains("ambiguous temporary and pending"));
        assert!(directory.join(TEMPORARY_FILE_NAME).exists());
        assert!(directory.join(PENDING_FILE_NAME).exists());
    }

    #[test]
    fn malformed_temporary_or_unknown_pending_record_fails_closed() {
        let temporary = TestDirectory::new();
        for (name, record_name, bytes) in [
            ("malformed", TEMPORARY_FILE_NAME, b"{truncated".to_vec()),
            (
                "unknown-field",
                PENDING_FILE_NAME,
                format!(
                    r#"{{"version":1,"endpoint":"https://sequencer.example/","stage":"fri","batch_number":7,"vk_hash":"{}","proof":"proof","lease_token":"{}","unexpected":true}}"#,
                    b256(0x11),
                    b256(0x22)
                )
                .into_bytes(),
            ),
        ] {
            let directory = temporary.spool(name);
            fs::create_dir(&directory).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            }
            let record = directory.join(record_name);
            write_private(&record, &bytes);
            assert!(DurableSubmissionStore::open(directory.clone()).is_err());
            assert!(record.exists());
        }
    }

    #[test]
    fn unsupported_version_and_group_readable_pending_record_fail_closed() {
        let temporary = TestDirectory::new();

        let future_directory = temporary.spool("future");
        fs::create_dir(&future_directory).unwrap();
        let mut future = envelope("https://sequencer.example/");
        future.version = ENVELOPE_VERSION + 1;
        let future_path = future_directory.join(PENDING_FILE_NAME);
        write_private(&future_path, &serde_json::to_vec(&future).unwrap());
        let error = DurableSubmissionStore::open(future_directory).unwrap_err();
        assert!(format!("{error:#}").contains("unsupported durable submission envelope version"));
        assert!(future_path.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let broad_directory = temporary.spool("broad-mode");
            fs::create_dir(&broad_directory).unwrap();
            let broad_path = broad_directory.join(PENDING_FILE_NAME);
            write_private(
                &broad_path,
                &serde_json::to_vec(&envelope("https://sequencer.example/")).unwrap(),
            );
            fs::set_permissions(&broad_path, fs::Permissions::from_mode(0o640)).unwrap();
            let error = DurableSubmissionStore::open(broad_directory).unwrap_err();
            assert!(format!("{error:#}").contains("mode 0600"));
            assert!(broad_path.exists());
        }
    }

    #[tokio::test]
    async fn runtime_temporary_record_blocks_fresh_work() {
        let temporary = TestDirectory::new();
        let directory = temporary.spool("runtime-temporary");
        let store = DurableSubmissionStore::open(directory.clone()).unwrap();
        let temporary_path = directory.join(TEMPORARY_FILE_NAME);
        write_private(&temporary_path, b"{partial");
        let error = store.ensure_empty().await.unwrap_err();
        assert!(error.to_string().contains("unrecovered temporary"));
        assert!(temporary_path.exists());
    }

    #[test]
    fn oversized_record_and_unknown_inventory_entry_fail_closed() {
        let temporary = TestDirectory::new();
        let oversized_directory = temporary.spool("oversized");
        fs::create_dir(&oversized_directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&oversized_directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let oversized = oversized_directory.join(PENDING_FILE_NAME);
        let file = File::create(&oversized).unwrap();
        file.set_len(MAX_ENVELOPE_BYTES + 1).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&oversized, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(DurableSubmissionStore::open(oversized_directory).is_err());

        let unknown_directory = temporary.spool("unknown");
        fs::create_dir(&unknown_directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&unknown_directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(unknown_directory.join("operator-note"), b"unexpected").unwrap();
        assert!(DurableSubmissionStore::open(unknown_directory).is_err());

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::ffi::OsStringExt as _;

            let non_utf8_directory = temporary.spool("non-utf8");
            fs::create_dir(&non_utf8_directory).unwrap();
            let name = std::ffi::OsString::from_vec(vec![b'p', b'e', b'n', b'd', 0xff]);
            fs::write(non_utf8_directory.join(name), b"unexpected").unwrap();
            let error = DurableSubmissionStore::open(non_utf8_directory).unwrap_err();
            assert!(format!("{error:#}").contains("non-UTF8 entry"));
        }
    }

    #[tokio::test]
    async fn endpoint_binding_and_single_global_pending_record_are_enforced() {
        let temporary = TestDirectory::new();
        let store = DurableSubmissionStore::open(temporary.spool("spool")).unwrap();
        store.persist(envelope("https://a.example/")).await.unwrap();
        let configured = HashSet::from(["https://b.example/".to_owned()]);
        assert!(store.validate_configured_endpoints(&configured).is_err());
        assert!(store.persist(envelope("https://b.example/")).await.is_err());
    }

    #[tokio::test]
    async fn exact_wire_body_limit_is_enforced_before_publication() {
        let temporary = TestDirectory::new();
        let directory = temporary.spool("spool");
        let store = DurableSubmissionStore::open(directory.clone()).unwrap();
        let oversized = DurableSubmissionEnvelope::fri(
            "https://sequencer.example/".to_owned(),
            1,
            b256(0x11),
            "x".repeat(crate::MAX_PROOF_SUBMISSION_BODY_BYTES),
            lease(0x22),
        );
        let error = store.persist(oversized).await.unwrap_err();
        assert!(error.to_string().contains("server maximum"));
        assert!(!directory.join(TEMPORARY_FILE_NAME).exists());
        assert!(!directory.join(PENDING_FILE_NAME).exists());
    }
}
