use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use serde::Serialize;
#[cfg(unix)]
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt, PermissionsExt as _};
use std::path::{Path, PathBuf};
use tracing_subscriber::{fmt, EnvFilter};
use zkos_wrapper::SnarkWrapperProof;
use zksync_sequencer_proof_client::{
    validate_canonical_endpoint_identity, FriJobInputs, L2BatchNumber, OpaqueSequencerEndpoint,
    ProofClient, ProverLeaseToken, SequencerProofClient, SnarkProofInputs,
    MAX_FRI_JOB_RESPONSE_BYTES, MAX_PROOF_SUBMISSION_BODY_BYTES, MAX_SNARK_JOB_RESPONSE_BYTES,
};

// SYSCOIN: Decoded proof/job structs expand when represented as JSON arrays and objects. Keep the
// manual format bounded, but allow a conservative fixed expansion over each authenticated wire cap.
const MAX_MANUAL_FRI_JOB_ARTIFACT_BYTES: usize = MAX_FRI_JOB_RESPONSE_BYTES * 8;
const MAX_MANUAL_SNARK_JOB_ARTIFACT_BYTES: usize = MAX_SNARK_JOB_RESPONSE_BYTES * 8;

struct BoundedWriter<W> {
    inner: W,
    remaining: usize,
}

impl<W: std::io::Write> std::io::Write for BoundedWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if buffer.len() > self.remaining {
            return Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                "manual job artifact exceeds its bounded decoded-JSON expansion",
            ));
        }
        let written = self.inner.write(buffer)?;
        self.remaining = self.remaining.saturating_sub(written);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

// SYSCOIN: Manual pick artifacts bind bearer authority to the credential-free canonical endpoint
// that issued it. Credentials are held only by the client and can never enter these serialized
// wrappers; submit checks this identity before opening a potentially expensive proof artifact.
#[derive(Serialize)]
struct SavedFriJob<'a> {
    sequencer_endpoint: &'a str,
    #[serde(flatten)]
    job: &'a FriJobInputs,
}

#[derive(Serialize)]
struct SavedSnarkJob<'a> {
    sequencer_endpoint: &'a str,
    #[serde(flatten)]
    job: &'a SnarkProofInputs,
}

// SYSCOIN: Submission authority is loaded from the private pick artifact, never argv.
#[derive(Deserialize)]
struct SavedFriJobAuthority {
    sequencer_endpoint: String,
    batch_number: u32,
    vk_hash: String,
    lease_token: ProverLeaseToken,
}

// SYSCOIN: Ignore the large proof inputs while reading only the private aggregate capability.
#[derive(Deserialize)]
struct SavedSnarkJobAuthority {
    sequencer_endpoint: String,
    from_batch_number: L2BatchNumber,
    to_batch_number: L2BatchNumber,
    vk_hash: String,
    lease_token: ProverLeaseToken,
}

// SYSCOIN: Manual publication uses only local-Unix semantics: a process-held `flock`, same-directory
// hard links, and file/directory fsync. NFS/FUSE/object-backed filesystems are unsupported unless
// they provide the same atomic no-replace, advisory-lock, and durability guarantees.
#[cfg(unix)]
const MANUAL_LOCK_SUFFIX: &str = ".manual-pick.lock";
#[cfg(unix)]
const MANUAL_PENDING_SUFFIX: &str = ".manual-pick.pending";

/// SYSCOIN: Hold a deterministic per-final lock while the final name remains absent. Publication
/// hard-links a fully fsynced same-directory pending file into the final name, which is a portable
/// local-Unix atomic no-overwrite operation. A crash-retained pending file blocks another pick for
/// explicit operator recovery instead of silently discarding a live lease.
#[cfg(unix)]
#[derive(Debug)]
struct ReservedJobPath {
    path: PathBuf,
    pending_path: PathBuf,
    _lock: File,
    parent: File,
    parent_path: PathBuf,
    published: bool,
}

#[cfg(unix)]
impl ReservedJobPath {
    fn new(path: impl AsRef<Path>) -> Result<Self> {
        let requested_path = path.as_ref();
        let file_name = requested_path
            .file_name()
            .filter(|name| !name.is_empty())
            .context("manual job destination must have a filename")?;
        ensure_manual_final_name_is_not_reserved(file_name)?;
        let requested_parent = requested_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let (parent_path, parent) = open_private_parent_directory(requested_parent)?;
        // SYSCOIN: Rebuild every authority-bearing name below the validated canonical parent.
        // A trusted lexical alias cannot redirect later operations to a different directory.
        let path = parent_path.join(file_name);
        let lock_path = manual_control_path(&path, MANUAL_LOCK_SUFFIX)?;
        let pending_path = manual_control_path(&path, MANUAL_PENDING_SUFFIX)?;

        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_path)
            .with_context(|| format!("open private manual-pick lock {}", lock_path.display()))?;
        ensure_private_regular_file(&lock_path, &lock.metadata()?, Some(1))?;
        try_lock_exclusive(&lock).with_context(|| {
            format!(
                "manual job destination {} is already reserved by another process",
                path.display()
            )
        })?;

        // SYSCOIN: Check both names only after holding the deterministic lock. The final remains
        // absent throughout the lease-changing request, so hard-link publication can be no-replace.
        ensure_path_absent(&path, "manual job destination already exists")?;
        ensure_path_absent(
            &pending_path,
            "stale manual job pending artifact requires operator recovery",
        )?;
        ensure_private_parent_identity(&parent_path, &parent)?;
        lock.sync_all().context("fsync private manual-pick lock")?;
        parent
            .sync_all()
            .with_context(|| format!("fsync manual job parent {}", parent_path.display()))?;

        Ok(Self {
            path,
            pending_path,
            _lock: lock,
            parent,
            parent_path,
            published: false,
        })
    }

    fn publish_json<T: Serialize>(&mut self, value: &T, maximum_bytes: usize) -> Result<()> {
        anyhow::ensure!(!self.published, "manual job artifact is already published");
        ensure_path_absent(&self.path, "manual job destination already exists")?;
        ensure_path_absent(
            &self.pending_path,
            "stale manual job pending artifact requires operator recovery",
        )?;
        ensure_private_parent_identity(&self.parent_path, &self.parent)?;

        let mut pending = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.pending_path)
            .with_context(|| {
                format!(
                    "create private manual job pending file {}",
                    self.pending_path.display()
                )
            })?;
        let expected = pending.metadata()?;
        ensure_private_regular_file(&self.pending_path, &expected, Some(1))?;

        // SYSCOIN: Until serialization succeeds the pending file is only an incomplete artifact,
        // so a bounded serialization failure safely removes only the inode this process created.
        let write_result = (|| -> Result<()> {
            let mut bounded = BoundedWriter {
                inner: &mut pending,
                remaining: maximum_bytes,
            };
            // SYSCOIN: A successful serializer return is the exact transition from safely
            // disposable partial bytes to a complete capability that must be retained on every
            // later error. Do not append an optional newline or flush inside the cleanup window.
            serde_json::to_writer(&mut bounded, value)?;
            Ok(())
        })();
        if let Err(error) = write_result {
            cleanup_file_if_same_inode(&self.pending_path, &expected, &self.parent);
            return Err(error);
        }

        // SYSCOIN: A complete capability is now present. Even a file-fsync error is ambiguous,
        // so retain the exact pending inode and block another pick for operator/restart recovery.
        pending
            .sync_all()
            .context("fsync private manual job pending file")?;

        // SYSCOIN: From this point the pending file itself is the only crash-durable copy of the
        // picked capability. Persist its directory entry before linking the final name; any later
        // publication failure retains it and blocks later picks.
        ensure_path_matches_file(&self.pending_path, &expected, Some(1))?;
        self.parent.sync_all().with_context(|| {
            format!(
                "fsync durable manual job pending name {}",
                self.pending_path.display()
            )
        })?;
        fs::hard_link(&self.pending_path, &self.path).with_context(|| {
            format!(
                "atomically publish private job file {} without overwrite; pending artifact retained at {}",
                self.path.display(),
                self.pending_path.display()
            )
        })?;
        ensure_path_matches_file(&self.path, &expected, Some(2))?;
        ensure_path_matches_file(&self.pending_path, &expected, Some(2))?;

        // SYSCOIN: Persist the two-name hard-link state before removing its recovery anchor.
        self.parent.sync_all().with_context(|| {
            format!(
                "fsync published manual job and pending names for {}",
                self.path.display()
            )
        })?;

        fs::remove_file(&self.pending_path).with_context(|| {
            format!(
                "remove published manual job pending link {}",
                self.pending_path.display()
            )
        })?;
        ensure_path_matches_file(&self.path, &expected, Some(1))?;
        self.parent
            .sync_all()
            .with_context(|| format!("fsync parent directory for {}", self.path.display()))?;
        ensure_private_parent_identity(&self.parent_path, &self.parent)?;
        self.published = true;
        Ok(())
    }
}

// SYSCOIN: Control names are deterministic `.<final><suffix>` siblings. Forbid choosing one of
// those hidden names as another command's final artifact, otherwise distinct per-final locks could
// authorize two reservations whose final/control names collide after both have acquired leases.
#[cfg(unix)]
fn ensure_manual_final_name_is_not_reserved(file_name: &std::ffi::OsStr) -> Result<()> {
    use std::os::unix::ffi::OsStrExt as _;

    let bytes = file_name.as_bytes();
    // SYSCOIN: APFS and other case-insensitive filesystems alias ASCII case variants of these
    // control suffixes. Reject every such spelling before two distinct lexical locks can reserve
    // one final/control entry and acquire separate leases.
    let has_reserved_suffix =
        [MANUAL_LOCK_SUFFIX, MANUAL_PENDING_SUFFIX]
            .into_iter()
            .any(|suffix| {
                let suffix = suffix.as_bytes();
                bytes.len() >= suffix.len()
                    && bytes[bytes.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
            });
    anyhow::ensure!(
        !(bytes.starts_with(b".") && has_reserved_suffix),
        "manual job destination filename is reserved for publication control state"
    );
    Ok(())
}

#[cfg(unix)]
fn manual_control_path(path: &Path, suffix: &str) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .context("manual job destination must have a filename")?;
    let mut control_name = OsString::from(".");
    control_name.push(file_name);
    control_name.push(suffix);
    Ok(path.with_file_name(control_name))
}

#[cfg(unix)]
fn open_private_parent_directory(path: &Path) -> Result<(PathBuf, File)> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    ensure_stable_manual_symlink_aliases(&absolute)?;
    let canonical = fs::canonicalize(&absolute)
        .with_context(|| format!("canonicalize manual job parent {}", path.display()))?;
    ensure_stable_manual_parent_ancestry(&canonical)?;
    let before = fs::symlink_metadata(&canonical)
        .with_context(|| format!("inspect manual job parent {}", canonical.display()))?;
    anyhow::ensure!(
        before.file_type().is_dir(),
        "job artifact parent is not a directory: {}",
        canonical.display()
    );
    anyhow::ensure!(
        before.uid() == unsafe { libc::geteuid() } && before.permissions().mode() & 0o022 == 0,
        "manual job parent must be current-user-owned and not group/world-writable: {}",
        canonical.display()
    );
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let directory = options
        .open(&canonical)
        .with_context(|| format!("open manual job parent {}", canonical.display()))?;
    let opened = directory.metadata()?;
    anyhow::ensure!(
        opened.is_dir()
            && opened.dev() == before.dev()
            && opened.ino() == before.ino()
            && opened.uid() == unsafe { libc::geteuid() }
            && opened.permissions().mode() & 0o022 == 0,
        "manual job parent changed or became unsafe while opening: {}",
        canonical.display()
    );
    ensure_stable_manual_symlink_aliases(&absolute)?;
    ensure_private_parent_identity(&canonical, &directory)?;
    Ok((canonical, directory))
}

// SYSCOIN: Manual capability paths use the same root/euid-only ancestor trust model as the
// durable spool. An untrusted owner could otherwise chmod an ancestor and replace the parent after
// validation even if its current mode is non-writable.
#[cfg(unix)]
fn ensure_stable_manual_parent_ancestry(path: &Path) -> Result<()> {
    let effective_uid = unsafe { libc::geteuid() };
    for child in path
        .ancestors()
        .take_while(|ancestor| ancestor.parent().is_some())
    {
        let parent = child.parent().expect("non-root ancestor has a parent");
        let parent_metadata = fs::symlink_metadata(parent)?;
        let child_metadata = fs::symlink_metadata(child)?;
        anyhow::ensure!(
            parent_metadata.file_type().is_dir()
                && child_metadata.file_type().is_dir()
                && (parent_metadata.uid() == 0 || parent_metadata.uid() == effective_uid),
            "manual job parent ancestry contains an untrusted or non-directory component"
        );
        let mode = parent_metadata.permissions().mode();
        if mode & 0o022 != 0 {
            anyhow::ensure!(
                mode & 0o1000 != 0 && child_metadata.uid() == effective_uid,
                "manual job parent has a replaceable group/world-writable ancestor"
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_stable_manual_symlink_aliases(path: &Path) -> Result<()> {
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
        let parent_metadata = fs::symlink_metadata(parent)?;
        let mode = parent_metadata.permissions().mode();
        anyhow::ensure!(
            (parent_metadata.uid() == 0 || parent_metadata.uid() == effective_uid)
                && (mode & 0o022 == 0 || (mode & 0o1000 != 0 && metadata.uid() == effective_uid)),
            "manual job destination uses a replaceable symlink alias"
        );
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_private_parent_identity(path: &Path, directory: &File) -> Result<()> {
    let named = fs::symlink_metadata(path)?;
    let opened = directory.metadata()?;
    anyhow::ensure!(
        named.file_type().is_dir()
            && named.dev() == opened.dev()
            && named.ino() == opened.ino()
            && opened.uid() == unsafe { libc::geteuid() }
            && opened.permissions().mode() & 0o022 == 0,
        "manual job parent changed or lost its private identity"
    );
    Ok(())
}

#[cfg(unix)]
fn ensure_path_absent(path: &Path, reason: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(anyhow!("{reason}: {}", path.display())),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

#[cfg(unix)]
fn ensure_private_regular_file(
    path: &Path,
    metadata: &fs::Metadata,
    expected_links: Option<u64>,
) -> Result<()> {
    anyhow::ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.permissions().mode() & 0o077 == 0
            && expected_links.is_none_or(|links| metadata.nlink() == links),
        "manual job control file must be regular, current-user-owned, owner-only, and have the expected link count: {}",
        path.display()
    );
    Ok(())
}

#[cfg(unix)]
fn ensure_path_matches_file(
    path: &Path,
    expected: &fs::Metadata,
    expected_links: Option<u64>,
) -> Result<()> {
    let current = fs::symlink_metadata(path)
        .with_context(|| format!("inspect manual job file {}", path.display()))?;
    ensure_private_regular_file(path, &current, expected_links)?;
    anyhow::ensure!(
        current.dev() == expected.dev() && current.ino() == expected.ino(),
        "manual job file changed during publication: {}",
        path.display()
    );
    Ok(())
}

#[cfg(unix)]
fn cleanup_file_if_same_inode(path: &Path, expected: &fs::Metadata, parent: &File) {
    if ensure_path_matches_file(path, expected, Some(1)).is_ok() && fs::remove_file(path).is_ok() {
        let _ = parent.sync_all();
    }
}

#[cfg(unix)]
fn try_lock_exclusive(file: &File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;

    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// SYSCOIN: Open a manual capability artifact without following symlinks and require the current
/// owner, one link, owner-only mode, regular-file type, and a bounded on-disk representation.
#[cfg(unix)]
fn open_private_job_file(path: impl AsRef<Path>, maximum_bytes: usize) -> Result<File> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let path = path.as_ref();
    let before = fs::symlink_metadata(path)
        .with_context(|| format!("inspect private job file {}", path.display()))?;
    anyhow::ensure!(
        before.file_type().is_file(),
        "private job path is not a regular file"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open private job file {}", path.display()))?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.dev() == before.dev()
            && metadata.ino() == before.ino()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.nlink() == 1
            && metadata.permissions().mode() & 0o077 == 0,
        "private job file must be current-user-owned, owner-only, and have exactly one link"
    );
    anyhow::ensure!(
        metadata.len() <= maximum_bytes as u64,
        "private job file exceeds {maximum_bytes} bytes"
    );
    Ok(file)
}

/// SYSCOIN: Read local manual artifacts fully under the same explicit wire-class caps used by the
/// network client. Metadata is only a hint; `take(max + 1)` also catches a file that grows after
/// open, before serde can allocate from attacker- or accident-controlled lengths.
fn deserialize_json_bounded<T: serde::de::DeserializeOwned>(
    file: File,
    maximum_bytes: usize,
    artifact_kind: &str,
) -> Result<T> {
    let initial_metadata = file.metadata()?;
    anyhow::ensure!(
        initial_metadata.len() <= maximum_bytes as u64,
        "{artifact_kind} exceeds {maximum_bytes} bytes"
    );
    let read_limit = u64::try_from(maximum_bytes)
        .context("manual artifact size limit does not fit u64")?
        .checked_add(1)
        .context("manual artifact size limit overflow")?;
    let mut limited = std::io::Read::take(file, read_limit);
    let value = serde_json::from_reader(&mut limited)
        .with_context(|| format!("decode {artifact_kind} JSON"))?;
    // SYSCOIN: Recheck the opened inode after streaming so growth cannot hide behind the initial
    // metadata check or a valid JSON prefix at the reader limit.
    let final_metadata = limited.get_ref().metadata()?;
    anyhow::ensure!(
        final_metadata.len() <= maximum_bytes as u64,
        "{artifact_kind} exceeds {maximum_bytes} bytes"
    );
    #[cfg(unix)]
    anyhow::ensure!(
        final_metadata.dev() == initial_metadata.dev()
            && final_metadata.ino() == initial_metadata.ino()
            && final_metadata.uid() == initial_metadata.uid()
            && final_metadata.nlink() == initial_metadata.nlink()
            && final_metadata.permissions().mode() == initial_metadata.permissions().mode(),
        "{artifact_kind} metadata changed while reading"
    );
    Ok(value)
}

fn deserialize_private_job_bounded<T: serde::de::DeserializeOwned>(
    path: impl AsRef<Path>,
    maximum_bytes: usize,
) -> Result<T> {
    deserialize_json_bounded(
        open_private_job_file(path, maximum_bytes)?,
        maximum_bytes,
        "private job artifact",
    )
}

// SYSCOIN: A manual bearer capability is valid only at the exact credential-free endpoint that
// issued it. Check this before opening proof material or making a submission request.
fn ensure_manual_job_endpoint(expected: &str, configured: &str) -> Result<()> {
    let expected = validate_canonical_endpoint_identity(expected)
        .context("private job artifact endpoint identity is invalid")?;
    anyhow::ensure!(
        expected.as_str() == configured,
        "private job artifact endpoint does not match the configured sequencer"
    );
    Ok(())
}

fn deserialize_proof_bounded<T: serde::de::DeserializeOwned>(
    path: impl AsRef<Path>,
    maximum_bytes: usize,
) -> Result<T> {
    let path = path.as_ref();
    let before = fs::symlink_metadata(path)
        .with_context(|| format!("inspect manual proof artifact {}", path.display()))?;
    anyhow::ensure!(
        before.file_type().is_file() && before.len() <= maximum_bytes as u64,
        "manual proof artifact must be a regular file no larger than {maximum_bytes} bytes"
    );
    // SYSCOIN: Close the inspect/open replacement window too: an untrusted writable parent must
    // not swap a checked proof path for a symlink to an unrelated local JSON file.
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .with_context(|| format!("open manual proof artifact {}", path.display()))?;
    let opened = file.metadata()?;
    anyhow::ensure!(
        opened.is_file() && opened.len() <= maximum_bytes as u64,
        "manual proof artifact changed type or exceeded {maximum_bytes} bytes while opening"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        anyhow::ensure!(
            opened.dev() == before.dev()
                && opened.ino() == before.ino()
                && opened.uid() == unsafe { libc::geteuid() }
                && opened.nlink() == 1
                && opened.permissions().mode() & 0o022 == 0,
            "manual proof artifact must be current-user-owned, not group/world-writable, singly linked, and unchanged while opening"
        );
    }
    deserialize_json_bounded(file, maximum_bytes, "manual proof artifact")
}

/// SYSCOIN: Fail closed where std cannot guarantee an owner-only capability file.
#[cfg(not(unix))]
struct ReservedJobPath;

#[cfg(not(unix))]
impl ReservedJobPath {
    fn new(_path: impl AsRef<Path>) -> Result<Self> {
        Err(anyhow!(
            "manual pick requires an owner-only job file; this platform is not supported"
        ))
    }

    fn publish_json<T: Serialize>(&mut self, _value: &T, _maximum_bytes: usize) -> Result<()> {
        Err(anyhow!(
            "manual pick requires an owner-only job file; this platform is not supported"
        ))
    }
}

#[cfg(not(unix))]
fn open_private_job_file(_path: impl AsRef<Path>, _maximum_bytes: usize) -> Result<File> {
    Err(anyhow!(
        "manual submit requires an owner-only job file; this platform is not supported"
    ))
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Sequencer URL to submit proofs to
    ///
    /// Format: http[s]://[username:password@]host:port. Do not put credentials on argv; set
    /// `ZKSYNC_SEQUENCER_URL` from an owner-only secret file instead.
    #[arg(
        short,
        long,
        global = true,
        value_name = "URL",
        env = "ZKSYNC_SEQUENCER_URL",
        hide_env_values = true,
        default_value = "http://localhost:3124"
    )]
    url: Option<OpaqueSequencerEndpoint>,

    /// Activate verbose logging (`-v`, `-vv`, ...)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

impl Cli {
    /// Regular `::parse()`, but checks that the `--url` argument is provided & initializes tracing.
    fn init() -> Result<Self> {
        let cli = Cli::parse();
        if cli.url.is_none() {
            return Err(anyhow!("The --url <URL> argument is required. It can be placed anywhere on the command line."));
        }
        init_tracing(cli.verbose);
        Ok(cli)
    }

    /// Return sequencer client from CLI params. To be called only after `Cli::init()`.
    fn sequencer_client(&self) -> anyhow::Result<SequencerProofClient> {
        // The CLI client declares no supported versions - the sequencer offers it any job.
        SequencerProofClient::new(
            self.url
                .clone()
                .expect("called sequencer_client() before init()")
                // SYSCOIN: Validate the opaque secret only after Clap has finished rendering.
                .into_endpoint()
                .context("invalid configured sequencer endpoint")?,
            "cli_client".to_string(),
            None,
            vec![],
        )
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Picks the next FRI proof job from the sequencer; sequencer marks job as picked (and will not give it to other clients, until the job expires)
    PickFri {
        /// Path to the FRI proof job to save
        #[arg(short, long, value_name = "FRI_PATH", default_value = "./fri_job.json")]
        path: String,
    },
    /// Submits batch's FRI proof to sequencer
    SubmitFri {
        /// SYSCOIN: Private FRI job file produced by the matching pick command
        #[arg(long, value_name = "FRI_JOB_PATH", default_value = "./fri_job.json")]
        job_path: String,
        /// Path to the FRI proof file to submit
        #[arg(
            long,
            value_name = "FRI_PROOF_PATH",
            default_value = "./fri_proof.json"
        )]
        proof_path: String,
    },
    /// Picks the next SNARK proof job from the sequencer; sequencer marks job as picked (and will not give it to other clients, until the job expires)
    PickSnark {
        /// Path to the SNARK proof job to save
        #[arg(
            short,
            long,
            value_name = "SNARK_PATH",
            default_value = "./snark_job.json"
        )]
        path: String,
    },
    /// Submits batch's SNARK proof to sequencer
    SubmitSnark {
        /// SYSCOIN: Private SNARK job file produced by the matching pick command
        #[arg(
            long,
            value_name = "SNARK_JOB_PATH",
            default_value = "./snark_job.json"
        )]
        job_path: String,
        /// Path to the SNARK proof file to submit
        #[arg(
            long,
            value_name = "SNARK_PROOF_PATH",
            default_value = "./snark_proof.json"
        )]
        proof_path: String,
    },
}

fn init_tracing(verbosity: u8) {
    let level = match verbosity {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    fmt::Subscriber::builder()
        .with_env_filter(env_filter)
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::init()?;

    let client = cli.sequencer_client()?;

    let url = client.sequencer_url();

    match cli.command {
        Commands::PickFri { path } => {
            // SYSCOIN: Lock before the lease-changing request. No-job/request failure leaves only
            // the reusable deterministic control lock; it never creates or removes the final name.
            let mut destination = ReservedJobPath::new(&path)?;
            tracing::info!("Picking next FRI proof job from sequencer at {}", url);
            match client.pick_fri_job().await? {
                Some(fri_job) => {
                    // SYSCOIN: Publish the input and capability atomically and durably without
                    // logging/group/world exposure, bound to the sanitized issuing endpoint.
                    let saved_job = SavedFriJob {
                        sequencer_endpoint: url.as_str(),
                        job: &fri_job,
                    };
                    destination.publish_json(&saved_job, MAX_MANUAL_FRI_JOB_ARTIFACT_BYTES)?;
                    tracing::info!(
                        "Picked FRI job for batch {} with vk {}, saved job to path {path}",
                        fri_job.batch_number,
                        fri_job.vk_hash,
                    );
                }
                None => {
                    tracing::info!("No FRI proof jobs available at the moment.");
                }
            }
        }
        Commands::SubmitFri {
            job_path,
            proof_path,
        } => {
            // SYSCOIN: Read batch/VK/capability from the matching private pick artifact so the
            // bearer token is absent from shell history and process listings.
            let job: SavedFriJobAuthority =
                deserialize_private_job_bounded(&job_path, MAX_MANUAL_FRI_JOB_ARTIFACT_BYTES)?;
            ensure_manual_job_endpoint(&job.sequencer_endpoint, url.as_str())?;
            tracing::info!(
                "Submitting FRI proof for batch {} with proof from {proof_path} to sequencer at {}",
                job.batch_number,
                url
            );
            let fri_proof: String =
                deserialize_proof_bounded(&proof_path, MAX_PROOF_SUBMISSION_BODY_BYTES)?;
            client
                .submit_fri_proof(job.batch_number, job.vk_hash, fri_proof, job.lease_token)
                .await?;
            tracing::info!(
                "Submitted FRI proof for batch {} to sequencer at {}",
                job.batch_number,
                url
            );
        }
        Commands::PickSnark { path } => {
            // SYSCOIN: Lock a safe owner-controlled destination before aggregate authority is
            // leased. No-job/request failure leaves only the reusable deterministic control lock.
            let mut destination = ReservedJobPath::new(&path)?;
            tracing::info!("Picking next SNARK proof job from sequencer at {}", url);
            match client.pick_snark_job().await? {
                Some(snark_proof_inputs) => {
                    tracing::info!(
                        "Received SNARK job for batchess [{}, {}], saving to disk...",
                        snark_proof_inputs.from_batch_number,
                        snark_proof_inputs.to_batch_number
                    );
                    // SYSCOIN: Store only the client's canonical identity, never URL credentials.
                    let saved_job = SavedSnarkJob {
                        sequencer_endpoint: url.as_str(),
                        job: &snark_proof_inputs,
                    };
                    destination.publish_json(&saved_job, MAX_MANUAL_SNARK_JOB_ARTIFACT_BYTES)?;
                    tracing::info!(
                        "Saved SNARK job for batches [{}, {}] with vk {} to path {path}",
                        snark_proof_inputs.from_batch_number,
                        snark_proof_inputs.to_batch_number,
                        snark_proof_inputs.vk_hash
                    );
                }
                None => {
                    tracing::info!("No SNARK proof jobs available at the moment.");
                }
            }
        }
        Commands::SubmitSnark {
            job_path,
            proof_path,
        } => {
            // SYSCOIN: Range/VK/capability come from the private pick artifact, not argv.
            let job: SavedSnarkJobAuthority =
                deserialize_private_job_bounded(&job_path, MAX_MANUAL_SNARK_JOB_ARTIFACT_BYTES)?;
            ensure_manual_job_endpoint(&job.sequencer_endpoint, url.as_str())?;
            tracing::info!(
                "Submitting SNARK proof for batches [{}, {}] with proof from {proof_path} to sequencer at {}",
                job.from_batch_number,
                job.to_batch_number,
                url
            );
            let snark_wrapper: SnarkWrapperProof =
                deserialize_proof_bounded(&proof_path, MAX_SNARK_JOB_RESPONSE_BYTES)?;
            client
                .submit_snark_proof(
                    job.from_batch_number,
                    job.to_batch_number,
                    job.vk_hash,
                    snark_wrapper,
                    job.lease_token,
                )
                .await?;
            tracing::info!(
                "Submitted proof for batches [{}, {}] to sequencer at {}",
                job.from_batch_number,
                job.to_batch_number,
                url
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;
    use zksync_sequencer_proof_client::SequencerEndpoint;

    #[cfg(unix)]
    fn private_test_directory(label: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "zksync-proof-client-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    #[test]
    fn submit_cli_uses_job_and_proof_files_without_authority_on_argv() {
        let cli = Cli::try_parse_from([
            "proof-client",
            "--url",
            "http://localhost:3124",
            "submit-fri",
            "--job-path",
            "private-job.json",
            "--proof-path",
            "proof.json",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::SubmitFri {
                job_path,
                proof_path,
            } if job_path == "private-job.json" && proof_path == "proof.json"
        ));

        // SYSCOIN: The removed bearer-token flag must remain rejected to prevent regression to
        // shell-history/process-list exposure.
        assert!(Cli::try_parse_from([
            "proof-client",
            "--url",
            "http://localhost:3124",
            "submit-fri",
            "--lease-token",
            "secret",
        ])
        .is_err());
    }

    // SYSCOIN: Clap accepts even malformed secret-bearing URL text opaquely and hides live env
    // values from help; only the post-parse value-free validator may reject it.
    #[test]
    fn cli_endpoint_errors_and_help_never_render_credentials() {
        let secret = "manual-clap-password-secret";
        let cli = Cli::try_parse_from([
            "proof-client",
            "--url",
            &format!("https://:{secret}@sequencer.example/"),
            "pick-fri",
        ])
        .expect("opaque endpoint must not fail inside Clap");
        let error = cli.sequencer_client().unwrap_err();
        assert!(!format!("{error:#}").contains(secret));

        let command = Cli::command();
        let url = command
            .get_arguments()
            .find(|argument| argument.get_id() == "url")
            .expect("url argument");
        assert!(url.is_hide_env_values_set());
    }

    #[cfg(unix)]
    #[test]
    fn picked_job_file_is_owner_only_and_never_overwritten() {
        use std::os::unix::fs::PermissionsExt;

        let directory = private_test_directory("private-job");
        let path = directory.join("job.json");
        let mut reservation = ReservedJobPath::new(&path).unwrap();
        assert!(
            !path.exists(),
            "the final name must remain absent before pick"
        );
        let lock_path = manual_control_path(&path, MANUAL_LOCK_SUFFIX).unwrap();
        assert_eq!(
            fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        reservation
            .publish_json(&serde_json::json!({"authority":"private"}), 1024)
            .unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(ReservedJobPath::new(&path).is_err());
        assert!(open_private_job_file(&path, 1024).is_ok());
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unused_reservation_is_removed_and_submit_rejects_unsafe_artifacts() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let directory = private_test_directory("private-safety");
        let reserved = directory.join("reserved.json");
        drop(ReservedJobPath::new(&reserved).unwrap());
        assert!(!reserved.exists());

        let replaced = directory.join("replaced.json");
        let reservation = ReservedJobPath::new(&replaced).unwrap();
        fs::write(&replaced, b"do-not-delete").unwrap();
        drop(reservation);
        assert_eq!(fs::read(&replaced).unwrap(), b"do-not-delete");

        let insecure = directory.join("insecure.json");
        fs::write(&insecure, b"{}").unwrap();
        fs::set_permissions(&insecure, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(open_private_job_file(&insecure, 1024).is_err());

        let target = directory.join("target.json");
        fs::write(&target, b"{}").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let link = directory.join("link.json");
        symlink(&target, &link).unwrap();
        assert!(open_private_job_file(&link, 1024).is_err());
        assert!(deserialize_proof_bounded::<serde_json::Value>(&link, 1024).is_err());

        // SYSCOIN: A proof path is integrity-sensitive because definitive rejection consumes the
        // private lease. Reject writable or aliased inodes even when their JSON is syntactically
        // valid and O_NOFOLLOW closes pathname substitution.
        let writable_proof = directory.join("writable-proof.json");
        fs::write(&writable_proof, br#""wrong-proof""#).unwrap();
        fs::set_permissions(&writable_proof, fs::Permissions::from_mode(0o622)).unwrap();
        assert!(deserialize_proof_bounded::<String>(&writable_proof, 1024).is_err());

        let aliased_proof = directory.join("aliased-proof.json");
        fs::write(&aliased_proof, br#""proof""#).unwrap();
        fs::set_permissions(&aliased_proof, fs::Permissions::from_mode(0o600)).unwrap();
        let second_alias = directory.join("aliased-proof-copy.json");
        fs::hard_link(&aliased_proof, &second_alias).unwrap();
        assert!(deserialize_proof_bounded::<String>(&aliased_proof, 1024).is_err());

        // SYSCOIN: A syntactically valid prefix cannot bypass the full-file allocation cap.
        let oversized_proof = directory.join("oversized-proof.json");
        fs::write(&oversized_proof, br#""proof" trailing"#).unwrap();
        assert!(deserialize_proof_bounded::<String>(&oversized_proof, 7).is_err());

        let oversized_job = directory.join("oversized-job.json");
        let mut reservation = ReservedJobPath::new(&oversized_job).unwrap();
        assert!(reservation
            .publish_json(&"decoded-job-expansion", 8)
            .is_err());
        drop(reservation);
        assert!(!oversized_job.exists());
        fs::remove_dir_all(directory).unwrap();
    }

    // SYSCOIN: The final name is atomically no-replace, and a crash-retained deterministic pending
    // artifact prevents another lease-changing pick until an operator recovers it.
    #[cfg(unix)]
    #[test]
    fn manual_publication_rejects_replacement_stale_pending_and_concurrent_owner() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = private_test_directory("publication-races");
        let path = directory.join("job.json");
        let mut reservation = ReservedJobPath::new(&path).unwrap();
        assert!(ReservedJobPath::new(&path).is_err());

        fs::write(&path, b"existing-artifact").unwrap();
        let error = reservation
            .publish_json(&serde_json::json!({"authority":"new"}), 1024)
            .unwrap_err();
        assert!(error.to_string().contains("already exists"));
        assert_eq!(fs::read(&path).unwrap(), b"existing-artifact");
        drop(reservation);
        fs::remove_file(&path).unwrap();

        let pending_path = manual_control_path(&path, MANUAL_PENDING_SUFFIX).unwrap();
        fs::write(&pending_path, b"durable-live-capability").unwrap();
        fs::set_permissions(&pending_path, fs::Permissions::from_mode(0o600)).unwrap();
        let error = ReservedJobPath::new(&path).unwrap_err();
        assert!(error.to_string().contains("operator recovery"));
        assert_eq!(fs::read(&pending_path).unwrap(), b"durable-live-capability");
        fs::remove_dir_all(directory).unwrap();
    }

    // SYSCOIN: A second command cannot reserve another job's deterministic hidden lock/pending
    // sibling as its final artifact under an independent lock.
    #[cfg(unix)]
    #[test]
    fn manual_pick_rejects_control_namespace_as_final_artifact() {
        let directory = private_test_directory("control-namespace");
        let ordinary = directory.join("job.json");
        for control_path in [
            manual_control_path(&ordinary, MANUAL_LOCK_SUFFIX).unwrap(),
            manual_control_path(&ordinary, MANUAL_PENDING_SUFFIX).unwrap(),
            // SYSCOIN: ASCII case variants alias the same entries on default macOS/APFS volumes.
            directory.join(".job.json.manual-pick.LOCK"),
            directory.join(".job.json.manual-pick.PENDING"),
        ] {
            let error = ReservedJobPath::new(&control_path).unwrap_err();
            assert!(error.to_string().contains("reserved"));
            assert!(!control_path.exists());
        }
        fs::remove_dir_all(directory).unwrap();
    }

    // SYSCOIN: Directory entry mutation is safe only in a current-user-controlled parent; refuse
    // shared writable locations before creating a lock or changing any destination name.
    #[cfg(unix)]
    #[test]
    fn manual_pick_rejects_group_or_world_writable_parent() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = private_test_directory("unsafe-parent");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o770)).unwrap();
        let path = directory.join("job.json");
        let error = ReservedJobPath::new(&path).unwrap_err();
        assert!(error.to_string().contains("not group/world-writable"));
        assert!(!path.exists());
        assert!(!manual_control_path(&path, MANUAL_LOCK_SUFFIX)
            .unwrap()
            .exists());
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(directory).unwrap();
    }

    // SYSCOIN: Pick artifacts contain the sanitized issuing endpoint, never credentials, and an
    // endpoint mismatch is detected before a proof artifact can be opened or submitted.
    #[test]
    fn manual_job_authority_is_credential_free_and_endpoint_bound() {
        let endpoint =
            SequencerEndpoint::parse("http://manual-user:manual-secret@localhost:3124").unwrap();
        let job = FriJobInputs {
            batch_number: 7,
            vk_hash: format!("0x{}", "ab".repeat(32)),
            prover_input: vec![1, 2, 3, 4],
            lease_token: ProverLeaseToken::from(format!("0x{}", "cd".repeat(32))),
        };
        let saved = SavedFriJob {
            sequencer_endpoint: endpoint.url.as_str(),
            job: &job,
        };
        let serialized = serde_json::to_string(&saved).unwrap();
        assert!(serialized.contains("http://localhost:3124/"));
        assert!(!serialized.contains("manual-user"));
        assert!(!serialized.contains("manual-secret"));
        ensure_manual_job_endpoint("http://localhost:3124/", endpoint.url.as_str()).unwrap();
        assert!(
            ensure_manual_job_endpoint("http://localhost:4124/", endpoint.url.as_str()).is_err()
        );

        // SYSCOIN: A legacy/corrupt artifact may contain userinfo. Reject it without reflecting
        // either username or password into an operator-visible error.
        let error = ensure_manual_job_endpoint(
            "http://legacy-user:legacy-secret@localhost:3124/",
            endpoint.url.as_str(),
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(!message.contains("legacy-user"));
        assert!(!message.contains("legacy-secret"));
    }
}
