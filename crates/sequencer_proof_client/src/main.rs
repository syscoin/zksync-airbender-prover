use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::io::Read as _;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt, PermissionsExt as _};
use std::path::{Path, PathBuf};
use tracing_subscriber::{fmt, EnvFilter};
use zkos_wrapper::SnarkWrapperProof;
use zksync_sequencer_proof_client::{
    validate_canonical_endpoint_identity, FriJobInputs, L2BatchNumber, OpaqueSequencerEndpoint,
    ProofClient, ProverLeaseToken, SequencerProofClient, SnarkProofInputs,
    MAX_CANONICAL_ENDPOINT_IDENTITY_BYTES, MAX_FRI_PICK_RESPONSE_BYTES,
    MAX_PROOF_SUBMISSION_BODY_BYTES, MAX_SNARK_JOB_RESPONSE_BYTES,
};

// SYSCOIN: These wire maxima make the manual FRI artifact bound auditable without changing its
// existing flattened JSON representation.
const MAX_JSON_STRING_EXPANSION_PER_BYTE: usize = 6;
const MAX_B256_WIRE_BYTES: usize = 66;
const MAX_U32_DECIMAL_BYTES: usize = 10;
// SYSCOIN: Fixed compact-JSON syntax plus the maximum u32 and two exact B256 wire values in a
// `SavedFriJob`. The endpoint and decoded prover input are accounted for separately below.
const MAX_MANUAL_FRI_JOB_FIXED_JSON_BYTES: usize = b"{\"sequencer_endpoint\":\"".len()
    + b"\",\"batch_number\":".len()
    + MAX_U32_DECIMAL_BYTES
    + b",\"vk_hash\":\"".len()
    + MAX_B256_WIRE_BYTES
    + b"\",\"prover_input\":[".len()
    + b"],\"lease_token\":\"".len()
    + MAX_B256_WIRE_BYTES
    + b"\"}".len();

// SYSCOIN: A valid base64 field occupying at most R response bytes decodes to at most 3R/4
// bytes, and compact JSON needs at most four bytes (`255,`) per decoded byte. Thus the byte-array
// representation is bounded by 3R. Add the six-byte worst-case JSON escape for every byte of the
// already-bounded canonical endpoint and the exact fixed object overhead without changing the
// historical manual artifact format.
const fn max_manual_fri_job_artifact_bytes(max_pick_response_bytes: usize) -> usize {
    max_pick_response_bytes * 3
        + MAX_CANONICAL_ENDPOINT_IDENTITY_BYTES * MAX_JSON_STRING_EXPANSION_PER_BYTE
        + MAX_MANUAL_FRI_JOB_FIXED_JSON_BYTES
}

const MAX_MANUAL_FRI_JOB_ARTIFACT_BYTES: usize =
    max_manual_fri_job_artifact_bytes(MAX_FRI_PICK_RESPONSE_BYTES);
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

/// SYSCOIN: Reserve the final owner-only job artifact before acquiring a lease. `create_new`
/// prevents concurrent or accidental overwrite, while a crash leaves one visible artifact that
/// the operator may retire after the lease expires.
#[cfg(unix)]
#[derive(Debug)]
struct ReservedJobPath {
    path: PathBuf,
    file: File,
    parent: File,
}

#[cfg(unix)]
impl ReservedJobPath {
    fn new(path: impl AsRef<Path>) -> Result<Self> {
        let requested_path = path.as_ref();
        let file_name = requested_path
            .file_name()
            .filter(|name| !name.is_empty())
            .context("manual job destination must have a filename")?;
        let requested_parent = requested_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        // SYSCOIN: Resolve a caller-chosen alias once, then perform every authority-bearing path
        // operation below the stable canonical parent instead of reusing the alias.
        let parent_path = fs::canonicalize(requested_parent).with_context(|| {
            format!(
                "canonicalize private manual job parent {}",
                requested_parent.display()
            )
        })?;
        let parent = open_private_parent_directory(&parent_path)?;
        let path = parent_path.join(file_name);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .with_context(|| format!("reserve private manual job file {}", path.display()))?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.permissions().mode() & 0o777 == 0o600,
            "manual job destination is not a current-user-owned mode-0600 regular file"
        );
        ensure_private_parent_identity(&parent_path, &parent)?;
        file.sync_all().context("fsync reserved manual job file")?;
        parent
            .sync_all()
            .with_context(|| format!("fsync reserved manual job name {}", path.display()))?;

        Ok(Self { path, file, parent })
    }

    fn publish_json<T: Serialize>(&mut self, value: &T, maximum_bytes: usize) -> Result<()> {
        let mut bounded = BoundedWriter {
            inner: &mut self.file,
            remaining: maximum_bytes,
        };
        // SYSCOIN: A serialization or sync failure after lease acquisition deliberately leaves the
        // partial owner-only artifact in place, preventing an unnoticed second manual pick.
        serde_json::to_writer(&mut bounded, value)?;
        self.file
            .sync_all()
            .context("fsync private manual job file")?;
        Ok(())
    }

    fn remove_unleased(self) -> Result<()> {
        let Self {
            path, file, parent, ..
        } = self;
        drop(file);
        fs::remove_file(&path)
            .with_context(|| format!("remove unused manual job reservation {}", path.display()))?;
        parent
            .sync_all()
            .with_context(|| format!("fsync removed manual job reservation {}", path.display()))
    }
}

// SYSCOIN: The final reservation is the concurrency primitive, but pathname creation and fsync
// still require one stable current-user-controlled parent directory.
#[cfg(unix)]
fn open_private_parent_directory(path: &Path) -> Result<File> {
    ensure_stable_parent_ancestry(path)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let directory = options
        .open(path)
        .with_context(|| format!("open private manual job parent {}", path.display()))?;
    ensure_private_parent_identity(path, &directory)?;
    Ok(directory)
}

// SYSCOIN: Canonical parents may sit below root/current-user-owned or sticky ancestors. Refuse an
// ancestor another uid can rename now or make writable later; same-UID mutation is not a boundary.
#[cfg(unix)]
fn ensure_stable_parent_ancestry(path: &Path) -> Result<()> {
    let effective_uid = unsafe { libc::geteuid() };
    for child in path
        .ancestors()
        .take_while(|ancestor| ancestor.parent().is_some())
    {
        let parent = child.parent().expect("non-root path has a parent");
        let parent_metadata = fs::symlink_metadata(parent)?;
        let child_metadata = fs::symlink_metadata(child)?;
        anyhow::ensure!(
            parent_metadata.file_type().is_dir()
                && child_metadata.file_type().is_dir()
                && (parent_metadata.uid() == 0 || parent_metadata.uid() == effective_uid),
            "manual job parent has an untrusted or non-directory ancestor"
        );
        let mode = parent_metadata.permissions().mode();
        anyhow::ensure!(
            mode & 0o022 == 0 || (mode & 0o1000 != 0 && child_metadata.uid() == effective_uid),
            "manual job parent has a replaceable group/world-writable ancestor"
        );
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_private_parent_identity(path: &Path, directory: &File) -> Result<()> {
    let named = fs::symlink_metadata(path)
        .with_context(|| format!("inspect private manual job parent {}", path.display()))?;
    let opened = directory.metadata()?;
    anyhow::ensure!(
        named.file_type().is_dir()
            && named.dev() == opened.dev()
            && named.ino() == opened.ino()
            && opened.uid() == unsafe { libc::geteuid() }
            && opened.permissions().mode() & 0o022 == 0,
        "manual job parent must be stable, current-user-owned, and not group/world-writable"
    );
    Ok(())
}

/// SYSCOIN: Job artifacts contain bearer authority, so require an owner-only regular file and do
/// not follow a symlink. Same-UID inode/link defenses add no security boundary here.
#[cfg(unix)]
fn open_private_job_file(path: impl AsRef<Path>, maximum_bytes: usize) -> Result<File> {
    let path = path.as_ref();
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open private job file {}", path.display()))?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.permissions().mode() & 0o077 == 0
            && metadata.len() <= maximum_bytes as u64,
        "private job file must be current-user-owned, owner-only, regular, and no larger than {maximum_bytes} bytes"
    );
    Ok(file)
}

/// SYSCOIN: Read local manual artifacts under explicit CLI-only caps; production critical FRI
/// transport instead uses its advertised deployment-capacity ceiling before acquiring a lease.
fn deserialize_json_bounded<T: serde::de::DeserializeOwned>(
    file: File,
    maximum_bytes: usize,
    artifact_kind: &str,
) -> Result<T> {
    let read_limit = u64::try_from(maximum_bytes)
        .context("manual artifact size limit does not fit u64")?
        .checked_add(1)
        .context("manual artifact size limit overflow")?;
    let mut limited = file.take(read_limit);
    let mut deserializer = serde_json::Deserializer::from_reader(&mut limited);
    let value = T::deserialize(&mut deserializer)
        .with_context(|| format!("decode {artifact_kind} JSON"))?;
    deserializer
        .end()
        .with_context(|| format!("reject trailing {artifact_kind} data"))?;
    drop(deserializer);
    anyhow::ensure!(
        limited.limit() > 0,
        "{artifact_kind} exceeds {maximum_bytes} bytes"
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
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .with_context(|| format!("open manual proof artifact {}", path.display()))?;
    let opened = file.metadata()?;
    // SYSCOIN: Proof bytes contain no bearer token, but writable substitution could consume the
    // exact leased attempt; link count remains irrelevant under the same-UID threat boundary.
    #[cfg(unix)]
    anyhow::ensure!(
        opened.is_file()
            && opened.uid() == unsafe { libc::geteuid() }
            && opened.permissions().mode() & 0o022 == 0
            && opened.len() <= maximum_bytes as u64,
        "manual proof artifact must be current-user-owned, non-writable by group/other, regular, and no larger than {maximum_bytes} bytes"
    );
    #[cfg(not(unix))]
    anyhow::ensure!(
        opened.is_file() && opened.len() <= maximum_bytes as u64,
        "manual proof artifact must be a regular file no larger than {maximum_bytes} bytes"
    );
    deserialize_json_bounded(file, maximum_bytes, "manual proof artifact")
}

/// SYSCOIN: Fail closed where std cannot guarantee an owner-only capability file.
#[cfg(not(unix))]
struct ReservedJobPath {
    // SYSCOIN: Platform-independent diagnostics still type-check this field even though `new()`
    // always rejects platforms that cannot provide the required owner-only file semantics.
    path: PathBuf,
}

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

    fn remove_unleased(self) -> Result<()> {
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
    /// SYSCOIN: Canonical sequencer URL to submit proofs to; credentials remain opaque/redacted.
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
            // SYSCOIN: Reserve before the lease-changing request. Only an explicit no-job response
            // removes it; request failures retain the empty artifact because acquisition is unclear.
            let mut destination = ReservedJobPath::new(&path)?;
            tracing::info!("Picking next FRI proof job from sequencer at {}", url);
            // SYSCOIN: Any request error is acquisition-ambiguous. `?` drops only the descriptor;
            // the fsynced empty reservation remains until the operator can rule out a live lease.
            let picked = client.pick_fri_job().await.with_context(|| {
                format!(
                    "FRI pick outcome is ambiguous; reservation retained at {}",
                    destination.path.display()
                )
            })?;
            match picked {
                Some(fri_job) => {
                    // SYSCOIN: Write the endpoint-bound input and capability durably into the
                    // pre-reserved owner-only artifact without logging or group/world exposure.
                    let saved_job = SavedFriJob {
                        sequencer_endpoint: url.as_str(),
                        job: &fri_job,
                    };
                    destination.publish_json(&saved_job, MAX_MANUAL_FRI_JOB_ARTIFACT_BYTES)?;
                    tracing::info!(
                        "Picked FRI job for batch {} with vk {}, saved job to path {}",
                        fri_job.batch_number,
                        fri_job.vk_hash,
                        destination.path.display(),
                    );
                }
                None => {
                    destination.remove_unleased()?;
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
            // SYSCOIN: Reserve an owner-only destination before aggregate authority is
            // leased. Only explicit no-job removes it; every ambiguous outcome remains visible.
            let mut destination = ReservedJobPath::new(&path)?;
            tracing::info!("Picking next SNARK proof job from sequencer at {}", url);
            // SYSCOIN: A transport or post-200 decode error may follow aggregate acquisition, so
            // retain the fsynced reservation and require explicit recovery after lease expiry.
            let picked = client.pick_snark_job().await.with_context(|| {
                format!(
                    "SNARK pick outcome is ambiguous; reservation retained at {}",
                    destination.path.display()
                )
            })?;
            match picked {
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
                        "Saved SNARK job for batches [{}, {}] with vk {} to path {}",
                        snark_proof_inputs.from_batch_number,
                        snark_proof_inputs.to_batch_number,
                        snark_proof_inputs.vk_hash,
                        destination.path.display(),
                    );
                }
                None => {
                    destination.remove_unleased()?;
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
        assert!(Cli::try_parse_from([
            "proof-client",
            "--url",
            "http://localhost:3124",
            "submit-snark",
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
            path.exists(),
            "the final name reserves the pick before HTTP"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(ReservedJobPath::new(&path).is_err());
        reservation
            .publish_json(&serde_json::json!({"authority":"private"}), 1024)
            .unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(open_private_job_file(&path, 1024).is_ok());
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unused_reservation_and_bounded_artifact_rules_are_explicit() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let directory = private_test_directory("private-safety");
        let reserved = directory.join("reserved.json");
        ReservedJobPath::new(&reserved)
            .unwrap()
            .remove_unleased()
            .unwrap();
        assert!(!reserved.exists());

        // SYSCOIN: Dropping after an acquisition-ambiguous error retains the durable reservation.
        let ambiguous = directory.join("ambiguous.json");
        drop(ReservedJobPath::new(&ambiguous).unwrap());
        assert!(ambiguous.exists());

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

        // SYSCOIN: Proofs contain no lease, but writable input could consume the leased attempt
        // with substituted bytes. Link count is intentionally irrelevant; write authority is not.
        let writable_proof = directory.join("writable-proof.json");
        fs::write(&writable_proof, br#""proof""#).unwrap();
        fs::set_permissions(&writable_proof, fs::Permissions::from_mode(0o622)).unwrap();
        assert!(deserialize_proof_bounded::<String>(&writable_proof, 1024).is_err());
        fs::set_permissions(&writable_proof, fs::Permissions::from_mode(0o600)).unwrap();
        let proof_alias = directory.join("proof-alias.json");
        fs::hard_link(&writable_proof, &proof_alias).unwrap();
        assert_eq!(
            deserialize_proof_bounded::<String>(&writable_proof, 1024).unwrap(),
            "proof"
        );

        // SYSCOIN: A syntactically valid prefix cannot bypass the full-file allocation cap.
        let oversized_proof = directory.join("oversized-proof.json");
        fs::write(&oversized_proof, br#""proof" trailing"#).unwrap();
        assert!(deserialize_proof_bounded::<String>(&oversized_proof, 7).is_err());
        fs::write(&oversized_proof, b"\"proof\" ").unwrap();
        assert!(deserialize_json_bounded::<String>(
            File::open(&oversized_proof).unwrap(),
            7,
            "test proof"
        )
        .is_err());

        let oversized_job = directory.join("oversized-job.json");
        let mut reservation = ReservedJobPath::new(&oversized_job).unwrap();
        assert!(reservation
            .publish_json(&"decoded-job-expansion", 8)
            .is_err());
        drop(reservation);
        assert!(oversized_job.exists());
        assert!(ReservedJobPath::new(&oversized_job).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    // SYSCOIN: Exercise a strict superset of every accepted FRI pick at a scaled response cap:
    // every response byte is treated as base64 payload, every decoded byte takes its widest JSON
    // representation, and every endpoint byte takes its widest JSON escape. The derived cap must
    // admit this representation while the immediately smaller writer bound still rejects it.
    #[test]
    fn fri_job_artifact_cap_covers_worst_case_decoded_json_expansion() {
        const SCALED_PICK_RESPONSE_BYTES: usize = 4 * 1024;
        const MAX_SCALED_DECODED_BYTES: usize = SCALED_PICK_RESPONSE_BYTES * 3 / 4;

        let endpoint = "\0".repeat(MAX_CANONICAL_ENDPOINT_IDENTITY_BYTES);
        let job = FriJobInputs {
            batch_number: u32::MAX,
            vk_hash: format!("0x{}", "f".repeat(64)),
            prover_input: vec![u8::MAX; MAX_SCALED_DECODED_BYTES],
            lease_token: ProverLeaseToken::from(format!("0x{}", "f".repeat(64))),
        };
        let saved = SavedFriJob {
            sequencer_endpoint: &endpoint,
            job: &job,
        };
        let serialized = serde_json::to_vec(&saved).unwrap();
        let derived_cap = max_manual_fri_job_artifact_bytes(SCALED_PICK_RESPONSE_BYTES);

        // Each 255 contributes `255,` except the final byte, so the constructed strict upper-bound
        // representation is exactly one byte below the inclusive mathematical cap.
        assert_eq!(serialized.len() + 1, derived_cap);

        let mut rejected = Vec::new();
        assert!(serde_json::to_writer(
            &mut BoundedWriter {
                inner: &mut rejected,
                remaining: serialized.len() - 1,
            },
            &saved,
        )
        .is_err());

        let mut accepted = Vec::new();
        serde_json::to_writer(
            &mut BoundedWriter {
                inner: &mut accepted,
                remaining: derived_cap,
            },
            &saved,
        )
        .unwrap();
        assert_eq!(accepted, serialized);
        assert_eq!(
            MAX_MANUAL_FRI_JOB_ARTIFACT_BYTES,
            max_manual_fri_job_artifact_bytes(MAX_FRI_PICK_RESPONSE_BYTES)
        );
    }

    #[cfg(unix)]
    #[test]
    fn reservation_rejects_unsafe_parent_and_resolves_safe_parent_alias_once() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let directory = private_test_directory("unsafe-parent");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o770)).unwrap();
        let unsafe_path = directory.join("job.json");
        let error = ReservedJobPath::new(&unsafe_path).unwrap_err();
        assert!(error.to_string().contains("not group/world-writable"));
        assert!(!unsafe_path.exists());
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();

        let alias = directory.with_file_name(format!(
            "{}-alias",
            directory.file_name().unwrap().to_string_lossy()
        ));
        symlink(&directory, &alias).unwrap();
        let aliased_path = alias.join("job.json");
        let reservation = ReservedJobPath::new(&aliased_path).unwrap();
        assert!(directory.join("job.json").exists());
        reservation.remove_unleased().unwrap();
        assert!(!directory.join("job.json").exists());
        fs::remove_file(alias).unwrap();
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
