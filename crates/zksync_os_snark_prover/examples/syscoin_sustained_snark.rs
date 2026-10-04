//! Offline sustained SNARK diagnostic using the unchanged production run_inner path.
//! One combiner and Warm/Bundled wrapper host cache survive across unique ranges.
//! No network, live lease, queue mutation, settlement, or release qualification.
//! Every saved wrapper proof still requires independent post-run verification.
use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Parser;
use protocol_version::SupportedProtocolVersions;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use url::Url;
use zkos_wrapper::SnarkWrapperProof;
use zksync_airbender_cli::prover_utils::{
    ProofArtifact, ProofTarget, ProverBackend, SecurityLevel,
};
use zksync_airbender_execution_utils::unified_circuit::compute_combined_recursion_layers_output;
use zksync_airbender_execution_utils::unrolled::UnrolledProgramProof;
use zksync_os_snark_prover::{
    create_combiner, init_tracing, run_inner, BinaryCommitmentPolicy, WrapperCachePolicy,
    WrapperSource,
};
use zksync_sequencer_proof_client::{
    FriJobInputs, JobQueueStage, L2BatchNumber, ProofClient, ProofRunOutcome, ProverLeaseToken,
    QueueJobStatus, SnarkProofInputs, MAX_FRIS_PER_SNARK_JOB, MAX_PROOF_SUBMISSION_BODY_BYTES,
    MAX_SNARK_JOB_RESPONSE_BYTES,
};

const BIN_SHA: &str = "0d69bb7bc5207041c737def52d8858bab261b2ccf0afadbf2ceed14aa86d7cf6";
const TEXT_SHA: &str = "9d999d91bc7422488c58cf6ca1f7f5041c2972065592ffe98bfcb8220ff0009a";
const PROGRAM: &str = "0x05c969ad8fcf8870cbb064c2947101ae27a5152c64467dcd7641f880485131de";
const VK: &str = "0xd5bc91a7af04425e93a92ad4e29f4f9ab62210087b5dea105d6bb579f1218139";
// Exact canonical GPU CRS in docker/prover-build-pins.json; never use CPU CRS here.
const CRS_BYTES: u64 = 4_831_838_468;
const CRS_SHA: &str = "90d1dea94da665d5741dcc6e9ffc1af23a29669f950a6d599a6ccfee4cfb81bd";
const SNARK_N: usize = 33_554_431;
const MAX_JSON: usize = 1024 * 1024;
const MAX_RECEIPTS: usize = 128 * MAX_JSON;
const MAX_PROOF: usize = 32 * MAX_JSON;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    manifest_sha256: String,
    #[arg(long)]
    fri_receipts: PathBuf,
    #[arg(long)]
    fri_receipts_sha256: String,
    /// Trusted independent CPU verification for this circuit/program identity;
    /// historical old-source verification receipts are not interchangeable.
    #[arg(long)]
    fri_verification: PathBuf,
    #[arg(long)]
    fri_verification_sha256: String,
    #[arg(long)]
    proof_dir: PathBuf,
    #[arg(long)]
    bin: PathBuf,
    #[arg(long)]
    text: PathBuf,
    /// Fixed chunk size; a final singleton is rejected, never duplicated or skipped.
    #[arg(long)]
    range_size: usize,
    /// Authenticate inputs only; do not initialize proving or create output.
    #[arg(long)]
    preflight_only: bool,
    #[arg(long)]
    trusted_setup_file: Option<PathBuf>,
    /// Must not exist; partial runs are retained and cannot be resumed/overwritten.
    #[arg(long)]
    output_dir: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    batches: Vec<Batch>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Batch {
    batch_id: u64,
    metadata: PathBuf,
    metadata_sha256: String,
    input: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    schema_version: u32,
    app_bin_sha256: String,
    app_text_sha256: String,
    prover_input_sha256: String,
    prover_input_words: u64,
    batch_id: u64,
    expected_public_input_hash: String,
    expected_security100_program_commitment: String,
    context: serde_json::Map<String, Value>,
}

struct Job {
    batch: Batch,
    metadata: Metadata,
    receipt: Value,
    expected: [u32; 16],
    canonical: Value,
}

fn sha(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}

fn hash(value: &str, prefix: bool) -> Result<[u8; 32]> {
    let value = if prefix {
        value.strip_prefix("0x").context("0x prefix required")?
    } else {
        value
    };
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "canonical lowercase 32-byte hash required"
    );
    let mut result = [0; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(result)
}

fn relative(path: &Path) -> Result<()> {
    let text = path.to_str().context("non-UTF8 relative path")?;
    ensure!(
        !text.is_empty()
            && path.components().all(|c| matches!(c, Component::Normal(_)))
            && text
                .split('/')
                .all(|p| !p.is_empty() && p != "." && p != ".."),
        "noncanonical relative path"
    );
    Ok(())
}

fn read_bound(path: &Path, digest: &str, limit: usize) -> Result<Vec<u8>> {
    hash(digest, false)?;
    ensure!(
        fs::symlink_metadata(path)?.is_file(),
        "regular non-symlink input required"
    );
    let file = File::open(path)?;
    let info = file.metadata()?;
    ensure!(
        info.is_file() && info.len() > 0 && info.len() <= limit as u64,
        "input exceeds size bound"
    );
    let mut raw = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut raw)?;
    ensure!(
        raw.len() <= limit && sha(&raw) == digest,
        "input size/SHA mismatch: {}",
        path.display()
    );
    Ok(raw)
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("missing/non-string {key}"))
}

fn number(value: &Value, key: &str) -> Result<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .with_context(|| format!("missing/non-u64 {key}"))
}

fn metadata_outputs(metadata: &Metadata) -> Result<[u32; 16]> {
    ensure!(
        metadata.schema_version == 1
            && metadata.batch_id > 0
            && metadata.batch_id <= u32::MAX as u64
            && metadata.app_bin_sha256 == BIN_SHA
            && metadata.app_text_sha256 == TEXT_SHA
            && metadata.expected_security100_program_commitment == PROGRAM
            && (1..=384 * 1024 * 1024 / 4).contains(&metadata.prover_input_words),
        "metadata identity mismatch"
    );
    hash(&metadata.prover_input_sha256, false)?;
    ensure!(
        metadata.context.get("protocol_version") == Some(&json!("0.32.0"))
            && metadata.context.get("execution_version") == Some(&json!(7))
            && metadata.context.get("proving_version") == Some(&json!(8))
            && metadata.context.get("batch_number") == Some(&json!(metadata.batch_id)),
        "wrong V32/V8 context"
    );
    let context = Value::Object(metadata.context.clone());
    ensure!(
        number(&context, "chain_id")? > 0 && number(&context, "settlement_layer_chain_id")? > 0,
        "zero chain identity"
    );
    let first = number(&context, "first_block_number")?;
    ensure!(
        first > 0 && first <= number(&context, "last_block_number")?,
        "invalid block range"
    );
    for key in ["state_before", "state_after", "chain_config_hash"] {
        hash(string(&context, key)?, true)?;
    }
    let target = string(&context, "compact_edge_da_commit_target")?;
    ensure!(
        target.len() == 42
            && target.starts_with("0x")
            && target[2..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid DA target"
    );
    let public = hash(&metadata.expected_public_input_hash, true)?;
    let program = hash(PROGRAM, true)?;
    let mut result = [0; 16];
    for i in 0..8 {
        result[i] = u32::from_le_bytes(public[4 * i..4 * i + 4].try_into().unwrap());
        result[8 + i] = u32::from_be_bytes(program[4 * i..4 * i + 4].try_into().unwrap());
    }
    Ok(result)
}

/// V3 generator exports these exact canonical server artifacts. Their byte hashes
/// are already bound by trusted metadata; checking the shared fields prevents a
/// structurally valid proof cohort from being mislabeled as different native work.
fn canonical_batch_files(metadata: &Metadata, metadata_path: &Path) -> Result<Value> {
    let context = Value::Object(metadata.context.clone());
    let root = metadata_path.parent().context("metadata parent missing")?;
    let mut values = Vec::new();
    for (file_key, hash_key, expected_name) in [
        ("batch_info_file", "batch_info_sha256", "batch-info.json"),
        (
            "batch_metadata_message_file",
            "batch_metadata_message_sha256",
            "batch-metadata-message.json",
        ),
    ] {
        ensure!(
            string(&context, file_key)? == expected_name,
            "unexpected canonical artifact name"
        );
        values.push(serde_json::from_slice::<Value>(&read_bound(
            &root.join(expected_name),
            string(&context, hash_key)?,
            MAX_JSON,
        )?)?);
    }
    let info = &values[0];
    let message = &values[1];
    check_canonical_fields(metadata, info, message)?;
    ensure!(
        string(&context, "canonical_pubdata_file")? == "pubdata.bin",
        "unexpected pubdata artifact name"
    );
    let pubdata = read_bound(
        &root.join("pubdata.bin"),
        string(&context, "canonical_pubdata_sha256")?,
        64 * MAX_JSON,
    )?;
    ensure!(
        pubdata.len() as u64 == number(&context, "canonical_pubdata_bytes")?,
        "canonical pubdata byte count mismatch"
    );
    Ok(json!({"batch_info_sha256":context["batch_info_sha256"],
        "batch_metadata_message_sha256":context["batch_metadata_message_sha256"],
        "canonical_pubdata_sha256":context["canonical_pubdata_sha256"],
        "canonical_pubdata_bytes":pubdata.len(), "chain_address":message["chain_address"]}))
}

fn check_canonical_fields(metadata: &Metadata, info: &Value, message: &Value) -> Result<()> {
    let context = Value::Object(metadata.context.clone());
    ensure!(
        message["commit_batch_info"] == *info
            && info["batch_number"] == metadata.batch_id
            && info["protocol_version"] == "0.32.0"
            && info["chain_id"] == context["chain_id"]
            && info["sl_chain_id"] == context["settlement_layer_chain_id"]
            && info["new_state_commitment"] == context["state_after"]
            && info["first_block_number"] == context["first_block_number"]
            && info["last_block_number"] == context["last_block_number"]
            && message["first_block_number"] == context["first_block_number"]
            && message["last_block_number"] == context["last_block_number"]
            && message["previous_stored_batch_info"]["state_commitment"] == context["state_before"]
            && number(&message["previous_stored_batch_info"], "batch_number")?.checked_add(1)
                == Some(metadata.batch_id)
            && message["pubdata_mode"] == "Blobs"
            && context["pubdata_mode"] == "Blobs",
        "canonical BatchMetadata domain/state/range mismatch"
    );
    let count = number(info, "number_of_layer1_txs")?
        .checked_add(number(info, "number_of_layer2_txs")?)
        .context("canonical transaction overflow")?;
    ensure!(
        count == number(&context, "transaction_count")? && count == number(message, "tx_count")?,
        "canonical transaction count mismatch"
    );
    let address = string(message, "chain_address")?;
    ensure!(
        address.len() == 42
            && address.starts_with("0x")
            && address[2..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid canonical chain address"
    );
    Ok(())
}

fn parse_manifest(raw: &[u8], range_size: usize) -> Result<Manifest> {
    let manifest: Manifest = serde_json::from_slice(raw)?;
    ensure!(
        manifest.schema_version == 1 && (2..=1000).contains(&manifest.batches.len()),
        "expected 2..1000 batches"
    );
    ensure!(
        (2..=MAX_FRIS_PER_SNARK_JOB).contains(&range_size)
            && manifest.batches.len() % range_size != 1,
        "invalid range size or final singleton"
    );
    let mut previous: Option<u64> = None;
    let mut paths = HashSet::new();
    for batch in &manifest.batches {
        ensure!(
            batch.batch_id > 0 && batch.batch_id <= u32::MAX as u64,
            "invalid batch ID"
        );
        if let Some(last) = previous {
            ensure!(
                Some(batch.batch_id) == last.checked_add(1),
                "noncontiguous batch IDs"
            );
        }
        previous = Some(batch.batch_id);
        hash(&batch.metadata_sha256, false)?;
        for path in [&batch.metadata, &batch.input] {
            relative(path)?;
            ensure!(paths.insert(path), "duplicate path");
        }
    }
    Ok(manifest)
}

fn load_jobs(args: &Args) -> Result<Vec<Job>> {
    let manifest = parse_manifest(
        &read_bound(&args.manifest, &args.manifest_sha256, MAX_JSON)?,
        args.range_size,
    )?;
    let raw = read_bound(&args.fri_receipts, &args.fri_receipts_sha256, MAX_RECEIPTS)?;
    ensure!(
        raw.last() == Some(&b'\n'),
        "receipts lack complete final newline"
    );
    let receipts: Vec<Value> = raw[..raw.len() - 1]
        .split(|b| *b == b'\n')
        .map(serde_json::from_slice)
        .collect::<std::result::Result<_, _>>()?;
    ensure!(
        receipts.len() == manifest.batches.len(),
        "receipt count mismatch"
    );
    let verified: Value = serde_json::from_slice(&read_bound(
        &args.fri_verification,
        &args.fri_verification_sha256,
        MAX_JSON,
    )?)?;
    ensure!(
        verified["schema"] == "syscoin-sustained-fri-independent-cpu-verification-v1"
            && verified["all_proofs_verified"] == true
            && verified["proof_count"] == manifest.batches.len()
            && verified["from_batch_number"] == manifest.batches[0].batch_id
            && verified["to_batch_number"] == manifest.batches.last().unwrap().batch_id
            && verified["manifest_sha256"] == args.manifest_sha256
            && verified["receipts_sha256"] == args.fri_receipts_sha256
            && verified["program_commitment"] == PROGRAM
            && verified["security_level"] == 100
            && verified["target"] == "recursion-unified"
            && verified["gpu_enabled"] == false
            && verified["cached_setup_artifact_read"] == false,
        "independent CPU verification does not bind this cohort"
    );
    for key in [
        "flipped_register_10_bit0_rejected",
        "wrong_program_keccak_rejected",
        "wrong_security80_rejected",
    ] {
        ensure!(
            verified["negative_controls"][key] == true,
            "missing independent negative control"
        );
    }
    let root = args.manifest.parent().context("manifest parent missing")?;
    let mut jobs: Vec<Job> = Vec::new();
    let mut input_hashes = HashSet::new();
    let mut proof_hashes = HashSet::new();
    let mut proof_paths = HashSet::new();
    let mut transaction_hashes = HashSet::new();
    let mut metadata_bytes = 0usize;
    for (index, (batch, receipt)) in manifest.batches.into_iter().zip(receipts).enumerate() {
        let raw = read_bound(
            &root.join(&batch.metadata),
            &batch.metadata_sha256,
            MAX_JSON,
        )?;
        metadata_bytes = metadata_bytes
            .checked_add(raw.len())
            .context("metadata size overflow")?;
        ensure!(
            metadata_bytes <= 64 * MAX_JSON,
            "cohort metadata exceeds 64MiB"
        );
        let metadata: Metadata = serde_json::from_slice(&raw)?;
        let expected = metadata_outputs(&metadata)?;
        let canonical = canonical_batch_files(&metadata, &root.join(&batch.metadata))?;
        ensure!(
            metadata.batch_id == batch.batch_id
                && input_hashes.insert(metadata.prover_input_sha256.clone()),
            "duplicate witness or wrong batch"
        );
        ensure!(
            receipt["schema_version"] == 1
                && receipt["status"] == "generated_pending_independent_verification"
                && receipt["index"] == index
                && receipt["batch_id"] == batch.batch_id
                && receipt["metadata_sha256"] == batch.metadata_sha256
                && receipt["prover_input_sha256"] == metadata.prover_input_sha256
                && receipt["expected_public_input_hash"] == metadata.expected_public_input_hash
                && receipt["expected_security100_program_commitment"] == PROGRAM,
            "FRI receipt binding mismatch"
        );
        let proof_hash = string(&receipt, "proof_sha256")?;
        hash(proof_hash, false)?;
        let proof_path = Path::new(string(&receipt, "proof_file")?);
        relative(proof_path)?;
        ensure!(
            proof_hashes.insert(proof_hash.to_owned())
                && proof_paths.insert(proof_path.to_owned())
                && (1..=MAX_PROOF as u64).contains(&number(&receipt, "proof_bytes")?),
            "duplicate/oversized proof"
        );
        let context = Value::Object(metadata.context.clone());
        let transactions = number(&context, "transaction_count")?;
        let benchmark = &context["benchmark"];
        let hashes = benchmark["transaction_hashes"]
            .as_array()
            .context("missing transaction hashes")?;
        let total = number(benchmark, "successful_transactions")?
            .checked_add(number(benchmark, "reverted_transactions")?)
            .and_then(|n| n.checked_add(benchmark["system_transactions"].as_u64()?))
            .context("transaction count overflow")?;
        ensure!(
            transactions > 0 && transactions == hashes.len() as u64 && transactions == total,
            "transaction count mismatch"
        );
        for value in hashes {
            let value = value.as_str().context("non-string transaction hash")?;
            hash(value, true)?;
            ensure!(
                transaction_hashes.insert(value.to_owned()),
                "duplicate transaction"
            );
        }
        number(benchmark, "gas_used")?;
        if let Some(first) = jobs.first() {
            ensure!(
                canonical["chain_address"] == first.canonical["chain_address"],
                "canonical chain address changes"
            );
            for key in [
                "chain_id",
                "settlement_layer_chain_id",
                "chain_config_hash",
                "compact_edge_da_commit_target",
            ] {
                ensure!(
                    metadata.context.get(key) == first.metadata.context.get(key),
                    "domain changes within cohort"
                );
            }
        }
        if let Some(last) = jobs.last() {
            ensure!(
                last.metadata.context.get("state_after") == metadata.context.get("state_before"),
                "broken state-root chain"
            );
            let last_context = Value::Object(last.metadata.context.clone());
            ensure!(
                number(&last_context, "last_block_number")?.checked_add(1)
                    == Some(number(&context, "first_block_number")?),
                "broken block sequence"
            );
        }
        jobs.push(Job {
            batch,
            metadata,
            receipt,
            expected,
            canonical,
        });
    }
    Ok(jobs)
}

/// Wrapper check_aux_params takes 28 statement bytes, packs four big-endian 56-bit
/// public inputs, then the SNARK wrapper concatenates them into one 224-bit scalar.
fn expected_snark_input(outputs: &[[u32; 16]]) -> Result<[[u64; 4]; 1]> {
    ensure!(
        (2..=MAX_FRIS_PER_SNARK_JOB).contains(&outputs.len()),
        "invalid range length"
    );
    ensure!(
        outputs.iter().all(|v| v[8..] == outputs[0][8..]),
        "mismatched program commitments"
    );
    let combined = compute_combined_recursion_layers_output(outputs);
    let mut big = [0u8; 32];
    for (index, word) in combined[..7].iter().enumerate() {
        big[4 + index * 4..8 + index * 4].copy_from_slice(&word.to_le_bytes());
    }
    Ok([std::array::from_fn(|index| {
        u64::from_be_bytes(big[24 - index * 8..32 - index * 8].try_into().unwrap())
    })])
}

fn range_wire_size(lengths: &[usize], from: u64, to: u64) -> Result<(usize, usize)> {
    ensure!(
        !lengths.is_empty() && lengths.len() <= MAX_FRIS_PER_SNARK_JOB,
        "invalid proof count"
    );
    // Same compact JSON envelope as GetSnarkProofPayload. Base64 is ASCII and
    // never JSON-escaped, so empty strings plus their exact lengths is exact.
    let overhead = serde_json::to_vec(&json!({
        "from_batch_number":from, "to_batch_number":to, "vk_hash":VK,
        "fri_proofs":vec![""; lengths.len()], "lease_token":format!("0x{}", "0".repeat(64))
    }))?
    .len();
    let mut raw_total = 0usize;
    let mut wire_total = overhead;
    for length in lengths {
        ensure!(
            (1..=MAX_PROOF_SUBMISSION_BODY_BYTES).contains(length),
            "individual FRI exceeds raw bound"
        );
        let base64 = length
            .checked_add(2)
            .and_then(|n| (n / 3).checked_mul(4))
            .context("base64 size overflow")?;
        ensure!(
            base64 <= MAX_PROOF_SUBMISSION_BODY_BYTES,
            "individual FRI exceeds encoded bound"
        );
        raw_total = raw_total
            .checked_add(*length)
            .context("raw proof size overflow")?;
        wire_total = wire_total
            .checked_add(base64)
            .context("aggregate JSON size overflow")?;
    }
    ensure!(
        wire_total <= MAX_SNARK_JOB_RESPONSE_BYTES,
        "range exceeds production aggregate response bound"
    );
    Ok((raw_total, wire_total))
}

fn load_range(
    jobs: &[Job],
    proof_root: &Path,
) -> Result<(Vec<UnrolledProgramProof>, usize, usize)> {
    let mut result = Vec::with_capacity(jobs.len());
    let mut lengths = Vec::with_capacity(jobs.len());
    for job in jobs {
        let raw = read_bound(
            &proof_root.join(string(&job.receipt, "proof_file")?),
            string(&job.receipt, "proof_sha256")?,
            MAX_PROOF,
        )?;
        ensure!(
            raw.len() as u64 == number(&job.receipt, "proof_bytes")?,
            "proof length mismatch"
        );
        let artifact: ProofArtifact = serde_json::from_slice(&raw)?;
        ensure!(
            artifact.schema_version == 1
                && artifact.batch_id == job.batch.batch_id
                && artifact.security_level == SecurityLevel::Security100
                && artifact.target == ProofTarget::RecursionUnified
                && artifact.backend == ProverBackend::Gpu,
            "FRI artifact identity mismatch"
        );
        for index in 0..8 {
            ensure!(
                artifact.proof.register_final_values[10 + index].value == job.expected[index],
                "FRI statement mismatch"
            );
        }
        let encoded = bincode::serde::encode_to_vec(&artifact.proof, bincode::config::standard())?;
        lengths.push(encoded.len());
        range_wire_size(
            &lengths,
            jobs[0].batch.batch_id,
            jobs.last().unwrap().batch.batch_id,
        )?;
        result.push(artifact.proof);
    }
    let (raw_bytes, wire_bytes) = range_wire_size(
        &lengths,
        jobs[0].batch.batch_id,
        jobs.last().unwrap().batch.batch_id,
    )?;
    Ok((result, raw_bytes, wire_bytes))
}

fn new_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}
fn write_new(path: &Path, raw: &[u8]) -> Result<()> {
    let mut file = new_file(path)?;
    file.write_all(raw)?;
    file.sync_all()?;
    File::open(path.parent().context("output parent missing")?)?.sync_all()?;
    Ok(())
}

fn read_generated(path: &Path) -> Result<Vec<u8>> {
    ensure!(
        fs::symlink_metadata(path)?.is_file(),
        "generated artifact is not a regular file"
    );
    let file = File::open(path)?;
    ensure!(
        file.metadata()?.len() <= MAX_PROOF as u64,
        "generated artifact exceeds bound"
    );
    let mut bytes = Vec::new();
    file.take(MAX_PROOF as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_PROOF,
        "generated artifact size mismatch"
    );
    Ok(bytes)
}
fn directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .context("fresh output directory required")?;
    File::open(path.parent().context("output parent missing")?)?.sync_all()?;
    Ok(())
}
fn unix_ms() -> Result<u128> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
}

struct CrsIdentity {
    length: u64,
    modified: SystemTime,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    changed: (i64, i64),
}
impl CrsIdentity {
    fn capture(path: &Path) -> Result<Self> {
        let info = fs::symlink_metadata(path)?;
        ensure!(
            info.is_file() && info.len() == CRS_BYTES,
            "noncanonical GPU CRS file"
        );
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        Ok(Self {
            length: info.len(),
            modified: info.modified()?,
            #[cfg(unix)]
            device: info.dev(),
            #[cfg(unix)]
            inode: info.ino(),
            #[cfg(unix)]
            changed: (info.ctime(), info.ctime_nsec()),
        })
    }
    fn check(&self, path: &Path) -> Result<()> {
        let now = Self::capture(path)?;
        ensure!(
            self.length == now.length && self.modified == now.modified,
            "CRS file changed"
        );
        #[cfg(unix)]
        ensure!(
            self.device == now.device && self.inode == now.inode && self.changed == now.changed,
            "CRS file replaced"
        );
        Ok(())
    }
}
fn authenticate_crs(path: &Path) -> Result<CrsIdentity> {
    let identity = CrsIdentity::capture(path)?;
    let mut input = File::open(path)?.take(CRS_BYTES + 1);
    let mut digest = Sha256::new();
    let mut buffer = vec![0; MAX_JSON];
    let mut size = 0u64;
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size += count as u64;
        digest.update(&buffer[..count]);
    }
    ensure!(
        size == CRS_BYTES && format!("{:x}", digest.finalize()) == CRS_SHA,
        "canonical GPU CRS SHA mismatch"
    );
    identity.check(path)?;
    Ok(identity)
}

struct OfflineClient {
    url: Url,
    input: Mutex<Option<SnarkProofInputs>>,
    token: ProverLeaseToken,
    from: u32,
    to: u32,
    expected: [[u64; 4]; 1],
    output: PathBuf,
    evidence: Value,
    submitted: AtomicBool,
}

#[derive(Serialize)]
struct SubmissionBody<'a> {
    from_batch_number: u64,
    to_batch_number: u64,
    vk_hash: &'a str,
    proof: &'a str,
    lease_token: &'a ProverLeaseToken,
}

fn submission_body(from: u64, to: u64, encoded: &str, token: &ProverLeaseToken) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(&SubmissionBody {
        from_batch_number: from,
        to_batch_number: to,
        vk_hash: VK,
        proof: encoded,
        lease_token: token,
    })?;
    ensure!(
        body.len() <= MAX_PROOF_SUBMISSION_BODY_BYTES,
        "SNARK exceeds production submission body bound"
    );
    Ok(body)
}
#[async_trait]
impl ProofClient for OfflineClient {
    fn sequencer_url(&self) -> &Url {
        &self.url
    }
    async fn pick_fri_job(&self) -> Result<Option<FriJobInputs>> {
        anyhow::bail!("offline SNARK client has no FRI jobs")
    }
    async fn submit_fri_proof(
        &self,
        _: u32,
        _: String,
        _: String,
        _: ProverLeaseToken,
    ) -> Result<()> {
        anyhow::bail!("offline SNARK client cannot submit FRI")
    }
    async fn status(&self, _: JobQueueStage) -> Result<Vec<QueueJobStatus>> {
        Ok(Vec::new())
    }
    async fn pick_snark_job(&self) -> Result<Option<SnarkProofInputs>> {
        Ok(Some(
            self.input
                .lock()
                .map_err(|_| anyhow::anyhow!("input mutex poisoned"))?
                .take()
                .context("offline input already consumed")?,
        ))
    }
    async fn submit_snark_proof(
        &self,
        from: L2BatchNumber,
        to: L2BatchNumber,
        vk: String,
        proof: SnarkWrapperProof,
        token: ProverLeaseToken,
    ) -> Result<()> {
        ensure!(
            from.0 == self.from && to.0 == self.to && vk == VK && token == self.token,
            "offline exact-range binding mismatch"
        );
        ensure!(
            proof.n == SNARK_N && serde_json::to_value(&proof.inputs)? == json!(self.expected),
            "SNARK domain/public input mismatch"
        );
        // Identical pure serialization to SequencerProofClient::serialize_snark_proof,
        // followed by the exact durable-submission JSON body. No journal or request.
        let (_, words) = crypto_codegen::serialize_proof(&proof);
        let native: Vec<u8> = words
            .iter()
            .flat_map(|word| {
                let mut bytes = [0; 32];
                word.to_big_endian(&mut bytes);
                bytes
            })
            .collect();
        let body = submission_body(
            u64::from(from.0),
            u64::from(to.0),
            &STANDARD.encode(&native),
            &token,
        )?;
        let wire = json!({"native_proof_bytes":native.len(), "submission_body_bytes":body.len(),
            "submission_body_sha256":sha(&body), "synthetic_offline_token":true, "journal_created":false});
        ensure!(
            !self.submitted.swap(true, Ordering::AcqRel),
            "duplicate offline submission"
        );
        let record = serde_json::to_vec_pretty(&json!({
                "schema": "syscoin-sustained-snark-proof-v1", "status": "generated_and_internally_verified_pending_independent_verification",
                "from_batch_number": self.from, "to_batch_number": self.to, "vk_hash": VK, "security_level": 100,
                "zk_enabled": true, "expected_public_inputs": self.expected, "n": proof.n, "input_evidence": self.evidence,
                "fri_verification": "CarriedChainCombiner verifies every input FRI", "snark_verification": "production prove_snark verifies before returning",
            "network_used": false, "live_claim_used": false, "live_submission_used": false, "production_wire":wire,"proof": proof,
        }))?;
        ensure!(record.len() <= MAX_PROOF, "SNARK record exceeds bound");
        write_new(&self.output, &record)
    }
}

async fn run(args: Args) -> Result<()> {
    let started = Instant::now();
    let started_unix_ms = unix_ms()?;
    for path in [
        &args.manifest,
        &args.fri_receipts,
        &args.fri_verification,
        &args.proof_dir,
        &args.bin,
        &args.text,
    ] {
        ensure!(path.is_absolute(), "absolute paths required");
    }
    let jobs = load_jobs(&args)?;
    let bin = read_bound(&args.bin, BIN_SHA, 64 * MAX_JSON)?;
    let text = read_bound(&args.text, TEXT_SHA, 64 * MAX_JSON)?;
    let versions = SupportedProtocolVersions::default();
    versions
        .ensure_syscoin_release_constants()
        .map_err(anyhow::Error::msg)?;
    ensure!(
        versions.vk_hashes() == [VK.to_owned()]
            && versions
                .program_commitment_for(VK)
                .map(|v| v.to_string())
                .as_deref()
                == Some(PROGRAM),
        "registry mismatch"
    );
    // Authenticate and decode one range at a time; retain no proof cohort in memory.
    for range in jobs.chunks(args.range_size) {
        expected_snark_input(&range.iter().map(|j| j.expected).collect::<Vec<_>>())?;
        drop(load_range(range, &args.proof_dir)?);
    }
    let preflight_ms = started.elapsed().as_millis();
    if args.preflight_only {
        ensure!(
            args.output_dir.is_none() && args.trusted_setup_file.is_none(),
            "preflight cannot accept output/CRS arguments"
        );
        println!(
            "{}",
            json!({"status":"authenticated_and_decoded_only", "batch_count":jobs.len(), "range_size":args.range_size,
            "range_count":jobs.chunks(args.range_size).len(), "preflight_ms":preflight_ms, "heavy_setup_started":false, "network_used":false})
        );
        return Ok(());
    }
    ensure!(
        cfg!(feature = "gpu"),
        "full diagnostic requires a GPU build"
    );
    let output = args.output_dir.as_ref().context("output-dir required")?;
    let crs = args
        .trusted_setup_file
        .as_ref()
        .context("trusted-setup-file required")?;
    ensure!(
        output.is_absolute() && crs.is_absolute(),
        "absolute output/CRS paths required"
    );
    let crs_start = Instant::now();
    let crs_identity = authenticate_crs(crs)?;
    let crs_auth_ms = crs_start.elapsed().as_millis();
    directory(output)?;
    let app = output.join("authenticated-app.bin");
    write_new(&app, &bin)?;
    write_new(&app.with_extension("text"), &text)?;
    drop((bin, text));
    write_new(
        &output.join("INPUTS.json"),
        &serde_json::to_vec_pretty(&json!({
            "schema":"syscoin-sustained-snark-inputs-v1", "started_unix_ms":started_unix_ms,
            "manifest":args.manifest, "manifest_sha256":args.manifest_sha256,
            "fri_receipts":args.fri_receipts, "fri_receipts_sha256":args.fri_receipts_sha256,
            "fri_verification":args.fri_verification, "fri_verification_sha256":args.fri_verification_sha256,
            "proof_directory":args.proof_dir, "app_bin_sha256":BIN_SHA, "app_text_sha256":TEXT_SHA,
            "crs":crs, "crs_bytes":CRS_BYTES, "crs_sha256":CRS_SHA, "crs_auth_ms":crs_auth_ms,
            "range_size":args.range_size, "batch_count":jobs.len(), "preflight_ms":preflight_ms,
            "wrapper_cache_policy":"warm", "binary_commitment_policy":"bundled", "zk_enabled":true,
            "network_used":false, "live_claim_used":false, "live_submission_used":false,
            "qualification":"Offline stage benchmark only; not pipeline, queue, settlement, or release qualification. Independent SNARK verification required."
        }))?,
    )?;
    let setup_start = Instant::now();
    let mut wrapper = WrapperSource::new_validated_with_policies(
        crs.to_str().context("non-UTF8 CRS")?.to_owned(),
        app.clone(),
        &versions,
        WrapperCachePolicy::Warm,
        BinaryCommitmentPolicy::Bundled,
    )?;
    let wrapper_setup_ms = setup_start.elapsed().as_millis();
    let combiner_start = Instant::now();
    let mut combiner = create_combiner();
    combiner.warm_up();
    let combiner_setup_ms = combiner_start.elapsed().as_millis();
    let setup_ms = setup_start.elapsed().as_millis();
    write_new(
        &output.join("STARTED.json"),
        &serde_json::to_vec_pretty(
            &json!({"schema_version":1,"status":"running_offline_diagnostic",
        "wrapper_setup_ms":wrapper_setup_ms,"combiner_setup_ms":combiner_setup_ms,"setup_ms":setup_ms,"started_unix_ms":started_unix_ms}),
        )?,
    )?;
    let mut receipts = new_file(&output.join("ranges.jsonl"))?;
    receipts.sync_all()?;
    File::open(output)?.sync_all()?;
    let cohort_start = Instant::now();
    let mut warm_start = None;
    let mut total_transactions = 0u64;
    let mut warm_transactions = 0u64;
    let mut total_gas = 0u64;
    let mut sum_job_ms = 0u128;
    for (index, range) in jobs.chunks(args.range_size).enumerate() {
        if index == 1 {
            warm_start = Some(Instant::now());
        }
        let job_start = Instant::now();
        let job_started_unix_ms = unix_ms()?;
        crs_identity.check(crs)?;
        read_bound(&app, BIN_SHA, 64 * MAX_JSON)?;
        read_bound(&app.with_extension("text"), TEXT_SHA, 64 * MAX_JSON)?;
        let (proofs, fri_bincode_bytes, aggregate_response_bytes) =
            load_range(range, &args.proof_dir)?;
        let from = u32::try_from(range[0].batch.batch_id)?;
        let to = u32::try_from(range.last().unwrap().batch.batch_id)?;
        let expected =
            expected_snark_input(&range.iter().map(|job| job.expected).collect::<Vec<_>>())?;
        let mut transaction_count = 0u64;
        let mut gas_used = 0u64;
        for job in range {
            let context = Value::Object(job.metadata.context.clone());
            transaction_count = transaction_count
                .checked_add(number(&context, "transaction_count")?)
                .context("transaction total overflow")?;
            gas_used = gas_used
                .checked_add(number(&context["benchmark"], "gas_used")?)
                .context("gas total overflow")?;
        }
        let input_load_ms = job_start.elapsed().as_millis();
        let range_dir = output.join(format!("range-{from}-{to}"));
        directory(&range_dir)?;
        // Synthetic token only exercises the exact-range lifecycle. It grants no authority.
        let token = ProverLeaseToken::from(format!(
            "0x{}",
            sha(format!("offline-only:{from}:{to}:{}", args.manifest_sha256).as_bytes())
        ));
        let evidence = json!({"manifest_sha256":args.manifest_sha256,"fri_receipts_sha256":args.fri_receipts_sha256,
            "fri_verification_sha256":args.fri_verification_sha256,"batches":range.iter().map(|j| json!({
                "batch_id":j.batch.batch_id,"metadata_sha256":j.batch.metadata_sha256,"proof_sha256":j.receipt["proof_sha256"],
                "expected_public_input_hash":j.metadata.expected_public_input_hash,"canonical":j.canonical})).collect::<Vec<_>>()});
        let proof_path = range_dir.join("proof-record.json");
        let client = OfflineClient {
            url: Url::parse("offline://sustained-snark-no-authority")?,
            input: Mutex::new(Some(SnarkProofInputs {
                from_batch_number: L2BatchNumber(from),
                to_batch_number: L2BatchNumber(to),
                vk_hash: VK.to_owned(),
                fri_proofs: proofs,
                lease_token: token.clone(),
            })),
            token,
            from,
            to,
            expected,
            output: proof_path.clone(),
            evidence,
            submitted: AtomicBool::new(false),
        };
        let prove_start = Instant::now();
        let prove_started_unix_ms = unix_ms()?;
        let outcome = run_inner(
            &client,
            &mut wrapper,
            &mut combiner,
            range_dir.to_str().context("non-UTF8 output")?.to_owned(),
            false,
            &versions,
        )
        .await?;
        let prove_wall_ms = prove_start.elapsed().as_millis();
        ensure!(
            outcome == ProofRunOutcome::ProofSubmitted && client.submitted.load(Ordering::Acquire),
            "offline job did not persist exactly once"
        );
        crs_identity.check(crs)?;
        let raw = read_generated(&proof_path)?;
        let production_wire = serde_json::from_slice::<Value>(&raw)?["production_wire"].clone();
        let proof_sha256 = sha(&raw);
        let proof_bytes = raw.len();
        drop(raw);
        total_transactions = total_transactions
            .checked_add(transaction_count)
            .context("transaction total overflow")?;
        if index > 0 {
            warm_transactions = warm_transactions
                .checked_add(transaction_count)
                .context("warm transaction total overflow")?;
        }
        total_gas = total_gas
            .checked_add(gas_used)
            .context("gas total overflow")?;
        sum_job_ms += prove_wall_ms;
        let receipt = json!({"schema_version":1,"status":"generated_and_internally_verified_pending_independent_verification",
            "index":index,"from_batch_number":from,"to_batch_number":to,"fri_count":range.len(),
            "started_unix_ms":job_started_unix_ms,"prove_started_unix_ms":prove_started_unix_ms,"finished_unix_ms":unix_ms()?,
            "input_load_ms":input_load_ms,"prove_wall_ms":prove_wall_ms,"job_wall_ms":job_start.elapsed().as_millis(),
            "transaction_count":transaction_count,"gas_used":gas_used,"expected_public_inputs":expected,
            "fri_bincode_bytes":fri_bincode_bytes,"aggregate_response_bytes":aggregate_response_bytes,
            "production_wire":production_wire,
            "proof_file":format!("range-{from}-{to}/proof-record.json"),"proof_sha256":proof_sha256,"proof_bytes":proof_bytes,
            "cache_mode":"one_resident_combiner_and_warm_wrapper_host_cache","zk_enabled":true,"network_used":false});
        serde_json::to_writer(&mut receipts, &receipt)?;
        receipts.write_all(b"\n")?;
        receipts.sync_all()?;
        println!("{}", receipt);
    }
    let cohort_wall_ms = cohort_start.elapsed().as_millis();
    let warm_wall_ms = warm_start.map(|start| start.elapsed().as_millis());
    drop((combiner, wrapper));
    read_bound(&args.manifest, &args.manifest_sha256, MAX_JSON)?;
    read_bound(&args.fri_receipts, &args.fri_receipts_sha256, MAX_RECEIPTS)?;
    read_bound(
        &args.fri_verification,
        &args.fri_verification_sha256,
        MAX_JSON,
    )?;
    for job in &jobs {
        read_bound(
            &args.manifest.parent().unwrap().join(&job.batch.metadata),
            &job.batch.metadata_sha256,
            MAX_JSON,
        )?;
        canonical_batch_files(
            &job.metadata,
            &args.manifest.parent().unwrap().join(&job.batch.metadata),
        )?;
    }
    authenticate_crs(crs)?;
    let summary = json!({"schema":"syscoin-sustained-snark-generated-v1","status":"generated_and_internally_verified_pending_independent_verification",
        "batch_count":jobs.len(),"range_count":jobs.chunks(args.range_size).len(),"range_size":args.range_size,
        "from_batch_number":jobs[0].batch.batch_id,"to_batch_number":jobs.last().unwrap().batch.batch_id,
        "total_transactions":total_transactions,"total_gas_used":total_gas,"warm_transactions":warm_transactions,
        "wrapper_setup_ms":wrapper_setup_ms,"combiner_setup_ms":combiner_setup_ms,"setup_ms":setup_ms,
        "cohort_wall_ms":cohort_wall_ms,"warm_wall_ms":warm_wall_ms,"sum_production_job_ms":sum_job_ms,"full_wall_ms":started.elapsed().as_millis(),
        "manifest_sha256":args.manifest_sha256,"fri_receipts_sha256":args.fri_receipts_sha256,"fri_verification_sha256":args.fri_verification_sha256,
        "zk_enabled":true,"network_used":false,"live_claim_used":false,"live_submission_used":false,
        "qualification":"Offline SNARK-stage measurement only. Warm metrics exclude the first range. Every wrapper proof requires independent verification; no end-to-end TPS claim."});
    write_new(
        &output.join("GENERATED.json"),
        &serde_json::to_vec_pretty(&summary)?,
    )?;
    println!("{}", summary);
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    init_tracing();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(256 * 1024 * 1024)
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || handle.block_on(run(args)))
            .await
            .context("offline SNARK worker panicked")?
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn manifest(ids: &[u64]) -> Vec<u8> {
        serde_json::to_vec(&json!({"schema_version":1,"batches":ids.iter().map(|id| json!({"batch_id":id,
            "metadata":format!("batch-{id}/manifest.json"),"metadata_sha256":"a".repeat(64),"input":format!("batch-{id}/input.bin")})).collect::<Vec<_>>()})).unwrap()
    }
    #[test]
    fn bounded_ordered_ranges() {
        assert!(parse_manifest(&manifest(&[24, 25, 26, 27]), 2).is_ok());
        for (ids, size) in [
            (vec![24], 2),
            (vec![24, 24], 2),
            (vec![25, 24], 2),
            (vec![24, 26], 2),
            (vec![24, 25, 26], 2),
            (vec![24, 25], 1),
            (vec![24, 25], 101),
        ] {
            assert!(parse_manifest(&manifest(&ids), size).is_err());
        }
    }
    #[test]
    fn canonical_hashes_and_paths() {
        assert!(hash(&format!("0x{}", "1".repeat(64)), true).is_ok());
        for value in [
            "A".repeat(64),
            "a".repeat(63),
            format!("0x{}", "a".repeat(64)),
        ] {
            assert!(hash(&value, false).is_err());
        }
        for path in ["../proof", "/proof", "./proof", "a//b", ""] {
            assert!(relative(Path::new(path)).is_err());
        }
    }
    #[test]
    fn exact_production_wire_bounds() {
        let lengths = [1usize, 2, 3, 4, 5, 6, 7];
        let encoded: Vec<_> = lengths
            .iter()
            .map(|n| STANDARD.encode(vec![0u8; *n]))
            .collect();
        let actual = serde_json::to_vec(
            &json!({"from_batch_number":24,"to_batch_number":30,"vk_hash":VK,
            "fri_proofs":encoded,"lease_token":format!("0x{}", "0".repeat(64))}),
        )
        .unwrap()
        .len();
        assert_eq!(range_wire_size(&lengths, 24, 30).unwrap(), (28, actual));
        // A realistic 100-proof range is valid, unlike the incorrect 10MiB aggregate cap.
        assert!(range_wire_size(&[2_600_000; 100], 24, 123).is_ok());
        assert!(range_wire_size(&[6_000_000; 100], 24, 123).is_err());
        let largest_raw = MAX_PROOF_SUBMISSION_BODY_BYTES / 4 * 3;
        assert!(range_wire_size(&[largest_raw], 24, 24).is_ok());
        assert!(range_wire_size(&[largest_raw + 1], 24, 24).is_err());
        assert!(range_wire_size(&[usize::MAX], 24, 24).is_err());
    }
    #[test]
    fn exact_submission_bytes_include_envelope() {
        let token = ProverLeaseToken::from(format!("0x{}", "1".repeat(64)));
        let overhead = submission_body(24, 123, "", &token).unwrap().len();
        let largest = "A".repeat(MAX_PROOF_SUBMISSION_BODY_BYTES - overhead);
        assert_eq!(
            submission_body(24, 123, &largest, &token).unwrap().len(),
            MAX_PROOF_SUBMISSION_BODY_BYTES
        );
        assert!(submission_body(24, 123, &(largest + "A"), &token).is_err());
        let encoded = "proof-with-\"-escape";
        let body = submission_body(24, 123, encoded, &token).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["proof"],
            encoded
        );
    }
    #[test]
    fn canonical_native_fields_preserve_u64_and_reject_drift() {
        let count = (1u64 << 53) + 1;
        let metadata = Metadata {
            schema_version:1, batch_id:24, app_bin_sha256:BIN_SHA.into(), app_text_sha256:TEXT_SHA.into(),
            prover_input_sha256:"1".repeat(64), prover_input_words:1,
            expected_public_input_hash:format!("0x{}", "2".repeat(64)), expected_security100_program_commitment:PROGRAM.into(),
            context:serde_json::from_value(json!({"chain_id":57001,"settlement_layer_chain_id":31337,
                "state_before":"before","state_after":"after","first_block_number":24,"last_block_number":24,
                "transaction_count":count,"pubdata_mode":"Blobs"})).unwrap(),
        };
        let info = json!({"batch_number":24,"protocol_version":"0.32.0","chain_id":57001,"sl_chain_id":31337,
            "new_state_commitment":"after","first_block_number":24,"last_block_number":24,
            "number_of_layer1_txs":0,"number_of_layer2_txs":count});
        let message = json!({"commit_batch_info":info,"first_block_number":24,"last_block_number":24,
            "previous_stored_batch_info":{"batch_number":23,"state_commitment":"before"},"pubdata_mode":"Blobs",
            "tx_count":count,"chain_address":"0x62614d63aa2f40c50b299394b209260d39f80bb6"});
        assert!(check_canonical_fields(&metadata, &info, &message).is_ok());
        let mut wrong = message.clone();
        wrong["tx_count"] = json!(count - 1);
        assert!(check_canonical_fields(&metadata, &info, &wrong).is_err());
        wrong = message.clone();
        wrong["previous_stored_batch_info"]["state_commitment"] = json!("different");
        assert!(check_canonical_fields(&metadata, &info, &wrong).is_err());
        wrong = message.clone();
        wrong["commit_batch_info"]["chain_id"] = json!(1);
        assert!(check_canonical_fields(&metadata, &info, &wrong).is_err());
        let mut overflow = info.clone();
        overflow["number_of_layer1_txs"] = json!(u64::MAX);
        wrong = message;
        wrong["commit_batch_info"] = overflow.clone();
        assert!(check_canonical_fields(&metadata, &overflow, &wrong).is_err());
    }
    #[test]
    fn historical_scalar_regression() {
        let statements = [
            "0xdf0aebf994d8c10c69f6e6f6ead904e4003c9e269dfb2ce57617142d48165bcb",
            "0x899754f313ed972f47898b74b75b26e22c12d3efd37eb95589f16663103ffb0c",
            "0xc31eb16a6f3f40eef7bf40621599b3437e72d5381ef2172d4dabcf756fdf1e57",
            "0x5e3031bb3790687da09b8290efbdab71039f6c63791b24707d9d3df6ff8f56b0",
        ];
        let mut outputs = Vec::new();
        for statement in statements {
            let raw = hash(statement, true).unwrap();
            let mut output = [0u32; 16];
            for index in 0..8 {
                output[index] =
                    u32::from_le_bytes(raw[index * 4..index * 4 + 4].try_into().unwrap());
            }
            outputs.push(output);
        }
        assert_eq!(
            expected_snark_input(&outputs).unwrap(),
            [[
                9_739_182_611_962_389_517,
                4_415_032_890_248_141_684,
                15_514_968_203_318_986_004,
                3_471_530_719
            ]]
        );
        outputs[1][8] = 1;
        assert!(expected_snark_input(&outputs).is_err());
    }
}
