//! CPU verification for an untrusted rental's exact, ordered V32/V8 candidate payload.
//!
//! The expected file is a trusted controller input: its program commitment must already be
//! authenticated against the registered nonzero VK. This utility authenticates native proof
//! statements; it does not authorize a lease, settlement transaction, or worker program.
//!
//! SYSCOIN: Publication recovery follows native verification and accepts only identical private
//! output, so an interrupted durability barrier cannot strand a valid result or bypass proof checks.

use std::ffi::{CString, OsString};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{ensure, Context};
use base64::{engine::general_purpose::STANDARD, Engine};
use execution_utils::setups::{
    binary_u8_to_u32, get_unified_circuit_artifact_for_machine_type,
    pad_bytecode_bytes_for_proving, pad_bytecode_for_proving, CompiledCircuitsSet,
};
use execution_utils::unified_circuit::{
    compute_unified_setup_for_machine_configuration, verify_proof_in_unified_layer,
};
use execution_utils::unrolled::{UnrolledProgramProof, UnrolledProgramSetup};
use execution_utils::verifier_binaries::recursion_artifact;
use execution_utils::{RecursionArtifact, RecursionLayer};
use riscv_transpiler::common_constants::{
    BLAKE2S_DELEGATION_CSR_REGISTER, REDUCED_MACHINE_CIRCUIT_FAMILY_IDX,
};
use riscv_transpiler::cycle::IWithoutByteAccessIsaConfigWithDelegation;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use verifier_common::transcript::Blake2sBufferingTranscript;
use verifier_common::SecurityModel;
use zksync_airbender_execution_utils as execution_utils;

const MAX_PAYLOAD_BYTES: usize = 256 * 1024 * 1024;
const MAX_EXPECTED_BYTES: usize = 64 * 1024;
const MAX_PROOF_BYTES: usize = 10 * 1024 * 1024;
const SECURITY: SecurityModel = SecurityModel::Security100;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    schema_version: u32,
    protocol_version: u32,
    proving_version: u32,
    security_level: u32,
    from_batch_number: u64,
    to_batch_number: u64,
    vk_hash: String,
    program_commitment: String,
    statements: Vec<String>,
    payload_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    from_batch_number: u64,
    to_batch_number: u64,
    vk_hash: String,
    fri_proofs: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Verified {
    schema_version: u32,
    verification: &'static str,
    payload_sha256: String,
    expected_sha256: String,
    vk_hash: String,
    program_commitment: String,
    from_batch_number: u64,
    to_batch_number: u64,
    proof_count: usize,
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn lower_hex_32(text: &str, prefix: bool) -> anyhow::Result<[u8; 32]> {
    let value = if prefix {
        text.strip_prefix("0x")
            .context("expected a 0x-prefixed hash")?
    } else {
        text
    };
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "expected a canonical lowercase 32-byte hash"
    );
    let mut result = [0; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(result)
}

fn registers(bytes: [u8; 32], little_endian: bool) -> [u32; 8] {
    std::array::from_fn(|index| {
        let word = bytes[index * 4..index * 4 + 4].try_into().unwrap();
        if little_endian {
            u32::from_le_bytes(word)
        } else {
            u32::from_be_bytes(word)
        }
    })
}

fn parse_inputs(
    payload_bytes: &[u8],
    expected_bytes: &[u8],
) -> anyhow::Result<(Payload, Expected)> {
    ensure!(
        payload_bytes.len() <= MAX_PAYLOAD_BYTES,
        "candidate payload exceeds size limit"
    );
    ensure!(
        expected_bytes.len() <= MAX_EXPECTED_BYTES,
        "expected input exceeds size limit"
    );
    let payload: Payload =
        serde_json::from_slice(payload_bytes).context("invalid candidate payload JSON")?;
    let expected: Expected =
        serde_json::from_slice(expected_bytes).context("invalid expected JSON")?;
    ensure!(
        expected.schema_version == 1
            && expected.protocol_version == 32
            && expected.proving_version == 8
            && expected.security_level == 100,
        "only native V32/V8 Security100 verification is supported"
    );
    lower_hex_32(&expected.payload_sha256, false)?;
    ensure!(
        sha256(payload_bytes) == expected.payload_sha256,
        "candidate payload SHA-256 mismatch"
    );
    ensure!(
        lower_hex_32(&expected.vk_hash, true)? != [0; 32],
        "zero VK is not registered"
    );
    ensure!(
        lower_hex_32(&expected.program_commitment, true)? != [0; 32],
        "zero program commitment"
    );
    let count = expected
        .to_batch_number
        .checked_sub(expected.from_batch_number)
        .and_then(|value| value.checked_add(1))
        .context("invalid batch range")?;
    ensure!(
        expected.from_batch_number > 0 && (2..=100).contains(&count),
        "expected 2..=100 consecutive batches"
    );
    ensure!(
        payload.from_batch_number == expected.from_batch_number
            && payload.to_batch_number == expected.to_batch_number
            && payload.vk_hash == expected.vk_hash,
        "candidate range or VK differs from trusted input"
    );
    ensure!(
        payload.fri_proofs.len() == count as usize && expected.statements.len() == count as usize,
        "proof or statement count differs from batch range"
    );
    for statement in &expected.statements {
        lower_hex_32(statement, true)?;
    }
    for proof in &payload.fri_proofs {
        ensure!(
            !proof.is_empty() && proof.len() <= MAX_PROOF_BYTES,
            "encoded FRI proof exceeds size limit or is empty"
        );
    }
    Ok((payload, expected))
}

fn decode_bincode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> anyhow::Result<T> {
    ensure!(
        bytes.len() <= MAX_PROOF_BYTES,
        "decoded FRI proof exceeds size limit"
    );
    let (proof, consumed) = bincode::serde::decode_from_slice(
        bytes,
        bincode::config::standard().with_limit::<MAX_PROOF_BYTES>(),
    )
    .context("invalid native FRI encoding")?;
    ensure!(
        consumed == bytes.len(),
        "native FRI encoding has trailing bytes"
    );
    Ok(proof)
}

fn decode_proof(encoded: &str) -> anyhow::Result<UnrolledProgramProof> {
    ensure!(
        encoded.len() <= MAX_PROOF_BYTES,
        "encoded FRI proof exceeds size limit"
    );
    let bytes = STANDARD.decode(encoded).context("invalid FRI base64")?;
    ensure!(
        STANDARD.encode(&bytes) == encoded,
        "noncanonical FRI base64"
    );
    decode_bincode(&bytes)
}

fn validate_shape_and_chain(proof: &UnrolledProgramProof) -> anyhow::Result<()> {
    let family = proof
        .circuit_families_proofs
        .get(&REDUCED_MACHINE_CIRCUIT_FAMILY_IDX);
    ensure!(
        proof.circuit_families_proofs.len() == 1
            && family.map(Vec::len)
                == Some(execution_utils::unified_recursion_target_family_proofs(
                    SECURITY
                )),
        "FRI proof is not a converged Security100 unified proof"
    );
    ensure!(
        proof.inits_and_teardowns_proofs.is_empty(),
        "unexpected init/teardown proofs"
    );
    ensure!(
        proof.delegation_proofs.len() == 1
            && proof
                .delegation_proofs
                .get(&BLAKE2S_DELEGATION_CSR_REGISTER)
                .map(Vec::len)
                == Some(1),
        "unexpected unified delegation proof shape"
    );
    let preimage = proof
        .recursion_chain_preimage
        .context("missing recursion chain preimage")?;
    let hash = proof
        .recursion_chain_hash
        .context("missing recursion chain hash")?;
    let mut hasher = Blake2sBufferingTranscript::new();
    hasher.absorb(&preimage);
    ensure!(hasher.finalize().0 == hash, "inconsistent recursion chain");
    Ok(())
}

struct UnifiedData {
    setup: UnrolledProgramSetup,
    layouts: CompiledCircuitsSet,
}

fn unified_data() -> &'static UnifiedData {
    static DATA: OnceLock<UnifiedData> = OnceLock::new();
    DATA.get_or_init(|| {
        let binary = recursion_artifact(SECURITY, RecursionLayer::Unified, RecursionArtifact::Bin);
        let text = recursion_artifact(SECURITY, RecursionLayer::Unified, RecursionArtifact::Txt);
        let padded = |input: &[u8]| {
            let mut value = input.to_vec();
            pad_bytecode_bytes_for_proving(&mut value);
            value
        };
        let setup = compute_unified_setup_for_machine_configuration::<
            IWithoutByteAccessIsaConfigWithDelegation,
        >(&padded(binary), &padded(text));
        let mut words = binary_u8_to_u32(binary);
        pad_bytecode_for_proving(&mut words);
        let layouts = get_unified_circuit_artifact_for_machine_type::<
            IWithoutByteAccessIsaConfigWithDelegation,
        >(&words);
        UnifiedData { setup, layouts }
    })
}

fn verify_native(proof: &UnrolledProgramProof) -> anyhow::Result<[u32; 16]> {
    validate_shape_and_chain(proof)?;
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let data = unified_data();
        verify_proof_in_unified_layer(proof, &data.setup, &data.layouts, false, SECURITY)
    }))
    .map_err(|_| anyhow::anyhow!("native FRI verifier panicked"))?
    .map_err(|_| anyhow::anyhow!("native FRI verification failed"))
}

fn bind_verified_registers(
    actual: [u32; 16],
    statement: &str,
    program: &str,
) -> anyhow::Result<()> {
    // Batch hashes are loaded as little-endian registers; ProgramCommitment's Display encodes
    // each recursion-chain register in big-endian order. The two representations differ.
    ensure!(
        actual[..8] == registers(lower_hex_32(statement, true)?, true),
        "verified FRI statement mismatch"
    );
    ensure!(
        actual[8..] == registers(lower_hex_32(program, true)?, false),
        "verified FRI program mismatch"
    );
    Ok(())
}

fn verify_bytes(payload_bytes: &[u8], expected_bytes: &[u8]) -> anyhow::Result<Verified> {
    let (payload, expected) = parse_inputs(payload_bytes, expected_bytes)?;
    for (index, (encoded, statement)) in payload
        .fri_proofs
        .iter()
        .zip(&expected.statements)
        .enumerate()
    {
        let proof = decode_proof(encoded)
            .with_context(|| format!("invalid proof at range index {index}"))?;
        let outputs = verify_native(&proof)
            .with_context(|| format!("failed proof at range index {index}"))?;
        bind_verified_registers(outputs, statement, &expected.program_commitment)
            .with_context(|| format!("unbound proof at range index {index}"))?;
    }
    Ok(Verified {
        schema_version: 1,
        verification: "native_v32_fri_payload",
        payload_sha256: expected.payload_sha256,
        expected_sha256: sha256(expected_bytes),
        vk_hash: expected.vk_hash,
        program_commitment: expected.program_commitment,
        from_batch_number: expected.from_batch_number,
        to_batch_number: expected.to_batch_number,
        proof_count: payload.fri_proofs.len(),
    })
}

fn read_bounded(path: &Path, limit: usize) -> anyhow::Result<Vec<u8>> {
    ensure!(
        path.is_absolute(),
        "verification inputs must use absolute paths"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= limit as u64,
        "verification input is not a bounded regular file"
    );
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit,
        "verification input grew beyond its limit"
    );
    Ok(bytes)
}

struct PendingAttestation {
    path: PathBuf,
    file: File,
    published: bool,
}

impl PendingAttestation {
    fn new(parent: &Path) -> anyhow::Result<Self> {
        let mut template = CString::new(parent.join(".verify-fri-XXXXXX").as_os_str().as_bytes())?
            .into_bytes_with_nul();
        // SAFETY: mkstemp receives a writable, NUL-terminated template ending in six Xs.
        let fd = unsafe { libc::mkstemp(template.as_mut_ptr().cast()) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        template.pop();
        let pending = Self {
            path: PathBuf::from(OsString::from_vec(template)),
            // SAFETY: successful mkstemp returns a new descriptor owned exclusively by this File.
            file: unsafe { File::from_raw_fd(fd) },
            published: false,
        };
        // SAFETY: the descriptor is live and F_SETFD accepts the integer FD_CLOEXEC flag.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(pending)
    }
}

impl Drop for PendingAttestation {
    fn drop(&mut self) {
        if !self.published {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn rename_attestation(source: &Path, destination: &Path) -> anyhow::Result<()> {
    let source = CString::new(source.as_os_str().as_bytes())?;
    let destination = CString::new(destination.as_os_str().as_bytes())?;
    // A hard-link fallback could leave a complete but multiply linked attestation after a crash,
    // which the controller correctly refuses. Require an exclusive rename from the filesystem.
    #[cfg(target_os = "linux")]
    // SAFETY: the arguments match renameat2; both paths are live and NUL-terminated.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(target_os = "macos")]
    // SAFETY: both pointers refer to live NUL-terminated paths; AT_FDCWD needs no open descriptor.
    let result = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn rename_attestation(_source: &Path, _destination: &Path) -> anyhow::Result<()> {
    anyhow::bail!("atomic attestation publication requires Linux or macOS")
}

fn same_attestation_metadata(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.nlink() == after.nlink()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn ensure_attestation_unchanged(
    path: &Path,
    file: &File,
    original: &Metadata,
) -> anyhow::Result<()> {
    ensure!(
        same_attestation_metadata(original, &file.metadata()?)
            && same_attestation_metadata(original, &std::fs::symlink_metadata(path)?),
        "existing verification output changed during recovery"
    );
    Ok(())
}

fn ensure_output_directory(parent: &Path, directory: &File) -> anyhow::Result<()> {
    let retained = directory.metadata()?;
    let current = std::fs::metadata(parent)?;
    ensure!(
        retained.is_dir()
            && current.is_dir()
            && retained.dev() == current.dev()
            && retained.ino() == current.ino(),
        "verification output directory changed during publication"
    );
    Ok(())
}

fn recover_verified(
    path: &Path,
    bytes: &[u8],
    directory: &File,
    sync_directory: impl FnOnce(&File) -> std::io::Result<()>,
) -> anyhow::Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no arguments and only observes this process's effective identity.
    let owner = unsafe { libc::geteuid() };
    ensure!(
        metadata.is_file()
            && metadata.uid() == owner
            && metadata.mode() & 0o7777 == 0o600
            && metadata.nlink() == 1
            && metadata.len() == bytes.len() as u64,
        "existing verification output must be an owned 0600 single-link regular file of the exact expected length"
    );
    let mut existing = Vec::with_capacity(bytes.len());
    (&mut file)
        .take(bytes.len() as u64 + 1)
        .read_to_end(&mut existing)?;
    ensure!(
        existing == bytes,
        "existing verification output differs from the verified result"
    );
    ensure_attestation_unchanged(path, &file, &metadata)?;
    let parent = path.parent().context("verification output has no parent")?;
    ensure_output_directory(parent, directory)?;
    // SYSCOIN: A previous process may have stopped after rename but before directory fsync.
    // Reusing its exact output must complete both durability barriers without replacing its inode.
    file.sync_all()?;
    sync_directory(directory)?;
    ensure_attestation_unchanged(path, &file, &metadata)?;
    ensure_output_directory(parent, directory)?;
    Ok(())
}

fn publish_verified(
    path: &Path,
    bytes: &[u8],
    prepare: impl FnOnce(&mut File, &[u8]) -> std::io::Result<()>,
) -> anyhow::Result<()> {
    publish_verified_with_directory_sync(path, bytes, prepare, File::sync_all)
}

fn publish_verified_with_directory_sync(
    path: &Path,
    bytes: &[u8],
    prepare: impl FnOnce(&mut File, &[u8]) -> std::io::Result<()>,
    sync_directory: impl FnOnce(&File) -> std::io::Result<()>,
) -> anyhow::Result<()> {
    ensure!(
        path.is_absolute(),
        "verification output must use an absolute path"
    );
    let parent = path.parent().context("verification output has no parent")?;
    let directory = File::open(parent)?;
    let mut pending = PendingAttestation::new(parent)?;
    prepare(&mut pending.file, bytes)?;
    ensure_output_directory(parent, &directory)?;
    if let Err(error) = rename_attestation(&pending.path, path) {
        if error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.raw_os_error() == Some(libc::EEXIST))
        {
            drop(pending);
            return recover_verified(path, bytes, &directory, sync_directory);
        }
        return Err(error);
    }
    pending.published = true;
    sync_directory(&directory)?;
    ensure_output_directory(parent, &directory)?;
    Ok(())
}

fn write_verified(path: &Path, verified: &Verified) -> anyhow::Result<()> {
    let mut bytes = serde_json::to_vec(verified)?;
    bytes.push(b'\n');
    publish_verified(path, &bytes, |file, bytes| {
        file.write_all(bytes)?;
        file.sync_all()
    })
}

/// Verify the complete ordered range before writing a new private success attestation.
pub fn verify_files(payload: &Path, expected: &Path, output: &Path) -> anyhow::Result<()> {
    let payload = read_bounded(payload, MAX_PAYLOAD_BYTES)?;
    let expected = read_bounded(expected, MAX_EXPECTED_BYTES)?;
    let verified = verify_bytes(&payload, &expected)?;
    write_verified(output, &verified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    fn inputs() -> (Value, Value) {
        let payload = json!({"from_batch_number": 1, "to_batch_number": 2,
            "vk_hash": format!("0x{}", "11".repeat(32)), "fri_proofs": ["AA==", "AA=="]});
        let expected = json!({"schema_version": 1, "protocol_version": 32, "proving_version": 8,
            "security_level": 100, "from_batch_number": 1, "to_batch_number": 2,
            "vk_hash": payload["vk_hash"], "program_commitment": format!("0x{}", "12345678".repeat(8)),
            "statements": [format!("0x{}", "01020304".repeat(8)), format!("0x{}", "05060708".repeat(8))],
            "payload_sha256": sha256(&serde_json::to_vec(&payload).unwrap())});
        (payload, expected)
    }

    fn parse_values(payload: &Value, expected: &Value) -> anyhow::Result<(Payload, Expected)> {
        parse_inputs(
            &serde_json::to_vec(payload)?,
            &serde_json::to_vec(expected)?,
        )
    }

    fn rebound(payload: &Value, mut expected: Value) -> Value {
        expected["payload_sha256"] = json!(sha256(&serde_json::to_vec(payload).unwrap()));
        expected
    }

    #[test]
    fn exact_ordered_range_and_raw_payload_hash() {
        let (payload, expected) = inputs();
        assert!(parse_values(&payload, &expected).is_ok());
        let mut bytes = serde_json::to_vec(&payload).unwrap();
        bytes.push(b'\n');
        assert!(parse_inputs(&bytes, &serde_json::to_vec(&expected).unwrap()).is_err());
    }

    #[test]
    fn reject_unknown_duplicate_and_capability_fields() {
        let (mut payload, expected) = inputs();
        payload["lease_id"] = json!("untrusted");
        assert!(parse_values(&payload, &rebound(&payload, expected.clone())).is_err());
        let (payload, _) = inputs();
        let bytes =
            serde_json::to_string(&payload)
                .unwrap()
                .replacen('{', "{\"from_batch_number\":1,", 1);
        assert!(parse_inputs(bytes.as_bytes(), &serde_json::to_vec(&expected).unwrap()).is_err());
        let mut expected = expected;
        expected["unchecked_program"] = json!(true);
        assert!(parse_values(&payload, &expected).is_err());
    }

    #[test]
    fn reject_version_security_or_identity_drift() {
        let (payload, expected) = inputs();
        for field in [
            "schema_version",
            "protocol_version",
            "proving_version",
            "security_level",
        ] {
            let mut bad = expected.clone();
            bad[field] = json!(0);
            assert!(parse_values(&payload, &bad).is_err());
        }
        for field in ["vk_hash", "program_commitment"] {
            let mut bad = expected.clone();
            bad[field] = json!(format!("0x{}", "00".repeat(32)));
            assert!(parse_values(&payload, &bad).is_err());
        }
        let mut bad = expected;
        bad["vk_hash"] = json!(format!("0x{}", "22".repeat(32)));
        assert!(parse_values(&payload, &bad).is_err());
    }

    #[test]
    fn reject_range_count_type_and_overflow() {
        let (payload, expected) = inputs();
        for (from, to) in [(0, 1), (1, 1), (2, 1), (1, 101), (0, u64::MAX)] {
            let mut bad = expected.clone();
            bad["from_batch_number"] = json!(from);
            bad["to_batch_number"] = json!(to);
            assert!(parse_values(&payload, &bad).is_err());
        }
        let mut bad = expected.clone();
        bad["from_batch_number"] = json!(true);
        assert!(parse_values(&payload, &bad).is_err());
        let mut bad = expected;
        bad["statements"].as_array_mut().unwrap().pop();
        assert!(parse_values(&payload, &bad).is_err());
    }

    #[test]
    fn statement_and_program_use_distinct_register_byte_orders() {
        let (_, expected) = inputs();
        let statement = expected["statements"][0].as_str().unwrap();
        let program = expected["program_commitment"].as_str().unwrap();
        let mut outputs = [0x04030201; 16];
        outputs[8..].fill(0x12345678);
        assert!(bind_verified_registers(outputs, statement, program).is_ok());
        outputs[0] ^= 1;
        assert!(bind_verified_registers(outputs, statement, program).is_err());
        outputs[0] ^= 1;
        outputs[8] ^= 1;
        assert!(bind_verified_registers(outputs, statement, program).is_err());
    }

    #[test]
    fn reject_reordered_statement_binding() {
        let (_, expected) = inputs();
        let program = expected["program_commitment"].as_str().unwrap();
        let mut outputs = [0x04030201; 16];
        outputs[8..].fill(0x12345678);
        assert!(bind_verified_registers(
            outputs,
            expected["statements"][1].as_str().unwrap(),
            program
        )
        .is_err());
    }

    #[test]
    fn bounded_canonical_bincode_rejects_trailing_and_truncated_bytes() {
        let value = vec![1u32, 2, 3];
        let mut bytes = bincode::serde::encode_to_vec(&value, bincode::config::standard()).unwrap();
        assert_eq!(decode_bincode::<Vec<u32>>(&bytes).unwrap(), value);
        bytes.push(0);
        assert!(decode_bincode::<Vec<u32>>(&bytes).is_err());
        assert!(decode_bincode::<Vec<u32>>(&[]).is_err());
        assert!(decode_bincode::<Vec<u32>>(&[255; 20]).is_err());
    }

    #[test]
    fn reject_malformed_base64_and_native_proof() {
        for value in ["?", "AA", "AB==", "AA==\n", "AA=="] {
            assert!(decode_proof(value).is_err());
        }
        let (payload, expected) = inputs();
        assert!(verify_bytes(
            &serde_json::to_vec(&payload).unwrap(),
            &serde_json::to_vec(&expected).unwrap()
        )
        .is_err());
    }

    #[test]
    fn canonical_hashes_reject_ambiguous_spellings() {
        for value in [
            format!("0X{}", "ab".repeat(32)),
            format!("0x{}", "AB".repeat(32)),
            format!("0x{}", "ab".repeat(31)),
            format!("0x{}", "gg".repeat(32)),
        ] {
            assert!(lower_hex_32(&value, true).is_err());
        }
    }

    fn temporary_dir() -> std::path::PathBuf {
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "native-fri-verify-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    fn verified_result() -> Verified {
        Verified {
            schema_version: 1,
            verification: "native_v32_fri_payload",
            payload_sha256: "a".repeat(64),
            expected_sha256: "b".repeat(64),
            vk_hash: format!("0x{}", "11".repeat(32)),
            program_commitment: format!("0x{}", "22".repeat(32)),
            from_batch_number: 1,
            to_batch_number: 2,
            proof_count: 2,
        }
    }

    fn verified_bytes(result: &Verified) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(result).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn prepare_attestation(file: &mut File, bytes: &[u8]) -> std::io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        prepare_attestation(&mut file, bytes).unwrap();
    }

    fn assert_private_attestation(path: &Path, bytes: &[u8]) {
        let metadata = std::fs::symlink_metadata(path).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }

    fn entries(directory: &Path) -> Vec<PathBuf> {
        let mut paths = std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        paths.sort();
        paths
    }

    #[test]
    fn private_exclusive_output_and_bounded_nofollow_input() {
        let directory = temporary_dir();
        let input = directory.join("input");
        std::fs::write(&input, b"bounded").unwrap();
        assert_eq!(read_bounded(&input, 7).unwrap(), b"bounded");
        assert!(read_bounded(&input, 6).is_err());
        assert!(read_bounded(Path::new("relative"), 7).is_err());
        assert!(read_bounded(&directory, 100).is_err());
        let link = directory.join("link");
        symlink(&input, &link).unwrap();
        assert!(read_bounded(&link, 7).is_err());
        let output = directory.join("output");
        let result = verified_result();
        write_verified(&output, &result).unwrap();
        let original = verified_bytes(&result);
        assert_private_attestation(&output, &original);
        let inode = std::fs::metadata(&output).unwrap().ino();
        for _ in 0..2 {
            write_verified(&output, &result).unwrap();
            assert_private_attestation(&output, &original);
            assert_eq!(std::fs::metadata(&output).unwrap().ino(), inode);
        }
        let mut replacement = verified_result();
        replacement.payload_sha256 = "c".repeat(64);
        assert!(write_verified(&output, &replacement).is_err());
        assert_private_attestation(&output, &original);
        assert_eq!(std::fs::metadata(&output).unwrap().ino(), inode);
        assert!(write_verified(&link, &result).is_err());
        assert_eq!(std::fs::read_link(&link).unwrap(), input);
        assert_eq!(std::fs::read(&input).unwrap(), b"bounded");
        let missing = directory.join("missing");
        let broken = directory.join("broken");
        symlink(&missing, &broken).unwrap();
        assert!(write_verified(&broken, &result).is_err());
        assert_eq!(std::fs::read_link(&broken).unwrap(), missing);
        assert!(!missing.exists());
        let relative = Path::new("relative-attestation");
        assert!(write_verified(relative, &result).is_err());
        let mut prepared = false;
        assert!(publish_verified(relative, &original, |_, _| {
            prepared = true;
            Ok(())
        })
        .is_err());
        assert!(!prepared);
        assert_eq!(entries(&directory).len(), 4);
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn failed_preparation_can_retry(write_everything: bool) {
        let directory = temporary_dir();
        let output = directory.join("result");
        let result = verified_result();
        let bytes = verified_bytes(&result);
        let error = publish_verified(&output, &bytes, |file, bytes| {
            let count = if write_everything {
                bytes.len()
            } else {
                bytes.len() / 2
            };
            file.write_all(&bytes[..count])?;
            assert!(!output.exists());
            Err(std::io::Error::other(if write_everything {
                "injected sync failure"
            } else {
                "injected partial write failure"
            }))
        })
        .unwrap_err();
        assert!(error.to_string().contains("injected"));
        assert!(!output.exists());
        assert!(entries(&directory).is_empty());
        write_verified(&output, &result).unwrap();
        assert_private_attestation(&output, &bytes);
        assert_eq!(entries(&directory), vec![output]);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn partial_attestation_write_failure_leaves_output_retryable() {
        failed_preparation_can_retry(false);
    }

    #[test]
    fn attestation_sync_failure_leaves_output_retryable() {
        failed_preparation_can_retry(true);
    }

    #[test]
    fn directory_sync_failure_recovers_the_exact_published_inode() {
        let directory = temporary_dir();
        let output = directory.join("result");
        let result = verified_result();
        let bytes = verified_bytes(&result);
        let error =
            publish_verified_with_directory_sync(&output, &bytes, prepare_attestation, |_| {
                Err(std::io::Error::from_raw_os_error(libc::EIO))
            })
            .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(libc::EIO)
        );
        assert_private_attestation(&output, &bytes);
        assert_eq!(entries(&directory), vec![output.clone()]);
        let inode = std::fs::metadata(&output).unwrap().ino();
        let mut synced = false;
        publish_verified_with_directory_sync(&output, &bytes, prepare_attestation, |parent| {
            assert_eq!(entries(&directory), vec![output.clone()]);
            synced = true;
            parent.sync_all()
        })
        .unwrap();
        assert!(synced, "exact reuse must repeat the durability barrier");
        assert_private_attestation(&output, &bytes);
        assert_eq!(std::fs::metadata(&output).unwrap().ino(), inode);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn exact_output_recovery_rejects_unsafe_or_nonidentical_files() {
        for kind in [
            "public",
            "readonly",
            "executable",
            "hardlink",
            "symlink",
            "fifo",
            "directory",
            "short",
            "long",
            "json-equivalent",
        ] {
            let directory = temporary_dir();
            let output = directory.join("result");
            let result = verified_result();
            let bytes = verified_bytes(&result);
            match kind {
                "fifo" => {
                    let path = CString::new(output.as_os_str().as_bytes()).unwrap();
                    // SAFETY: path is NUL-terminated and mode is a valid file permission mask.
                    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
                }
                "directory" => std::fs::create_dir(&output).unwrap(),
                "symlink" => {
                    let target = directory.join("target");
                    write_private(&target, &bytes);
                    symlink(target, &output).unwrap();
                }
                "short" => write_private(&output, &bytes[..bytes.len() - 1]),
                "long" => write_private(&output, &[bytes.as_slice(), b"\n"].concat()),
                "json-equivalent" => {
                    let reordered = String::from_utf8(bytes.clone())
                        .unwrap()
                        .replacen(
                            "{\"schema_version\":1,\"verification\":\"native_v32_fri_payload\",",
                            "{\"verification\":\"native_v32_fri_payload\",\"schema_version\":1,",
                            1,
                        )
                        .into_bytes();
                    assert_eq!(reordered.len(), bytes.len());
                    assert_ne!(reordered, bytes);
                    assert_eq!(
                        serde_json::from_slice::<Value>(&reordered).unwrap(),
                        serde_json::from_slice::<Value>(&bytes).unwrap()
                    );
                    write_private(&output, &reordered);
                }
                _ => {
                    write_private(&output, &bytes);
                    match kind {
                        "public" | "readonly" | "executable" => {
                            let mode = match kind {
                                "public" => 0o644,
                                "readonly" => 0o400,
                                _ => 0o700,
                            };
                            std::fs::set_permissions(
                                &output,
                                std::fs::Permissions::from_mode(mode),
                            )
                            .unwrap();
                        }
                        "hardlink" => {
                            std::fs::hard_link(&output, directory.join("linked")).unwrap()
                        }
                        _ => unreachable!(),
                    }
                }
            }
            let before = std::fs::symlink_metadata(&output).unwrap();
            let content = before.is_file().then(|| std::fs::read(&output).unwrap());
            let previous_entries = entries(&directory);
            assert!(write_verified(&output, &result).is_err(), "{kind}");
            assert!(
                same_attestation_metadata(&before, &std::fs::symlink_metadata(&output).unwrap()),
                "{kind} must remain unchanged"
            );
            if let Some(content) = content {
                assert_eq!(std::fs::read(&output).unwrap(), content, "{kind}");
            }
            assert_eq!(entries(&directory), previous_entries, "{kind}");
            std::fs::remove_dir_all(directory).unwrap();
        }
    }

    #[test]
    fn exact_output_recovery_rechecks_path_after_durability_barrier() {
        let directory = temporary_dir();
        let output = directory.join("result");
        let replaced = directory.join("replaced");
        let result = verified_result();
        let bytes = verified_bytes(&result);
        write_verified(&output, &result).unwrap();
        let inode = std::fs::metadata(&output).unwrap().ino();
        let error =
            publish_verified_with_directory_sync(&output, &bytes, prepare_attestation, |parent| {
                std::fs::rename(&output, &replaced)?;
                write_private(&output, &bytes);
                parent.sync_all()
            })
            .unwrap_err();
        assert!(error.to_string().contains("changed during recovery"));
        assert_eq!(std::fs::metadata(&replaced).unwrap().ino(), inode);
        assert_ne!(std::fs::metadata(&output).unwrap().ino(), inode);
        assert_private_attestation(&output, &bytes);
        assert_private_attestation(&replaced, &bytes);
        assert_eq!(entries(&directory), vec![replaced, output]);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn attestation_crash_child() {
        let Some(output) = std::env::var_os("ZKSYS_ATTESTATION_CRASH_TEST_OUTPUT") else {
            return;
        };
        let bytes = verified_bytes(&verified_result());
        if std::env::var_os("ZKSYS_ATTESTATION_CRASH_AFTER_RENAME").is_some() {
            publish_verified_with_directory_sync(
                Path::new(&output),
                &bytes,
                prepare_attestation,
                |_| {
                    std::fs::write(Path::new(&output).with_extension("ready"), b"published")?;
                    loop {
                        std::thread::park();
                    }
                },
            )
            .unwrap();
            panic!("child unexpectedly completed the directory barrier");
        }
        publish_verified(Path::new(&output), &bytes, |file, bytes| {
            file.write_all(&bytes[..bytes.len() / 2])?;
            file.sync_all()?;
            std::process::exit(73);
        })
        .unwrap();
        panic!("child unexpectedly published an attestation");
    }

    fn attestation_child(output: &Path) -> Command {
        let test_name = format!(
            "{}::attestation_crash_child",
            module_path!().split_once("::").unwrap().1
        );
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", &test_name, "--test-threads=1"])
            .env("ZKSYS_ATTESTATION_CRASH_TEST_OUTPUT", output)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    #[test]
    fn abrupt_exit_before_publication_leaves_private_temp_and_allows_retry() {
        let directory = temporary_dir();
        let output = directory.join("result");
        let mut child = attestation_child(&output).spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                std::fs::remove_dir_all(&directory).unwrap();
                panic!("attestation crash child timed out");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(status.code(), Some(73));
        assert!(!output.exists());
        let orphaned = entries(&directory);
        assert_eq!(orphaned.len(), 1);
        assert!(orphaned[0]
            .file_name()
            .unwrap()
            .as_bytes()
            .starts_with(b".verify-fri-"));
        let result = verified_result();
        let bytes = verified_bytes(&result);
        assert_private_attestation(&orphaned[0], &bytes[..bytes.len() / 2]);
        write_verified(&output, &result).unwrap();
        assert_private_attestation(&output, &bytes);
        assert_private_attestation(&orphaned[0], &bytes[..bytes.len() / 2]);
        assert_eq!(entries(&directory).len(), 2);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn killed_after_rename_recovers_the_exact_published_inode() {
        let directory = temporary_dir();
        let output = directory.join("result");
        let ready = output.with_extension("ready");
        let mut child = attestation_child(&output)
            .env("ZKSYS_ATTESTATION_CRASH_AFTER_RENAME", "1")
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() {
            if let Some(status) = child.try_wait().unwrap() {
                std::fs::remove_dir_all(&directory).unwrap();
                panic!("attestation child exited before publication: {status}");
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                std::fs::remove_dir_all(&directory).unwrap();
                panic!("attestation child did not reach the directory barrier");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        std::fs::remove_file(ready).unwrap();
        let result = verified_result();
        let bytes = verified_bytes(&result);
        let inode = std::fs::metadata(&output).unwrap().ino();
        assert_private_attestation(&output, &bytes);
        write_verified(&output, &result).unwrap();
        assert_private_attestation(&output, &bytes);
        assert_eq!(std::fs::metadata(&output).unwrap().ino(), inode);
        assert_eq!(entries(&directory), vec![output]);
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn concurrent_publications(matching: bool) {
        let directory = temporary_dir();
        let output = directory.join("result");
        let first = verified_bytes(&verified_result());
        let mut other = verified_result();
        if !matching {
            other.payload_sha256 = "c".repeat(64);
        }
        let second = verified_bytes(&other);
        let (ready_send, ready_receive) = mpsc::channel();
        std::thread::scope(|scope| {
            let mut publishers = Vec::new();
            let mut start = Vec::new();
            for bytes in [&first, &second] {
                let (go, wait) = mpsc::channel();
                start.push(go);
                let ready = ready_send.clone();
                let destination = &output;
                publishers.push(scope.spawn(move || {
                    publish_verified(destination, bytes, |file, bytes| {
                        file.write_all(bytes)?;
                        file.sync_all()?;
                        ready.send(()).unwrap();
                        wait.recv_timeout(Duration::from_secs(10))
                            .map_err(std::io::Error::other)?;
                        Ok(())
                    })
                }));
            }
            for _ in 0..2 {
                ready_receive.recv_timeout(Duration::from_secs(10)).unwrap();
            }
            assert!(!output.exists());
            assert_eq!(entries(&directory).len(), 2);
            for sender in start {
                sender.send(()).unwrap();
            }
            let outcomes = publishers
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(
                outcomes.iter().filter(|result| result.is_ok()).count(),
                if matching { 2 } else { 1 }
            );
            let winner = outcomes.iter().position(|result| result.is_ok()).unwrap();
            if !matching {
                let error = outcomes.into_iter().find_map(Result::err).unwrap();
                assert!(error
                    .to_string()
                    .contains("differs from the verified result"));
            }
            assert_private_attestation(&output, [&first, &second][winner]);
        });
        assert_eq!(entries(&directory), vec![output]);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn concurrent_publishers_preserve_one_complete_exclusive_attestation() {
        concurrent_publications(false);
    }

    #[test]
    fn concurrent_matching_publishers_reuse_one_complete_attestation() {
        concurrent_publications(true);
    }

    #[test]
    fn failed_proof_never_creates_or_reuses_a_success_file() {
        let directory = temporary_dir();
        let (payload, expected) = inputs();
        let paths = (
            directory.join("payload"),
            directory.join("expected"),
            directory.join("result"),
        );
        std::fs::write(&paths.0, serde_json::to_vec(&payload).unwrap()).unwrap();
        std::fs::write(&paths.1, serde_json::to_vec(&expected).unwrap()).unwrap();
        assert!(verify_files(&paths.0, &paths.1, &paths.2).is_err());
        assert!(!paths.2.exists());
        let bytes = verified_bytes(&verified_result());
        write_private(&paths.2, &bytes);
        let inode = std::fs::metadata(&paths.2).unwrap().ino();
        assert!(verify_files(&paths.0, &paths.1, &paths.2).is_err());
        assert_private_attestation(&paths.2, &bytes);
        assert_eq!(std::fs::metadata(&paths.2).unwrap().ino(), inode);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
