//! CPU verification for an untrusted rental's exact, ordered V32/V8 candidate payload.
//!
//! The expected file is a trusted controller input: its program commitment must already be
//! authenticated against the registered nonzero VK. This utility authenticates native proof
//! statements; it does not authorize a lease, settlement transaction, or worker program.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
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

fn write_verified(path: &Path, verified: &Verified) -> anyhow::Result<()> {
    ensure!(
        path.is_absolute(),
        "verification output must use an absolute path"
    );
    let mut bytes = serde_json::to_vec(verified)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(path.parent().context("verification output has no parent")?)?.sync_all()?;
    Ok(())
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
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};

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
        let result = Verified {
            schema_version: 1,
            verification: "native_v32_fri_payload",
            payload_sha256: "a".repeat(64),
            expected_sha256: "b".repeat(64),
            vk_hash: format!("0x{}", "11".repeat(32)),
            program_commitment: format!("0x{}", "22".repeat(32)),
            from_batch_number: 1,
            to_batch_number: 2,
            proof_count: 2,
        };
        write_verified(&output, &result).unwrap();
        assert_eq!(
            std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(write_verified(&output, &result).is_err());
        assert!(write_verified(&link, &result).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn failed_proof_never_creates_a_success_file() {
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
        std::fs::remove_dir_all(directory).unwrap();
    }
}
