//! Opt-in candidate cryptographic diagnostic, never a production worker or release gate.
use anyhow::{ensure, Context, Result};
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;
use zksync_airbender_cli::prover_utils::{
    verify_artifact, GpuMemoryPreset, ProgramProver, ProgramProverConfig, ProgramSource,
    ProofTarget, ProverBackend, SecurityLevel,
};

const MAX_METADATA_BYTES: usize = 1024 * 1024;
const MAX_PROGRAM_BYTES: usize = 64 * 1024 * 1024;
const MAX_INPUT_BYTES: usize = 384 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
enum MemoryPreset {
    Normal,
    Low,
}

#[derive(Parser)]
#[command(about = "Offline candidate FRI diagnostic: no leases, submissions, or release promotion")]
struct Args {
    #[arg(long)]
    metadata: PathBuf,
    /// SHA-256 from the trusted witness-generation handoff, not inferred from this file.
    #[arg(long)]
    metadata_sha256: String,
    #[arg(long)]
    bin: PathBuf,
    #[arg(long)]
    text: PathBuf,
    /// Raw little-endian u32 words from real native execution and Merkle witnesses.
    #[arg(long)]
    input: PathBuf,
    /// Must not exist. Failed runs are retained and must not be reused.
    #[arg(long)]
    output_dir: PathBuf,
    /// Explicit preset: Auto is intentionally unavailable for an interpretable comparison.
    #[arg(long, value_enum)]
    gpu_memory_preset: MemoryPreset,
    #[arg(long, default_value_t = 8)]
    gpu_replay_threads: usize,
}

#[derive(Debug, Serialize, Deserialize)]
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
    context: serde_json::Map<String, serde_json::Value>,
}

fn hash_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn decode_hash(value: &str, prefixed: bool) -> Result<[u8; 32]> {
    let hex = if prefixed {
        value
            .strip_prefix("0x")
            .context("expected 0x-prefixed hash")?
    } else {
        value
    };
    ensure!(
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "expected exactly 64 lowercase hexadecimal digits"
    );
    let mut result = [0; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)?;
    }
    Ok(result)
}

fn check_hash(bytes: &[u8], expected: &str, label: &str) -> Result<()> {
    decode_hash(expected, false).with_context(|| format!("invalid {label} SHA-256"))?;
    ensure!(hash_hex(bytes) == expected, "{label} SHA-256 mismatch");
    Ok(())
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= maximum as u64,
        "{} is not a bounded regular file",
        path.display()
    );
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= maximum,
        "{} grew past its bound",
        path.display()
    );
    Ok(bytes)
}

fn input_words(bytes: &[u8], expected_words: u64) -> Result<Vec<u32>> {
    ensure!(
        !bytes.is_empty() && bytes.len() % 4 == 0,
        "input must contain complete, nonempty little-endian u32 words"
    );
    ensure!(
        u64::try_from(bytes.len() / 4)? == expected_words,
        "input word count mismatch"
    );
    Ok(bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect())
}

fn expected_registers(metadata: &Metadata) -> Result<[u32; 16]> {
    ensure!(metadata.schema_version == 1, "unsupported metadata schema");
    ensure!(
        !metadata.context.is_empty(),
        "missing witness provenance context"
    );
    let public_input = decode_hash(&metadata.expected_public_input_hash, true)?;
    let commitment = decode_hash(&metadata.expected_security100_program_commitment, true)?;
    ensure!(
        commitment != [0; 32],
        "zero program commitment is not a candidate identity"
    );
    let mut registers = [0; 16];
    // Public-input hash words follow the server's hash_as_register_values convention.
    for (index, chunk) in public_input.chunks_exact(4).enumerate() {
        registers[index] = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    // Wrapper BinaryCommitment renders each chain word as eight big-endian hex digits.
    for (index, chunk) in commitment.chunks_exact(4).enumerate() {
        registers[index + 8] = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    Ok(registers)
}

fn check_registers(actual: [u32; 16], expected: [u32; 16]) -> Result<()> {
    ensure!(
        actual[..8] == expected[..8],
        "verified proof public input differs from the native witness manifest"
    );
    ensure!(
        actual[8..] == expected[8..],
        "verified proof Security100 program commitment differs from the manifest"
    );
    Ok(())
}

fn private_directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .with_context(|| format!("create fresh directory {}", path.display()))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    zksync_os_fri_prover::init_tracing();
    ensure!(
        cfg!(feature = "gpu"),
        "build this example with --features gpu"
    );
    ensure!(
        args.gpu_replay_threads > 0,
        "GPU replay threads must be positive"
    );
    let metadata_bytes = read_bounded(&args.metadata, MAX_METADATA_BYTES)?;
    check_hash(&metadata_bytes, &args.metadata_sha256, "metadata")?;
    let metadata: Metadata = serde_json::from_slice(&metadata_bytes)?;
    let expected = expected_registers(&metadata)?;
    let bin = read_bounded(&args.bin, MAX_PROGRAM_BYTES)?;
    let text = read_bounded(&args.text, MAX_PROGRAM_BYTES)?;
    let input = read_bounded(&args.input, MAX_INPUT_BYTES)?;
    ensure!(
        !bin.is_empty() && !text.is_empty() && bin.len() % 4 == 0 && text.len() % 4 == 0,
        "program sections must contain complete nonempty u32 words"
    );
    check_hash(&bin, &metadata.app_bin_sha256, "app bin")?;
    check_hash(&text, &metadata.app_text_sha256, "app text")?;
    check_hash(&input, &metadata.prover_input_sha256, "prover input")?;
    let words = input_words(&input, metadata.prover_input_words)?;

    // Freeze the checked bytes under fresh names before the prover reopens its program.
    private_directory(&args.output_dir)?;
    let staged = args.output_dir.join("inputs");
    private_directory(&staged)?;
    write_new(&staged.join("app.bin"), &bin)?;
    write_new(&staged.join("app.text"), &text)?;
    write_new(&staged.join("prover-input.le.bin"), &input)?;
    write_new(&staged.join("metadata.json"), &metadata_bytes)?;
    drop((bin, text, input));
    let source = ProgramSource::from_paths(
        staged
            .join("app.bin")
            .to_str()
            .context("non-UTF8 output path")?
            .to_owned(),
        None,
    );
    let mut config = ProgramProverConfig {
        security_level: SecurityLevel::Security100,
        target: ProofTarget::RecursionUnified,
        backend: ProverBackend::Gpu,
        ..Default::default()
    };
    config.gpu.replay_worker_threads_count = args.gpu_replay_threads;
    config.gpu.memory_preset = match args.gpu_memory_preset {
        MemoryPreset::Normal => GpuMemoryPreset::Normal,
        MemoryPreset::Low => GpuMemoryPreset::Low,
    };
    let setup_start = Instant::now();
    let prover = ProgramProver::new(source.clone(), config).map_err(anyhow::Error::msg)?;
    let setup_ms = setup_start.elapsed().as_millis();
    let actual_commitment = prover
        .program_commitment()
        .context("GPU prover omitted its program commitment")?;
    ensure!(
        actual_commitment == expected[8..],
        "GPU setup program commitment differs from manifest"
    );
    let prove_start = Instant::now();
    let artifact = prover
        .prove_words(metadata.batch_id, words)
        .map_err(anyhow::Error::msg)?;
    let prove_ms = prove_start.elapsed().as_millis();
    let proof_bytes = serde_json::to_vec(&artifact)?;
    let proof_sha256 = hash_hex(&proof_bytes);
    write_new(&args.output_dir.join("proof.json"), &proof_bytes)?;
    // Free resident GPU/host caches before independent verification rebuilds its own setup.
    drop(prover);
    let verify_start = Instant::now();
    let actual = verify_artifact(
        &artifact,
        &source,
        SecurityLevel::Security100,
        ProofTarget::RecursionUnified,
    )
    .map_err(anyhow::Error::msg)?;
    check_registers(actual, expected)?;
    let result = serde_json::json!({
        "status": "verified_offline_candidate",
        "qualification": "candidate cryptography and explicit GPU preset only; not server API, deployment, or actual 24GB hardware qualification",
        "metadata_sha256": args.metadata_sha256,
        "proof_sha256": proof_sha256,
        "security_level": 100,
        "target": "recursion-unified",
        "gpu_memory_preset": args.gpu_memory_preset,
        "gpu_replay_threads": args.gpu_replay_threads,
        "setup_ms": setup_ms,
        "prove_wall_ms": prove_ms,
        "verify_ms": verify_start.elapsed().as_millis(),
        "artifact_timings_ms": artifact.timings_ms,
        "proof_counts": artifact.proof_counts,
        "cycles": artifact.cycles,
        "verified_registers": actual,
        "metadata": metadata,
    });
    write_new(
        &args.output_dir.join("VERIFIED.json"),
        &serde_json::to_vec_pretty(&result)?,
    )?;
    println!(
        "SUCCESS: verified real offline Security100 candidate proof; evidence {}",
        args.output_dir.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata() -> Metadata {
        Metadata {
            schema_version: 1,
            app_bin_sha256: "1".repeat(64),
            app_text_sha256: "2".repeat(64),
            prover_input_sha256: "3".repeat(64),
            prover_input_words: 2,
            batch_id: 1,
            expected_public_input_hash: format!("0x{}", "01020304".repeat(8)),
            expected_security100_program_commitment: format!("0x{}", "05060708".repeat(8)),
            context: serde_json::from_value(serde_json::json!({"genesis_sha256": "4".repeat(64)}))
                .unwrap(),
        }
    }

    #[test]
    fn strict_hash_shape_and_content() {
        assert!(decode_hash(&"f".repeat(63), false).is_err());
        assert!(decode_hash(&"F".repeat(64), false).is_err());
        assert!(decode_hash(&"a".repeat(64), true).is_err());
        assert!(check_hash(b"abc", &hash_hex(b"abc"), "test").is_ok());
        assert!(check_hash(b"changed", &hash_hex(b"abc"), "test").is_err());
    }

    #[test]
    fn input_shape_and_count_are_exact() {
        assert_eq!(
            input_words(&[1, 0, 0, 0, 2, 0, 0, 0], 2).unwrap(),
            vec![1, 2]
        );
        assert!(input_words(&[], 0).is_err());
        assert!(input_words(&[1, 2, 3], 0).is_err());
        assert!(input_words(&[1, 0, 0, 0], 2).is_err());
    }

    #[test]
    fn register_endianness_and_both_bindings_are_checked() {
        let expected = expected_registers(&metadata()).unwrap();
        assert_eq!(&expected[..8], &[0x04030201; 8]);
        assert_eq!(&expected[8..], &[0x05060708; 8]);
        assert!(check_registers(expected, expected).is_ok());
        let mut changed = expected;
        changed[0] ^= 1;
        assert!(check_registers(changed, expected)
            .unwrap_err()
            .to_string()
            .contains("public input"));
        changed = expected;
        changed[8] ^= 1;
        assert!(check_registers(changed, expected)
            .unwrap_err()
            .to_string()
            .contains("program commitment"));
    }

    #[test]
    fn schema_context_zero_identity_and_unknown_fields_fail() {
        let mut value = metadata();
        value.schema_version = 2;
        assert!(expected_registers(&value).is_err());
        value = metadata();
        value.context.clear();
        assert!(expected_registers(&value).is_err());
        value = metadata();
        value.expected_security100_program_commitment = format!("0x{}", "0".repeat(64));
        assert!(expected_registers(&value).is_err());
        let mut json = serde_json::to_value(metadata()).unwrap();
        json["security_level"] = 80.into();
        assert!(serde_json::from_value::<Metadata>(json).is_err());
    }

    #[test]
    fn presets_cannot_silently_fall_back_to_auto() {
        assert!(MemoryPreset::from_str("normal", false).is_ok());
        assert!(MemoryPreset::from_str("low", false).is_ok());
        assert!(MemoryPreset::from_str("auto", false).is_err());
    }
}
