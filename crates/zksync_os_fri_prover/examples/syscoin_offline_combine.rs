//! Opt-in real two-batch combine diagnostic; no worker leases or release-gate changes.
use anyhow::{ensure, Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;
use zksync_airbender_cli::prover_utils::{
    verify_artifact, CarriedChainCombiner, ProgramSource, ProofArtifact, ProofTarget, SecurityLevel,
};
#[cfg(feature = "gpu")]
use zksync_airbender_cli::prover_utils::{GpuConfig, GpuMemoryPreset};
use zksync_airbender_execution_utils::unified_circuit::compute_combined_recursion_layers_output;

const MAX_METADATA_BYTES: usize = 1024 * 1024;
const MAX_PROGRAM_BYTES: usize = 64 * 1024 * 1024;
const MAX_PROOF_BYTES: usize = 384 * 1024 * 1024;

#[derive(Parser)]
#[command(
    about = "Offline two-batch carried-chain combine; no leases, SNARK execution, or promotion"
)]
struct Args {
    #[arg(long)]
    manifest: PathBuf,
    /// Trusted external handoff hash, not inferred from the same untrusted file.
    #[arg(long)]
    manifest_sha256: String,
    #[arg(long)]
    bin: PathBuf,
    #[arg(long)]
    text: PathBuf,
    /// Must not exist; failed output directories remain evidence and must not be reused.
    #[arg(long)]
    output_dir: PathBuf,
    #[arg(long, default_value_t = 8)]
    gpu_replay_threads: usize,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    proof: PathBuf,
    proof_sha256: String,
    metadata: PathBuf,
    metadata_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CombineManifest {
    schema_version: u32,
    app_bin_sha256: String,
    app_text_sha256: String,
    expected_security100_program_commitment: String,
    from_batch_number: u64,
    to_batch_number: u64,
    expected_combined_public_input_hash: String,
    // Deliberately exactly two: a real range, never a duplicated single-proof shortcut.
    inputs: [Input; 2],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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
    let value = if prefixed {
        value.strip_prefix("0x").context("expected 0x hash")?
    } else {
        value
    };
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "expected 64 lowercase hexadecimal digits"
    );
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(bytes)
}

fn check_hash(bytes: &[u8], expected: &str) -> Result<()> {
    decode_hash(expected, false)?;
    ensure!(hash_hex(bytes) == expected, "input SHA-256 mismatch");
    Ok(())
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= maximum as u64,
        "input is not a bounded regular file"
    );
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= maximum, "input grew past its bound");
    Ok(bytes)
}

fn registers(public: &str, commitment: &str) -> Result<[u32; 16]> {
    let public = decode_hash(public, true)?;
    let commitment = decode_hash(commitment, true)?;
    ensure!(commitment != [0; 32], "zero program commitment");
    let mut result = [0; 16];
    for (index, chunk) in public.chunks_exact(4).enumerate() {
        result[index] = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    for (index, chunk) in commitment.chunks_exact(4).enumerate() {
        result[index + 8] = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    Ok(result)
}

fn context_u64(metadata: &Metadata, key: &str) -> Result<u64> {
    metadata
        .context
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .with_context(|| format!("missing numeric witness context {key}"))
}

fn context_hash(metadata: &Metadata, key: &str) -> Result<[u8; 32]> {
    decode_hash(
        metadata
            .context
            .get(key)
            .and_then(serde_json::Value::as_str)
            .with_context(|| format!("missing witness context hash {key}"))?,
        true,
    )
}

fn check_sequence(manifest: &CombineManifest, metadata: &[Metadata; 2]) -> Result<()> {
    ensure!(manifest.schema_version == 1, "unsupported combine schema");
    ensure!(
        manifest.from_batch_number > 0
            && manifest.from_batch_number.checked_add(1) == Some(manifest.to_batch_number),
        "expected exactly two consecutive positive batch numbers"
    );
    ensure!(
        manifest.inputs[0].proof_sha256 != manifest.inputs[1].proof_sha256
            && manifest.inputs[0].metadata_sha256 != manifest.inputs[1].metadata_sha256,
        "duplicate proof or metadata identity"
    );
    ensure!(
        metadata[0].prover_input_sha256 != metadata[1].prover_input_sha256
            && metadata[0].expected_public_input_hash != metadata[1].expected_public_input_hash,
        "duplicate witness or public input"
    );
    for (index, item) in metadata.iter().enumerate() {
        ensure!(
            item.schema_version == 1 && item.prover_input_words > 0,
            "invalid witness schema or word count"
        );
        ensure!(
            item.batch_id == manifest.from_batch_number + index as u64,
            "nonconsecutive witness batch ID"
        );
        ensure!(
            item.app_bin_sha256 == manifest.app_bin_sha256
                && item.app_text_sha256 == manifest.app_text_sha256
                && item.expected_security100_program_commitment
                    == manifest.expected_security100_program_commitment,
            "witness guest identity mismatch"
        );
        decode_hash(&item.prover_input_sha256, false)?;
        registers(
            &item.expected_public_input_hash,
            &item.expected_security100_program_commitment,
        )?;
        ensure!(
            context_u64(item, "security_bits")? == 100,
            "wrong witness security level"
        );
        ensure!(
            context_u64(item, "first_block_number")? <= context_u64(item, "last_block_number")?,
            "invalid witness block range"
        );
    }
    for key in [
        "chain_id",
        "sl_chain_id",
        "protocol_version",
        "proving_version",
        "execution_version",
        "pubdata_mode",
        "genesis_sha256",
        "guest_source_tree",
        "compact_da_commit_target",
        "chain_config_hash",
    ] {
        let first = metadata[0]
            .context
            .get(key)
            .with_context(|| format!("missing context {key}"))?;
        ensure!(
            !first.is_null() && metadata[1].context.get(key) == Some(first),
            "witness context differs at {key}"
        );
    }
    ensure!(
        context_u64(&metadata[0], "last_block_number")?.checked_add(1)
            == Some(context_u64(&metadata[1], "first_block_number")?),
        "witness block ranges are not contiguous"
    );
    ensure!(
        context_hash(&metadata[0], "state_after")? == context_hash(&metadata[1], "state_before")?,
        "witness state roots are not contiguous"
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

fn gpu_combiner(replay_threads: usize) -> Result<CarriedChainCombiner> {
    #[cfg(feature = "gpu")]
    {
        Ok(CarriedChainCombiner::new_gpu(
            SecurityLevel::Security100,
            GpuConfig {
                replay_worker_threads_count: replay_threads,
                // Upstream's combiner uses its measured 21,820-MiB Normal arena, not Auto.
                memory_preset: GpuMemoryPreset::Normal,
            },
        ))
    }
    #[cfg(not(feature = "gpu"))]
    {
        let _ = replay_threads;
        anyhow::bail!("build this example with --features gpu")
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    zksync_os_fri_prover::init_tracing();
    ensure!(
        cfg!(feature = "gpu") && args.gpu_replay_threads > 0,
        "GPU build and positive replay thread count required"
    );
    let manifest_bytes = read_bounded(&args.manifest, MAX_METADATA_BYTES)?;
    check_hash(&manifest_bytes, &args.manifest_sha256)?;
    let manifest: CombineManifest = serde_json::from_slice(&manifest_bytes)?;
    let expected = registers(
        &manifest.expected_combined_public_input_hash,
        &manifest.expected_security100_program_commitment,
    )?;
    let bin = read_bounded(&args.bin, MAX_PROGRAM_BYTES)?;
    let text = read_bounded(&args.text, MAX_PROGRAM_BYTES)?;
    ensure!(
        !bin.is_empty() && !text.is_empty() && bin.len() % 4 == 0 && text.len() % 4 == 0,
        "invalid program sections"
    );
    check_hash(&bin, &manifest.app_bin_sha256)?;
    check_hash(&text, &manifest.app_text_sha256)?;
    let mut metadata_bytes = Vec::new();
    let mut proof_bytes = Vec::new();
    let mut artifacts = Vec::new();
    let mut metadata = Vec::new();
    for input in &manifest.inputs {
        ensure!(
            input.proof.is_absolute() && input.metadata.is_absolute(),
            "input paths must be absolute"
        );
        let proof = read_bounded(&input.proof, MAX_PROOF_BYTES)?;
        let witness = read_bounded(&input.metadata, MAX_METADATA_BYTES)?;
        check_hash(&proof, &input.proof_sha256)?;
        check_hash(&witness, &input.metadata_sha256)?;
        artifacts.push(serde_json::from_slice::<ProofArtifact>(&proof)?);
        metadata.push(serde_json::from_slice::<Metadata>(&witness)?);
        metadata_bytes.push(witness);
        proof_bytes.push(proof);
    }
    let metadata: [Metadata; 2] = metadata
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected two metadata inputs"))?;
    check_sequence(&manifest, &metadata)?;
    for (index, artifact) in artifacts.iter().enumerate() {
        ensure!(
            artifact.batch_id == metadata[index].batch_id,
            "artifact batch ID differs from witness"
        );
    }
    private_directory(&args.output_dir)?;
    let staged = args.output_dir.join("inputs");
    private_directory(&staged)?;
    write_new(&staged.join("app.bin"), &bin)?;
    write_new(&staged.join("app.text"), &text)?;
    write_new(&staged.join("combine-manifest.json"), &manifest_bytes)?;
    for index in 0..2 {
        write_new(
            &staged.join(format!("metadata-{index}.json")),
            &metadata_bytes[index],
        )?;
        write_new(
            &staged.join(format!("proof-{index}.json")),
            &proof_bytes[index],
        )?;
    }
    drop((bin, text, proof_bytes, metadata_bytes));
    let source = ProgramSource::from_paths(
        staged
            .join("app.bin")
            .to_str()
            .context("non-UTF8 output path")?
            .to_owned(),
        None,
    );
    let verify_inputs = Instant::now();
    let mut outputs = Vec::new();
    for (index, artifact) in artifacts.iter().enumerate() {
        let output = verify_artifact(
            artifact,
            &source,
            SecurityLevel::Security100,
            ProofTarget::RecursionUnified,
        )
        .map_err(anyhow::Error::msg)?;
        ensure!(
            output
                == registers(
                    &metadata[index].expected_public_input_hash,
                    &manifest.expected_security100_program_commitment
                )?,
            "input proof does not match its native witness"
        );
        outputs.push(output);
    }
    ensure!(
        compute_combined_recursion_layers_output(&outputs) == expected,
        "trusted combined output differs from canonical input-output hash"
    );
    let verify_inputs_ms = verify_inputs.elapsed().as_millis();
    // Same real carried-chain flow as production merge_fris, without inventing a lease.
    let mut combiner = gpu_combiner(args.gpu_replay_threads)?;
    let warm_up = Instant::now();
    combiner.warm_up();
    let warm_up_ms = warm_up.elapsed().as_millis();
    let combine_start = Instant::now();
    let combined = combiner.combine(&artifacts).map_err(anyhow::Error::msg)?;
    let combine_ms = combine_start.elapsed().as_millis();
    drop(combiner);
    let verify_start = Instant::now();
    let actual = verify_artifact(
        &combined,
        &source,
        SecurityLevel::Security100,
        ProofTarget::RecursionCombined,
    )
    .map_err(anyhow::Error::msg)?;
    ensure!(
        actual == expected,
        "combined proof output differs from trusted output"
    );
    let raw_registers: [u32; 16] =
        std::array::from_fn(|index| combined.proof.register_final_values[10 + index].value);
    ensure!(
        raw_registers == expected,
        "combined raw registers do not satisfy wrapper public-input/aux contract"
    );
    let combined_bytes = serde_json::to_vec(&combined)?;
    // Typed serialization is lossless for all u64 proof fields; never mutate registers.
    let raw_bytes = serde_json::to_vec(&combined.proof)?;
    let result = serde_json::json!({
        "schema_version": 1,
        "status": "verified_offline_combined_candidate",
        "qualification": "real two-batch combination only; not SNARK, server API, deployment, throughput, or actual 24GB qualification",
        "manifest_sha256": args.manifest_sha256,
        "security_level": 100, "target": "recursion-combined",
        "proof_sha256": hash_hex(&combined_bytes), "raw_proof_sha256": hash_hex(&raw_bytes),
        "verified_registers": actual, "wrapper_raw_registers": raw_registers,
        "input_verified_registers": outputs,
        "verify_inputs_ms": verify_inputs_ms, "warm_up_ms": warm_up_ms,
        "combine_ms": combine_ms, "verify_ms": verify_start.elapsed().as_millis(),
        "gpu_replay_threads": args.gpu_replay_threads,
        "gpu_memory_policy": "upstream combiner fixed 21820-MiB Normal arena",
        "artifact_timings_ms": combined.timings_ms, "proof_counts": combined.proof_counts,
        "combine_manifest": manifest, "input_metadata": metadata,
    });
    write_new(
        &args.output_dir.join("combined-proof.json"),
        &combined_bytes,
    )?;
    write_new(&args.output_dir.join("snark-input.json"), &raw_bytes)?;
    write_new(
        &args.output_dir.join("COMBINED_VERIFIED.json"),
        &serde_json::to_vec_pretty(&result)?,
    )?;
    println!("SUCCESS: verified real two-batch Security100 combination; wrapper raw aux/public-input bindings checked");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (CombineManifest, [Metadata; 2]) {
        let context = serde_json::json!({
            "security_bits": 100, "chain_id": 57057, "sl_chain_id": 57001,
            "protocol_version": "v32.0", "proving_version": 8, "execution_version": 7,
            "pubdata_mode": "RelayedL2Calldata", "genesis_sha256": "a".repeat(64),
            "guest_source_tree": "b".repeat(40), "compact_da_commit_target": "c".repeat(40),
            "chain_config_hash": "d".repeat(64), "first_block_number": 1, "last_block_number": 1,
            "state_before": format!("0x{}", "3".repeat(64)), "state_after": format!("0x{}", "4".repeat(64))
        }).as_object().unwrap().clone();
        let first = Metadata {
            schema_version: 1,
            app_bin_sha256: "1".repeat(64),
            app_text_sha256: "2".repeat(64),
            prover_input_sha256: "3".repeat(64),
            prover_input_words: 10,
            batch_id: 1,
            expected_public_input_hash: format!("0x{}", "4".repeat(64)),
            expected_security100_program_commitment: format!("0x{}", "5".repeat(64)),
            context,
        };
        let mut second = first.clone();
        second.batch_id = 2;
        second.prover_input_sha256 = "6".repeat(64);
        second.expected_public_input_hash = format!("0x{}", "7".repeat(64));
        second.context.insert("first_block_number".into(), 2.into());
        second.context.insert("last_block_number".into(), 2.into());
        second
            .context
            .insert("state_before".into(), first.context["state_after"].clone());
        let manifest = CombineManifest {
            schema_version: 1,
            app_bin_sha256: first.app_bin_sha256.clone(),
            app_text_sha256: first.app_text_sha256.clone(),
            expected_security100_program_commitment: first
                .expected_security100_program_commitment
                .clone(),
            from_batch_number: 1,
            to_batch_number: 2,
            expected_combined_public_input_hash: format!("0x{}", "8".repeat(64)),
            inputs: std::array::from_fn(|index| Input {
                proof: format!("/proof-{index}").into(),
                proof_sha256: (index + 1).to_string().repeat(64),
                metadata: format!("/metadata-{index}").into(),
                metadata_sha256: (index + 3).to_string().repeat(64),
            }),
        };
        (manifest, [first, second])
    }

    #[test]
    fn consecutive_distinct_witnesses_are_required() {
        let (manifest, mut metadata) = fixture();
        check_sequence(&manifest, &metadata).unwrap();
        metadata[1].batch_id = 1;
        assert!(check_sequence(&manifest, &metadata).is_err());
        let (mut manifest, metadata) = fixture();
        manifest.inputs[1].proof_sha256 = manifest.inputs[0].proof_sha256.clone();
        assert!(check_sequence(&manifest, &metadata).is_err());
        let (manifest, mut metadata) = fixture();
        metadata[1].prover_input_sha256 = metadata[0].prover_input_sha256.clone();
        assert!(check_sequence(&manifest, &metadata).is_err());
    }

    #[test]
    fn state_chain_and_guest_identity_must_continue() {
        for key in [
            "state_before",
            "chain_id",
            "guest_source_tree",
            "first_block_number",
        ] {
            let (manifest, mut metadata) = fixture();
            metadata[1]
                .context
                .insert(key.into(), serde_json::Value::Null);
            assert!(check_sequence(&manifest, &metadata).is_err(), "{key}");
        }
        let (manifest, mut metadata) = fixture();
        metadata[1].app_bin_sha256 = "9".repeat(64);
        assert!(check_sequence(&manifest, &metadata).is_err());
    }

    #[test]
    fn manifest_requires_exactly_two_inputs_and_rejects_unknown_fields() {
        let (manifest, _) = fixture();
        let mut value = serde_json::to_value(&manifest).unwrap();
        value["inputs"].as_array_mut().unwrap().pop();
        assert!(serde_json::from_value::<CombineManifest>(value).is_err());
        let mut value = serde_json::to_value(&manifest).unwrap();
        value["bypass"] = true.into();
        assert!(serde_json::from_value::<CombineManifest>(value).is_err());
    }

    #[test]
    fn hashes_and_register_endianness_are_strict() {
        let public = format!("0x{}", "01020304".repeat(8));
        let commitment = format!("0x{}", "11223344".repeat(8));
        let words = registers(&public, &commitment).unwrap();
        assert_eq!(words[0], 0x04030201);
        assert_eq!(words[8], 0x11223344);
        assert!(registers(&public, &format!("0x{}", "0".repeat(64))).is_err());
        assert!(decode_hash(&"A".repeat(64), false).is_err());
        assert!(check_hash(b"proof", &"a".repeat(64)).is_err());
    }
}
