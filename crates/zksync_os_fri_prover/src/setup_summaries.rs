//! Authenticated, repository-bundled compact FRI setup summaries.
//!
//! These are public circuit constants, not witnesses or a trusted setup. A release
//! artifact saves the expensive CPU reconstruction of Merkle caps; normal GPU
//! registration, proving, and program/queue checks remain unchanged. Its digest is
//! a reviewed release pin, not a hash supplied by an untrusted artifact. No runtime
//! file-cache path is accepted and a failed validation never falls back to deriving.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{ensure, Context};
use clap::ValueEnum;
use protocol_version::{ProgramCommitment, SupportedProtocolVersions};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zksync_airbender_cli::prover_utils::SecurityLevel;
use zksync_airbender_execution_utils::setup_summaries::ProgramSetupSummaries;
use zksync_airbender_execution_utils::verifier_binaries::recursion_artifact;
use zksync_airbender_execution_utils::{RecursionArtifact, RecursionLayer};

const BUNDLED_ARTIFACT: &[u8] =
    include_bytes!("../artifacts/syscoin-v32-security100-fri-setups.json");
// Updated only after independent CPU derivation and a complete equality check.
const BUNDLED_ARTIFACT_SHA256: &str =
    "b48932a3f93d761bdc1df9c20e4d32de4462925adbe02843db4f012575b6c3a6";
const MAX_ARTIFACT_BYTES: usize = 1024 * 1024;
const AIRBENDER_REVISION: &str = "03454c7a41053a4b88bb421e97fb9efe893a92f5";
const VK_HASH: &str = "0xc1ab3d6506620ad299672c2c2530e8732ac7bae55cdb9d8cf1fa12355b7388fe";
const PROGRAM_COMMITMENT: &str =
    "0x1be0999eb16ad9235efc3c320a750afa496f7ee4cb9474926decbd539eeea674";
const UNIFIED_END_PARAMS: [u32; 8] = [
    3441797293, 1347312019, 3816093676, 2915098529, 3451555131, 3884046816, 1487615163, 4112950744,
];

/// How a FRI worker obtains the three compact setup summaries.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FriSetupPolicy {
    /// Use only the authenticated repository release artifact (default).
    #[default]
    Bundled,
    /// Explicitly reconstruct all three summaries on CPU; slow, no cache fallback.
    Recompute,
}

impl std::fmt::Display for FriSetupPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Bundled => "bundled",
            Self::Recompute => "recompute",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileIdentity {
    size_bytes: u64,
    sha256: String,
}

impl FileIdentity {
    fn pinned(size_bytes: u64, sha256: &str) -> Self {
        Self {
            size_bytes,
            sha256: sha256.to_owned(),
        }
    }

    fn verify(&self, bytes: &[u8], label: &str) -> anyhow::Result<()> {
        ensure!(
            bytes.len() as u64 == self.size_bytes,
            "bundled FRI setup {label} length mismatch"
        );
        ensure!(
            digest(bytes) == self.sha256,
            "bundled FRI setup {label} SHA-256 mismatch"
        );
        Ok(())
    }

    fn read_verified(&self, path: &Path, label: &str) -> anyhow::Result<Vec<u8>> {
        let file = File::open(path).with_context(|| format!("open {label} {path:?}"))?;
        let metadata = file.metadata()?;
        ensure!(metadata.is_file(), "{label} is not a regular file");
        ensure!(
            metadata.len() == self.size_bytes,
            "bundled FRI setup {label} length mismatch"
        );
        let mut bytes = Vec::new();
        // The release pin bounds allocation; reject a growing file, not just its prefix.
        file.take(self.size_bytes + 1).read_to_end(&mut bytes)?;
        self.verify(&bytes, label)?;
        Ok(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BinaryIdentity {
    bin: FileIdentity,
    text: FileIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    schema_version: u32,
    protocol_version: u32,
    execution_version: u32,
    proving_version: u32,
    security_bits: u32,
    proof_target: String,
    setup_algorithm: String,
    airbender_revision: String,
    circuit_identity: String,
    cap_size: usize,
    num_cosets: usize,
    vk_hash: String,
    program_commitment: String,
    app: BinaryIdentity,
    recursion_unrolled: BinaryIdentity,
    recursion_unified: BinaryIdentity,
}

fn canonical_metadata() -> Metadata {
    Metadata {
        schema_version: 1,
        protocol_version: 32,
        execution_version: 7,
        proving_version: 8,
        security_bits: 100,
        proof_target: "recursion-unified".to_owned(),
        setup_algorithm: "base-unrolled-unified-v1".to_owned(),
        airbender_revision: AIRBENDER_REVISION.to_owned(),
        circuit_identity: "rv32im-unsigned-base/reduced-unrolled/reduced-unified-v1".to_owned(),
        cap_size: 64,
        num_cosets: 2,
        vk_hash: VK_HASH.to_owned(),
        program_commitment: PROGRAM_COMMITMENT.to_owned(),
        app: BinaryIdentity {
            bin: FileIdentity::pinned(
                1329732,
                "0d69bb7bc5207041c737def52d8858bab261b2ccf0afadbf2ceed14aa86d7cf6",
            ),
            text: FileIdentity::pinned(
                1200064,
                "9d999d91bc7422488c58cf6ca1f7f5041c2972065592ffe98bfcb8220ff0009a",
            ),
        },
        recursion_unrolled: BinaryIdentity {
            bin: FileIdentity::pinned(
                2314544,
                "bd9fc269381964d9ef5aa9ce88ee9e078445cd4483093a759508025e5a5b9bd2",
            ),
            text: FileIdentity::pinned(
                2274080,
                "63fddaddb77f57f802548e46ffe15a0a90d7fa6537c14ca3cda023e0959b1a03",
            ),
        },
        recursion_unified: BinaryIdentity {
            bin: FileIdentity::pinned(
                1273464,
                "20d40ba936d428019be8e9ecfee1a237e7bf68f942bce8be0d0183ece4e6ff80",
            ),
            text: FileIdentity::pinned(
                1241576,
                "3ef1dc44c5361f4a5f2811d56487c6e6434e153baa5a246aaf39f7541fee3060",
            ),
        },
    }
}

impl Metadata {
    fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self == &canonical_metadata(),
            "bundled FRI setup metadata does not match the canonical release identities"
        );
        ensure!(
            zksync_airbender_execution_utils::setups::CAP_SIZE == self.cap_size
                && zksync_airbender_execution_utils::setups::NUM_COSETS == self.num_cosets,
            "bundled FRI setup compiled cap/coset geometry mismatch"
        );
        let versions = SupportedProtocolVersions::default();
        versions
            .ensure_syscoin_release_constants()
            .map_err(anyhow::Error::msg)?;
        ensure!(
            versions
                .program_commitment_for(&self.vk_hash)
                .map(|p| p.to_string())
                == Some(self.program_commitment.clone()),
            "bundled FRI setup program/VK identity differs from the protocol registry"
        );
        Ok(())
    }

    fn checked_inputs(&self, bin: &Path, text: &Path) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        self.validate()?;
        for (layer, identity, name) in [
            (
                RecursionLayer::Unrolled,
                &self.recursion_unrolled,
                "unrolled",
            ),
            (RecursionLayer::Unified, &self.recursion_unified, "unified"),
        ] {
            for (kind, expected, suffix) in [
                (RecursionArtifact::Bin, &identity.bin, "binary"),
                (RecursionArtifact::Txt, &identity.text, "text"),
            ] {
                expected.verify(
                    recursion_artifact(SecurityLevel::Security100.model(), layer, kind),
                    &format!("{name} recursion {suffix}"),
                )?;
            }
        }
        Ok((
            self.app.bin.read_verified(bin, "app binary")?,
            self.app.text.read_verified(text, "app text")?,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    metadata: Metadata,
    summaries: ProgramSetupSummaries,
}

impl Artifact {
    fn validate_summaries(&self, base_binary: &[u8]) -> anyhow::Result<()> {
        self.metadata.validate()?;
        self.summaries
            .validate(SecurityLevel::Security100.model(), base_binary)
            .map_err(anyhow::Error::msg)
            .context("validate bundled FRI setup structure and derived end parameters")?;
        ensure!(
            self.summaries.recursion_unified.end_params == UNIFIED_END_PARAMS,
            "bundled FRI setup unified end parameters differ from the release pin"
        );
        let commitment = ProgramCommitment(self.summaries.program_commitment());
        ensure!(
            commitment.to_string() == self.metadata.program_commitment
                && SupportedProtocolVersions::default().supports_program(&commitment),
            "bundled FRI setup derived recursion chain differs from the protocol registry"
        );
        Ok(())
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn parse_authenticated(bytes: &[u8]) -> anyhow::Result<Artifact> {
    ensure!(
        bytes.len() <= MAX_ARTIFACT_BYTES,
        "FRI setup artifact exceeds size bound"
    );
    ensure!(
        digest(bytes) == BUNDLED_ARTIFACT_SHA256,
        "bundled FRI setup artifact SHA-256 mismatch"
    );
    serde_json::from_slice(bytes).context("parse bundled FRI setup artifact")
}

/// Validate the release digest, exact input bytes, circuit identities and complete
/// recursion chain before returning compact summaries. This performs no GPU work.
pub fn load_bundled_setup_summaries(
    bin: &Path,
    text: &Path,
) -> anyhow::Result<ProgramSetupSummaries> {
    Ok(load_bundled_setup_summaries_and_program(bin, text)?.0)
}

/// Return the exact authenticated byte snapshots as well as the summaries. GPU
/// construction must consume these bytes without reopening the mutable paths.
pub fn load_bundled_setup_summaries_and_program(
    bin: &Path,
    text: &Path,
) -> anyhow::Result<(ProgramSetupSummaries, Vec<u8>, Vec<u8>)> {
    let artifact = parse_authenticated(BUNDLED_ARTIFACT)?;
    let (binary, text_bytes) = artifact.metadata.checked_inputs(bin, text)?;
    artifact.validate_summaries(&binary)?;
    Ok((artifact.summaries, binary, text_bytes))
}

/// Explicit, expensive CPU-only release generation. Checks canonical input hashes
/// before derivation and returns an authenticated-format artifact, not proof data.
/// The caller must separately review and pin the resulting digest in this source.
pub fn derive_release_artifact(bin: &Path, text: &Path) -> anyhow::Result<Vec<u8>> {
    let metadata = canonical_metadata();
    let (binary, text_bytes) = metadata.checked_inputs(bin, text)?;
    let summaries =
        ProgramSetupSummaries::compute(SecurityLevel::Security100.model(), &binary, &text_bytes);
    let artifact = Artifact {
        metadata,
        summaries,
    };
    artifact.validate_summaries(&binary)?;
    let mut bytes = serde_json::to_vec_pretty(&artifact)?;
    bytes.push(b'\n');
    ensure!(
        bytes.len() <= MAX_ARTIFACT_BYTES,
        "generated FRI setup artifact exceeds size bound"
    );
    Ok(bytes)
}

/// Compare every field and cap word against a freshly derived release artifact.
/// Derivation is deliberately separate so the explicit verification tool must call
/// [`derive_release_artifact`] first. Startup does not call this function.
pub fn verify_derived_release_artifact(
    bin: &Path,
    text: &Path,
    derived: &[u8],
) -> anyhow::Result<()> {
    let bundled = parse_authenticated(BUNDLED_ARTIFACT)?;
    let (binary, _) = bundled.metadata.checked_inputs(bin, text)?;
    bundled.validate_summaries(&binary)?;
    ensure!(
        derived.len() <= MAX_ARTIFACT_BYTES,
        "derived FRI setup artifact exceeds size bound"
    );
    let derived_value: serde_json::Value =
        serde_json::from_slice(derived).context("parse derived FRI setups")?;
    let derived: Artifact = serde_json::from_value(derived_value.clone())?;
    derived.validate_summaries(&binary)?;
    ensure!(
        // Compare original JSON values too: upstream nested types do not all
        // reject unknown fields, and those must not be silently discarded here.
        derived_value == serde_json::to_value(&bundled)?,
        "freshly derived FRI setup summaries differ from the complete bundled artifact"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn app_paths() -> (std::path::PathBuf, std::path::PathBuf) {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        (
            root.join("multiblock_batch.bin"),
            root.join("multiblock_batch.text"),
        )
    }

    fn artifact() -> Artifact {
        parse_authenticated(BUNDLED_ARTIFACT).unwrap()
    }

    #[test]
    fn bundled_is_default_and_policy_names_are_explicit() {
        assert_eq!(FriSetupPolicy::default(), FriSetupPolicy::Bundled);
        for (name, policy) in [
            ("bundled", FriSetupPolicy::Bundled),
            ("recompute", FriSetupPolicy::Recompute),
        ] {
            assert_eq!(FriSetupPolicy::from_str(name, false).unwrap(), policy);
            assert_eq!(policy.to_string(), name);
        }
        assert!(FriSetupPolicy::from_str("auto", false).is_err());
    }

    #[test]
    fn cached_constructor_rejects_cpu_and_nonunified_targets_before_io() {
        use zksync_airbender_cli::prover_utils::{
            ProgramProver, ProgramProverConfig, ProgramSource, ProofTarget, ProverBackend,
        };

        let source = ProgramSource::from_paths(
            "/nonexistent/syscoin-fri-setup-test/app.bin".to_owned(),
            None,
        );
        let summaries = artifact().summaries;
        for backend in [ProverBackend::Cpu, ProverBackend::Gpu] {
            for target in [
                ProofTarget::Base,
                ProofTarget::RecursionUnrolled,
                ProofTarget::RecursionUnified,
                ProofTarget::RecursionCombined,
            ] {
                if backend == ProverBackend::Gpu && target == ProofTarget::RecursionUnified {
                    continue;
                }
                let config = ProgramProverConfig {
                    backend,
                    target,
                    security_level: SecurityLevel::Security100,
                    ..Default::default()
                };
                let error = ProgramProver::new_with_setup_summaries_and_program_bytes(
                    source.clone(),
                    config,
                    summaries.clone(),
                    vec![],
                    vec![],
                )
                .err()
                .expect("unsupported cached construction must fail before IO or GPU setup");
                assert_eq!(
                    error,
                    "setup summaries require GPU backend and recursion-unified target"
                );
            }
        }
        // The legacy CPU constructor remains lazy and accepts the same source
        // without touching nonexistent files or requiring CUDA.
        assert!(ProgramProver::new(
            source,
            ProgramProverConfig {
                backend: ProverBackend::Cpu,
                target: ProofTarget::RecursionUnified,
                security_level: SecurityLevel::Security100,
                ..Default::default()
            }
        )
        .is_ok());
    }

    #[test]
    fn repository_artifact_matches_inputs_and_registered_program_without_deriving() {
        let (bin, text) = app_paths();
        let summaries = load_bundled_setup_summaries(&bin, &text).unwrap();
        assert_eq!(summaries.security_bits, 100);
        assert_eq!(summaries.recursion_unified.end_params, UNIFIED_END_PARAMS);
        assert!(SupportedProtocolVersions::default()
            .supports_program(&ProgramCommitment(summaries.program_commitment())));
        verify_derived_release_artifact(&bin, &text, BUNDLED_ARTIFACT).unwrap();
    }

    #[test]
    fn artifact_corruption_truncation_and_unknown_fields_fail_closed() {
        let mut changed = BUNDLED_ARTIFACT.to_vec();
        changed[0] ^= 1;
        assert!(parse_authenticated(&changed).is_err());
        assert!(parse_authenticated(&BUNDLED_ARTIFACT[..BUNDLED_ARTIFACT.len() - 1]).is_err());
        let mut value: Value = serde_json::from_slice(BUNDLED_ARTIFACT).unwrap();
        value["unrecognized"] = json!(true);
        assert!(serde_json::from_value::<Artifact>(value).is_err());
        let (bin, text) = app_paths();
        let mut value: Value = serde_json::from_slice(BUNDLED_ARTIFACT).unwrap();
        value["summaries"]["base"]["unrecognized"] = json!(true);
        assert!(
            verify_derived_release_artifact(&bin, &text, &serde_json::to_vec(&value).unwrap())
                .is_err()
        );
    }

    #[test]
    fn every_metadata_field_is_release_pinned() {
        let canonical = serde_json::to_value(canonical_metadata()).unwrap();
        for (key, field) in canonical.as_object().unwrap() {
            let mut changed = canonical.clone();
            changed[key] = match field {
                Value::String(_) => json!("changed"),
                Value::Number(_) => json!(0),
                Value::Object(_) => {
                    let mut changed_identity = field.clone();
                    changed_identity["bin"]["sha256"] = json!("0".repeat(64));
                    changed_identity
                }
                _ => panic!("unhandled metadata field {key}"),
            };
            let metadata: Metadata = serde_json::from_value(changed).unwrap();
            assert!(
                metadata.validate().is_err(),
                "accepted changed metadata {key}"
            );
        }
    }

    #[test]
    fn both_sections_of_every_input_are_hash_and_length_bound() {
        let metadata = canonical_metadata();
        let (bin, text) = app_paths();
        let (binary, text_bytes) = metadata.checked_inputs(&bin, &text).unwrap();
        for (identity, bytes) in [
            (&metadata.app.bin, binary.as_slice()),
            (&metadata.app.text, text_bytes.as_slice()),
            (
                &metadata.recursion_unrolled.bin,
                recursion_artifact(
                    SecurityLevel::Security100.model(),
                    RecursionLayer::Unrolled,
                    RecursionArtifact::Bin,
                ),
            ),
            (
                &metadata.recursion_unrolled.text,
                recursion_artifact(
                    SecurityLevel::Security100.model(),
                    RecursionLayer::Unrolled,
                    RecursionArtifact::Txt,
                ),
            ),
            (
                &metadata.recursion_unified.bin,
                recursion_artifact(
                    SecurityLevel::Security100.model(),
                    RecursionLayer::Unified,
                    RecursionArtifact::Bin,
                ),
            ),
            (
                &metadata.recursion_unified.text,
                recursion_artifact(
                    SecurityLevel::Security100.model(),
                    RecursionLayer::Unified,
                    RecursionArtifact::Txt,
                ),
            ),
        ] {
            identity.verify(bytes, "test").unwrap();
            let mut changed = bytes.to_vec();
            changed[0] ^= 1;
            assert!(identity.verify(&changed, "test").is_err());
            assert!(identity.verify(&bytes[..bytes.len() - 1], "test").is_err());
            changed.extend_from_slice(&[0]);
            assert!(identity.verify(&changed, "test").is_err());
        }
    }

    #[test]
    fn summary_order_security_geometry_and_derived_values_are_checked() {
        let (bin, text) = app_paths();
        let (binary, _) = canonical_metadata().checked_inputs(&bin, &text).unwrap();
        let value = serde_json::to_value(artifact()).unwrap();
        let mut swapped = artifact();
        std::mem::swap(
            &mut swapped.summaries.base,
            &mut swapped.summaries.recursion_unrolled,
        );
        assert!(swapped.validate_summaries(&binary).is_err());
        for level in ["base", "recursion_unrolled", "recursion_unified"] {
            for field in [
                "expected_final_pc",
                "binary_hash",
                "end_params",
                "circuit_families_setups",
                "inits_and_teardowns_setup",
            ] {
                let mut changed = value.clone();
                let target = &mut changed["summaries"][level][field];
                match field {
                    "expected_final_pc" => *target = json!(0),
                    "binary_hash" | "end_params" => {
                        target[0] = json!(target[0].as_u64().unwrap() ^ 1)
                    }
                    "circuit_families_setups" => target.as_object_mut().unwrap().clear(),
                    "inits_and_teardowns_setup" => {
                        target.as_array_mut().unwrap().pop().map(|_| ()).unwrap()
                    }
                    _ => unreachable!(),
                }
                if let Ok(changed) = serde_json::from_value::<Artifact>(changed) {
                    assert!(
                        changed.validate_summaries(&binary).is_err(),
                        "accepted changed {level}.{field}"
                    );
                }
            }
        }
        let mut changed = artifact();
        changed.summaries.security_bits = 80;
        assert!(changed.validate_summaries(&binary).is_err());
        let mut changed = artifact();
        changed
            .summaries
            .base
            .circuit_families_setups
            .values_mut()
            .next()
            .unwrap()[0]
            .cap[0][0] ^= 1;
        assert!(changed.validate_summaries(&binary).is_err());
        let mut changed = artifact();
        changed
            .summaries
            .recursion_unified
            .inits_and_teardowns_setup[0]
            .cap[0][0] = 1;
        assert!(changed.validate_summaries(&binary).is_err());
    }
}
