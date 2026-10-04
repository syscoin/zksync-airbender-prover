//! A repository-pinned, public BinaryCommitment for the canonical Syscoin app.
//!
//! The two 32-byte arrays are circuit constants, not per-proof randomness or secret
//! setup material. Hashing the exact app and embedded recursion binaries avoids
//! synthesizing three CPU setups on every process start. The JSON is compiled into
//! this crate: it is trusted release data, not an operator-supplied cache. Its hashes
//! bind that trusted data to the current inputs; they do not authenticate a third-party
//! artifact. Callers must still derive and check the actual final wrapper VK against
//! the protocol registry before accepting work.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{ensure, Context};
use clap::ValueEnum;
use protocol_version::{ProgramCommitment, SupportedProtocolVersions};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use verifier_common::SecurityModel;
use zkos_wrapper::circuits::BinaryCommitment;
use zksync_airbender_execution_utils::verifier_binaries::recursion_artifact;
use zksync_airbender_execution_utils::{RecursionArtifact, RecursionLayer};

const BUNDLED_ARTIFACT: &str = include_str!("../artifacts/syscoin-v32-security100-commitment.json");
// Upstream revisions are origins, not effective patched circuit identities.
// These trees are reviewed in the repository's cumulative source manifests.
const AIRBENDER_REVISION: &str = "03454c7a41053a4b88bb421e97fb9efe893a92f5";
const WRAPPER_CIRCUIT_REVISION: &str = "585595f145cb53a09a130706ca36f80ddcac3961";
const AIRBENDER_PATCHED_TREE: &str = "e30d9332b55cbc6a5ea4cae71824e6a5a0858394";
const WRAPPER_CIRCUIT_PATCHED_TREE: &str = "b2697abcd4038e2c107917f4fd03f9832fa8c435";
// The unified-verifier half is pinned independently, just as the app-chain half is
// pinned by protocol_version. Regenerate and review both when the circuit changes.
const UNIFIED_END_PARAMS: [u32; 8] = [
    2585332216, 4028819937, 637847264, 175307493, 775066544, 3052378236, 2233121786, 181571852,
];

/// How a cold wrapper obtains its app-bound circuit constants.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BinaryCommitmentPolicy {
    /// Validate and use the repository's canonical Syscoin commitment (default).
    #[default]
    Bundled,
    /// Derive from the configured app and active verifier binaries; slow, explicit.
    Recompute,
}

impl std::fmt::Display for BinaryCommitmentPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Bundled => "bundled",
            Self::Recompute => "recompute",
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    schema_version: u32,
    protocol_version: u32,
    execution_version: u32,
    proving_version: u32,
    security_bits: u32,
    wrapper_domain_log: u32,
    check_aux_params: bool,
    commitment_algorithm: String,
    airbender_revision: String,
    wrapper_circuit_revision: String,
    airbender_patched_tree: String,
    wrapper_circuit_patched_tree: String,
    vk_hash: String,
    program_commitment: String,
    app: BinaryIdentity,
    recursion_unrolled: BinaryIdentity,
    recursion_unified: BinaryIdentity,
    end_params: [u32; 8],
    aux_params: [u32; 8],
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BinaryIdentity {
    bin: FileIdentity,
    text: FileIdentity,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileIdentity {
    size_bytes: u64,
    sha256: String,
}

impl FileIdentity {
    fn verify(&self, bytes: &[u8], label: &str) -> anyhow::Result<()> {
        ensure!(
            bytes.len() as u64 == self.size_bytes,
            "bundled commitment {label} length mismatch (expected {}, got {})",
            self.size_bytes,
            bytes.len()
        );
        ensure!(
            format!("{:x}", Sha256::digest(bytes)) == self.sha256,
            "bundled commitment {label} SHA-256 mismatch"
        );
        Ok(())
    }

    fn verify_file(&self, path: &Path, label: &str) -> anyhow::Result<()> {
        let file = File::open(path).with_context(|| format!("open {label} {path:?}"))?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file(),
            "{label} is not a regular file: {path:?}"
        );
        ensure!(
            metadata.len() == self.size_bytes,
            "bundled commitment {label} length mismatch for {path:?}"
        );
        // Never accept a prefix if the file grows while being read. The embedded
        // artifact bounds allocation; unknown inputs cannot cause an unbounded read.
        let mut bytes = Vec::new();
        file.take(self.size_bytes + 1).read_to_end(&mut bytes)?;
        self.verify(&bytes, label)
            .with_context(|| format!("configured {label} {path:?}"))
    }
}

impl Artifact {
    fn validate_metadata(&self, active_security_bits: u32) -> anyhow::Result<()> {
        ensure!(
            self.schema_version == 2,
            "unsupported commitment artifact schema"
        );
        ensure!(
            (
                self.protocol_version,
                self.execution_version,
                self.proving_version
            ) == (32, 7, 8),
            "bundled commitment protocol/execution/proving version mismatch"
        );
        ensure!(
            self.security_bits == 100 && active_security_bits == 100,
            "bundled commitment requires the active Security100 wrapper"
        );
        ensure!(
            self.wrapper_domain_log == 25
                && zkos_wrapper::L1_VERIFIER_DOMAIN_SIZE_LOG == 25
                && self.check_aux_params,
            "bundled commitment requires app-bound log-25 wrapper configuration"
        );
        ensure!(
            self.commitment_algorithm == "base-unrolled-unified-v1",
            "bundled commitment algorithm mismatch"
        );
        ensure!(
            self.airbender_revision == AIRBENDER_REVISION
                && self.wrapper_circuit_revision == WRAPPER_CIRCUIT_REVISION,
            "bundled commitment circuit revision mismatch"
        );
        ensure!(
            self.airbender_patched_tree == AIRBENDER_PATCHED_TREE
                && self.wrapper_circuit_patched_tree == WRAPPER_CIRCUIT_PATCHED_TREE,
            "bundled commitment effective circuit source tree mismatch"
        );
        ensure!(
            self.end_params == UNIFIED_END_PARAMS,
            "bundled commitment unified end_params mismatch"
        );
        let versions = SupportedProtocolVersions::default();
        versions
            .ensure_syscoin_release_constants()
            .map_err(anyhow::Error::msg)?;
        ensure!(
            versions.program_commitment_for(&self.vk_hash)
                == Some(ProgramCommitment(self.aux_params)),
            "bundled commitment app aux_params/final VK mismatch with protocol registry"
        );
        ensure!(
            self.program_commitment == ProgramCommitment(self.aux_params).to_string(),
            "bundled commitment program commitment encoding mismatch"
        );
        Ok(())
    }

    fn validate_recursion_binaries(&self) -> anyhow::Result<()> {
        for (layer, identity, label) in [
            (
                RecursionLayer::Unrolled,
                &self.recursion_unrolled,
                "unrolled",
            ),
            (RecursionLayer::Unified, &self.recursion_unified, "unified"),
        ] {
            identity.bin.verify(
                recursion_artifact(SecurityModel::Security100, layer, RecursionArtifact::Bin),
                &format!("{label} recursion binary"),
            )?;
            identity.text.verify(
                recursion_artifact(SecurityModel::Security100, layer, RecursionArtifact::Txt),
                &format!("{label} recursion text"),
            )?;
        }
        Ok(())
    }
}

/// Load only the embedded release artifact and bind it to every current input.
///
/// Unknown or changed apps fail closed; callers may offer an explicit `recompute`
/// policy for development and regeneration, but must not silently fall back to it.
/// This does not replace the caller's actual derived-VK/protocol registration gate.
pub fn load_bundled_commitment(
    bin_path: &Path,
    text_path: &Path,
) -> anyhow::Result<BinaryCommitment> {
    let artifact: Artifact =
        serde_json::from_str(BUNDLED_ARTIFACT).context("parse embedded binary commitment")?;
    artifact.validate_metadata(zkos_wrapper::binary_commitment_security_bits())?;
    artifact.validate_recursion_binaries()?;
    artifact.app.bin.verify_file(bin_path, "app binary")?;
    artifact.app.text.verify_file(text_path, "app text")?;
    Ok(BinaryCommitment {
        end_params: artifact.end_params,
        aux_params: artifact.aux_params,
    })
}

/// Compare a freshly recomputed commitment with the checked-in release artifact.
///
/// This function does not perform the expensive derivation: the regeneration tool
/// must obtain `derived` from `BinaryCommitment::from_base_binary` first. Comparing
/// both arrays is mandatory; matching only the app-chain half is insufficient.
pub fn verify_derived_commitment(
    bin_path: &Path,
    text_path: &Path,
    derived: &BinaryCommitment,
) -> anyhow::Result<()> {
    let bundled = load_bundled_commitment(bin_path, text_path)?;
    ensure!(
        derived.end_params == bundled.end_params && derived.aux_params == bundled.aux_params,
        "freshly derived binary commitment differs from the bundled release artifact"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn artifact() -> Artifact {
        serde_json::from_str(BUNDLED_ARTIFACT).unwrap()
    }

    fn app_paths() -> (std::path::PathBuf, std::path::PathBuf) {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        (
            root.join("multiblock_batch.bin"),
            root.join("multiblock_batch.text"),
        )
    }

    #[test]
    fn bundled_is_default_and_cli_names_are_explicit() {
        assert_eq!(
            BinaryCommitmentPolicy::default(),
            BinaryCommitmentPolicy::Bundled
        );
        assert_eq!(
            BinaryCommitmentPolicy::from_str("bundled", false).unwrap(),
            BinaryCommitmentPolicy::Bundled
        );
        assert_eq!(
            BinaryCommitmentPolicy::from_str("recompute", false).unwrap(),
            BinaryCommitmentPolicy::Recompute
        );
        assert!(BinaryCommitmentPolicy::from_str("auto", false).is_err());
        assert_eq!(BinaryCommitmentPolicy::Bundled.to_string(), "bundled");
        assert_eq!(BinaryCommitmentPolicy::Recompute.to_string(), "recompute");
    }

    #[test]
    fn current_repository_app_and_embedded_verifiers_match() {
        let (bin, text) = app_paths();
        let commitment = load_bundled_commitment(&bin, &text).unwrap();
        assert_eq!(commitment.end_params, UNIFIED_END_PARAMS);
        assert!(SupportedProtocolVersions::default()
            .supports_program(&ProgramCommitment(commitment.aux_params)));
        verify_derived_commitment(&bin, &text, &commitment).unwrap();
    }

    #[test]
    fn every_metadata_field_is_checked() {
        for (field, wrong) in [
            ("schema_version", json!(1)),
            ("protocol_version", json!(31)),
            ("execution_version", json!(6)),
            ("proving_version", json!(7)),
            ("security_bits", json!(80)),
            ("wrapper_domain_log", json!(24)),
            ("check_aux_params", json!(false)),
            ("commitment_algorithm", json!("base-unrolled-v1")),
            ("airbender_revision", json!("changed")),
            ("wrapper_circuit_revision", json!("changed")),
            ("airbender_patched_tree", json!("0".repeat(40))),
            ("wrapper_circuit_patched_tree", json!("0".repeat(40))),
            ("vk_hash", json!(format!("0x{}", "0".repeat(64)))),
            ("program_commitment", json!(format!("0x{}", "0".repeat(64)))),
        ] {
            let mut value: Value = serde_json::from_str(BUNDLED_ARTIFACT).unwrap();
            value[field] = wrong;
            let changed: Artifact = serde_json::from_value(value).unwrap();
            assert!(
                changed.validate_metadata(100).is_err(),
                "accepted changed {field}"
            );
        }
        assert!(artifact().validate_metadata(80).is_err());
    }

    #[test]
    fn old_schema_and_wrong_effective_source_trees_fail_closed() {
        // Metadata-only fixtures do not qualify cached commitment words or guest
        // bytes. The full bundle tests require regenerated release artifacts.
        let mut canonical: Value = serde_json::from_str(BUNDLED_ARTIFACT).unwrap();
        canonical["schema_version"] = json!(2);
        canonical["airbender_patched_tree"] = json!(AIRBENDER_PATCHED_TREE);
        canonical["wrapper_circuit_patched_tree"] = json!(WRAPPER_CIRCUIT_PATCHED_TREE);
        serde_json::from_value::<Artifact>(canonical.clone())
            .unwrap()
            .validate_metadata(100)
            .unwrap();

        let mut old_schema = canonical.clone();
        old_schema["schema_version"] = json!(1);
        assert!(serde_json::from_value::<Artifact>(old_schema)
            .unwrap()
            .validate_metadata(100)
            .is_err());

        for field in ["airbender_patched_tree", "wrapper_circuit_patched_tree"] {
            let mut wrong_tree = canonical.clone();
            wrong_tree[field] = json!("0".repeat(40));
            assert!(serde_json::from_value::<Artifact>(wrong_tree)
                .unwrap()
                .validate_metadata(100)
                .is_err());

            let mut missing_tree = canonical.clone();
            missing_tree.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<Artifact>(missing_tree).is_err());
        }
    }

    #[test]
    fn every_commitment_word_is_checked() {
        for field in ["end_params", "aux_params"] {
            for index in 0..8 {
                let mut value: Value = serde_json::from_str(BUNDLED_ARTIFACT).unwrap();
                let old = value[field][index].as_u64().unwrap();
                value[field][index] = json!(old ^ 1);
                let changed: Artifact = serde_json::from_value(value).unwrap();
                assert!(
                    changed.validate_metadata(100).is_err(),
                    "accepted changed {field}[{index}]"
                );
            }
        }
    }

    #[test]
    fn every_binary_length_and_digest_is_checked() {
        let (bin, text) = app_paths();
        for binary in ["app", "recursion_unrolled", "recursion_unified"] {
            for section in ["bin", "text"] {
                for (field, wrong) in [("size_bytes", json!(1)), ("sha256", json!("0".repeat(64)))]
                {
                    let mut value: Value = serde_json::from_str(BUNDLED_ARTIFACT).unwrap();
                    value[binary][section][field] = wrong;
                    let changed: Artifact = serde_json::from_value(value).unwrap();
                    let result = if binary == "app" {
                        if section == "bin" {
                            changed.app.bin.verify_file(&bin, "app binary")
                        } else {
                            changed.app.text.verify_file(&text, "app text")
                        }
                    } else {
                        changed.validate_recursion_binaries()
                    };
                    assert!(
                        result.is_err(),
                        "accepted changed {binary}.{section}.{field}"
                    );
                }
            }
        }
    }

    #[test]
    fn unexpected_or_missing_schema_fields_are_rejected() {
        for pointer in ["", "/app", "/app/bin"] {
            let mut value: Value = serde_json::from_str(BUNDLED_ARTIFACT).unwrap();
            value
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("unknown".to_owned(), json!(true));
            assert!(serde_json::from_value::<Artifact>(value).is_err());
        }
        let mut value: Value = serde_json::from_str(BUNDLED_ARTIFACT).unwrap();
        value.as_object_mut().unwrap().remove("end_params");
        assert!(serde_json::from_value::<Artifact>(value).is_err());
    }

    #[test]
    fn changed_bytes_and_swapped_app_sections_are_rejected() {
        let (bin, text) = app_paths();
        assert!(load_bundled_commitment(&text, &bin).is_err());
        let manifest = artifact();
        let mut bytes = std::fs::read(bin).unwrap();
        bytes[0] ^= 1;
        assert!(manifest
            .app
            .bin
            .verify(&bytes, "mutated app binary")
            .is_err());
        assert!(manifest
            .app
            .bin
            .verify(&bytes[..bytes.len() - 1], "truncated app binary")
            .is_err());
        let mut bytes = std::fs::read(text).unwrap();
        bytes[0] ^= 1;
        assert!(manifest
            .app
            .text
            .verify(&bytes, "mutated app text")
            .is_err());
    }

    #[test]
    fn missing_app_paths_fail_closed() {
        let (bin, text) = app_paths();
        // A regular file cannot contain a child path, so these paths are guaranteed
        // not to exist without creating or deleting a test fixture.
        assert!(load_bundled_commitment(&bin.join("missing"), &text).is_err());
        assert!(load_bundled_commitment(&bin, &text.join("missing")).is_err());
    }

    #[test]
    fn derived_comparison_checks_both_arrays() {
        let (bin, text) = app_paths();
        let mut derived = load_bundled_commitment(&bin, &text).unwrap();
        derived.end_params[0] ^= 1;
        assert!(verify_derived_commitment(&bin, &text, &derived).is_err());
        derived.end_params[0] ^= 1;
        derived.aux_params[0] ^= 1;
        assert!(verify_derived_commitment(&bin, &text, &derived).is_err());
    }
}
