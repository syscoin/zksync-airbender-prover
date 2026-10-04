"""Inert cache source-identity guards; no imports of build helpers or artifact derivation.

These checks bind Rust's expected effective circuit trees to the reviewed source
manifests. They do not execute Rust tests or qualify cached mathematical bodies.
"""

import hashlib
import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
FRI_SOURCE = ROOT / "crates/zksync_os_fri_prover/src/setup_summaries.rs"
SNARK_SOURCE = ROOT / "crates/zksync_os_snark_prover/src/binary_commitment.rs"
COMMITMENT = ROOT / "crates/zksync_os_snark_prover/artifacts/syscoin-v32-security100-commitment.json"


def constant(source, name):
    values = re.findall(
        rf'^const {re.escape(name)}: &str =\s*"([0-9a-f]{{40}})";$',
        source,
        re.MULTILINE,
    )
    if len(values) != 1:
        raise AssertionError(f"expected one literal circuit identity {name}")
    return values[0]


def strict_struct(source, name):
    values = re.findall(
        rf'#\[serde\(deny_unknown_fields\)\]\nstruct {re.escape(name)} \{{(.*?)\n\}}',
        source,
        re.DOTALL,
    )
    if len(values) != 1:
        raise AssertionError(f"expected one strict metadata struct {name}")
    return values[0]


def hash_constant(source, name):
    values = re.findall(
        rf'^const {re.escape(name)}: &str =\s*"(0x[0-9a-f]{{64}})";$',
        source,
        re.MULTILINE,
    )
    if len(values) != 1:
        raise AssertionError(f"expected one literal proving identity {name}")
    return values[0]


def words_constant(source, name):
    values = re.findall(
        rf'^const {re.escape(name)}: \[u32; 8\] = \[(.*?)\];$',
        source,
        re.MULTILINE | re.DOTALL,
    )
    if len(values) != 1:
        raise AssertionError(f"expected one end-parameter array {name}")
    return [int(word.strip(), 0) for word in values[0].split(",") if word.strip()]


class CacheProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fri = FRI_SOURCE.read_text()
        cls.snark = SNARK_SOURCE.read_text()
        cls.airbender = json.loads(
            (ROOT / "patches/airbender-cuda-device-diagnostics.json").read_text()
        )
        cls.wrapper = json.loads(
            (ROOT / "patches/zkos-wrapper-buffered-os-rng.json").read_text()
        )
        cls.commitment = json.loads(COMMITMENT.read_text())

    def test_upstream_revisions_remain_origin_pins(self):
        for source in (self.fri, self.snark):
            self.assertEqual(
                constant(source, "AIRBENDER_REVISION"),
                self.airbender["upstream_commit"],
            )
        self.assertEqual(
            constant(self.snark, "WRAPPER_CIRCUIT_REVISION"),
            self.wrapper["upstream_commit"],
        )

    def test_effective_airbender_tree_matches_reviewed_manifest_in_both_caches(self):
        tree = self.airbender["patched_tree"]
        self.assertRegex(tree, r"^[0-9a-f]{40}$")
        self.assertNotEqual(tree, self.airbender["upstream_tree"])
        for source in (self.fri, self.snark):
            self.assertEqual(constant(source, "AIRBENDER_PATCHED_TREE"), tree)
            self.assertIn("self.airbender_patched_tree == AIRBENDER_PATCHED_TREE", source)
        self.assertIn(
            "airbender_patched_tree: AIRBENDER_PATCHED_TREE.to_owned()", self.fri
        )

    def test_effective_wrapper_tree_matches_reviewed_manifest_in_snark_cache(self):
        tree = self.wrapper["patched_tree"]
        self.assertRegex(tree, r"^[0-9a-f]{40}$")
        self.assertNotEqual(tree, self.wrapper["upstream_tree"])
        self.assertEqual(constant(self.snark, "WRAPPER_CIRCUIT_PATCHED_TREE"), tree)
        self.assertIn(
            "self.wrapper_circuit_patched_tree == WRAPPER_CIRCUIT_PATCHED_TREE",
            self.snark,
        )

    def test_schema_two_tree_fields_are_required_and_fail_closed(self):
        for source, struct_name, fields in (
            (self.fri, "Metadata", ("airbender_patched_tree",)),
            (
                self.snark,
                "Artifact",
                ("airbender_patched_tree", "wrapper_circuit_patched_tree"),
            ),
        ):
            body = strict_struct(source, struct_name)
            self.assertNotIn("serde(default", body)
            for field in fields:
                self.assertRegex(body, rf"(?m)^    {field}: String,$")
            self.assertIn("self.schema_version == 2", source)
            self.assertNotIn("self.schema_version == 1", source)
        self.assertIn("schema_version: 2,", self.fri)
        self.assertIn("self == &canonical_metadata()", self.fri)

    def test_rust_rejections_cover_old_schema_wrong_and_missing_trees(self):
        self.assertIn(
            "fn old_schema_and_wrong_effective_source_tree_fail_closed()", self.fri
        )
        self.assertIn("old_schema.schema_version = 1;", self.fri)
        self.assertIn('wrong_tree.airbender_patched_tree = "0".repeat(40);', self.fri)
        self.assertIn('.remove("airbender_patched_tree")', self.fri)
        self.assertIn(
            "fn old_schema_and_wrong_effective_source_trees_fail_closed()", self.snark
        )
        self.assertIn('old_schema["schema_version"] = json!(1);', self.snark)
        self.assertIn(
            'for field in ["airbender_patched_tree", "wrapper_circuit_patched_tree"]',
            self.snark,
        )
        self.assertIn('wrong_tree[field] = json!("0".repeat(40));', self.snark)
        self.assertIn("missing_tree.as_object_mut().unwrap().remove(field);", self.snark)

    def test_commitment_artifact_binds_effective_source_trees_and_origins(self):
        artifact = self.commitment
        self.assertEqual(artifact["schema_version"], 2)
        for field, pins, pin_field in (
            ("airbender_revision", self.airbender, "upstream_commit"),
            ("wrapper_circuit_revision", self.wrapper, "upstream_commit"),
            ("airbender_patched_tree", self.airbender, "patched_tree"),
            ("wrapper_circuit_patched_tree", self.wrapper, "patched_tree"),
        ):
            self.assertEqual(artifact[field], pins[pin_field])

    def test_active_registry_loaders_and_diagnostic_share_measured_identity(self):
        artifact = self.commitment
        protocol = (ROOT / "crates/protocol_version/src/lib.rs").read_text()
        diagnostic = (
            ROOT / "crates/zksync_os_snark_prover/examples/syscoin_sustained_snark.rs"
        ).read_text()
        for source, vk_name, program_name in (
            (self.fri, "VK_HASH", "PROGRAM_COMMITMENT"),
            (diagnostic, "VK", "PROGRAM"),
        ):
            self.assertEqual(hash_constant(source, vk_name), artifact["vk_hash"])
            self.assertEqual(hash_constant(source, program_name), artifact["program_commitment"])
        self.assertEqual(hash_constant(protocol, "SYSCOIN_VK_HASH"), artifact["vk_hash"])
        matches = re.findall(
            r"const SYSCOIN_PROGRAM_COMMITMENT: ProgramCommitment = ProgramCommitment\(\[(.*?)\]\);",
            protocol,
            re.DOTALL,
        )
        self.assertEqual(len(matches), 1)
        words = [int(word.strip(), 0) for word in matches[0].split(",") if word.strip()]
        self.assertEqual(words, artifact["aux_params"])
        self.assertEqual(
            "0x" + "".join(f"{word:08x}" for word in words), artifact["program_commitment"]
        )
        for source in (self.fri, self.snark):
            self.assertEqual(words_constant(source, "UNIFIED_END_PARAMS"), artifact["end_params"])

    def test_measured_guest_identities_match_reviewed_recursive_postimages(self):
        for identity, layer in (("recursion_unrolled", "unrolled"), ("recursion_unified", "unified")):
            for section, suffix in (("bin", "bin"), ("text", "text")):
                relative = f"tools/verifier/recursion_in_{layer}_layer_security_100_bits.{suffix}"
                pinned = self.airbender["changed_files"][relative]
                file_identity = self.commitment[identity][section]
                self.assertEqual(file_identity["sha256"], pinned["postimage_sha256"])
                self.assertEqual(file_identity["size_bytes"], pinned["postimage_size"])
                self.assertIn('"' + file_identity["sha256"] + '"', self.fri)
        for section, relative in (("bin", "multiblock_batch.bin"), ("text", "multiblock_batch.text")):
            raw = (ROOT / relative).read_bytes()
            self.assertEqual(self.commitment["app"][section], {
                "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw),
            })


if __name__ == "__main__":
    unittest.main()
