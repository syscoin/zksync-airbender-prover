"""Verify the worker's V2 cache inputs without constructing a proof or opening a lease."""
import hashlib
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
PINS = json.loads((ROOT / "patches/v2-proving-sources.json").read_text())
ARTIFACT = json.loads((ROOT / "crates/zksync_os_snark_prover/artifacts/syscoin-v32-security100-commitment.json").read_text())
FRI = (ROOT / "crates/zksync_os_fri_prover/src/setup_summaries.rs").read_text()
SNARK = (ROOT / "crates/zksync_os_snark_prover/src/binary_commitment.rs").read_text()
REGISTRY = (ROOT / "crates/protocol_version/src/lib.rs").read_text()


class CacheProvenanceTests(unittest.TestCase):
    def test_worker_uses_the_authenticated_guest_with_v2_resident_caps(self):
        worker = (ROOT / "crates/zksync_os_fri_prover/src/lib.rs").read_text()
        self.assertIn("setup_summaries::authenticated_program(source)", worker)
        self.assertIn("ProgramSource::from_bytes", FRI)
        self.assertNotIn("syscoin-v32-security100-fri-setups.json", FRI)
        self.assertIn("program_commitment()", worker)

    def test_bundled_wrapper_identity_validates_both_source_trees(self):
        for section, field in (("airbender", "airbender_patched_tree"), ("protocol", "wrapper_circuit_patched_tree")):
            self.assertIn(f"self.{field} == pins.{section}.tree", SNARK)
        self.assertIn('include_str!("../../../patches/v2-proving-sources.json")', SNARK)
        self.assertIn("recursion_end_params(SecurityModel::Security100, RecursionLayer::Unified)", SNARK)
        self.assertIn("program_commitment_for(&self.vk_hash)", SNARK)

    def test_active_worker_registry_binds_the_verified_artifact(self):
        sentinel = "pub const SYSCOIN_VK_HASH: &str = ZERO_VK_HASH;"
        if sentinel in REGISTRY:
            self.assertIn("pub const SYSCOIN_PROGRAM_COMMITMENT: ProgramCommitment = ProgramCommitment([0; 8]);", REGISTRY)
            self.assertIn("unqualified_candidate_advertises_no_registered_lane", REGISTRY)
            return
        self.assertEqual(ARTIFACT["airbender_revision"], PINS["airbender"]["commit"])
        self.assertEqual(ARTIFACT["airbender_patched_tree"], PINS["airbender"]["tree"])
        self.assertEqual(ARTIFACT["wrapper_circuit_revision"], PINS["protocol"]["commit"])
        self.assertEqual(ARTIFACT["wrapper_circuit_patched_tree"], PINS["protocol"]["tree"])
        self.assertEqual(ARTIFACT["wrapper_domain_log"], 22)
        self.assertTrue(ARTIFACT["check_aux_params"])
        self.assertEqual(ARTIFACT["security_bits"], 100)
        self.assertIn(ARTIFACT["vk_hash"], REGISTRY)
        self.assertEqual(ARTIFACT["program_commitment"], "0x" + "".join(f"{word:08x}" for word in ARTIFACT["aux_params"]))
        declared = re.search(r"pub const SYSCOIN_PROGRAM_COMMITMENT:.*?ProgramCommitment\(\[(.+?)\]\)", REGISTRY, re.S)
        self.assertEqual([int(v.strip(), 0) for v in declared.group(1).split(",") if v.strip()], ARTIFACT["aux_params"])

    def test_app_sections_match_the_exact_guest(self):
        for section in ("bin", "text"):
            raw = (ROOT / f"multiblock_batch.{section}").read_bytes()
            self.assertEqual(ARTIFACT["app"][section], {"size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})


if __name__ == "__main__":
    unittest.main()
