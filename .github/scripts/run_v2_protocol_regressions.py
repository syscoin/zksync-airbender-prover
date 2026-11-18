#!/usr/bin/env python3
"""Run dependency unit tests against the exact protocol tree used by the worker."""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
PREPARER = ROOT / "scripts/prepare-v2-proving-sources.py"
spec = importlib.util.spec_from_file_location("v2_source", PREPARER)
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)

PROOF_POLICY_TEST = "cs::implementations::cs::test::prove_simple"

TESTS = {
    "wrapper": ("zkos-wrapper", "zkos-wrapper", ("--no-default-features", "--features", "security_100"), {
        "buffered_os_rng::tests": 5,
        "provided_binary_commitment_skips_derivation": 1,
        "snapshot_skips_other_recursion_programs_before_loading_setups": 1,
        "compression_synthesis_fits_row_budget": 1,
        "from_base_binary_aux_params_fold_depth": 1,
    }),
    "boojum": ("crypto", "boojum", (), {
        "canonical_query_bits_accept_boundaries_and_match_native_indices": 1,
        "opening_precompute_matches_original_constraints_and_native_across_groups": 1,
        PROOF_POLICY_TEST: 1,
        "cs::implementations::cs::test::prove_simple_specialized_with_lookups": 1,
    }),
}


def main(record_path, group):
    receipt = source.base.json_document(Path(record_path))
    pins = source.base.json_document(ROOT / source.PIN_FILE)
    source.base.require(receipt["schema"] == "syscoin-v2-worker-build-v1" and receipt["label"] == "ci-test"
                        and receipt["inputs_reverified"] is True and receipt["cargo_exit_code"] == 0
                        and receipt["sources"] == pins, "invalid worker build receipt")
    protocol = Path(receipt["source_roots"]["protocol"]).resolve(strict=True)
    source.check_checkout(protocol, pins["protocol"])
    directory, package, features, tests = TESTS[group]
    manifest = protocol / directory / "Cargo.toml"
    env = {**os.environ, "CARGO_TARGET_DIR": receipt["cargo_target_dir"]}
    for selector, expected in tests.items():
        command = ["cargo", "test", "--manifest-path", str(manifest), "--locked", "-p", package,
                   *features, "--lib", selector, "--", "--test-threads=1"]
        if selector == PROOF_POLICY_TEST:
            # Several lookup and specialization tests share the prove_simple prefix.
            command.append("--exact")
        output = subprocess.check_output(command, env=env, text=True)
        print(output, flush=True)
        counts = re.findall(r"^test result: ok\. (\d+) passed; 0 failed;", output, re.MULTILINE)
        source.base.require(counts == [str(expected)], f"test count changed for {selector}: {counts}")
    source.check_checkout(protocol, pins["protocol"])


if __name__ == "__main__":
    main(*sys.argv[1:])
