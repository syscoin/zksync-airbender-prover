"""Offline source-overlay guards; no CUDA calls, builds, downloads, or shared-cache writes."""

import copy
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "patched_airbender", ROOT / "scripts/prepare-patched-airbender.py"
)
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)
PINS = HELPER.load_airbender_pins()
CRYPTO_PINS = HELPER.load_crypto_pins()


def parent_lock_bytes():
    """Exact lock from parent488f70ac, reconstructed without requiring Git history in CI."""
    raw = (ROOT / "Cargo.lock").read_bytes()
    for name, removed in (
        ("zksync_os_fri_prover", (b' "sha2 0.10.9",\n',)),
        ("zksync_os_snark_prover", (
            b' "async-trait",\n', b' "base64 0.22.1",\n', b' "bincode 2.0.1",\n', b' "libc",\n',
            b' "riscv_transpiler",\n', b' "sha2 0.10.9",\n', b' "verifier_common",\n',
            b' "zksync_solidity_vk_codegen",\n',
        )),
    ):
        blocks = raw.split(b"[[package]]\n")
        matches = [index for index, block in enumerate(blocks)
                   if block.startswith(('name = "' + name + '"\n').encode())]
        if len(matches) != 1:
            raise AssertionError("parent lock fixture package missing")
        index = matches[0]
        for line in removed:
            if blocks[index].count(line) != 1:
                raise AssertionError("parent lock fixture edge missing")
            blocks[index] = blocks[index].replace(line, b"", 1)
        raw = b"[[package]]\n".join(blocks)
    if hashlib.sha256(raw).hexdigest() != "6dc78e75804154521c118e6210e39ddc5fa6fb23342c7be3dae57fc89834c4d3":
        raise AssertionError("actual parent lock fixture changed")
    return raw


class LockOverlayTests(unittest.TestCase):
    def setUp(self):
        self.canonical = HELPER.read_toml(ROOT / "Cargo.lock")
        self.overlay = HELPER.read_toml(ROOT / "patches/airbender.Cargo.lock")

    def test_exact_checked_in_hashes(self):
        for relative, key in (
            ("Cargo.lock", "canonical_lock_sha256"),
            ("patches/airbender.Cargo.lock", "overlay_lock_sha256"),
            ("patches/airbender-cuda-device-diagnostics.patch", "patch_sha256"),
        ):
            HELPER.checked_hash(ROOT / relative, PINS[key])

    def test_only_complete_common_source_identities_change(self):
        packages = HELPER.audit_lock(self.canonical, self.overlay, PINS)
        self.assertEqual(len(packages), 46)
        self.assertIn("gpu_prover", packages)
        self.assertIn("cli", packages)
        self.assertIn("execution_utils", packages)
        self.assertFalse(any("zksync-airbender" in item.get("source", "")
                             for item in self.overlay["package"]))
        self.assertFalse(any("zkos-wrapper" in item.get("source", "")
                             for item in self.overlay["package"]))
        self.assertFalse(any(item.get("source") == HELPER.CRYPTO_LOCK_SOURCE
                             for item in self.overlay["package"]))

    def test_current_derivation_is_byte_identical_to_reviewed_overlay(self):
        raw, selected = HELPER.selected_lock_overlay(
            ROOT / "Cargo.lock", ROOT / "patches/airbender.Cargo.lock", PINS)
        self.assertEqual(raw, (ROOT / "patches/airbender.Cargo.lock").read_bytes())
        self.assertEqual(selected["canonical_lock_sha256"], PINS["canonical_lock_sha256"])
        self.assertEqual(selected["overlay_lock_sha256"], PINS["overlay_lock_sha256"])
        self.assertEqual(selected["airbender_packages"], HELPER.audit_lock(self.canonical, self.overlay, PINS))
        self.assertEqual(selected["schema_version"], 3)
        self.assertEqual(selected["derivation"], "common-proving-source-identity-only-v3")
        self.assertEqual(selected["zkos_wrapper_packages"],
                         {"circuit_mersenne_field": "0.1.0", "zkos-wrapper": "0.1.0"})
        self.assertEqual(selected["zksync_crypto_packages"], HELPER.CRYPTO_PACKAGES)

    def test_actual_parent_lock_with_separate_current_tooling(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "older-source"
            source.mkdir()
            lock = source / "Cargo.lock"
            lock.write_bytes(parent_lock_bytes())
            raw, selected = HELPER.selected_lock_overlay(lock, ROOT / "patches/airbender.Cargo.lock", PINS)
            old = HELPER.read_toml(lock)
            derived = HELPER.tomllib.loads(raw.decode())
            self.assertEqual(len(HELPER.audit_lock(old, derived, PINS)), 46)
            self.assertNotEqual(selected["canonical_lock_sha256"], PINS["canonical_lock_sha256"])
            self.assertNotEqual(selected["overlay_lock_sha256"], PINS["overlay_lock_sha256"])
            self.assertEqual(lock.read_bytes(), parent_lock_bytes())
            with self.assertRaisesRegex(ValueError, "more than common proving"):
                HELPER.audit_lock(old, self.overlay, PINS)

    def test_parent_lock_fixture_preserves_exact_historical_bytes(self):
        raw = parent_lock_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         "6dc78e75804154521c118e6210e39ddc5fa6fb23342c7be3dae57fc89834c4d3")
        old = HELPER.tomllib.loads(raw.decode())
        package = next(row for row in old["package"] if row["name"] == "zksync_os_snark_prover")
        self.assertNotIn("async-trait", package["dependencies"])
        self.assertNotIn("zksync_solidity_vk_codegen", package["dependencies"])

    def test_selected_incompatible_revision_version_and_reference_drift_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            lock, reference = Path(temporary) / "Cargo.lock", Path(temporary) / "overlay.lock"
            original = parent_lock_bytes()
            for changed in (
                original.replace(b"03454c7a41053a4b88bb421e97fb9efe893a92f5", b"f" * 40),
                original.replace(b'name = "gpu_prover"\nversion = "0.1.0"',
                                 b'name = "gpu_prover"\nversion = "99.0.0"'),
            ):
                lock.write_bytes(changed)
                with self.assertRaises(ValueError):
                    HELPER.selected_lock_overlay(lock, ROOT / "patches/airbender.Cargo.lock", PINS)
            lock.write_bytes(original)
            reference.write_bytes((ROOT / "patches/airbender.Cargo.lock").read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                HELPER.selected_lock_overlay(lock, reference, PINS)

    def test_selected_lock_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            link = Path(temporary) / "Cargo.lock"
            link.symlink_to(ROOT / "Cargo.lock")
            with self.assertRaisesRegex(ValueError, "invalid selected"):
                HELPER.selected_lock_overlay(link, ROOT / "patches/airbender.Cargo.lock", PINS)

    def test_registry_checksum_version_or_dependency_drift_rejected(self):
        for field, value in (("checksum", "0" * 64), ("version", "99.0.0"),
                             ("dependencies", ["unexpected"])):
            with self.subTest(field=field):
                modified = copy.deepcopy(self.overlay)
                registry = next(item for item in modified["package"]
                                if item.get("source", "").startswith("registry+"))
                registry[field] = value
                with self.assertRaisesRegex(ValueError, "more than common proving"):
                    HELPER.audit_lock(self.canonical, modified, PINS)

    def test_crypto_pin_or_wrapper_path_identity_drift_rejected(self):
        for name in ("zksync_bellman", "zkos-wrapper", "circuit_mersenne_field"):
            with self.subTest(name=name):
                modified = copy.deepcopy(self.overlay)
                item = next(item for item in modified["package"] if item["name"] == name)
                item["source"] = item.get("source", HELPER.WRAPPER_LOCK_SOURCE) + "-changed"
                with self.assertRaises(ValueError):
                    HELPER.audit_lock(self.canonical, modified, PINS)

    def test_wrapper_source_version_package_and_partial_overlay_drift_rejected(self):
        for edit in (
            lambda p: p.update(source=p["source"] + "-changed"),
            lambda p: p.update(version="0.2.0"),
            lambda p: p.update(name="unknown-wrapper"),
        ):
            original = copy.deepcopy(self.canonical)
            edit(next(p for p in original["package"] if p["name"] == "zkos-wrapper"))
            with self.assertRaises(ValueError):
                HELPER.audit_lock(original, self.overlay, PINS)
        for name in HELPER.WRAPPER_PACKAGES:
            original = copy.deepcopy(self.canonical)
            original["package"] = [p for p in original["package"] if p["name"] != name]
            with self.assertRaisesRegex(ValueError, "incomplete wrapper"):
                HELPER.audit_lock(original, self.overlay, PINS)
            modified = copy.deepcopy(self.overlay)
            next(p for p in modified["package"] if p["name"] == name)["source"] = HELPER.WRAPPER_LOCK_SOURCE
            with self.assertRaises(ValueError):
                HELPER.audit_lock(self.canonical, modified, PINS)

    def test_partial_overlay_rejected(self):
        modified = copy.deepcopy(self.overlay)
        first = next(item for item in modified["package"] if item["name"] == "gpu_prover")
        first["source"] = PINS["upstream_lock_source"]
        with self.assertRaises(ValueError):
            HELPER.audit_lock(self.canonical, modified, PINS)

    def test_mixed_airbender_pins_rejected(self):
        modified = copy.deepcopy(self.canonical)
        first = next(item for item in modified["package"] if item["name"] == "gpu_prover")
        first["source"] = first["source"].replace("03454c7", "ffffffff")
        with self.assertRaisesRegex(ValueError, "mixed Airbender"):
            HELPER.audit_lock(modified, self.overlay, PINS)

    def test_missing_airbender_package_rejected(self):
        modified = copy.deepcopy(self.canonical)
        modified["package"] = [item for item in modified["package"] if item["name"] != "gpu_prover"]
        with self.assertRaisesRegex(ValueError, "package count"):
            HELPER.audit_lock(modified, self.overlay, PINS)


class CommonCryptoOverlayTests(unittest.TestCase):
    def fixture(self, temporary, pins=None):
        directory = Path(temporary)
        (directory / CRYPTO_PINS["patch_file"]).write_bytes(
            (ROOT / "patches" / CRYPTO_PINS["patch_file"]).read_bytes())
        manifest = directory / HELPER.CRYPTO_PIN_PATH.name
        manifest.write_text(json.dumps(pins or CRYPTO_PINS))
        return manifest

    def test_exact_manifest_and_native_patch_scope(self):
        self.assertEqual(HELPER.load_crypto_pins(), CRYPTO_PINS)
        self.assertEqual(len(CRYPTO_PINS["upstream_packages"]), 11)
        raw = (ROOT / "patches" / CRYPTO_PINS["patch_file"]).read_text()
        sections = raw.split("diff --git ")[1:]
        self.assertEqual(
            {section.splitlines()[0].split()[1][2:] for section in sections},
            set(CRYPTO_PINS["changed_files"]),
        )
        verifier = next(section for section in sections if section.startswith(
            "a/crates/boojum/src/cs/implementations/verifier.rs "))
        added = [line[1:].strip() for line in verifier.splitlines()
                 if line.startswith("+") and not line.startswith("+++")]
        self.assertEqual(added, [
            "use super::prover::ProofConfig;",
            "/// `expected_proof_config` must come from verifier policy, independently of `proof`.",
            "expected_proof_config: &ProofConfig,",
            "if &proof.proof_config != expected_proof_config {",
            'log!("Proof configuration differs from verifier expectation");',
            "return false;",
            "}",
            "",
            "return false;",
        ])
        for text in ("empty FRI query list must fail", "one missing FRI query must fail",
                     "an extra FRI query must fail", "original proof must still verify"):
            self.assertIn(text, raw)

    def test_manifest_unknown_origins_paths_fields_sizes_and_digests_rejected(self):
        edits = (
            lambda p: p.update(schema_version=True),
            lambda p: p.update(upstream_url="https://example.invalid/crypto"),
            lambda p: p.update(upstream_commit="f" * 40),
            lambda p: p.update(upstream_tree="f" * 40),
            lambda p: p.update(upstream_lock_source=HELPER.CRYPTO_LOCK_SOURCE + "-changed"),
            lambda p: p["upstream_packages"].update(boojum="0.32.9"),
            lambda p: p.update(patch_file="../escape.patch"),
            lambda p: p.update(patch_sha256="0" * 64),
            lambda p: p.update(patched_tree="f" * 40),
            lambda p: p["changed_files"].update({"../escape": {}}),
            lambda p: p["changed_files"][next(iter(p["changed_files"]))].update(postimage_size=True),
            lambda p: p["changed_files"][next(iter(p["changed_files"]))].update(preimage_sha256=None),
            lambda p: p.update(unknown="unreviewed"),
        )
        for edit in edits:
            with self.subTest(edit=edit), tempfile.TemporaryDirectory() as temporary:
                pins = copy.deepcopy(CRYPTO_PINS)
                edit(pins)
                with self.assertRaises(ValueError):
                    HELPER.load_crypto_pins(self.fixture(temporary, pins))

    def test_duplicate_keys_symlinks_and_changed_patch_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest = self.fixture(temporary)
            manifest.write_text('{"schema_version":1,"schema_version":1}')
            with self.assertRaisesRegex(ValueError, "duplicate"):
                HELPER.load_crypto_pins(manifest)
            manifest.unlink()
            manifest.symlink_to(HELPER.CRYPTO_PIN_PATH)
            with self.assertRaises(ValueError):
                HELPER.load_crypto_pins(manifest)
        with tempfile.TemporaryDirectory() as temporary:
            manifest = self.fixture(temporary)
            (manifest.parent / CRYPTO_PINS["patch_file"]).write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                HELPER.load_crypto_pins(manifest)

    def test_lock_mixed_missing_duplicate_unknown_version_and_partial_graph_rejected(self):
        canonical = HELPER.read_toml(ROOT / "Cargo.lock")
        overlay = HELPER.read_toml(ROOT / "patches/airbender.Cargo.lock")
        for field, value in (("source", HELPER.CRYPTO_LOCK_SOURCE + "-changed"),
                             ("name", "unknown-crypto"), ("version", "0.32.9")):
            modified = copy.deepcopy(canonical)
            next(p for p in modified["package"] if p["name"] == "boojum")[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                HELPER.audit_lock(modified, overlay, PINS)
        for name in HELPER.CRYPTO_PACKAGES:
            modified = copy.deepcopy(canonical)
            modified["package"] = [p for p in modified["package"] if p["name"] != name]
            with self.subTest(missing=name), self.assertRaisesRegex(ValueError, "incomplete common crypto"):
                HELPER.audit_lock(modified, overlay, PINS)
            partial = copy.deepcopy(overlay)
            next(p for p in partial["package"] if p["name"] == name)["source"] = HELPER.CRYPTO_LOCK_SOURCE
            with self.subTest(partial=name), self.assertRaises(ValueError):
                HELPER.audit_lock(canonical, partial, PINS)
        modified = copy.deepcopy(canonical)
        modified["package"].append(copy.deepcopy(next(p for p in modified["package"] if p["name"] == "boojum")))
        with self.assertRaisesRegex(ValueError, "unknown common crypto"):
            HELPER.audit_lock(modified, overlay, PINS)

    def test_prepare_clones_exact_origin_and_all_packages_without_touching_original(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            build = Path(temporary)
            local = build / "original"
            local.mkdir()
            git = stack.enter_context(patch.object(HELPER, "run_git", side_effect=lambda repo, *args:
                "" if args == ("status", "--porcelain") else CRYPTO_PINS["upstream_tree"]))
            hashes = stack.enter_context(patch.object(HELPER, "checked_hash"))
            verify = stack.enter_context(patch.object(HELPER, "verify_crypto"))
            paths = {name: "crates/" + name for name in HELPER.CRYPTO_PACKAGES}
            stack.enter_context(patch.object(HELPER, "package_paths", return_value=paths))
            run = stack.enter_context(patch.object(HELPER.subprocess, "run"))
            stack.enter_context(patch.dict(HELPER.os.environ, {"ZKSYNC_CRYPTO_SOURCE_DIR": str(local)}, clear=True))
            root, clone, actual = HELPER.prepare_crypto(build, CRYPTO_PINS)
            self.assertEqual(root, build / "zksync-crypto")
            self.assertEqual(clone, str(local.resolve()))
            self.assertEqual(actual, paths)
            self.assertIn("--no-hardlinks", run.call_args.args[0])
            self.assertEqual(list(local.iterdir()), [])
            verify.assert_called_once_with(root, CRYPTO_PINS)
            git.assert_any_call(root, "checkout", "--quiet", "--detach", CRYPTO_PINS["upstream_commit"])
            for relative, row in CRYPTO_PINS["changed_files"].items():
                hashes.assert_any_call(root / relative, row["preimage_sha256"])

    def test_crypto_reverification_rejects_head_tree_paths_untracked_and_late_edits(self):
        pins = copy.deepcopy(CRYPTO_PINS)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative, row in pins["changed_files"].items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(relative.encode())
                row["postimage_sha256"] = HELPER.sha256(path)
                row["postimage_size"] = path.stat().st_size
            values = {
                ("rev-parse", "HEAD"): pins["upstream_commit"],
                ("rev-parse", "HEAD^{tree}"): pins["upstream_tree"],
                ("diff", "--name-only", "HEAD"): "\n".join(sorted(pins["changed_files"])),
                ("ls-files", "--others", "--exclude-standard"): "",
                ("diff", "--name-only"): "",
                ("write-tree",): pins["patched_tree"],
            }
            with patch.object(HELPER, "run_git", side_effect=lambda repo, *args: values[args]):
                HELPER.verify_crypto(root, pins)
                for args in values:
                    original = values[args]
                    values[args] = "unexpected"
                    with self.subTest(args=args), self.assertRaises(ValueError):
                        HELPER.verify_crypto(root, pins)
                    values[args] = original
                row = pins["changed_files"][next(iter(pins["changed_files"]))]
                row["postimage_size"] += 1
                with self.assertRaisesRegex(ValueError, "postimage size mismatch"):
                    HELPER.verify_crypto(root, pins)
                row["postimage_size"] -= 1
                relative = next(iter(pins["changed_files"]))
                source = root / relative
                source.unlink()
                source.symlink_to(HELPER.CRYPTO_PIN_PATH)
                with self.assertRaisesRegex(ValueError, "not a regular input"):
                    HELPER.verify_crypto(root, pins)
                source.unlink()
                source.write_bytes(relative.encode())
                (root / next(iter(pins["changed_files"]))).write_bytes(b"late edit")
                with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                    HELPER.verify_crypto(root, pins)

    def test_pure_metadata_never_invokes_external_commands(self):
        with patch.object(HELPER.subprocess, "run") as run, patch.object(HELPER.subprocess, "check_output") as output:
            metadata = HELPER.crypto_pins_metadata()
            self.assertEqual(metadata["pins"], CRYPTO_PINS)
            self.assertEqual(metadata["manifest_sha256"], HELPER.sha256(HELPER.CRYPTO_PIN_PATH))
            run.assert_not_called()
            output.assert_not_called()


class DiagnosticsPreservationTests(unittest.TestCase):
    def test_logger_patch_has_no_proving_changes(self):
        source = (ROOT / "patches/airbender-cuda-device-diagnostics.patch").read_text()
        self.assertEqual(source.count("diff --git "), 31)
        source = next("diff --git " + section for section in source.split("diff --git ")
                      if section.startswith("a/gpu_prover/src/execution/gpu_worker.rs "))
        # Diff index IDs and hunk context changed when the cumulative patch was
        # regenerated. Every ordered added/removed production line is identical
        # to the historical diagnostics patch, and its full postimage is pinned.
        edits = "\n".join(line for line in source.splitlines()
                          if line.startswith(("+", "-")) and not line.startswith(("+++", "---")))
        self.assertEqual(hashlib.sha256(edits.encode()).hexdigest(),
                         "829c7aeb3aeff7aa135223eb5e38abc15a9f7fb9f2ba81be2cafb19d7b3eaa4a")
        self.assertEqual(PINS["changed_files"]["gpu_prover/src/execution/gpu_worker.rs"]["postimage_sha256"],
                         "3a809535fd15cf2b6a456881c0b9a4dddec606ae0d95ce17c928987dd76aca84")
        additions = "\n".join(line[1:] for line in source.splitlines()
                              if line.startswith("+") and not line.startswith("+++"))
        self.assertIn("device_get_attribute(CudaDeviceAttr::MultiProcessorCount, device_id)?", additions)
        self.assertNotIn("get_device_properties", additions)
        self.assertNotIn("unsafe", additions)
        self.assertNotIn("CStr", additions)


class StreamedInitTeardownPatchTests(unittest.TestCase):
    """Static source-integration guards, not CUDA execution or queue-lag tests."""

    def setUp(self):
        raw = (ROOT / "patches/airbender-cuda-device-diagnostics.patch").read_text()
        sections = raw.split("diff --git ")[1:]
        self.sections = {section.splitlines()[0].split()[1][2:]: section for section in sections}
        self.assertEqual(len(sections), len(self.sections))
        self.module_path = "gpu_prover/src/execution/empty_inits_and_teardowns.rs"
        self.module = self.additions(self.module_path) + "\n"
        self.production = self.module.split("#[cfg(test)]", 1)[0]

    def additions(self, path):
        return "\n".join(line[1:] for line in self.sections[path].splitlines()
                         if line.startswith("+") and not line.startswith("+++"))

    def test_exact_closed_overlay_scope_and_existing_postimages_are_preserved(self):
        expected = {
            "execution_utils/src/lib.rs": "ef863d1a3e09648348e5ff6daddab7469bcb42fa74bd63172459d3a6337f3049",
            "execution_utils/src/setup_summaries.rs": "f88bc6142088e6255b1356e70d031d6557445560984debe2d329d70042ab2b02",
            "execution_utils/src/unrolled_gpu.rs": "13ae69259a2791b8e8a9343da975ba04eb6e0535b4c11143c929a768307a3110",
            "gpu_prover/src/execution/gpu_worker.rs": "3a809535fd15cf2b6a456881c0b9a4dddec606ae0d95ce17c928987dd76aca84",
            "gpu_prover/src/execution/cpu_worker.rs": "9d6a3b83f1148f1bf60394a6c98d713e84733a362cfab3e9b97c49d13165dbbd",
            self.module_path: "412f5d778cef22834c845aa72628e5822ce350fa47fa23816567e3fc88d9003c",
            "gpu_prover/src/execution/simulation_runner.rs": "1d792692fd0f585753b8865dfba68043ba66690066fad2ac6f23620e9105ebc0",
            "tools/cli/src/prover_utils.rs": "8aa93a6fb387d298076012989b1b73069c5883b5b2d1dd2e0014fe563a42e2d8",
        }
        self.assertEqual(set(self.sections), HELPER.AIRBENDER_CHANGED_PATHS)
        self.assertEqual(set(PINS["changed_files"]), HELPER.AIRBENDER_CHANGED_PATHS)
        self.assertEqual(len(self.sections), 31)
        self.assertTrue(set(expected) < set(self.sections))
        for path, digest in expected.items():
            self.assertEqual(PINS["changed_files"][path]["postimage_sha256"], digest)
        self.assertEqual(PINS["patched_tree"], "e30d9332b55cbc6a5ea4cae71824e6a5a0858394")
        self.assertIsNone(PINS["changed_files"][self.module_path]["preimage_sha256"])
        self.assertEqual(hashlib.sha256(self.module.encode()).hexdigest(), expected[self.module_path])
        self.assertEqual(len(self.module.encode()), PINS["changed_files"][self.module_path]["postimage_size"])
        # The original streaming/diagnostic subset remains byte-identical. The
        # cumulative overlay now separately carries security and guest updates.
        self.assertFalse(any(path.startswith(("circuit_defs/", "verifier/", "full_statement_verifier/"))
                             for path in expected))

    def test_per_word_geometry_conservative_monotone_release_and_fail_closed_finish(self):
        self.assertIn("max_it_instances: ram_words.div_ceil(cycles_per_circuit)", self.production)
        self.assertIn("let completed_circuits = cycles_so_far / self.cycles_per_circuit;", self.production)
        self.assertIn("let frontier = completed_circuits.saturating_sub(self.max_it_instances);", self.production)
        self.assertIn("self.next_sequence_id = frontier.max(start);", self.production)
        self.assertIn("start..self.next_sequence_id", self.production)
        self.assertIn("self.next_sequence_id <= empty_circuits", self.production)
        self.assertIn("self.next_sequence_id..empty_circuits", self.production)
        self.assertIn("assert_ne!(cycles_per_circuit, 0);", self.production)
        self.assertIn("const RAM_WORDS: usize = (1 << 30) / size_of::<u32>();", self.module)
        self.assertIn("const CYCLES_PER_CIRCUIT: usize = (1 << 23) - 1;", self.module)
        ram_words, usable_rows = 1 << 28, (1 << 23) - 1
        self.assertEqual((ram_words + usable_rows - 1) // usable_rows, 33)

    def test_unified_only_activation_and_exact_final_marker_suffix(self):
        worker = self.sections["gpu_prover/src/execution/cpu_worker.rs"]
        added = self.additions("gpu_prover/src/execution/cpu_worker.rs")
        self.assertIn("runner.empty_it_streamer = (!T::IS_SPLIT).then(|| {", added)
        self.assertIn("memory_holder.memory.len(),", added)
        self.assertIn("setups::unified_reduced_machine::NUM_CYCLES,", added)
        self.assertIn("let empty_cycles = total_cycles - count;", worker)
        self.assertIn("let empty_circuits = empty_cycles / per_circuit_count;", worker)
        self.assertIn(".finish(empty_circuits);", added)
        self.assertIn("for sequence_id in remaining_empty {", added)
        self.assertIn("-            for sequence_id in 0..empty_circuits {", worker)
        self.assertEqual(added.count("!T::IS_SPLIT"), 1)

    def test_streaming_module_is_wired_before_snapshot_trace_allocation(self):
        runner = self.sections["gpu_prover/src/execution/simulation_runner.rs"]
        added = self.additions("gpu_prover/src/execution/simulation_runner.rs")
        self.assertIn('#[path = "empty_inits_and_teardowns.rs"]', added)
        self.assertIn("pub(crate) use empty_inits_and_teardowns::EmptyInitsAndTeardownsStreamer;", added)
        self.assertIn("empty_it_streamer: None,", added)
        self.assertIn("(self.empty_it_streamer.as_mut(), self.results.as_ref())", added)
        self.assertIn("((timestamp - INITIAL_TIMESTAMP) / TIMESTAMP_STEP) as usize;", added)
        self.assertIn("for sequence_id in streamer.release(cycles_so_far) {", added)
        self.assertIn("inits_and_teardowns: None,", added)
        self.assertIn(".send(WorkerResult::InitsAndTeardownsData(data))", added)
        self.assertLess(runner.index("streamer.release(cycles_so_far)"),
                        runner.index("let trace = self.trace.take().unwrap();"))
        self.assertLess(runner.index("streamer.release(cycles_so_far)"),
                        runner.index("let result = WorkerResult::SnapshotProduced;"))

    def test_dependency_free_regression_coverage_is_retained(self):
        self.assertEqual(self.module.count("#[test]"), 7)
        for name in (
            "pinned_per_word_geometry_has_thirty_three_trailing_instances",
            "partial_circuits_and_repeated_snapshots_do_not_release_early_or_duplicate",
            "all_final_occupancies_preserve_the_original_exact_prefix",
            "delegation_bursts_cannot_exceed_the_ram_word_bound",
            "finite_pool_model_progresses_beyond_forty_six_circuits",
            "split_mode_none_keeps_all_markers_for_finalization",
            "finalization_fails_closed_if_a_future_layout_violates_the_bound",
        ):
            self.assertIn("fn " + name + "()", self.module)
        self.assertIn("const POOL: usize = 384;", self.module)
        self.assertIn("for completed in 1..=160", self.module)
        self.assertIn("streamed unified init/teardown prefix exceeds the final empty prefix", self.module)


class AirbenderPinTests(unittest.TestCase):
    def fixture(self, directory, pins):
        directory = Path(directory)
        manifest = directory / HELPER.PIN_PATH.name
        manifest.write_text(json.dumps(pins))
        for filename in (PINS["patch_file"], PINS["overlay_lock_file"]):
            (directory / filename).write_bytes((ROOT / "patches" / filename).read_bytes())
        return manifest

    def test_exact_source_closure_and_pure_metadata(self):
        with patch.object(HELPER.subprocess, "run") as run, patch.object(HELPER.subprocess, "check_output") as output:
            pins = HELPER.load_airbender_pins()
            self.assertEqual(set(pins["changed_files"]), HELPER.AIRBENDER_CHANGED_PATHS)
            self.assertEqual(pins["patched_tree"], HELPER.AIRBENDER_PATCHED_TREE)
            sections = (ROOT / "patches" / pins["patch_file"]).read_text().split("diff --git ")[1:]
            self.assertEqual({section.splitlines()[0].split()[1][2:] for section in sections},
                             HELPER.AIRBENDER_CHANGED_PATHS)
            run.assert_not_called()
            output.assert_not_called()

    def test_fri_release_artifact_binds_locked_source_circuits_and_security(self):
        artifact_path = ROOT / "crates/zksync_os_fri_prover/artifacts/syscoin-v32-security100-fri-setups.json"
        artifact = HELPER.json_document(artifact_path)
        metadata, summaries = artifact["metadata"], artifact["summaries"]
        loader = (ROOT / "crates/zksync_os_fri_prover/src/setup_summaries.rs").read_text()
        integration = (ROOT / "crates/zksync_os_fri_prover/src/lib.rs").read_text()
        dependencies = HELPER.read_toml(ROOT / "Cargo.toml")["workspace"]["dependencies"]
        lock = HELPER.read_toml(ROOT / "Cargo.lock")
        revision = PINS["upstream_commit"]
        self.assertEqual(metadata["airbender_revision"], revision)
        self.assertIn(f'const AIRBENDER_REVISION: &str = "{revision}";', loader)
        self.assertIn('const BUNDLED_ARTIFACT_SHA256: &str =\n    "'
                      + HELPER.sha256(artifact_path) + '";', loader)
        for dependency, package in (("zksync_airbender_execution_utils", "execution_utils"),
                                    ("zksync_airbender_cli", "cli")):
            self.assertEqual(dependencies[dependency]["git"], PINS["upstream_url"])
            self.assertEqual(PINS["upstream_lock_source"],
                             f'git+{dependencies[dependency]["git"]}'
                             f'?tag={dependencies[dependency]["tag"]}#{revision}')
            locked = [row for row in lock["package"] if row["name"] == package]
            self.assertEqual(len(locked), 1)
            self.assertEqual(locked[0]["source"], PINS["upstream_lock_source"])
        self.assertEqual(metadata["security_bits"], 100)
        self.assertEqual(summaries["security_bits"], 100)
        self.assertEqual(metadata["circuit_identity"],
                         "rv32im-unsigned-base/reduced-unrolled/reduced-unified-v1")
        self.assertEqual(metadata["setup_algorithm"], "base-unrolled-unified-v1")
        self.assertEqual(metadata["proof_target"], "recursion-unified")
        self.assertEqual((metadata["cap_size"], metadata["num_cosets"]), (64, 2))
        self.assertIn("zksync_airbender_execution_utils::setups::CAP_SIZE == self.cap_size", loader)
        self.assertIn("zksync_airbender_execution_utils::setups::NUM_COSETS == self.num_cosets", loader)
        self.assertIn(".validate(SecurityLevel::Security100.model(), base_binary)", loader)
        self.assertIn("target: ProofTarget::RecursionUnified", integration)
        self.assertIn("ProgramProver::new_with_setup_summaries_and_program_bytes(", integration)
        self.assertEqual(set(PINS["changed_files"]), HELPER.AIRBENDER_CHANGED_PATHS)
        self.assertIn("circuit_defs/unrolled_circuits/unified_reduced_machine/generated/quotient.rs",
                      PINS["changed_files"])
        # Upstream revision matching alone does not qualify these old release
        # artifacts against the new cumulative security overlay and guest bytes.
        for section, relative in (("bin", "multiblock_batch.bin"), ("text", "multiblock_batch.text")):
            self.assertEqual(metadata["app"][section]["sha256"], HELPER.sha256(ROOT / relative))
            self.assertEqual(metadata["app"][section]["size_bytes"], (ROOT / relative).stat().st_size)
        for identity in ("app", "recursion_unrolled", "recursion_unified"):
            for section in ("bin", "text"):
                self.assertIn('"' + metadata[identity][section]["sha256"] + '"', loader)
        commitment = HELPER.json_document(
            ROOT / "crates/zksync_os_snark_prover/artifacts/syscoin-v32-security100-commitment.json")
        for field in ("protocol_version", "execution_version", "proving_version", "security_bits",
                      "vk_hash", "program_commitment", "airbender_revision"):
            self.assertEqual(metadata[field], commitment[field])
        for level, families in (("base", [1, 2, 3, 4, 16, 17]),
                                ("recursion_unrolled", [1, 2, 3, 16]),
                                ("recursion_unified", [128])):
            setup = summaries[level]
            self.assertEqual(sorted(map(int, setup["circuit_families_setups"])), families)
            groups = list(setup["circuit_families_setups"].values()) + [setup["inits_and_teardowns_setup"]]
            for caps in groups:
                self.assertEqual(len(caps), metadata["num_cosets"])
                for cap in caps:
                    self.assertEqual(len(cap["cap"]), metadata["cap_size"])
                    self.assertTrue(all(len(word) == 8 for word in cap["cap"]))

    def test_locked_application_ci_covers_summary_validation_without_upstream_resolution(self):
        workflow = (ROOT / ".github/workflows/ci.yaml").read_text()
        loader = (ROOT / "crates/zksync_os_fri_prover/src/setup_summaries.rs").read_text()
        self.assertIn("ci-test -- cargo test --locked --no-default-features", workflow)
        self.assertNotIn('cargo test --manifest-path "${airbender}/Cargo.toml"', workflow)
        for test in ("repository_artifact_matches_inputs_and_registered_program_without_deriving",
                     "artifact_corruption_truncation_and_unknown_fields_fail_closed",
                     "every_metadata_field_is_release_pinned",
                     "both_sections_of_every_input_are_hash_and_length_bound",
                     "summary_order_security_geometry_and_derived_values_are_checked"):
            self.assertIn("fn " + test + "()", loader)

    def test_unknown_invalid_or_missing_pin_fields_fail_closed(self):
        for edit in (
            lambda p: p.update(extra=True),
            lambda p: p.update(schema_version=True),
            lambda p: p.update(schema_version=1),
            lambda p: p.update(upstream_url="https://example.invalid/airbender"),
            lambda p: p.update(upstream_commit="f" * 40),
            lambda p: p.update(upstream_tree="f" * 40),
            lambda p: p.update(upstream_lock_source=p["upstream_lock_source"] + "-changed"),
            lambda p: p.update(upstream_package_count=True),
            lambda p: p.update(patch_file="../escape.patch"),
            lambda p: p.update(overlay_lock_file="../escape.lock"),
            lambda p: p.update(patch_sha256="0" * 64),
            lambda p: p.update(patched_tree="f" * 40),
            lambda p: p["changed_files"].pop("execution_utils/src/lib.rs"),
            lambda p: p["changed_files"].update({"../unexpected": {}}),
            lambda p: p["changed_files"]["execution_utils/src/lib.rs"].update(preimage_sha256=None),
            lambda p: p["changed_files"]["execution_utils/src/setup_summaries.rs"].update(preimage_sha256="f" * 64),
            lambda p: p["changed_files"]["gpu_prover/src/execution/empty_inits_and_teardowns.rs"].update(preimage_sha256="f" * 64),
            lambda p: p["changed_files"]["execution_utils/src/lib.rs"].update(postimage_sha256="0" * 64),
            lambda p: p["changed_files"]["execution_utils/src/lib.rs"].update(postimage_size=True),
            lambda p: p["changed_files"]["execution_utils/src/lib.rs"].update(extra=1),
            lambda p: p.update(purpose=""),
        ):
            with tempfile.TemporaryDirectory() as temporary:
                pins = copy.deepcopy(PINS)
                edit(pins)
                with self.assertRaises(ValueError):
                    HELPER.load_airbender_pins(self.fixture(temporary, pins))

    def test_duplicate_manifest_keys_symlinks_and_changed_inputs_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest = self.fixture(temporary, PINS)
            manifest.write_text('{"schema_version":2,"schema_version":2}')
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                HELPER.load_airbender_pins(manifest)
            manifest.unlink()
            manifest.symlink_to(HELPER.PIN_PATH)
            with self.assertRaises(ValueError):
                HELPER.load_airbender_pins(manifest)
            manifest.unlink()
            for name in (PINS["patch_file"], PINS["overlay_lock_file"]):
                manifest = self.fixture(temporary, PINS)
                (manifest.parent / name).write_bytes(b"changed")
                with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                    HELPER.load_airbender_pins(manifest)

    def test_preimages_check_every_existing_file_and_reject_new_file_collisions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(HELPER, "checked_hash") as hashes:
                HELPER.check_airbender_preimages(root, PINS)
                self.assertEqual(hashes.call_count, 29)
                for relative, row in PINS["changed_files"].items():
                    if row["preimage_sha256"] is not None:
                        hashes.assert_any_call(root / relative, row["preimage_sha256"])
                for relative in ("execution_utils/src/setup_summaries.rs",
                                 "gpu_prover/src/execution/empty_inits_and_teardowns.rs"):
                    with self.subTest(new_file=relative):
                        new = root / relative
                        new.parent.mkdir(parents=True, exist_ok=True)
                        new.symlink_to(root / "missing")
                        with self.assertRaisesRegex(ValueError, "preimage already exists"):
                            HELPER.check_airbender_preimages(root, PINS)
                        new.unlink()

    def test_reverification_rejects_git_state_hash_size_and_symlink_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pins = copy.deepcopy(PINS)
            for relative, row in pins["changed_files"].items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(relative.encode())
                row["postimage_sha256"] = HELPER.sha256(path)
                row["postimage_size"] = path.stat().st_size
            values = {
                ("rev-parse", "HEAD"): pins["upstream_commit"],
                ("rev-parse", "HEAD^{tree}"): pins["upstream_tree"],
                ("diff", "--name-only", "HEAD"): "\n".join(sorted(pins["changed_files"])),
                ("ls-files", "--others", "--exclude-standard"): "",
                ("diff", "--name-only"): "",
                ("write-tree",): pins["patched_tree"],
            }
            with patch.object(HELPER, "run_git", side_effect=lambda repo, *args: values[args]):
                HELPER.verify_upstream(root, pins)
                for args, original in list(values.items()):
                    values[args] = "unexpected"
                    with self.assertRaises(ValueError):
                        HELPER.verify_upstream(root, pins)
                    values[args] = original
                for relative, row in pins["changed_files"].items():
                    row["postimage_size"] += 1
                    with self.assertRaisesRegex(ValueError, "size mismatch"):
                        HELPER.verify_upstream(root, pins)
                    row["postimage_size"] -= 1
                    path = root / relative
                    path.write_bytes(b"changed")
                    with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                        HELPER.verify_upstream(root, pins)
                    path.unlink()
                    path.symlink_to(root / "missing")
                    with self.assertRaisesRegex(ValueError, "not a regular input"):
                        HELPER.verify_upstream(root, pins)
                    path.unlink()
                    path.write_bytes(relative.encode())


class WrapperPinTests(unittest.TestCase):
    def fixture(self, directory, pins):
        directory = Path(directory)
        manifest = directory / "zkos-wrapper-buffered-os-rng.json"
        manifest.write_text(json.dumps(pins))
        (directory / "zkos-wrapper-buffered-os-rng.patch").write_bytes(
            (ROOT / "patches/zkos-wrapper-buffered-os-rng.patch").read_bytes())
        return manifest

    def test_metadata_is_complete_and_never_executes_subprocess(self):
        with patch.object(HELPER.subprocess, "run") as run, patch.object(HELPER.subprocess, "check_output") as output:
            metadata = HELPER.wrapper_pins_metadata()
            self.assertEqual(metadata["manifest_sha256"], HELPER.sha256(HELPER.WRAPPER_PIN_PATH))
            self.assertEqual(metadata["pins"]["upstream_packages"], HELPER.WRAPPER_PACKAGES)
            self.assertEqual(set(metadata["pins"]["changed_files"]), HELPER.WRAPPER_CHANGED_PATHS)
            self.assertEqual(metadata["pins"]["patched_tree"], HELPER.WRAPPER_PATCHED_TREE)
            run.assert_not_called()
            output.assert_not_called()

    def test_bundled_commitment_revisions_match_attested_and_locked_sources(self):
        artifact = HELPER.json_document(
            ROOT / "crates/zksync_os_snark_prover/artifacts/syscoin-v32-security100-commitment.json")
        wrapper_pins = HELPER.load_wrapper_pins()
        loader = (ROOT / "crates/zksync_os_snark_prover/src/binary_commitment.rs").read_text()
        lock = HELPER.read_toml(ROOT / "Cargo.lock")
        dependencies = HELPER.read_toml(ROOT / "Cargo.toml")["workspace"]["dependencies"]
        for field, constant, dependency, package, pins in (
            ("airbender_revision", "AIRBENDER_REVISION", "zksync_airbender_execution_utils",
             "execution_utils", PINS),
            ("wrapper_circuit_revision", "WRAPPER_CIRCUIT_REVISION", "zkos_wrapper",
             "zkos-wrapper", wrapper_pins),
        ):
            with self.subTest(field=field):
                revision = pins["upstream_commit"]
                self.assertEqual(artifact[field], revision)
                self.assertIn(f'const {constant}: &str = "{revision}";', loader)
                self.assertEqual(dependencies[dependency]["git"], pins["upstream_url"])
                self.assertEqual(pins["upstream_lock_source"],
                                 f'git+{dependencies[dependency]["git"]}'
                                 f'?tag={dependencies[dependency]["tag"]}#{revision}')
                locked = [row for row in lock["package"] if row["name"] == package]
                self.assertEqual(len(locked), 1)
                self.assertEqual(locked[0]["source"], pins["upstream_lock_source"])
        self.assertEqual(artifact["security_bits"], 100)
        self.assertEqual(dependencies["zkos_wrapper"]["features"], ["security_100"])
        self.assertIs(dependencies["zkos_wrapper"]["default-features"], False)
        for field, relative in (("bin", "multiblock_batch.bin"), ("text", "multiblock_batch.text")):
            self.assertEqual(artifact["app"][field]["sha256"], HELPER.sha256(ROOT / relative))
            self.assertEqual(artifact["app"][field]["size_bytes"], (ROOT / relative).stat().st_size)

    def test_unknown_invalid_or_missing_pin_fields_fail_closed(self):
        pins = HELPER.load_wrapper_pins()
        for edit in (
            lambda p: p.update(extra=True),
            lambda p: p.update(schema_version=True),
            lambda p: p.update(upstream_url="https://example.invalid/zkos-wrapper.git"),
            lambda p: p.update(upstream_commit="f" * 40),
            lambda p: p.update(upstream_tree="f" * 40),
            lambda p: p.update(upstream_lock_source=p["upstream_lock_source"] + "-changed"),
            lambda p: p["upstream_packages"].update({"unknown": "0.1.0"}),
            lambda p: p["upstream_packages"].pop("circuit_mersenne_field"),
            lambda p: p.update(patch_file="../escape.patch"),
            lambda p: p.update(patch_sha256="0" * 64),
            lambda p: p.update(patched_tree="f" * 40),
            lambda p: p["changed_files"].pop("wrapper/src/lib.rs"),
            lambda p: p["changed_files"]["wrapper/src/lib.rs"].update(preimage_sha256=None),
            lambda p: p["changed_files"]["wrapper/src/lib.rs"].update(postimage_sha256="0" * 64),
            lambda p: p["changed_files"]["wrapper/src/lib.rs"].update(postimage_size=True),
            lambda p: p.update(purpose=""),
        ):
            with tempfile.TemporaryDirectory() as temporary:
                invalid = copy.deepcopy(pins)
                edit(invalid)
                with self.assertRaises(ValueError):
                    HELPER.load_wrapper_pins(self.fixture(temporary, invalid))

    def test_duplicate_manifest_keys_symlinks_and_changed_patch_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest = self.fixture(temporary, HELPER.load_wrapper_pins())
            manifest.write_text('{"schema_version":1,"schema_version":1}')
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                HELPER.load_wrapper_pins(manifest)
            manifest.unlink()
            manifest.symlink_to(HELPER.WRAPPER_PIN_PATH)
            with self.assertRaisesRegex(ValueError, "invalid JSON input"):
                HELPER.load_wrapper_pins(manifest)
            manifest.unlink()
            manifest = self.fixture(temporary, HELPER.load_wrapper_pins())
            artifact = manifest.parent / "zkos-wrapper-buffered-os-rng.patch"
            artifact.write_bytes(b"changed patch")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                HELPER.load_wrapper_pins(manifest)
            artifact.unlink()
            artifact.symlink_to(ROOT / "patches/zkos-wrapper-buffered-os-rng.patch")
            with self.assertRaises(ValueError):
                HELPER.load_wrapper_pins(manifest)

    def test_patch_preserves_private_rng_and_exact_two_padding_substitutions(self):
        raw = (ROOT / "patches/zkos-wrapper-buffered-os-rng.patch").read_text()
        chunks = raw.split("diff --git ")[1:]
        self.assertEqual({chunk.splitlines()[0].split()[1][2:] for chunk in chunks},
                         HELPER.WRAPPER_CHANGED_PATHS)
        callsites = [chunk for chunk in chunks if chunk.splitlines()[0].split()[1][2:]
                     in {"wrapper/src/gpu/snark.rs", "wrapper/src/lib.rs"}]
        additions = [line[1:] for chunk in callsites for line in chunk.splitlines()
                     if line.startswith("+") and not line.startswith("+++")]
        self.assertCountEqual(additions, [
            "mod buffered_os_rng;",
            "    SnarkWrapperFunction, SnarkWrapperProof, SnarkWrapperVK, buffered_os_rng::BufferedOsRng,",
            "        let mut rng = BufferedOsRng::new();",
            "        let mut rng = buffered_os_rng::BufferedOsRng::new();",
            "/// Security level selected by this wrapper's enabled feature, for authenticating",
            "/// precomputed binary commitments without deriving recursion-layer setups.",
            "pub const fn binary_commitment_security_bits() -> u32 {",
            "    use risc_verifier::verifier_common::SecurityModel;",
            "    match active_security::ACTIVE_SECURITY_MODEL {",
            "        SecurityModel::Security80 => 80,",
            "        SecurityModel::Security100 => 100,",
            "    }",
            "}",
            "",
            "    let expected_proof_config = RiscWrapper::get_proof_config();",
            "    verifier.verify::<RiscWrapperTreeHasher, RiscWrapperTranscript, NoPow>(",
            "        (),",
            "        vk,",
            "        proof,",
            "        &expected_proof_config,",
            "    )",
            "    let expected_proof_config = CompressionCircuit::get_proof_config();",
            "    verifier.verify::<CompressionTreeHasher, CompressionTranscript, NoPow>(",
            "        (),",
            "        vk,",
            "        proof,",
            "        &expected_proof_config,",
            "    )",
        ])
        rng = next(chunk for chunk in chunks if "a/wrapper/src/buffered_os_rng.rs " in chunk.splitlines()[0])
        self.assertIn("pub(crate) struct BufferedOsRng", rng)
        self.assertIn("const OS_ENTROPY_BUFFER_BYTES: usize = 64 * 1024;", rng)
        self.assertIn("impl<R: RngCore + CryptoRng> CryptoRng for BufferedOsRng<R>", rng)
        self.assertNotIn("unsafe", rng)
        self.assertNotIn("Clone", rng)
        self.assertIn("not be retained or reused across a process fork", rng)

    def test_precomputed_constructor_and_getter_only_reuse_existing_validated_paths(self):
        raw = (ROOT / "patches/zkos-wrapper-buffered-os-rng.patch").read_text()
        wrapper = next(chunk for chunk in raw.split("diff --git ")[1:]
                       if chunk.splitlines()[0].split()[1] == "b/wrapper/src/wrapper/mod.rs")
        self.assertFalse(any(line.startswith("-") and not line.startswith("---")
                             for line in wrapper.splitlines()))
        hunks = wrapper.split("\n@@ ")
        self.assertEqual(len(hunks), 3)
        production = [line[1:] for line in hunks[1].splitlines() if line.startswith("+")]
        self.assertEqual(production, [
            "    /// Build a wrapper using a precomputed commitment for the configured program.",
            "    ///",
            "    /// The caller must authenticate the commitment against the exact base and recursion",
            "    /// binaries and active security configuration before calling this constructor. This",
            "    /// does not validate those inputs by recomputing their commitment. All ordinary",
            "    /// constructor validation, setup derivation, and proof verification remain enabled.",
            "    pub fn new_with_binary_commitment(",
            "        config: SnarkWrapperConfig,",
            "        binary_commitment: BinaryCommitment,",
            "    ) -> anyhow::Result<Self> {",
            "        let mut wrapper = Self::new(config)?;",
            "        wrapper.binary_commitment = Some(binary_commitment);",
            "        Ok(wrapper)",
            "    }",
            "",
            "    /// Return this session's binary commitment, deriving and caching it on first use",
            "    /// after [`Self::new`], or reusing the value from [`Self::new_with_binary_commitment`].",
            "    pub fn resolved_binary_commitment(&mut self) -> anyhow::Result<BinaryCommitment> {",
            "        self.binary_commitment()",
            "    }",
            "",
        ])
        tests = hunks[2]
        for name in ("security_matches_enabled_feature", "preserves_values_config_and_host_cache",
                     "preserves_constructor_validation", "does_not_change_legacy_lazy_constructor"):
            self.assertIn("fn precomputed_commitment_" + name + "()", tests)
        self.assertNotIn("BinaryCommitment::default()", tests)
        self.assertNotIn("BinaryCommitment::from_base_binary", tests)

    def test_ci_executes_dependency_rng_and_commitment_tests_from_attested_wrapper_workspace(self):
        workflow = (ROOT / ".github/workflows/ci.yaml").read_text()
        self.assertIn('AIRBENDER_BUILD_ATTESTATION="${RUNNER_TEMP}/ci-test-airbender-inputs.json"', workflow)
        self.assertIn("ci-test -- cargo test --locked --no-default-features", workflow)
        self.assertIn('python3 -B .github/scripts/run_pinned_wrapper_tests.py \\\n'
                      '            "${RUNNER_TEMP}/ci-test-airbender-inputs.json"', workflow)
        self.assertIn('run: python3 -B .github/scripts/test_run_pinned_wrapper_tests.py', workflow)
        self.assertNotIn('cargo test --manifest-path "${wrapper}/Cargo.toml"', workflow)
        self.assertNotIn('cargo test --manifest-path "${workspace}/Cargo.toml"', workflow)
        self.assertIn('      - name: Run pinned wrapper RNG and commitment tests\n'
                      '        env:\n'
                      '          RUST_MIN_STACK: "33554432"\n'
                      '          CARGO_PROFILE_DEV_DEBUG: "0"\n'
                      '        run: |', workflow)

    def test_ci_wrapper_shell_routes_attestation_and_preserves_helper_failure(self):
        lines = (ROOT / ".github/workflows/ci.yaml").read_text().splitlines()
        step = lines.index("      - name: Run pinned wrapper RNG and commitment tests")
        start = lines.index("        run: |", step) + 1
        self.assertEqual(lines[step + 1], "        env:")
        step_env = dict(line.strip().split(": ", 1) for line in lines[step + 2:start - 1])
        step_env = {key: value.strip('"') for key, value in step_env.items()}
        self.assertEqual(step_env, {"RUST_MIN_STACK": "33554432", "CARGO_PROFILE_DEV_DEBUG": "0"})
        body = []
        for line in lines[start:]:
            if line.startswith("          "):
                body.append(line[10:])
            elif not line.strip():
                body.append("")
            else:
                break
        script = "\n".join(body)
        stub = r'''
import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
assert name == "python3"
event = {"argv": sys.argv[1:], "rust_min_stack": os.environ["RUST_MIN_STACK"],
         "profile_dev_debug": os.environ["CARGO_PROFILE_DEV_DEBUG"]}
with Path(os.environ["WORKFLOW_CALL_LOG"]).open("a") as output:
    output.write(json.dumps(event) + "\n")
raise SystemExit(int(os.environ["WRAPPER_HELPER_EXIT_CODE"]))
'''
        for helper_status in (0, 7, 9):
            with self.subTest(helper_status=helper_status), \
                    tempfile.TemporaryDirectory(prefix="wrapper ci ") as temporary:
                root = Path(temporary)
                commands = root / "commands"
                commands.mkdir()
                for name in ("python3",):
                    executable = commands / name
                    executable.write_text("#!" + sys.executable + "\n" + stub)
                    executable.chmod(0o700)
                log = root / "calls.jsonl"
                result = subprocess.run(["bash", "-eu", "-c", script], cwd=ROOT, capture_output=True,
                                        text=True, env={**os.environ, **step_env, "RUNNER_TEMP": str(root),
                                        "PATH": str(commands) + os.pathsep + os.environ.get("PATH", ""),
                                        "WORKFLOW_CALL_LOG": str(log),
                                        "WRAPPER_HELPER_EXIT_CODE": str(helper_status)})
                self.assertEqual(result.returncode, helper_status, result.stderr)
                events = [json.loads(line) for line in log.read_text().splitlines()]
                expected = [
                    {"rust_min_stack": "33554432", "profile_dev_debug": "0", "argv": [
                        "-B", ".github/scripts/run_pinned_wrapper_tests.py",
                        str(root / "ci-test-airbender-inputs.json")]},
                ]
                self.assertEqual(events, expected)

    def test_prepare_uses_isolated_clone_exact_pin_and_reverification(self):
        pins = HELPER.load_wrapper_pins()
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary).resolve()
            local_source = root / "source"
            local_source.mkdir()
            marker = local_source / "untouched"
            marker.write_bytes(b"source must remain unchanged")
            stack.enter_context(patch.dict(HELPER.os.environ, {"ZKOS_WRAPPER_SOURCE_DIR": str(local_source)}, clear=True))
            run = stack.enter_context(patch.object(HELPER.subprocess, "run"))
            git = stack.enter_context(patch.object(HELPER, "run_git", return_value=pins["upstream_tree"]))
            hashes = stack.enter_context(patch.object(HELPER, "checked_hash"))
            verify = stack.enter_context(patch.object(HELPER, "verify_wrapper"))
            paths = stack.enter_context(patch.object(HELPER, "package_paths", return_value={"zkos-wrapper": "wrapper"}))
            upstream, clone_source, package_paths = HELPER.prepare_wrapper(root, pins)
            self.assertEqual(upstream, root / "zkos-wrapper")
            self.assertEqual(clone_source, str(local_source))
            self.assertEqual(package_paths, {"zkos-wrapper": "wrapper"})
            run.assert_called_once_with(["git", "clone", "--quiet", "--no-checkout", "--no-hardlinks",
                                         str(local_source), str(upstream)], check=True)
            git.assert_any_call(upstream, "checkout", "--quiet", "--detach", pins["upstream_commit"])
            git.assert_any_call(upstream, "apply", "--check", str(ROOT / "patches" / pins["patch_file"]))
            git.assert_any_call(upstream, "apply", str(ROOT / "patches" / pins["patch_file"]))
            git.assert_any_call(upstream, "add", "--", *sorted(pins["changed_files"]))
            self.assertEqual(hashes.call_count, 6)
            verify.assert_called_once_with(upstream, pins)
            paths.assert_called_once_with(upstream, pins["upstream_packages"])
            self.assertEqual(marker.read_bytes(), b"source must remain unchanged")

    def test_reverification_rejects_git_state_hash_and_size_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pins = copy.deepcopy(HELPER.load_wrapper_pins())
            for relative, row in pins["changed_files"].items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(relative.encode())
                row["postimage_sha256"] = HELPER.sha256(path)
                row["postimage_size"] = path.stat().st_size
            values = {
                ("rev-parse", "HEAD"): pins["upstream_commit"],
                ("rev-parse", "HEAD^{tree}"): pins["upstream_tree"],
                ("diff", "--name-only", "HEAD"): "\n".join(sorted(pins["changed_files"])),
                ("ls-files", "--others", "--exclude-standard"): "",
                ("diff", "--name-only"): "",
                ("write-tree",): pins["patched_tree"],
            }
            with patch.object(HELPER, "run_git", side_effect=lambda repo, *args: values[args]):
                HELPER.verify_wrapper(root, pins)
                for args, original in list(values.items()):
                    values[args] = "unexpected"
                    with self.assertRaises(ValueError):
                        HELPER.verify_wrapper(root, pins)
                    values[args] = original
                relative = "wrapper/src/lib.rs"
                pins["changed_files"][relative]["postimage_size"] += 1
                with self.assertRaisesRegex(ValueError, "size mismatch"):
                    HELPER.verify_wrapper(root, pins)
                pins["changed_files"][relative]["postimage_size"] -= 1
                (root / relative).write_bytes(b"changed")
                with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                    HELPER.verify_wrapper(root, pins)


class CommandTests(unittest.TestCase):
    def test_manifest_injected_without_changing_role_or_application_arguments(self):
        command = ["cargo", "run", "--locked", "-p", "zksync_os_fri_prover", "--features", "gpu",
                   "--", "--app-bin-path", "./guest/app.bin", "--path", "./output"]
        actual = HELPER.cargo_command(command, Path("/prepared/Cargo.toml"))
        self.assertEqual(actual, ["cargo", "run", "--manifest-path", "/prepared/Cargo.toml", *command[2:]])

    def test_clippy_rustc_arguments_preserved(self):
        command = ["cargo", "clippy", "--locked", "--no-default-features", "--", "-D", "warnings"]
        self.assertEqual(HELPER.cargo_command(command, Path("/prepared/Cargo.toml"))[-3:],
                         ["--", "-D", "warnings"])

    def test_mutable_or_overridden_builds_rejected(self):
        for command in (
            ["cargo", "update", "--locked"], ["cargo", "build"],
            ["cargo", "run", "--", "--locked"],
            ["cargo", "build", "--locked", "--manifest-path=/other/Cargo.toml"],
            ["cargo", "build", "--locked", "--config", "override.toml"],
            ["cargo", "build", "--locked", "--target-dir", "/other"],
            ["cargo", "build", "--locked", "--lockfile-path=/other/Cargo.lock"],
        ):
            with self.subTest(command=command), self.assertRaises(ValueError):
                HELPER.cargo_command(command, Path("/prepared/Cargo.toml"))

    def test_invalid_label_fails_before_input_or_network_access(self):
        with patch.object(HELPER, "checked_hash") as checked:
            with self.assertRaisesRegex(ValueError, "invalid build label"):
                HELPER.main(["../bad", "--", "cargo", "build", "--locked"])
            checked.assert_not_called()


class WrapperCpuIntegrationTests(unittest.TestCase):
    def exercise(self, temporary, *, reject_reverification=False, reject_tooling=False,
                 reject_crypto_reverification=False, reject_crypto_tooling=False, cargo_exit_code=0):
        """Test CPU orchestration with real snapshots/records and mocked external tools."""
        source = Path(temporary).resolve()
        (source / "crates/example/src").mkdir(parents=True)
        (source / "crates/example/src/lib.rs").write_text("pub fn fixture() {}\n")
        (source / "crates/example/Cargo.toml").write_text('[package]\nname = "example"\nversion = "0.1.0"\n')
        for name in HELPER.SOURCE_FILES:
            (source / name).write_bytes((ROOT / name).read_bytes())
        (source / "Cargo.toml").write_text('[workspace]\nmembers = ["crates/example"]\n')
        attestation = source / "verified-build.json"
        events = []
        pins = HELPER.load_wrapper_pins()
        paths = {"circuit_mersenne_field": "circuit_mersenne_field", "zkos-wrapper": "wrapper"}
        crypto_pins = HELPER.load_crypto_pins()
        crypto_paths = {name: "crates/" + name for name in HELPER.CRYPTO_PACKAGES}
        checked_hash = HELPER.checked_hash

        def check_local_or_external(path, digest):
            if path.name in {Path(name).name for name in PINS["changed_files"]} and "airbender" in path.parts:
                return
            if reject_tooling and path == HELPER.WRAPPER_PIN_PATH:
                raise ValueError("tooling changed after Cargo")
            if reject_crypto_tooling and path == HELPER.CRYPTO_PIN_PATH:
                raise ValueError("common crypto tooling changed after Cargo")
            checked_hash(path, digest)

        def prepare_wrapper(build, selected_pins):
            self.assertEqual(selected_pins, pins)
            events.append("prepare-wrapper")
            return build / "zkos-wrapper", pins["upstream_url"], paths

        def verify_wrapper(root, selected_pins):
            self.assertEqual(root.name, "zkos-wrapper")
            self.assertEqual(selected_pins, pins)
            events.append("reverify-wrapper")
            if reject_reverification:
                raise ValueError("wrapper changed after Cargo")

        def prepare_crypto(build, selected_pins):
            self.assertEqual(selected_pins, crypto_pins)
            events.append("prepare-crypto")
            return build / "zksync-crypto", crypto_pins["upstream_url"], crypto_paths

        def verify_crypto(root, selected_pins):
            self.assertEqual(root.name, "zksync-crypto")
            self.assertEqual(selected_pins, crypto_pins)
            events.append("reverify-crypto")
            if reject_crypto_reverification:
                raise ValueError("common crypto changed after Cargo")

        def run(command, **kwargs):
            if command[0] == "cargo":
                events.append("cargo")
                manifest = HELPER.read_toml(Path(command[command.index("--manifest-path") + 1]))
                self.assertEqual(set(manifest["patch"][pins["upstream_url"]]), set(paths))
                self.assertEqual(set(manifest["patch"][crypto_pins["upstream_url"]]), set(crypto_paths))
                self.assertIn("--no-default-features", command)
                return unittest.mock.Mock(returncode=cargo_exit_code)
            self.assertEqual(command[:2], ["git", "clone"])
            return unittest.mock.Mock(returncode=0)

        with ExitStack() as stack:
            stack.enter_context(patch.dict(HELPER.os.environ, {
                "PROVER_SOURCE_DIR": str(source), "AIRBENDER_BUILD_ATTESTATION": str(attestation),
            }, clear=True))
            for name, kwargs in (
                ("checked_hash", {"side_effect": check_local_or_external}),
                ("run_git", {"return_value": PINS["upstream_tree"]}),
                ("verify_upstream", {}),
                ("package_paths", {"side_effect": lambda root, packages: {p: p for p in packages}}),
                ("prepare_wrapper", {"side_effect": prepare_wrapper}),
                ("verify_wrapper", {"side_effect": verify_wrapper}),
                ("prepare_crypto", {"side_effect": prepare_crypto}),
                ("verify_crypto", {"side_effect": verify_crypto}),
            ):
                stack.enter_context(patch.object(HELPER, name, **kwargs))
            stack.enter_context(patch.object(HELPER.subprocess, "run", side_effect=run))
            stack.enter_context(patch.object(HELPER.subprocess, "check_output", return_value="offline-test-version"))
            command = ["--cpu", "test-wrapper", "--", "cargo", "build", "--locked", "--no-default-features"]
            if reject_reverification or reject_tooling or reject_crypto_reverification or reject_crypto_tooling:
                with self.assertRaisesRegex(ValueError, "changed after Cargo"):
                    HELPER.main(command)
            else:
                self.assertEqual(HELPER.main(command), cargo_exit_code)
        builds = list((source / "target/patched-airbender").iterdir())
        self.assertEqual(len(builds), 1)
        return attestation, builds[0], events

    def test_cpu_success_records_wrapper_closure_after_reverification(self):
        with tempfile.TemporaryDirectory() as temporary:
            attestation, build, events = self.exercise(temporary)
            self.assertEqual(events, ["prepare-wrapper", "prepare-crypto", "cargo", "reverify-wrapper", "reverify-crypto"])
            record = json.loads(attestation.read_text())
            self.assertIs(record["inputs_reverified"], True)
            self.assertEqual(record["zkos_wrapper"]["inputs"], HELPER.wrapper_pins_metadata())
            self.assertEqual(record["zkos_wrapper"]["source"]["patched_tree"], HELPER.WRAPPER_PATCHED_TREE)
            self.assertEqual(set(record["zkos_wrapper"]["package_paths"]), set(HELPER.WRAPPER_PACKAGES))
            self.assertEqual(record["zksync_crypto"]["inputs"], HELPER.crypto_pins_metadata())
            self.assertEqual(record["zksync_crypto"]["source"]["patched_tree"], HELPER.CRYPTO_PATCHED_TREE)
            self.assertEqual(set(record["zksync_crypto"]["package_paths"]), set(HELPER.CRYPTO_PACKAGES))
            for suffix in ("json", "patch"):
                relative = "patches/zkos-wrapper-buffered-os-rng." + suffix
                self.assertEqual(record["tooling_sha256"][relative], HELPER.sha256(ROOT / relative))
                relative = "patches/zksync-crypto-native-fri-query-count." + suffix
                self.assertEqual(record["tooling_sha256"][relative], HELPER.sha256(ROOT / relative))
            self.assertEqual(record, json.loads((build / "build-result.json").read_text()))
            self.assertEqual((Path(temporary) / "Cargo.lock").read_bytes(), (ROOT / "Cargo.lock").read_bytes())
            self.assertEqual((build / "prover/Cargo.lock").read_bytes(),
                             (ROOT / "patches/airbender.Cargo.lock").read_bytes())

    def test_cpu_reverification_failure_never_emits_success_attestation(self):
        with tempfile.TemporaryDirectory() as temporary:
            attestation, build, events = self.exercise(temporary, reject_reverification=True)
            self.assertEqual(events, ["prepare-wrapper", "prepare-crypto", "cargo", "reverify-wrapper"])
            self.assertFalse(attestation.exists())
            self.assertFalse((build / "build-result.json").exists())

    def test_cpu_cargo_failure_remains_unverified(self):
        with tempfile.TemporaryDirectory() as temporary:
            attestation, build, events = self.exercise(temporary, cargo_exit_code=9)
            self.assertEqual(events, ["prepare-wrapper", "prepare-crypto", "cargo"])
            self.assertFalse(attestation.exists())
            record = json.loads((build / "build-result.json").read_text())
            self.assertIs(record["inputs_reverified"], False)
            self.assertEqual(record["cargo_exit_code"], 9)

    def test_cpu_tooling_drift_never_emits_success_attestation(self):
        with tempfile.TemporaryDirectory() as temporary:
            attestation, build, events = self.exercise(temporary, reject_tooling=True)
            self.assertEqual(events, ["prepare-wrapper", "prepare-crypto", "cargo", "reverify-wrapper", "reverify-crypto"])
            self.assertFalse(attestation.exists())
            self.assertFalse((build / "build-result.json").exists())

    def test_cpu_crypto_reverification_failure_never_emits_success_attestation(self):
        with tempfile.TemporaryDirectory() as temporary:
            attestation, build, events = self.exercise(temporary, reject_crypto_reverification=True)
            self.assertEqual(events, ["prepare-wrapper", "prepare-crypto", "cargo", "reverify-wrapper", "reverify-crypto"])
            self.assertFalse(attestation.exists())
            self.assertFalse((build / "build-result.json").exists())

    def test_cpu_crypto_tooling_drift_never_emits_success_attestation(self):
        with tempfile.TemporaryDirectory() as temporary:
            attestation, build, events = self.exercise(temporary, reject_crypto_tooling=True)
            self.assertEqual(events, ["prepare-wrapper", "prepare-crypto", "cargo", "reverify-wrapper", "reverify-crypto"])
            self.assertFalse(attestation.exists())
            self.assertFalse((build / "build-result.json").exists())


class MaterializationTests(unittest.TestCase):
    def make_application(self, root):
        for name in HELPER.SOURCE_FILES:
            (root / name).write_text(name)
        (root / "crates/example/src").mkdir(parents=True)
        (root / "crates/example/src/lib.rs").write_text("pub fn example() {}\n")

    def test_snapshot_is_independent_and_hashed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, output = Path(tmp) / "application", Path(tmp) / "snapshot"
            root.mkdir()
            self.make_application(root)
            hashes = HELPER.copy_application(root, output)
            self.assertEqual(len(hashes), len(HELPER.SOURCE_FILES) + 1)
            for relative, digest in hashes.items():
                self.assertEqual(HELPER.sha256(root / relative), digest)
                self.assertEqual(HELPER.sha256(output / relative), digest)
            (output / "Cargo.toml").write_text("changed snapshot")
            self.assertEqual((root / "Cargo.toml").read_text(), "Cargo.toml")

    def test_canonical_bundled_commitment_is_copied_and_hashed_with_loader(self):
        artifact = "crates/zksync_os_snark_prover/artifacts/syscoin-v32-security100-commitment.json"
        loader = "crates/zksync_os_snark_prover/src/binary_commitment.rs"
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "snapshot"
            hashes = HELPER.copy_application(ROOT, output)
            for relative in (artifact, loader):
                self.assertIn(relative, hashes)
                self.assertEqual(hashes[relative], HELPER.sha256(ROOT / relative))
                self.assertEqual(hashes[relative], HELPER.sha256(output / relative))
                self.assertEqual((output / relative).read_bytes(), (ROOT / relative).read_bytes())
            self.assertIn('include_str!("../artifacts/syscoin-v32-security100-commitment.json")',
                          (output / loader).read_text())
            self.assertFalse((output / "patches").exists())

    def test_source_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_application(root)
            (root / "crates/example/src/link.rs").symlink_to(root / "Cargo.toml")
            with self.assertRaisesRegex(ValueError, "symlink"):
                HELPER.copy_application(root, root / "snapshot")

    def test_main_accepts_actual_parent_source_before_any_clone_or_cargo(self):
        class CloneBoundary(Exception):
            pass

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_application(root)
            # This main-entry test now crosses the pure selected-feature guard;
            # unlike copy-only fixtures, its Cargo manifests must be valid TOML.
            (root / "Cargo.toml").write_text('[workspace]\nmembers = ["crates/example"]\n')
            (root / "crates/example/Cargo.toml").write_text('[package]\nname = "example"\nversion = "0.1.0"\n')
            (root / "Cargo.lock").write_bytes(parent_lock_bytes())
            before = {name: (root / name).read_bytes() for name in HELPER.SOURCE_FILES}
            with patch.dict(HELPER.os.environ, {"PROVER_SOURCE_DIR": str(root)}, clear=True), \
                    patch.object(HELPER.subprocess, "run", side_effect=CloneBoundary) as run:
                with self.assertRaises(CloneBoundary):
                    HELPER.main(["parent-source", "--", "cargo", "build", "--locked"])
                run.assert_called_once()
                self.assertEqual(run.call_args.args[0][:4], ["git", "clone", "--quiet", "--no-checkout"])
            self.assertEqual(before, {name: (root / name).read_bytes() for name in HELPER.SOURCE_FILES})
            snapshots = list((root / "target/patched-airbender").glob("parent-source-*/prover/Cargo.lock"))
            self.assertEqual(len(snapshots), 1)
            self.assertEqual(snapshots[0].read_bytes(), parent_lock_bytes())

    def test_main_incompatible_source_fails_before_snapshot_or_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_application(root)
            (root / "Cargo.toml").write_text('[workspace]\nmembers = ["crates/example"]\n')
            (root / "crates/example/Cargo.toml").write_text('[package]\nname = "example"\nversion = "0.1.0"\n')
            (root / "Cargo.lock").write_bytes(parent_lock_bytes().replace(
                b"03454c7a41053a4b88bb421e97fb9efe893a92f5", b"f" * 40))
            with patch.dict(HELPER.os.environ, {"PROVER_SOURCE_DIR": str(root)}, clear=True), \
                    patch.object(HELPER.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "mixed Airbender"):
                    HELPER.main(["incompatible-source", "--", "cargo", "build", "--locked"])
                run.assert_not_called()
            self.assertFalse((root / "target").exists())

    def test_success_attestation_never_overwrites_existing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "attestation.json"
            HELPER.write_json_exclusive(output, {"first": True})
            with self.assertRaises(FileExistsError):
                HELPER.write_json_exclusive(output, {"second": True})
            self.assertEqual(json.loads(output.read_text()), {"first": True})


if __name__ == "__main__":
    unittest.main()
