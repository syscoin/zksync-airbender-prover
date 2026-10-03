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


def parent_lock_bytes():
    """Exact lock from parent488f70ac, reconstructed without requiring Git history in CI."""
    raw = (ROOT / "Cargo.lock").read_bytes()
    for name, removed in (
        ("zksync_os_fri_prover", (b' "sha2 0.10.9",\n',)),
        ("zksync_os_snark_prover", (
            b' "base64 0.22.1",\n', b' "bincode 2.0.1",\n', b' "libc",\n',
            b' "riscv_transpiler",\n', b' "sha2 0.10.9",\n', b' "verifier_common",\n',
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

    def test_only_all_airbender_and_wrapper_source_identities_change(self):
        packages = HELPER.audit_lock(self.canonical, self.overlay, PINS)
        self.assertEqual(len(packages), 46)
        self.assertIn("gpu_prover", packages)
        self.assertIn("cli", packages)
        self.assertIn("execution_utils", packages)
        self.assertFalse(any("zksync-airbender" in item.get("source", "")
                             for item in self.overlay["package"]))
        self.assertFalse(any("zkos-wrapper" in item.get("source", "")
                             for item in self.overlay["package"]))

    def test_current_derivation_is_byte_identical_to_reviewed_overlay(self):
        raw, selected = HELPER.selected_lock_overlay(
            ROOT / "Cargo.lock", ROOT / "patches/airbender.Cargo.lock", PINS)
        self.assertEqual(raw, (ROOT / "patches/airbender.Cargo.lock").read_bytes())
        self.assertEqual(selected["canonical_lock_sha256"], PINS["canonical_lock_sha256"])
        self.assertEqual(selected["overlay_lock_sha256"], PINS["overlay_lock_sha256"])
        self.assertEqual(selected["airbender_packages"], HELPER.audit_lock(self.canonical, self.overlay, PINS))
        self.assertEqual(selected["schema_version"], 2)
        self.assertEqual(selected["derivation"], "airbender-wrapper-source-identity-only-v2")
        self.assertEqual(selected["zkos_wrapper_packages"],
                         {"circuit_mersenne_field": "0.1.0", "zkos-wrapper": "0.1.0"})

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
            with self.assertRaisesRegex(ValueError, "more than Airbender"):
                HELPER.audit_lock(old, self.overlay, PINS)

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
                with self.assertRaisesRegex(ValueError, "more than Airbender"):
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

    def test_logger_patch_has_no_proving_changes(self):
        source = (ROOT / "patches/airbender-cuda-device-diagnostics.patch").read_text()
        self.assertEqual(source.count("diff --git "), 5)
        source = next("diff --git " + section for section in source.split("diff --git ")
                      if section.startswith("a/gpu_prover/src/execution/gpu_worker.rs "))
        self.assertEqual(hashlib.sha256(source.encode()).hexdigest(),
                         "768e9305dd5ebacff733a172f40fcabd5b333c212bc9582424526dcb16f257e2")
        additions = "\n".join(line[1:] for line in source.splitlines()
                              if line.startswith("+") and not line.startswith("+++"))
        self.assertIn("device_get_attribute(CudaDeviceAttr::MultiProcessorCount, device_id)?", additions)
        self.assertNotIn("get_device_properties", additions)
        self.assertNotIn("unsafe", additions)
        self.assertNotIn("CStr", additions)


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
        self.assertFalse(any(relative.startswith(("circuit_defs/", "verifier/", "full_statement_verifier/"))
                             for relative in PINS["changed_files"]))
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
                self.assertEqual(hashes.call_count, 4)
                for relative, row in PINS["changed_files"].items():
                    if row["preimage_sha256"] is not None:
                        hashes.assert_any_call(root / relative, row["preimage_sha256"])
                new = root / "execution_utils/src/setup_summaries.rs"
                new.parent.mkdir(parents=True)
                new.symlink_to(root / "missing")
                with self.assertRaisesRegex(ValueError, "preimage already exists"):
                    HELPER.check_airbender_preimages(root, PINS)

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
        self.assertIn("workspace=\"$(jq -er '.workspace' \"${record}\")\"", workflow)
        self.assertIn('wrapper="$(dirname -- "${workspace}")/zkos-wrapper"', workflow)
        self.assertIn("target=\"$(jq -er '.cargo_target_dir' \"${record}\")\"", workflow)
        self.assertIn('CARGO_TARGET_DIR="${target}" cargo test --manifest-path "${wrapper}/Cargo.toml"', workflow)
        self.assertNotIn('cargo test --manifest-path "${workspace}/Cargo.toml"', workflow)
        self.assertIn("--locked -p zkos-wrapper --lib buffered_os_rng::tests", workflow)
        self.assertIn("--locked -p zkos-wrapper --lib wrapper::tests::precomputed_commitment", workflow)
        self.assertIn('helper.verify_wrapper(Path(sys.argv[1]), helper.load_wrapper_pins())', workflow)
        self.assertIn('      - name: Run pinned wrapper RNG and commitment tests\n'
                      '        env:\n'
                      '          RUST_MIN_STACK: "33554432"\n'
                      '          CARGO_PROFILE_DEV_DEBUG: "0"\n'
                      '        run: |', workflow)

    def test_ci_wrapper_rng_shell_routes_manifest_and_preserves_failure(self):
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
if name == "jq":
    record = json.loads(Path(sys.argv[-1]).read_text())
    print(record[sys.argv[-2].removeprefix(".")])
    raise SystemExit(0)
if name == "python3":
    source = sys.stdin.read()
    assert "helper.verify_wrapper" in source and "helper.load_wrapper_pins" in source
    event = {"kind": "verify", "wrapper": sys.argv[-1]}
else:
    assert name == "cargo"
    event = {"kind": "cargo", "argv": sys.argv[1:], "target": os.environ["CARGO_TARGET_DIR"],
             "rust_min_stack": os.environ["RUST_MIN_STACK"],
             "profile_dev_debug": os.environ["CARGO_PROFILE_DEV_DEBUG"]}
with Path(os.environ["WORKFLOW_CALL_LOG"]).open("a") as output:
    output.write(json.dumps(event) + "\n")
if name == "cargo":
    status_key = ("WRAPPER_COMMITMENT_TEST_EXIT_CODE" if "wrapper::tests::precomputed_commitment"
                  in sys.argv else "WRAPPER_TEST_EXIT_CODE")
    raise SystemExit(int(os.environ[status_key]))
'''
        for rng_status, commitment_status in ((0, 0), (7, 0), (0, 9)):
            with self.subTest(rng_status=rng_status, commitment_status=commitment_status), \
                    tempfile.TemporaryDirectory(prefix="wrapper ci ") as temporary:
                root = Path(temporary)
                commands = root / "commands"
                commands.mkdir()
                for name in ("jq", "python3", "cargo"):
                    executable = commands / name
                    executable.write_text("#!" + sys.executable + "\n" + stub)
                    executable.chmod(0o700)
                workspace, target = root / "snapshot build/prover", root / "target cache"
                (root / "ci-test-airbender-inputs.json").write_text(json.dumps({
                    "workspace": str(workspace), "cargo_target_dir": str(target)}))
                log = root / "calls.jsonl"
                result = subprocess.run(["bash", "-eu", "-c", script], cwd=ROOT, capture_output=True,
                                        text=True, env={**os.environ, **step_env, "RUNNER_TEMP": str(root),
                                        "PATH": str(commands) + os.pathsep + os.environ.get("PATH", ""),
                                        "WORKFLOW_CALL_LOG": str(log),
                                        "WRAPPER_TEST_EXIT_CODE": str(rng_status),
                                        "WRAPPER_COMMITMENT_TEST_EXIT_CODE": str(commitment_status)})
                self.assertEqual(result.returncode, rng_status or commitment_status, result.stderr)
                events = [json.loads(line) for line in log.read_text().splitlines()]
                wrapper = workspace.parent / "zkos-wrapper"
                expected = [
                    {"kind": "verify", "wrapper": str(wrapper)},
                    {"kind": "cargo", "target": str(target), "rust_min_stack": "33554432",
                     "profile_dev_debug": "0", "argv": [
                        "test", "--manifest-path", str(wrapper / "Cargo.toml"), "--locked",
                        "-p", "zkos-wrapper", "--lib", "buffered_os_rng::tests"]},
                ]
                if not rng_status:
                    expected.append({"kind": "cargo", "target": str(target), "rust_min_stack": "33554432",
                                     "profile_dev_debug": "0", "argv": [
                                         "test", "--manifest-path", str(wrapper / "Cargo.toml"), "--locked",
                                         "-p", "zkos-wrapper", "--lib", "wrapper::tests::precomputed_commitment"]})
                expected.append({"kind": "verify", "wrapper": str(wrapper)})
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
            self.assertEqual(hashes.call_count, 3)
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
    def exercise(self, temporary, *, reject_reverification=False, reject_tooling=False, cargo_exit_code=0):
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
        checked_hash = HELPER.checked_hash

        def check_local_or_external(path, digest):
            if path.name in {Path(name).name for name in PINS["changed_files"]} and "airbender" in path.parts:
                return
            if reject_tooling and path == HELPER.WRAPPER_PIN_PATH:
                raise ValueError("tooling changed after Cargo")
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

        def run(command, **kwargs):
            if command[0] == "cargo":
                events.append("cargo")
                manifest = HELPER.read_toml(Path(command[command.index("--manifest-path") + 1]))
                self.assertEqual(set(manifest["patch"][pins["upstream_url"]]), set(paths))
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
            ):
                stack.enter_context(patch.object(HELPER, name, **kwargs))
            stack.enter_context(patch.object(HELPER.subprocess, "run", side_effect=run))
            stack.enter_context(patch.object(HELPER.subprocess, "check_output", return_value="offline-test-version"))
            command = ["--cpu", "test-wrapper", "--", "cargo", "build", "--locked", "--no-default-features"]
            if reject_reverification or reject_tooling:
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
            self.assertEqual(events, ["prepare-wrapper", "cargo", "reverify-wrapper"])
            record = json.loads(attestation.read_text())
            self.assertIs(record["inputs_reverified"], True)
            self.assertEqual(record["zkos_wrapper"]["inputs"], HELPER.wrapper_pins_metadata())
            self.assertEqual(record["zkos_wrapper"]["source"]["patched_tree"], HELPER.WRAPPER_PATCHED_TREE)
            self.assertEqual(set(record["zkos_wrapper"]["package_paths"]), set(HELPER.WRAPPER_PACKAGES))
            for suffix in ("json", "patch"):
                relative = "patches/zkos-wrapper-buffered-os-rng." + suffix
                self.assertEqual(record["tooling_sha256"][relative], HELPER.sha256(ROOT / relative))
            self.assertEqual(record, json.loads((build / "build-result.json").read_text()))
            self.assertEqual((Path(temporary) / "Cargo.lock").read_bytes(), (ROOT / "Cargo.lock").read_bytes())
            self.assertEqual((build / "prover/Cargo.lock").read_bytes(),
                             (ROOT / "patches/airbender.Cargo.lock").read_bytes())

    def test_cpu_reverification_failure_never_emits_success_attestation(self):
        with tempfile.TemporaryDirectory() as temporary:
            attestation, build, events = self.exercise(temporary, reject_reverification=True)
            self.assertEqual(events, ["prepare-wrapper", "cargo", "reverify-wrapper"])
            self.assertFalse(attestation.exists())
            self.assertFalse((build / "build-result.json").exists())

    def test_cpu_cargo_failure_remains_unverified(self):
        with tempfile.TemporaryDirectory() as temporary:
            attestation, build, events = self.exercise(temporary, cargo_exit_code=9)
            self.assertEqual(events, ["prepare-wrapper", "cargo"])
            self.assertFalse(attestation.exists())
            record = json.loads((build / "build-result.json").read_text())
            self.assertIs(record["inputs_reverified"], False)
            self.assertEqual(record["cargo_exit_code"], 9)

    def test_cpu_tooling_drift_never_emits_success_attestation(self):
        with tempfile.TemporaryDirectory() as temporary:
            attestation, build, events = self.exercise(temporary, reject_tooling=True)
            self.assertEqual(events, ["prepare-wrapper", "cargo", "reverify-wrapper"])
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
