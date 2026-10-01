"""Offline source-overlay guards; no CUDA calls, builds, downloads, or shared-cache writes."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "patched_airbender", ROOT / "scripts/prepare-patched-airbender.py"
)
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)
PINS = json.loads((ROOT / "patches/airbender-cuda-device-diagnostics.json").read_text())


def parent_lock_bytes():
    """Exact lock from parent488f70ac, reconstructed without requiring Git history in CI."""
    raw = (ROOT / "Cargo.lock").read_bytes()
    for name, removed in (
        ("zksync_os_fri_prover", (b' "sha2 0.10.9",\n',)),
        ("zksync_os_snark_prover", (b' "libc",\n', b' "sha2 0.10.9",\n')),
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

    def test_only_all_airbender_source_identities_change(self):
        packages = HELPER.audit_lock(self.canonical, self.overlay, PINS)
        self.assertEqual(len(packages), 46)
        self.assertIn("gpu_prover", packages)
        self.assertIn("cli", packages)
        self.assertIn("execution_utils", packages)
        self.assertFalse(any("zksync-airbender" in item.get("source", "")
                             for item in self.overlay["package"]))

    def test_current_derivation_is_byte_identical_to_reviewed_overlay(self):
        raw, selected = HELPER.selected_lock_overlay(
            ROOT / "Cargo.lock", ROOT / "patches/airbender.Cargo.lock", PINS)
        self.assertEqual(raw, (ROOT / "patches/airbender.Cargo.lock").read_bytes())
        self.assertEqual(selected["canonical_lock_sha256"], PINS["canonical_lock_sha256"])
        self.assertEqual(selected["overlay_lock_sha256"], PINS["overlay_lock_sha256"])
        self.assertEqual(selected["airbender_packages"], HELPER.audit_lock(self.canonical, self.overlay, PINS))

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
                with self.assertRaisesRegex(ValueError, "more than Airbender source identity"):
                    HELPER.audit_lock(self.canonical, modified, PINS)

    def test_crypto_or_wrapper_pin_drift_rejected(self):
        for dependency in ("zksync-crypto.git", "zkos-wrapper.git"):
            with self.subTest(dependency=dependency):
                modified = copy.deepcopy(self.overlay)
                item = next(item for item in modified["package"]
                            if dependency in item.get("source", ""))
                item["source"] += "-changed"
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
        self.assertEqual(source.count("diff --git "), 1)
        self.assertIn("gpu_prover/src/execution/gpu_worker.rs", source)
        additions = "\n".join(line[1:] for line in source.splitlines()
                              if line.startswith("+") and not line.startswith("+++"))
        self.assertIn("device_get_attribute(CudaDeviceAttr::MultiProcessorCount, device_id)?", additions)
        self.assertNotIn("get_device_properties", additions)
        self.assertNotIn("unsafe", additions)
        self.assertNotIn("CStr", additions)


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
