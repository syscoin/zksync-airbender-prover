"""Regression checks for the release-input gate."""

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("check_release_inputs.py")
SPEC = importlib.util.spec_from_file_location("release_inputs", SCRIPT)
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)


class ReleaseInputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        paths = set(RELEASE.GUARD.collect_inputs(RELEASE.ROOT))
        paths.update({RELEASE.GUARD.DEFAULT_SCOPE, ".github/release-please/manifest.json",
                      "patches/airbender-fork-source.json", "patches/airbender.Cargo.lock"})
        for path in paths:
            destination = self.root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(RELEASE.ROOT / path, destination)

    def read_json(self, path):
        return json.loads((self.root / path).read_text())

    def write_json(self, path, value):
        (self.root / path).write_text(json.dumps(value, indent=2) + "\n")

    def test_release_automation_is_bound_to_main(self):
        workflow = (RELEASE.ROOT / ".github/workflows/release-please.yaml").read_text()
        self.assertIn("if: ${{ github.ref == 'refs/heads/main' }}", workflow)
        self.assertIn("target-branch: main", workflow)

    def test_checked_in_inputs_pass(self):
        RELEASE.validate(self.root)

    def test_release_manifest_version_mismatch_fails(self):
        path = ".github/release-please/manifest.json"
        self.write_json(path, {".": "0.8.99"})
        with self.assertRaisesRegex(ValueError, "release manifest and workspace version differ"):
            RELEASE.validate(self.root)

    def test_release_please_bump_needs_lock_updates(self):
        self.write_json(".github/release-please/manifest.json", {".": "0.8.99"})
        cargo = self.root / "Cargo.toml"
        original = cargo.read_text()
        current = RELEASE.tomllib.loads(original)["workspace"]["package"]["version"]
        self.assertEqual(original.count(f'version = "{current}"'), 1)
        cargo.write_text(original.replace(f'version = "{current}"', 'version = "0.8.99"'))
        with self.assertRaisesRegex(ValueError, "workspace package version differs"):
            RELEASE.validate(self.root)

    def test_changed_lock_with_stale_hash_fails(self):
        path = self.root / "Cargo.lock"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "scope inputs changed.*Cargo.lock"):
            RELEASE.validate(self.root)

    def test_rehashed_lock_with_wrong_local_package_version_fails(self):
        lock_path = "Cargo.lock"
        data = (self.root / lock_path).read_text()
        current = self.read_json(".github/release-please/manifest.json")["."]
        record = f'name = "protocol_version"\nversion = "{current}"'
        self.assertEqual(data.count(record), 1)
        data = data.replace(record,
                            'name = "protocol_version"\nversion = "0.8.99"')
        (self.root / lock_path).write_text(data)
        scope = self.read_json(RELEASE.GUARD.DEFAULT_SCOPE)
        scope["inputs"][lock_path] = hashlib.sha256(data.encode()).hexdigest()
        self.write_json(RELEASE.GUARD.DEFAULT_SCOPE, scope)
        with self.assertRaisesRegex(ValueError, "workspace package version differs"):
            RELEASE.validate(self.root)

    def test_v2_git_source_must_match_the_selected_manifest(self):
        pins = self.read_json(RELEASE.V2_PINS)
        pins["airbender"]["commit"] = "0" * 40
        self.write_json(RELEASE.V2_PINS, pins)
        with self.assertRaisesRegex(ValueError, "Cargo.lock differs from the V2 source manifest"):
            RELEASE.validate(self.root)

    def test_v2_tree_change_still_requires_scope_review(self):
        pins = self.read_json(RELEASE.V2_PINS)
        pins["airbender"]["tree"] = "0" * 40
        self.write_json(RELEASE.V2_PINS, pins)
        with self.assertRaisesRegex(ValueError, "scope inputs changed.*v2-proving-sources.json"):
            RELEASE.validate(self.root)

    def test_v2_manifest_symlink_is_rejected(self):
        path = self.root / RELEASE.V2_PINS
        path.unlink()
        path.symlink_to(RELEASE.ROOT / RELEASE.V2_PINS)
        with self.assertRaisesRegex(ValueError, "symlinked scope input"):
            RELEASE.validate(self.root)

    def test_missing_v2_manifest_cannot_bypass_reviewed_scope(self):
        (self.root / RELEASE.V2_PINS).unlink()
        pins_path = "patches/airbender-fork-source.json"
        pins = self.read_json(pins_path)
        data = (self.root / "Cargo.lock").read_bytes()
        (self.root / "patches/airbender.Cargo.lock").write_bytes(data)
        for key in ("canonical_lock_sha256", "overlay_lock_sha256"):
            pins[key] = hashlib.sha256(data).hexdigest()
        self.write_json(pins_path, pins)
        with self.assertRaisesRegex(ValueError, "missing or nonregular scope input.*v2-proving-sources.json"):
            RELEASE.validate(self.root)

    def test_legacy_lock_hash_and_workspace_checks_remain_enforced(self):
        data = b'[[package]]\nname = "legacy"\nversion = "1.0.0"\n'
        paths = {"Cargo.lock": "canonical_lock_sha256",
                 "patches/airbender.Cargo.lock": "overlay_lock_sha256"}
        pins = {}
        for relative, key in paths.items():
            (self.root / relative).write_bytes(data)
            pins[key] = hashlib.sha256(data).hexdigest()
        self.write_json("patches/airbender-fork-source.json", pins)
        RELEASE.validate_legacy_locks(self.root, {"legacy": "1.0.0"})
        with self.assertRaisesRegex(ValueError, "workspace package version differs"):
            RELEASE.validate_legacy_locks(self.root, {"legacy": "1.0.1"})
        for relative in paths:
            with self.subTest(path=relative):
                (self.root / relative).write_bytes(data + b"\n")
                with self.assertRaisesRegex(ValueError, "lock hash differs"):
                    RELEASE.validate_legacy_locks(self.root, {"legacy": "1.0.0"})
                (self.root / relative).write_bytes(data)

    def test_scope_remains_fail_closed(self):
        path = self.root / "deny.toml"
        path.write_text(path.read_text() + "\n# requires review\n")
        with self.assertRaisesRegex(ValueError, "scope inputs changed"):
            RELEASE.validate(self.root)


if __name__ == "__main__":
    unittest.main()
