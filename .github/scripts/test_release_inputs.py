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
        paths.update({RELEASE.GUARD.DEFAULT_SCOPE, ".github/release-please/manifest.json"})
        for path in paths:
            destination = self.root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(RELEASE.ROOT / path, destination)

    def read_json(self, path):
        return json.loads((self.root / path).read_text())

    def write_json(self, path, value):
        (self.root / path).write_text(json.dumps(value, indent=2) + "\n")

    def test_checked_in_inputs_pass(self):
        RELEASE.validate(self.root)

    def test_release_manifest_version_mismatch_fails(self):
        path = ".github/release-please/manifest.json"
        self.write_json(path, {".": "0.8.99"})
        with self.assertRaisesRegex(ValueError, "release manifest and workspace version differ"):
            RELEASE.validate(self.root)

    def test_changed_lock_with_stale_hash_fails(self):
        for path in ("Cargo.lock", "patches/airbender.Cargo.lock"):
            with self.subTest(path=path):
                original = (self.root / path).read_bytes()
                (self.root / path).write_bytes(original + b"\n")
                with self.assertRaisesRegex(ValueError, "lock hash differs"):
                    RELEASE.validate(self.root)
                (self.root / path).write_bytes(original)

    def test_rehashed_lock_with_wrong_local_package_version_fails(self):
        lock_path = "Cargo.lock"
        data = (self.root / lock_path).read_text()
        data = data.replace('name = "protocol_version"\nversion = "0.8.2"',
                            'name = "protocol_version"\nversion = "0.8.99"')
        (self.root / lock_path).write_text(data)
        pins_path = "patches/airbender-fork-source.json"
        pins = self.read_json(pins_path)
        pins["canonical_lock_sha256"] = hashlib.sha256(data.encode()).hexdigest()
        self.write_json(pins_path, pins)
        with self.assertRaisesRegex(ValueError, "workspace package version differs"):
            RELEASE.validate(self.root)

    def test_scope_remains_fail_closed(self):
        path = self.root / "deny.toml"
        path.write_text(path.read_text() + "\n# requires review\n")
        with self.assertRaisesRegex(ValueError, "scope inputs changed"):
            RELEASE.validate(self.root)


if __name__ == "__main__":
    unittest.main()
