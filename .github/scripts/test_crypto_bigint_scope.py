"""Offline tests for the immutable crypto-bigint advisory exception scope."""

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("check_crypto_bigint_scope.py")
SPEC = importlib.util.spec_from_file_location("crypto_bigint_scope", SCRIPT)
GUARD = importlib.util.module_from_spec(SPEC)
exec(compile(SCRIPT.read_bytes(), str(SCRIPT), "exec"), GUARD.__dict__)


def lockfile():
    return f'''version = 4

[[package]]
name = "crypto-bigint"
version = "{GUARD.CRYPTO_BIGINT_VERSION}"
source = "{GUARD.CRYPTO_BIGINT_SOURCE}"
checksum = "{GUARD.CRYPTO_BIGINT_CHECKSUM}"

[[package]]
name = "boojum"
version = "0.32.10"
dependencies = ["crypto-bigint"]

[[package]]
name = "elliptic-curve"
version = "0.13.8"
dependencies = ["crypto-bigint"]
'''


class CryptoBigintScopeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for relative in GUARD.FIXED_INPUTS:
            self.write(relative, "reviewed fixture input: " + relative + "\n")
        self.write("Cargo.toml", '[workspace]\nmembers = ["crates/prover"]\n')
        self.write("deny.toml", '[advisories]\nignore = ["' + GUARD.ADVISORY + '"]\n')
        for relative in GUARD.LOCK_PATHS:
            self.write(relative, lockfile())
        self.write("crates/prover/Cargo.toml", '[package]\nname = "prover"\nversion = "0.1.0"\n')
        self.write("crates/prover/src/lib.rs", "pub fn prove() {}\n")
        self.write("crates/prover/build.rs", "fn main() {}\n")
        self.write("crates/prover/examples/wrap.rs", "fn main() {}\n")
        self.record_scope()

    def write(self, relative, contents):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
        return path

    def scope(self):
        return {"schema_version": 1, "advisory": GUARD.ADVISORY,
                "inputs": GUARD.collect_inputs(self.root)}

    def record_scope(self, scope=None):
        return self.write(GUARD.DEFAULT_SCOPE, json.dumps(self.scope() if scope is None else scope,
                                                        indent=2, sort_keys=True) + "\n")

    def assert_rejected(self, message):
        with self.assertRaisesRegex(ValueError, message):
            GUARD.check_scope(self.root)

    def test_valid_temporary_repository_and_default_manifest(self):
        self.assertEqual(GUARD.check_scope(self.root), len(GUARD.collect_inputs(self.root)))
        self.assertEqual(list(GUARD.collect_inputs(self.root)), sorted(GUARD.collect_inputs(self.root)))

    def test_every_fixed_input_and_crate_source_change_invalidates_scope(self):
        for relative in GUARD.collect_inputs(self.root):
            if relative in GUARD.LOCK_PATHS or relative == "deny.toml":
                continue
            with self.subTest(relative=relative):
                path = self.root / relative
                original = path.read_bytes()
                path.write_bytes(original + b"\nreview required\n")
                self.assert_rejected("scope inputs changed")
                path.write_bytes(original)

    def test_new_entrypoint_manifest_and_build_script_are_not_implicitly_reviewed(self):
        for relative in ("crates/prover/src/bin/sign.rs", "crates/new/Cargo.toml",
                         "crates/new/build.rs", "crates/prover/tests/non_native.rs"):
            with self.subTest(relative=relative):
                path = self.write(relative, "// new scope input\n")
                self.assert_rejected("file list changed")
                path.unlink()

    def test_removed_source_is_not_implicitly_reviewed(self):
        (self.root / "crates/prover/src/lib.rs").unlink()
        self.assert_rejected("file list changed")

    def test_both_lockfile_content_changes_invalidate_scope(self):
        for relative in GUARD.LOCK_PATHS:
            with self.subTest(relative=relative):
                path = self.root / relative
                original = path.read_text()
                path.write_text(original + '\n[[package]]\nname = "extra"\nversion = "1.0.0"\n')
                self.assert_rejected("scope inputs changed")
                path.write_text(original)

    def test_package_identity_checks_are_independent_of_recorded_hashes(self):
        for relative in GUARD.LOCK_PATHS:
            for field, original, replacement in (
                ("version", GUARD.CRYPTO_BIGINT_VERSION, "0.5.6"),
                ("source", GUARD.CRYPTO_BIGINT_SOURCE, "git+https://example.test/crypto-bigint"),
                ("checksum", GUARD.CRYPTO_BIGINT_CHECKSUM, "a" * 64),
            ):
                with self.subTest(relative=relative, field=field):
                    path = self.root / relative
                    path.write_text(lockfile().replace(original, replacement))
                    self.record_scope()
                    self.assert_rejected("crypto-bigint identity changed")
                    path.write_text(lockfile())
        self.record_scope()

    def test_extra_or_missing_crypto_bigint_versions_are_rejected(self):
        for replacement in ("", lockfile() + '\n[[package]]\nname = "crypto-bigint"\nversion = "0.6.0"\n'):
            with self.subTest(replacement=replacement):
                self.write("Cargo.lock", replacement)
                self.record_scope()
                self.assert_rejected("package list|exactly one crypto-bigint")
        self.write("Cargo.lock", lockfile())

    def test_direct_parent_names_are_checked_in_both_locks(self):
        for relative in GUARD.LOCK_PATHS:
            for invalid in (
                lockfile().replace('name = "boojum"', 'name = "signing-service"'),
                lockfile().replace('dependencies = ["crypto-bigint"]', 'dependencies = []', 1),
                lockfile() + '\n[[package]]\nname = "new-parent"\nversion = "1.0.0"\ndependencies = ["crypto-bigint"]\n',
                lockfile() + '\n[[package]]\nname = "boojum"\nversion = "0.33.0"\ndependencies = ["crypto-bigint"]\n',
            ):
                with self.subTest(relative=relative, invalid=invalid):
                    self.write(relative, invalid)
                    self.record_scope()
                    self.assert_rejected("direct parents changed")
                    self.write(relative, lockfile())
        self.record_scope()

    def test_explicit_cargo_dependency_edges_resolve_to_reviewed_identity(self):
        for edge in ("crypto-bigint " + GUARD.CRYPTO_BIGINT_VERSION,
                     "crypto-bigint " + GUARD.CRYPTO_BIGINT_VERSION + " (" + GUARD.CRYPTO_BIGINT_SOURCE + ")"):
            with self.subTest(edge=edge):
                self.write("Cargo.lock", lockfile().replace('"crypto-bigint"]', json.dumps(edge) + "]"))
                self.record_scope()
                GUARD.check_scope(self.root)

    def test_unknown_crypto_bigint_dependency_identity_is_rejected(self):
        self.write("Cargo.lock", lockfile().replace('"crypto-bigint"]', '"crypto-bigint 0.6.0"]'))
        self.record_scope()
        self.assert_rejected("unknown crypto-bigint dependency edge")

    def test_crypto_fork_manifest_full_contents_are_bound(self):
        path = self.root / "patches/zksync-crypto-fork-source.json"
        path.write_text('{"fork_commit": "changed", "purpose": "unreviewed source"}\n')
        self.assert_rejected("scope inputs changed.*zksync-crypto-fork-source.json")

    def test_exact_advisory_ignore_is_required_even_after_recording_new_hashes(self):
        for ignores in ([], ["RUSTSEC-2026-0388"], [GUARD.ADVISORY, GUARD.ADVISORY],
                        [{"id": GUARD.ADVISORY, "reason": "not an exact string ignore"}]):
            with self.subTest(ignores=ignores):
                self.write("deny.toml", "[advisories]\nignore = " + json.dumps(ignores).replace(":", " =") + "\n")
                self.record_scope()
                self.assert_rejected("must ignore exactly")

    def test_changes_to_other_ignores_invalidate_review(self):
        self.write("deny.toml", '[advisories]\nignore = ["' + GUARD.ADVISORY + '", "RUSTSEC-2026-0999"]\n')
        self.assert_rejected("scope inputs changed.*deny.toml")

    def test_new_cargo_override_invalidates_review(self):
        self.write(".cargo/config.toml", '[patch.crates-io]\ncrypto-bigint = { path = "../unreviewed" }\n')
        self.assert_rejected("file list changed")

    def test_source_and_directory_symlinks_are_rejected(self):
        source = self.root / "crates/prover/src/lib.rs"
        source.unlink()
        source.symlink_to(self.write("external.rs", "pub fn unreviewed() {}\n"))
        self.assert_rejected("symlinked scope input")
        source.unlink()
        self.write("crates/prover/src/lib.rs", "pub fn prove() {}\n")
        directory = self.root / "crates/linked"
        directory.symlink_to(self.root / "crates/prover", target_is_directory=True)
        self.assert_rejected("symlinked crate directory")

    def test_missing_fixed_input_is_rejected(self):
        (self.root / "scripts/prepare-patched-airbender.py").unlink()
        self.assert_rejected("missing or nonregular scope input")

    def test_missing_manifest_and_manifest_symlink_are_rejected(self):
        scope = self.root / GUARD.DEFAULT_SCOPE
        original = scope.read_text()
        scope.unlink()
        self.assert_rejected("missing or nonregular reviewed scope")
        scope.symlink_to(self.write("alternate-scope.json", original))
        self.assert_rejected("missing or nonregular reviewed scope")

    def test_strict_json_schema_digest_and_path_validation(self):
        original = self.scope()
        for mutate in (
            lambda scope: scope.update(extra="unreviewed"),
            lambda scope: scope.update(schema_version=True),
            lambda scope: scope.update(advisory="RUSTSEC-2026-0999"),
            lambda scope: scope.update(inputs={}),
            lambda scope: scope["inputs"].update({"../outside.rs": "a" * 64}),
            lambda scope: scope["inputs"].update({"crates//prover/src/lib.rs": "a" * 64}),
            lambda scope: scope["inputs"].update({"Cargo.toml": "bad-digest"}),
            lambda scope: scope["inputs"].pop("Cargo.toml"),
        ):
            scope = copy.deepcopy(original)
            mutate(scope)
            with self.subTest(scope=scope):
                self.record_scope(scope)
                self.assert_rejected("scope")

    def test_duplicate_json_key_is_rejected(self):
        self.write(GUARD.DEFAULT_SCOPE, '{"schema_version": 1, "schema_version": 1}')
        self.assert_rejected("duplicate scope JSON key")

    def test_cli_checks_and_does_not_offer_auto_refresh(self):
        valid = subprocess.run([sys.executable, str(SCRIPT), "--root", str(self.root)],
                               capture_output=True, text=True)
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertIn(GUARD.ADVISORY, valid.stdout)
        self.write("crates/prover/src/main.rs", "fn main() {}\n")
        invalid = subprocess.run([sys.executable, str(SCRIPT), "--root", str(self.root)],
                                 capture_output=True, text=True)
        self.assertEqual(invalid.returncode, 1)
        self.assertIn("file list changed", invalid.stderr)
        refresh = subprocess.run([sys.executable, str(SCRIPT), "--refresh"],
                                 capture_output=True, text=True)
        self.assertNotEqual(refresh.returncode, 0)
        self.assertIn("unrecognized arguments", refresh.stderr)


if __name__ == "__main__":
    unittest.main()
