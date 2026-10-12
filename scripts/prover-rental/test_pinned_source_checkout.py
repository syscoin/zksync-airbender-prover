"""Offline exact Git checkout regressions; no provider, build, or proof calls."""

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("pinned_checkout", ROOT / "scripts/pinned_source_checkout.py")
HELPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HELPER)


class PinnedSourceCheckoutTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        self.git(self.source, "init", "--quiet")
        self.git(self.source, "config", "user.name", "Local fixture")
        self.git(self.source, "config", "user.email", "fixture@example.invalid")
        (self.source / "historical-large.bin").write_bytes(b"historical fixture" * (1024 * 256))
        (self.source / "current.txt").write_text("first\n")
        self.git(self.source, "add", ".")
        self.git(self.source, "commit", "--quiet", "-m", "historical large blob")
        self.ancestor = self.git(self.source, "rev-parse", "HEAD")
        self.old_blob = self.git(self.source, "rev-parse", "HEAD:historical-large.bin")
        (self.source / "historical-large.bin").unlink()
        (self.source / "current.txt").write_text("pinned current tree\n")
        self.git(self.source, "add", "--all")
        self.git(self.source, "commit", "--quiet", "-m", "remove historical blob")
        self.commit = self.git(self.source, "rev-parse", "HEAD")
        self.tree = self.git(self.source, "rev-parse", "HEAD^{tree}")
        self.destination = self.root / "checkout"

    def git(self, repository, *arguments):
        environment = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull,
                       "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"}
        return subprocess.check_output(["git", "-C", str(repository), *arguments],
                                       text=True, env=environment).strip()

    def test_exact_tree_and_full_ancestry_without_historical_blob(self):
        before = self.git(self.source, "config", "--local", "--list")
        HELPER.checkout_pinned_source(self.source, self.destination, self.commit, self.tree)
        self.assertEqual(self.git(self.destination, "rev-parse", "HEAD"), self.commit)
        self.assertEqual(self.git(self.destination, "rev-parse", "HEAD^{tree}"), self.tree)
        self.assertEqual(self.git(self.destination, "status", "--porcelain", "--untracked-files=all"), "")
        self.assertEqual((self.destination / "current.txt").read_text(), "pinned current tree\n")
        self.assertEqual(self.git(self.destination, "merge-base", "HEAD", self.ancestor), self.ancestor)
        self.assertEqual(self.git(self.destination, "rev-parse", "--is-shallow-repository"), "false")
        # Inspect stored objects without invoking Git's lazy-fetch path.
        stored = subprocess.check_output(["git", "-C", str(self.destination), "cat-file",
                                          "--batch-all-objects", "--batch-check=%(objectname)"], text=True)
        self.assertNotIn(self.old_blob, stored.splitlines())
        self.assertEqual(self.git(self.source, "config", "--local", "--list"), before)
        self.assertEqual(self.git(self.source, "status", "--porcelain"), "")

    def test_wrong_tree_refuses_before_materialization_and_preserves_outcome(self):
        with self.assertRaisesRegex(ValueError, "differs from the reviewed"):
            HELPER.checkout_pinned_source(self.source, self.destination, self.commit, "1" * 40)
        self.assertTrue((self.destination / ".git").is_dir())
        self.assertFalse((self.destination / "current.txt").exists())
        with self.assertRaisesRegex(ValueError, "fresh absolute"):
            HELPER.checkout_pinned_source(self.source, self.destination, self.commit, self.tree)

    def test_wrong_commit_and_malformed_identity_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "cache lacks objects"):
            HELPER.checkout_pinned_source(self.source, self.destination, "1" * 40, self.tree)
        self.assertFalse((self.destination / "current.txt").exists())
        for commit in ("main", self.commit.upper(), "0" * 40):
            with self.subTest(commit=commit), self.assertRaisesRegex(ValueError, "Git identities"):
                HELPER.checkout_pinned_source(self.source, self.root / "fresh", commit, self.tree)
        self.assertFalse((self.root / "fresh").exists())

    def test_occupied_directory_file_and_dangling_link_are_preserved(self):
        for name, kind in (("directory", "directory"), ("file", "file"), ("link", "link")):
            target = self.root / name
            if kind == "directory":
                target.mkdir()
                (target / "retained").write_text("retained")
            elif kind == "file":
                target.write_text("retained")
            else:
                target.symlink_to(self.root / "missing")
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "fresh absolute"):
                HELPER.checkout_pinned_source(self.source, target, self.commit, self.tree)
            if kind == "directory":
                self.assertEqual((target / "retained").read_text(), "retained")
            elif kind == "file":
                self.assertEqual(target.read_text(), "retained")
            else:
                self.assertTrue(target.is_symlink())

    def test_credentials_in_urls_are_rejected_before_checkout(self):
        for url in ("https://user:secret@example.invalid/repository.git",
                    "https://example.invalid/repository.git?token=secret"):
            with self.subTest(url=url), self.assertRaisesRegex(ValueError, "credential-free"):
                HELPER.checkout_pinned_source(url, self.destination, self.commit, self.tree)
        self.assertFalse(self.destination.exists())

    def test_canonical_rental_cli_uses_the_same_verified_checkout(self):
        result = subprocess.run([sys.executable, str(ROOT / "scripts/pinned_source_checkout.py"),
                                 str(self.source), self.commit, self.tree, str(self.destination)],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.git(self.destination, "rev-parse", "HEAD"), self.commit)

    def test_callers_local_git_configuration_cannot_rewrite_the_source(self):
        caller = self.root / "caller"
        caller.mkdir()
        self.git(caller, "init", "--quiet")
        self.git(caller, "config", "url.file:///missing-source/.insteadOf", self.source.as_uri())
        self.git(caller, "config", "http.extraHeader", "Authorization: fixture-only")
        result = subprocess.run([sys.executable, str(ROOT / "scripts/pinned_source_checkout.py"),
                                 str(self.source), self.commit, self.tree, str(self.destination)],
                                cwd=caller, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.git(self.destination, "rev-parse", "HEAD"), self.commit)
        self.assertFalse((self.destination / ".git/config").read_text().find("fixture-only") >= 0)

    def test_intermediate_symlink_parent_is_refused(self):
        parent = self.root / "parent"
        parent.mkdir()
        link = self.root / "alias"
        link.symlink_to(parent, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "fresh absolute"):
            HELPER.checkout_pinned_source(self.source, link / "checkout", self.commit, self.tree)
        self.assertFalse((parent / "checkout").exists())

    def test_partial_local_cache_missing_tip_blob_refuses_without_modifying_cache(self):
        cache = self.root / "partial-cache"
        HELPER.checkout_pinned_source(self.source, cache, self.commit, self.tree)
        blob = self.git(self.source, "rev-parse", "HEAD:current.txt")
        # Remove only the disposable fixture pack containing the tip's fetched blob.
        for index in (cache / ".git/objects/pack").glob("*.idx"):
            objects = self.git(cache, "verify-pack", "-v", str(index))
            if any(line.startswith(blob + " ") for line in objects.splitlines()):
                for suffix in (".idx", ".pack", ".promisor"):
                    path = index.with_suffix(suffix)
                    if path.exists():
                        path.unlink()
        before = {str(path.relative_to(cache)): path.read_bytes()
                  for path in cache.rglob("*") if path.is_file()}
        with self.assertRaisesRegex(ValueError, "cache lacks objects"):
            HELPER.checkout_pinned_source(cache, self.destination, self.commit, self.tree)
        self.assertEqual(before, {str(path.relative_to(cache)): path.read_bytes()
                                 for path in cache.rglob("*") if path.is_file()})
        self.assertFalse(self.destination.exists())

    def test_materialized_partial_local_cache_keeps_missing_history_and_source_unchanged(self):
        cache = self.root / "partial-cache"
        HELPER.checkout_pinned_source(self.source, cache, self.commit, self.tree)
        before = {str(path.relative_to(cache)): path.read_bytes()
                  for path in cache.rglob("*") if path.is_file()}
        HELPER.checkout_pinned_source(cache, self.destination, self.commit, self.tree)
        self.assertEqual(before, {str(path.relative_to(cache)): path.read_bytes()
                                 for path in cache.rglob("*") if path.is_file()})
        self.assertEqual((self.destination / "current.txt").read_text(), "pinned current tree\n")
        stored = self.git(cache, "cat-file", "--batch-all-objects", "--batch-check=%(objectname)")
        self.assertNotIn(self.old_blob, stored.splitlines())


if __name__ == "__main__":
    unittest.main()
