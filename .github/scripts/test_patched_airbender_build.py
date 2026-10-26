"""Offline source-overlay guards; no CUDA calls, builds, downloads, or shared-cache writes."""

import copy
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
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
    registry_fixture = (ROOT / ".github/tests/fixtures/parent-registry.Cargo.lock").read_bytes()
    restored_names = HELPER.tomllib.loads(registry_fixture.decode())["restore"]["remove_names"]
    blocks = re.split(rb"(?m)(?=^\[\[package\]\]\n)", raw)
    package_name = lambda block: HELPER.tomllib.loads(block.decode())["package"][0]["name"]
    packages = [block for block in blocks[1:] if package_name(block) not in restored_names]
    packages.extend(re.split(rb"(?m)(?=^\[\[package\]\]\n)", registry_fixture)[1:])
    raw = blocks[0] + b"".join(sorted(packages, key=package_name))
    fork = HELPER.fork_lock_source(PINS).encode()
    upstream = PINS["upstream_lock_source"].encode()
    if raw.count(fork) != 46:
        raise AssertionError("canonical fork lock fixture changed")
    raw = raw.replace(fork, upstream)
    wrapper_fork = HELPER.fork_wrapper_lock_source(HELPER.load_wrapper_pins()).encode()
    if raw.count(wrapper_fork) != 2:
        raise AssertionError("canonical wrapper fork lock fixture changed")
    raw = raw.replace(wrapper_fork, HELPER.WRAPPER_LOCK_SOURCE.encode())
    current_webpki = (b'name = "rustls-webpki"\nversion = "0.103.16"\n'
                      b'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                      b'checksum = "4443b1b6d39d7c663139942cc4558262562d2c84123bb6282ef177009ca8b281"')
    parent_webpki = current_webpki.replace(b'0.103.16', b'0.103.6').replace(
        b'4443b1b6d39d7c663139942cc4558262562d2c84123bb6282ef177009ca8b281',
        b'8572f3c2cb9934231157b45499fc41e1f58c589fdfb81a844ba873265e80f8eb')
    if raw.count(current_webpki) != 1:
        raise AssertionError("canonical TLS lock fixture changed")
    raw = raw.replace(current_webpki, parent_webpki)
    current_rustls = (b'name = "rustls"\nversion = "0.23.46"\n'
                      b'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                      b'checksum = "48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf"')
    parent_rustls = current_rustls.replace(b'0.23.46', b'0.23.32').replace(
        b'48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf',
        b'cd3c25631629d034ce7cd9940adc9d45762d46de2b0f57193c4443b92c6d4d40')
    if raw.count(current_rustls) != 1:
        raise AssertionError("canonical rustls lock fixture changed")
    raw = raw.replace(current_rustls, parent_rustls)
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
        self.assertEqual(selected["schema_version"], 4)
        self.assertEqual(selected["derivation"], "common-proving-source-identity-only-v4")
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

    def test_historical_source_redirects_wrappers_fork_dependencies(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            manifest = source / "Cargo.toml"
            manifest.write_text('''[workspace]
members = []
[workspace.dependencies]
zksync_airbender_execution_utils = { package = "execution_utils", git = "https://github.com/matter-labs/zksync-airbender", tag = "v0.6.0-rc.2" }
zkos_wrapper = { package = "zkos-wrapper", git = "https://github.com/matter-labs/zkos-wrapper.git", tag = "v0.6.0-rc.2" }
''')
            lock = source / "Cargo.lock"
            lock.write_bytes(parent_lock_bytes())
            _, selected = HELPER.selected_lock_overlay(
                lock, ROOT / "patches/airbender.Cargo.lock", PINS)
            self.assertEqual(selected["airbender_lock_source"], PINS["upstream_lock_source"])
            paths = {name: "crates/" + name for name in selected["airbender_packages"]}
            wrapper = HELPER.load_wrapper_pins()
            crypto = HELPER.load_crypto_pins()
            HELPER.prepare_application_manifest(
                manifest, source / "unused-snark.toml", PINS,
                selected["airbender_lock_source"], paths, wrapper,
                {name: name for name in wrapper["upstream_packages"]}, crypto,
                {name: name for name in crypto["upstream_packages"]},
                source / "airbender", source / "wrapper", source / "crypto")
            patches = HELPER.read_toml(manifest)["patch"]
            expected = {name: {"path": str(source / "airbender" / path)}
                        for name, path in paths.items()}
            self.assertEqual(patches[PINS["upstream_url"]], expected)
            self.assertEqual(patches[PINS["fork_url"]], expected)
            self.assertTrue(set(HELPER.WRAPPER_AIRBENDER_ROOTS) <= set(expected))

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
        first["source"] = first["source"].replace(PINS["fork_commit"], "f" * 40)
        with self.assertRaisesRegex(ValueError, "mixed or unknown Airbender"):
            HELPER.audit_lock(modified, self.overlay, PINS)

    def test_missing_airbender_package_rejected(self):
        modified = copy.deepcopy(self.canonical)
        modified["package"] = [item for item in modified["package"] if item["name"] != "gpu_prover"]
        with self.assertRaisesRegex(ValueError, "package count"):
            HELPER.audit_lock(modified, self.overlay, PINS)


class CommonCryptoForkTests(unittest.TestCase):
    def fixture(self, temporary, pins=None):
        manifest = Path(temporary) / HELPER.CRYPTO_PIN_PATH.name
        manifest.write_text(json.dumps(pins or CRYPTO_PINS))
        return manifest

    def test_exact_manifest_and_no_byte_patch_inputs(self):
        self.assertEqual(HELPER.load_crypto_pins(), CRYPTO_PINS)
        self.assertEqual(CRYPTO_PINS["schema_version"], 2)
        self.assertEqual(len(CRYPTO_PINS["upstream_packages"]), 11)
        self.assertEqual(tuple(CRYPTO_PINS[key] for key in ("fork_url", "fork_commit", "fork_tree")),
                         HELPER.CRYPTO_FORK)
        self.assertTrue({"patch_file", "patch_sha256", "changed_files", "patched_tree"}.isdisjoint(CRYPTO_PINS))
        for suffix in ("json", "patch"):
            self.assertFalse((ROOT / "patches" / ("zksync-crypto-native-fri-query-count." + suffix)).exists())

    def test_manifest_unknown_origins_sources_fields_and_versions_rejected(self):
        edits = (
            lambda p: p.update(schema_version=True),
            lambda p: p.update(schema_version=1),
            lambda p: p.update(upstream_url="https://example.invalid/crypto"),
            lambda p: p.update(upstream_commit="f" * 40),
            lambda p: p.update(upstream_tree="f" * 40),
            lambda p: p.update(upstream_lock_source=HELPER.CRYPTO_LOCK_SOURCE + "-changed"),
            lambda p: p["upstream_packages"].update(boojum="0.32.9"),
            lambda p: p.update(fork_url="https://example.invalid/fork"),
            lambda p: p.update(fork_commit="f" * 40),
            lambda p: p.update(fork_tree="f" * 40),
            lambda p: p.update(patch_file="../escape.patch"),
            lambda p: p.update(patched_tree="f" * 40),
            lambda p: p.update(unknown="unreviewed"),
        )
        for edit in edits:
            with self.subTest(edit=edit), tempfile.TemporaryDirectory() as temporary:
                pins = copy.deepcopy(CRYPTO_PINS)
                edit(pins)
                with self.assertRaises(ValueError):
                    HELPER.load_crypto_pins(self.fixture(temporary, pins))

    def test_duplicate_keys_and_symlinks_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest = self.fixture(temporary)
            manifest.write_text('{"schema_version":2,"schema_version":2}')
            with self.assertRaisesRegex(ValueError, "duplicate"):
                HELPER.load_crypto_pins(manifest)
            manifest.unlink()
            manifest.symlink_to(HELPER.CRYPTO_PIN_PATH)
            with self.assertRaises(ValueError):
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

    def test_extra_fork_git_package_cannot_pass_as_an_unrelated_lock_input(self):
        fork_source = ("git+" + CRYPTO_PINS["fork_url"] + "?rev=" + CRYPTO_PINS["fork_commit"]
                       + "#" + CRYPTO_PINS["fork_commit"])
        extra = {"name": "unexpected-common-fork", "version": "0.32.10", "source": fork_source}
        canonical = copy.deepcopy(HELPER.read_toml(ROOT / "Cargo.lock"))
        overlay = copy.deepcopy(HELPER.read_toml(ROOT / "patches/airbender.Cargo.lock"))
        canonical["package"].append(extra.copy())
        overlay["package"].append(extra.copy())
        with self.assertRaisesRegex(ValueError, "mixed common crypto sources"):
            HELPER.audit_lock(canonical, overlay, PINS)
        with tempfile.TemporaryDirectory() as temporary:
            lock = Path(temporary) / "Cargo.lock"
            lock.write_text((ROOT / "Cargo.lock").read_text()
                            + '\n[[package]]\nname = "unexpected-common-fork"\nversion = "0.32.10"\n'
                            + "source = " + json.dumps(fork_source) + "\n")
            original = lock.read_bytes()
            with self.assertRaisesRegex(ValueError, "mixed common crypto sources"):
                HELPER.selected_lock_overlay(lock, ROOT / "patches/airbender.Cargo.lock", PINS)
            self.assertEqual(lock.read_bytes(), original)

    def test_prepare_clones_exact_fork_and_all_packages_without_touching_original(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            build = Path(temporary)
            local = build / "original"
            local.mkdir()
            verify = stack.enter_context(patch.object(HELPER, "verify_crypto"))
            paths = {name: "crates/" + name for name in HELPER.CRYPTO_PACKAGES}
            stack.enter_context(patch.object(HELPER, "package_paths", return_value=paths))
            run = stack.enter_context(patch.object(HELPER.subprocess, "run"))
            checkout = stack.enter_context(patch.object(HELPER, "checkout_pinned_source"))
            stack.enter_context(patch.dict(HELPER.os.environ, {"ZKSYNC_CRYPTO_SOURCE_DIR": str(local)}, clear=True))
            root, clone, actual = HELPER.prepare_crypto(build, CRYPTO_PINS)
            self.assertEqual(root, build / "zksync-crypto")
            self.assertEqual(clone, str(local.resolve()))
            self.assertEqual(actual, paths)
            checkout.assert_called_once_with(
                str(local.resolve()), root, CRYPTO_PINS["fork_commit"], CRYPTO_PINS["fork_tree"])
            run.assert_not_called()
            self.assertEqual(list(local.iterdir()), [])
            verify.assert_called_once_with(root, CRYPTO_PINS)

    def test_crypto_reverification_rejects_head_base_tree_and_dirty_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            values = {
                ("rev-parse", "HEAD"): CRYPTO_PINS["fork_commit"],
                ("merge-base", "HEAD", CRYPTO_PINS["upstream_commit"]): CRYPTO_PINS["upstream_commit"],
                ("rev-parse", "HEAD^{tree}"): CRYPTO_PINS["fork_tree"],
                ("status", "--porcelain", "--untracked-files=all"): "",
            }
            with patch.object(HELPER, "run_git", side_effect=lambda repo, *args: values[args]):
                HELPER.verify_crypto(root, CRYPTO_PINS)
                for args in values:
                    original = values[args]
                    values[args] = "unexpected"
                    with self.subTest(args=args), self.assertRaises(ValueError):
                        HELPER.verify_crypto(root, CRYPTO_PINS)
                    values[args] = original

    def test_real_fork_accepts_ancestry_and_rejects_staged_unstaged_and_untracked_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "--quiet", str(root)], check=True)

            def commit(message):
                subprocess.run(["git", "-C", str(root), "-c", "user.name=Test",
                                "-c", "user.email=test@example.invalid", "commit",
                                "--allow-empty", "--quiet", "-m", message], check=True)
                return HELPER.run_git(root, "rev-parse", "HEAD")

            source = root / "source.rs"
            source.write_text("baseline")
            HELPER.run_git(root, "add", "source.rs")
            base = commit("upstream baseline")
            source.write_text("fork")
            HELPER.run_git(root, "add", "source.rs")
            fork = commit("reviewed crypto fork")
            pins = {**CRYPTO_PINS, "upstream_commit": base, "fork_commit": fork,
                    "fork_tree": HELPER.run_git(root, "rev-parse", "HEAD^{tree}")}
            HELPER.verify_crypto(root, pins)
            source.write_text("late edit")
            with self.assertRaisesRegex(ValueError, "fork source changed"):
                HELPER.verify_crypto(root, pins)
            HELPER.run_git(root, "add", "source.rs")
            with self.assertRaisesRegex(ValueError, "fork source changed"):
                HELPER.verify_crypto(root, pins)
            HELPER.run_git(root, "restore", "--staged", "--worktree", "source.rs")
            untracked = root / "new.rs"
            untracked.write_text("unreviewed")
            with self.assertRaisesRegex(ValueError, "fork source changed"):
                HELPER.verify_crypto(root, pins)
            untracked.unlink()
            HELPER.run_git(root, "checkout", "--quiet", "-b", "sibling", base)
            pins["fork_commit"] = commit("sibling")
            pins["fork_tree"] = HELPER.run_git(root, "rev-parse", "HEAD^{tree}")
            pins["upstream_commit"] = fork
            with self.assertRaisesRegex(ValueError, "fork base changed"):
                HELPER.verify_crypto(root, pins)

    def test_pure_metadata_never_invokes_external_commands(self):
        with patch.object(HELPER.subprocess, "run") as run, patch.object(HELPER.subprocess, "check_output") as output:
            metadata = HELPER.crypto_pins_metadata()
            self.assertEqual(metadata["pins"], CRYPTO_PINS)
            self.assertEqual(metadata["manifest_sha256"], HELPER.sha256(HELPER.CRYPTO_PIN_PATH))
            run.assert_not_called()
            output.assert_not_called()


class AirbenderPinTests(unittest.TestCase):
    def test_canonical_cargo_graph_pins_one_fork_source(self):
        manifest = HELPER.read_toml(ROOT / "Cargo.toml")
        snark = HELPER.read_toml(ROOT / "crates/zksync_os_snark_prover/Cargo.toml")
        self.assertEqual(manifest["patch"][PINS["upstream_url"]], {
            name: {"git": PINS["fork_url"], "rev": PINS["fork_commit"]}
            for name in HELPER.WRAPPER_AIRBENDER_ROOTS})
        for dependency in ("zksync_airbender_execution_utils", "zksync_airbender_cli"):
            self.assertEqual(manifest["workspace"]["dependencies"][dependency]["git"], PINS["fork_url"])
            self.assertEqual(manifest["workspace"]["dependencies"][dependency]["rev"], PINS["fork_commit"])
        for dependency in ("riscv_transpiler", "verifier_common"):
            self.assertEqual(snark["dependencies"][dependency],
                             {"git": PINS["fork_url"], "rev": PINS["fork_commit"]})
        lock = HELPER.read_toml(ROOT / "Cargo.lock")
        self.assertEqual(sum(p.get("source") == HELPER.fork_lock_source(PINS)
                             for p in lock["package"]), 46)
        self.assertFalse(any(p.get("source") == PINS["upstream_lock_source"]
                             for p in lock["package"]))

    def fixture(self, directory, pins):
        directory = Path(directory)
        manifest = directory / HELPER.PIN_PATH.name
        manifest.write_text(json.dumps(pins))
        for filename in (PINS["overlay_lock_file"],):
            (directory / filename).write_bytes((ROOT / "patches" / filename).read_bytes())
        return manifest

    def test_immutable_fork_source_and_pure_metadata(self):
        with patch.object(HELPER.subprocess, "run") as run, patch.object(HELPER.subprocess, "check_output") as output:
            pins = HELPER.load_airbender_pins()
            self.assertEqual(tuple(pins[key] for key in ("fork_url", "fork_commit", "fork_tree")),
                             HELPER.AIRBENDER_FORK)
            self.assertEqual(tuple(pins[key] for key in ("upstream_url", "upstream_commit", "upstream_tree")),
                             HELPER.AIRBENDER_UPSTREAM)
            run.assert_not_called()
            output.assert_not_called()

    def test_current_fri_artifact_matches_lifted_source(self):
        artifact_path = ROOT / "crates/zksync_os_fri_prover/artifacts/syscoin-v32-security100-fri-setups.json"
        artifact = HELPER.json_document(artifact_path)
        metadata, summaries = artifact["metadata"], artifact["summaries"]
        loader = (ROOT / "crates/zksync_os_fri_prover/src/setup_summaries.rs").read_text()
        integration = (ROOT / "crates/zksync_os_fri_prover/src/lib.rs").read_text()
        dependencies = HELPER.read_toml(ROOT / "Cargo.toml")["workspace"]["dependencies"]
        lock = HELPER.read_toml(ROOT / "Cargo.lock")
        revision = PINS["upstream_commit"]
        self.assertEqual(metadata["airbender_revision"], revision)
        self.assertEqual(metadata["airbender_patched_tree"], PINS["fork_tree"])
        self.assertIn(f'const AIRBENDER_REVISION: &str = "{revision}";', loader)
        self.assertIn('const BUNDLED_ARTIFACT_SHA256: &str =\n    "'
                      + HELPER.sha256(artifact_path) + '";', loader)
        for dependency, package in (("zksync_airbender_execution_utils", "execution_utils"),
                                    ("zksync_airbender_cli", "cli")):
            self.assertEqual(dependencies[dependency]["git"], PINS["fork_url"])
            self.assertEqual(dependencies[dependency]["rev"], PINS["fork_commit"])
            locked = [row for row in lock["package"] if row["name"] == package]
            self.assertEqual(len(locked), 1)
            self.assertEqual(locked[0]["source"], HELPER.fork_lock_source(PINS))
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
        # The base revision still names the rc.2 lineage. The tree names the
        # actual fork source. Matching source identities is not proof qualification.
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
        for test in ("current_bundled_artifact_loads_and_binds_all_release_inputs",
                     "historical_source_key_and_program_metadata_fail_closed",
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
            lambda p: p.update(overlay_lock_file="../escape.lock"),
            lambda p: p.update(fork_url="https://example.invalid/airbender"),
            lambda p: p.update(fork_commit="f" * 40),
            lambda p: p.update(fork_tree="f" * 40),
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
            manifest.write_text('{"schema_version":3,"schema_version":3}')
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                HELPER.load_airbender_pins(manifest)
            manifest.unlink()
            manifest.symlink_to(HELPER.PIN_PATH)
            with self.assertRaises(ValueError):
                HELPER.load_airbender_pins(manifest)
            manifest.unlink()
            for name in (PINS["overlay_lock_file"],):
                manifest = self.fixture(temporary, PINS)
                (manifest.parent / name).write_bytes(b"changed")
                with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                    HELPER.load_airbender_pins(manifest)

    def test_reverification_rejects_commit_ancestry_tree_and_dirty_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            values = {
                ("rev-parse", "HEAD"): PINS["fork_commit"],
                ("merge-base", "HEAD", PINS["upstream_commit"]): PINS["upstream_commit"],
                ("rev-parse", "HEAD^{tree}"): PINS["fork_tree"],
                ("status", "--porcelain", "--untracked-files=all"): "",
            }
            with patch.object(HELPER, "run_git", side_effect=lambda repo, *args: values[args]):
                HELPER.verify_airbender_source(root, PINS)
                for args, original in list(values.items()):
                    values[args] = "unexpected"
                    with self.assertRaises(ValueError):
                        HELPER.verify_airbender_source(root, PINS)
                    values[args] = original

    def test_fork_source_allows_non_parent_upstream_ancestor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "--quiet", str(root)], check=True)

            def commit(message):
                subprocess.run(["git", "-C", str(root), "-c", "user.name=Test",
                                "-c", "user.email=test@example.invalid", "commit",
                                "--allow-empty", "--quiet", "-m", message], check=True)
                return HELPER.run_git(root, "rev-parse", "HEAD")

            base = commit("upstream base")
            commit("first fork fix")
            tip = commit("second fork fix")
            pins = copy.deepcopy(PINS)
            pins["upstream_commit"] = base
            pins["fork_commit"] = tip
            pins["fork_tree"] = HELPER.run_git(root, "rev-parse", "HEAD^{tree}")
            HELPER.verify_airbender_source(root, pins)

            subprocess.run(["git", "-C", str(root), "checkout", "--quiet", "-b",
                            "unrelated", base], check=True)
            pins["upstream_commit"] = tip
            pins["fork_commit"] = commit("sibling fork")
            with self.assertRaisesRegex(ValueError, "fork base changed"):
                HELPER.verify_airbender_source(root, pins)


class WrapperPinTests(unittest.TestCase):
    def fixture(self, directory, pins):
        manifest = Path(directory) / "zkos-wrapper-fork-source.json"
        manifest.write_text(json.dumps(pins))
        return manifest

    def test_metadata_is_complete_and_never_executes_subprocess(self):
        with patch.object(HELPER.subprocess, "run") as run, patch.object(HELPER.subprocess, "check_output") as output:
            metadata = HELPER.wrapper_pins_metadata()
            self.assertEqual(metadata["manifest_sha256"], HELPER.sha256(HELPER.WRAPPER_PIN_PATH))
            self.assertEqual(metadata["pins"]["upstream_packages"], HELPER.WRAPPER_PACKAGES)
            self.assertEqual(tuple(metadata["pins"][key] for key in ("fork_url", "fork_commit", "fork_tree")),
                             HELPER.WRAPPER_FORK)
            run.assert_not_called()
            output.assert_not_called()

    def test_bundled_commitment_matches_the_pinned_wrapper_fork(self):
        artifact = HELPER.json_document(
            ROOT / "crates/zksync_os_snark_prover/artifacts/syscoin-v32-security100-commitment.json")
        pins = HELPER.load_wrapper_pins()
        loader = (ROOT / "crates/zksync_os_snark_prover/src/binary_commitment.rs").read_text()
        lock = HELPER.read_toml(ROOT / "Cargo.lock")
        dependency = HELPER.read_toml(ROOT / "Cargo.toml")["workspace"]["dependencies"]["zkos_wrapper"]
        self.assertNotEqual(artifact["wrapper_circuit_revision"], pins["upstream_commit"])
        self.assertEqual(artifact["wrapper_circuit_revision"], pins["fork_commit"])
        self.assertEqual(artifact["wrapper_circuit_patched_tree"], pins["fork_tree"])
        self.assertIn(f'const WRAPPER_CIRCUIT_REVISION: &str = "{pins["fork_commit"]}";', loader)
        self.assertIn(f'const WRAPPER_CIRCUIT_PATCHED_TREE: &str = "{pins["fork_tree"]}";', loader)
        self.assertEqual(dependency["git"], pins["fork_url"])
        self.assertEqual(dependency["rev"], pins["fork_commit"])
        self.assertEqual(dependency["features"], ["security_100"])
        self.assertIs(dependency["default-features"], False)
        locked = [row for row in lock["package"] if row["name"] == "zkos-wrapper"]
        self.assertEqual(len(locked), 1)
        self.assertEqual(locked[0]["source"], HELPER.fork_wrapper_lock_source(pins))
        for field, relative in (("bin", "multiblock_batch.bin"), ("text", "multiblock_batch.text")):
            self.assertEqual(artifact["app"][field]["sha256"], HELPER.sha256(ROOT / relative))
            self.assertEqual(artifact["app"][field]["size_bytes"], (ROOT / relative).stat().st_size)

    def test_current_bundles_share_the_registered_key_chain_and_setup_digest(self):
        commitment = HELPER.json_document(
            ROOT / "crates/zksync_os_snark_prover/artifacts/syscoin-v32-security100-commitment.json")
        fri_path = ROOT / "crates/zksync_os_fri_prover/artifacts/syscoin-v32-security100-fri-setups.json"
        fri = HELPER.json_document(fri_path)
        for field in ("schema_version", "protocol_version", "execution_version", "proving_version",
                      "security_bits", "airbender_revision", "airbender_patched_tree", "vk_hash",
                      "program_commitment", "app", "recursion_unrolled", "recursion_unified"):
            self.assertEqual(fri["metadata"][field], commitment[field], field)
        words = [int(commitment["program_commitment"][offset:offset + 8], 16)
                 for offset in range(2, 66, 8)]
        self.assertEqual(commitment["aux_params"], words)
        self.assertEqual(commitment["end_params"], fri["summaries"]["recursion_unified"]["end_params"])
        self.assertEqual(fri["summaries"]["security_bits"], 100)
        self.assertEqual(commitment["wrapper_domain_log"], 25)
        self.assertIs(commitment["check_aux_params"], True)
        fri_source = (ROOT / "crates/zksync_os_fri_prover/src/setup_summaries.rs").read_text()
        registry = (ROOT / "crates/protocol_version/src/lib.rs").read_text()
        self.assertIn('"' + HELPER.sha256(fri_path) + '"', fri_source)
        self.assertIn('const VK_HASH: &str = "' + commitment["vk_hash"] + '";', fri_source)
        self.assertIn('const SYSCOIN_VK_HASH: &str = "' + commitment["vk_hash"] + '";', registry)
        self.assertIn('"' + commitment["program_commitment"] + '"', fri_source)

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
            lambda p: p.update(fork_url="https://example.invalid/zkos-wrapper.git"),
            lambda p: p.update(fork_commit="f" * 40),
            lambda p: p.update(fork_tree="f" * 40),
            lambda p: p.update(purpose=""),
        ):
            with tempfile.TemporaryDirectory() as temporary:
                invalid = copy.deepcopy(pins)
                edit(invalid)
                with self.assertRaises(ValueError):
                    HELPER.load_wrapper_pins(self.fixture(temporary, invalid))

    def test_duplicate_manifest_keys_and_symlinks_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest = self.fixture(temporary, HELPER.load_wrapper_pins())
            manifest.write_text('{"schema_version":2,"schema_version":2}')
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                HELPER.load_wrapper_pins(manifest)
            manifest.unlink()
            manifest.symlink_to(HELPER.WRAPPER_PIN_PATH)
            with self.assertRaisesRegex(ValueError, "invalid JSON input"):
                HELPER.load_wrapper_pins(manifest)

    def test_ci_executes_dependency_rng_and_commitment_tests_from_attested_wrapper_workspace(self):
        workflow = (ROOT / ".github/workflows/ci.yaml").read_text()
        self.assertIn('AIRBENDER_BUILD_ATTESTATION="${RUNNER_TEMP}/ci-test-airbender-inputs.json"', workflow)
        self.assertIn("ci-test -- cargo test --locked --no-default-features", workflow)
        self.assertIn('python3 -B .github/scripts/run_pinned_wrapper_tests.py \\\n'
                      '            "${RUNNER_TEMP}/ci-test-airbender-inputs.json"', workflow)
        self.assertIn('run: python3 -B .github/scripts/test_run_pinned_wrapper_tests.py', workflow)
        self.assertNotIn('cargo test --manifest-path "${wrapper}/Cargo.toml"', workflow)
        self.assertNotIn('cargo test --manifest-path "${workspace}/Cargo.toml"', workflow)
        self.assertIn('      - name: Run pinned wrapper source tests\n'
                      '        env:\n'
                      '          RUST_MIN_STACK: "33554432"\n'
                      '          CARGO_PROFILE_DEV_DEBUG: "0"\n'
                      '        run: |', workflow)

    def test_ci_wrapper_shell_routes_attestation_and_preserves_helper_failure(self):
        lines = (ROOT / ".github/workflows/ci.yaml").read_text().splitlines()
        step = lines.index("      - name: Run pinned wrapper source tests")
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

    def test_prepare_uses_isolated_fork_clone_and_exact_pin(self):
        pins = HELPER.load_wrapper_pins()
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary).resolve()
            local_source = root / "source"
            local_source.mkdir()
            marker = local_source / "untouched"
            marker.write_bytes(b"source must remain unchanged")
            stack.enter_context(patch.dict(HELPER.os.environ, {"ZKOS_WRAPPER_SOURCE_DIR": str(local_source)}, clear=True))
            run = stack.enter_context(patch.object(HELPER.subprocess, "run"))
            git = stack.enter_context(patch.object(HELPER, "run_git"))
            checkout = stack.enter_context(patch.object(HELPER, "checkout_pinned_source"))
            verify = stack.enter_context(patch.object(HELPER, "verify_wrapper"))
            paths = stack.enter_context(patch.object(HELPER, "package_paths", return_value={"zkos-wrapper": "wrapper"}))
            upstream, clone_source, package_paths = HELPER.prepare_wrapper(root, pins)
            self.assertEqual(upstream, root / "zkos-wrapper")
            self.assertEqual(clone_source, str(local_source))
            self.assertEqual(package_paths, {"zkos-wrapper": "wrapper"})
            checkout.assert_called_once_with(
                str(local_source), upstream, pins["fork_commit"], pins["fork_tree"])
            run.assert_not_called()
            git.assert_not_called()
            verify.assert_called_once_with(upstream, pins)
            paths.assert_called_once_with(upstream, pins["upstream_packages"])
            self.assertEqual(marker.read_bytes(), b"source must remain unchanged")

    def test_reverification_rejects_head_tree_ancestry_and_dirty_source(self):
        pins = HELPER.load_wrapper_pins()
        values = {
            ("rev-parse", "HEAD"): pins["fork_commit"],
            ("merge-base", "HEAD", pins["upstream_commit"]): pins["upstream_commit"],
            ("rev-parse", "HEAD^{tree}"): pins["fork_tree"],
            ("status", "--porcelain", "--untracked-files=all"): "",
        }
        with patch.object(HELPER, "run_git", side_effect=lambda repo, *args: values[args]):
            HELPER.verify_wrapper(Path("/fixture"), pins)
            for args, original in list(values.items()):
                values[args] = "unexpected"
                with self.assertRaises(ValueError):
                    HELPER.verify_wrapper(Path("/fixture"), pins)
                values[args] = original


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


class PreparedGuardCompatibilityTests(unittest.TestCase):
    def validate(self, source):
        HELPER.require_compatible_build_guards(
            source, PINS, HELPER.load_wrapper_pins(), HELPER.load_crypto_pins())

    def test_current_guards_match_the_selected_marker_identity(self):
        self.validate(ROOT)
        for crate in ("zksync_os_fri_prover", "zksync_os_snark_prover"):
            self.assertEqual(HELPER.sha256(ROOT / "crates" / crate / "build.rs"),
                             HELPER.PREPARED_BUILD_GUARD_SHA256)

    def test_guardless_historical_source_retains_existing_compatibility_checks(self):
        with tempfile.TemporaryDirectory() as temporary:
            self.validate(Path(temporary))

    def test_old_exact_tree_and_malformed_guards_are_rejected_unchanged(self):
        current = (ROOT / "crates/zksync_os_fri_prover/build.rs").read_bytes()
        old = current.replace(b"a1e9a551b9588b1dfab5c5088554fc69770c0e85",
                              b"9a1110f6c514338b3143909a726fe97b9af6c9cd").replace(
            b"c52391d0df82126d27e5c76810e9df85c61875d0",
            b"f8d7b132a841e0bfbfccd27614314a279d523887")
        preceding = current.replace(b"c52391d0df82126d27e5c76810e9df85c61875d0",
                                    b"4fda70a408c7817474fe67fba46b38cfbe420e59")
        malformed = current.replace(b"assert_eq!(actual, expected", b"assert_eq!(actual, actual")
        for crate in ("zksync_os_fri_prover", "zksync_os_snark_prover"):
            for raw in (old, preceding, malformed):
                with self.subTest(crate=crate, old=raw == old), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    guard = root / "crates" / crate / "build.rs"
                    guard.parent.mkdir(parents=True)
                    guard.write_bytes(raw)
                    with self.assertRaisesRegex(ValueError, "exact matching validated tooling"):
                        self.validate(root)
                    self.assertEqual(guard.read_bytes(), raw)
                    self.assertFalse((root / "target").exists())

    def test_guard_identity_cannot_disagree_with_selected_pins(self):
        changed = dict(HELPER.load_crypto_pins(), fork_tree="f" * 40)
        with self.assertRaisesRegex(ValueError, "incompatible proving-source guard"):
            HELPER.require_compatible_build_guards(ROOT, PINS, HELPER.load_wrapper_pins(), changed)

    def test_guard_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            guard = root / "crates/zksync_os_fri_prover/build.rs"
            guard.parent.mkdir(parents=True)
            guard.symlink_to(ROOT / "crates/zksync_os_fri_prover/build.rs")
            with self.assertRaisesRegex(ValueError, "incompatible proving-source guard"):
                self.validate(root)

    def test_cpu_rejects_incompatible_guard_before_snapshot_network_or_cargo(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Cargo.toml").write_text('[workspace]\nmembers = ["crates/protocol_version"]\n')
            package = root / "crates/protocol_version/Cargo.toml"
            package.parent.mkdir(parents=True)
            package.write_text('[package]\nname = "protocol_version"\nversion = "0.1.0"\n')
            guard = root / "crates/zksync_os_snark_prover/build.rs"
            guard.parent.mkdir(parents=True)
            original = (ROOT / "crates/zksync_os_snark_prover/build.rs").read_bytes().replace(
                b"c52391d0df82126d27e5c76810e9df85c61875d0",
                b"4fda70a408c7817474fe67fba46b38cfbe420e59")
            guard.write_bytes(original)
            with patch.dict(HELPER.os.environ, {"PROVER_SOURCE_DIR": str(root)}, clear=True), \
                    patch.object(HELPER, "copy_application") as copy_app, \
                    patch.object(HELPER, "checkout_pinned_source") as checkout, \
                    patch.object(HELPER.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "incompatible proving-source guard"):
                    HELPER.main(["old-guard", "--", "cargo", "build", "--locked", "-p", "protocol_version"])
                copy_app.assert_not_called()
                checkout.assert_not_called()
                run.assert_not_called()
            self.assertEqual(guard.read_bytes(), original)
            self.assertFalse((root / "target").exists())


class PreparedBuildGuardTests(unittest.TestCase):
    def test_proving_build_scripts_require_workspace_bound_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary).resolve() / "prepared/prover"
            workspace.mkdir(parents=True)
            marker = workspace / HELPER.PREPARED_SOURCE_MARKER
            marker.write_bytes(HELPER.prepared_source_marker(
                workspace, PINS, HELPER.load_wrapper_pins(), HELPER.load_crypto_pins()))
            for crate in ("zksync_os_fri_prover", "zksync_os_snark_prover"):
                with self.subTest(crate=crate):
                    (workspace / "crates" / crate).mkdir(parents=True)
                    binary = Path(temporary) / (crate + "-build-guard")
                    subprocess.run(["rustc", "--edition=2021", str(ROOT / "crates" / crate / "build.rs"),
                                    "-o", str(binary)], check=True, capture_output=True)
                    environment = os.environ.copy()
                    environment["CARGO_MANIFEST_DIR"] = str(ROOT / "crates" / crate)
                    self.assertNotEqual(subprocess.run([binary], env=environment, capture_output=True).returncode, 0)
                    environment["CARGO_MANIFEST_DIR"] = str(workspace / "crates" / crate)
                    self.assertEqual(subprocess.run([binary], env=environment, capture_output=True).returncode, 0)
                    marker.write_bytes(b"stale prepared sources\n")
                    self.assertNotEqual(subprocess.run([binary], env=environment, capture_output=True).returncode, 0)
                    marker.write_bytes(HELPER.prepared_source_marker(
                        workspace, PINS, HELPER.load_wrapper_pins(), HELPER.load_crypto_pins()))


class WrapperCpuIntegrationTests(unittest.TestCase):
    def exercise(self, temporary, *, reject_reverification=False, reject_tooling=False,
                 reject_crypto_reverification=False, reject_crypto_tooling=False,
                 reject_marker=False, cargo_exit_code=0):
        """Test CPU orchestration with real snapshots/records and mocked external tools."""
        source = Path(temporary).resolve()
        (source / "crates/example/src").mkdir(parents=True)
        (source / "crates/example/src/lib.rs").write_text("pub fn fixture() {}\n")
        (source / "crates/example/Cargo.toml").write_text('[package]\nname = "example"\nversion = "0.1.0"\n')
        for name in HELPER.SOURCE_FILES:
            (source / name).write_bytes((ROOT / name).read_bytes())
        (source / "Cargo.lock").write_bytes((source / "Cargo.lock").read_bytes().replace(
            HELPER.fork_lock_source(PINS).encode(), PINS["upstream_lock_source"].encode()))
        (source / "Cargo.toml").write_text('[workspace]\nmembers = ["crates/example"]\n')
        attestation = source / "verified-build.json"
        events = []
        pins = HELPER.load_wrapper_pins()
        paths = {"circuit_mersenne_field": "circuit_mersenne_field", "zkos-wrapper": "wrapper"}
        crypto_pins = HELPER.load_crypto_pins()
        crypto_paths = {name: "crates/" + name for name in HELPER.CRYPTO_PACKAGES}
        checked_hash = HELPER.checked_hash

        def check_local_or_external(path, digest):
            if reject_tooling and path == HELPER.WRAPPER_PIN_PATH:
                raise ValueError("tooling changed after Cargo")
            if reject_crypto_tooling and path == HELPER.CRYPTO_PIN_PATH:
                raise ValueError("common crypto tooling changed after Cargo")
            checked_hash(path, digest)

        def prepare_wrapper(build, selected_pins):
            self.assertEqual(selected_pins, pins)
            events.append("prepare-wrapper")
            return build / "zkos-wrapper", pins["fork_url"], paths

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
                self.assertEqual(set(manifest["patch"][pins["fork_url"]]), set(paths))
                self.assertEqual(set(manifest["patch"][crypto_pins["upstream_url"]]), set(crypto_paths))
                self.assertIn("--no-default-features", command)
                if reject_marker:
                    Path(command[command.index("--manifest-path") + 1]).parent.joinpath(
                        HELPER.PREPARED_SOURCE_MARKER).write_text("changed after Cargo\n")
                return unittest.mock.Mock(returncode=cargo_exit_code)
            self.fail(f"unexpected external command: {command}")

        with ExitStack() as stack:
            stack.enter_context(patch.dict(HELPER.os.environ, {
                "PROVER_SOURCE_DIR": str(source), "AIRBENDER_BUILD_ATTESTATION": str(attestation),
            }, clear=True))
            checkout = stack.enter_context(patch.object(HELPER, "checkout_pinned_source"))
            for name, kwargs in (
                ("checked_hash", {"side_effect": check_local_or_external}),
                ("run_git", {"return_value": PINS["upstream_tree"]}),
                ("verify_airbender_source", {}),
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
            if (reject_reverification or reject_tooling or reject_crypto_reverification
                    or reject_crypto_tooling or reject_marker):
                with self.assertRaisesRegex(ValueError, "SHA-256 mismatch" if reject_marker else "changed after Cargo"):
                    HELPER.main(command)
            else:
                self.assertEqual(HELPER.main(command), cargo_exit_code)
        builds = list((source / "target/patched-airbender").iterdir())
        self.assertEqual(len(builds), 1)
        checkout.assert_called_once_with(
            PINS["fork_url"], builds[0] / "airbender", PINS["fork_commit"], PINS["fork_tree"])
        return attestation, builds[0], events

    def test_cpu_success_records_wrapper_closure_after_reverification(self):
        with tempfile.TemporaryDirectory() as temporary:
            attestation, build, events = self.exercise(temporary)
            self.assertEqual(events, ["prepare-wrapper", "prepare-crypto", "cargo", "reverify-wrapper", "reverify-crypto"])
            record = json.loads(attestation.read_text())
            self.assertIs(record["inputs_reverified"], True)
            self.assertEqual(record["zkos_wrapper"]["inputs"], HELPER.wrapper_pins_metadata())
            self.assertEqual(record["zkos_wrapper"]["source"]["fork_tree"], HELPER.WRAPPER_FORK[2])
            self.assertEqual(set(record["zkos_wrapper"]["package_paths"]), set(HELPER.WRAPPER_PACKAGES))
            self.assertEqual(record["zksync_crypto"]["inputs"], HELPER.crypto_pins_metadata())
            self.assertEqual(record["zksync_crypto"]["source"]["fork_tree"], HELPER.CRYPTO_FORK[2])
            self.assertEqual(set(record["zksync_crypto"]["package_paths"]), set(HELPER.CRYPTO_PACKAGES))
            relative = "patches/zkos-wrapper-fork-source.json"
            self.assertEqual(record["tooling_sha256"][relative], HELPER.sha256(ROOT / relative))
            relative = "scripts/pinned_source_checkout.py"
            self.assertEqual(record["tooling_sha256"][relative], HELPER.sha256(ROOT / relative))
            relative = "patches/zksync-crypto-fork-source.json"
            self.assertEqual(record["tooling_sha256"][relative], HELPER.sha256(ROOT / relative))
            self.assertEqual(record["zksync_crypto"]["source"]["fork_commit"], HELPER.CRYPTO_FORK[1])
            self.assertEqual(record, json.loads((build / "build-result.json").read_text()))
            self.assertEqual((Path(temporary) / "Cargo.lock").read_bytes(),
                             (ROOT / "Cargo.lock").read_bytes().replace(
                                 HELPER.fork_lock_source(PINS).encode(),
                                 PINS["upstream_lock_source"].encode()))
            self.assertEqual((build / "prover/Cargo.lock").read_bytes(),
                             (ROOT / "patches/airbender.Cargo.lock").read_bytes())
            self.assertEqual(record["prepared_source_marker_sha256"],
                             HELPER.sha256(build / "prover" / HELPER.PREPARED_SOURCE_MARKER))

    def test_cpu_reverification_failure_never_emits_success_attestation(self):
        with tempfile.TemporaryDirectory() as temporary:
            attestation, build, events = self.exercise(temporary, reject_reverification=True)
            self.assertEqual(events, ["prepare-wrapper", "prepare-crypto", "cargo", "reverify-wrapper"])
            self.assertFalse(attestation.exists())
            self.assertFalse((build / "build-result.json").exists())

    def test_cpu_marker_drift_never_emits_success_attestation(self):
        with tempfile.TemporaryDirectory() as temporary:
            attestation, build, events = self.exercise(temporary, reject_marker=True)
            self.assertEqual(events, ["prepare-wrapper", "prepare-crypto", "cargo", "reverify-wrapper", "reverify-crypto"])
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
                    patch.object(HELPER, "checkout_pinned_source", side_effect=CloneBoundary) as checkout, \
                    patch.object(HELPER.subprocess, "run") as run:
                with self.assertRaises(CloneBoundary):
                    HELPER.main(["parent-source", "--", "cargo", "build", "--locked"])
                checkout.assert_called_once()
                clone_source, destination, commit, tree = checkout.call_args.args
                self.assertEqual(clone_source, PINS["fork_url"])
                self.assertEqual(destination.name, "airbender")
                self.assertEqual(commit, PINS["fork_commit"])
                self.assertEqual(tree, PINS["fork_tree"])
                run.assert_not_called()
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
                    patch.object(HELPER.subprocess, "run") as run, \
                    patch.object(HELPER, "checkout_pinned_source") as checkout:
                with self.assertRaisesRegex(ValueError, "mixed or unknown Airbender"):
                    HELPER.main(["incompatible-source", "--", "cargo", "build", "--locked"])
                run.assert_not_called()
                checkout.assert_not_called()
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
