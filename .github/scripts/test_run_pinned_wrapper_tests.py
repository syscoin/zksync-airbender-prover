"""Offline tests for dependency unit-test graph ownership and input integrity."""

import copy
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "pinned_wrapper_tests", ROOT / ".github/scripts/run_pinned_wrapper_tests.py")
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)
BASE = RUNNER.BASE


class WrapperTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="wrapper graph with spaces ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        self.workspace = self.root / "prepared/prover"
        self.workspace.mkdir(parents=True)
        self.roots = {group: self.workspace.parent / name for group, name in (
            ("air", "airbender"), ("wrapper", "zkos-wrapper"), ("crypto", "zksync-crypto"))}
        for directory in self.roots.values():
            directory.mkdir()
        self.air, self.wrapper, self.crypto = (BASE.load_airbender_pins(), BASE.load_wrapper_pins(),
                                              BASE.load_crypto_pins())
        self.overlay, self.selected = BASE.selected_lock_overlay(
            ROOT / "Cargo.lock", BASE.PIN_PATH.parent / self.air["overlay_lock_file"],
            self.air, self.wrapper, self.crypto)
        self.groups = {
            "air": {name: version for name, version in self.selected["airbender_packages"].items()
                    if name not in {"cli", "gpu_prover"}},
            "crypto": {name: version for name, version in self.crypto["upstream_packages"].items()
                       if name != "zksync_solidity_vk_codegen"}}
        self.paths = {"air": {name: "crates/" + name for name in self.selected["airbender_packages"]},
                      "crypto": {name: "crates/" + name for name in self.crypto["upstream_packages"]},
                      "wrapper": {"zkos-wrapper": "wrapper", "circuit_mersenne_field": "circuit_mersenne_field"}}
        self.own_paths = {**self.paths["wrapper"], "wrapper_generator": "wrapper_generator"}
        for name, route in self.own_paths.items():
            package = self.roots["wrapper"] / route
            package.mkdir()
            (package / "Cargo.toml").write_text(f'[package]\nname = "{name}"\nversion = "0.1.0"\n')
        wrapper_source = self.roots["wrapper"] / "wrapper/src"
        wrapper_source.mkdir()
        (wrapper_source / "lib.rs").write_text("// pinned wrapper source fixture\n")
        (self.roots["wrapper"] / "Cargo.toml").write_text(
            '[workspace]\nresolver = "2"\nmembers = ["wrapper", "circuit_mersenne_field", "wrapper_generator"]\n')
        self.raw = self.canonical_wrapper_lock()
        (self.roots["wrapper"] / "Cargo.lock").write_bytes(self.raw)
        for relative in ("Cargo.toml", "Cargo.lock"):
            (self.source / relative).write_bytes((ROOT / relative).read_bytes())
        (self.source / "fixture.rs").write_text("// application input\n")
        (self.workspace / "fixture.rs").write_bytes((self.source / "fixture.rs").read_bytes())
        manifest = (self.source / "Cargo.toml").read_text()
        for group, pins in (("air", self.air), ("wrapper", self.wrapper), ("crypto", self.crypto)):
            manifest += "\n[patch." + json.dumps(pins["upstream_url"]) + "]\n"
            for name, route in self.paths[group].items():
                manifest += json.dumps(name) + " = { path = " + json.dumps(str(self.roots[group] / route)) + " }\n"
        (self.workspace / "Cargo.toml").write_text(manifest)
        (self.workspace / "Cargo.lock").write_bytes(self.overlay)
        tooling = (BASE.PIN_PATH, BASE.PIN_PATH.parent / self.air["patch_file"],
                   BASE.PIN_PATH.parent / self.air["overlay_lock_file"], BASE.WRAPPER_PIN_PATH,
                   BASE.WRAPPER_PIN_PATH.parent / self.wrapper["patch_file"], BASE.CRYPTO_PIN_PATH,
                   BASE.CRYPTO_PIN_PATH.parent / self.crypto["patch_file"],
                   ROOT / "scripts/prepare-patched-airbender.py", ROOT / "scripts/cargo-with-patched-airbender.sh")
        self.target = self.root / "target cache"
        self.record = {
            "schema_version": 1, "label": "ci-test", "cargo_exit_code": 0, "inputs_reverified": True,
            "pins": self.air, "zkos_wrapper": {"inputs": BASE.wrapper_pins_metadata(),
                "package_paths": self.paths["wrapper"]},
            "zksync_crypto": {"inputs": BASE.crypto_pins_metadata(), "package_paths": self.paths["crypto"]},
            "workspace": str(self.workspace), "application_source": str(self.source),
            "application_inputs_sha256": {relative: BASE.sha256(self.source / relative)
                for relative in ("Cargo.toml", "Cargo.lock", "fixture.rs")},
            "workspace_manifest_sha256": BASE.sha256(self.workspace / "Cargo.toml"),
            "selected_lock": self.selected, "package_paths": self.paths["air"],
            "tooling_sha256": {str(path.relative_to(ROOT)): BASE.sha256(path) for path in tooling},
            "cargo_target_dir": str(self.target)}
        self.record_path = self.root / "ci-test attestation.json"
        self.record_path.write_text(json.dumps(self.record))

    def canonical_wrapper_lock(self):
        raw = '# wrapper lock fixture retains all package edges and versions\nversion = 4\n'
        for group, pins in (("air", self.air), ("crypto", self.crypto)):
            for name, version in sorted(self.groups[group].items()):
                raw += '\n[[package]]\nname = ' + json.dumps(name) + '\nversion = ' + json.dumps(version)
                raw += '\nsource = ' + json.dumps(pins["upstream_lock_source"]) + '\n'
        for name, version in sorted(RUNNER.WRAPPER_WORKSPACE_PACKAGES.items()):
            raw += f'\n[[package]]\nname = "{name}"\nversion = "{version}"\n'
            if name == "zkos-wrapper":
                raw += 'dependencies = ["boojum", "execution_utils", "rand", "hex", "libc", "tempfile"]\n'
        for name, version in (("rand", "0.8.6"), ("hex", "0.4.3"), ("libc", "0.2.182"), ("tempfile", "3.26.0")):
            raw += f'\n[[package]]\nname = "{name}"\nversion = "{version}"\n'
            raw += 'source = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "untouched"\n'
        return raw.encode()

    def package_paths(self, root, expected):
        group = next(group for group, directory in self.roots.items() if directory == root)
        return {name: (self.own_paths if group == "wrapper" else self.paths[group])[name] for name in expected}

    def authenticated(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        for verifier in ("verify_upstream", "verify_wrapper", "verify_crypto"):
            stack.enter_context(patch.object(BASE, verifier))
        stack.enter_context(patch.object(BASE, "package_paths", side_effect=self.package_paths))
        return stack

    def metadata(self, workspace):
        packages = []
        for group in ("air", "crypto"):
            for name, version in self.groups[group].items():
                if name == "fflonk":
                    continue
                packages.append({"name": name, "version": version, "source": None, "id": name,
                                 "manifest_path": str(self.roots[group] / self.paths[group][name] / "Cargo.toml")})
        for name, version in RUNNER.WRAPPER_WORKSPACE_PACKAGES.items():
            packages.append({"name": name, "version": version, "source": None, "id": name,
                             "manifest_path": str(workspace / self.own_paths[name] / "Cargo.toml")})
        return {"workspace_root": str(workspace), "packages": packages,
                "workspace_members": list(RUNNER.WRAPPER_WORKSPACE_PACKAGES),
                "resolve": {"nodes": [{"id": "zkos-wrapper", "features": ["security_100"]}]}}

    def test_overlay_changes_only_exact_proving_source_assignments(self):
        overlay, groups = RUNNER.lock_overlay(self.raw, self.selected, self.air, self.crypto)
        expected = self.raw
        for pins in (self.air, self.crypto):
            expected = expected.replace(('source = ' + json.dumps(pins["upstream_lock_source"]) + '\n').encode(), b"")
        self.assertEqual(overlay, expected)
        self.assertEqual(groups, self.groups)
        original = BASE.tomllib.loads(self.raw.decode())
        rewritten = BASE.tomllib.loads(overlay.decode())
        self.assertEqual(original["package"][-7:], rewritten["package"][-7:])

    def test_mixed_unknown_partial_unpatched_and_qualified_graphs_rejected(self):
        first = next(iter(sorted(self.groups["air"])))
        air_line = ('source = ' + json.dumps(self.air["upstream_lock_source"]) + '\n').encode()
        source_block = f'\n[[package]]\nname = "{first}"\nversion = "0.1.0"\n'.encode() + air_line
        cases = {
            "mixed": self.raw.replace(self.air["upstream_commit"].encode(), b"f" * 40, 1),
            "unknown": self.raw.replace(('name = "' + first + '"').encode(), b'name = "unknown-air"', 1),
            "partial": self.raw.replace(source_block, b"", 1),
            "unpatched": self.raw.replace(air_line, b"", 1),
            "qualified": self.raw.replace(b'"boojum",', ('"boojum 0.32.10 (' + self.crypto["upstream_lock_source"] + ')",').encode(), 1),
        }
        for name, raw in cases.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                RUNNER.lock_overlay(raw, self.selected, self.air, self.crypto)

    def test_attestation_label_success_pins_lock_source_and_tooling_drift_rejected(self):
        self.authenticated()
        RUNNER.authenticate(self.record, "ci-test")
        for name, mutate in (
            ("label", lambda record: record.update(label="other")),
            ("exit", lambda record: record.update(cargo_exit_code=7)),
            ("unverified", lambda record: record.update(inputs_reverified=False)),
            ("pins", lambda record: record["pins"].update(patched_tree="f" * 40)),
            ("selection", lambda record: record["selected_lock"].update(overlay_lock_sha256="0" * 64)),
            ("tooling", lambda record: record["tooling_sha256"].pop("scripts/cargo-with-patched-airbender.sh")),
        ):
            record = copy.deepcopy(self.record)
            mutate(record)
            with self.subTest(name=name), self.assertRaises(ValueError):
                RUNNER.authenticate(record, "ci-test")
        (self.workspace / "Cargo.lock").write_bytes(self.overlay + b"\n")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            RUNNER.authenticate(self.record, "ci-test")

    def test_metadata_requires_complete_pinned_paths_and_cpu_security(self):
        self.authenticated()
        workspace = self.root / "test copy"
        metadata = self.metadata(workspace)
        RUNNER.metadata_graph(metadata, workspace, self.roots, self.paths, self.groups)
        for mutate in (
            lambda data: data["packages"][0].update(source=self.air["upstream_lock_source"]),
            lambda data: data["packages"][0].update(manifest_path="/wrong/Cargo.toml"),
            lambda data: data["packages"].pop(),
            lambda data: data.update(packages=[row for row in data["packages"] if row["name"] != "boojum"]),
            lambda data: data["packages"].append(data["packages"][0]),
            lambda data: data["workspace_members"].pop(),
            lambda data: data["resolve"]["nodes"][0].update(features=["security_100", "gpu"]),
        ):
            invalid = copy.deepcopy(metadata)
            mutate(invalid)
            with self.assertRaises(ValueError):
                RUNNER.metadata_graph(invalid, workspace, self.roots, self.paths, self.groups)

    def test_inactive_cpu_fflonk_may_be_absent_but_must_be_pinned_if_emitted(self):
        self.authenticated()
        workspace = self.root / "test copy"
        metadata = self.metadata(workspace)
        self.assertNotIn("fflonk", {row["name"] for row in metadata["packages"]})
        RUNNER.metadata_graph(metadata, workspace, self.roots, self.paths, self.groups)
        package = {"name": "fflonk", "version": self.groups["crypto"]["fflonk"],
                   "source": None, "id": "fflonk", "manifest_path": str(
                       self.roots["crypto"] / self.paths["crypto"]["fflonk"] / "Cargo.toml")}
        metadata["packages"].append(package)
        RUNNER.metadata_graph(metadata, workspace, self.roots, self.paths, self.groups)
        package["source"] = self.crypto["upstream_lock_source"]
        with self.assertRaises(ValueError):
            RUNNER.metadata_graph(metadata, workspace, self.roots, self.paths, self.groups)

    def execute(self, statuses=(0, 0), drift=None, metadata_status=0):
        self.authenticated()
        calls = []
        tracked = sorted(str(path.relative_to(self.roots["wrapper"]))
                         for path in self.roots["wrapper"].rglob("*") if path.is_file())
        tests = iter(statuses)

        def cargo(argv, **kwargs):
            calls.append((argv, kwargs))
            workspace = Path(argv[argv.index("--manifest-path") + 1]).parent
            if argv[1] == "metadata":
                return subprocess.CompletedProcess(argv, metadata_status, json.dumps(self.metadata(workspace)), "")
            status = next(tests)
            if drift == "lock":
                (workspace / "Cargo.lock").write_bytes(b"Cargo changed the derived lock\n")
            elif drift == "source":
                (self.source / "fixture.rs").write_text("source changed after Cargo\n")
            return subprocess.CompletedProcess(argv, status)

        with patch.object(RUNNER.subprocess, "check_output", return_value=("\0".join(tracked) + "\0").encode()), \
                patch.object(RUNNER.subprocess, "run", side_effect=cargo), \
                patch.dict(os.environ, {"RUST_MIN_STACK": "33554432", "CARGO_PROFILE_DEV_DEBUG": "0"}):
            status = RUNNER.run(self.record_path)
        return status, calls

    def test_run_uses_owning_copy_locked_graph_paths_with_spaces_and_shared_target(self):
        status, calls = self.execute()
        self.assertEqual(status, 0)
        self.assertEqual([argv[1] for argv, _ in calls], ["metadata", "test", "test"])
        self.assertEqual([argv[-1] for argv, _ in calls[1:]], list(RUNNER.TEST_FILTERS))
        manifest = Path(calls[0][0][calls[0][0].index("--manifest-path") + 1])
        self.assertNotEqual(manifest.parent, self.roots["wrapper"])
        self.assertNotEqual(manifest.parent, self.workspace)
        self.assertNotIn(".git", {path.name for path in manifest.parent.iterdir()})
        self.assertEqual((self.roots["wrapper"] / "Cargo.lock").read_bytes(), self.raw)
        derived, _ = RUNNER.lock_overlay(self.raw, self.selected, self.air, self.crypto)
        self.assertEqual((manifest.parent / "Cargo.lock").read_bytes(), derived)
        patches = BASE.read_toml(manifest)["patch"]
        self.assertEqual(set(patches[self.air["upstream_url"]]), set(self.groups["air"]))
        self.assertEqual(set(patches[self.crypto["upstream_url"]]), set(self.groups["crypto"]))
        for argv, kwargs in calls:
            self.assertIn("--locked", argv)
            self.assertIn("--no-default-features", argv)
            self.assertEqual(kwargs["cwd"], manifest.parent)
            self.assertEqual(kwargs["env"]["CARGO_TARGET_DIR"], str(self.target))
            self.assertEqual(kwargs["env"]["RUST_MIN_STACK"], "33554432")
            self.assertEqual(kwargs["env"]["CARGO_PROFILE_DEV_DEBUG"], "0")
        self.assertEqual(BASE.verify_wrapper.call_count, 2)
        self.assertEqual(BASE.verify_crypto.call_count, 2)
        self.assertEqual(BASE.verify_upstream.call_count, 2)

    def test_cargo_failure_preserved_second_test_skipped_and_inputs_reverified(self):
        for statuses, metadata_status, expected, count in (
            ((7, 0), 0, 7, 2), ((0, 9), 0, 9, 3), ((0, 0), 11, 11, 1)):
            with self.subTest(statuses=statuses, metadata_status=metadata_status):
                status, calls = self.execute(statuses, metadata_status=metadata_status)
                self.assertEqual(status, expected)
                self.assertEqual(len(calls), count)
                self.assertEqual(BASE.verify_wrapper.call_count, 2)

    def test_source_and_lock_drift_fail_even_when_cargo_tests_failed(self):
        for drift in ("lock", "source"):
            with self.subTest(drift=drift), self.assertRaises(ValueError):
                self.execute((7, 0), drift=drift)

    def test_default_cli_requires_ci_test_label(self):
        with patch.object(RUNNER, "run", return_value=17) as run:
            self.assertEqual(RUNNER.main([str(self.record_path)]), 17)
            run.assert_called_once_with(self.record_path, "ci-test")


if __name__ == "__main__":
    unittest.main()
