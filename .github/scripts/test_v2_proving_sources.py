"""Check the locked V2 closure and successful build receipt under controlled failures."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
FILE = ROOT / "scripts/prepare-v2-proving-sources.py"
spec = importlib.util.spec_from_file_location("v2_source", FILE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
PINS = module.base.json_document(ROOT / module.PIN_FILE)


class V2SourceTests(unittest.TestCase):
    def test_locked_packages_use_one_exact_git_revision_per_repository(self):
        manifest = module.base.read_toml(ROOT / "Cargo.toml")["workspace"]["dependencies"]
        lock = module.base.read_toml(ROOT / "Cargo.lock")["package"]
        expected = {name: f"git+{pin['repository']}?rev={pin['commit']}#{pin['commit']}"
                    for name, pin in PINS.items() if name in module.REQUIRED}
        self.assertEqual({p["source"] for p in lock if p.get("source", "").startswith("git+")}, set(expected.values()))
        for group, packages in module.REQUIRED.items():
            for name in packages:
                self.assertEqual([p["source"] for p in lock if p["name"] == name], [expected[group]])
        for alias, group in (("zksync_airbender_cli", "airbender"), ("zkos_wrapper", "protocol"),
                             ("crypto_codegen", "protocol")):
            self.assertEqual(manifest[alias]["git"], PINS[group]["repository"])
            self.assertEqual(manifest[alias]["rev"], PINS[group]["commit"])

    def test_gpu_native_release_pin_matches_docker_source(self):
        docker = json.loads((ROOT / "docker/prover-build-pins.json").read_text())
        for key in ("commit", "repository"):
            self.assertEqual(docker["bellman_cuda"][key], PINS["bellman_cuda"][key])
        self.assertEqual(docker["cpu_snark_crs"]["g1_count"], 1 << 22)

    def exercise(self, directory, failure=None):
        application = directory / "app"
        (application / "crates/example/src").mkdir(parents=True)
        for name in module.base.SOURCE_FILES:
            (application / name).write_text("input\n")
        receipt = directory / "role.json"
        env = {"PROVER_SOURCE_DIR": str(application), "CARGO_TARGET_DIR": str(directory / "target"),
               "AIRBENDER_BUILD_ATTESTATION": str(receipt)}
        def compile_worker(command, env, check):
            workspace = Path(command[command.index("--manifest-path") + 1]).parent
            self.assertEqual((workspace / module.base.PREPARED_SOURCE_MARKER).read_text(),
                             str(workspace) + "\n" + (ROOT / module.PIN_FILE).read_text())
            if failure == "cargo":
                raise module.subprocess.CalledProcessError(1, command)
            if failure == "source":
                (workspace / "Cargo.lock").write_text("modified")
            if failure == "marker":
                (workspace / module.base.PREPARED_SOURCE_MARKER).write_text("changed")
            if failure == "pins":
                (workspace / module.PIN_FILE).write_text("{}")
        with patch.dict(os.environ, env, clear=True), patch.object(module.base, "require_airbender_only"), \
             patch.object(module, "validate_graph", return_value={g: str(directory / g) for g in module.REQUIRED}), \
             patch.object(module, "check_checkout") as verify, patch.object(module.subprocess, "run", side_effect=compile_worker):
            if failure is None:
                module.main(["ci-test", "--", "cargo", "test", "--locked", "--no-default-features"])
                record = json.loads(receipt.read_text())
                self.assertTrue(record["inputs_reverified"])
                self.assertEqual(record["sources"], PINS)
                self.assertEqual(record["cargo_lock_sha256"], module.base.sha256(application / "Cargo.lock"))
                self.assertEqual(verify.call_count, 2)
            else:
                with self.assertRaises((ValueError, module.subprocess.CalledProcessError)):
                    module.main(["ci-test", "--", "cargo", "test", "--locked", "--no-default-features"])
                self.assertFalse(receipt.exists())

    def test_reused_target_builds_each_archived_application_revision(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            application = root / "application"
            package = application / "crates/fixture"
            (package / "src").mkdir(parents=True)
            (application / "Cargo.toml").write_text('[workspace]\nmembers = ["crates/fixture"]\nresolver = "2"\n')
            (application / "Cargo.lock").write_text(
                'version = 4\n\n[[package]]\nname = "fixture"\nversion = "0.1.0"\n'
            )
            (application / "rust-toolchain.toml").write_bytes((ROOT / "rust-toolchain.toml").read_bytes())
            for name in ("multiblock_batch.bin", "multiblock_batch.text"):
                (application / name).write_bytes(b"test guest")
            (package / "Cargo.toml").write_text('[package]\nname = "fixture"\nversion = "0.1.0"\nedition = "2021"\n')
            (package / "build.rs").write_text(
                'fn main() {\n'
                '    println!("cargo:rerun-if-changed=release.txt");\n'
                '    let release = std::fs::read_to_string("release.txt").unwrap();\n'
                '    println!("cargo:rustc-env=FIXTURE_RELEASE={release}");\n'
                '}\n'
            )
            default_target = root / "target"
            receipts = []
            env = {"PROVER_SOURCE_DIR": str(application), "CARGO_TARGET_DIR": str(default_target)}
            # Real Cargo builds exercise the application's cache. This fixture has no external Git packages.
            with patch.object(module, "validate_graph", return_value={}):
                revisions = (("one", "first"), ("one", "first"), ("two", "other"))
                for index, (rust_value, release_value) in enumerate(revisions):
                    (package / "src/main.rs").write_text(
                        f'fn main() {{ println!("{{}}:{{}}", "{rust_value}", env!("FIXTURE_RELEASE")); }}\n'
                    )
                    (package / "release.txt").write_text(release_value)
                    # Reproducible archives commonly retain a fixed timestamp for both revisions.
                    for path in package.rglob("*"):
                        if path.is_file():
                            os.utime(path, (1_700_000_000, 1_700_000_000))
                    receipt = root / f"inputs-{index}.json"
                    with patch.dict(os.environ, {**env, "AIRBENDER_BUILD_ATTESTATION": str(receipt)}):
                        module.main(["cache-test", "--", "cargo", "build", "--locked", "--offline", "-p", "fixture"])
                    record = json.loads(receipt.read_text())
                    inputs = record["application_input_sha256"]
                    for relative in ("crates/fixture/src/main.rs", "crates/fixture/release.txt"):
                        self.assertEqual(inputs[relative], module.base.sha256(application / relative))
                    receipts.append(record)

            self.assertEqual(receipts[0]["cargo_build_dir"], receipts[1]["cargo_build_dir"])
            self.assertNotEqual(receipts[1]["cargo_build_dir"], receipts[2]["cargo_build_dir"])
            self.assertEqual(len({record["artifact_dir"] for record in receipts}), len(receipts))
            for record, (rust_value, release_value) in zip(receipts, revisions):
                binary = Path(record["artifact_dir"]) / "fixture"
                self.assertEqual(record["artifact_sha256"]["fixture"], module.base.sha256(binary))
                self.assertEqual(subprocess.check_output([binary], text=True).strip(), f"{rust_value}:{release_value}")

    def test_success_receipt_has_reverified_both_source_trees(self):
        with tempfile.TemporaryDirectory() as temp:
            self.exercise(Path(temp))

    def test_cargo_or_changed_inputs_cannot_publish_success_receipt(self):
        for failure in ("cargo", "source", "pins", "marker"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temp:
                self.exercise(Path(temp), failure)


if __name__ == "__main__":
    unittest.main()
