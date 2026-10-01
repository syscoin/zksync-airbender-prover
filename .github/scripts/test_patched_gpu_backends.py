"""Offline overlay and admission tests; no downloads, CUDA, Cargo or shared-cache writes."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/prepare-patched-gpu-backends.py"
SPEC = importlib.util.spec_from_file_location("gpu_backend_overlay", SCRIPT)
HELPER = importlib.util.module_from_spec(SPEC)
exec(compile(SCRIPT.read_bytes(), str(SCRIPT), "exec"), HELPER.__dict__)
PINS = HELPER.load_pins()
BASE = HELPER.base_helper()
AIR = json.loads(BASE.PIN_PATH.read_text())


class GpuLockTests(unittest.TestCase):
    def raw(self):
        return BASE.selected_lock_overlay(ROOT / "Cargo.lock", ROOT / "patches/airbender.Cargo.lock", AIR)[0]

    def test_eight_packages_six_edges_and_only_two_pair_orders(self):
        raw = self.raw()
        result = HELPER.crypto_lock_overlay(raw, PINS)
        before = HELPER.tomllib.loads(raw.decode())
        after = HELPER.tomllib.loads(result.decode())
        expected = copy.deepcopy(before)
        changed, edge_count = set(), 0
        for package in expected["package"]:
            if package.get("source") == PINS["crypto"]["upstream_lock_source"]:
                changed.add(package["name"])
                del package["source"]
                for index, edge in enumerate(package.get("dependencies", [])):
                    if PINS["crypto"]["upstream_edge_source"] in edge:
                        package["dependencies"][index] = edge.split(" (")[0]
                        edge_count += 1
        for name in ("era_cudart", "era_cudart_sys"):
            indexes = [i for i, p in enumerate(expected["package"]) if p["name"] == name]
            records = sorted((expected["package"][i] for i in indexes), key=lambda p: p.get("source", ""))
            for index, record in zip(indexes, records):
                expected["package"][index] = record
        self.assertEqual(changed, set(HELPER.CRYPTO_PACKAGES))
        self.assertEqual(edge_count, 6)
        self.assertEqual(after, expected)
        self.assertNotIn(PINS["crypto"]["upstream_edge_source"].encode(), result)

    def test_selected_other_application_graph_is_preserved_not_replaced(self):
        selected = (ROOT / "Cargo.lock").read_bytes() + (
            b'\n[[package]]\nname = "selected-application-extra"\nversion = "3.2.1"\n'
            b'source = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "'
            + b"a" * 64 + b'"\n')
        with tempfile.TemporaryDirectory() as temporary:
            lock = Path(temporary) / "Cargo.lock"
            lock.write_bytes(selected)
            derived = HELPER.gpu_backend_pins(HELPER.PIN_PATH, lock)
            raw, _ = BASE.selected_lock_overlay(lock, ROOT / "patches/airbender.Cargo.lock", AIR)
            combined = HELPER.crypto_lock_overlay(raw, PINS)
            self.assertIn(b'selected-application-extra', combined)
            self.assertEqual(lock.read_bytes(), selected)
            self.assertEqual(derived["selected_lock"]["combined_overlay_lock_sha256"], hashlib.sha256(combined).hexdigest())
            self.assertNotEqual(derived["selected_lock"]["combined_overlay_lock_sha256"],
                                HELPER.gpu_backend_pins(HELPER.PIN_PATH, ROOT / "Cargo.lock")
                                ["selected_lock"]["combined_overlay_lock_sha256"])

    def test_mixed_revision_package_version_missing_and_unknown_edges_rejected(self):
        raw = self.raw()
        for invalid in (
            raw.replace(PINS["crypto"]["upstream_commit"].encode(), b"f" * 40),
            raw.replace(b'name = "zksync-gpu-prover"\nversion = "0.156.0"',
                        b'name = "zksync-gpu-prover"\nversion = "0.155.0"'),
            raw.replace(b'name = "zksync-gpu-prover"', b'name = "unknown-gpu-package"'),
            raw.replace(b'era_cudart 0.156.0 (git+', b'other_cudart 0.156.0 (git+', 1),
        ):
            with self.subTest(invalid=hashlib.sha256(invalid).hexdigest()), self.assertRaises(ValueError):
                HELPER.crypto_lock_overlay(invalid, PINS)

    def test_duplicate_path_registry_identity_rejected(self):
        raw = self.raw()
        invalid = raw.replace(b'name = "era_cudart"\nversion = "0.156.0"\nsource = "registry+',
                              b'name = "unknown_cudart"\nversion = "0.156.0"\nsource = "registry+')
        with self.assertRaises(ValueError):
            HELPER.crypto_lock_overlay(invalid, PINS)

    def test_pure_metadata_api_does_not_execute_subprocess(self):
        with patch.object(HELPER.subprocess, "run") as run, patch.object(HELPER.subprocess, "check_output") as output:
            metadata = HELPER.gpu_backend_pins(HELPER.PIN_PATH, ROOT / "Cargo.lock")
            self.assertEqual(metadata["selected_lock"]["airbender_overlay_lock_sha256"], AIR["overlay_lock_sha256"])
            self.assertEqual(len(metadata["selected_lock"]["airbender_packages"]), 46)
            self.assertEqual(len(metadata["selected_lock"]["crypto_packages"]), 8)
            run.assert_not_called()
            output.assert_not_called()


class ManifestTests(unittest.TestCase):
    def fixture(self, temporary, changed=None):
        root = Path(temporary)
        for kind in ("crypto", "bellman"):
            (root / PINS[kind]["patch_file"]).write_bytes((HELPER.PIN_PATH.parent / PINS[kind]["patch_file"]).read_bytes())
        manifest = root / "gpu32-memory.json"
        manifest.write_text(json.dumps(changed or PINS))
        return manifest

    def test_exact_postimages_remain_bound_to_original_accepted_source(self):
        self.assertEqual(PINS["crypto"]["changed_files"]["crates/gpu-prover/src/cuda_bindings/context.rs"]
                         ["postimage_sha256"], "3395819a697542e16c954aeddb4d54e029b2ddddec2df1f5732e179785e8d761")
        self.assertEqual(PINS["crypto"]["changed_files"]["crates/gpu-prover/src/proof.rs"]
                         ["postimage_sha256"], "feea55a4c6d6f1c2b43d3ef79b02279dca03b485bb437509c6066ae8d83e0b58")
        self.assertEqual(set(PINS["bellman"]["changed_files"]), HELPER.CHANGED_PATHS["bellman"])
        self.assertEqual(PINS["security_bits"], 100)
        self.assertEqual(PINS["domain_log"], 25)
        self.assertEqual(PINS["polynomial_slots"], 29)

    def test_patch_drift_zero_unknown_origins_and_domains_fail_closed(self):
        edits = [lambda p: p["crypto"].update(upstream_commit="f" * 40),
                 lambda p: p["bellman"].update(patch_sha256="0" * 64),
                 lambda p: p.update(security_bits=80),
                 lambda p: p.update(domain_log=True),
                 lambda p: p["crypto"]["changed_files"].update({"../escape": next(iter(p["crypto"]["changed_files"].values()))}),
                 lambda p: p["crypto_packages"].update({"unknown": "0.156.0"})]
        for edit in edits:
            with tempfile.TemporaryDirectory() as temporary:
                invalid = copy.deepcopy(PINS)
                edit(invalid)
                with self.assertRaises(ValueError):
                    HELPER.load_pins(self.fixture(temporary, invalid))
        with tempfile.TemporaryDirectory() as temporary:
            manifest = self.fixture(temporary)
            (manifest.parent / PINS["crypto"]["patch_file"]).write_bytes(b"changed")
            with self.assertRaises(ValueError):
                HELPER.load_pins(manifest)

    def test_duplicate_json_keys_and_symlink_manifest_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest = Path(temporary) / "gpu32-memory.json"
            manifest.write_text('{"schema_version":1,"schema_version":1}')
            with self.assertRaises(ValueError):
                HELPER.load_pins(manifest)
            manifest.unlink()
            manifest.symlink_to(HELPER.PIN_PATH)
            with self.assertRaises(ValueError):
                HELPER.load_pins(manifest)


class SourceAdmissionTests(unittest.TestCase):
    def native_fixture(self, temporary):
        root = Path(temporary).resolve() / "bellman"
        (root / "build/src").mkdir(parents=True)
        record = {"schema": "syscoin-gpu-memory-source-v1", "kind": "bellman", "source_root": str(root),
                  "clone_source": PINS["bellman"]["upstream_url"],
                  "manifest_sha256": HELPER.sha256(HELPER.PIN_PATH), "preparer_sha256": HELPER.sha256(SCRIPT),
                  "upstream_commit": PINS["bellman"]["upstream_commit"], "upstream_tree": PINS["bellman"]["upstream_tree"],
                  "patched_tree": PINS["bellman"]["patched_tree"], "tracked_inventory": {"source.cu": {"sha256": "a" * 64}}}
        (root / HELPER.SOURCE_RECORD).write_text(json.dumps(record))
        (root / "build/CMakeCache.txt").write_text('BUILD_TESTS:BOOL=OFF\nCMAKE_HOME_DIRECTORY:INTERNAL=' + str(root)
                                                   + '\nCMAKE_CUDA_ARCHITECTURES:STRING=120\n')
        (root / "build/src/libbellman-cuda.a").write_bytes(b"!<arch>\nfixture")
        return root

    def test_actual_library_metadata_not_historical_binary_pin(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(HELPER.os.environ, {}, clear=True):
            root = self.native_fixture(temporary)
            fake = unittest.mock.Mock()
            fake.run_git.return_value = PINS["bellman"]["patched_tree"]
            with patch.object(HELPER, "verify_backend") as verify:
                result = HELPER.bellman_library(root, PINS, fake)
                verify.assert_called_once()
                self.assertEqual(result["library_sha256"], hashlib.sha256(b"!<arch>\nfixture").hexdigest())
                self.assertEqual(result["cuda_architectures"], "120")

    def test_test_library_wrong_source_architecture_duplicate_or_missing_fail_closed(self):
        for bad_cache in ('BUILD_TESTS:BOOL=ON\n', 'CMAKE_HOME_DIRECTORY:INTERNAL=/wrong\n',
                          'CMAKE_CUDA_ARCHITECTURES:STRING=invalid\n', 'BUILD_TESTS:BOOL=OFF\nBUILD_TESTS:BOOL=OFF\n'):
            with self.subTest(cache=bad_cache), tempfile.TemporaryDirectory() as temporary:
                root = self.native_fixture(temporary)
                (root / "build/CMakeCache.txt").write_text(bad_cache)
                fake = unittest.mock.Mock()
                fake.run_git.return_value = PINS["bellman"]["patched_tree"]
                with patch.object(HELPER, "verify_backend"), self.assertRaises(ValueError):
                    HELPER.bellman_library(root, PINS, fake)
        with tempfile.TemporaryDirectory() as temporary:
            root = self.native_fixture(temporary)
            fake = unittest.mock.Mock()
            fake.run_git.return_value = PINS["bellman"]["patched_tree"]
            with patch.object(HELPER, "verify_backend"), patch.dict(HELPER.os.environ, {"CUDAARCHS": "90"}), self.assertRaises(ValueError):
                HELPER.bellman_library(root, PINS, fake)
            (root / "build/src/libbellman-cuda.a").unlink()
            with patch.object(HELPER, "verify_backend"), self.assertRaises(ValueError):
                HELPER.bellman_library(root, PINS, fake)

    def test_gitlink_is_recorded_without_loading_or_initializing_submodule(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "source.cu").write_bytes(b"source")
            fake = unittest.mock.Mock()
            fake.run_git.return_value = "100644 " + "a" * 40 + " 0\tsource.cu\n160000 " + "b" * 40 + " 0\textern/googletest"
            inventory = HELPER.tracked_inventory(root, fake)
            self.assertEqual(inventory["extern/googletest"], {"gitlink": "b" * 40})
            self.assertEqual(inventory["source.cu"]["sha256"], hashlib.sha256(b"source").hexdigest())

    def test_source_symlinks_and_unmerged_entries_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "source.cu").symlink_to(SCRIPT)
            fake = unittest.mock.Mock()
            for entry in ("100644 " + "a" * 40 + " 0\tsource.cu", "100644 " + "a" * 40 + " 1\tsource.cu"):
                fake.run_git.return_value = entry
                with self.assertRaises(ValueError):
                    HELPER.tracked_inventory(root, fake)

    def test_no_native_fallback_or_mutable_cargo_command(self):
        with patch.object(HELPER, "prepare_backend") as prepare:
            with self.assertRaises(ValueError):
                HELPER.main(["test", "--", "cargo", "build"])
            prepare.assert_not_called()
        self.assertIn("no automatic fallback build", SCRIPT.read_text())
        self.assertIn('settings.get("BUILD_TESTS") == "OFF"', SCRIPT.read_text())

    def test_context_whitelist_contains_every_gpu_overlay_input(self):
        context = (ROOT / "docker/prepare-prover-image-context.sh").read_text()
        ignore = (ROOT / ".dockerignore").read_text()
        for relative in ("scripts/prepare-patched-gpu-backends.py", "patches/gpu32-memory.json",
                         "patches/crypto-gpu32-memory.patch", "patches/bellman-gpu32-memory.patch"):
            self.assertIn("    " + relative + "\n", context)
            self.assertIn("!" + relative + "\n", ignore)


class BuildLaneTests(unittest.TestCase):
    def command(self, *options):
        return ["cargo", "build", "--locked", *options]

    def source_fixture(self, temporary, edits=None):
        root = Path(temporary)
        (root / "Cargo.toml").write_bytes((ROOT / "Cargo.toml").read_bytes())
        for member in BASE.read_toml(ROOT / "Cargo.toml")["workspace"]["members"]:
            path = root / member
            (path / "src").mkdir(parents=True)
            (path / "src/main.rs").write_text("fn main() {}\n")
            raw = (ROOT / member / "Cargo.toml").read_text()
            (path / "Cargo.toml").write_text(edits(member, raw) if edits else raw)
        return root

    def test_actual_gpu_defaults_with_explicit_cpu_dependency_boundary(self):
        for package in ("zksync_os_snark_prover", "zksync_os_prover_service"):
            self.assertEqual(BASE.read_toml(ROOT / "crates" / package / "Cargo.toml")["features"]["default"], ["gpu"])
        combined = BASE.read_toml(ROOT / "crates/zksync_os_prover_service/Cargo.toml")
        self.assertIs(combined["dependencies"]["zksync_os_snark_prover"]["default-features"], False)

    def test_cpu_ci_and_scoped_fri_gpu_matrix(self):
        for options in (
            ("--no-default-features",), ("--workspace", "--no-default-features"),
            ("-p", "zksync_os_snark_prover", "--no-default-features"),
            ("--package=zksync_os_prover_service", "--no-default-features"),
            ("-p", "zksync_os_fri_prover", "--features", "gpu"),
            ("-pzksync_os_fri_prover", "-Fgpu"),
            ("-p", "zksync_os_fri_prover", "--all-features"),
            ("-p", "zksync_os_fri_prover", "--bin", "zksync_os_fri_prover", "--features=gpu"),
            ("--workspace", "--exclude", "zksync_os_snark_prover", "--exclude", "zksync_os_prover_service", "--features", "gpu"),
            ("--no-default-features", "--features", "zksync_os_fri_prover/gpu"),
            ("-p", "protocol_version"),
        ):
            with self.subTest(options=options):
                BASE.require_airbender_only(ROOT, self.command(*options))
        BASE.require_airbender_only(ROOT, self.command("--no-default-features"), explicit_cpu=True)
        BASE.require_airbender_only(ROOT, ["cargo", "clippy", "--locked", "--no-default-features", "--", "-D", "warnings"])
        BASE.require_airbender_only(ROOT, ["cargo", "run", "--locked", "-p", "zksync_os_snark_prover",
                                         "--no-default-features", "--", "--features", "gpu"])

    def test_unpatched_gpu_default_explicit_alias_and_all_features_rejected(self):
        for options in (
            (), ("--workspace",), ("-p", "zksync_os_snark_prover"),
            ("--package=zksync_os_prover_service",), ("--bin", "zksync-os-prover-service"),
            ("--bin", "zksync_os_fri_prover", "--features=gpu"),
            ("--no-default-features", "--all-features"),
            ("-p", "zksync_os_snark_prover", "--no-default-features", "--features", "gpu"),
            ("--no-default-features", "--features", "zksync_os_snark_prover/gpu"),
            ("-p", "zksync_os_snark_prover", "--no-default-features", "-Fzkos_wrapper/gpu"),
        ):
            with self.subTest(options=options), self.assertRaisesRegex(ValueError, "--gpu32"):
                BASE.require_airbender_only(ROOT, self.command(*options))
        with self.assertRaises(ValueError):
            BASE.require_airbender_only(ROOT, self.command("-p", "zksync_os_fri_prover", "--features", "gpu"), explicit_cpu=True)

    def test_older_selected_cpu_defaults_and_gpu_alias_are_inspected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.source_fixture(temporary, lambda _, text: text.replace('default = ["gpu"]', 'default = []'))
            BASE.require_airbender_only(root, self.command())
            with self.assertRaises(ValueError):
                BASE.require_airbender_only(root, self.command("-p", "zksync_os_snark_prover", "--features", "gpu"))
        with tempfile.TemporaryDirectory() as temporary:
            root = self.source_fixture(temporary, lambda member, text:
                text.replace('default = ["gpu"]', 'default = ["fast"]\nfast = ["gpu"]')
                if member.endswith("zksync_os_snark_prover") else text)
            with self.assertRaises(ValueError):
                BASE.require_airbender_only(root, self.command("-p", "zksync_os_snark_prover"))

    def test_unknown_selectors_missing_values_and_feature_routes_fail_closed(self):
        for options in (("-p", "unknown"), ("--bin=unknown",), ("-p",), ("-F",),
                        ("--all",), ("-p", "protocol_version", "--all"),
                        ("--workspace", "-p", "protocol_version"), ("--exclude", "protocol_version"),
                        ("-p", "zksync_os_fri_prover", "--features", "zkos_wrapper/gpu"),
                        ("--no-default-features", "--features", "unknown")):
            with self.subTest(options=options), self.assertRaises(ValueError):
                BASE.require_airbender_only(ROOT, self.command(*options))

    def test_all_alias_cannot_hide_gpu_roles_outside_default_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.source_fixture(temporary)
            manifest = root / "Cargo.toml"
            manifest.write_text(manifest.read_text().replace(
                "[workspace]\n", '[workspace]\ndefault-members = ["crates/protocol_version"]\n', 1))
            BASE.require_airbender_only(root, self.command())
            with self.assertRaisesRegex(ValueError, "--all"):
                BASE.require_airbender_only(root, self.command("--all"))

    def test_lane_guard_runs_before_materialization_and_cpu_token_is_preserved(self):
        with patch.dict(BASE.os.environ, {"PROVER_SOURCE_DIR": str(ROOT)}), patch.object(BASE, "copy_application") as copy_app:
            with self.assertRaises(ValueError):
                BASE.main(["plain", "--", "cargo", "build", "--locked"])
            with self.assertRaises(ValueError):
                BASE.main(["--cpu", "cpu", "--", "cargo", "build", "--locked", "--features", "gpu"])
            copy_app.assert_not_called()
        self.assertIn('elif [[ "${1:-}" == "--cpu" ]]; then\n  # Preserve CPU intent',
                      (ROOT / "scripts/cargo-with-patched-airbender.sh").read_text())


if __name__ == "__main__":
    unittest.main()
