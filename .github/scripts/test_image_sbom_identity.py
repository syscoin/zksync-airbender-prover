"""SYSCOIN: Offline regressions for image-matrix identity and SBOM evidence binding."""

import copy
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("image-sbom-identity.py")
SPEC = importlib.util.spec_from_file_location("image_sbom_identity", SCRIPT)
identity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(identity)
ROOT = SCRIPT.parents[2]
LOCK_TEST_SPEC = importlib.util.spec_from_file_location(
    "lock_fixture", SCRIPT.with_name("test_patched_airbender_build.py"))
LOCK_FIXTURE = importlib.util.module_from_spec(LOCK_TEST_SPEC)
LOCK_TEST_SPEC.loader.exec_module(LOCK_FIXTURE)


class ImageIdentityTests(unittest.TestCase):
    def setUp(self):
        self.env = {
            "GITHUB_REPOSITORY": "Syscoin/zksync-airbender-prover",
            "SOURCE_SHA": "a" * 40,
            "TOOLING_SHA": "b" * 40,
            "VERSION": "v0.0.8",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "2",
            "BUILD_RUN_ATTEMPT": "2",
        }
        self.context = identity.build_identity(self.env)
        self.digests = {
            component: "sha256:" + str(number) * 64
            for number, component in enumerate(identity.COMPONENTS, 1)
        }
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def inventory(self):
        for component, digest in reversed(tuple(self.digests.items())):
            directory = self.directory / identity.artifact_name(self.context, component)
            directory.mkdir()
            record = identity.image_record(self.context, component, digest)
            (directory / "image-digest.json").write_text(json.dumps(record))
        return self.directory

    def record_path(self, component=None):
        component = component or identity.COMPONENTS[0]
        return self.directory / identity.artifact_name(self.context, component) / "image-digest.json"

    def cli(self, *args, **env):
        return subprocess.run(
            [sys.executable, "-B", str(SCRIPT), *args],
            env={**self.env, **env}, text=True, capture_output=True, check=True,
        ).stdout

    def test_all_matrix_components_keep_their_own_digest(self):
        result = identity.collect_digests(self.inventory(), self.context)
        self.assertEqual(result, self.digests)
        matrix = identity.image_matrix(result, self.context)
        self.assertEqual(len(matrix["include"]), 3)
        for row in matrix["include"]:
            digest = self.digests[row["app"]]
            self.assertEqual(row["digest"], digest)
            self.assertEqual(row["image"], f"ghcr.io/syscoin/{row['app']}@{digest}")
            self.assertNotIn(self.env["VERSION"], row["image"])

    def test_partial_retry_requires_complete_current_attempt(self):
        self.inventory()
        prior_attempt = {**self.context, "run_attempt": "1"}
        component = identity.COMPONENTS[0]
        (self.directory / identity.artifact_name(self.context, component)).rename(
            self.directory / identity.artifact_name(prior_attempt, component))
        with self.assertRaisesRegex(ValueError, "inventory"):
            identity.collect_digests(self.directory, self.context)

    def test_missing_component_rejected(self):
        with self.assertRaisesRegex(ValueError, "inventory"):
            identity.collect_digests(self.directory, self.context)

    def test_unexpected_artifact_rejected(self):
        self.inventory()
        (self.directory / "unrequested-component").mkdir()
        with self.assertRaisesRegex(ValueError, "inventory"):
            identity.collect_digests(self.directory, self.context)

    def test_duplicate_record_cannot_overwrite_another_component(self):
        self.inventory()
        self.record_path(identity.COMPONENTS[1]).write_text(self.record_path().read_text())
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            identity.collect_digests(self.directory, self.context)

    def test_extra_record_rejected(self):
        self.inventory()
        self.record_path().with_name("another.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "exactly one"):
            identity.collect_digests(self.directory, self.context)

    def test_source_tooling_run_version_and_image_mismatches_rejected(self):
        self.inventory()
        path = self.record_path()
        original = json.loads(path.read_text())
        mutations = {
            "source_sha": "c" * 40, "tooling_sha": "c" * 40,
            "run_id": "98765", "run_attempt": "1", "version": "v0.0.9",
            "repository": "other/repository", "image": "ghcr.io/syscoin/test:latest",
            "schema": "unknown",
        }
        for key, value in mutations.items():
            with self.subTest(key=key):
                path.write_text(json.dumps({**original, key: value}))
                with self.assertRaisesRegex(ValueError, "identity mismatch"):
                    identity.collect_digests(self.directory, self.context)

    def test_invalid_digest_formats_rejected_at_both_boundaries(self):
        for digest in ("latest", "sha256:" + "a" * 63, "sha256:" + "A" * 64,
                       "sha512:" + "a" * 64, "sha256:" + "0" * 64 + "\n", None, 1):
            with self.subTest(digest=digest):
                component = identity.COMPONENTS[0]
                with self.assertRaisesRegex(ValueError, "invalid image digest"):
                    identity.image_record(self.context, component, digest)
                with self.assertRaisesRegex(ValueError, "invalid image digest"):
                    identity.image_matrix({**self.digests, component: digest}, self.context)

    def test_missing_unknown_and_duplicate_matrix_components_rejected(self):
        for digests in ({}, {**self.digests, "unknown": self.digests[identity.COMPONENTS[0]]}, []):
            with self.assertRaisesRegex(ValueError, "every expected component"):
                identity.image_matrix(digests, self.context)
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            identity.parse_json('{"zksync-airbender-prover":"a","zksync-airbender-prover":"b"}')

    def test_sbom_preserves_scanner_metadata_and_records_exact_identity(self):
        scanner = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [],
                   "metadata": {"component": {"name": "scanned-image"},
                                "properties": [{"name": "scanner", "value": "syft"}]}}
        record = identity.image_record(self.context, identity.COMPONENTS[0],
                                       self.digests[identity.COMPONENTS[0]])
        bound = identity.bind_sbom(copy.deepcopy(scanner), record)
        self.assertEqual(bound["metadata"]["component"], scanner["metadata"]["component"])
        self.assertEqual(bound["metadata"]["properties"][0], {"name": "scanner", "value": "syft"})
        properties = {item["name"]: item["value"] for item in bound["metadata"]["properties"]}
        for key, value in record.items():
            self.assertEqual(properties[f"io.syscoin.prover.image-build.{key}"], value)
        with self.assertRaisesRegex(ValueError, "already contains build identity"):
            identity.bind_sbom(bound, record)

    def test_cli_manifest_to_scan_to_evidence_ignores_reused_version_tag(self):
        digests = self.cli("collect", str(self.inventory()))
        matrix = json.loads(self.cli("matrix", IMAGE_DIGESTS=digests))
        for row in matrix["include"]:
            # Mock the scanner's response, using its exact matrix input. A tag now resolving
            # to a different digest cannot change this already-bound scanner reference.
            component = row["app"]
            tag_now_points_to = f"ghcr.io/syscoin/{component}@sha256:" + "f" * 64
            self.assertNotEqual(row["image"], tag_now_points_to)
            bom = self.directory / f"{component}.json"
            bom.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6",
                                       "metadata": {"component": {"name": row["image"]}}}))
            evidence = json.loads(self.cli("bind", component, row["digest"], str(bom)))
            props = {p["name"]: p["value"] for p in evidence["metadata"]["properties"]}
            self.assertEqual(props["io.syscoin.prover.image-build.image"], row["image"])
            self.assertEqual(props["io.syscoin.prover.image-build.digest"], self.digests[component])

    def test_workflow_uses_collector_and_bound_evidence(self):
        build = (ROOT / ".github/workflows/stage-build.yaml").read_text()
        reusable = (ROOT / ".github/workflows/sbom-analysis-reusable.yaml").read_text()
        self.assertIn("image_digests: ${{ needs.collect-image-digests.outputs.image_digests }}", build)
        self.assertIn("merge-multiple: false", build)
        self.assertIn("prover-image-digest-${{ github.run_id }}-${{ github.run_attempt }}-${{ matrix.component }}", build)
        self.assertIn("image: ${{ matrix.image }}", reusable)
        self.assertNotIn("${{ matrix.app }}:${{ inputs.version }}", reusable)
        self.assertIn('bomfilename: "bom-${{ matrix.app }}-image.bound.cdx.json"', reusable)
        self.assertIn("ref: ${{ job.workflow_sha }}", reusable)
        self.assertIn("build_run_attempt: ${{ needs.collect-image-digests.outputs.build_run_attempt }}", build)
        self.assertIn("BUILD_RUN_ATTEMPT: ${{ inputs.build_run_attempt }}", reusable)

    def test_sbom_only_retry_preserves_original_build_attempt(self):
        context = identity.build_identity({**self.env, "GITHUB_RUN_ATTEMPT": "3"})
        self.assertEqual(context["run_attempt"], "2")
        with self.assertRaisesRegex(ValueError, "newer than"):
            identity.build_identity({**self.env, "BUILD_RUN_ATTEMPT": "3"})

    def test_airbender_pins_bind_exact_manifest_patch_and_overlay(self):
        manifest = ROOT / "patches/airbender-cuda-device-diagnostics.json"
        result = identity.airbender_build_pins(manifest)
        self.assertEqual(result["manifest_sha256"], hashlib.sha256(manifest.read_bytes()).hexdigest())
        self.assertEqual(result["pins"]["upstream_package_count"], 46)
        wrapper_manifest = ROOT / "patches/zkos-wrapper-buffered-os-rng.json"
        self.assertEqual(result["zkos_wrapper"]["manifest_sha256"],
                         hashlib.sha256(wrapper_manifest.read_bytes()).hexdigest())
        self.assertEqual(result["zkos_wrapper"]["pins"]["upstream_packages"],
                         {"circuit_mersenne_field": "0.1.0", "zkos-wrapper": "0.1.0"})
        crypto_manifest = ROOT / "patches/zksync-crypto-native-fri-query-count.json"
        self.assertEqual(result["zksync_crypto"]["manifest_sha256"],
                         hashlib.sha256(crypto_manifest.read_bytes()).hexdigest())
        self.assertEqual(result["zksync_crypto"]["pins"]["upstream_commit"],
                         "bf2797e4ca13475bf797aa43e085389cdd6732f9")
        self.assertEqual(len(result["zksync_crypto"]["pins"]["upstream_packages"]), 11)
        cli_result = json.loads(self.cli("airbender-pins", str(manifest)))
        self.assertEqual(cli_result, result)
        record = identity.image_record(self.context, identity.COMPONENTS[0],
                                       self.digests[identity.COMPONENTS[0]])
        bound = identity.bind_sbom({"bomFormat": "CycloneDX", "specVersion": "1.6"}, record, result)
        properties = {item["name"]: item["value"] for item in bound["metadata"]["properties"]}
        self.assertEqual(json.loads(properties["io.syscoin.prover.airbender-build.inputs"]), result)

    def test_airbender_changed_patch_or_overlay_fails_closed(self):
        for filename in ("airbender-cuda-device-diagnostics.patch", "airbender.Cargo.lock"):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                for original in (ROOT / "patches").iterdir():
                    if original.is_file():
                        shutil.copyfile(original, directory / original.name)
                (directory / filename).write_bytes(b"changed input")
                with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                    identity.airbender_build_pins(directory / "airbender-cuda-device-diagnostics.json")

    def test_gpu_backend_pins_and_cli_bind_exact_tested_manifest(self):
        manifest = ROOT / "patches/gpu32-memory.json"
        result = identity.gpu_backend_build_pins(manifest, ROOT / "Cargo.lock")
        self.assertEqual(result["manifest_sha256"], hashlib.sha256(manifest.read_bytes()).hexdigest())
        self.assertEqual(result["pins"]["security_bits"], 100)
        self.assertEqual(result["pins"]["domain_log"], 25)
        self.assertEqual(result["pins"]["polynomial_slots"], 29)
        self.assertEqual(result["pins"]["crypto"]["upstream_commit"],
                         "845905b2aae49215e3d4ad0b71998b4a6b5abebf")
        selected = result["selected_lock"]
        self.assertEqual(selected["derivation"], "common-proving-and-crypto-gpu-source-identity-only-v3")
        common = identity.airbender_build_pins(ROOT / "patches/airbender-cuda-device-diagnostics.json")
        self.assertEqual(result["zksync_crypto"], common["zksync_crypto"])
        self.assertEqual(selected["zksync_crypto_packages"], common["zksync_crypto"]["pins"]["upstream_packages"])
        self.assertNotEqual(result["pins"]["crypto"]["upstream_commit"],
                            result["zksync_crypto"]["pins"]["upstream_commit"])
        self.assertEqual(selected["canonical_lock_sha256"], hashlib.sha256((ROOT / "Cargo.lock").read_bytes()).hexdigest())
        self.assertNotEqual(selected["combined_overlay_lock_sha256"], selected["airbender_overlay_lock_sha256"])
        self.assertEqual(json.loads(self.cli("gpu-backend-pins", str(manifest), "--source-lock", str(ROOT / "Cargo.lock"))), result)
        for component in ("zksync-airbender-prover", "zksync-os-prover-snark"):
            record = identity.image_record(self.context, component, self.digests[component])
            bound = identity.bind_sbom({"bomFormat": "CycloneDX", "specVersion": "1.6"}, record, gpu_backend=result)
            props = {prop["name"]: prop["value"] for prop in bound["metadata"]["properties"]}
            self.assertEqual(json.loads(props["io.syscoin.prover.gpu-backend-build.inputs"]), result)
            # Duplicate GPU evidence is rejected independently of the image property checks.
            gpu_only = {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"properties": [
                {"name": "io.syscoin.prover.gpu-backend-build.inputs", "value": "old"}]}}
            with self.assertRaisesRegex(ValueError, "already contains GPU"):
                identity.bind_sbom(gpu_only, record, gpu_backend=result)
        fri = identity.image_record(self.context, "zksync-os-prover-fri", self.digests["zksync-os-prover-fri"])
        with self.assertRaisesRegex(ValueError, "FRI-only"):
            identity.bind_sbom({"bomFormat": "CycloneDX", "specVersion": "1.6"}, fri, gpu_backend=result)

    def test_wrapper_input_tampering_fails_before_sbom_evidence(self):
        for filename in ("zkos-wrapper-buffered-os-rng.patch", "zkos-wrapper-buffered-os-rng.json"):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                for original in (ROOT / "patches").iterdir():
                    if original.is_file():
                        shutil.copyfile(original, directory / original.name)
                if filename.endswith(".patch"):
                    (directory / filename).write_bytes(b"changed wrapper source input")
                else:
                    manifest = json.loads((directory / filename).read_text())
                    manifest["upstream_commit"] = "0" * 40
                    (directory / filename).write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    identity.airbender_build_pins(directory / "airbender-cuda-device-diagnostics.json")

    def test_gpu_backend_changed_patch_fails_before_evidence(self):
        for filename in ("crypto-gpu32-memory.patch", "bellman-gpu32-memory.patch"):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                for original in (ROOT / "patches").iterdir():
                    if original.is_file():
                        shutil.copyfile(original, directory / original.name)
                (directory / filename).write_bytes(b"changed GPU source input")
                with self.assertRaises(ValueError):
                    identity.gpu_backend_build_pins(directory / "gpu32-memory.json", ROOT / "Cargo.lock")

    def test_common_crypto_input_tampering_fails_before_sbom_evidence(self):
        for filename in ("zksync-crypto-native-fri-query-count.patch",
                         "zksync-crypto-native-fri-query-count.json"):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                for original in (ROOT / "patches").iterdir():
                    if original.is_file():
                        shutil.copyfile(original, directory / original.name)
                if filename.endswith(".patch"):
                    (directory / filename).write_bytes(b"changed common crypto source input")
                else:
                    pins = json.loads((directory / filename).read_text())
                    # The common bf2797 graph must never be attributed to the GPU 845 graph.
                    pins["upstream_commit"] = "845905b2aae49215e3d4ad0b71998b4a6b5abebf"
                    (directory / filename).write_text(json.dumps(pins))
                with self.assertRaises(ValueError):
                    identity.airbender_build_pins(directory / "airbender-cuda-device-diagnostics.json")

    def test_gpu_and_common_sbom_inputs_must_agree_on_common_crypto(self):
        common = identity.airbender_build_pins(ROOT / "patches/airbender-cuda-device-diagnostics.json")
        gpu = identity.gpu_backend_build_pins(ROOT / "patches/gpu32-memory.json")
        record = identity.image_record(self.context, "zksync-os-prover-snark",
                                       self.digests["zksync-os-prover-snark"])
        for changed in ({}, {"manifest_sha256": "0" * 64}):
            with self.subTest(changed=changed):
                gpu["zksync_crypto"] = changed
                with self.assertRaisesRegex(ValueError, "disagree on the common crypto"):
                    identity.bind_sbom({"bomFormat": "CycloneDX", "specVersion": "1.6"},
                                       record, common, gpu)

    def test_gpu_backend_cli_roundtrip_retains_only_gpu_role_origin(self):
        manifest = ROOT / "patches/gpu32-memory.json"
        gpu = identity.gpu_backend_build_pins(manifest, ROOT / "Cargo.lock")
        bom = self.directory / "gpu-bom.json"
        bom.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6"}))
        component = "zksync-os-prover-snark"
        bound = json.loads(self.cli("bind", component, self.digests[component], str(bom),
                                   "--airbender-pins", str(ROOT / "patches/airbender-cuda-device-diagnostics.json"),
                                   "--gpu-backend-pins", str(manifest), "--source-lock", str(ROOT / "Cargo.lock")))
        props = {prop["name"]: prop["value"] for prop in bound["metadata"]["properties"]}
        self.assertEqual(json.loads(props["io.syscoin.prover.gpu-backend-build.inputs"]), gpu)

    def test_selected_parent_lock_is_bound_separately_in_cli_and_sbom(self):
        manifest = ROOT / "patches/airbender-cuda-device-diagnostics.json"
        lock = self.directory / "Cargo.lock"
        lock.write_bytes(LOCK_FIXTURE.parent_lock_bytes())
        selected = identity.airbender_build_pins(manifest, lock)
        reference = identity.airbender_build_pins(manifest)
        self.assertEqual(selected["pins"], reference["pins"])
        self.assertEqual(selected["manifest_sha256"], reference["manifest_sha256"])
        self.assertEqual(selected["selected_lock"]["schema_version"], 3)
        self.assertEqual(selected["selected_lock"]["derivation"], "common-proving-source-identity-only-v3")
        self.assertEqual(selected["selected_lock"]["zksync_crypto_packages"],
                         reference["zksync_crypto"]["pins"]["upstream_packages"])
        self.assertEqual(selected["selected_lock"]["canonical_lock_sha256"],
                         hashlib.sha256(lock.read_bytes()).hexdigest())
        self.assertNotEqual(selected["selected_lock"]["overlay_lock_sha256"],
                            reference["pins"]["overlay_lock_sha256"])
        self.assertEqual(json.loads(self.cli("airbender-pins", str(manifest), "--source-lock", str(lock))), selected)
        bom = self.directory / "bom.json"
        bom.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6"}))
        result = json.loads(self.cli("bind", identity.COMPONENTS[0], self.digests[identity.COMPONENTS[0]],
                                    str(bom), "--airbender-pins", str(manifest), "--source-lock", str(lock)))
        value = next(item["value"] for item in result["metadata"]["properties"]
                     if item["name"] == "io.syscoin.prover.airbender-build.inputs")
        self.assertEqual(json.loads(value), selected)

    def test_image_provenance_and_sbom_include_airbender_input_identity(self):
        stage = (ROOT / ".github/workflows/stage-build.yaml").read_text()
        reusable = (ROOT / ".github/workflows/sbom-analysis-reusable.yaml").read_text()
        for workflow in (stage, (ROOT / ".github/workflows/release-bins.yml").read_text()):
            self.assertIn("$airbender.pins.upstream_commit", workflow)
            self.assertIn("$airbender.pins.patch_sha256", workflow)
            self.assertIn("$airbender.pins.overlay_lock_sha256", workflow)
            self.assertIn("$airbender.manifest_sha256", workflow)
            self.assertIn("$airbender.zkos_wrapper.pins.upstream_commit", workflow)
            self.assertIn("$airbender.zkos_wrapper.pins.patch_sha256", workflow)
            self.assertIn("$airbender.zkos_wrapper.manifest_sha256", workflow)
            self.assertIn("$airbender.zksync_crypto.pins.upstream_commit", workflow)
            self.assertIn("$airbender.zksync_crypto.pins.patch_sha256", workflow)
            self.assertIn("$airbender.zksync_crypto.manifest_sha256", workflow)
        self.assertIn(".zkos_wrapper.inputs == $expected.zkos_wrapper",
                      (ROOT / ".github/workflows/release-bins.yml").read_text())
        self.assertIn(".zksync_crypto.inputs == $expected.zksync_crypto",
                      (ROOT / ".github/workflows/release-bins.yml").read_text())
        self.assertIn("airbenderBuild: $airbender", stage)
        for workflow in (stage, (ROOT / ".github/workflows/release-bins.yml").read_text()):
            self.assertIn("$airbender.selected_lock.canonical_lock_sha256", workflow)
            self.assertIn("$airbender.selected_lock.overlay_lock_sha256", workflow)
            self.assertIn('uri: "syscoin:generated-lock:common-proving-source-identity-only-v3"', workflow)
            self.assertIn('uri: "syscoin:generated-lock:common-proving-and-crypto-gpu-source-identity-only-v3"', workflow)
        self.assertIn("--airbender-pins .sbom-tooling/patches/airbender-cuda-device-diagnostics.json", reusable)
        self.assertIn("--source-lock .sbom-image-source/Cargo.lock", reusable)
        self.assertIn('"$(git -C .sbom-image-source rev-parse HEAD)" == "${SOURCE_SHA}"', reusable)
        self.assertIn("            airbender-build-pins.json", reusable)
        self.assertIn("--gpu-backend-pins .sbom-tooling/patches/gpu32-memory.json", reusable)
        self.assertIn("            gpu-backend-build-pins.json", reusable)
        self.assertIn('if [[ "${COMPONENT}" != zksync-os-prover-fri ]]; then', reusable)
        for workflow in (stage, (ROOT / ".github/workflows/release-bins.yml").read_text()):
            self.assertIn("$gpu_backend.manifest_sha256", workflow)
            self.assertIn("$gpu_backend.pins.crypto.patch_sha256", workflow)
            self.assertIn("$gpu_backend.pins.bellman.patch_sha256", workflow)
            self.assertIn("$gpu_backend.selected_lock.combined_overlay_lock_sha256", workflow)

    @unittest.skipUnless(shutil.which("jq"), "jq is required")
    def test_actual_release_provenance_filter_binds_role_records(self):
        # Exercise the checked-in jq expression, without claiming a real build or signing.
        workflow = (ROOT / ".github/workflows/release-bins.yml").read_text()
        step = workflow.split("      - name: Bind release source into provenance\n", 1)[1]
        expression = re.search(r"\n            '\n(.*?)\n            ' <<<", step, re.S).group(1)
        lock = self.directory / "Cargo.lock"
        lock.write_bytes(LOCK_FIXTURE.parent_lock_bytes())
        pins = identity.airbender_build_pins(ROOT / "patches/airbender-cuda-device-diagnostics.json", lock)
        records = {role: {"sha256": str(index) * 64}
                   for index, role in enumerate(("combined", "fri", "snark", "snark-cpu"), 1)}
        gpu = identity.gpu_backend_build_pins(ROOT / "patches/gpu32-memory.json", lock)
        source_uri = "git+https://example.invalid/source@refs/tags/fixture"
        args = ["jq", "-ce", "--arg", "source_uri", source_uri,
                "--arg", "source_sha", "a" * 40, "--arg", "tooling_uri", "git+https://example.invalid/tooling",
                "--arg", "tooling_sha", "b" * 40, "--argjson", "airbender", json.dumps(pins),
                "--argjson", "airbender_records", json.dumps(records),
                "--argjson", "gpu_backend", json.dumps(gpu), expression]
        base = {"buildDefinition": {"buildType": "https://actions.github.io/buildtypes/workflow/v1",
                                   "externalParameters": {"workflow": {}}, "internalParameters": {},
                                   "resolvedDependencies": []},
                "runDetails": {"builder": {"id": "offline-test"}}}
        result = subprocess.run(args, input=json.dumps(base), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        definition = json.loads(result.stdout)["buildDefinition"]
        self.assertEqual(definition["internalParameters"]["syscoinAirbenderBuild"],
                         {"inputs": pins, "roleInputRecords": records, "cargoLocked": True})
        self.assertEqual(definition["internalParameters"]["syscoinGpuBackendBuild"],
                         {"inputs": gpu, "roles": ["combined", "snark"]})
        digests = [entry["digest"] for entry in definition["resolvedDependencies"]]
        self.assertIn({"gitCommit": pins["pins"]["upstream_commit"]}, digests)
        for value in (pins["manifest_sha256"], pins["pins"]["patch_sha256"], pins["pins"]["overlay_lock_sha256"]):
            self.assertIn({"sha256": value}, digests)
        self.assertIn({"gitCommit": pins["zkos_wrapper"]["pins"]["upstream_commit"]}, digests)
        for value in (pins["zkos_wrapper"]["manifest_sha256"], pins["zkos_wrapper"]["pins"]["patch_sha256"]):
            self.assertIn({"sha256": value}, digests)
        self.assertIn({"gitCommit": pins["zksync_crypto"]["pins"]["upstream_commit"]}, digests)
        for value in (pins["zksync_crypto"]["manifest_sha256"], pins["zksync_crypto"]["pins"]["patch_sha256"]):
            self.assertIn({"sha256": value}, digests)
        for key in ("canonical_lock_sha256", "overlay_lock_sha256"):
            self.assertIn({"sha256": pins["selected_lock"][key]}, digests)
        generated = next(item for item in definition["resolvedDependencies"]
                         if item["uri"] == "syscoin:generated-lock:common-proving-source-identity-only-v3")
        self.assertEqual(generated["digest"], {"sha256": pins["selected_lock"]["overlay_lock_sha256"]})
        for value in (gpu["manifest_sha256"], gpu["pins"]["crypto"]["patch_sha256"],
                      gpu["pins"]["bellman"]["patch_sha256"], gpu["selected_lock"]["combined_overlay_lock_sha256"]):
            self.assertIn({"sha256": value}, digests)
        base["buildDefinition"]["resolvedDependencies"] = [
            {"uri": source_uri, "digest": {"gitCommit": "c" * 40}}]
        self.assertNotEqual(subprocess.run(args, input=json.dumps(base), capture_output=True,
                                          text=True).returncode, 0)

    @unittest.skipUnless(shutil.which("jq"), "jq is required")
    def test_release_role_validation_rejects_missing_or_different_common_crypto(self):
        workflow = (ROOT / ".github/workflows/release-bins.yml").read_text()
        validation = workflow.split("          for role in combined fri snark snark-cpu; do\n", 1)[1]
        expression = re.search(r"\n              '(.*?)' \\\n", validation, re.S).group(1)
        pins = identity.airbender_build_pins(ROOT / "patches/airbender-cuda-device-diagnostics.json",
                                             ROOT / "Cargo.lock")
        record = {"cargo_exit_code": 0, "inputs_reverified": True, "label": "release-fri",
                  "pins": pins["pins"], "selected_lock": pins["selected_lock"],
                  "zkos_wrapper": {"inputs": pins["zkos_wrapper"]},
                  "zksync_crypto": {"inputs": pins["zksync_crypto"]},
                  "application_inputs_sha256": {"Cargo.lock": pins["selected_lock"]["canonical_lock_sha256"]}}
        args = ["jq", "-e", "--argjson", "expected", json.dumps(pins),
                "--arg", "role", "release-fri", expression]
        self.assertEqual(subprocess.run(args, input=json.dumps(record), capture_output=True,
                                        text=True).returncode, 0)
        for crypto in (None, {}, {"inputs": {"manifest_sha256": "0" * 64}}):
            with self.subTest(crypto=crypto):
                record["zksync_crypto"] = crypto
                self.assertNotEqual(subprocess.run(args, input=json.dumps(record), capture_output=True,
                                                   text=True).returncode, 0)

    def test_native_boojum_ci_uses_attested_workspace_and_preserves_failures(self):
        lines = (ROOT / ".github/workflows/ci.yaml").read_text().splitlines()
        step = lines.index("      - name: Run pinned native Boojum FRI query-count regression")
        self.assertEqual(lines[step + 1], "        timeout-minutes: 20")
        self.assertEqual(lines[step + 2], "        env:")
        start = lines.index("        run: |", step) + 1
        step_env = dict(line.strip().split(": ", 1) for line in lines[step + 3:start - 1])
        step_env = {key: value.strip('"') for key, value in step_env.items()}
        self.assertEqual(step_env, {"RUST_MIN_STACK": "33554432", "CARGO_PROFILE_DEV_DEBUG": "0",
                                    "CARGO_BUILD_JOBS": "1"})
        body = []
        for line in lines[start:]:
            if line.startswith("          "):
                body.append(line[10:])
            elif not line.strip():
                body.append("")
            else:
                break
        script = "\n".join(body)
        self.assertIn('record["zksync_crypto"]["inputs"] == helper.crypto_pins_metadata()', script)
        self.assertIn('record["cargo_exit_code"] == 0 and record["inputs_reverified"] is True', script)
        self.assertIn('record["label"] == "ci-test"', script)
        stub = r'''
import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
if name == "jq":
    record = json.loads(Path(sys.argv[-1]).read_text())
    print(record[sys.argv[-2].removeprefix(".")])
    raise SystemExit(0)
log = Path(os.environ["WORKFLOW_CALL_LOG"])
if name == "python3":
    source = sys.stdin.read()
    assert "helper.verify_crypto" in source and "helper.load_crypto_pins" in source
    event = {"kind": "verify", "crypto": sys.argv[-2], "record": sys.argv[-1]}
    previous = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    status_key = "VERIFY_AFTER_EXIT_CODE" if previous else "VERIFY_BEFORE_EXIT_CODE"
else:
    assert name == "cargo"
    event = {"kind": "cargo", "argv": sys.argv[1:], "target": os.environ["CARGO_TARGET_DIR"],
             "jobs": os.environ["CARGO_BUILD_JOBS"]}
    status_key = "BOOJUM_TEST_EXIT_CODE"
with log.open("a") as output:
    output.write(json.dumps(event) + "\n")
raise SystemExit(int(os.environ[status_key]))
'''
        for cargo_status, before_status, after_status in ((0, 0, 0), (7, 0, 0), (0, 9, 0), (0, 0, 11)):
            with self.subTest(cargo=cargo_status, before=before_status, after=after_status), \
                    tempfile.TemporaryDirectory(prefix="native boojum ci ") as temporary:
                root = Path(temporary)
                commands = root / "commands"
                commands.mkdir()
                for name in ("jq", "python3", "cargo"):
                    executable = commands / name
                    executable.write_text("#!" + sys.executable + "\n" + stub)
                    executable.chmod(0o700)
                workspace, target = root / "snapshot build/prover", root / "target cache"
                record = root / "ci-test-airbender-inputs.json"
                record.write_text(json.dumps({"workspace": str(workspace), "cargo_target_dir": str(target)}))
                log = root / "calls.jsonl"
                result = subprocess.run(["bash", "-eu", "-c", script], cwd=ROOT, capture_output=True,
                                        text=True, env={**os.environ, **step_env, "RUNNER_TEMP": str(root),
                                        "PATH": str(commands) + os.pathsep + os.environ.get("PATH", ""),
                                        "WORKFLOW_CALL_LOG": str(log), "BOOJUM_TEST_EXIT_CODE": str(cargo_status),
                                        "VERIFY_BEFORE_EXIT_CODE": str(before_status),
                                        "VERIFY_AFTER_EXIT_CODE": str(after_status)})
                self.assertEqual(result.returncode, before_status or after_status or cargo_status, result.stderr)
                crypto = workspace.parent / "zksync-crypto"
                verify = {"kind": "verify", "crypto": str(crypto), "record": str(record)}
                expected = [verify]
                if not before_status:
                    expected += [{"kind": "cargo", "target": str(target), "jobs": "1", "argv": [
                        "test", "--manifest-path", str(crypto / "Cargo.toml"), "--locked", "-p", "boojum", "--lib",
                        "cs::implementations::cs::test::prove_simple", "--", "--exact", "--nocapture", "--test-threads=1"]},
                        verify]
                self.assertEqual([json.loads(line) for line in log.read_text().splitlines()], expected)


if __name__ == "__main__":
    unittest.main()
