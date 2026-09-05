"""SYSCOIN: Offline regressions for image-matrix identity and SBOM evidence binding."""

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("image-sbom-identity.py")
SPEC = importlib.util.spec_from_file_location("image_sbom_identity", SCRIPT)
identity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(identity)
ROOT = SCRIPT.parents[2]


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


if __name__ == "__main__":
    unittest.main()
