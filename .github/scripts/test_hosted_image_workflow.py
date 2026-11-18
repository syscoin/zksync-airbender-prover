#!/usr/bin/env python3
"""Exercise the image workflow's source binding for a same-run release call."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = (ROOT / ".github/workflows/stage-build.yaml").read_text()


def step_script(name, next_name):
    body = WORKFLOW.split(f"      - name: {name}\n", 1)[1]
    body = body.split(f"      - name: {next_name}\n", 1)[0]
    return textwrap.dedent(body.split("        run: |\n", 1)[1])


class HostedImageWorkflow(unittest.TestCase):
    def test_called_release_binds_tag_to_sha_even_on_push_event(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / "source").write_text("v1\n")
            subprocess.run(["git", "-C", str(repo), "add", "source"], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=Fixture", "-c",
                            "user.email=fixture@example.invalid", "commit", "-qm", "v1"], check=True)
            sha = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            subprocess.run(["git", "-C", str(repo), "tag", "v1.0.0"], check=True)
            output = repo / "outputs"
            output.touch()
            env = {**os.environ, "GITHUB_EVENT_NAME": "push", "GITHUB_REF_TYPE": "branch",
                   "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": sha, "GITHUB_OUTPUT": str(output),
                   "REQUESTED_TAG": "v1.0.0", "REQUESTED_SOURCE_SHA": sha}
            validate = step_script("Validate requested source identity", "Checkout exact requested source")
            verify = step_script("Verify source identity", "Compute SHA tag")
            subprocess.run(["bash", "-c", validate], cwd=repo, env=env, check=True)
            self.assertIn("checkout_ref=refs/tags/v1.0.0", output.read_text())
            subprocess.run(["bash", "-c", verify], cwd=repo, env=env, check=True)
            self.assertIn("source_ref=refs/tags/v1.0.0", output.read_text())
            self.assertIn(f"source_sha={sha}", output.read_text())
            mismatch = {**env, "REQUESTED_SOURCE_SHA": "f" * 40}
            self.assertNotEqual(subprocess.run(["bash", "-c", verify], cwd=repo, env=mismatch,
                                               capture_output=True).returncode, 0)
            partial = {**env, "REQUESTED_SOURCE_SHA": ""}
            self.assertNotEqual(subprocess.run(["bash", "-c", validate], cwd=repo, env=partial,
                                               capture_output=True).returncode, 0)

    def test_docker_hub_optional_login_rejects_partial_configuration(self):
        check = step_script("Check optional Docker Hub credentials", "Login to Docker Hub for pinned base images")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            for username, token, expected in (("", "", "false"), ("user", "token", "true")):
                output.write_text("")
                env = {**os.environ, "HUB_USER": username, "HUB_TOKEN": token, "GITHUB_OUTPUT": str(output)}
                subprocess.run(["bash", "-c", check], env=env, check=True)
                self.assertEqual(output.read_text(), f"enabled={expected}\n")
            for username, token in (("user", ""), ("", "token")):
                env = {**os.environ, "HUB_USER": username, "HUB_TOKEN": token, "GITHUB_OUTPUT": str(output)}
                self.assertNotEqual(subprocess.run(["bash", "-c", check], env=env,
                                                   capture_output=True).returncode, 0)

    def test_v2_image_predicate_records_each_role_and_its_locked_sources(self):
        script = step_script("Bind source, app, toolchain, and CRS into provenance", "Attest GHCR image digest")
        pin_file = ROOT / "patches/v2-proving-sources.json"
        identity = ROOT / ".github/scripts/image-sbom-identity.py"

        def read_pins(command):
            return json.loads(subprocess.check_output(
                [sys.executable, str(identity), command, str(pin_file), "--source-lock", str(ROOT / "Cargo.lock")]
            ))

        common = read_pins("airbender-pins")
        gpu = read_pins("gpu-backend-pins")
        build = json.loads((ROOT / "docker/prover-build-pins.json").read_text())
        predicate = {"buildDefinition": {"buildType": "https://actions.github.io/buildtypes/workflow/v1",
                                         "internalParameters": {}, "resolvedDependencies": []},
                     "runDetails": {"builder": {"id": "fixture"}}}
        with tempfile.TemporaryDirectory() as temporary:
            env = {**os.environ, "RUNNER_TEMP": temporary, "BASE_PROVENANCE": json.dumps(predicate),
                   "BASE_PROVENANCE_TYPE": "https://slsa.dev/provenance/v1",
                   "GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "syscoin/zksync-airbender-prover",
                   "SOURCE_REF": "refs/heads/fixture", "SOURCE_SHA": "1" * 40,
                   "TOOLING_REPOSITORY": "syscoin/zksync-airbender-prover", "TOOLING_SHA": "2" * 40,
                   "APP_BIN_SHA256": "3" * 64, "APP_BIN_SIZE": "10", "APP_TEXT_SHA256": "4" * 64,
                   "APP_TEXT_SIZE": "9", "BUILD_PINS": json.dumps(build), "AIRBENDER_PINS": json.dumps(common)}
            for role in ("zksync-os-prover-fri", "zksync-os-prover-snark", "zksync-airbender-prover"):
                backend = None if role == "zksync-os-prover-fri" else gpu
                with self.subTest(role=role):
                    run_env = {**env, "COMPONENT": role, "GPU_BACKEND_PINS": json.dumps(backend)}
                    subprocess.run(["bash", "-c", script], env=run_env, check=True)
                    definition = json.loads((Path(temporary) / f"{role}-provenance.json").read_text())["buildDefinition"]
                    record = definition["internalParameters"]["syscoinProverImage"]
                    self.assertEqual(record["airbenderBuild"], common)
                    self.assertEqual(record["gpuBackendBuild"], backend)
                    self.assertEqual(record["securityLevel"], 100)
                    references = {entry["uri"]: entry["digest"] for entry in definition["resolvedDependencies"]}
                    for source in (common["airbender"], common["protocol"]):
                        self.assertEqual(references["git+" + source["repository"]], {"gitCommit": source["commit"]})
                    native = gpu["bellman_cuda"]
                    if backend is None:
                        self.assertNotIn("git+" + native["repository"], references)
                        self.assertIsNone(record["trustedSetup"])
                    else:
                        self.assertEqual(references["git+" + native["repository"]], {"gitCommit": native["commit"]})
                        self.assertEqual(record["bellmanCudaCommit"], native["commit"])
                        self.assertEqual(record["trustedSetup"]["sha256"], build["crs"]["sha256"])

            altered_gpu = {**gpu, "protocol": {**gpu["protocol"], "commit": "5" * 40}}
            for role, backend in (("zksync-os-prover-snark", altered_gpu), ("zksync-os-prover-fri", gpu)):
                run_env = {**env, "COMPONENT": role, "GPU_BACKEND_PINS": json.dumps(backend)}
                failure = subprocess.run(["bash", "-c", script], env=run_env, capture_output=True)
                self.assertNotEqual(failure.returncode, 0)

    def test_smoke_workflow_never_pushes_or_grants_write_permissions(self):
        smoke = (ROOT / ".github/workflows/image-build-smoke.yaml").read_text()
        self.assertIn("push: false", smoke)
        self.assertNotIn("packages: write", smoke)
        self.assertNotIn("id-token: write", smoke)
        self.assertNotIn("secrets.", smoke)


if __name__ == "__main__":
    unittest.main()
