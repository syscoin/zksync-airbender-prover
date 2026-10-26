#!/usr/bin/env python3
"""Exercise the image workflow's source binding for a same-run release call."""

import os
from pathlib import Path
import subprocess
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

    def test_smoke_workflow_never_pushes_or_grants_write_permissions(self):
        smoke = (ROOT / ".github/workflows/image-build-smoke.yaml").read_text()
        self.assertIn("push: false", smoke)
        self.assertNotIn("packages: write", smoke)
        self.assertNotIn("id-token: write", smoke)
        self.assertNotIn("secrets.", smoke)


if __name__ == "__main__":
    unittest.main()
