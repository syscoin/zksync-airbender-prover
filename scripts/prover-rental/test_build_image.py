import argparse
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import job
import runpod
from test_adapter import release


spec = importlib.util.spec_from_file_location("rental_build_image", Path(__file__).with_name("build-image.py"))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class BuildImageTests(unittest.TestCase):
    def test_warm_build_context_contains_importable_persistent_worker(self):
        real_run = subprocess.run
        with tempfile.TemporaryDirectory() as temporary:
            release_path = Path(temporary) / "FRI.json"
            job.write_new(release_path, job.encode(release("FRI")))

            def inspect_build(command, **_):
                context = Path(command[-1])
                for line in (context / "Dockerfile").read_text().splitlines():
                    if line.startswith("COPY "):
                        for name in line.split()[1:-1]:
                            self.assertTrue((context / name).exists(), name)
                self.assertTrue((context / "fri_session.py").is_file())
                result = real_run([sys.executable, str(context / "warm_worker.py"), "--help"],
                                  cwd=context, env={}, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)

            argv = ["build-image.py", "--warm", "--fri-release", str(release_path), "--base-image",
                    "example/prover@sha256:" + "a" * 64, "--tag", "warm-test", "--execute"]
            with patch.object(sys, "argv", argv), patch.object(builder.subprocess, "run", inspect_build):
                builder.main()

    def test_warm_image_pins_both_stages_to_same_application(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for stage in ("FRI", "SNARK"):
                job.write_new(root / (stage + ".json"), job.encode(release(stage)))
            args = argparse.Namespace(warm=True, release=None,
                fri_release=str(root / "FRI.json"), snark_release=str(root / "SNARK.json"))
            self.assertEqual(set(builder.releases_for(args)), {"releases/FRI.json", "releases/SNARK.json"})
            original = release("SNARK")
            for field in ("vk_hash", "program_commitment", "app_bin_sha256", "app_text_sha256"):
                altered = {**original, field: ("0x" if field in ("vk_hash", "program_commitment") else "") + "e" * 64}
                runpod.atomic_json(root / "SNARK.json", altered)
                with self.subTest(field=field), self.assertRaisesRegex(runpod.Error, "warm_stage_identity_mismatch"):
                    builder.releases_for(args)

    def test_role_specific_image_requires_correct_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "release.json"
            job.write_new(source, job.encode(release("SNARK")))
            args = argparse.Namespace(warm=True, release=None, fri_release=None, snark_release=str(source))
            self.assertEqual(set(builder.releases_for(args)), {"releases/SNARK.json"})
            args.fri_release, args.snark_release = args.snark_release, None
            with self.assertRaisesRegex(runpod.Error, "stage_release_mismatch"):
                builder.releases_for(args)

    def test_serverless_requires_only_the_fri_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "release.json"
            job.write_new(source, job.encode(release("FRI")))
            args = argparse.Namespace(serverless_fri=True, warm=False, release=None,
                                      fri_release=str(source), snark_release=None)
            self.assertEqual(set(builder.releases_for(args)), {"release.json"})
            for field, value in (("warm", True), ("release", str(source)), ("snark_release", str(source)),
                                 ("fri_release", None)):
                altered = argparse.Namespace(**{**vars(args), field: value})
                with self.subTest(field=field), self.assertRaisesRegex(runpod.Error,
                                                                       "serverless_requires_fri_release_only"):
                    builder.releases_for(altered)
            runpod.atomic_json(source, release("SNARK"))
            with self.assertRaisesRegex(runpod.Error, "stage_release_mismatch"):
                builder.releases_for(args)

    def test_serverless_build_context_keeps_sdk_and_local_provider_distinct(self):
        real_run = subprocess.run
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            release_path = root / "FRI.json"
            job.write_new(release_path, job.encode(release("FRI")))
            sdk = root / "sdk"
            sdk.mkdir()
            (sdk / "runpod.py").write_text("is_sdk = True\n")

            def inspect_build(command, **_):
                context = Path(command[-1])
                self.assertFalse((context / "runpod.py").exists())
                self.assertTrue((context / "rental_provider.py").exists())
                for line in (context / "Dockerfile").read_text().splitlines():
                    if line.startswith("COPY "):
                        for name in line.split()[1:-1]:
                            self.assertTrue((context / name).exists(), name)
                script = ("import runpod, rental_provider, job, worker, fri_session, serverless_worker; "
                          "assert runpod.is_sdk; assert job.Error is rental_provider.Error; "
                          "assert fri_session.Error is rental_provider.Error")
                result = real_run([sys.executable, "-c", script], cwd=context,
                                  env={"PYTHONPATH": str(sdk), "PYTHONDONTWRITEBYTECODE": "1"},
                                  capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)

            argv = ["build-image.py", "--serverless-fri", "--fri-release", str(release_path),
                    "--base-image", "example/fri@sha256:" + "a" * 64, "--tag", "serverless-test", "--execute"]
            with patch.object(sys, "argv", argv), patch.object(builder.subprocess, "run", inspect_build):
                builder.main()

    def test_serverless_dependency_closure_is_hash_pinned(self):
        path = Path(__file__).with_name("requirements-serverless.txt")
        requirements = [line for line in path.read_text().splitlines() if line and not line.startswith("#")]
        for requirement in requirements:
            self.assertRegex(requirement, r"^[a-z0-9-]+==[^ ]+ --hash=sha256:[0-9a-f]{64}$")
        self.assertIn("runpod==1.12.0 --hash=sha256:2c52d5ad4268879bd4d8288f84a9861488abc756ffc5195d95f1cffe4c4f3454",
                      requirements)

    def test_serverless_recipe_uses_prebuilt_fri_without_startup_installs(self):
        recipe = Path(__file__).with_name("Dockerfile.serverless").read_text()
        self.assertIn("--require-hashes", recipe)
        self.assertIn("worker.py --validate-image", recipe)
        self.assertIn('"/opt/zksys-serverless/serverless_runner.py"', recipe)
        self.assertIn("RUNPOD_LOG_LEVEL=INFO", recipe)
        self.assertIn("RUNPOD_INIT_TIMEOUT=610", recipe)
        self.assertIn("RUNPOD_REALTIME_CONCURRENCY=1", recipe)
        self.assertNotIn("setup_compact.key", recipe)
        self.assertNotIn("git clone", recipe)
        self.assertNotIn("cargo build", recipe)
        base = Path(__file__).resolve().parents[2] / "docker/zksync-os-prover-fri/Dockerfile"
        self.assertIn("-p zksync_os_fri_prover", base.read_text())
        self.assertNotIn("setup_compact.key", base.read_text())


if __name__ == "__main__":
    unittest.main()
