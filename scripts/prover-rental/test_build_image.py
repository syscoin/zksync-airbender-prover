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


if __name__ == "__main__":
    unittest.main()
