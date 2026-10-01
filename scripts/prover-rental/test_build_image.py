import argparse
import importlib.util
from pathlib import Path
import tempfile
import unittest

import job
import runpod
from test_adapter import release


spec = importlib.util.spec_from_file_location("rental_build_image", Path(__file__).with_name("build-image.py"))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class BuildImageTests(unittest.TestCase):
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
