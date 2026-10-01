"""SYSCOIN: Offline role/format regressions; no large download, Docker build, or key generation.

Only curl is substituted in download tests. The production shell helper, jq selection, byte
count, and SHA-256 verification run against distinct tiny, explicitly synthetic fixture files.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "docker/fetch-verified-crs.sh"
PINS = json.loads((ROOT / "docker/prover-build-pins.json").read_text())
WORKFLOW = (ROOT / ".github/workflows/stage-build.yaml").read_text()


def workflow_filter(start, end):
    return WORKFLOW.split(start, 1)[1].split(end, 1)[0]


class VerifiedCrsRoleTests(unittest.TestCase):
    def setUp(self):
        for program in ("jq", "sha256sum", "sh", "od"):
            self.assertIsNotNone(shutil.which(program), f"{program} is required")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.bin_dir = self.directory / "bin"
        self.bin_dir.mkdir()
        self.fixture_pins = copy.deepcopy(PINS)
        self.payloads = {"cpu-snark": (1 << 25).to_bytes(8, "big") + b"synthetic CPU CRS fixture\n",
                         "gpu-snark": b"synthetic compact GPU fixture\n"}
        for role, payload in self.payloads.items():
            (self.directory / role).write_bytes(payload)
            key = "cpu_snark_crs" if role == "cpu-snark" else "crs"
            self.fixture_pins[key] = {
                "url": f"https://fixtures.invalid/{role}", "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
            if role == "cpu-snark":
                self.fixture_pins[key]["g1_count"] = 1 << 25
        self.pins_path = self.directory / "pins.json"
        self.save_pins()
        self.output = self.directory / "output.key"
        self.curl_log = self.directory / "curl.json"
        # There is no network fallback: every unexpected URL or argument fails this substitute.
        curl = self.bin_dir / "curl"
        curl.write_text(f"#!{sys.executable}\n" + """
import json
import os
from pathlib import Path
import sys
args = sys.argv[1:]
directory = Path(os.environ['CRS_FIXTURE_DIRECTORY'])
(directory / 'curl.json').write_text(json.dumps(args))
if args[-1] not in ('https://fixtures.invalid/cpu-snark', 'https://fixtures.invalid/gpu-snark'):
    sys.exit(91)
role = args[-1].rsplit('/', 1)[1]
payload = (directory / role).read_bytes()
mutation = os.environ.get('CRS_FIXTURE_MUTATION')
if mutation == 'truncate':
    payload = payload[:-1]
elif mutation == 'corrupt':
    payload = bytes([payload[0] ^ 1]) + payload[1:]
Path(args[args.index('--output') + 1]).write_bytes(payload)
if mutation == 'curl-failure':
    sys.exit(22)
""")
        curl.chmod(0o755)
        self.env = {**os.environ, "PATH": str(self.bin_dir) + os.pathsep + os.environ["PATH"],
                    "PROVER_BUILD_PINS": str(self.pins_path),
                    "CRS_FIXTURE_DIRECTORY": str(self.directory),
                    "PYTHONDONTWRITEBYTECODE": "1"}

    def save_pins(self):
        self.pins_path.write_text(json.dumps(self.fixture_pins))

    def download(self, *args, mutation=None):
        env = dict(self.env)
        if mutation:
            env["CRS_FIXTURE_MUTATION"] = mutation
        return subprocess.run(["sh", str(HELPER), *map(str, args)], env=env,
                              text=True, capture_output=True)

    def test_each_explicit_role_downloads_and_verifies_its_own_format(self):
        for role, expected in self.payloads.items():
            with self.subTest(role=role):
                result = self.download(role, self.output)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.output.read_bytes(), expected)
                self.assertEqual(self.output.stat().st_mode & 0o777, 0o644)
                args = json.loads(self.curl_log.read_text())
                self.assertEqual(args[-1], f"https://fixtures.invalid/{role}")
                for option in ("--proto", "--proto-redir"):
                    self.assertEqual(args[args.index(option) + 1], "=https")
                self.assertEqual(list(self.directory.glob("output.key.part.*")), [])

    def test_legacy_single_path_still_explicitly_warns_and_selects_compact(self):
        result = self.download(self.output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_bytes(), self.payloads["gpu-snark"])
        self.assertIn("CPU requires cpu-snark OUTPUT", result.stderr)

    def test_bad_invocation_and_fri_role_fail_before_download(self):
        for args in ((), ("cpu-snark",), ("gpu-snark",), ("fri",),
                     ("fri", self.output), ("cpu", self.output),
                     ("cpu-snark", ""), ("cpu-snark", self.output, "extra")):
            with self.subTest(args=args):
                self.assertNotEqual(self.download(*args).returncode, 0)
                self.assertFalse(self.curl_log.exists())
                self.assertFalse(self.output.exists())

    def test_invalid_selected_pins_fail_before_download(self):
        original = copy.deepcopy(self.fixture_pins)
        mutations = (("url", "http://fixtures.invalid/cpu-snark"), ("url", None),
                     ("size", 0), ("size", 1.5), ("size", "24"),
                     ("sha256", "a" * 63), ("sha256", "A" * 64),
                     ("sha256", "0" * 64), ("sha256", None),
                     ("g1_count", 1 << 24), ("g1_count", None),
                     ("g1_count", (1 << 25) + 0.5))
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                self.fixture_pins = copy.deepcopy(original)
                self.fixture_pins["cpu_snark_crs"][field] = value
                self.save_pins()
                self.assertNotEqual(self.download("cpu-snark", self.output).returncode, 0)
                self.assertFalse(self.curl_log.exists())
        self.fixture_pins.pop("cpu_snark_crs")
        self.save_pins()
        self.assertNotEqual(self.download("cpu-snark", self.output).returncode, 0)
        self.assertFalse(self.curl_log.exists())

    def test_size_hash_and_transport_failures_preserve_existing_output(self):
        for mutation in ("truncate", "corrupt", "curl-failure"):
            with self.subTest(mutation=mutation):
                self.output.write_bytes(b"previous verified artifact")
                result = self.download("cpu-snark", self.output, mutation=mutation)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.output.read_bytes(), b"previous verified artifact")
                self.assertEqual(list(self.directory.glob("output.key.part.*")), [])

    def test_pinned_cpu_source_and_digest_are_distinct_from_compact(self):
        self.assertEqual(PINS["cpu_snark_crs"], {
            "url": "https://storage.googleapis.com/matterlabs-setup-keys-us/setup-keys/"
                   "setup_2%5E25.key?generation=1682086010630627",
            "size": 2147483920,
            "sha256": "021fcc36428ff74352a94ff9ccdd6ef234e99e33e670c2507612994849aa1421",
            "g1_count": 1 << 25,
        })
        self.assertEqual(PINS["crs"]["size"], 4831838468)
        self.assertEqual(PINS["crs"]["sha256"],
                         "90d1dea94da665d5741dcc6e9ffc1af23a29669f950a6d599a6ccfee4cfb81bd")

    def test_docker_crs_roles_and_runtime_paths_match(self):
        for image, role, filename in (
            ("zksync-os-prover-snark", "cpu-snark", "setup_2^25.key"),
            ("zksync-airbender-prover", "gpu-snark", "setup_compact.key"),
        ):
            source = (ROOT / "docker" / image / "Dockerfile").read_text()
            self.assertIn(f"fetch-verified-crs {role} /{filename}", source)
            self.assertIn(f"COPY --from=builder /{filename} /{filename}", source)
            other = "setup_compact.key" if role == "cpu-snark" else "setup_2^25.key"
            self.assertNotIn(other, source)
        fri = (ROOT / "docker/zksync-os-prover-fri/Dockerfile").read_text()
        for forbidden in ("fetch-verified-crs", "setup_compact.key", "setup_2^25.key"):
            self.assertNotIn(forbidden, fri)

    def test_readme_commands_match_crs_to_compiled_backend(self):
        source = re.sub(r"\\\r?\n\s*", " ", (ROOT / "README.md").read_text())
        cpu_count = gpu_count = 0
        for line in source.splitlines():
            if "cargo run" not in line or "--trusted-setup-file" not in line:
                continue
            tokens = shlex.split(line)
            path = tokens[tokens.index("--trusted-setup-file") + 1]
            if "--no-default-features" in tokens:
                self.assertEqual(path, "crs/setup_2^25.key")
                cpu_count += 1
            else:
                self.assertIn("gpu", tokens)
                self.assertEqual(path, "crs/setup_compact.key")
                gpu_count += 1
        self.assertEqual(cpu_count, 3)
        self.assertEqual(gpu_count, 1)

    def test_image_pin_validation_requires_both_verified_formats(self):
        expression = workflow_filter('build_pins="$(jq -ce \'',
                                     "' \"${build_context}/docker/prover-build-pins.json\")\"")
        def validate(pins):
            return subprocess.run(["jq", "-ce", expression], input=json.dumps(pins),
                                  text=True, capture_output=True)
        self.assertEqual(validate(PINS).returncode, 0)
        for key in ("crs", "cpu_snark_crs"):
            for mutation in (None, {**PINS[key], "sha256": "0" * 64},
                             {**PINS[key], "size": 2.5}):
                with self.subTest(key=key, mutation=mutation):
                    self.assertNotEqual(validate({**PINS, key: mutation}).returncode, 0)
        for count in (None, 1 << 24, (1 << 25) + 0.5):
            self.assertNotEqual(validate({**PINS, "cpu_snark_crs": {
                **PINS["cpu_snark_crs"], "g1_count": count,
            }}).returncode, 0)

    def test_cpu_header_capacity_is_checked_even_with_matching_size_and_hash(self):
        for header in ((1 << 24).to_bytes(8, "big"), (1 << 26).to_bytes(8, "big"),
                       (1 << 25).to_bytes(8, "little"), b"short"):
            with self.subTest(header=header):
                # Recompute the synthetic fixture digest so failure must come from the header
                # check, not the independent byte-count or checksum gates.
                payload = header
                (self.directory / "cpu-snark").write_bytes(payload)
                self.fixture_pins["cpu_snark_crs"].update({
                    "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest(),
                })
                self.save_pins()
                self.output.write_bytes(b"previous verified artifact")
                result = self.download("cpu-snark", self.output)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.output.read_bytes(), b"previous verified artifact")
                self.assertEqual(list(self.directory.glob("output.key.part.*")), [])

    def test_image_provenance_uses_actual_role_crs_or_none_for_fri(self):
        expression = workflow_filter('--argjson airbender "${AIRBENDER_PINS}" \\\n            \'',
                                     "' <<< \"${BASE_PROVENANCE}\"")
        base = {"buildDefinition": {"buildType": "https://actions.github.io/buildtypes/workflow/v1",
                                   "internalParameters": {}, "resolvedDependencies": []},
                "runDetails": {"builder": {"id": "offline-test"}}}
        args = ["jq", "-ce", "--argjson", "build_pins", json.dumps(PINS)]
        manifest = ROOT / "patches/airbender-cuda-device-diagnostics.json"
        airbender = {"manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
                     "pins": json.loads(manifest.read_text())}
        args += ["--argjson", "airbender", json.dumps(airbender)]
        for name in ("source_uri", "source_sha", "tooling_uri", "tooling_repository", "tooling_sha",
                     "app_bin_sha256", "app_text_sha256"):
            args += ["--arg", name, "offline-fixture"]
        for name in ("app_bin_size", "app_text_size"):
            args += ["--argjson", name, "1"]
        for component, crs in (("zksync-os-prover-snark", PINS["cpu_snark_crs"]),
                               ("zksync-airbender-prover", PINS["crs"]),
                               ("zksync-os-prover-fri", None), ("unknown", None)):
            with self.subTest(component=component):
                result = subprocess.run(args + ["--arg", "component", component, expression],
                                        input=json.dumps(base), text=True, capture_output=True)
                if component == "unknown":
                    self.assertNotEqual(result.returncode, 0)
                    continue
                self.assertEqual(result.returncode, 0, result.stderr)
                definition = json.loads(result.stdout)["buildDefinition"]
                trusted = definition["internalParameters"]["syscoinProverImage"]["trustedSetup"]
                self.assertEqual(definition["internalParameters"]["syscoinProverImage"]["airbenderBuild"],
                                 airbender)
                crs_dependencies = [dep for dep in definition["resolvedDependencies"]
                                    if dep["uri"] in {PINS["crs"]["url"], PINS["cpu_snark_crs"]["url"]}]
                if crs is None:
                    self.assertIsNone(trusted)
                    self.assertEqual(crs_dependencies, [])
                else:
                    self.assertEqual(trusted, {"sha256": crs["sha256"], "size": crs["size"]})
                    self.assertEqual(crs_dependencies,
                                     [{"uri": crs["url"], "digest": {"sha256": crs["sha256"]}}])

    def test_ci_runs_offline_crs_tests(self):
        self.assertIn("run: python3 -B .github/scripts/test_verified_crs_roles.py",
                      (ROOT / ".github/workflows/ci.yaml").read_text())


if __name__ == "__main__":
    unittest.main()
