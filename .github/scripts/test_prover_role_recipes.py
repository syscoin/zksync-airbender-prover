"""SYSCOIN: Offline regressions for package-scoped production prover build roles.

These recipe checks do not replace native CUDA builds or dependency-tree validation.
"""

from pathlib import Path
import importlib.util
import json
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
ROLES = {
    "zksync_os_fri_prover": ("zksync_os_fri_prover", "zksync-os-prover-fri", True),
    "zksync_os_snark_prover": ("zksync_os_snark_prover", "zksync-os-prover-snark", False),
    "zksync-os-prover-service": ("zksync_os_prover_service", "zksync-airbender-prover", True),
}
RELEASE_BINS = {
    "${ZKSYNC_OS_FRI_PROVER_BIN}": "zksync_os_fri_prover",
    "${ZKSYNC_OS_SNARK_PROVER_BIN}": "zksync_os_snark_prover",
    "${ZKSYNC_OS_PROVER_BIN}": "zksync-os-prover-service",
}
OVERLAY_FILES = (
    "scripts/cargo-with-patched-airbender.sh",
    "scripts/prepare-patched-airbender.py",
    "patches/airbender-cuda-device-diagnostics.patch",
    "patches/airbender-cuda-device-diagnostics.json",
    "patches/airbender.Cargo.lock",
)
LOCK_TEST_SPEC = importlib.util.spec_from_file_location(
    "lock_fixture", ROOT / ".github/scripts/test_patched_airbender_build.py")
LOCK_FIXTURE = importlib.util.module_from_spec(LOCK_TEST_SPEC)
LOCK_TEST_SPEC.loader.exec_module(LOCK_FIXTURE)


def cargo_commands(source, verb):
    """Read literal multiline recipe commands without running shell or Cargo."""
    source = re.sub(r"\\\r?\n\s*", " ", source)
    commands = []
    for line in source.splitlines():
        if line.lstrip().startswith("#"):
            continue
        match = re.search(rf"\bcargo\s+{verb}\b", line)
        if match:
            tokens = shlex.split(line[match.start():], comments=True)
            # Application flags after `cargo run --` are not Cargo options.
            if "--" in tokens:
                tokens = tokens[:tokens.index("--")]
            commands.append(tokens)
    return commands


def option_values(tokens, *names):
    values = []
    for index, token in enumerate(tokens):
        if token in names:
            if index + 1 >= len(tokens):
                raise AssertionError(f"missing value for {token}")
            values.append(tokens[index + 1])
        else:
            for name in names:
                if token.startswith(name + "="):
                    values.append(token[len(name) + 1:])
    return values


class ProverRoleRecipeTests(unittest.TestCase):
    def assert_role(self, tokens, binary, gpu):
        package = ROLES[binary][0]
        self.assertEqual(option_values(tokens, "-p", "--package"), [package])
        bins = option_values(tokens, "--bin")
        self.assertEqual([RELEASE_BINS.get(value, value) for value in bins], [binary])
        self.assertFalse({"--workspace", "--all", "--all-features"}.intersection(tokens))
        features = {
            feature
            for value in option_values(tokens, "--features", "-F")
            for feature in re.split(r"[,\s]+", value)
            if feature
        }
        self.assertEqual(features, {"gpu"} if gpu else set())
        if not gpu:
            self.assertIn("--no-default-features", tokens)

    def test_docker_builds_isolate_each_role(self):
        for binary, (_, image, gpu) in ROLES.items():
            with self.subTest(role=binary):
                dockerfile = ROOT / "docker" / image / "Dockerfile"
                commands = cargo_commands(dockerfile.read_text(), "build")
                self.assertEqual(len(commands), 1)
                self.assert_role(commands[0], binary, gpu)
                self.assertIn("--locked", commands[0])

    def test_release_builds_match_docker_roles(self):
        workflow = (ROOT / ".github/workflows/release-bins.yml").read_text()
        commands = cargo_commands(workflow, "build")
        self.assertEqual(len(commands), len(ROLES))
        seen = []
        for tokens in commands:
            bins = option_values(tokens, "--bin")
            self.assertEqual(len(bins), 1)
            binary = RELEASE_BINS.get(bins[0], bins[0])
            self.assertIn(binary, ROLES)
            self.assert_role(tokens, binary, ROLES[binary][2])
            self.assertIn("--locked", tokens)
            seen.append(binary)
        self.assertCountEqual(seen, ROLES)

    def test_documented_worker_commands_select_their_package(self):
        for path, expected in (
            ("README.md", set(ROLES)),
            ("docs/setup_linux_vm.md", {"zksync_os_fri_prover", "zksync_os_snark_prover"}),
        ):
            seen = set()
            for tokens in cargo_commands((ROOT / path).read_text(), "run"):
                bins = option_values(tokens, "--bin")
                if len(bins) != 1 or bins[0] not in ROLES:
                    continue
                binary = bins[0]
                # The development guide intentionally demonstrates optional GPU SNARK.
                gpu = ROLES[binary][2] or path == "docs/setup_linux_vm.md"
                with self.subTest(path=path, role=binary):
                    self.assert_role(tokens, binary, gpu)
                seen.add(binary)
            self.assertEqual(seen, expected)

    def test_binary_selection_alone_is_rejected(self):
        tokens = shlex.split("cargo build --bin zksync_os_fri_prover --features gpu")
        with self.assertRaises(AssertionError):
            self.assert_role(tokens, "zksync_os_fri_prover", True)

    def test_wrong_package_and_workspace_selection_are_rejected(self):
        for selection in ("-p zksync_os_snark_prover", "-p zksync_os_fri_prover --workspace"):
            tokens = shlex.split(
                f"cargo build {selection} --bin zksync_os_fri_prover --features gpu"
            )
            with self.subTest(selection=selection), self.assertRaises(AssertionError):
                self.assert_role(tokens, "zksync_os_fri_prover", True)

    def test_cpu_snark_gpu_feature_is_rejected(self):
        tokens = shlex.split(
            "cargo build -p zksync_os_snark_prover --bin zksync_os_snark_prover "
            "--no-default-features --features gpu"
        )
        with self.assertRaises(AssertionError):
            self.assert_role(tokens, "zksync_os_snark_prover", False)

    def test_ci_runs_role_recipe_checks(self):
        workflow = (ROOT / ".github/workflows/ci.yaml").read_text()
        self.assertIn("run: python3 -B .github/scripts/test_prover_role_recipes.py", workflow)

    def test_all_production_builds_use_the_reviewed_wrapper(self):
        paths = [".github/workflows/release-bins.yml", *(
            f"docker/{image}/Dockerfile" for _, image, _ in ROLES.values())]
        for path in paths:
            source = re.sub(r"\\\r?\n\s*", " ", (ROOT / path).read_text())
            for line in source.splitlines():
                if re.search(r"\bcargo build\b", line) and not line.lstrip().startswith("#"):
                    with self.subTest(path=path, line=line):
                        self.assertRegex(line, r"bash (?:\.release-tooling/)?scripts/"
                                         r"cargo-with-patched-airbender\.sh [a-z-]+ --\s+cargo build")
                        self.assertIn("AIRBENDER_BUILD_ATTESTATION=", line)
        ci = (ROOT / ".github/workflows/ci.yaml").read_text()
        for command in ("clippy", "build", "test"):
            self.assertRegex(ci, rf"cargo-with-patched-airbender\.sh ci-[a-z]+ -- cargo {command} --locked")
        self.assertIn("python3 -B .github/scripts/test_patched_airbender_build.py", ci)

    def test_every_role_retains_its_success_record(self):
        release = (ROOT / ".github/workflows/release-bins.yml").read_text()
        for role, image in (("fri", "zksync-os-prover-fri"),
                            ("snark", "zksync-os-prover-snark"),
                            ("combined", "zksync-airbender-prover")):
            docker = (ROOT / "docker" / image / "Dockerfile").read_text()
            record = f"{role}-airbender-build-inputs.json"
            self.assertIn(f"AIRBENDER_BUILD_ATTESTATION=/usr/src/zksync/{record}", docker)
            self.assertIn(f"COPY --from=builder /usr/src/zksync/{record} "
                          "/usr/share/syscoin-prover/airbender-build-inputs.json", docker)
            self.assertRegex(release, rf'tar -czf [^\n]+\\\n[^\n]+{record}')
        self.assertIn(".cargo_exit_code == 0 and .inputs_reverified == true", release)
        self.assertIn("roleInputRecords: $airbender_records", release)
        self.assertIn("PROVER_SOURCE_DIR: ${{ github.workspace }}", release)

    @unittest.skipUnless(shutil.which("git"), "Git is required")
    def test_release_selected_lock_matches_git_blob_before_build_and_role_validation(self):
        release = (ROOT / ".github/workflows/release-bins.yml").read_text()
        guard = '[[ "$(git hash-object -- Cargo.lock)" == "$(git rev-parse HEAD:Cargo.lock)" ]]'
        self.assertEqual(release.count(guard), 2)
        build = release.index('AIRBENDER_BUILD_ATTESTATION="${PWD}/combined-airbender-build-inputs.json"')
        last_build = release.index('--bin "${ZKSYNC_OS_SNARK_PROVER_BIN}" --no-default-features')
        records = release.index('airbender_pins="$(python3 .release-tooling/')
        positions = [match.start() for match in re.finditer(re.escape(guard), release)]
        self.assertLess(positions[0], build)
        self.assertTrue(last_build < positions[1] < records)
        # Run the actual workflow guard against committed current and exact parent locks.
        # Unrelated dirty application files are deliberately not a lock-identity bypass.
        for raw in ((ROOT / "Cargo.lock").read_bytes(), LOCK_FIXTURE.parent_lock_bytes()):
            with self.subTest(lock=raw[:32]), tempfile.TemporaryDirectory() as temporary:
                repo = Path(temporary)
                (repo / "Cargo.lock").write_bytes(raw)
                (repo / "unrelated.txt").write_text("original\n")
                subprocess.run(["git", "init", "-q", str(repo)], check=True)
                subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
                subprocess.run(["git", "-C", str(repo), "-c", "user.name=Fixture",
                                "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture"], check=True)
                (repo / "unrelated.txt").write_text("unrelated dirty change\n")
                self.assertEqual(subprocess.run(["bash", "-c", guard], cwd=repo).returncode, 0)
                (repo / "Cargo.lock").write_bytes(raw + b"\n")
                self.assertNotEqual(subprocess.run(["bash", "-c", guard], cwd=repo).returncode, 0)

    def test_context_and_dockerinclude_the_exact_overlay_inputs(self):
        context = (ROOT / "docker/prepare-prover-image-context.sh").read_text()
        ignore = (ROOT / ".dockerignore").read_text().splitlines()
        stage = (ROOT / ".github/workflows/stage-build.yaml").read_text()
        release = (ROOT / ".github/workflows/release-bins.yml").read_text()
        for workflow in (stage, release):
            self.assertRegex(workflow, r"sparse-checkout: \|\n(?:[^\n]+\n)*?            scripts\n            patches")
        for path in OVERLAY_FILES:
            self.assertIn("    " + path + "\n", context)
            self.assertIn("!" + path, ignore)
            for _, image, _ in ROLES.values():
                self.assertIn(path, (ROOT / "docker" / image / "Dockerfile").read_text())
        for path in ("docker/install-build-toolchain.sh", ".github/actions/runner-setup/action.yaml"):
            text = (ROOT / path).read_text()
            self.assertIn("python3 python3-tomli", text)

    @unittest.skipUnless(shutil.which("git") and shutil.which("jq"), "Git and jq are required")
    def test_context_takes_overlay_from_tooling_not_older_application(self):
        # Real context composition and exact parent lock; no dependency downloads or builds.
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source, tooling = directory / "source", directory / "tooling"
            source.mkdir()
            tooling.mkdir()
            for name in ("Cargo.toml", "Cargo.lock", "multiblock_batch.bin", "multiblock_batch.text"):
                (source / name).write_text("synthetic context fixture\n")
            (source / "Cargo.lock").write_bytes(LOCK_FIXTURE.parent_lock_bytes())
            (source / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "nightly-2026-01-01"\n')
            (source / "crates").mkdir()
            (source / "crates/README").write_text("synthetic application fixture\n")
            for path in OVERLAY_FILES:
                (source / path).parent.mkdir(parents=True, exist_ok=True)
                (source / path).write_text("obsolete application tooling must not be copied\n")
            script = (ROOT / "docker/prepare-prover-image-context.sh").read_text()
            block = re.search(r"readonly tooling_files=\(\n(.*?)\n\)", script, re.S).group(1)
            for relative in block.split():
                target = tooling / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
            for repo in (source, tooling):
                subprocess.run(["git", "init", "-q", str(repo)], check=True)
                subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
                subprocess.run(["git", "-C", str(repo), "-c", "user.name=Fixture",
                                "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture"], check=True)
            output = directory / "context"
            command = ["bash", str(ROOT / "docker/prepare-prover-image-context.sh"),
                       str(source), str(tooling), str(output)]
            subprocess.run(command, check=True, capture_output=True, text=True)
            for relative in OVERLAY_FILES:
                self.assertEqual((output / relative).read_bytes(), (tooling / relative).read_bytes())
                self.assertNotEqual((output / relative).read_bytes(), (source / relative).read_bytes())
            self.assertEqual((output / "Cargo.lock").read_bytes(), (source / "Cargo.lock").read_bytes())
            # Invoke the wrapper's actual derivation from the composed tooling/source,
            # not just a file-copy assertion that misses old-tag lock incompatibility.
            spec = importlib.util.spec_from_file_location("context_wrapper", output / OVERLAY_FILES[1])
            wrapper = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(wrapper)
            reference_pins = json.loads((output / OVERLAY_FILES[3]).read_text())
            raw, selection = wrapper.selected_lock_overlay(
                output / "Cargo.lock", output / OVERLAY_FILES[4], reference_pins)
            self.assertEqual(len(wrapper.audit_lock(wrapper.read_toml(output / "Cargo.lock"),
                                                   wrapper.tomllib.loads(raw.decode()), reference_pins)), 46)
            self.assertNotEqual(selection["overlay_lock_sha256"], reference_pins["overlay_lock_sha256"])
            pins = json.loads((output / "docker/prover-build-pins.json").read_text())
            self.assertEqual(pins["rust_toolchain"], "nightly-2026-01-01")
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)


if __name__ == "__main__":
    unittest.main()
