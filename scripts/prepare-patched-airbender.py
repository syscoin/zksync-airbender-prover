#!/usr/bin/env python3
"""Build with one reviewed Airbender patch, without altering the original checkout.

Usage: cargo-with-patched-airbender.sh LABEL -- cargo build|test|run|check|clippy|metadata|tree --locked ...
PROVER_SOURCE_DIR separates reviewed tooling from application source in release CI.
AIRBENDER_SOURCE_DIR optionally supplies a local Git clone (never modified).
AIRBENDER_BUILD_ATTESTATION names a fresh absolute success-only JSON output.
The caller's working directory and absolute CARGO_TARGET_DIR are preserved. By
default artifacts stay in the application source's target directory. Fresh source
snapshots and build-inputs.json records remain under target/patched-airbender/.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

try:
    import tomllib
except ImportError:  # Ubuntu 22.04: installed by apt, never fetched with pip.
    import tomli as tomllib


TOOLING_ROOT = Path(__file__).resolve().parents[1]
PIN_PATH = TOOLING_ROOT / "patches/airbender-cuda-device-diagnostics.json"
SOURCE_FILES = ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml",
                "multiblock_batch.bin", "multiblock_batch.text")
ALLOWED_COMMANDS = {"build", "test", "run", "check", "clippy", "metadata", "tree"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def checked_hash(path, expected):
    require(path.is_file() and not path.is_symlink(), f"not a regular input: {path}")
    require(sha256(path) == expected, f"SHA-256 mismatch: {path}")


def read_toml(path):
    with path.open("rb") as source:
        return tomllib.load(source)


def run_git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def audit_lock(canonical, overlay, pins):
    """Allow only the reviewed Git-to-path identity change for every Airbender crate."""
    expected = copy.deepcopy(canonical)
    packages = []
    for package in expected["package"]:
        source = package.get("source", "")
        if "github.com/matter-labs/zksync-airbender" in source:
            require(source == pins["upstream_lock_source"], "mixed Airbender sources in lock")
            packages.append((package["name"], package["version"]))
            del package["source"]
    require(len(packages) == pins["upstream_package_count"], "unexpected Airbender package count")
    require(len({name for name, _ in packages}) == len(packages), "duplicate Airbender package name")
    require(expected == overlay, "lock overlay changes more than Airbender source identity")
    return dict(packages)


def selected_lock_overlay(source_lock, reference_overlay, pins):
    """Derive only the reviewed source-identity substitution from the selected lock.

    The checked-in overlay remains an immutable tooling reference, not a replacement
    for another compatible application's dependency graph. No Cargo resolution occurs.
    """
    require(source_lock.is_file() and not source_lock.is_symlink(), "invalid selected Cargo.lock")
    checked_hash(reference_overlay, pins["overlay_lock_sha256"])
    raw = source_lock.read_bytes()
    canonical = tomllib.loads(raw.decode("utf-8"))
    reference = read_toml(reference_overlay)
    blocks = re.split(rb"(?m)(?=^\[\[package\]\]\r?$)", raw)
    require(len(blocks) == len(canonical["package"]) + 1, "unexpected lock package layout")
    for index, package in enumerate(canonical["package"], 1):
        source = package.get("source", "")
        if "github.com/matter-labs/zksync-airbender" not in source:
            continue
        require(source == pins["upstream_lock_source"], "mixed Airbender sources in lock")
        lines = blocks[index].splitlines(keepends=True)
        # Cargo emits this simple quoted source assignment. Refuse alternate layouts
        # instead of guessing which bytes to remove from an application lock.
        expected_line = ("source = " + json.dumps(source)).encode()
        matches = [i for i, line in enumerate(lines) if line.rstrip(b"\r\n") == expected_line]
        require(len(matches) == 1, "unexpected Airbender source assignment")
        del lines[matches[0]]
        blocks[index] = b"".join(lines)
    overlay_raw = b"".join(blocks)
    packages = audit_lock(canonical, tomllib.loads(overlay_raw.decode("utf-8")), pins)
    for name, version in packages.items():
        matches = [item for item in reference["package"]
                   if item["name"] == name and item["version"] == version and "source" not in item]
        require(len(matches) == 1, "selected Airbender package differs from tooling reference")
    selection = {
        "schema_version": 1, "derivation": "airbender-source-identity-only-v1",
        "canonical_lock_sha256": hashlib.sha256(raw).hexdigest(),
        "overlay_lock_sha256": hashlib.sha256(overlay_raw).hexdigest(),
        "airbender_packages": packages,
    }
    return overlay_raw, selection


def cargo_command(argv, manifest):
    require(len(argv) >= 2 and argv[0] == "cargo" and argv[1] in ALLOWED_COMMANDS,
            "expected literal cargo build|test|run|check|clippy|metadata|tree")
    options = argv[2:argv.index("--")] if "--" in argv else argv[2:]
    require("--locked" in options or "--frozen" in options, "Cargo must use --locked or --frozen")
    require(not any(arg == "--manifest-path" or arg.startswith("--manifest-path=")
                    or arg == "--lockfile-path" or arg.startswith("--lockfile-path=")
                    or arg == "--config" or arg.startswith("--config=")
                    or arg == "--target-dir" or arg.startswith("--target-dir=") for arg in options),
            "manifest/lock/config/target overrides are not supported; use CARGO_TARGET_DIR")
    return [*argv[:2], "--manifest-path", str(manifest), *argv[2:]]


def copy_application(source, workspace):
    """Materialize only build inputs; reject links and retain every copied input hash."""
    files = [source / name for name in SOURCE_FILES]
    crates = source / "crates"
    require(crates.is_dir() and not crates.is_symlink(), "missing regular crates directory")
    for path in sorted(crates.rglob("*")):
        require(not path.is_symlink(), f"symlink in application source: {path}")
        if path.is_dir():
            require(path.name not in {"target", ".git"}, f"unexpected generated directory: {path}")
        else:
            files.append(path)
    # Cargo's per-repository configuration affects build inputs too, when present.
    config = source / ".cargo"
    if config.exists():
        require(config.is_dir() and not config.is_symlink(), "invalid .cargo directory")
        for path in sorted(config.rglob("*")):
            require(not path.is_symlink(), f"symlink in Cargo config: {path}")
            if not path.is_dir():
                files.append(path)
    hashes = {}
    for path in files:
        require(path.is_file() and not path.is_symlink(), f"not a regular application input: {path}")
        relative = path.relative_to(source)
        destination = workspace / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
        hashes[str(relative)] = sha256(destination)
    return hashes


def package_paths(upstream, expected):
    paths = {}
    root = read_toml(upstream / "Cargo.toml")
    for relative in run_git(upstream, "ls-files", "*Cargo.toml").splitlines():
        path = upstream / relative
        package = read_toml(path).get("package")
        if not package or package["name"] not in expected:
            continue
        name = package["name"]
        version = package["version"]
        if isinstance(version, dict) and version.get("workspace") is True:
            version = root["workspace"]["package"]["version"]
        require(version == expected[name], f"version mismatch for {name}")
        require(name not in paths, f"ambiguous package path for {name}")
        paths[name] = str(Path(relative).parent)
    require(set(paths) == set(expected), "incomplete Airbender package mapping")
    return dict(sorted(paths.items()))


def verify_upstream(upstream, pins):
    require(run_git(upstream, "rev-parse", "HEAD") == pins["upstream_commit"], "upstream HEAD changed")
    require(run_git(upstream, "diff", "--name-only", "HEAD") == pins["changed_path"],
            "unexpected upstream changed paths")
    require(not run_git(upstream, "ls-files", "--others", "--exclude-standard"),
            "unexpected upstream untracked files")
    require(not run_git(upstream, "diff", "--name-only"), "upstream changed after patch staging")
    require(run_git(upstream, "write-tree") == pins["patched_tree"], "patched tree mismatch")
    checked_hash(upstream / pins["changed_path"], pins["postimage_sha256"])


def write_json_exclusive(path, value):
    with path.open("x", encoding="utf-8") as destination:
        json.dump(value, destination, sort_keys=True, indent=2)
        destination.write("\n")


def main(argv):
    require(len(argv) >= 4 and argv[1] == "--", "usage: LABEL -- cargo COMMAND --locked ...")
    label = argv[0]
    require(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", label), "invalid build label")
    # Validate before cloning, copying, or creating any build directory.
    cargo_command(argv[2:], Path("placeholder/Cargo.toml"))
    source = Path(os.environ.get("PROVER_SOURCE_DIR", TOOLING_ROOT)).resolve(strict=True)
    pins = json.loads(PIN_PATH.read_text())
    require(pins["schema_version"] == 1, "unsupported pin schema")
    patch = PIN_PATH.parent / pins["patch_file"]
    overlay = PIN_PATH.parent / pins["overlay_lock_file"]
    checked_hash(patch, pins["patch_sha256"])
    checked_hash(overlay, pins["overlay_lock_sha256"])
    overlay_raw, selected_lock = selected_lock_overlay(source / "Cargo.lock", overlay, pins)
    expected = selected_lock["airbender_packages"]
    attestation = os.environ.get("AIRBENDER_BUILD_ATTESTATION")
    if attestation:
        attestation = Path(attestation)
        require(attestation.is_absolute() and attestation.parent.is_dir()
                and not attestation.exists() and not attestation.is_symlink(),
                "attestation must be a fresh absolute path with an existing parent")
    target = Path(os.environ.get("CARGO_TARGET_DIR", source / "target"))
    require(target.is_absolute(), "CARGO_TARGET_DIR must be absolute")
    build_parent = source / "target/patched-airbender"
    build_parent.mkdir(parents=True, exist_ok=True)
    build = Path(tempfile.mkdtemp(prefix=label + "-", dir=build_parent))
    workspace = build / "prover"
    workspace.mkdir()
    source_hashes = copy_application(source, workspace)
    checked_hash(workspace / "Cargo.lock", selected_lock["canonical_lock_sha256"])
    upstream = build / "airbender"
    clone_source = os.environ.get("AIRBENDER_SOURCE_DIR", pins["upstream_url"])
    if "AIRBENDER_SOURCE_DIR" in os.environ:
        clone_source = str(Path(clone_source).resolve(strict=True))
        require(Path(clone_source).is_dir(), "AIRBENDER_SOURCE_DIR must be a Git directory")
    subprocess.run(["git", "clone", "--quiet", "--no-checkout", "--no-hardlinks",
                    clone_source, str(upstream)], check=True)
    run_git(upstream, "checkout", "--quiet", "--detach", pins["upstream_commit"])
    require(run_git(upstream, "rev-parse", "HEAD^{tree}") == pins["upstream_tree"], "upstream tree mismatch")
    checked_hash(upstream / pins["changed_path"], pins["preimage_sha256"])
    run_git(upstream, "apply", "--check", str(patch))
    run_git(upstream, "apply", str(patch))
    run_git(upstream, "add", "--", pins["changed_path"])
    verify_upstream(upstream, pins)
    paths = package_paths(upstream, expected)
    manifest = workspace / "Cargo.toml"
    application_manifest = read_toml(manifest)
    require("patch" not in application_manifest and "replace" not in application_manifest,
            "application already has dependency overrides; review required")
    # All locked Airbender crates share this path graph. A gpu_prover-only patch
    # would create incompatible duplicate path/Git types through workspace deps.
    with manifest.open("a", encoding="utf-8") as destination:
        destination.write('\n[patch."' + pins["upstream_url"] + '"]\n')
        for name, relative in paths.items():
            destination.write(json.dumps(name) + " = { path = "
                              + json.dumps(str(upstream / relative)) + " }\n")
    (workspace / "Cargo.lock").write_bytes(overlay_raw)
    record = {
        "schema_version": 1, "label": label, "pins": pins, "selected_lock": selected_lock,
        "tooling_sha256": {str(path.relative_to(TOOLING_ROOT)): sha256(path) for path in
                           (PIN_PATH, patch, overlay, Path(__file__).resolve(),
                            TOOLING_ROOT / "scripts/cargo-with-patched-airbender.sh")},
        "application_source": str(source), "application_inputs_sha256": source_hashes,
        "workspace": str(workspace), "upstream_clone_source": clone_source,
        "package_paths": paths, "workspace_manifest_sha256": sha256(manifest),
        "cargo_target_dir": str(target), "caller_cwd": os.getcwd(),
        "build_environment": {name: os.environ[name] for name in (
            "RUSTUP_TOOLCHAIN", "RUSTUP_HOME", "CARGO_HOME", "CARGO_BUILD_JOBS",
            "CARGO_INCREMENTAL", "RUST_MIN_STACK", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS",
            "CUDAARCHS", "CUDA_HOME", "CUDACXX", "CMAKE", "BELLMAN_CUDA_DIR",
        ) if name in os.environ},
        "cargo_command": cargo_command(argv[2:], manifest),
        "rustc_version": subprocess.check_output(["rustc", "--version", "--verbose"], text=True).strip(),
        "cargo_version": subprocess.check_output(["cargo", "--version"], text=True).strip(),
        "started_unix": int(time.time()),
    }
    write_json_exclusive(build / "build-inputs.json", record)
    print(f"Patched Airbender build inputs: {build / 'build-inputs.json'}", file=sys.stderr, flush=True)
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(target)
    result = subprocess.run(record["cargo_command"], env=env)
    record["cargo_exit_code"] = result.returncode
    record["finished_unix"] = int(time.time())
    if result.returncode:
        record["inputs_reverified"] = False
        write_json_exclusive(build / "build-result.json", record)
        return result.returncode
    verify_upstream(upstream, pins)
    checked_hash(workspace / "Cargo.lock", selected_lock["overlay_lock_sha256"])
    checked_hash(manifest, record["workspace_manifest_sha256"])
    for relative, expected_hash in source_hashes.items():
        if relative not in {"Cargo.toml", "Cargo.lock"}:
            checked_hash(workspace / relative, expected_hash)
    record["inputs_reverified"] = True
    write_json_exclusive(build / "build-result.json", record)
    if attestation:
        write_json_exclusive(attestation, record)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"patched Airbender build failed: {error}", file=sys.stderr)
        sys.exit(1)
