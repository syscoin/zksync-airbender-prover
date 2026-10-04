#!/usr/bin/env python3
"""Run wrapper unit tests in an owning workspace with the attested source graph.

The wrapper's canonical lock retains its dev-dependencies and registry versions.
Only the reviewed Airbender/common-crypto Git identities become pinned paths in
a fresh copy. The successful application snapshot and source clones are inputs,
never the test workspace. No Cargo resolution or source update is permitted.
"""

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "patched_airbender", ROOT / "scripts/prepare-patched-airbender.py")
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
TEST_FILTERS = ("buffered_os_rng::tests", "wrapper::tests::precomputed_commitment")
WRAPPER_WORKSPACE_PACKAGES = {**BASE.WRAPPER_PACKAGES, "wrapper_generator": "0.1.0"}


def relative_path(value):
    path = Path(value)
    BASE.require(isinstance(value, str) and value and not path.is_absolute()
                 and ".." not in path.parts and str(path) == value,
                 "noncanonical input route")
    return path


def directory(value):
    path = Path(value)
    BASE.require(path.is_absolute() and path.is_dir() and not path.is_symlink()
                 and path.resolve() == path, "noncanonical source directory")
    return path


def authenticate(record, expected_label):
    BASE.require(record["schema_version"] == 1 and record["label"] == expected_label
                 and type(record["cargo_exit_code"]) is int and record["cargo_exit_code"] == 0
                 and record["inputs_reverified"] is True,
                 "application inputs lack a successful verified attestation")
    air, wrapper, crypto = (BASE.load_airbender_pins(), BASE.load_wrapper_pins(),
                            BASE.load_crypto_pins())
    BASE.require(record["pins"] == air, "attested Airbender differs from current pins")
    BASE.require(record["zkos_wrapper"]["inputs"] == BASE.wrapper_pins_metadata(),
                 "attested wrapper differs from current pins")
    BASE.require(record["zksync_crypto"]["inputs"] == BASE.crypto_pins_metadata(),
                 "attested common crypto differs from current pins")
    workspace = directory(record["workspace"])
    source = directory(record["application_source"])
    roots = {"air": directory(workspace.parent / "airbender"),
             "wrapper": directory(workspace.parent / "zkos-wrapper"),
             "crypto": directory(workspace.parent / "zksync-crypto")}
    BASE.verify_upstream(roots["air"], air)
    BASE.verify_wrapper(roots["wrapper"], wrapper)
    BASE.verify_crypto(roots["crypto"], crypto)
    for relative, digest in record["application_inputs_sha256"].items():
        route = relative_path(relative)
        BASE.checked_hash(source / route, digest)
        if relative not in {"Cargo.toml", "Cargo.lock"}:
            BASE.checked_hash(workspace / route, digest)
    overlay, selected = BASE.selected_lock_overlay(
        source / "Cargo.lock", BASE.PIN_PATH.parent / air["overlay_lock_file"],
        air, wrapper, crypto)
    BASE.require(selected == record["selected_lock"], "attested selected lock differs")
    BASE.checked_hash(workspace / "Cargo.lock", selected["overlay_lock_sha256"])
    BASE.require((workspace / "Cargo.lock").read_bytes() == overlay,
                 "application lock overlay differs")
    BASE.checked_hash(workspace / "Cargo.toml", record["workspace_manifest_sha256"])
    paths = {"air": BASE.package_paths(roots["air"], selected["airbender_packages"]),
             "wrapper": BASE.package_paths(roots["wrapper"], wrapper["upstream_packages"]),
             "crypto": BASE.package_paths(roots["crypto"], crypto["upstream_packages"])}
    BASE.require(paths["air"] == record["package_paths"]
                 and paths["wrapper"] == record["zkos_wrapper"]["package_paths"]
                 and paths["crypto"] == record["zksync_crypto"]["package_paths"],
                 "attested package routes differ")
    patches = {pins["upstream_url"]: {
        name: {"path": str(roots[group] / route)} for name, route in paths[group].items()}
        for group, pins in (("air", air), ("wrapper", wrapper), ("crypto", crypto))}
    manifest = BASE.read_toml(workspace / "Cargo.toml")
    BASE.require(manifest.get("patch") == patches and "replace" not in manifest,
                 "application proving patch graph differs")
    tooling = {str(path.relative_to(ROOT)) for path in (
        BASE.PIN_PATH, BASE.PIN_PATH.parent / air["patch_file"],
        BASE.PIN_PATH.parent / air["overlay_lock_file"], BASE.WRAPPER_PIN_PATH,
        BASE.WRAPPER_PIN_PATH.parent / wrapper["patch_file"], BASE.CRYPTO_PIN_PATH,
        BASE.CRYPTO_PIN_PATH.parent / crypto["patch_file"],
        ROOT / "scripts/prepare-patched-airbender.py", ROOT / "scripts/cargo-with-patched-airbender.sh")}
    BASE.require(set(record["tooling_sha256"]) == tooling, "incomplete attested tooling")
    for relative, digest in record["tooling_sha256"].items():
        BASE.checked_hash(ROOT / relative_path(relative), digest)
    target = Path(record["cargo_target_dir"])
    BASE.require(target.is_absolute(), "nonabsolute attested Cargo target")
    return workspace, roots, paths, selected, air, crypto, target


def lock_overlay(raw, selected, air, crypto):
    """Preserve the wrapper lock byte-for-byte except exact Git source lines."""
    canonical = BASE.tomllib.loads(raw.decode("utf-8"))
    expected = copy.deepcopy(canonical)
    air_packages = {name: version for name, version in selected["airbender_packages"].items()
                    if name not in {"cli", "gpu_prover"}}
    crypto_packages = {name: version for name, version in crypto["upstream_packages"].items()
                       if name != "zksync_solidity_vk_codegen"}
    BASE.require(len(air_packages) == 44 and len(crypto_packages) == 10,
                 "unknown wrapper proving package closure")
    groups = ((air["upstream_lock_source"], air_packages),
              (crypto["upstream_lock_source"], crypto_packages))
    reviewed = {name: (source, version) for source, packages in groups
                for name, version in packages.items()}
    blocks = re.split(rb"(?m)(?=^\[\[package\]\]\r?$)", raw)
    BASE.require(len(blocks) == len(canonical["package"]) + 1,
                 "unexpected wrapper lock package layout")
    found = set()
    local = {}
    for index, package in enumerate(expected["package"], 1):
        name, version = package["name"], package["version"]
        source = package.get("source", "")
        if name in reviewed:
            wanted_source, wanted_version = reviewed[name]
            BASE.require(name not in found and source == wanted_source and version == wanted_version,
                         "mixed/unpatched wrapper proving source or version")
            found.add(name)
            lines = blocks[index].splitlines(keepends=True)
            assignment = ("source = " + json.dumps(source)).encode()
            matches = [i for i, line in enumerate(lines) if line.rstrip(b"\r\n") == assignment]
            BASE.require(len(matches) == 1, "unexpected wrapper proving source assignment")
            del lines[matches[0]]
            blocks[index] = b"".join(lines)
            del package["source"]
        else:
            BASE.require(not any(origin in source for origin in (
                "github.com/matter-labs/zksync-airbender", "github.com/matter-labs/zkos-wrapper",
                "github.com/matter-labs/zksync-crypto.git")), "unknown wrapper proving source")
        if not source:
            BASE.require(name not in local, "duplicate wrapper workspace package")
            local[name] = version
        for edge in package.get("dependencies", []):
            BASE.require(not any(origin in edge for origin in (
                "github.com/matter-labs/zksync-airbender", "github.com/matter-labs/zksync-crypto.git")),
                "qualified proving dependency edge requires review")
    BASE.require(found == set(reviewed), "partial wrapper proving source graph")
    BASE.require(local == WRAPPER_WORKSPACE_PACKAGES, "unknown wrapper workspace package graph")
    result = b"".join(blocks)
    BASE.require(BASE.tomllib.loads(result.decode("utf-8")) == expected,
                 "wrapper lock overlay changed dependency inputs")
    return result, {"air": air_packages, "crypto": crypto_packages}


def copy_wrapper(source, destination):
    tracked = subprocess.check_output(["git", "-C", str(source), "ls-files", "-z"])
    files = [relative_path(row.decode("utf-8")) for row in tracked.split(b"\0") if row]
    BASE.require(files and len(set(files)) == len(files), "invalid tracked wrapper input list")
    for route in files:
        origin = source / route
        BASE.require(not any(part in {".git", "target"} for part in route.parts)
                     and origin.is_file() and not origin.is_symlink()
                     and origin.resolve().is_relative_to(source), "nonregular tracked wrapper input")
        output = destination / route
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(origin, output)
        BASE.checked_hash(output, BASE.sha256(origin))


def snapshot(directory):
    result = {}
    for path in directory.rglob("*"):
        BASE.require(not path.is_symlink(), "symlink in wrapper test workspace")
        if path.is_file():
            result[str(path.relative_to(directory))] = BASE.sha256(path)
    return result


def metadata_graph(metadata, workspace, roots, paths, groups):
    own_paths = BASE.package_paths(roots["wrapper"], WRAPPER_WORKSPACE_PACKAGES)
    expected = {name: (groups[group][name], roots[group] / paths[group][name] / "Cargo.toml")
                for group in ("air", "crypto") for name in groups[group]}
    expected.update({name: (WRAPPER_WORKSPACE_PACKAGES[name], workspace / route / "Cargo.toml")
                     for name, route in own_paths.items()})
    BASE.require(Path(metadata["workspace_root"]) == workspace, "wrong wrapper test workspace")
    found = {}
    for package in metadata["packages"]:
        name = package["name"]
        if name in expected:
            version, manifest = expected[name]
            BASE.require(name not in found and package["version"] == version
                         and package["source"] is None and Path(package["manifest_path"]) == manifest,
                         "Cargo resolved an unpatched/duplicate proving package")
            found[name] = package["id"]
        else:
            BASE.require(not any(origin in (package.get("source") or "") for origin in (
                "github.com/matter-labs/zksync-airbender", "github.com/matter-labs/zkos-wrapper",
                "github.com/matter-labs/zksync-crypto.git")), "Cargo resolved an unknown proving package")
    # Cargo omits the inactive GPU-only fflonk package from CPU metadata. Its
    # pinned path patch and exact lock identity remain mandatory in the owning
    # manifest/lock; if emitted, the path/version/source checks above still apply.
    BASE.require(set(expected) - set(found) <= {"fflonk"},
                 "Cargo resolved a partial required CPU proving graph")
    BASE.require(set(metadata["workspace_members"]) == {found[name] for name in own_paths},
                 "Cargo wrapper workspace ownership differs")
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    features = set(nodes[found["zkos-wrapper"]]["features"])
    BASE.require("security_100" in features and not features.intersection({"gpu", "security_80"}),
                 "wrapper tests must use CPU security_100")


def run(record_path, expected_label="ci-test"):
    record_path = record_path.resolve(strict=True)
    record_hash = BASE.sha256(record_path)
    record = BASE.json_document(record_path)
    workspace, roots, paths, selected, air, crypto, target = authenticate(record, expected_label)
    raw = (roots["wrapper"] / "Cargo.lock").read_bytes()
    overlay, groups = lock_overlay(raw, selected, air, crypto)
    build = Path(tempfile.mkdtemp(prefix="wrapper-unit-tests-", dir=workspace.parent))
    test_workspace = build / "zkos-wrapper"
    test_workspace.mkdir()
    copy_wrapper(roots["wrapper"], test_workspace)
    manifest = test_workspace / "Cargo.toml"
    BASE.require(not any(key in BASE.read_toml(manifest) for key in ("patch", "replace")),
                 "wrapper already has dependency overrides")
    with manifest.open("a", encoding="utf-8") as output:
        for group, pins in (("air", air), ("crypto", crypto)):
            output.write("\n[patch." + json.dumps(pins["upstream_url"]) + "]\n")
            for name in sorted(groups[group]):
                output.write(json.dumps(name) + " = { path = "
                             + json.dumps(str(roots[group] / paths[group][name])) + " }\n")
    (test_workspace / "Cargo.lock").write_bytes(overlay)
    copied_inputs = snapshot(test_workspace)
    BASE.write_json_exclusive(build / "test-inputs.json", {
        "schema_version": 1, "application_attestation": str(record_path),
        "application_attestation_sha256": record_hash, "workspace": str(test_workspace),
        "canonical_wrapper_lock_sha256": hashlib.sha256(raw).hexdigest(),
        "overlay_wrapper_lock_sha256": hashlib.sha256(overlay).hexdigest(),
        "proving_packages": groups, "test_inputs_sha256": copied_inputs,
        "cargo_target_dir": str(target), "test_filters": TEST_FILTERS})
    print(f"Pinned wrapper test inputs: {build / 'test-inputs.json'}", flush=True)
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(target)
    env.setdefault("RUST_MIN_STACK", "33554432")
    env.setdefault("CARGO_PROFILE_DEV_DEBUG", "0")
    status = 0
    try:
        result = subprocess.run([
            "cargo", "metadata", "--manifest-path", str(manifest), "--locked",
            "--format-version", "1", "--no-default-features", "--features", "zkos-wrapper/security_100"],
            cwd=test_workspace, env=env, text=True, capture_output=True)
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="")
        status = result.returncode
        if status == 0:
            metadata_graph(json.loads(result.stdout), test_workspace, roots, paths, groups)
            for test_filter in TEST_FILTERS:
                status = subprocess.run([
                    "cargo", "test", "--manifest-path", str(manifest), "--locked",
                    "-p", "zkos-wrapper", "--lib", "--no-default-features",
                    "--features", "security_100", test_filter], cwd=test_workspace, env=env).returncode
                if status:
                    break
    finally:
        BASE.checked_hash(record_path, record_hash)
        authenticate(record, expected_label)
        BASE.require(snapshot(test_workspace) == copied_inputs,
                     "wrapper test source, manifest or lock changed after Cargo")
    return status


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attestation", type=Path)
    parser.add_argument("--expected-label", default="ci-test",
                        help="local qualification label; CI requires the default ci-test label")
    args = parser.parse_args(argv)
    return run(args.attestation, args.expected_label)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        print(f"Pinned wrapper tests failed: {error}", file=sys.stderr)
        sys.exit(1)
