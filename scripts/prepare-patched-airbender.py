#!/usr/bin/env python3
"""Build with reviewed Airbender and zkos-wrapper patches without altering source checkouts.

Usage: cargo-with-patched-airbender.sh LABEL -- cargo build|test|run|check|clippy|metadata|tree --locked ...
PROVER_SOURCE_DIR separates reviewed tooling from application source in release CI.
AIRBENDER_SOURCE_DIR optionally supplies a local Git clone (never modified).
ZKOS_WRAPPER_SOURCE_DIR optionally supplies the exact pinned wrapper Git clone.
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
WRAPPER_PIN_PATH = TOOLING_ROOT / "patches/zkos-wrapper-buffered-os-rng.json"
SOURCE_FILES = ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml",
                "multiblock_batch.bin", "multiblock_batch.text")
ALLOWED_COMMANDS = {"build", "test", "run", "check", "clippy", "metadata", "tree"}
WRAPPER_UPSTREAM = (
    "https://github.com/matter-labs/zkos-wrapper.git",
    "585595f145cb53a09a130706ca36f80ddcac3961",
    "8c6e6a2ac3fa86708864c740d582ca30afe6851f",
)
WRAPPER_LOCK_SOURCE = (
    "git+https://github.com/matter-labs/zkos-wrapper.git?tag=v0.6.0-rc.2"
    "#585595f145cb53a09a130706ca36f80ddcac3961"
)
WRAPPER_PACKAGES = {"circuit_mersenne_field": "0.1.0", "zkos-wrapper": "0.1.0"}
WRAPPER_CHANGED_PATHS = {
    "wrapper/src/buffered_os_rng.rs", "wrapper/src/gpu/snark.rs", "wrapper/src/lib.rs",
    "wrapper/src/wrapper/mod.rs",
}
WRAPPER_PATCHED_TREE = "b2081f4c987e22043f31ca5a9656f2a1655b06c3"


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


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def json_document(path):
    require(path.is_file() and not path.is_symlink(), "invalid JSON input: " + str(path))
    return json.loads(path.read_text(), object_pairs_hook=unique_object)


def load_wrapper_pins(path=WRAPPER_PIN_PATH):
    pins = json_document(path)
    require(set(pins) == {"schema_version", "upstream_url", "upstream_commit", "upstream_tree",
            "upstream_lock_source", "upstream_packages", "patch_file", "patch_sha256",
            "changed_files", "patched_tree", "purpose"}, "unknown wrapper pin fields")
    require(pins["schema_version"] == 1 and type(pins["schema_version"]) is int,
            "unsupported wrapper pin schema")
    require(tuple(pins[k] for k in ("upstream_url", "upstream_commit", "upstream_tree"))
            == WRAPPER_UPSTREAM, "unknown wrapper upstream origin")
    require(pins["upstream_lock_source"] == WRAPPER_LOCK_SOURCE,
            "unknown wrapper lock source")
    require(pins["upstream_packages"] == WRAPPER_PACKAGES,
            "unknown wrapper package graph")
    require(pins["patch_file"] == "zkos-wrapper-buffered-os-rng.patch"
            and re.fullmatch(r"[0-9a-f]{64}", pins["patch_sha256"])
            and pins["patch_sha256"] != "0" * 64, "invalid wrapper patch identity")
    checked_hash(path.parent / pins["patch_file"], pins["patch_sha256"])
    require(pins["patched_tree"] == WRAPPER_PATCHED_TREE, "unknown wrapper patched tree")
    require(isinstance(pins["changed_files"], dict)
            and set(pins["changed_files"]) == WRAPPER_CHANGED_PATHS,
            "unknown wrapper source closure")
    for relative, row in pins["changed_files"].items():
        require(not Path(relative).is_absolute() and ".." not in Path(relative).parts
                and str(Path(relative)) == relative, "noncanonical wrapper source route")
        require(set(row) == {"preimage_sha256", "postimage_sha256", "postimage_size"},
                "unknown wrapper source fields")
        is_new = relative == "wrapper/src/buffered_os_rng.rs"
        require((row["preimage_sha256"] is None) == is_new, "invalid wrapper new-file preimage")
        require(is_new or isinstance(row["preimage_sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", row["preimage_sha256"])
                and row["preimage_sha256"] != "0" * 64, "invalid wrapper preimage")
        require(isinstance(row["postimage_sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", row["postimage_sha256"])
                and row["postimage_sha256"] != "0" * 64
                and type(row["postimage_size"]) is int and row["postimage_size"] > 0,
                "invalid wrapper postimage")
    require(isinstance(pins["purpose"], str) and pins["purpose"], "missing wrapper purpose")
    return pins


def wrapper_pins_metadata(path=WRAPPER_PIN_PATH):
    return {"manifest_sha256": sha256(path), "pins": load_wrapper_pins(path)}


def run_git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def audit_lock(canonical, overlay, pins, wrapper_pins=None):
    """Allow only reviewed Git-to-path identity changes for Airbender and wrapper crates."""
    wrapper_pins = wrapper_pins or load_wrapper_pins()
    expected = copy.deepcopy(canonical)
    packages = []
    wrapper_packages = {}
    for package in expected["package"]:
        source = package.get("source", "")
        if "github.com/matter-labs/zksync-airbender" in source:
            require(source == pins["upstream_lock_source"], "mixed Airbender sources in lock")
            packages.append((package["name"], package["version"]))
            del package["source"]
        elif "github.com/matter-labs/zkos-wrapper" in source:
            require(source == wrapper_pins["upstream_lock_source"],
                    "mixed wrapper sources in lock")
            name, version = package["name"], package["version"]
            require(name not in wrapper_packages and wrapper_pins["upstream_packages"].get(name) == version,
                    "unknown wrapper package/version")
            wrapper_packages[name] = version
            del package["source"]
    require(len(packages) == pins["upstream_package_count"], "unexpected Airbender package count")
    require(len({name for name, _ in packages}) == len(packages), "duplicate Airbender package name")
    require(wrapper_packages == wrapper_pins["upstream_packages"],
            "incomplete wrapper package graph")
    require(expected == overlay,
            "lock overlay changes more than Airbender/wrapper source identities")
    return dict(packages)


def selected_lock_overlay(source_lock, reference_overlay, pins, wrapper_pins=None):
    """Derive only the reviewed source-identity substitution from the selected lock.

    The checked-in overlay remains an immutable tooling reference, not a replacement
    for another compatible application's dependency graph. No Cargo resolution occurs.
    """
    wrapper_pins = wrapper_pins or load_wrapper_pins()
    require(source_lock.is_file() and not source_lock.is_symlink(), "invalid selected Cargo.lock")
    checked_hash(reference_overlay, pins["overlay_lock_sha256"])
    raw = source_lock.read_bytes()
    canonical = tomllib.loads(raw.decode("utf-8"))
    reference = read_toml(reference_overlay)
    blocks = re.split(rb"(?m)(?=^\[\[package\]\]\r?$)", raw)
    require(len(blocks) == len(canonical["package"]) + 1, "unexpected lock package layout")
    for index, package in enumerate(canonical["package"], 1):
        source = package.get("source", "")
        airbender = "github.com/matter-labs/zksync-airbender" in source
        wrapper = "github.com/matter-labs/zkos-wrapper" in source
        if not airbender and not wrapper:
            continue
        if airbender:
            require(source == pins["upstream_lock_source"], "mixed Airbender sources in lock")
        else:
            require(source == wrapper_pins["upstream_lock_source"], "mixed wrapper sources in lock")
            require(wrapper_pins["upstream_packages"].get(package["name"]) == package["version"],
                    "unknown wrapper package/version")
        lines = blocks[index].splitlines(keepends=True)
        # Cargo emits this simple quoted source assignment. Refuse alternate layouts
        # instead of guessing which bytes to remove from an application lock.
        expected_line = ("source = " + json.dumps(source)).encode()
        matches = [i for i, line in enumerate(lines) if line.rstrip(b"\r\n") == expected_line]
        require(len(matches) == 1, "unexpected reviewed-source assignment")
        del lines[matches[0]]
        blocks[index] = b"".join(lines)
    overlay_raw = b"".join(blocks)
    packages = audit_lock(canonical, tomllib.loads(overlay_raw.decode("utf-8")), pins, wrapper_pins)
    for name, version in packages.items():
        matches = [item for item in reference["package"]
                   if item["name"] == name and item["version"] == version and "source" not in item]
        require(len(matches) == 1, "selected Airbender package differs from tooling reference")
    for name, version in wrapper_pins["upstream_packages"].items():
        matches = [item for item in reference["package"]
                   if item["name"] == name and item["version"] == version and "source" not in item]
        require(len(matches) == 1, "selected wrapper package differs from tooling reference")
    selection = {
        "schema_version": 2, "derivation": "airbender-wrapper-source-identity-only-v2",
        "canonical_lock_sha256": hashlib.sha256(raw).hexdigest(),
        "overlay_lock_sha256": hashlib.sha256(overlay_raw).hexdigest(),
        "airbender_packages": packages,
        "zkos_wrapper_packages": wrapper_pins["upstream_packages"],
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


def require_airbender_only(source, argv, explicit_cpu=False):
    """Reject GPU wrapping in this lane, using the selected source's features.

    This is a conservative, pure Cargo-selection guard, not a second resolver.
    Unknown selectors/feature routes fail closed before source materialization.
    FRI GPU and explicit CPU CI remain valid; GPU wrapping requires --gpu32.
    """
    cargo_command(argv, Path("placeholder/Cargo.toml"))
    root = read_toml(source / "Cargo.toml")
    members = root.get("workspace", {}).get("members", [])
    require(all(isinstance(p, str) and not any(c in p for c in "*?[") for p in members),
            "ambiguous workspace selection; use a reviewed --gpu32 build")
    manifests, directories = {}, {}
    for relative in (["."] if "package" in root else []) + members:
        directory = source / relative
        require(directory.resolve().is_relative_to(source.resolve()) and not directory.is_symlink(),
                "noncanonical selected package")
        manifest = read_toml(directory / "Cargo.toml")
        name = manifest["package"]["name"]
        require(name not in manifests, "duplicate selected package")
        manifests[name], directories[directory.resolve()] = manifest, name
    require(manifests, "missing selected workspace packages")
    options = argv[2:argv.index("--")] if "--" in argv else argv[2:]
    packages, excluded, features, bins = [], [], [], []
    workspace = no_default = all_features = False
    index = 0
    while index < len(options):
        arg = options[index]
        field = None
        for short, long, target in (("-p", "--package", packages), ("-F", "--features", features),
                                    (None, "--exclude", excluded), (None, "--bin", bins)):
            if arg == short or arg == long:
                index += 1
                require(index < len(options), "missing Cargo selection value")
                field = (target, options[index])
                break
            if arg.startswith(long + "="):
                field = (target, arg[len(long) + 1:])
                break
            if short and arg.startswith(short) and len(arg) > len(short):
                field = (target, arg[len(short):])
                break
        if field:
            field[0].extend(re.split(r"[,\s]+", field[1]) if field[0] is features else [field[1]])
        elif arg == "--workspace":
            workspace = True
        elif arg == "--all":
            require(False, "deprecated --all selector is unsupported; use --workspace")
        elif arg == "--no-default-features":
            no_default = True
        elif arg == "--all-features":
            all_features = True
        elif arg.startswith(("--package", "--features", "--exclude", "--bin=", "--workspace=",
                             "--no-default-features=", "--all-features=")):
            require(False, "ambiguous Cargo selection flag")
        index += 1
    require(not (workspace and packages), "ambiguous Cargo workspace/package selection")
    require(all(p in manifests for p in packages + excluded), "unknown Cargo package selector")
    require(not excluded or workspace, "Cargo exclusions require --workspace")
    if packages:
        selected = set(packages)
    elif workspace:
        selected = set(manifests)
    elif "package" in root:
        selected = {root["package"]["name"]}
    else:
        defaults = root.get("workspace", {}).get("default-members", members)
        require(all((source / p).resolve() in directories for p in defaults), "unknown default workspace member")
        selected = {directories[(source / p).resolve()] for p in defaults}
    selected -= set(excluded)
    if bins:
        matching = set()
        for binary in bins:
            choices = {name for name in selected if binary in
                       {entry["name"] for entry in manifests[name].get("bin", [])}
                       or binary == name and manifests[name].get("package", {}).get("autobins", True)
                       and any((path / "src/main.rs").is_file() for path, value in directories.items() if value == name)}
            require(len(choices) == 1, "ambiguous Cargo binary selector")
            matching.update(choices)
        # --bin selects targets, not the package/feature scope. Keep all selected
        # packages in the feature audit; only -p/--package narrows that scope.
    require(selected, "empty Cargo package selection")
    workspace_dependencies = root.get("workspace", {}).get("dependencies", {})

    def dependencies(name):
        result = {}
        for section in ("dependencies", "build-dependencies", "dev-dependencies"):
            for alias, value in manifests[name].get(section, {}).items():
                spec = {"version": value} if isinstance(value, str) else copy.deepcopy(value)
                if spec.pop("workspace", False):
                    inherited = workspace_dependencies[alias]
                    inherited = {"version": inherited} if isinstance(inherited, str) else copy.deepcopy(inherited)
                    if "path" in inherited and "path" not in spec:
                        inherited["_workspace_path"] = True
                    spec["features"] = inherited.get("features", []) + spec.get("features", [])
                    spec = {**inherited, **spec}
                require(alias not in result or result[alias] == spec,
                        "ambiguous dependency feature selection")
                result[alias] = spec
        # Target-specific feature forwarding cannot be guessed from the host.
        require(not manifests[name].get("target"), "target-specific dependencies need --gpu32 review")
        return result

    deps = {name: dependencies(name) for name in manifests}
    enabled, visited, active = set(), set(), set()

    def local_target(name, spec):
        if "path" not in spec:
            return None
        directory = next(path for path, value in directories.items() if value == name)
        target = ((source if spec.get("_workspace_path") else directory) / spec["path"]).resolve()
        require(target in directories, "unknown local dependency package")
        return directories[target]

    def activate_dependency(name, alias, feature=None):
        require(alias in deps[name], "unknown dependency feature route")
        spec = deps[name][alias]
        dependency_name = spec.get("package", alias)
        require(not (explicit_cpu and (feature == "gpu" or "gpu" in spec.get("features", []))),
                "--cpu conflicts with selected GPU features")
        require(not (dependency_name in {"zkos_wrapper", "zkos-wrapper"}
                     and (feature == "gpu" or "gpu" in spec.get("features", []))),
                "GPU wrapping requires --gpu32; CPU builds must disable GPU features")
        if dependency_name in {"zkos_wrapper", "zkos-wrapper"}:
            require(spec.get("default-features") is False, "ambiguous wrapper defaults require --gpu32")
        target = local_target(name, spec)
        if target:
            activate_package(target, spec.get("default-features", True))
            for item in spec.get("features", []):
                activate_feature(target, item)
            if feature:
                activate_feature(target, feature)

    def activate_feature(name, feature):
        pair = (name, feature)
        if pair in visited:
            return
        visited.add(pair)
        require(not (feature == "gpu" and name in {"zksync_os_snark_prover", "zksync_os_prover_service"}),
                "GPU wrapping requires --gpu32; CPU builds must disable GPU features")
        table = manifests[name].get("features", {})
        if feature not in table:
            require(feature in deps[name] and deps[name][feature].get("optional"), "unknown selected feature")
            activate_dependency(name, feature)
            return
        enabled.add(pair)
        for item in table[feature]:
            if item.startswith("dep:"):
                activate_dependency(name, item[4:])
            elif "/" in item:
                alias, child = item.split("/", 1)
                # Conditional optional-dependency forwarding is deliberately
                # conservative: rejecting a possible wrapping GPU is safer.
                activate_dependency(name, alias.rstrip("?"), child)
            else:
                activate_feature(name, item)

    def activate_package(name, defaults):
        if name not in active:
            active.add(name)
            for alias, spec in deps[name].items():
                if not spec.get("optional", False):
                    activate_dependency(name, alias)
        if defaults and "default" in manifests[name].get("features", {}):
            activate_feature(name, "default")

    for name in selected:
        activate_package(name, not no_default)
        if all_features:
            for feature in manifests[name].get("features", {}):
                activate_feature(name, feature)
    for feature in features:
        if "/" in feature:
            name, child = feature.split("/", 1)
            if name in manifests:
                require(name in selected, "feature selects an unselected workspace package")
                activate_feature(name, child)
            else:
                for package in selected:
                    activate_dependency(package, name, child)
        else:
            choices = [name for name in selected if feature in manifests[name].get("features", {})
                       or feature in deps[name] and deps[name][feature].get("optional")]
            require(choices, "unknown selected feature")
            for name in choices:
                activate_feature(name, feature)
    if explicit_cpu:
        require(not any(feature == "gpu" for _, feature in enabled),
                "--cpu conflicts with selected GPU features")


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
    require(set(paths) == set(expected), "incomplete reviewed package mapping")
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


def verify_wrapper(upstream, pins):
    require(run_git(upstream, "rev-parse", "HEAD") == pins["upstream_commit"],
            "wrapper HEAD changed")
    require(run_git(upstream, "rev-parse", "HEAD^{tree}") == pins["upstream_tree"],
            "wrapper upstream tree changed")
    require(run_git(upstream, "diff", "--name-only", "HEAD").splitlines()
            == sorted(pins["changed_files"]), "unexpected wrapper changed paths")
    require(not run_git(upstream, "ls-files", "--others", "--exclude-standard"),
            "unexpected wrapper untracked files")
    require(not run_git(upstream, "diff", "--name-only"),
            "wrapper changed after patch staging")
    require(run_git(upstream, "write-tree") == pins["patched_tree"],
            "wrapper patched tree mismatch")
    for relative, row in pins["changed_files"].items():
        path = upstream / relative
        checked_hash(path, row["postimage_sha256"])
        require(path.stat().st_size == row["postimage_size"],
                "wrapper postimage size mismatch")


def prepare_wrapper(build, pins):
    upstream = build / "zkos-wrapper"
    clone_source = os.environ.get("ZKOS_WRAPPER_SOURCE_DIR", pins["upstream_url"])
    if "ZKOS_WRAPPER_SOURCE_DIR" in os.environ:
        clone_source = str(Path(clone_source).resolve(strict=True))
        require(Path(clone_source).is_dir(), "ZKOS_WRAPPER_SOURCE_DIR must be a Git directory")
    subprocess.run(["git", "clone", "--quiet", "--no-checkout", "--no-hardlinks",
                    clone_source, str(upstream)], check=True)
    run_git(upstream, "checkout", "--quiet", "--detach", pins["upstream_commit"])
    require(run_git(upstream, "rev-parse", "HEAD^{tree}") == pins["upstream_tree"],
            "wrapper upstream tree mismatch")
    for relative, row in pins["changed_files"].items():
        path = upstream / relative
        if row["preimage_sha256"] is None:
            require(not path.exists() and not path.is_symlink(),
                    "wrapper new-file preimage already exists")
        else:
            checked_hash(path, row["preimage_sha256"])
    patch = WRAPPER_PIN_PATH.parent / pins["patch_file"]
    run_git(upstream, "apply", "--check", str(patch))
    run_git(upstream, "apply", str(patch))
    run_git(upstream, "add", "--", *sorted(pins["changed_files"]))
    verify_wrapper(upstream, pins)
    paths = package_paths(upstream, pins["upstream_packages"])
    return upstream, clone_source, paths


def write_json_exclusive(path, value):
    with path.open("x", encoding="utf-8") as destination:
        json.dump(value, destination, sort_keys=True, indent=2)
        destination.write("\n")


def main(argv):
    explicit_cpu = bool(argv and argv[0] == "--cpu")
    if explicit_cpu:
        argv = argv[1:]
    require(len(argv) >= 4 and argv[1] == "--", "usage: LABEL -- cargo COMMAND --locked ...")
    label = argv[0]
    require(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", label), "invalid build label")
    # Validate before cloning, copying, or creating any build directory.
    cargo_command(argv[2:], Path("placeholder/Cargo.toml"))
    source = Path(os.environ.get("PROVER_SOURCE_DIR", TOOLING_ROOT)).resolve(strict=True)
    require_airbender_only(source, argv[2:], explicit_cpu)
    pins = json.loads(PIN_PATH.read_text())
    wrapper_pins = load_wrapper_pins()
    wrapper_inputs = wrapper_pins_metadata()
    require(pins["schema_version"] == 1, "unsupported pin schema")
    patch = PIN_PATH.parent / pins["patch_file"]
    overlay = PIN_PATH.parent / pins["overlay_lock_file"]
    checked_hash(patch, pins["patch_sha256"])
    checked_hash(overlay, pins["overlay_lock_sha256"])
    overlay_raw, selected_lock = selected_lock_overlay(
        source / "Cargo.lock", overlay, pins, wrapper_pins)
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
    wrapper, wrapper_clone_source, wrapper_paths = prepare_wrapper(build, wrapper_pins)
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
        destination.write('\n[patch.' + json.dumps(wrapper_pins["upstream_url"]) + ']\n')
        for name, relative in wrapper_paths.items():
            destination.write(json.dumps(name) + " = { path = "
                              + json.dumps(str(wrapper / relative)) + " }\n")
    (workspace / "Cargo.lock").write_bytes(overlay_raw)
    record = {
        "schema_version": 1, "label": label, "pins": pins, "selected_lock": selected_lock,
        "zkos_wrapper": {
            "inputs": wrapper_inputs,
            "source": {"clone_source": wrapper_clone_source,
                       "upstream_commit": wrapper_pins["upstream_commit"],
                       "upstream_tree": wrapper_pins["upstream_tree"],
                       "patched_tree": wrapper_pins["patched_tree"]},
            "package_paths": wrapper_paths,
        },
        "tooling_sha256": {str(path.relative_to(TOOLING_ROOT)): sha256(path) for path in
                           (PIN_PATH, patch, overlay, WRAPPER_PIN_PATH,
                            WRAPPER_PIN_PATH.parent / wrapper_pins["patch_file"], Path(__file__).resolve(),
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
    print(f"Reviewed source-overlay build inputs: {build / 'build-inputs.json'}", file=sys.stderr, flush=True)
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
    verify_wrapper(wrapper, wrapper_pins)
    checked_hash(workspace / "Cargo.lock", selected_lock["overlay_lock_sha256"])
    checked_hash(manifest, record["workspace_manifest_sha256"])
    for relative, expected_hash in source_hashes.items():
        if relative not in {"Cargo.toml", "Cargo.lock"}:
            checked_hash(workspace / relative, expected_hash)
    for relative, expected_hash in record["tooling_sha256"].items():
        checked_hash(TOOLING_ROOT / relative, expected_hash)
    record["inputs_reverified"] = True
    write_json_exclusive(build / "build-result.json", record)
    if attestation:
        write_json_exclusive(attestation, record)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"reviewed source-overlay build failed: {error}", file=sys.stderr)
        sys.exit(1)
