#!/usr/bin/env python3
"""Apply the exact GPU32 source overlays without mutating shared Git checkouts.

LABEL -- cargo COMMAND --locked ... composes the existing selected-lock-aware
Airbender overlay with the reviewed GPU graph. --prepare-bellman ABS_FRESH_DIR
only creates an attested source tree; the caller builds its production library.
No CUDA tests, proof, service, or automatic CPU fallback is run by this helper.
"""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

try:
    import tomllib
except ImportError:
    import tomli as tomllib

TOOLING_ROOT = Path(__file__).resolve().parents[1]
PIN_PATH = TOOLING_ROOT / "patches/gpu32-memory.json"
SOURCE_RECORD = "syscoin-gpu-memory-source.json"
CRYPTO_PACKAGES = dict.fromkeys((
    "boojum-cuda", "era_cudart", "era_cudart_sys", "fflonk-cuda",
    "proof-compression", "shivini", "zksync-gpu-ffi", "zksync-gpu-prover",
), "0.156.0")
CRYPTO_EDGES = {
    "boojum-cuda": ["era_cudart", "era_cudart_sys"],
    "era_cudart": ["era_cudart_sys"],
    "shivini": ["era_cudart", "era_cudart_sys"],
    "zksync-gpu-ffi": ["era_cudart_sys"],
}
UPSTREAM = {
    "crypto": ("https://github.com/matter-labs/zksync-crypto-gpu.git",
               "845905b2aae49215e3d4ad0b71998b4a6b5abebf",
               "9284de2a103f6aa1a1cc8f9a9df30f8d6c5af20c"),
    "bellman": ("https://github.com/matter-labs/era-bellman-cuda.git",
                "d1fa8670ee84ec3477c6cc1c85a3554cfa5e0206",
                "fa1ab78c59f9cdba2fedf4a00813dcf1c4c92d5c"),
}
PATCHED_TREES = {"crypto": "8c754adf137ab81dd531100dc470f6c7d019920b",
                 "bellman": "6e403e5a75ed91ca75c0bec533dbc73f82541ce2"}
CHANGED_PATHS = {
    "crypto": {"crates/gpu-prover/src/cuda_bindings/context.rs",
               "crates/gpu-prover/src/setup_precomputations.rs", "crates/gpu-prover/src/proof.rs"},
    "bellman": {"src/ff.cu", "src/ff_kernels.cu", "src/ff_kernels.cuh", "src/msm.cu",
                "src/msm_memory_policy.cuh", "tests/msm_test.cu", "tests/msm_memory_policy_test.cpp",
                "tests/ff_memory_correctness.cu", "tests/ff_chunk_reference.py", "tests/msm_host_bases_test.cu"},
}


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
    require(path.is_file() and not path.is_symlink(), "nonregular input: " + str(path))
    require(sha256(path) == expected, "input digest mismatch: " + str(path))


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def document(path):
    require(path.is_file() and not path.is_symlink(), "invalid JSON input")
    return json.loads(path.read_text(), object_pairs_hook=unique_object)


def base_helper():
    path = TOOLING_ROOT / "scripts/prepare-patched-airbender.py"
    spec = importlib.util.spec_from_file_location("airbender_overlay", path)
    module = importlib.util.module_from_spec(spec)
    # Avoid untracked __pycache__ in independently verified sparse tooling trees.
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


def load_pins(manifest=PIN_PATH):
    pins = document(manifest)
    require(isinstance(pins, dict) and set(pins) == {"schema_version", "security_bits", "domain_log",
            "polynomial_slots", "crypto_packages", "crypto_dependency_edges", "crypto", "bellman"},
            "unknown GPU pin fields")
    require(pins.get("schema_version") == 1 and type(pins["schema_version"]) is int,
            "unsupported GPU pin schema")
    require((pins.get("security_bits"), pins.get("domain_log"), pins.get("polynomial_slots"))
            == (100, 25, 29) and all(type(pins[k]) is int for k in
                                   ("security_bits", "domain_log", "polynomial_slots")),
            "GPU security/domain/slot pins changed")
    require(pins.get("crypto_packages") == CRYPTO_PACKAGES
            and pins.get("crypto_dependency_edges") == CRYPTO_EDGES,
            "unknown GPU package graph")
    for kind, expected in UPSTREAM.items():
        backend = pins[kind]
        fields = {"upstream_url", "upstream_commit", "upstream_tree", "patched_tree", "patch_file",
                  "patch_sha256", "changed_files"}
        if kind == "crypto":
            fields.update({"upstream_lock_source", "upstream_edge_source"})
        require(isinstance(backend, dict) and set(backend) == fields, "unknown GPU backend fields")
        require(tuple(backend.get(k) for k in ("upstream_url", "upstream_commit", "upstream_tree"))
                == expected, "unknown GPU upstream origin")
        require(backend.get("patched_tree") == PATCHED_TREES[kind], "unknown GPU patched tree")
        require(backend.get("patch_file") == kind + "-gpu32-memory.patch",
                "unexpected GPU patch route")
        require(re.fullmatch(r"[0-9a-f]{64}", backend.get("patch_sha256", ""))
                and backend["patch_sha256"] != "0" * 64, "invalid GPU patch hash")
        checked_hash(manifest.parent / backend["patch_file"], backend["patch_sha256"])
        require(isinstance(backend.get("changed_files"), dict)
                and set(backend["changed_files"]) == CHANGED_PATHS[kind], "unknown GPU source closure")
        for relative, row in backend["changed_files"].items():
            require(not Path(relative).is_absolute() and ".." not in Path(relative).parts
                    and str(Path(relative)) == relative, "noncanonical GPU source route")
            require(set(row) == {"preimage_sha256", "postimage_sha256", "postimage_size"},
                    "unknown GPU source fields")
            for key in ("preimage_sha256", "postimage_sha256"):
                value = row[key]
                require(value is None and key == "preimage_sha256" or
                        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
                        and value != "0" * 64, "invalid GPU source digest")
            require(type(row["postimage_size"]) is int and row["postimage_size"] > 0,
                    "invalid GPU source size")
    crypto = pins["crypto"]
    require(crypto.get("upstream_lock_source") == "git+" + crypto["upstream_url"]
            + "?branch=oh_for_wrapper#" + crypto["upstream_commit"]
            and crypto.get("upstream_edge_source") == "git+" + crypto["upstream_url"]
            + "?branch=oh_for_wrapper", "unknown crypto lock origin")
    return pins


def crypto_lock_overlay(raw, pins):
    """Change only eight path identities, six exact edges and two Cargo pair orders."""
    original = tomllib.loads(raw.decode("utf-8"))
    expected = copy.deepcopy(original)
    seen, edges = {}, {}
    backend = pins["crypto"]
    for package in expected["package"]:
        source = package.get("source", "")
        if "github.com/matter-labs/zksync-crypto-gpu" not in source:
            continue
        require(source == backend["upstream_lock_source"], "mixed crypto GPU source")
        name = package["name"]
        require(name not in seen and CRYPTO_PACKAGES.get(name) == package["version"],
                "unknown crypto GPU package/version")
        seen[name] = package["version"]
        del package["source"]
        for index, edge in enumerate(package.get("dependencies", [])):
            if "github.com/matter-labs/zksync-crypto-gpu" not in edge:
                continue
            target = edge.split(" ")[0]
            require(target in CRYPTO_EDGES.get(name, []) and edge == target + " 0.156.0 ("
                    + backend["upstream_edge_source"] + ")", "unknown crypto GPU edge")
            require(target not in edges.setdefault(name, []), "duplicate crypto GPU edge")
            edges[name].append(target)
            package["dependencies"][index] = target + " 0.156.0"
    require(seen == CRYPTO_PACKAGES and edges == CRYPTO_EDGES,
            "incomplete crypto GPU package/edge mapping")
    source_line = ('source = "' + backend["upstream_lock_source"] + '"\n').encode()
    require(raw.count(source_line) == len(CRYPTO_PACKAGES), "unexpected crypto lock layout")
    result = raw.replace(source_line, b"")
    for target in ("era_cudart", "era_cudart_sys"):
        old = (target + " 0.156.0 (" + backend["upstream_edge_source"] + ")").encode()
        require(result.count(old) == sum(target in targets for targets in CRYPTO_EDGES.values()),
                "unexpected crypto edge layout")
        result = result.replace(old, (target + " 0.156.0").encode())
    parts = result.decode().split("\n[[package]]\n")
    require(len(parts) - 1 == len(expected["package"]), "unexpected lock package layout")
    for name in ("era_cudart", "era_cudart_sys"):
        indexes = [i for i, p in enumerate(expected["package"]) if p["name"] == name]
        require(len(indexes) == 2 and all(expected["package"][i]["version"] == "0.156.0" for i in indexes)
                and {expected["package"][i].get("source", "") for i in indexes}
                == {"", "registry+https://github.com/rust-lang/crates.io-index"},
                "unexpected CUDA path/registry identities")
        ordered = sorted(indexes, key=lambda i: expected["package"][i].get("source", ""))
        records = [expected["package"][i] for i in ordered]
        blocks = [parts[i + 1] for i in ordered]
        for destination, record, block in zip(indexes, records, blocks):
            expected["package"][destination] = record
            parts[destination + 1] = block
    result = "\n[[package]]\n".join(parts).encode()
    require(tomllib.loads(result.decode()) == expected, "unreviewed combined lock change")
    return result


def gpu_backend_pins(manifest, source_lock=None):
    """Pure SBOM metadata API; does not invoke Git, Cargo, CMake or a native module."""
    pins = load_pins(manifest)
    result = {"manifest_sha256": sha256(manifest), "pins": pins}
    if source_lock is not None:
        base = base_helper()
        air = document(base.PIN_PATH)
        raw, selected = base.selected_lock_overlay(
            source_lock, base.PIN_PATH.parent / air["overlay_lock_file"], air)
        combined = crypto_lock_overlay(raw, pins)
        result["selected_lock"] = {
            "derivation": "airbender-and-crypto-gpu-source-identity-only-v1",
            "canonical_lock_sha256": selected["canonical_lock_sha256"],
            "airbender_overlay_lock_sha256": selected["overlay_lock_sha256"],
            "combined_overlay_lock_sha256": hashlib.sha256(combined).hexdigest(),
            "airbender_packages": selected["airbender_packages"],
            "crypto_packages": CRYPTO_PACKAGES,
        }
    return result


def tracked_inventory(repo, base):
    result = {}
    for line in base.run_git(repo, "ls-files", "--stage").splitlines():
        entry, relative = line.split("\t", 1)
        mode, object_id, stage = entry.split()
        require(stage == "0", "unmerged GPU source input")
        if mode == "160000":
            # The Bellman test submodule is pinned but not needed for production.
            result[relative] = {"gitlink": object_id}
            continue
        path = repo / relative
        require(mode in {"100644", "100755"} and path.is_file() and not path.is_symlink(),
                "nonregular tracked GPU source")
        result[relative] = {"sha256": sha256(path), "size": path.stat().st_size,
                            "executable": bool(path.stat().st_mode & 0o111)}
    require(result, "empty GPU source inventory")
    return result


def verify_backend(repo, kind, pins, base, expected_inventory=None, record_allowed=False):
    backend = pins[kind]
    require(base.run_git(repo, "rev-parse", "HEAD") == backend["upstream_commit"]
            and base.run_git(repo, "rev-parse", "HEAD^{tree}") == backend["upstream_tree"],
            "GPU upstream origin changed")
    require(base.run_git(repo, "diff", "--name-only", "HEAD").splitlines()
            == sorted(backend["changed_files"]), "unexpected GPU changed paths")
    require(not base.run_git(repo, "diff", "--name-only"), "GPU source changed after staging")
    require(base.run_git(repo, "write-tree") == backend["patched_tree"], "GPU patched tree mismatch")
    others = base.run_git(repo, "ls-files", "--others", "--exclude-standard").splitlines()
    require(others == ([SOURCE_RECORD] if record_allowed else []), "unexpected GPU untracked source")
    for relative, row in backend["changed_files"].items():
        path = repo / relative
        checked_hash(path, row["postimage_sha256"])
        require(path.stat().st_size == row["postimage_size"], "GPU postimage size mismatch")
    inventory = tracked_inventory(repo, base)
    if expected_inventory is not None:
        require(inventory == expected_inventory, "GPU source inventory changed")
    return inventory


def prepare_backend(repo, kind, pins, base):
    require(repo.is_absolute() and repo.parent.is_dir() and not repo.exists() and not repo.is_symlink(),
            "GPU source destination must be a fresh absolute directory")
    backend = pins[kind]
    variable = "CRYPTO_GPU_SOURCE_DIR" if kind == "crypto" else "BELLMAN_SOURCE_DIR"
    clone = os.environ.get(variable, backend["upstream_url"])
    if variable in os.environ:
        clone = str(Path(clone).resolve(strict=True))
        require(Path(clone).is_dir(), "invalid local GPU clone source")
    subprocess.run(["git", "clone", "--quiet", "--no-checkout", "--no-hardlinks", clone, str(repo)], check=True)
    base.run_git(repo, "checkout", "--quiet", "--detach", backend["upstream_commit"])
    require(base.run_git(repo, "rev-parse", "HEAD^{tree}") == backend["upstream_tree"]
            and not base.run_git(repo, "status", "--porcelain"), "dirty/wrong GPU source baseline")
    for relative, row in backend["changed_files"].items():
        path = repo / relative
        if row["preimage_sha256"] is None:
            require(not path.exists() and not path.is_symlink(), "new GPU source already exists")
        else:
            checked_hash(path, row["preimage_sha256"])
    patch = PIN_PATH.parent / backend["patch_file"]
    base.run_git(repo, "apply", "--check", str(patch))
    base.run_git(repo, "apply", str(patch))
    base.run_git(repo, "add", "--", *sorted(backend["changed_files"]))
    inventory = verify_backend(repo, kind, pins, base)
    record = {
        "schema": "syscoin-gpu-memory-source-v1", "kind": kind,
        "manifest_sha256": sha256(PIN_PATH), "preparer_sha256": sha256(Path(__file__).resolve()),
        "upstream_commit": backend["upstream_commit"], "upstream_tree": backend["upstream_tree"],
        "patched_tree": base.run_git(repo, "write-tree"), "source_root": str(repo),
        "clone_source": clone, "tracked_inventory": inventory,
    }
    base.write_json_exclusive(repo / SOURCE_RECORD, record)
    verify_backend(repo, kind, pins, base, inventory, record_allowed=True)
    return record


def bellman_library(repo, pins, base):
    require(repo.is_absolute() and repo == repo.resolve(strict=True) and not repo.is_symlink(),
            "BELLMAN_CUDA_DIR must name the canonical prepared source root")
    record = document(repo / SOURCE_RECORD)
    require(isinstance(record, dict) and set(record) == {"schema", "kind", "source_root", "clone_source",
            "manifest_sha256", "preparer_sha256", "upstream_commit", "upstream_tree", "patched_tree",
            "tracked_inventory"}, "unknown Bellman source record fields")
    require(record.get("schema") == "syscoin-gpu-memory-source-v1" and record.get("kind") == "bellman"
            and record.get("source_root") == str(repo) and record.get("manifest_sha256") == sha256(PIN_PATH)
            and record.get("preparer_sha256") == sha256(Path(__file__).resolve())
            and record.get("upstream_commit") == pins["bellman"]["upstream_commit"]
            and record.get("upstream_tree") == pins["bellman"]["upstream_tree"],
            "Bellman source attestation mismatch")
    verify_backend(repo, "bellman", pins, base, record["tracked_inventory"], record_allowed=True)
    require(base.run_git(repo, "write-tree") == record["patched_tree"], "Bellman patched tree changed")
    for directory in (repo / "build", repo / "build/src"):
        require(directory.is_dir() and not directory.is_symlink(), "noncanonical Bellman build directory")
    cache = repo / "build/CMakeCache.txt"
    require(cache.is_file() and not cache.is_symlink(), "missing production CMake cache")
    settings = {}
    for line in cache.read_text().splitlines():
        match = re.fullmatch(r"([^#/:=]+):[^=]+=(.*)", line)
        if match:
            key, value = match.groups()
            require(key not in settings, "duplicate CMake cache setting")
            settings[key] = value
    require(settings.get("BUILD_TESTS") == "OFF" and settings.get("CMAKE_HOME_DIRECTORY") == str(repo),
            "Bellman must be a production BUILD_TESTS=OFF library from this source")
    architectures = settings.get("CMAKE_CUDA_ARCHITECTURES", "")
    require(re.fullmatch(r"[1-9][0-9]*(?:-(?:real|virtual))?(?:;[1-9][0-9]*(?:-(?:real|virtual))?)*", architectures),
            "invalid CMake CUDA architecture closure")
    require("CUDAARCHS" not in os.environ or os.environ["CUDAARCHS"] == architectures,
            "CMake CUDA architectures differ from Cargo build environment")
    library = repo / "build/src/libbellman-cuda.a"
    require(library.is_file() and not library.is_symlink() and library.stat().st_size > 0,
            "missing compiled production Bellman library (no automatic fallback build)")
    return {"source": record, "source_record_sha256": sha256(repo / SOURCE_RECORD),
            "library_path": str(library), "library_sha256": sha256(library), "library_size": library.stat().st_size,
            "cmake_cache_sha256": sha256(cache), "cuda_architectures": architectures}


def main(argv):
    pins = load_pins()
    base = base_helper()
    if len(argv) == 2 and argv[0] == "--prepare-bellman":
        prepare_backend(Path(argv[1]), "bellman", pins, base)
        return 0
    require(len(argv) >= 4 and argv[1] == "--", "usage: LABEL -- cargo COMMAND --locked ...")
    label = argv[0]
    require(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", label), "invalid build label")
    base.cargo_command(argv[2:], Path("placeholder/Cargo.toml"))
    source = Path(os.environ.get("PROVER_SOURCE_DIR", TOOLING_ROOT)).resolve(strict=True)
    air = document(base.PIN_PATH)
    patch = base.PIN_PATH.parent / air["patch_file"]
    base.checked_hash(patch, air["patch_sha256"])
    overlay_raw, selected_lock = base.selected_lock_overlay(
        source / "Cargo.lock", base.PIN_PATH.parent / air["overlay_lock_file"], air)
    combined = crypto_lock_overlay(overlay_raw, pins)
    metadata = gpu_backend_pins(PIN_PATH, source / "Cargo.lock")
    require(metadata["selected_lock"]["canonical_lock_sha256"] == selected_lock["canonical_lock_sha256"]
            and metadata["selected_lock"]["airbender_overlay_lock_sha256"] == selected_lock["overlay_lock_sha256"]
            and metadata["selected_lock"]["combined_overlay_lock_sha256"] == hashlib.sha256(combined).hexdigest(),
            "selected source lock changed during preparation")
    require("BELLMAN_CUDA_DIR" in os.environ, "GPU build requires prepared BELLMAN_CUDA_DIR")
    native_root = Path(os.environ["BELLMAN_CUDA_DIR"])
    native = bellman_library(native_root, pins, base)
    attestation = os.environ.get("AIRBENDER_BUILD_ATTESTATION")
    if attestation:
        attestation = Path(attestation)
        require(attestation.is_absolute() and attestation.parent.is_dir()
                and not attestation.exists() and not attestation.is_symlink(), "attestation must be a fresh absolute path")
    target = Path(os.environ.get("CARGO_TARGET_DIR", source / "target"))
    require(target.is_absolute(), "CARGO_TARGET_DIR must be absolute")
    parent = source / "target/patched-gpu-backends"
    parent.mkdir(parents=True, exist_ok=True)
    build = Path(tempfile.mkdtemp(prefix=label + "-", dir=parent))
    workspace = build / "prover"
    workspace.mkdir()
    source_hashes = base.copy_application(source, workspace)
    base.checked_hash(workspace / "Cargo.lock", selected_lock["canonical_lock_sha256"])
    upstream = build / "airbender"
    clone = os.environ.get("AIRBENDER_SOURCE_DIR", air["upstream_url"])
    if "AIRBENDER_SOURCE_DIR" in os.environ:
        clone = str(Path(clone).resolve(strict=True))
    subprocess.run(["git", "clone", "--quiet", "--no-checkout", "--no-hardlinks", clone, str(upstream)], check=True)
    base.run_git(upstream, "checkout", "--quiet", "--detach", air["upstream_commit"])
    require(base.run_git(upstream, "rev-parse", "HEAD^{tree}") == air["upstream_tree"], "Airbender tree mismatch")
    base.checked_hash(upstream / air["changed_path"], air["preimage_sha256"])
    base.run_git(upstream, "apply", "--check", str(patch))
    base.run_git(upstream, "apply", str(patch))
    base.run_git(upstream, "add", "--", air["changed_path"])
    base.verify_upstream(upstream, air)
    air_paths = base.package_paths(upstream, selected_lock["airbender_packages"])
    crypto = build / "crypto-gpu"
    crypto_record = prepare_backend(crypto, "crypto", pins, base)
    crypto_paths = base.package_paths(crypto, CRYPTO_PACKAGES)
    manifest = workspace / "Cargo.toml"
    application_manifest = base.read_toml(manifest)
    require("patch" not in application_manifest and "replace" not in application_manifest,
            "application dependency overrides need review")
    with manifest.open("a", encoding="utf-8") as destination:
        for url, root, paths in ((air["upstream_url"], upstream, air_paths),
                                 (pins["crypto"]["upstream_url"], crypto, crypto_paths)):
            destination.write('\n[patch.' + json.dumps(url) + ']\n')
            for name, relative in paths.items():
                destination.write(json.dumps(name) + " = { path = " + json.dumps(str(root / relative)) + " }\n")
    (workspace / "Cargo.lock").write_bytes(combined)
    tooling = (PIN_PATH, *(PIN_PATH.parent / pins[k]["patch_file"] for k in ("crypto", "bellman")),
               base.PIN_PATH, patch, base.PIN_PATH.parent / air["overlay_lock_file"],
               Path(__file__).resolve(), TOOLING_ROOT / "scripts/prepare-patched-airbender.py",
               TOOLING_ROOT / "scripts/cargo-with-patched-airbender.sh")
    record = {
        "schema_version": 1, "label": label, "pins": air, "selected_lock": selected_lock,
        "gpu_backend_overlay": {"inputs": metadata, "crypto_source": crypto_record, "bellman_native": native},
        "tooling_sha256": {str(p.relative_to(TOOLING_ROOT)): sha256(p) for p in tooling},
        "application_source": str(source), "application_inputs_sha256": source_hashes,
        "workspace": str(workspace), "upstream_clone_source": clone, "package_paths": air_paths,
        "crypto_package_paths": crypto_paths, "workspace_manifest_sha256": sha256(manifest),
        "cargo_target_dir": str(target), "caller_cwd": os.getcwd(),
        "build_environment": {name: os.environ[name] for name in (
            "RUSTUP_TOOLCHAIN", "RUSTUP_HOME", "CARGO_HOME", "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL",
            "RUST_MIN_STACK", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CUDAARCHS", "CUDA_HOME", "CUDACXX", "CMAKE",
            "BELLMAN_CUDA_DIR") if name in os.environ},
        "cargo_command": base.cargo_command(argv[2:], manifest),
        "rustc_version": subprocess.check_output(["rustc", "--version", "--verbose"], text=True).strip(),
        "cargo_version": subprocess.check_output(["cargo", "--version"], text=True).strip(),
        "started_unix": int(time.time()),
    }
    base.write_json_exclusive(build / "build-inputs.json", record)
    print("Patched GPU build inputs: " + str(build / "build-inputs.json"), file=sys.stderr, flush=True)
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(target)
    result = subprocess.run(record["cargo_command"], env=env)
    record["cargo_exit_code"] = result.returncode
    record["finished_unix"] = int(time.time())
    if result.returncode:
        record["inputs_reverified"] = False
        base.write_json_exclusive(build / "build-result.json", record)
        return result.returncode
    base.verify_upstream(upstream, air)
    verify_backend(crypto, "crypto", pins, base, crypto_record["tracked_inventory"], record_allowed=True)
    require(bellman_library(native_root, pins, base) == native, "Bellman native/source closure changed")
    base.checked_hash(workspace / "Cargo.lock", metadata["selected_lock"]["combined_overlay_lock_sha256"])
    base.checked_hash(manifest, record["workspace_manifest_sha256"])
    for relative, digest in source_hashes.items():
        if relative not in {"Cargo.toml", "Cargo.lock"}:
            base.checked_hash(workspace / relative, digest)
    for relative, digest in record["tooling_sha256"].items():
        checked_hash(TOOLING_ROOT / relative, digest)
    record["inputs_reverified"] = True
    base.write_json_exclusive(build / "build-result.json", record)
    if attestation:
        base.write_json_exclusive(attestation, record)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print("patched GPU build failed: " + str(error), file=sys.stderr)
        sys.exit(1)
