#!/usr/bin/env python3
"""Build the V2 worker from the locked, unified Airbender and wrapper/crypto Git graph."""
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "scripts/prepare-patched-airbender.py"
spec = importlib.util.spec_from_file_location("source_tools", BASE)
base = importlib.util.module_from_spec(spec)
exec(compile(BASE.read_bytes(), str(BASE), "exec"), base.__dict__)

PIN_FILE = Path("patches/v2-proving-sources.json")
REQUIRED = {
    "airbender": {"cli", "execution_utils", "verifier_common", "riscv_transpiler", "prover"},
    "protocol": {"zkos-wrapper", "boojum", "zksync_bellman", "snark_wrapper", "zksync_solidity_vk_codegen"},
}


def check_checkout(directory, pin):
    git = ["git", "-C", str(directory)]
    for name, selector in (("commit", "HEAD"), ("tree", "HEAD^{tree}")):
        actual = subprocess.check_output([*git, "rev-parse", selector], text=True).strip()
        base.require(actual == pin[name], f"{directory}: {name} changed")
    subprocess.run([*git, "diff", "--quiet", "HEAD", "--"], check=True)


def validate_graph(workspace, pins, environment):
    data = subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version", "1", "--all-features"],
        cwd=workspace, env=environment,
    )
    graph = json.loads(data)
    expected = {
        name: f"git+{pins[name]['repository']}?rev={pins[name]['commit']}#{pins[name]['commit']}"
        for name in REQUIRED
    }
    seen = {name: set() for name in REQUIRED}
    roots = {}
    for package in graph["packages"]:
        source = package["source"]
        path = Path(package["manifest_path"]).resolve().parent
        if source is None:
            base.require(path.is_relative_to(workspace), f"unexpected external path source: {path}")
            continue
        for name, uri in expected.items():
            if source == uri:
                root = subprocess.check_output(
                    ["git", "-C", str(path), "rev-parse", "--show-toplevel"], text=True
                ).strip()
                roots[name] = root
                seen[name].add(package["name"])
            elif package["name"] in REQUIRED[name]:
                raise ValueError(f"{package['name']} resolved from a different source: {source}")
        if source.startswith("git+"):
            base.require(source in expected.values(), f"unreviewed Git dependency: {source}")
    for name, names in REQUIRED.items():
        base.require(names <= seen[name], f"missing {name} packages: {names - seen[name]}")
        check_checkout(roots[name], pins[name])


def main(args):
    pins = base.json_document(ROOT / PIN_FILE)
    if len(args) == 2 and args[0] == "--prepare-bellman":
        native = pins["bellman_cuda"]
        directory = Path(args[1])
        base.require(directory.is_absolute() and not directory.exists(), "expected a fresh absolute native source directory")
        base.checkout_pinned_source(native["repository"], directory, native["commit"], native["tree"])
        return
    gpu = bool(args and args[0] == "--gpu32")
    cpu = bool(args and args[0] == "--cpu")
    if gpu or cpu:
        args = args[1:]
    base.require(len(args) >= 4 and re.fullmatch(r"[A-Za-z0-9_-]+", args[0]) and args[1] == "--",
                 "usage: [--cpu|--gpu32] LABEL -- cargo COMMAND --locked ...")
    cargo = args[2:]
    source = Path(os.environ.get("PROVER_SOURCE_DIR", ROOT)).resolve(strict=True)
    native_record = None
    if not gpu:
        base.require_airbender_only(source, cargo, explicit_cpu=cpu)
    else:
        native = Path(os.environ["BELLMAN_CUDA_DIR"]).resolve(strict=True)
        check_checkout(native, pins["bellman_cuda"])
        library = native / "build/src/libbellman-cuda.a"
        cache = native / "build/CMakeCache.txt"
        base.require(library.is_file() and not library.is_symlink() and library.stat().st_size > 0, "missing compiled bellman-cuda archive")
        cmake = dict(re.findall(r"^([^#/:=]+):[^=]+=(.*)$", cache.read_text(), re.MULTILINE))
        base.require(cmake.get("CMAKE_HOME_DIRECTORY") == str(native) and cmake.get("CMAKE_BUILD_TYPE") == "Release",
                     "Bellman archive must be compiled from the selected native Release checkout")
        native_record = {"library_sha256": base.sha256(library), "cmake_cache_sha256": base.sha256(cache),
                         "cuda_architectures": cmake.get("CMAKE_CUDA_ARCHITECTURES")}
    environment = dict(os.environ)
    target = Path(environment.get("CARGO_TARGET_DIR", source / "target")).resolve()
    environment["CARGO_TARGET_DIR"] = str(target)
    build_root = target / "prepared-v2"
    build_root.mkdir(parents=True, exist_ok=True)
    workspace = Path(tempfile.mkdtemp(prefix=args[0] + "-", dir=build_root))
    input_hashes = base.copy_application(source, workspace)
    (workspace / PIN_FILE.parent).mkdir()
    shutil.copy2(ROOT / PIN_FILE, workspace / PIN_FILE)
    command = base.cargo_command(cargo, workspace / "Cargo.toml")
    validate_graph(workspace, pins, environment)
    (workspace / base.PREPARED_SOURCE_MARKER).write_text(str(workspace) + "\n" + (workspace / PIN_FILE).read_text())
    records = [Path(environment[key]) for key in ("AIRBENDER_BUILD_ATTESTATION", "GPU_BACKEND_BUILD_ATTESTATION") if key in environment]
    for path in records:
        base.require(path.is_absolute() and not path.exists(), "attestation output must be fresh and absolute")
    subprocess.run(command, env=environment, check=True)
    receipt = {"schema": "syscoin-v2-worker-build-v1", "sources": pins, "cargo_lock_sha256": base.sha256(workspace / "Cargo.lock"),
               "application_input_sha256": input_hashes, "command": cargo, "native": native_record}
    for path in [workspace / "build-inputs.json", *records]:
        with path.open("x") as output:
            json.dump(receipt, output, indent=2)
            output.write("\n")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, KeyError, ValueError, subprocess.CalledProcessError) as exc:
        sys.exit(f"V2 source preparation failed: {exc}")
