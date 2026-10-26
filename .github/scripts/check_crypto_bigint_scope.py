#!/usr/bin/env python3
"""Fail closed when inputs to the reviewed crypto-bigint exception change.

The checked-in scope is a review record. Updating it requires reviewing the
exception again; this checker deliberately has no command to refresh it.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tomllib

ADVISORY = "RUSTSEC-2026-0387"
CRYPTO_BIGINT_VERSION = "0.5.5"
CRYPTO_BIGINT_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
CRYPTO_BIGINT_CHECKSUM = "0dc92fb57ca44df6db8059111ab3af99a63d5d0f8375d9972e319a379c6bab76"
DIRECT_PARENTS = {"boojum", "elliptic-curve"}
LOCK_PATHS = ("Cargo.lock", "patches/airbender.Cargo.lock")
FIXED_INPUTS = (
    "Cargo.toml",
    *LOCK_PATHS,
    "deny.toml",
    "rust-toolchain.toml",
    "patches/airbender-fork-source.json",
    "patches/zkos-wrapper-fork-source.json",
    "patches/zksync-crypto-fork-source.json",
    "patches/gpu32-memory.json",
    "patches/crypto-gpu32-memory.patch",
    "patches/bellman-gpu32-memory.patch",
    "scripts/cargo-with-patched-airbender.sh",
    "scripts/prepare-patched-airbender.py",
    "scripts/prepare-patched-gpu-backends.py",
    "scripts/pinned_source_checkout.py",
)
DEFAULT_SCOPE = "docs/crypto-bigint-scope.json"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def regular_input(root, relative):
    path = root / relative
    # A symlinked directory could silently supply an unreviewed source tree.
    require(not any(part.is_symlink() for part in (path, *path.parents)
                    if part != root and root in part.parents),
            "symlinked scope input: " + relative)
    require(path.is_file() and not path.is_symlink(), "missing or nonregular scope input: " + relative)
    return path


def collect_inputs(root):
    """Return input digests, including the complete local Rust source file list."""
    root = Path(root).resolve()
    paths = set(FIXED_INPUTS)
    crates = root / "crates"
    require(crates.is_dir() and not crates.is_symlink(), "missing or symlinked crates directory")

    def walk_error(error):
        raise ValueError("cannot enumerate scope inputs: " + str(error)) from error

    for directory, directories, files in os.walk(crates, onerror=walk_error, followlinks=False):
        directory = Path(directory)
        for name in directories:
            require(not (directory / name).is_symlink(),
                    "symlinked crate directory: " + (directory / name).relative_to(root).as_posix())
        for name in files:
            if name.endswith(".rs") or name == "Cargo.toml":
                paths.add((directory / name).relative_to(root).as_posix())

    # Cargo reads these before resolving the locked graph. Their introduction
    # must invalidate the review just as an existing manifest edit does.
    for relative in (".cargo/config", ".cargo/config.toml"):
        path = root / relative
        if path.exists() or path.is_symlink():
            paths.add(relative)
    return {relative: hashlib.sha256(regular_input(root, relative).read_bytes()).hexdigest()
            for relative in sorted(paths)}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate scope JSON key: " + key)
        result[key] = value
    return result


def read_toml(root, relative):
    with regular_input(root, relative).open("rb") as source:
        return tomllib.load(source)


def check_lock(root, relative):
    packages = read_toml(root, relative).get("package")
    require(isinstance(packages, list) and all(isinstance(package, dict)
            and isinstance(package.get("name"), str) and isinstance(package.get("version"), str)
            for package in packages), relative + ": invalid package list")
    bigint = [package for package in packages if package.get("name") == "crypto-bigint"]
    require(len(bigint) == 1, relative + ": expected exactly one crypto-bigint package")
    expected = {"version": CRYPTO_BIGINT_VERSION, "source": CRYPTO_BIGINT_SOURCE,
                "checksum": CRYPTO_BIGINT_CHECKSUM}
    require(all(bigint[0].get(key) == value for key, value in expected.items()),
            relative + ": crypto-bigint identity changed; review the advisory exception")

    allowed_edges = {"crypto-bigint", "crypto-bigint " + CRYPTO_BIGINT_VERSION,
                     "crypto-bigint " + CRYPTO_BIGINT_VERSION + " (" + CRYPTO_BIGINT_SOURCE + ")"}
    parents = []
    for package in packages:
        dependencies = package.get("dependencies", [])
        require(isinstance(dependencies, list) and all(isinstance(edge, str) for edge in dependencies),
                relative + ": invalid dependency list")
        for edge in dependencies:
            if edge.split(" ", 1)[0] == "crypto-bigint":
                require(edge in allowed_edges, relative + ": unknown crypto-bigint dependency edge")
                parents.append(package.get("name"))
    require(len(parents) == 2 and set(parents) == DIRECT_PARENTS,
            relative + ": crypto-bigint direct parents changed; expected boojum and elliptic-curve")


def check_scope(root, scope_path=None):
    root = Path(root).resolve()
    scope_path = Path(scope_path) if scope_path is not None else root / DEFAULT_SCOPE
    require(scope_path.is_file() and not scope_path.is_symlink(),
            "missing or nonregular reviewed scope: " + str(scope_path))
    scope = json.loads(scope_path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    require(isinstance(scope, dict) and set(scope) == {"schema_version", "advisory", "inputs"},
            "unknown crypto-bigint scope fields")
    require(type(scope["schema_version"]) is int and scope["schema_version"] == 1,
            "unsupported crypto-bigint scope schema")
    require(scope["advisory"] == ADVISORY, "crypto-bigint scope advisory changed")
    expected = scope["inputs"]
    require(isinstance(expected, dict) and expected, "missing reviewed scope inputs")
    for relative, digest in expected.items():
        require(isinstance(relative, str) and relative and not Path(relative).is_absolute()
                and ".." not in Path(relative).parts and Path(relative).as_posix() == relative
                and "\\" not in relative,
                "noncanonical reviewed scope input: " + str(relative))
        require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest),
                "invalid reviewed scope digest: " + relative)

    advisories = read_toml(root, "deny.toml").get("advisories", {})
    require(isinstance(advisories, dict), "deny.toml: invalid advisories table")
    ignores = advisories.get("ignore", [])
    require(isinstance(ignores, list) and all(isinstance(ignore, str) for ignore in ignores)
            and ignores.count(ADVISORY) == 1,
            "deny.toml must ignore exactly " + ADVISORY + " once for the reviewed exception")
    for relative in LOCK_PATHS:
        check_lock(root, relative)
    actual = collect_inputs(root)
    added = sorted(actual.keys() - expected.keys())
    removed = sorted(expected.keys() - actual.keys())
    require(not added and not removed,
            "crypto-bigint scope file list changed; added=" + repr(added) + "; removed=" + repr(removed))
    changed = [relative for relative in actual if actual[relative] != expected[relative]]
    require(not changed,
            "crypto-bigint scope inputs changed; review the advisory exception: " + ", ".join(changed))
    return len(actual)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2],
                        help="repository root (default: this checker's repository)")
    args = parser.parse_args(argv)
    try:
        count = check_scope(args.root)
    except (OSError, ValueError, TypeError) as error:
        print("crypto-bigint scope check failed: " + str(error), file=sys.stderr)
        return 1
    print(f"{ADVISORY}: reviewed crypto-bigint scope matches {count} inputs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
