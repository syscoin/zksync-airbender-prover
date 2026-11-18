#!/usr/bin/env python3
"""Reject a release when version, lock pins, or reviewed scope do not agree."""

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[2]
GUARD_PATH = Path(__file__).with_name("check_crypto_bigint_scope.py")
SPEC = importlib.util.spec_from_file_location("check_crypto_bigint_scope", GUARD_PATH)
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)
IDENTITY_PATH = Path(__file__).with_name("image-sbom-identity.py")
SPEC = importlib.util.spec_from_file_location("release_source_identity", IDENTITY_PATH)
IDENTITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IDENTITY)
V2_PINS = "patches/v2-proving-sources.json"
BUNDLED_COMMITMENT = "crates/zksync_os_snark_prover/artifacts/syscoin-v32-security100-commitment.json"


def validate_package_versions(data, relative, members):
    packages = tomllib.loads(data.decode())["package"]
    for name, expected in members.items():
        matches = [p for p in packages if p["name"] == name and "source" not in p]
        if len(matches) != 1 or matches[0]["version"] != expected:
            raise ValueError(relative + ": workspace package version differs for " + name)


def validate_legacy_locks(root, members):
    pins = json.loads((root / "patches/airbender-fork-source.json").read_text())
    for relative, pin in (("Cargo.lock", "canonical_lock_sha256"),
                          ("patches/airbender.Cargo.lock", "overlay_lock_sha256")):
        data = (root / relative).read_bytes()
        if hashlib.sha256(data).hexdigest() != pins[pin]:
            raise ValueError(relative + ": lock hash differs from pinned hash")
        validate_package_versions(data, relative, members)


def validate(root):
    root = Path(root)
    workspace = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]
    version = workspace["package"]["version"]
    release_version = json.loads((root / ".github/release-please/manifest.json").read_text())["."]
    if version != release_version:
        raise ValueError("release manifest and workspace version differ")
    members = {}
    for path in workspace["members"]:
        package = tomllib.loads((root / path / "Cargo.toml").read_text())["package"]
        if package["name"] in members:
            raise ValueError("duplicate workspace member")
        members[package["name"]] = version if package["version"] == {"workspace": True} else package["version"]
    if (root / V2_PINS).exists() or (root / V2_PINS).is_symlink():
        # V2 builds use one locked graph. Its reviewed scope binds the lock bytes;
        # historical overlay hashes must not be rewritten to describe this graph.
        pins = GUARD.regular_input(root, V2_PINS)
        lock = GUARD.regular_input(root, "Cargo.lock")
        IDENTITY.v2_proving_pins(pins, lock)
        validate_package_versions(lock.read_bytes(), "Cargo.lock", members)
    else:
        validate_legacy_locks(root, members)
    GUARD.check_scope(root)
    if (root / V2_PINS).exists():
        sources = json.loads(pins.read_bytes())
        bundled = json.loads(GUARD.regular_input(root, BUNDLED_COMMITMENT).read_bytes())
        for key, source in (("airbender", "airbender"), ("wrapper_circuit", "protocol")):
            if (bundled[key + "_revision"], bundled[key + "_patched_tree"]) != (
                sources[source]["commit"], sources[source]["tree"]
            ):
                raise ValueError("bundled commitment source differs from V2 pins: " + source)


def main():
    try:
        validate(ROOT)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("Release inputs invalid: " + str(error), file=sys.stderr)
        return 1
    print("Release versions, lock pins and reviewed dependency scope agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
