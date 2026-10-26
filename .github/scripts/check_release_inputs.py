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
    pins = json.loads((root / "patches/airbender-fork-source.json").read_text())
    for relative, pin in (("Cargo.lock", "canonical_lock_sha256"),
                          ("patches/airbender.Cargo.lock", "overlay_lock_sha256")):
        data = (root / relative).read_bytes()
        if hashlib.sha256(data).hexdigest() != pins[pin]:
            raise ValueError(relative + ": lock hash differs from pinned hash")
        packages = tomllib.loads(data.decode())["package"]
        for name, expected in members.items():
            matches = [p for p in packages if p["name"] == name and "source" not in p]
            if len(matches) != 1 or matches[0]["version"] != expected:
                raise ValueError(relative + ": workspace package version differs for " + name)
    GUARD.check_scope(root)


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
