#!/usr/bin/env python3
"""SYSCOIN: Bind the complete image build matrix and SBOM evidence to immutable digests."""

import argparse
import json
import os
from pathlib import Path
import re
import sys


COMPONENTS = (
    "zksync-airbender-prover",
    "zksync-os-prover-fri",
    "zksync-os-prover-snark",
)
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
SHA = re.compile(r"[0-9a-f]{40}")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(text):
    return json.loads(text, object_pairs_hook=unique_object)


def build_identity(env):
    identity = {
        "schema": "syscoin-prover-image-digest-v1",
        "repository": env["GITHUB_REPOSITORY"],
        "source_sha": env["SOURCE_SHA"],
        "tooling_sha": env["TOOLING_SHA"],
        "version": env["VERSION"],
        "run_id": env["GITHUB_RUN_ID"],
        # SYSCOIN: An SBOM-only retry must retain the attempt that built the images.
        "run_attempt": env["BUILD_RUN_ATTEMPT"],
    }
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", identity["repository"]),
            "invalid build repository")
    require(SHA.fullmatch(identity["source_sha"]), "invalid source SHA")
    require(SHA.fullmatch(identity["tooling_sha"]), "invalid tooling SHA")
    require(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", identity["version"]),
            "invalid image version")
    for field in ("run_id", "run_attempt"):
        require(re.fullmatch(r"[1-9][0-9]*", identity[field]), f"invalid {field}")
    require(re.fullmatch(r"[1-9][0-9]*", env["GITHUB_RUN_ATTEMPT"]), "invalid current attempt")
    require(int(identity["run_attempt"]) <= int(env["GITHUB_RUN_ATTEMPT"]),
            "image build attempt is newer than this workflow attempt")
    return identity


def image_record(identity, component, digest):
    require(component in COMPONENTS, "unexpected image component")
    require(isinstance(digest, str) and DIGEST.fullmatch(digest), "invalid image digest")
    owner = identity["repository"].split("/")[0].lower()
    return {
        **identity,
        "component": component,
        "digest": digest,
        "image": f"ghcr.io/{owner}/{component}@{digest}",
    }


def artifact_name(identity, component):
    return f"prover-image-digest-{identity['run_id']}-{identity['run_attempt']}-{component}"


def collect_digests(directory, identity):
    # SYSCOIN: Matrix job outputs are last-writer-wins. Read one immutable artifact per
    # component and reject incomplete, stale-attempt, duplicate, or unexpected inventories.
    expected = {artifact_name(identity, component): component for component in COMPONENTS}
    require({entry.name for entry in directory.iterdir()} == set(expected),
            "image digest artifact inventory is incomplete or unexpected; rerun all build jobs")
    result = {}
    for name, component in expected.items():
        artifact = directory / name
        require(artifact.is_dir() and not artifact.is_symlink(), "invalid image digest artifact")
        require({entry.name for entry in artifact.iterdir()} == {"image-digest.json"},
                "image digest artifact must contain exactly one record")
        record_path = artifact / "image-digest.json"
        require(record_path.is_file() and not record_path.is_symlink(), "invalid digest record")
        record = parse_json(record_path.read_text())
        require(isinstance(record, dict), "image digest record must be an object")
        expected_record = image_record(identity, component, record.get("digest"))
        require(record == expected_record, f"image build identity mismatch: {component}")
        result[component] = record["digest"]
    return result


def image_matrix(digests, identity):
    require(isinstance(digests, dict) and set(digests) == set(COMPONENTS),
            "image digests must contain every expected component exactly once")
    return {"include": [
        {"app": component, "digest": digests[component],
         "image": image_record(identity, component, digests[component])["image"]}
        for component in COMPONENTS
    ]}


def bind_sbom(bom, record):
    require(isinstance(bom, dict) and bom.get("bomFormat") == "CycloneDX"
            and bom.get("specVersion") == "1.6", "expected a CycloneDX 1.6 SBOM")
    metadata = bom.setdefault("metadata", {})
    require(isinstance(metadata, dict), "invalid SBOM metadata")
    properties = metadata.setdefault("properties", [])
    require(isinstance(properties, list), "invalid SBOM metadata properties")
    # SYSCOIN: Keep Syft's existing image metadata and carry the exact build identity into
    # both Dependency-Track's SBOM and the retained workflow evidence.
    for key, value in record.items():
        name = f"io.syscoin.prover.image-build.{key}"
        require(not any(isinstance(prop, dict) and prop.get("name") == name for prop in properties),
                f"SBOM already contains build identity: {key}")
        properties.append({"name": name, "value": value})
    return bom


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    record = commands.add_parser("record")
    record.add_argument("component")
    record.add_argument("digest")
    collect = commands.add_parser("collect")
    collect.add_argument("directory", type=Path)
    commands.add_parser("matrix")
    bind = commands.add_parser("bind")
    bind.add_argument("component")
    bind.add_argument("digest")
    bind.add_argument("bom", type=Path)
    args = parser.parse_args()
    identity = build_identity(os.environ)
    if args.command == "record":
        result = image_record(identity, args.component, args.digest)
    elif args.command == "collect":
        result = collect_digests(args.directory, identity)
    elif args.command == "matrix":
        result = image_matrix(parse_json(os.environ["IMAGE_DIGESTS"]), identity)
    else:
        result = bind_sbom(parse_json(args.bom.read_text()),
                           image_record(identity, args.component, args.digest))
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError) as error:
        print(f"Image SBOM identity error: {error}", file=sys.stderr)
        sys.exit(1)
