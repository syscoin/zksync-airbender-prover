#!/usr/bin/env python3
"""Build single-job or reusable rental adapters over a pinned GPU prover image."""

import argparse
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

import job
from runpod import require


def releases_for(args):
    if not args.warm:
        require(args.release and not args.fri_release and not args.snark_release,
                "single_job_requires_one_release")
        raw = job.read_file(args.release, job.MAX_MANIFEST)
        job.release_identity(raw)
        return {"release.json": raw}
    require(not args.release and (args.fri_release or args.snark_release),
            "warm_requires_stage_releases")
    releases, identity = {}, None
    shared = ("protocol_version", "execution_version", "proving_version", "security_level",
              "vk_hash", "program_commitment", "app_bin_sha256", "app_text_sha256")
    for stage, path in (("FRI", args.fri_release), ("SNARK", args.snark_release)):
        if not path:
            continue
        raw = job.read_file(path, job.MAX_MANIFEST)
        release = job.release_identity(raw)
        require(release["stage"] == stage, "stage_release_mismatch")
        current = tuple(release[key] for key in shared)
        require(identity is None or current == identity, "warm_stage_identity_mismatch")
        identity = current
        releases["releases/" + stage + ".json"] = raw
    return releases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-image", required=True)
    parser.add_argument("--release")
    parser.add_argument("--warm", action="store_true")
    parser.add_argument("--fri-release")
    parser.add_argument("--snark-release")
    parser.add_argument("--tag", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--check", action="store_true", help="Docker static check only; does not qualify a proving image")
    args = parser.parse_args()
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./:_-]*@sha256:[0-9a-f]{64}", args.base_image),
            "base_image_requires_digest")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./:_-]*", args.tag), "invalid_image_tag")
    releases = releases_for(args)
    if not args.execute:
        print("dry-run: pinned image and release metadata validated; no Docker action")
        return
    source = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix="zksys-rental-image-") as temporary:
        context = Path(temporary)
        for name in ("runpod.py", "job.py", "worker.py", "entrypoint.py"):
            shutil.copyfile(source / name, context / name)
        recipe = "Dockerfile.warm" if args.warm else "Dockerfile"
        shutil.copyfile(source / recipe, context / "Dockerfile")
        if args.warm:
            for name in ("warm_worker.py", "warm_protocol.py"):
                shutil.copyfile(source / name, context / name)
        for name, release in releases.items():
            destination = context / name
            destination.parent.mkdir(exist_ok=True)
            job.write_new(destination, release)
        command = ["docker", "build", "--platform", "linux/amd64", "--build-arg", "PROVER_BASE_IMAGE=" + args.base_image,
                   "--tag", args.tag]
        if args.check:
            command.append("--check")
        subprocess.run([*command, str(context)], check=True)


if __name__ == "__main__":
    main()
