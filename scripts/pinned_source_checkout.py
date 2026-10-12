#!/usr/bin/env python3
"""Fresh exact source checkout without downloading unrelated historical blobs."""

import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit


def _git(*arguments, packet_trace=False):
    # Public source fetches must not inherit credential helpers, URL rewrites,
    # injected headers or an unrelated repository from the operator's Git config.
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("GIT_")}
    environment.update(GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1",
                       GIT_CONFIG_GLOBAL=os.devnull)
    if packet_trace:
        environment["GIT_TRACE_PACKET"] = "1"
    return subprocess.run(
        ["git", "-c", "protocol.version=2", "-c", "credential.helper=",
         "-c", "core.askPass=", *map(str, arguments)], env=environment, cwd=os.path.sep,
        check=True, text=True, capture_output=True)


def checkout_pinned_source(source, target, commit, tree):
    """Preserve ancestry and materialize only the hash-checked pinned tree.

    Failed fresh directories are retained; occupied paths are never reused.
    Local caches are served through Git's file transport, never copied/hardlinked
    or modified. Blob filtering is required, not a silent full-fetch fallback.
    """
    target = Path(target)
    if (not target.is_absolute() or not target.parent.is_dir()
            or target.parent.resolve(strict=True) != target.parent
            or target.exists() or target.is_symlink()):
        raise ValueError("source destination must be a fresh absolute directory")
    if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value)
           or value == "0" * 40 for value in (commit, tree)):
        raise ValueError("commit and tree must be nonzero full lowercase Git identities")
    source = str(source)
    local = Path(source)
    if local.is_absolute():
        source = local.resolve(strict=True).as_uri()
    parsed = urlsplit(source)
    if (parsed.scheme not in {"https", "file"} or parsed.username or parsed.password
            or parsed.query or parsed.fragment or not parsed.path
            or (parsed.scheme == "https" and not parsed.hostname)
            or (parsed.scheme == "file" and parsed.netloc not in {"", "localhost"})):
        raise ValueError("source must be a credential-free HTTPS URL or local Git directory")
    local_transport = parsed.scheme == "file"
    if local_transport:
        # --missing=print disables lazy fetch before revision parsing, including
        # on Git 2.43. Inspect only this commit's tree, not historical blobs.
        # An incomplete local cache must never hydrate itself during upload-pack.
        local_source = Path(unquote(parsed.path)).resolve(strict=True)
        try:
            available = _git("-C", local_source, "rev-list", "--objects", "--no-object-names",
                             "--no-walk=unsorted", "--missing=print", commit)
        except subprocess.CalledProcessError as error:
            raise ValueError("local source cache lacks objects in the pinned tree") from error
        if any(line.startswith("?") for line in available.stdout.splitlines()):
            raise ValueError("local source cache lacks objects in the pinned tree")
    upload_pack = "git -c uploadpack.allowFilter=true upload-pack"
    capability_args = ["ls-remote"]
    if local_transport:
        capability_args.append("--upload-pack=" + upload_pack)
    capabilities = _git(*capability_args, source, "HEAD", packet_trace=True)
    if not re.search(r"fetch=[^\n]*\bfilter\b", capabilities.stderr):
        raise ValueError("source server must support protocol-v2 blob filtering")
    target.mkdir(mode=0o700)
    _git("init", "--quiet", "--template=", target)
    _git("-C", target, "remote", "add", "origin", source)
    if local_transport:
        _git("-C", target, "config", "remote.origin.uploadpack", upload_pack)
    _git("-C", target, "config", "remote.origin.promisor", "true")
    _git("-C", target, "config", "remote.origin.partialclonefilter", "blob:none")
    # No depth limit: the existing fork/base ancestry checks must still work.
    _git("-C", target, "fetch", "--quiet", "--no-tags", "--filter=blob:none",
         "origin", commit)
    if (_git("-C", target, "rev-parse", "FETCH_HEAD^{commit}").stdout.strip() != commit
            or _git("-C", target, "rev-parse", "FETCH_HEAD^{tree}").stdout.strip() != tree):
        raise ValueError("fetched source commit/tree differs from the reviewed identity")
    _git("-C", target, "checkout", "--quiet", "--detach", commit)
    if (_git("-C", target, "rev-parse", "HEAD").stdout.strip() != commit
            or _git("-C", target, "rev-parse", "HEAD^{tree}").stdout.strip() != tree
            or _git("-C", target, "status", "--porcelain", "--untracked-files=all").stdout):
        raise ValueError("pinned source checkout is dirty or has changed identity")


def main(arguments):
    if len(arguments) != 4:
        raise ValueError("usage: pinned_source_checkout.py SOURCE COMMIT TREE FRESH_ABSOLUTE_DIRECTORY")
    source, commit, tree, destination = arguments
    checkout_pinned_source(source, Path(destination), commit, tree)
    print(f"Verified pinned checkout: {destination} {commit} {tree}")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"pinned source checkout refused: {error}", file=sys.stderr)
        raise SystemExit(1)
