#!/usr/bin/env bash
# SYSCOIN: A disposable, pinned source overlay avoids modifying shared Cargo caches.
set -euo pipefail
tooling_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly tooling_root
exec python3 "$tooling_root/scripts/prepare-patched-airbender.py" "$@"
