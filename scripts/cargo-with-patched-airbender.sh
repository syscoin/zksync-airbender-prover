#!/usr/bin/env bash
# SYSCOIN: Disposable, pinned source overlays avoid modifying shared Cargo caches.
set -euo pipefail
tooling_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly tooling_root
# SYSCOIN: Every lane prepares exact Airbender and zkos-wrapper sources. GPU
# wrapping additionally requires the reviewed crypto/CUDA memory overlay.
preparer=prepare-patched-airbender.py
if [[ "${1:-}" == "--gpu32" ]]; then
  preparer=prepare-patched-gpu-backends.py
  shift
elif [[ "${1:-}" == "--cpu" ]]; then
  # Preserve CPU intent for the selected-manifest-aware feature guard.
  preparer=prepare-patched-airbender.py
fi
exec python3 "$tooling_root/scripts/$preparer" "$@"
