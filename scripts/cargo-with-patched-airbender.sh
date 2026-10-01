#!/usr/bin/env bash
# SYSCOIN: A disposable, pinned source overlay avoids modifying shared Cargo caches.
set -euo pipefail
tooling_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
readonly tooling_root
# SYSCOIN: GPU wrapping additionally requires the exact reviewed crypto/CUDA
# memory overlay. CPU and FRI-only callers retain the original Airbender lane.
preparer=prepare-patched-airbender.py
if [[ "${1:-}" == "--gpu32" ]]; then
  preparer=prepare-patched-gpu-backends.py
  shift
elif [[ "${1:-}" == "--cpu" ]]; then
  # Preserve CPU intent for the selected-manifest-aware feature guard.
  preparer=prepare-patched-airbender.py
fi
exec python3 "$tooling_root/scripts/$preparer" "$@"
