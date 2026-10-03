# Pinned proving-source overlays

Worker builds use `scripts/cargo-with-patched-airbender.sh LABEL -- cargo ... --locked`.
The common source overlay retains Airbender
`03454c7a41053a4b88bb421e97fb9efe893a92f5` and applies only
`patches/airbender-cuda-device-diagnostics.patch`. The cumulative overlay replaces a
runtime-versioned bulk device-properties startup log with the scalar SM-count query already used
by operational GPU sizing, supports authenticated compact FRI setup summaries, and backports
[upstream PR 403](https://github.com/matter-labs/zksync-airbender/pull/403)'s empty unified
init/teardown marker streaming. It does not change circuits, verification, guest code, security
parameters, proof format, registry dependencies, or the configured 384-entry host allocator pool.

The streaming backport uses this pinned revision's per-word geometry, not upstream PR 403's newer
window layout: `MemoryHolder.memory` contains `2^28` words, collection emits at most one I&T record
per word, and a unified circuit holds `2^23 - 1` records. Thus no more than
`ceil(2^28 / (2^23 - 1)) = 33` trailing circuits can contain I&T data, even for delegation bursts.
Before snapshot tracing requests another host allocator, the simulator releases only the leading
`floor(cycles_so_far / (2^23 - 1)) - 33` markers (saturating at zero). Finalization retains the
original exact `floor((total_cycles - record_count) / (2^23 - 1))` empty prefix and sends only its
not-yet-streamed suffix, asserting that the streamed prefix does not exceed it. Split-mode
simulation and the CPU pipeline model retain their original post-run protocol. Only result-message
timing changes; the circuit sequence identities and witness partitioning remain unchanged.

The patched `gpu_prover/src/execution/empty_inits_and_teardowns.rs` production module has seven
dependency-free tests and can be checked without CUDA with
`rustc --edition=2021 --test PATH_TO_PATCHED_SOURCE/gpu_prover/src/execution/empty_inits_and_teardowns.rs -o /tmp/empty-it-tests`
followed by `/tmp/empty-it-tests`. Coverage includes the pinned 33-instance bound, exhaustive
reduced-geometry final prefixes, partial circuits, repeated snapshots, worst-case RAM occupancy
with irregular delegation-heavy advances, split-mode absence, and fail-closed finalization. A
160-circuit finite-pool model checks marker-driven reclamation beyond 46 circuits under completed
replay/GPU work; it does not qualify native queue lag, performance, or proof-byte equivalence.

The same preparation also retains `zkos-wrapper`
`585595f145cb53a09a130706ca36f80ddcac3961` and applies only
`patches/zkos-wrapper-buffered-os-rng.patch`. The patch adds a private 64 KiB buffer around
`OsRng` and uses one fresh buffer for each synchronous Bellman proof-finalization call, on both
the CPU and GPU padding paths. It batches operating-system entropy requests while preserving the
entropy source and byte distribution; the padding calculation, circuit, verification key, security
parameters and proof format are unchanged. The buffer is not shared, cloned, serialized or
returned to callers. It must not survive a process fork; the reviewed call sites contain no
callback, asynchronous suspension or fork while it is live. A future use outside that closed
synchronous scope requires new review.

The manifests `patches/airbender-cuda-device-diagnostics.json` and
`patches/zkos-wrapper-buffered-os-rng.json` bind the exact upstream commits and trees, patch
SHA-256 values, pre/post source hashes and resulting trees; the wrapper manifest also binds exact
postimage sizes. The generated lock
changes only the source identities of all 46 locked Airbender packages and the two pinned wrapper
packages (`circuit_mersenne_field` and `zkos-wrapper`); every package version, dependency edge and
registry checksum must remain equal. Each package family maps to one disposable patched checkout.
For a compatible separately selected source tag, the helper derives its overlay from that source's
own `Cargo.lock`, removing only those same 48 pinned source identities. Checked-in lock hashes
remain immutable tooling references, not a requirement that older application dependencies equal
today's graph. Mixed or incompatible revisions and overlay drift fail closed; the helper never
resolves fresh versions to make a tag fit.

The wrapper requires Git, the repository's Rust toolchain, and Python 3.11+, or Python 3 with the
distribution's `python3-tomli` package. It creates fresh source copies and input/result records
under `target/patched-airbender/LABEL-*/`. It does not patch the original checkout or Cargo's
shared Git/registry sources. Normal Cargo dependency downloads and compilation remain possible.
The caller's working directory is preserved, as is an explicit absolute `CARGO_TARGET_DIR`;
otherwise binaries remain under this repository's `target/` directory.

Optional inputs:

- `AIRBENDER_SOURCE_DIR`: an existing exact upstream Git checkout, cloned without modifying it.
- `ZKOS_WRAPPER_SOURCE_DIR`: an existing exact wrapper Git checkout, cloned without modifying it.
- `PROVER_SOURCE_DIR`: application source separate from the wrapper/patch tooling revision.
- `AIRBENDER_BUILD_ATTESTATION`: a fresh absolute JSON path with an existing parent; written only
  after Cargo succeeds and source/lock hashes are rechecked. Do not reuse an existing output.

FRI and the explicit CPU SNARK fallback use this common source-preparation path. The isolated FRI
binary does not link the wrapper packages, and remains package-scoped GPU without the SNARK CUDA
backend. CPU SNARK uses `--no-default-features` and the full CPU CRS; its wrapper finalization uses
the buffered RNG. Default standalone SNARK and combined GPU recipes add `--gpu32` before the label,
use the compact GPU CRS, and also apply `patches/gpu32-memory.json` with its two hash-checked
crypto-GPU/Bellman patches. The extra GPU overlay retains all eight crypto-GPU package
versions/dependency edges and the exact Security100/domain-log25 VK and proof checks; it changes
memory placement and setup calculation, not the statement, security level or proof format.

The GPU recipes first run `scripts/prepare-patched-gpu-backends.py --prepare-bellman ABS_FRESH_DIR`.
This only prepares pinned native source and its source record. CMake separately builds Release
with `BUILD_TESTS=OFF` and the reviewed architectures, including SM120. `BELLMAN_CUDA_DIR` points
at that source root (library under `build/src/`); the Cargo wrapper verifies the native source,
CMake cache and actual library before recording a successful build. There is no automatic CPU
fallback. CPU-cold caching is an explicit CPU-only runtime policy, not a GPU option.

Each runtime image includes `/usr/share/syscoin-prover/airbender-build-inputs.json`; each release
archive includes its role's `*-airbender-build-inputs.json`. These records contain source-input
hashes, exact patch/lock pins, resolved package paths, command and tool versions. The image digest
or signed archive digest binds the record to the built artifact. Build provenance also records
both upstream sources and patch/lock identities. The records, release/image provenance and image
SBOM evidence distinguish immutable tooling pins from `selected_lock`: the actual source lock
hash, generated overlay hash, identity-only derivation, complete 46-package Airbender map and
two-package wrapper map. `zkos_wrapper.inputs` and `zkos_wrapper.source` separately bind the exact
wrapper manifest, patch and prepared source tree. Generated lock bytes are not attributed to the
checked-in tooling overlay file.
GPU records additionally retain `gpu_backend_overlay.inputs`, the combined selected-source lock,
the actual crypto/native source inventories and native library identity. Image provenance and
GPU image SBOM properties bind the GPU manifest/patch/combined-lock identity; FRI/CPU records
are not relabelled as GPU builds.

The retained RTX5090 experiment verified only final phase 3 for an earlier genuine compression
proof (303.82s total, 29.91GiB sampled GPU memory). It did not qualify an ordinary service range,
all-phase memory, sustained throughput, an instantaneous memory peak, or other GPU architectures.
These integrated recipes still require new normal worker builds and native/service validation.

The former bulk-property log reported an incorrect SM count with CUDA 12.9. Its removal is a
compatibility correction, not a throughput improvement claim. Rebuild and re-run native proof
validation before qualifying the corrected binary; retain earlier evidence under its original
binary/source identity.
