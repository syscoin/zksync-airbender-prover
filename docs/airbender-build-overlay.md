# Pinned Airbender and GPU32 build overlays

Worker builds use `scripts/cargo-with-patched-airbender.sh LABEL -- cargo ... --locked`.
The wrapper retains Airbender `03454c7a41053a4b88bb421e97fb9efe893a92f5` and applies only
`patches/airbender-cuda-device-diagnostics.patch`. This replaces a runtime-versioned bulk
device-properties startup log with the scalar SM-count query already used by operational GPU
sizing. It changes no proving, verification, allocation, guest, or registry dependency code.

The manifest `patches/airbender-cuda-device-diagnostics.json` binds the exact upstream commit
and tree, patch SHA-256, pre/post source hashes, resulting tree, and canonical/overlay lock hashes.
The alternate lock changes only the source identities of all 46 locked Airbender packages; every
package version, dependency edge, and registry checksum must remain equal. All those packages
map to the same disposable patched checkout. For a compatible separately selected source tag,
the wrapper derives its overlay from that source's own `Cargo.lock`, removing only those same
46 pinned Airbender source identities. The checked-in lock hashes remain immutable tooling
reference hashes, not a requirement that older application dependencies equal today's graph.
Mixed or incompatible Airbender revisions and overlay drift fail closed; the wrapper never
resolves fresh versions to make a tag fit.

The wrapper requires Git, the repository's Rust toolchain, and Python 3.11+, or Python 3 with the
distribution's `python3-tomli` package. It creates fresh source copies and input/result records
under `target/patched-airbender/LABEL-*/`. It does not patch the original checkout or Cargo's
shared Git/registry sources. Normal Cargo dependency downloads and compilation remain possible.
The caller's working directory is preserved, as is an explicit absolute `CARGO_TARGET_DIR`;
otherwise binaries remain under this repository's `target/` directory.

Optional inputs:

- `AIRBENDER_SOURCE_DIR`: an existing exact upstream Git checkout, cloned without modifying it.
- `PROVER_SOURCE_DIR`: application source separate from the wrapper/patch tooling revision.
- `AIRBENDER_BUILD_ATTESTATION`: a fresh absolute JSON path with an existing parent; written only
  after Cargo succeeds and source/lock hashes are rechecked. Do not reuse an existing output.

FRI and the explicit CPU SNARK fallback use this diagnostic-only wrapper path. FRI remains
package-scoped GPU, without the SNARK CUDA backend. CPU SNARK uses `--no-default-features`
and the full CPU CRS. Default standalone SNARK and combined GPU recipes add `--gpu32` before
the label, use the compact GPU CRS, and also apply `patches/gpu32-memory.json` with its two
hash-checked crypto-GPU/Bellman patches. The extra overlay retains all eight crypto-GPU package
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
the upstream source and patch/lock identity. The records, release/image provenance and image SBOM
evidence distinguish immutable tooling pins from `selected_lock`: the actual source lock hash,
the generated overlay hash, the identity-only derivation and its complete Airbender package map.
Generated lock bytes are not attributed to the checked-in tooling overlay file.
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
