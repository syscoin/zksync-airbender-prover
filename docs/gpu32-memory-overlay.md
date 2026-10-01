# GPU32 wrapping source overlay

GPU SNARK wrapping and the combined service default to the GPU build. CPU wrapping
is explicit (`--no-default-features`, or Docker's `cpu` target); a GPU error does
not silently select a different prover. FRI-only builds retain their existing
Airbender overlay and do not acquire this second overlay or the compact SNARK CRS.

The GPU path composes two independently pinned dependency sources:

- `zksync-crypto-gpu` commit `845905b2aae49215e3d4ad0b71998b4a6b5abebf`, three exact Rust postimages;
- `era-bellman-cuda` commit `d1fa8670ee84ec3477c6cc1c85a3554cfa5e0206`, five production postimages and five correctness-test inputs.

`patches/gpu32-memory.json` binds upstream trees, patch bytes, every preimage,
postimage, size and patched Git tree. Existing source checkouts and shared Cargo
caches are never edited. The security-100 configuration, log2-domain 25, all
29 polynomial slots, proof format, guest program and verification key are unchanged.

The legacy Airbender-only lane inspects the selected application's package,
default and forwarded features before creating a build snapshot. Default or
explicit SNARK/combined GPU activation requires `--gpu32`; it cannot accidentally
compile an unpatched GPU wrapper. Scoped FRI GPU commands remain supported.
`--cpu` is checked rather than merely stripped: conflicting GPU features are
rejected. CPU workspace CI keeps `--no-default-features`, and compatible older
CPU-default manifests remain valid without substituting this tooling's defaults.

## What changed

The log25 context owns a pinned-host G1 base copy rather than retaining a complete
2 GiB device copy. Its lifetime includes a device completion barrier, including
partial setup failures. Smaller 14/14 omega tables preserve the backend's exact
table reconstruction. MSM uses the existing window17 kernel with default chunk20
for log25; its full count is 32 chunks, not a truncated proof.

In-place inversion and polynomial evaluation reuse bounded chunk scratch (16 MiB
instead of a full 1 GiB vector), preserving absolute coefficient offsets and exact
input/output aliases. In-place inversion rejects zero denominators before output
mutation; the nonalias path is unchanged. A zero denominator must abort proving,
not produce an accepted proof.

The log25 setup computes permutation polynomials with the existing CPU helper and
four IFFTs. A **runtime-only** cache belongs to that generated `AsyncSetup`; it is
not serialized. GPU proof creation validates this cache before using it and fails
closed when missing or incompatible. The generated setup object must reach proof
creation directly. Loading an old serialized setup is not a supported way to
obtain this cache, and no verification-key regeneration or replacement is required.

## Build

The Bellman preparation command creates only a fresh patched source tree and its
`syscoin-gpu-memory-source.json` record. It does not invoke CMake or run CUDA:

```sh
python3 scripts/prepare-patched-gpu-backends.py --prepare-bellman /absolute/fresh/bellman-cuda
cmake -S /absolute/fresh/bellman-cuda -B /absolute/fresh/bellman-cuda/build \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=OFF \
  -DCMAKE_CUDA_ARCHITECTURES='80;89;90;120'
cmake --build /absolute/fresh/bellman-cuda/build
BELLMAN_CUDA_DIR=/absolute/fresh/bellman-cuda \
  CUDAARCHS='80;89;90;120' \
  AIRBENDER_BUILD_ATTESTATION=/absolute/fresh/build-inputs.json \
  bash scripts/cargo-with-patched-airbender.sh --gpu32 snark -- \
  cargo build --locked --release -p zksync_os_snark_prover --features gpu
```

`BELLMAN_CUDA_DIR` is the **source root**, not its `build` directory. The helper
requires the attested production `build/src/libbellman-cuda.a`, `BUILD_TESTS=OFF`
and matching CMake source/architectures; it will not silently rebuild an unpatched
native backend. Test libraries are intentionally separate: the earlier upstream
test-library build was not a linkable production artifact for the Rust worker.
Optional `BELLMAN_SOURCE_DIR`, `CRYPTO_GPU_SOURCE_DIR` and `AIRBENDER_SOURCE_DIR`
provide local Git clone origins; they are cloned without hardlinks and never modified.

`PROVER_SOURCE_DIR` can select another compatible application checkout. The helper
first uses the existing selected-lock-aware Airbender derivation, then removes only
eight pinned crypto Git source identities, normalizes six exact dependency edges,
and orders two path/registry package pairs as Cargo expects. All other selected
versions, checksums and edges are preserved. The historical experiment's combined
lock is **not** imposed on another application's graph. Incompatible sources fail
closed and require a new reviewed overlay.

The success-only attestation retains the original `pins` / `selected_lock`
Airbender fields. `gpu_backend_overlay.inputs` separately identifies the GPU pin
manifest and selected **combined** lock digest. Its sibling fields contain complete
actual crypto/native source inventories, production-library digest and CMake
configuration digest. `gpu_backend_pins(manifest, source_lock)` is the same pure
metadata API used by image/SBOM provenance; it does not run Git, Cargo or CUDA.

## Tests and evidence limits

Run the offline policy tests with:

```sh
python3 .github/scripts/test_patched_gpu_backends.py
python3 /absolute/fresh/bellman-cuda/tests/ff_chunk_reference.py
```

The patch also carries standalone full-domain CUDA FF and pinned-host MSM tests.
These are deliberately not added to the upstream aggregate CMake test executable;
the host-bases test includes the original `msm_test.cu` fixture and must not be
compiled a second time into that same executable. Compile it with the prepared
tests/src include paths, original `tests/common.cu` and `tests/tests.cu`, GoogleTest,
curand, CUDA separable compilation and the reviewed backend library. Run both
`msm_host_bases_test.correctness_size_25_host_bases_*` cases: each checks all 2^25
bases/scalars with an independent full-count checksum and a fresh pool whose
used/reserved high-water bounds are 512 MiB. The FF test includes zero rejection,
nondivisible chunk counts, point 0/1/random, aliases, full25 counts and scratch bounds.

The retained experiment proved **offline phase3 for original batches 1–2**, not a
complete service cycle. It produced the accepted verification key unchanged,
and the independent CPU native verifier accepted the security-100 proof's 44 words
and folded public input. Outer wall time was 303.8206s (setup 127.970s, proving 161.223s),
with sampled GPU usage 30631 MiB (29.913 GiB). CPU-hybrid setup and pinned-host memory
remain part of this result. The sampled figures are observations, not a universal
32GiB minimum or a five-minute end-to-end service guarantee. Fresh normal-worker
builds, service admission, submission, native verification and canonical DA/root
settlement must still pass independently; no retained offline proof is installed
or relabeled as a new service result.
