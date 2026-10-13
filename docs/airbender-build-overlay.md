# Pinned proving sources

Worker builds use `scripts/cargo-with-patched-airbender.sh LABEL -- cargo ... --locked`.
Airbender comes from the immutable Syscoin fork commit
`0d8c852954afcae1f160151a17fe80886f1755b0`. It descends from the pinned Matter Labs
`v0.6.0-rc.2` commit `03454c7a41053a4b88bb421e97fb9efe893a92f5`, and its tree is
`a41a4a18eeb102b405bcb63ad7ca85e9b6b13213`. It carries the former cumulative
Airbender overlay and subsequent randomized FRI degree-lift hardening. The fork owns the
related native and recursive verifier changes, rebuilt Security100 recursion binaries,
Security100 sizing, diagnostics, compact setup summaries, and streamed empty unified
init/teardown markers. No Airbender patch is replayed by this repository.

The build helper clones the fork into a fresh disposable source checkout, detaches the
exact commit, and checks its ancestry from the pinned upstream commit, tree, and clean
worktree before and after Cargo.
The current application declares the exact fork commit directly. Its canonical lock
contains 46 fork packages, and seven Cargo redirects bind the wrapper's remaining rc.2
references to the same commit. The helper replaces these Git redirects with path
overrides to the verified fork checkout in a disposable application workspace. It
removes only the reviewed Git source assignments from the selected lock; package
versions, dependency edges, and registry checksums must remain identical. For an older
compatible application tag with the original rc.2 lock, the helper uses that tag's
own source identity and dependency graph. It never substitutes the current full lock.
The checked-in `patches/airbender.Cargo.lock` is an immutable reference for that
source-identity derivation.

Direct Cargo builds of the FRI and SNARK packages fail without a workspace-bound
marker created by the preparer and rechecked after Cargo. The fork pin alone does not
carry the separate wrapper and common-crypto verifier fixes, so proving binaries must
use the prepared source workspace.
Before creating snapshots or downloading proving sources, both preparation lanes reject
application tags whose existing FRI/SNARK build guards bind a different source generation.
Use such a tag's exact matching validated tooling; current tooling does not rewrite its
guard, mislabel old trees as current, or accept an old guarded VK/source combination.
Historically guardless tags retain the existing dependency-graph and feature compatibility
checks; their availability is not a claim of current proof or release qualification.

The separate `zkos-wrapper` and common `zksync-crypto` sources also come from
immutable Syscoin forks. The wrapper adds a private 64 KiB `OsRng` buffer around
synchronous Bellman proof finalization. The common crypto fork is commit
`5eafa1f914519d88a13c577a9e8cc5c7db1dfc77`, tree
`c52391d0df82126d27e5c76810e9df85c61875d0`, descending from Matter Labs commit
`bf2797e4ca13475bf797aa43e085389cdd6732f9`. It retains the reviewed native FRI
query count, verifier-owned proof policy, degree lift, recursive/SNARK agreement,
SHA-256, and row-accounting fixes. It hoists the shared `z * omega` product
outside the FRI query loop and computes constrained weighted opening claims once
per opening group. FRI folding shares the constrained coset factor across pairs,
skips the constant first interpolation factor, and omits each group's unused final
base-power square while preserving the coset inverse carried into the next group.
Final-polynomial Horner evaluation starts from the highest coefficient. It also
constrains recursive transcript query bits to their canonical Goldilocks
representative and corrects addition witnesses whose sum equals the modulus.
The query-bit guard adds compression constraints. Fresh compression/SNARK proofs for
this source passed independent CPU verification; its generated verifier accepted the
actual proof and rejected changed-public-input and changed-scalar-opening controls on
the normal-profile local EVM. The new app-bound VK is
`0x22b4a58c40ab11839bfc79c96957f24711776f3e1992fa3cf14c1c3b898a2153`.
The runtime candidate bundles now bind this VK while retaining the unchanged setup
summaries and commitment parameters. Independent CPU key agreement, normal worker
build/loader checks and release qualification remain pending. Earlier measurements
belong to `4f1e95bf`, not this source.
`patches/zksync-crypto-fork-source.json` binds the common source identity;
no common crypto byte patch is replayed. Both fork manifests bind exact upstream
and fork commits and trees, ancestry, and the reviewed package versions. Preparation
checks clean, exact source trees before and after Cargo. The FRI-only binary does
not link the wrapper, but source preparation checks the common proving graph in
every role. Cargo path overrides continue to unify the selected application's
upstream common crypto references with all eleven packages from this verified fork.

FRI and explicit CPU SNARK builds use the common source preparation. The standalone
FRI role is package-scoped and does not pull in the SNARK CUDA backend. CPU SNARK uses
`--no-default-features` and the full CPU CRS. Default standalone SNARK and combined
GPU recipes add `--gpu32` and also apply `patches/gpu32-memory.json`, whose separate
crypto-GPU and Bellman patches change memory placement and setup calculation. Those
patches, their hashes, and the native Bellman library attestation remain required.
There is no automatic CPU fallback for a GPU build.

Optional inputs:

- `AIRBENDER_SOURCE_DIR`: an existing local Git clone containing the exact fork commit;
  it is cloned without modification.
- `ZKOS_WRAPPER_SOURCE_DIR`: an existing exact wrapper Git clone.
- `ZKSYNC_CRYPTO_SOURCE_DIR`: an existing exact common crypto Git clone.
- `PROVER_SOURCE_DIR`: application source separate from wrapper tooling for release CI.
- `AIRBENDER_BUILD_ATTESTATION`: a fresh absolute JSON path with an existing parent,
  written only after Cargo succeeds and inputs are rechecked.

The helper creates fresh source copies and build records under
`target/patched-airbender/LABEL-*/` or `target/patched-gpu-backends/LABEL-*/`. It does
not change the original checkout or Cargo's shared Git and registry sources. Each
runtime image includes `/usr/share/syscoin-prover/airbender-build-inputs.json`; each
release archive includes its role's build record. The image or archive digest binds
that record to the binary. The record and SBOM/provenance metadata identify the fork
commit and tree, original lock source, selected lock derivation, wrapper and common
crypto fork identities, source package paths, and other build inputs. GPU builds
also retain the separate backend patch identities.

The preceding `4f1e95bf` snapshot's bundled FRI setup summaries and SNARK commitment
were qualified with its prepared fork identities. Its normal locked CPU release-loader
tests accepted matching bundles and rejected altered inputs. For the retained
two-batch input, native FRI proofs, stock GPU wrapper/compression/SNARK proving and
all three independent CPU verifications completed; all three CPU/GPU keys matched
byte-for-byte. That generated verifier accepted its actual optimized proof on the
normal-profile local EVM, and changed-public-input and valid-field scalar-opening
controls both reverted. These are historical results, not new worker or bundle
qualification for the canonical-query fix.

These offline results do not establish live verifier deployment, service acceptance,
broader workload qualification or sustained throughput. Those gates remain pending;
see the [current qualification and build scope](../README.md#separate-fri-and-default-gpu-snark-deployment) for the
measured input, identities, normal-worker build provenance and remaining limits.
