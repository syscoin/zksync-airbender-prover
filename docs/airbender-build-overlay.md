# Pinned Airbender diagnostic build overlay

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

All three Docker roles and release binaries use this wrapper with their existing package and
feature selections. CPU SNARK remains `--no-default-features`, FRI remains package-scoped GPU,
and the combined service retains its GPU SNARK backend. CRS selection is unchanged.

Each runtime image includes `/usr/share/syscoin-prover/airbender-build-inputs.json`; each release
archive includes its role's `*-airbender-build-inputs.json`. These records contain source-input
hashes, exact patch/lock pins, resolved package paths, command and tool versions. The image digest
or signed archive digest binds the record to the built artifact. Build provenance also records
the upstream source and patch/lock identity. The records, release/image provenance and image SBOM
evidence distinguish immutable tooling pins from `selected_lock`: the actual source lock hash,
the generated overlay hash, the identity-only derivation and its complete Airbender package map.
Generated lock bytes are not attributed to the checked-in tooling overlay file.

The former bulk-property log reported an incorrect SM count with CUDA 12.9. Its removal is a
compatibility correction, not a throughput improvement claim. Rebuild and re-run native proof
validation before qualifying the corrected binary; retain earlier evidence under its original
binary/source identity.
