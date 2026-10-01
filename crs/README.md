# CRS files by proving backend

The pinned CPU and GPU SNARK wrappers read different CRS serializations. Download the file for
the backend you built; renaming one format does not convert it into the other. Standalone FRI
proving does not need a CRS.

The pinned Security100 CPU wrapper requires at least `2^25` G1 points; the older upstream
`setup_2^24.key` example is correctly serialized but too small for this lane.

Run these commands from the repository root with `curl`, `jq`, and `sha256sum` installed:

```sh
# CPU SNARK (--no-default-features), including CPU wrapper key generation.
PROVER_BUILD_PINS=docker/prover-build-pins.json \
  sh docker/fetch-verified-crs.sh cpu-snark 'crs/setup_2^25.key'

# GPU SNARK / combined service (--features gpu).
PROVER_BUILD_PINS=docker/prover-build-pins.json \
  sh docker/fetch-verified-crs.sh gpu-snark crs/setup_compact.key
```

The helper selects the role's source, exact byte count, and SHA-256 from
[`docker/prover-build-pins.json`](../docker/prover-build-pins.json). It verifies the download
and, for CPU, verifies the big-endian G1-count header and Security100 minimum capacity before
replacing the output file. For compatibility, the old one-argument invocation still
downloads the compact GPU file and emits a warning; CPU callers must specify `cpu-snark`.

The CPU file `setup_2^25.key` is 2,147,483,920 bytes and the compact GPU file is
4,831,838,468 bytes. "Compact" names the GPU serialization, not a smaller interchangeable CPU
file. These large files are not checked into Git. CPU images include `/setup_2^25.key`; combined
GPU images include `/setup_compact.key`; pass the matching path as `--trusted-setup-file`.
The FRI image includes neither file.
