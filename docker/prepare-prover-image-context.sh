#!/usr/bin/env bash

# SYSCOIN: Compose an image context from independently pinned application source and hardened
# image tooling. This lets a manual rebuild use an older, verified tag without executing or
# depending on that tag's obsolete Dockerfiles and download logic.
set -euo pipefail

source_repo="${1:?verified application source checkout is required}"
tooling_repo="${2:?verified image tooling checkout is required}"
output_dir="${3:?output directory is required}"

test "$(git -C "${source_repo}" rev-parse --is-inside-work-tree)" = "true"
test "$(git -C "${tooling_repo}" rev-parse --is-inside-work-tree)" = "true"

readonly app_files=(
    Cargo.toml
    Cargo.lock
    rust-toolchain.toml
    multiblock_batch.bin
    multiblock_batch.text
)
for path in "${app_files[@]}"; do
    git -C "${source_repo}" cat-file -e "HEAD:${path}"
done
git -C "${source_repo}" cat-file -e HEAD:crates

readonly tooling_files=(
    .dockerignore
    docker/prover-build-pins.json
    docker/install-build-toolchain.sh
    docker/fetch-verified-crs.sh
    docker/zksync-airbender-prover/Dockerfile
    docker/zksync-airbender-prover/entrypoint.sh
    docker/zksync-os-prover-fri/Dockerfile
    docker/zksync-os-prover-snark/Dockerfile
    docker/zksync-os-prover-snark/entrypoint.sh
)
for path in "${tooling_files[@]}"; do
    git -C "${tooling_repo}" cat-file -e "HEAD:${path}"
    test -f "${tooling_repo}/${path}"
done

# Refuse a pre-existing destination so stale runner files cannot enter the attested context.
mkdir "${output_dir}"
git -C "${source_repo}" archive --format=tar HEAD -- \
    "${app_files[@]}" crates \
    | tar -xf - -C "${output_dir}"

readonly tooling_data_files=(
    .dockerignore
    docker/zksync-airbender-prover/Dockerfile
    docker/zksync-os-prover-fri/Dockerfile
    docker/zksync-os-prover-snark/Dockerfile
)
for path in "${tooling_data_files[@]}"; do
    install -d "${output_dir}/$(dirname "${path}")"
    install -m 0644 "${tooling_repo}/${path}" "${output_dir}/${path}"
done

readonly tooling_executables=(
    docker/install-build-toolchain.sh
    docker/fetch-verified-crs.sh
    docker/zksync-airbender-prover/entrypoint.sh
    docker/zksync-os-prover-snark/entrypoint.sh
)
for path in "${tooling_executables[@]}"; do
    install -d "${output_dir}/$(dirname "${path}")"
    install -m 0755 "${tooling_repo}/${path}" "${output_dir}/${path}"
done

# The compiler channel is part of the verified application tree. Keep all downloader, CMake,
# CUDA, bellman-cuda, and CRS pins from the hardened tooling tree, but install and attest the
# exact Rust channel selected by the source being rebuilt.
source_toolchain="$(sed -nE 's/^channel = "([^"]+)"$/\1/p' "${output_dir}/rust-toolchain.toml")"
source_toolchain_count="$(awk '/^channel = "[^"]+"$/ { count++ } END { print count + 0 }' "${output_dir}/rust-toolchain.toml")"
if [ "${source_toolchain_count}" -ne 1 ] \
    || [[ ! "${source_toolchain}" =~ ^(nightly|beta)-[0-9]{4}-[0-9]{2}-[0-9]{2}$ \
        && ! "${source_toolchain}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Invalid or ambiguous source Rust toolchain: ${source_toolchain}" >&2
    exit 1
fi
jq -e --arg source_toolchain "${source_toolchain}" \
    '.rust_toolchain = $source_toolchain' \
    "${tooling_repo}/docker/prover-build-pins.json" \
    > "${output_dir}/docker/prover-build-pins.json"
