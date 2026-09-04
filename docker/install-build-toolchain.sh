#!/bin/sh

# SYSCOIN: Shared image-build bootstrap. The reviewed data file is also embedded in provenance;
# downloaded executables are verified before use.
set -eu

apt-get update
apt-get install -y --no-install-recommends \
    build-essential ca-certificates clang curl gcc g++ git jq libclang-dev libssl-dev openssl pkg-config
rm -rf /var/lib/apt/lists/*

pins='/usr/src/zksync/docker/prover-build-pins.json'
jq -e '.schema == "syscoin-prover-image-build-pins-v1"' "${pins}" >/dev/null
rust_toolchain="$(jq -er '.rust_toolchain' "${pins}")"
rustup_version="$(jq -er '.rustup_init.version' "${pins}")"
rustup_sha256="$(jq -er '.rustup_init.sha256' "${pins}")"
cmake_version="$(jq -er '.cmake.version' "${pins}")"
cmake_sha256="$(jq -er '.cmake.sha256' "${pins}")"
grep -Fqx "channel = \"${rust_toolchain}\"" /usr/src/zksync/rust-toolchain.toml
if [ -n "${CUDAARCHS:-}" ]; then
    test "${CUDAARCHS}" = "$(jq -er '.cuda_architectures' "${pins}")"
fi

curl --proto '=https' --tlsv1.2 --fail --location --retry 5 \
    --output /tmp/rustup-init \
    "https://static.rust-lang.org/rustup/archive/${rustup_version}/x86_64-unknown-linux-gnu/rustup-init"
echo "${rustup_sha256}  /tmp/rustup-init" | sha256sum --check --strict
chmod 0755 /tmp/rustup-init
/tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain none
rm /tmp/rustup-init
rustup toolchain install "${rust_toolchain}" --profile minimal

curl --proto '=https' --tlsv1.2 --fail --location --retry 5 \
    --output /tmp/cmake.tar.gz \
    "https://github.com/Kitware/CMake/releases/download/v${cmake_version}/cmake-${cmake_version}-linux-x86_64.tar.gz"
echo "${cmake_sha256}  /tmp/cmake.tar.gz" | sha256sum --check --strict
mkdir -p /opt/cmake
tar -xzf /tmp/cmake.tar.gz --strip-components=1 -C /opt/cmake
rm /tmp/cmake.tar.gz

rustc "+${rust_toolchain}" --version
/opt/cmake/bin/cmake --version
