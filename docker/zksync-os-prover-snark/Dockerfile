# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# SYSCOIN: CPU wrapping is an explicit build target, never a runtime error fallback.
# The final/default image below uses the GPU backend and compact CRS.
FROM ubuntu:22.04@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc AS cpu-builder

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/opt/cmake/bin:/usr/local/cargo/bin:${PATH}

WORKDIR /usr/src/zksync
COPY rust-toolchain.toml ./
COPY docker/prover-build-pins.json ./docker/prover-build-pins.json
COPY docker/install-build-toolchain.sh /usr/local/bin/install-build-toolchain
RUN chmod 0755 /usr/local/bin/install-build-toolchain && install-build-toolchain

COPY docker/fetch-verified-crs.sh /usr/local/bin/fetch-verified-crs
RUN chmod 0755 /usr/local/bin/fetch-verified-crs && fetch-verified-crs cpu-snark /setup_2^25.key

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY multiblock_batch.bin multiblock_batch.text ./
COPY scripts/cargo-with-patched-airbender.sh scripts/prepare-patched-airbender.py ./scripts/
COPY patches/airbender-cuda-device-diagnostics.patch patches/airbender-cuda-device-diagnostics.json patches/airbender.Cargo.lock ./patches/

# SYSCOIN: Match the hardened release topology: CPU-only wrapping, without the GPU feature.
RUN AIRBENDER_BUILD_ATTESTATION=/usr/src/zksync/snark-cpu-airbender-build-inputs.json \
    bash scripts/cargo-with-patched-airbender.sh docker-snark-cpu -- \
    cargo build --locked --profile release --target x86_64-unknown-linux-gnu \
    -p zksync_os_snark_prover --bin zksync_os_snark_prover --no-default-features

FROM ubuntu:22.04@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc AS cpu

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl libpq5 && \
    rm -rf /var/lib/apt/lists/*

COPY docker/zksync-os-prover-snark/entrypoint.sh /entrypoint.sh
COPY --from=cpu-builder /setup_2^25.key /setup_2^25.key
COPY --from=cpu-builder /usr/src/zksync/multiblock_batch.bin /multiblock_batch.bin
COPY --from=cpu-builder /usr/src/zksync/multiblock_batch.text /multiblock_batch.text
COPY --from=cpu-builder /usr/src/zksync/target/x86_64-unknown-linux-gnu/release/zksync_os_snark_prover /usr/bin/zksync_os_snark_prover
COPY --from=cpu-builder /usr/src/zksync/snark-cpu-airbender-build-inputs.json /usr/share/syscoin-prover/airbender-build-inputs.json

RUN chmod 0755 /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

# SYSCOIN: Match the tested GPU32 backend's CUDA ABI and SM120 compilation. A
# fresh normal service build is still required; the retained offline example is
# not installed or relabelled as this worker.
FROM nvidia/cuda:12.9.1-devel-ubuntu24.04@sha256:e542739fcaa4f45da5add8c4cf5769783a61628b2518304a5bbe4ace468b8c8f AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    CUDAARCHS=80;89;90;120 \
    PROVER_GPU_ROLE=snark \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/opt/cmake/bin:/usr/local/cargo/bin:${PATH}

WORKDIR /usr/src/zksync
COPY rust-toolchain.toml ./
COPY docker/prover-build-pins.json ./docker/prover-build-pins.json
COPY docker/install-build-toolchain.sh /usr/local/bin/install-build-toolchain
RUN chmod 0755 /usr/local/bin/install-build-toolchain && install-build-toolchain

COPY scripts/prepare-patched-gpu-backends.py scripts/prepare-patched-airbender.py ./scripts/
COPY patches ./patches
RUN python3 scripts/prepare-patched-gpu-backends.py --prepare-bellman /opt/bellman-cuda && \
    cmake -B/opt/bellman-cuda/build -S/opt/bellman-cuda \
      -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=OFF -DCMAKE_CUDA_ARCHITECTURES="${CUDAARCHS}" && \
    cmake --build /opt/bellman-cuda/build

COPY docker/fetch-verified-crs.sh /usr/local/bin/fetch-verified-crs
RUN chmod 0755 /usr/local/bin/fetch-verified-crs && fetch-verified-crs gpu-snark /setup_compact.key

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY multiblock_batch.bin multiblock_batch.text ./
COPY scripts/cargo-with-patched-airbender.sh scripts/prepare-patched-airbender.py ./scripts/
COPY patches ./patches

RUN BELLMAN_CUDA_DIR=/opt/bellman-cuda \
    AIRBENDER_BUILD_ATTESTATION=/usr/src/zksync/snark-airbender-build-inputs.json \
    bash scripts/cargo-with-patched-airbender.sh --gpu32 docker-snark -- \
    cargo build --locked --profile release --target x86_64-unknown-linux-gnu \
    -p zksync_os_snark_prover --bin zksync_os_snark_prover --features gpu

FROM nvidia/cuda:12.9.1-runtime-ubuntu24.04@sha256:1287141d283b8f06f45681b56a48a85791398c615888b1f96bfb9fc981392d98 AS gpu

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl libpq5 && \
    rm -rf /var/lib/apt/lists/*

COPY docker/zksync-os-prover-snark/entrypoint.sh /entrypoint.sh
COPY --from=builder /setup_compact.key /setup_compact.key
COPY --from=builder /usr/src/zksync/multiblock_batch.bin /multiblock_batch.bin
COPY --from=builder /usr/src/zksync/multiblock_batch.text /multiblock_batch.text
COPY --from=builder /usr/src/zksync/target/x86_64-unknown-linux-gnu/release/zksync_os_snark_prover /usr/bin/zksync_os_snark_prover
COPY --from=builder /usr/src/zksync/snark-airbender-build-inputs.json /usr/share/syscoin-prover/airbender-build-inputs.json

RUN chmod 0755 /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
