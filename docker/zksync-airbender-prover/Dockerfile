# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# SYSCOIN: Immutable base identity; build and runtime share CUDA 12.9 / Ubuntu 24.04 so the
# compiled glibc and CUDA ABI never run on an older image.
FROM nvidia/cuda:12.9.1-devel-ubuntu24.04@sha256:e542739fcaa4f45da5add8c4cf5769783a61628b2518304a5bbe4ace468b8c8f AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    CUDAARCHS=80;89;90;120 \
    PROVER_GPU_ROLE=combined \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/opt/cmake/bin:/usr/local/cargo/bin:${PATH}

WORKDIR /usr/src/zksync
COPY rust-toolchain.toml ./
COPY docker/prover-build-pins.json ./docker/prover-build-pins.json
COPY docker/install-build-toolchain.sh /usr/local/bin/install-build-toolchain
RUN chmod 0755 /usr/local/bin/install-build-toolchain && install-build-toolchain

# SYSCOIN: Exact tested GPU32 native postimages; never a mutable backend checkout.
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

# SYSCOIN: Match the locked GPU combined-service build published by release-bins.yml.
RUN BELLMAN_CUDA_DIR=/opt/bellman-cuda \
    AIRBENDER_BUILD_ATTESTATION=/usr/src/zksync/combined-airbender-build-inputs.json \
    bash scripts/cargo-with-patched-airbender.sh --gpu32 docker-combined -- \
    cargo build --locked --profile release \
    --target x86_64-unknown-linux-gnu -p zksync_os_prover_service \
    --bin zksync-os-prover-service --features gpu

FROM nvidia/cuda:12.9.1-runtime-ubuntu24.04@sha256:1287141d283b8f06f45681b56a48a85791398c615888b1f96bfb9fc981392d98

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl libpq5 && \
    rm -rf /var/lib/apt/lists/*

COPY docker/zksync-airbender-prover/entrypoint.sh /entrypoint.sh
COPY --from=builder /setup_compact.key /setup_compact.key
COPY --from=builder /usr/src/zksync/multiblock_batch.bin /multiblock_batch.bin
COPY --from=builder /usr/src/zksync/multiblock_batch.text /multiblock_batch.text
COPY --from=builder /usr/src/zksync/target/x86_64-unknown-linux-gnu/release/zksync-os-prover-service /usr/bin/zksync-airbender-prover
COPY --from=builder /usr/src/zksync/combined-airbender-build-inputs.json /usr/share/syscoin-prover/airbender-build-inputs.json

RUN chmod 0755 /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
