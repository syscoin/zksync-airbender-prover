# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# SYSCOIN: Immutable base identity; build and runtime share CUDA 12.9 / Ubuntu 24.04 so the
# compiled glibc and CUDA ABI never run on an older image.
FROM nvidia/cuda:12.9.1-cudnn-devel-ubuntu24.04@sha256:a2e1e2360c85298ac47ec2543b406ab1e8cec42e31ee47e4d32140ebc82e1067 AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    CUDAARCHS=80;89;90 \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/opt/cmake/bin:/usr/local/cargo/bin:${PATH}

WORKDIR /usr/src/zksync
COPY rust-toolchain.toml ./
COPY docker/prover-build-pins.json ./docker/prover-build-pins.json
COPY docker/install-build-toolchain.sh /usr/local/bin/install-build-toolchain
RUN chmod 0755 /usr/local/bin/install-build-toolchain && install-build-toolchain

# SYSCOIN: Exact CUDA backend used by release-bins.yml; no mutable branch checkout.
RUN bellman_repository="$(jq -er '.bellman_cuda.repository' docker/prover-build-pins.json)" && \
    bellman_commit="$(jq -er '.bellman_cuda.commit' docker/prover-build-pins.json)" && \
    git clone --no-tags "${bellman_repository}" /opt/bellman-cuda && \
    git -C /opt/bellman-cuda checkout --detach "${bellman_commit}" && \
    test "$(git -C /opt/bellman-cuda rev-parse HEAD)" = "${bellman_commit}" && \
    cmake -B/opt/bellman-cuda/build -S/opt/bellman-cuda -DCMAKE_BUILD_TYPE=Release && \
    cmake --build /opt/bellman-cuda/build

COPY docker/fetch-verified-crs.sh /usr/local/bin/fetch-verified-crs
RUN chmod 0755 /usr/local/bin/fetch-verified-crs && fetch-verified-crs /setup_compact.key

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY multiblock_batch.bin multiblock_batch.text ./

# SYSCOIN: Match the locked GPU combined-service build published by release-bins.yml.
RUN BELLMAN_CUDA_DIR=/opt/bellman-cuda cargo build --locked --profile release \
    --target x86_64-unknown-linux-gnu --bin zksync-os-prover-service --features gpu

FROM nvidia/cuda:12.9.1-runtime-ubuntu24.04@sha256:1287141d283b8f06f45681b56a48a85791398c615888b1f96bfb9fc981392d98

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl libpq5 && \
    rm -rf /var/lib/apt/lists/*

COPY docker/zksync-airbender-prover/entrypoint.sh /entrypoint.sh
COPY --from=builder /setup_compact.key /setup_compact.key
COPY --from=builder /usr/src/zksync/multiblock_batch.bin /multiblock_batch.bin
COPY --from=builder /usr/src/zksync/multiblock_batch.text /multiblock_batch.text
COPY --from=builder /usr/src/zksync/target/x86_64-unknown-linux-gnu/release/zksync-os-prover-service /usr/bin/zksync-airbender-prover

RUN chmod 0755 /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
