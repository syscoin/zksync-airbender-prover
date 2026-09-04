# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# SYSCOIN: The independently scalable SNARK worker is the release-bins CPU lane; GPU FRI and
# combined roles retain CUDA separately. Both stages use the same immutable glibc base.
FROM ubuntu:22.04@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc AS builder

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
RUN chmod 0755 /usr/local/bin/fetch-verified-crs && fetch-verified-crs /setup_compact.key

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY multiblock_batch.bin multiblock_batch.text ./

# SYSCOIN: Match the hardened release topology: CPU-only wrapping, without the GPU feature.
RUN cargo build --locked --profile release --target x86_64-unknown-linux-gnu \
    --bin zksync_os_snark_prover --no-default-features

FROM ubuntu:22.04@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl libpq5 && \
    rm -rf /var/lib/apt/lists/*

COPY docker/zksync-os-prover-snark/entrypoint.sh /entrypoint.sh
COPY --from=builder /setup_compact.key /setup_compact.key
COPY --from=builder /usr/src/zksync/multiblock_batch.bin /multiblock_batch.bin
COPY --from=builder /usr/src/zksync/multiblock_batch.text /multiblock_batch.text
COPY --from=builder /usr/src/zksync/target/x86_64-unknown-linux-gnu/release/zksync_os_snark_prover /usr/bin/zksync_os_snark_prover

RUN chmod 0755 /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
