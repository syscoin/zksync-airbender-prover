# ZKsync OS: Airbender Prover

This repo contains the Prover Service implementation for ZKsync OS Airbender prover.

## Overview

This repo contains 3 crates:

- sequencer_proof_client
- zksync_os_fri_prover
- zksync_os_snark_prover
- zksync_os_prover_service

### Sequencer Proof Client

Small HTTP wrapper around the Sequencer Prover API.
Apart from providing lib to use in provers, it also has a binary that acts as a CLI.
Useful for troubleshooting (i.e. manually pushing a SNARK proof to sequencer, instead of running the entire sequencer).

### ZKsync OS FRI Prover

The FRI prover for ZKsync OS. Retrieves proof input, proves a batch (which is a set of blocks) and submits it back to sequencer.
There's no state persisted in between.

### ZKsync OS SNARK Prover

SNARKs the final proof. Gets a set of continuous FRIs from sequencer, merges them into a single FRI, creates a FINAL proof out of it and then SNARKs it.

### ZKsync OS Prover Service

The ZKsync OS Prover Service alternates FRI and SNARK proving on one visible GPU. You can configure `max_snark_latency` and `max_fris_per_snark`; they have OR semantics.

### Usage

Before starting, make sure that your **sequencer** has fake proofs disabled:

```
prover_api_fake_fri_provers_enabled=false prover_api_fake_snark_provers_enabled=false
```

Before starting, please download the trusted setup file (see info in crs/README.md).

Sample usage for commands.

**This command currently requires a GPU (at least 24GB of VRAM)**

```bash
# start FRI prover with a single sequencer
cargo run --release --features gpu --bin zksync_os_fri_prover -- --sequencer-urls http://localhost:3124 --app-bin-path ./multiblock_batch.bin --path ./output/fri_proof.json

# start FRI prover with multiple sequencers
cargo run --release --features gpu --bin zksync_os_fri_prover -- --sequencer-urls http://localhost:3124,http://localhost:3125,http://localhost:3126 --app-bin-path ./multiblock_batch.bin --path ./output/fri_proof.json
```

Specify optional `--iterations` argument to run FRI prover N times and then exit.
Specify optional `--path` argument if you want to serialize FRI proof to file.
`--request-timeout-secs` controls the 600s total request backstop. Connect timeout is
5s and read inactivity timeout is 10s. Large compressed sequencer responses are decoded
automatically.
Specify `--sequencer-urls` to provide a comma-separated list. Status is probed concurrently
with a bounded fan-out and a two-second hint deadline; the oldest unassigned head is tried
first, and every client remains in the pick fallback if status is empty, slow, unavailable,
or unsupported.

Note: the app program consists of the `.bin` file passed via `--app-bin-path` **and** its
`.text` sibling, which is resolved by replacing the extension (e.g. `multiblock_batch.bin`
+ `multiblock_batch.text`). Both files must be present; the prover refuses to start otherwise.

**This command currently requires around 140 GB of RAM - and GPU**

```bash
# optional - increase stack size to 300M (TODO: check if this could be lower)
ulimit -s 300000

# start SNARK prover with a single sequencer
RUST_MIN_STACK=267108864 cargo run --release --features gpu --bin zksync_os_snark_prover -- run-prover --sequencer-urls http://localhost:3124 --trusted-setup-file crs/setup_compact.key --output-dir ./outputs

# start SNARK prover with multiple sequencers
RUST_MIN_STACK=267108864 cargo run --release --features gpu --bin zksync_os_snark_prover -- run-prover --sequencer-urls http://localhost:3124,http://localhost:3125,http://localhost:3126 --trusted-setup-file crs/setup_compact.key --output-dir ./outputs
```

Specify optional `--iterations` argument to run SNARK prover N times and then exit.
The same timeout, decompression, and multi-sequencer scheduling rules described for the FRI
prover apply here.

### Canonical three-GPU deployment

Use two standalone FRI workers and one standalone SNARK worker. Expose exactly one GPU to
each process: Airbender enumerates all visible CUDA devices, so leaving all three visible can
allow one process to reserve the whole machine. All workers must use the same generated
Syscoin `multiblock_batch.bin` and `.text` artifacts.

```bash
mkdir -p output/fri-gpu0 output/fri-gpu1 output/snark-gpu2

CUDA_VISIBLE_DEVICES=0 cargo run --release --features gpu \
  --bin zksync_os_fri_prover -- \
  --sequencer-urls http://localhost:3124 \
  --app-bin-path ./multiblock_batch.bin \
  --prover-name syscoin-fri-gpu0 --prometheus-port 3210 \
  --path ./output/fri-gpu0/fri_proof.json

CUDA_VISIBLE_DEVICES=1 cargo run --release --features gpu \
  --bin zksync_os_fri_prover -- \
  --sequencer-urls http://localhost:3124 \
  --app-bin-path ./multiblock_batch.bin \
  --prover-name syscoin-fri-gpu1 --prometheus-port 3211 \
  --path ./output/fri-gpu1/fri_proof.json

CUDA_VISIBLE_DEVICES=2 RUST_MIN_STACK=267108864 cargo run --release \
  --features gpu \
  --bin zksync_os_snark_prover -- run-prover \
  --sequencer-urls http://localhost:3124 \
  --app-bin-path ./multiblock_batch.bin \
  --trusted-setup-file crs/setup_compact.key \
  --output-dir ./output/snark-gpu2 \
  --prover-name syscoin-snark-gpu2 --prometheus-port 3212
```

The workspace uses the exact upstream Matter Labs Airbender `v0.6.0-rc.2` graph, with no Syscoin
core fork. Every real SNARK job must therefore contain at least two compatible FRI proofs; the
prover fails before merge or wrapper setup if the server violates that contract. Fake FRI and
SNARK provers must be off. For the dedicated SNARK worker, batching readiness is authoritative on
the server: target 100 FRIs and release an older compatible range after 3600 seconds, but never
release fewer than two. The combined-service flags below do not control this worker. Queue
`/status` does not expose that readiness, so an adaptive local threshold (the old value was 80)
must not be used to switch early and churn on an unavailable SNARK job.

Rare upgrade or security boundaries need a second real, same-VK proof. Before activating such a
boundary, operators must ensure that a second same-VK batch is actually sealed and committed; an
intentionally empty real batch is one option, but this repository does not automate creating it.
Otherwise the range waits. A future upstream Airbender API could instead add an output-preserving
extra unified pass before a singleton is wrapped. Duplicating a proof is not valid: stock
aggregation hashes every input and would change the settlement public output.

The release names belong to different repositories: `v0.6.0-rc.2` is the pinned Airbender proving
stack, while the checked-in Syscoin guest below is based on final `zksync-os v0.4.0`.

The canonical record already contains the patched Syscoin app MD5 and Security100 program
commitment. Its VK is deliberately a zero regeneration sentinel, so the binaries fail closed
until production keygen supplies the app-bound VK and it is updated atomically with the server
and Era verifier constants.

The checked-in guest is built reproducibly from final `zksync-os v0.4.0` (`69bc4305...`) plus
the reviewed Syscoin patch. `multiblock_batch.bin` is 1,324,616 bytes with SHA-256
`20fe50c9840cc7ff872cc1f190e320b4595e006c56a385b10a0e10bbba712f19`; its paired `.text`
is 1,195,064 bytes with SHA-256
`462cc621c6d44b4a04b8455f0ddeebc8269234817b85dbaebefdaba88c67bf07`.

**This one is only needed if you want to manually upload.**

```bash
# pick a FRI job manually and serialize to file specified in `--path`
cargo run --release --bin zksync_sequencer_proof_client -- pick-fri --url http://localhost:3124 --path "./fri_job.json"
# submit a FRI proof specified in `--path` manually to sequencer
cargo run --release --bin zksync_sequencer_proof_client -- submit-fri --batch-number 1 --url http://localhost:3124 --path "./fri_proof.json"
# pick a SNARK job manually and serialize to file specified in `--path`
cargo run --release --bin zksync_sequencer_proof_client -- pick-snark --url http://localhost:3124 --path "./snark_job.json"
# submit a SNARK proof specified in `--path` manually to sequencer
cargo run --release --bin zksync_sequencer_proof_client -- submit-snark --from-batch-number 1 --to-batch-number 2 --url http://localhost:3124 --path "./snark_proof.json"
```

Specify --path argument to override default location.

**This command starts ZKsync OS Prover Service**

```bash
# optional - increase stack size to 300M (TODO: check if this could be lower)
ulimit -s 300000

# start prover service
RUST_MIN_STACK=267108864 cargo run --release --features gpu --bin zksync_os_prover_service -- --base-url http://localhost:3124 --app-bin-path ./multiblock_batch.bin --trusted-setup-file crs/setup_compact.key --output-dir ./outputs --max-snark-latency 3600 --max-fris-per-snark 100
```

Specify optional `--iterations` argument to run SNARK prover N times and then exit.
`--max-snark-latency` and `--max-fris-per-snark` may be supplied together. The combined
service exits its FRI phase when either threshold is reached (by default, 3600 seconds OR
100 locally produced FRI proofs). These are local phase controls, not the dedicated SNARK
worker's server-side batching readiness policy.
Specify `--snark-acquire-timeout-secs` to return to FRI proving if no SNARK job becomes available after switching modes.

## Development / WIP

- Add information on how to setup GPU for snark wraper

## FAQ

If you get the error like `cargo::rustc-check-cfg=cfg(no_cuda)` during compilation, you might have to install
Bellman Cuda (see instructions below).

## Installing bellman-cuda

```shell
git clone https://github.com/matter-labs/era-bellman-cuda.git --branch main bellman-cuda && \
cmake -Bbellman-cuda/build -Sbellman-cuda/ -DCMAKE_BUILD_TYPE=Release && \
cmake --build bellman-cuda/build/
```

And then:

```shell
export BELLMAN_CUDA_DIR=...
```

## Policies

- [Security policy](SECURITY.md)
- [Contribution policy](CONTRIBUTING.md)

## License

ZKsync OS repositories are distributed under the terms of either

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/blog/license/mit/>)

at your option.

## Official Links

- [Website](https://zksync.io/)
- [GitHub](https://github.com/matter-labs)
- [ZK Credo](https://github.com/zksync/credo)
- [Twitter](https://twitter.com/zksync)
- [Twitter for Developers](https://twitter.com/zkSyncDevs)
- [Discord](https://join.zksync.dev/)
- [Mirror](https://zksync.mirror.xyz/)
- [Youtube](https://www.youtube.com/@zksync-io)
