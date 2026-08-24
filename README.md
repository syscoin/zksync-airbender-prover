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
Generated proof submissions are persisted with their exact lease capability until the sequencer
returns the SYSCOIN application disposition contract described below.

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

**SYSCOIN security:** Never embed `username:password@` in `--sequencer-urls`; command arguments
are visible in shell history and process listings. For an authenticated deployment, store the full
HTTPS URL in an owner-only (`0600`) secret file and have the service manager load it into
`ZKSYNC_SEQUENCER_URLS`; omit `--sequencer-urls` entirely. The manual proof client accepts the
same pattern through `ZKSYNC_SEQUENCER_URL`. Environment injection avoids argv/history exposure,
while the secret file remains the durable source of authority.

Non-loopback plaintext `http://` endpoints fail closed by default, even with credentials. Use
HTTPS for every remote production sequencer. The
`--allow-insecure-sequencer-http` escape hatch is only for an isolated private container network
whose transport is protected outside this process; it must never be used across the public
internet.

Every production worker also owns an exclusively locked durable submission spool. FRI defaults to
`.zksync-prover-submissions/fri`; SNARK and combined workers default to
`<output-dir>/.pending-submissions`. Give each process its own `--submission-dir`. Files are
created mode `0600` inside a mode-`0700` directory and couple the sanitized endpoint identity,
stage/range, VK, opaque token, and exact encoded proof. On restart they replay before any new pick.
Responses 408/425/429, every 5xx (including proxy 520-524), and transport failures retry identical
bytes. A retained 401/403/404/redirect/config response fails the worker visibly and blocks all new
picks until configuration is corrected; it does not spin or discard the proof.
The spool is a dedicated directory: any unknown/non-UTF8 entry or unrecovered runtime temporary
record fails closed. Put no logs, notes, or unrelated artifacts in it. Crash durability assumes a
local Unix filesystem with reliable `flock`, same-filesystem atomic hard links, and file/directory
`fsync`; NFS, FUSE, object-backed mounts, and ephemeral container layers are unsupported unless
their equivalent semantics have been explicitly validated.

**SYSCOIN disposition contract:** a submission is retired only for `204` plus
`x-syscoin-prover-disposition: accepted`, or one of `400`, `409`, `413`, and `422` plus
`x-syscoin-prover-disposition: rejected`. The server must add this header only after the FRI/SNARK
manager reaches that exact terminal outcome. An unmarked response from a proxy, body limiter, JSON
extractor, or older server—including any generic 2xx/4xx—retains the envelope and fails closed.
Serialized submission bodies are rejected locally above the server's exact 10 MiB ceiling.

Note: the app program consists of the `.bin` file passed via `--app-bin-path` **and** its
`.text` sibling, which is resolved by replacing the extension (e.g. `multiblock_batch.bin`
+ `multiblock_batch.text`). Both files must be present; the prover refuses to start otherwise.

The standalone SNARK prover supports either the CPU backend (no `gpu` feature) or the GPU
backend (`--features gpu`). The canonical Syscoin layout below uses a dedicated CPU worker so
the three FRI GPUs stay resident. Plan 256 GiB of physical RAM for that worker (192 GiB is a
bring-up floor), do not rely on swap, and keep the initial server lease at two hours until a
production-size Security100 range is measured.

```bash
# optional - increase stack size to 300M (TODO: check if this could be lower)
ulimit -s 300000

# start the canonical CPU SNARK worker with a single sequencer
RUST_MIN_STACK=267108864 cargo run --release --no-default-features --bin zksync_os_snark_prover -- run-prover --sequencer-urls http://localhost:3124 --app-bin-path ./multiblock_batch.bin --trusted-setup-file crs/setup_compact.key --output-dir ./outputs

# start the canonical CPU SNARK worker with multiple sequencers
RUST_MIN_STACK=267108864 cargo run --release --no-default-features --bin zksync_os_snark_prover -- run-prover --sequencer-urls http://localhost:3124,http://localhost:3125,http://localhost:3126 --app-bin-path ./multiblock_batch.bin --trusted-setup-file crs/setup_compact.key --output-dir ./outputs
```

Specify optional `--iterations` argument to run SNARK prover N times and then exit.
The same timeout, decompression, and multi-sequencer scheduling rules described for the FRI
prover apply here.

### Canonical three-GPU FRI plus CPU SNARK deployment

<!-- SYSCOIN: Keep FRI residency separate from the server-leased CPU combine/wrap worker. -->
Use three standalone, permanently resident FRI workers and one standalone CPU SNARK worker on
a separate high-memory server. Expose exactly one GPU to each FRI process: Airbender enumerates
all visible CUDA devices, so leaving all three visible can allow one process to reserve the whole
machine. The CPU worker must not be built with `--features gpu`. All workers must use the same
generated Syscoin `multiblock_batch.bin` and `.text` artifacts.

```bash
mkdir -p output/fri-gpu0 output/fri-gpu1 output/fri-gpu2

CUDA_VISIBLE_DEVICES=0 cargo run --release --features gpu \
  --bin zksync_os_fri_prover -- \
  --sequencer-urls http://localhost:3124 \
  --app-bin-path ./multiblock_batch.bin \
  --prover-name syscoin-fri-gpu0 --prometheus-port 3210 \
  --submission-dir ./output/fri-gpu0/pending-submissions \
  --path ./output/fri-gpu0/fri_proof.json

CUDA_VISIBLE_DEVICES=1 cargo run --release --features gpu \
  --bin zksync_os_fri_prover -- \
  --sequencer-urls http://localhost:3124 \
  --app-bin-path ./multiblock_batch.bin \
  --prover-name syscoin-fri-gpu1 --prometheus-port 3211 \
  --submission-dir ./output/fri-gpu1/pending-submissions \
  --path ./output/fri-gpu1/fri_proof.json

CUDA_VISIBLE_DEVICES=2 cargo run --release --features gpu \
  --bin zksync_os_fri_prover -- \
  --sequencer-urls http://localhost:3124 \
  --app-bin-path ./multiblock_batch.bin \
  --prover-name syscoin-fri-gpu2 --prometheus-port 3212 \
  --submission-dir ./output/fri-gpu2/pending-submissions \
  --path ./output/fri-gpu2/fri_proof.json

# Run this process on the separate CPU server. No CUDA device is required or used.
mkdir -p output/snark-cpu
RUST_MIN_STACK=267108864 cargo run --release --no-default-features \
  --bin zksync_os_snark_prover -- run-prover \
  --sequencer-urls http://localhost:3124 \
  --app-bin-path ./multiblock_batch.bin \
  --trusted-setup-file crs/setup_compact.key \
  --output-dir ./output/snark-cpu \
  --prover-name syscoin-snark-cpu --prometheus-port 3213
```

The sequencer owns SNARK assignment and atomically leases one compatible range to one eligible
requester. A worker asks for work when ready; the server does not broadcast the same range to
every SNARK prover. In a decentralized pool this lease remains the single-work guarantee while
multiple compatible workers may request jobs. The CPU worker combines its assigned FRI range and
performs the wrapper entirely on CPU.

<!-- SYSCOIN: This section documents the downstream deployment and batching policy. -->
The workspace uses the exact upstream Matter Labs Airbender `v0.6.0-rc.2` graph, with no Syscoin
core fork. The sole supported lane is protocol V32 / Execution V7 / Proving V8. Every real SNARK
job must therefore contain at least two compatible FRI proofs; the
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
the reviewed Syscoin patch. `multiblock_batch.bin` is 1,323,208 bytes with SHA-256
`3eab56f061f330704fc90da98c5c3de9aef824842873fc2eb240475da5945d4a` and MD5
`5117d5dac6dbd34b93fef54e04d0b41c`; its paired `.text` is 1,193,676 bytes with SHA-256
`cd1c9b6679b97a47b24a71208d281b417a3cb714760fcf5b065896e6c6a84ce9`. Its Security100
program commitment is
`0x0d2bc42eeea78bfb08553eb9e18ee1efa4a97e199b5db62d9972e78924d28425`.

**This one is only needed if you want to manually upload.**

**SYSCOIN:** Pick artifacts contain live bearer authority, so the client creates them owner-only
and submit reads that authority from the saved job rather than exposing it on the command line.
Each artifact records the credential-free canonical endpoint that issued the lease, and submit
rejects an endpoint mismatch before opening the proof. Manual pick requires a current-user-owned
parent that is not group/world-writable. It holds a deterministic owner-only lock, leaves the final
name absent, and publishes by same-directory atomic no-replace hard link after file fsync. A stale
hidden `*.manual-pick.pending` file is retained for operator recovery and blocks another pick.
For authenticated remote use, load `ZKSYNC_SEQUENCER_URL` from an owner-only secret file and omit
`--url`; never place embedded Basic Auth credentials in the command itself.

```bash
# pick a FRI job manually into a fresh owner-only job file (existing files are not overwritten)
cargo run --release --bin zksync_sequencer_proof_client -- pick-fri --url http://localhost:3124 --path "./fri_job.json"
# submit using batch, VK, and private lease from the saved job; the proof stays a separate file
cargo run --release --bin zksync_sequencer_proof_client -- submit-fri --url http://localhost:3124 --job-path "./fri_job.json" --proof-path "./fri_proof.json"
# pick a SNARK job manually into a fresh owner-only job file
cargo run --release --bin zksync_sequencer_proof_client -- pick-snark --url http://localhost:3124 --path "./snark_job.json"
# submit using range, VK, and private lease from the saved job; the proof stays a separate file
cargo run --release --bin zksync_sequencer_proof_client -- submit-snark --url http://localhost:3124 --job-path "./snark_job.json" --proof-path "./snark_proof.json"
```

Pick refuses to overwrite an existing job file so a live lease cannot be lost accidentally.
Use `--path` to select a fresh pick file and pass that same file back with `--job-path`.

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
