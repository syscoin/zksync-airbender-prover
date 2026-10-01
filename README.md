# ZKsync OS: Airbender Prover

This repo contains the Prover Service implementation for ZKsync OS Airbender prover.

## Overview

This repo contains 4 service crates:

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

FRI does not need a trusted setup file. For SNARK proving, download the verified CRS for the
chosen backend: Security100 CPU uses `crs/setup_2^25.key`, while GPU SNARK / the combined service use
`crs/setup_compact.key`. These serializations are not interchangeable; see [CRS instructions](crs/README.md).

Sample usage for commands.

Use `-p` to select the worker package as well as `--bin`: selecting only a binary at the
workspace root can unify other workers' GPU features and pull the SNARK CUDA backend into FRI.
The isolated FRI GPU worker does not require `BELLMAN_CUDA_DIR`; GPU SNARK and combined workers do.

Use the checked-in Cargo wrapper shown below for worker builds and runs. FRI and explicit CPU
builds retain the pinned diagnostic-only Airbender patch. GPU SNARK and combined builds select
`--gpu32`, additionally applying the tested memory patches to pinned crypto-GPU and Bellman CUDA
sources in disposable copies. It audits the complete lock overlay and leaves artifacts under
the usual `target/` directory. Python 3.11+ or Python 3 with
the distribution's `python3-tomli` package is required. Direct `cargo` worker builds omit this fix;
see [build overlay and provenance](docs/airbender-build-overlay.md).

FRI requires a CUDA GPU. Airbender selects a bounded arena from available VRAM; the
current V32 service validation used a 32 GiB RTX 5090. Physical 24 GiB operation is not
qualified by that run, and arena capacity is not a guarantee of total process VRAM.

```bash
# start FRI prover with a single sequencer
bash scripts/cargo-with-patched-airbender.sh fri-run -- cargo run --locked --release -p zksync_os_fri_prover --features gpu --bin zksync_os_fri_prover -- --sequencer-urls http://localhost:3124 --app-bin-path ./multiblock_batch.bin --submission-dir "$PWD/output/fri-submissions" --path ./output/fri_proof.json

# start FRI prover with multiple sequencers
bash scripts/cargo-with-patched-airbender.sh fri-run -- cargo run --locked --release -p zksync_os_fri_prover --features gpu --bin zksync_os_fri_prover -- --sequencer-urls http://localhost:3124,http://localhost:3125,http://localhost:3126 --app-bin-path ./multiblock_batch.bin --submission-dir "$PWD/output/fri-submissions" --path ./output/fri_proof.json
```

Specify optional `--iterations` argument to run FRI prover N times and then exit.
Specify optional `--path` argument if you want to serialize FRI proof to file.
`--request-timeout-secs` controls the 600s total request backstop. Connect timeout is
5s and read inactivity timeout is 10s. Large compressed sequencer responses are decoded
automatically.
**SYSCOIN:** The worker advertises its current 384 MiB complete decompressed FRI-pick capacity;
the sequencer conservatively filters complete base64/JSON size before leasing, and the client
reuses the advertised scalar as its streaming read bound. This is a deployment capacity gate, not
a canonical V8 input bound. Raising it requires raising the worker, sequencer clamp, and
trusted-proxy spool together.
Authority-free FRI peeks remain independently capped at 64 MiB, while queue/failed-proof
diagnostics and SNARK aggregate responses retain their class-specific defensive bounds.
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

Every production worker also owns an exclusively locked durable submission spool. Give each
process its own explicit absolute `--submission-dir`; relative paths are rejected so a service
manager working-directory change cannot silently abandon a retained proof. Files are
created mode `0600` inside a mode-`0700` directory and couple the sanitized endpoint identity,
stage/range, VK, opaque token, and exact encoded proof. On restart they replay before any new pick.
Responses 408/425/429, every 5xx (including proxy 520-524), and transport failures retry identical
bytes. A retained 401/403/404/redirect/config response fails the worker visibly and blocks all new
picks until configuration is corrected; it does not spin or discard the proof.
The spool is a dedicated directory: any unknown/non-UTF8 entry or unrecovered runtime temporary
record fails closed. Put no logs, notes, or unrelated artifacts in it. Crash durability assumes a
local Unix filesystem with reliable `flock`, atomic rename, and file/directory
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

The standalone SNARK prover defaults to the GPU backend. Build it through `--gpu32` and use
the compact GPU CRS; GPU errors fail the worker rather than silently switching to CPU.
`--no-default-features` explicitly selects the separate CPU fallback and its full CPU CRS.
Only that CPU binary accepts `--wrapper-cache-policy cpu-cold`; GPU builds use `warm` and reject
`cpu-cold`. The validated serial CPU mock workflow admitted 235 GiB of effective
host RAM with a 32 GiB runtime reserve on a 256 GiB host, with no swap. This is a tested
admission policy, not a guarantee for larger ranges or concurrent FRI/SNARK jobs.
See [CPU-cold cache ownership and input checks](CPU_COLD_CACHE.md).

```bash
# optional - increase stack size to 300M (TODO: check if this could be lower)
ulimit -s 300000

# start the default GPU SNARK worker with a single sequencer
RUST_MIN_STACK=267108864 bash scripts/cargo-with-patched-airbender.sh --gpu32 snark-run -- cargo run --locked --release -p zksync_os_snark_prover --features gpu --bin zksync_os_snark_prover -- run-prover --sequencer-urls http://localhost:3124 --app-bin-path ./multiblock_batch.bin --trusted-setup-file crs/setup_compact.key --output-dir ./outputs --submission-dir "$PWD/output/snark-submissions"

# start the default GPU SNARK worker with multiple sequencers
RUST_MIN_STACK=267108864 bash scripts/cargo-with-patched-airbender.sh --gpu32 snark-run -- cargo run --locked --release -p zksync_os_snark_prover --features gpu --bin zksync_os_snark_prover -- run-prover --sequencer-urls http://localhost:3124,http://localhost:3125,http://localhost:3126 --app-bin-path ./multiblock_batch.bin --trusted-setup-file crs/setup_compact.key --output-dir ./outputs --submission-dir "$PWD/output/snark-submissions"

# explicit CPU fallback: choose this before acquiring a job, not after a GPU error
RUST_MIN_STACK=267108864 bash scripts/cargo-with-patched-airbender.sh snark-cpu-run -- cargo run --locked --release -p zksync_os_snark_prover --no-default-features --bin zksync_os_snark_prover -- run-prover --wrapper-cache-policy cpu-cold --sequencer-urls http://localhost:3124 --app-bin-path ./multiblock_batch.bin --trusted-setup-file 'crs/setup_2^25.key' --output-dir ./outputs --submission-dir "$PWD/output/snark-cpu-submissions"
```

Specify optional `--iterations` argument to run SNARK prover N times and then exit.
The same timeout, decompression, and multi-sequencer scheduling rules described for the FRI
prover apply here.

### Separate FRI and default GPU SNARK deployment

<!-- SYSCOIN: Keep FRI residency separate from the server-leased combine/wrap worker. -->
Use three standalone, permanently resident FRI workers and a dedicated GPU SNARK worker on
a separate GPU/high-memory server. Expose exactly one GPU to each process: Airbender enumerates
all visible CUDA devices, so leaving all three visible can allow one process to reserve the whole
machine. Do not overlap FRI and SNARK on one GPU. The explicit CPU fallback must not be built
with `--features gpu`. All workers must use the same
generated Syscoin `multiblock_batch.bin` and `.text` artifacts.

```bash
mkdir -p output/fri-gpu0 output/fri-gpu1 output/fri-gpu2

CUDA_VISIBLE_DEVICES=0 bash scripts/cargo-with-patched-airbender.sh fri-run -- cargo run --locked --release -p zksync_os_fri_prover --features gpu \
  --bin zksync_os_fri_prover -- \
  --sequencer-urls http://localhost:3124 \
  --app-bin-path ./multiblock_batch.bin \
  --prover-name syscoin-fri-gpu0 --prometheus-port 3210 \
  --submission-dir "$PWD/output/fri-gpu0/pending-submissions" \
  --path ./output/fri-gpu0/fri_proof.json

CUDA_VISIBLE_DEVICES=1 bash scripts/cargo-with-patched-airbender.sh fri-run -- cargo run --locked --release -p zksync_os_fri_prover --features gpu \
  --bin zksync_os_fri_prover -- \
  --sequencer-urls http://localhost:3124 \
  --app-bin-path ./multiblock_batch.bin \
  --prover-name syscoin-fri-gpu1 --prometheus-port 3211 \
  --submission-dir "$PWD/output/fri-gpu1/pending-submissions" \
  --path ./output/fri-gpu1/fri_proof.json

CUDA_VISIBLE_DEVICES=2 bash scripts/cargo-with-patched-airbender.sh fri-run -- cargo run --locked --release -p zksync_os_fri_prover --features gpu \
  --bin zksync_os_fri_prover -- \
  --sequencer-urls http://localhost:3124 \
  --app-bin-path ./multiblock_batch.bin \
  --prover-name syscoin-fri-gpu2 --prometheus-port 3212 \
  --submission-dir "$PWD/output/fri-gpu2/pending-submissions" \
  --path ./output/fri-gpu2/fri_proof.json

# Run this process on the separate GPU SNARK server.
mkdir -p output/snark-gpu
CUDA_VISIBLE_DEVICES=0 RUST_MIN_STACK=267108864 bash scripts/cargo-with-patched-airbender.sh --gpu32 snark-run -- cargo run --locked --release -p zksync_os_snark_prover --features gpu \
  --bin zksync_os_snark_prover -- run-prover \
  --sequencer-urls http://localhost:3124 \
  --app-bin-path ./multiblock_batch.bin \
  --trusted-setup-file crs/setup_compact.key \
  --output-dir ./output/snark-gpu \
  --submission-dir "$PWD/output/snark-gpu/pending-submissions" \
  --prover-name syscoin-snark-gpu --prometheus-port 3213
```

The sequencer owns SNARK assignment and atomically leases one compatible range to one eligible
requester. A worker asks for work when ready; the server does not broadcast the same range to
every SNARK prover. In a decentralized pool this lease remains the single-work guarantee while
multiple compatible workers may request jobs. The GPU worker combines its assigned FRI range
and uses the GPU backend for the three wrapper proof phases; host witness generation, synthesis
and verification still run. The offline 30 GiB result covers final phase 3 only, not this full
service pipeline or a larger range.

The default `docker/zksync-os-prover-snark/Dockerfile` target is `gpu`; `--target cpu` explicitly
builds the CPU image. Release archives distinguish `zksync_os_snark_prover-...-gpu.tar.gz`
(default) from `...-cpu.tar.gz` (fallback), each with its own successful build-input record.
Build and resource admission must be requalified for the selected backend before running it.

<!-- SYSCOIN: This section documents the downstream deployment and batching policy. -->
The workspace retains the upstream Matter Labs Airbender `v0.6.0-rc.2` versions and proving code.
The build wrapper preserves the pinned startup-diagnostic compatibility patch; `--gpu32` adds
the exact tested memory placement/setup changes without weakening proof checks or changing guest
artifacts. The sole supported lane is protocol V32 / Execution
V7 / Proving V8. Every real SNARK
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

This V32 source integration binds the generated Syscoin app MD5, Security100 program
commitment and app-bound VK `0xc1ab3d6506620ad299672c2c2530e8732ac7bae55cdb9d8cf1fa12355b7388fe`.
The zero-VK rejection and all other production identity checks remain intact. Genuine
FRI and CPU SNARK service proofs, native verification and canonical DA/commit/prove/execute
receipts have been observed for an 11-batch mock frontier. Those retained results validate
the tested source snapshot, not a newly built release commit or production deployment.
Sustained throughput/drain, migration, asset-bridge and recovery gates remain pending,
and server/Era/prover identities must be rolled out together before a public cutover.

The GPU32 memory optimization passed an offline final-wrapper experiment with the same
Security100 VK: 303.82 seconds end to end, 29.91 GiB sampled GPU memory and 43.61 GiB sampled
host RSS on an RTX5090. This source now integrates its pinned Bellman CUDA and crypto-GPU
overlays into the default SNARK/combined build recipes. A new ordinary service build,
full-range service acceptance, native/DA/settlement verification and sustained performance
are still required; the retained offline binary/proof is not a service qualification or a
claim of an instantaneous memory peak or other hardware support.

The guest is built reproducibly from final `zksync-os v0.4.0` (`69bc4305...`) plus
the reviewed Syscoin patch, source tree `6935489bdbc7b1ed31e608677d1b2418b10691b5`.
`multiblock_batch.bin` is 1,329,732 bytes with SHA-256
`0d69bb7bc5207041c737def52d8858bab261b2ccf0afadbf2ceed14aa86d7cf6` and MD5
`1bc285f1bbde995134d483c4e75ee204`; its paired `.text` is 1,200,064 bytes with SHA-256
`9d999d91bc7422488c58cf6ca1f7f5041c2972065592ffe98bfcb8220ff0009a`. Its Security100
program commitment is
`0x1be0999eb16ad9235efc3c320a750afa496f7ee4cb9474926decbd539eeea674`.
Only the paired runtime `multiblock_batch.bin` and `.text` are promoted here; duplicate
ELF/guest-artifact outputs and task-local provenance are not release inputs. Rebuilding
this draft must produce a new build attestation; retained candidate binary attestations
must not be relabelled with the release commit.

**This one is only needed if you want to manually upload.**

**SYSCOIN:** Pick artifacts contain live bearer authority, so the client creates them owner-only
and submit reads that authority from the saved job rather than exposing it on the command line.
Each artifact records the credential-free canonical endpoint that issued the lease, and submit
rejects an endpoint mismatch before opening the proof. Manual pick requires a current-user-owned
parent that is not group/world-writable. Before the lease-changing request it creates the final
artifact with no-overwrite mode `0600`, fsyncs the empty file and parent directory, and therefore
uses that visible name as the reservation. An explicit no-job response removes and directory-fsyncs
the reservation. Once the request can begin, any request error, crash, serialization failure, or
sync failure retains the empty, partial, or complete artifact and blocks another pick; inspect it
and remove it only after the possible lease has expired. A successful pick writes and fsyncs the
complete endpoint-bound job into that same reserved file. Proof input is separate, but must be
current-user-owned and not group/world-writable so substituted bytes cannot consume the leased
attempt.
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
RUST_MIN_STACK=267108864 bash scripts/cargo-with-patched-airbender.sh --gpu32 combined-run -- cargo run --locked --release -p zksync_os_prover_service --features gpu --bin zksync-os-prover-service -- --base-url http://localhost:3124 --app-bin-path ./multiblock_batch.bin --trusted-setup-file crs/setup_compact.key --output-dir ./outputs --submission-dir "$PWD/output/combined-submissions" --max-snark-latency 3600 --max-fris-per-snark 100
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
# SYSCOIN: Exact GPU32 source postimages and source record; choose a fresh destination.
python3 scripts/prepare-patched-gpu-backends.py --prepare-bellman "$PWD/bellman-cuda" && \
cmake -Bbellman-cuda/build -Sbellman-cuda/ -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=OFF -DCMAKE_CUDA_ARCHITECTURES='80;89;90;120' && \
cmake --build bellman-cuda/build/
```

And then:

```shell
export BELLMAN_CUDA_DIR="$PWD/bellman-cuda"
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
