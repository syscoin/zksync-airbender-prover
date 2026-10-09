# Prover-owned GPU rentals

The prover operator runs the rental controller on a trusted machine. New
supervisor examples enable Runpod Serverless with FlashBoot for FRI. A worker
prepares the compiled CUDA prover before accepting requests, processes one job at
a time, then scales to zero after five idle seconds. Runpod may retain the
initialized process and GPU state for the next request. Eviction still requires
a cold start from the published image; FlashBoot is a best-effort cache.

SNARK jobs use the existing rented Pods and their independent watchdog. The local
supervisor remains running to submit work as it arrives. Multiple supervisors
can share provider directories and their limits. Each Serverless controller
allows one unresolved FRI attempt at a time; its endpoint permits one GPU worker.
With Serverless FRI enabled, an unused SNARK Pod keeps its own idle timer and
can stop while a FRI job is still running. Successful empty SNARK polls establish
that timer; FRI activity does not reset it.

`supervisor.py` is the continuous runner. It checks actual SNARK job claims before
FRI work, retains exact lease and submission state locally, and never interprets
an endpoint failure as an empty queue. `runpod.py watchdog` runs independently and
enforces the Pods session deadline even if the supervisor exits. Ambiguous
allocation is reconciled without repeating a create request. Serverless requests
carry provider execution/queue limits and an absolute worker deadline; an
uncertain POST is retained without repeating the request.

Workers claim asynchronously and retain only one outstanding job. A busy worker
does not reserve a backlog, so other polling workers can claim distinct available
jobs. Faster workers may complete more jobs; the scheduler does not wait for every
worker to finish a numbered round or promise equal counts.

The existing reusable Pods image keeps one FRI prover process alive across consecutive FRI jobs
inside the rented pod, preserving its process-local setup cache. It finishes the
current proof before switching stages, then stops and reaps the FRI process before
starting the standalone SNARK worker. A later FRI job starts a fresh FRI process.
FRI caches are also released on stop, fatal error or session expiry; a guardian
terminates native compute if the pod adapter dies. Proofs and the pod journal are
durable before local acknowledgement, and result-upload retries reuse those exact
bytes. The coordinator holds orchestration state; proving caches live in the pod.
The idle grace and provider watchdog still bound the rental lifetime.
On Linux, the guardian retains worker ownership until the kernel confirms every
adopted child has been reaped; unavailable process metadata keeps replacement
workers blocked while cleanup retries.

Provider credentials, object-store credentials, sequencer credentials, real leases
and signing keys remain on the operator's machine. Pods see session mailbox
capabilities and authenticated commands; Serverless workers receive individual
hash-bound inputs and scoped claim/result URLs. Every completed result is durably collected before its exact
native submission or external service handoff. A transport receipt is not proof
verification or service credit.

## Runtime and configuration

Use Python 3.10+ on Unix with durable local storage. The native one-job/pool tools
use the standard library; automatic S3-compatible storage plans additionally need
`requirements-controller.txt`. All CLI mutations remain dry-run unless `--execute` is given.
Hardware, CUDA, images, runtime and price limits are explicit operator choices in
`policy.example.json` and `serverless-policy.example.json`; placeholders deliberately fail validation. Qualify both
stages on the selected GPU and allow for cold setup, upload and submission before
a lease or selected wrapper turn expires.

The default `supervisor-config.example.json` selects `decentralized-service`:
it reads this prover's private pools of assigned duties and rejects direct native
queue credentials. FRI assignments retain the dispatcher's signed readiness,
one-outstanding-duty and quota rules; SNARK duties retain the selected wrapper
permit. This does not make the bare native queue enforce service membership.

For direct compute using authorized native queue access, use
`supervisor-native-config.example.json` and its `native-compute` mode. Its workers
all poll and receive distinct leased jobs as capacity becomes free. This mode
does not create service assignments or award decentralized participation credit.

Both supervisor examples set `serverless_fri.enabled` to `true`. To use the
existing Pods workflow for both stages, replace that block with
`"serverless_fri": {"enabled": false}` before initialization. This opt-out retains
the Pods idle grace and starts a new Pod after the previous one has stopped.
Saved configurations that omit the block keep their existing behavior. Backend
settings are frozen at initialization: drain and reconcile an existing runner
before creating replacement supervisor state; do not edit its journal to switch.

Copy the appropriate example to a private operator file. Initialize the
shared Pods policy and separate Serverless policy before the supervisor, then validate the supervisor config
without `--execute`. The provider state and each supervisor state must be distinct
absolute paths, created on durable local storage with private permissions.

```sh
python3 -m pip install -r scripts/prover-rental/requirements-controller.txt

python3 scripts/prover-rental/runpod.py --state-dir /secure/prover/provider \
  --execute init --config /secure/prover/policy.json

python3 scripts/prover-rental/serverless.py --state-dir /secure/prover/serverless-fri \
  --execute init --policy /secure/prover/serverless-policy.json
python3 scripts/prover-rental/serverless.py --state-dir /secure/prover/serverless-fri \
  --execute validate-endpoint

python3 scripts/prover-rental/supervisor.py --state-dir /secure/prover/worker-1 \
  init --config /secure/prover/supervisor.json
python3 scripts/prover-rental/supervisor.py --state-dir /secure/prover/worker-1 \
  --execute init --config /secure/prover/supervisor.json
```

Skip the two Serverless commands when opting out. Point the enabled supervisor
block at the initialized Serverless state directory. For assigned external FRI
duties, the pool's FRI image policy must match the Serverless adapter image; the
existing duty ownership and readiness checks still apply.

Run these two processes under separate service-manager units on the trusted host.
Load `RUNPOD_API_KEY` and S3 credentials through private service environment files
or the configured AWS profile. Do not put keys on command lines or in the image.

```sh
python3 scripts/prover-rental/runpod.py --state-dir /secure/prover/provider \
  --execute watchdog
python3 scripts/prover-rental/supervisor.py --state-dir /secure/prover/worker-1 \
  --execute run
```

`run --once` performs one scheduler pass. `status` prints identifiers and states
without credentials or object URLs. `--execute recover` retries retained work
without acquiring another job. `--execute drain` requests that the running
supervisor finish its current job and stop its session; keep the watchdog running
until provider deletion is confirmed. Stopping a local process alone does not
delete a remote pod. Serverless scales down through the endpoint's idle timeout;
keep its maximum worker count at one. Setting it to zero pauses requests instead
of providing normal scale-to-zero operation.

The Serverless journal reserves the configured `max_operation_usd` before its
single submission and retains that charge after completion. Set an operator
qualified upper hourly rate and reserve at least that rate multiplied by
`(max_runtime_seconds + result_retention_seconds + startup_timeout_seconds + 10 + idle_timeout_seconds) / 3600`.
The startup allowance must cover the image's 600-second initialization cap;
another ten seconds cover native cleanup.
These admission limits use that rate assumption; Runpod controls infrastructure
startup, teardown and billing. They are not a provider-enforced dollar cap.
Runpod retains async results for a fixed 30 minutes after completion, independently
of request TTL. The legacy-named `result_retention_seconds` policy field (at least
1,800 seconds) adds TTL padding; it does **not** configure that retention period.
Neither padding nor reconciliation extends the worker's absolute computation
deadline or its lease.

For an acknowledged run, the journal retains its exact TTL/execution timeout and
the response-received time (an upper bound on provider acceptance). A fresh status
404 may close only the provider side after that anchor plus TTL, execution timeout,
startup allowance, ten seconds of cleanup, and idle timeout. This deliberately
conservative wait relies on Runpod's documented lifetime/execution bounds and the
trusted host clock. It is not new spending or execution authority. The observed
status remains `ABSENT`, with separate immutable closure evidence; no provider
completion or proof verification is invented. Observed queued/running work after
that bound permanently disables the 404 fallback for that operation; a genuine
terminal response can still reconcile it. The first closure/counterevidence is
retained across restarts. Older known-ID journals start a fresh observation anchor
and wait the full maximum policy bounds. Unknown POSTs
without a run ID remain blocked. Source-lease/submission reconciliation and durable
proof checks still apply, and lifetime reservations are never refunded.
See Runpod's [TTL and result-retention documentation](https://docs.runpod.io/serverless/endpoints/send-requests#ttl-vs-execution-timeout).

Each Serverless attempt conditionally creates one durable object-store claim.
Repeated deliveries and conflicting workers cannot both compute that attempt;
the same handler retries transient publication failures using retained proof
bytes, with readback after an ambiguous upload and no repeated computation.
The original absolute lease deadline bounds initialization, proving and uploads.
Initialization has its own 600-second allowance; the configured proving allowance
starts after setup. A restored session without enough remaining lifetime is
reaped and replaced before admitting native work. Interrupted local cleanup can
recover only against the matching complete remote claim, proof and receipt.
A failed or unknown execution is kept for reconciliation rather than silently
recomputed. A missing Runpod status is
not evidence that its worker stopped. If a POST response was lost but the run
completed, identify its run ID in Runpod, then bind it using:

```sh
python3 scripts/prover-rental/serverless.py --state-dir /secure/prover/serverless-fri \
  --execute bind-completed-run --operation EXACT_ATTEMPT_ID --run-id EXACT_RUN_ID
python3 scripts/prover-rental/supervisor.py --state-dir /secure/prover/worker-1 \
  --execute recover
```

Binding requires the completed SDK output and durable stored proof to match the
original attempt, job and manifest. Keep the Serverless controller's private
journal, history and proofs. Once a durable proof has finished its source
submission, an unresolved provider run blocks further FRI spending while
independently available SNARK work can continue. An unresolved source lease
remains the supervisor's one active job and blocks new claims until recovery or
safe expiry.

The provider's live journal stays below 2 MiB. Once a warm job has a final native
or external disposition and a durable result receipt, its full record moves to
private `history/` files. Completed sessions retain a compact reference and their
original budget charge. Archive records, job lookup indexes, and proof files must
stay with the provider directory: recovery and exact retry checks still use them.
Active, uncertain, and failed attempts remain in the live journal.

On the Pods backend, after a supervisor-owned native job receives a definitive accepted or rejected
disposition, the supervisor archives its completion identity and file hashes in
the job directory's private `native-completion.json`. It then removes
`picked-wire.json`, `payload.json`, `evidence.json`, and `submission.json` before
clearing the active job. Interrupted cleanup resumes from that durable record.
Keep the small authority, manifest, release, and controller metadata with the
provider history and final proof file; recovery still verifies the retained proof.
Ambiguous submissions, external service jobs and Serverless FRI jobs keep their original files.

To reclaim intermediates from older completed native jobs, preview
`supervisor.py --state-dir /private/supervisor compact-completed`, then add
`--execute` before `compact-completed` to apply it. This local maintenance command
needs no provider API key or object-storage connection. It verifies the same
completion evidence and skips active, expired, retired, and foreign jobs.
Stop the supervisor loop before applying it, and keep the provider watchdog running.

Admission checks reserve room for pending completion and cleanup records. Long
URLs or unresolved work can therefore limit capacity before the configured pod
maximum is reached. A late capacity refusal preserves the owned job for retry;
it does not acquire a replacement lease. Let existing work finish or drain while
the watchdog continues. Do not raise the journal cap or delete history to bypass
the guard. Older journals with completed warm history compact during authorized
writes; a full journal containing only unresolved records is preserved and rejects
new admission rather than discarding authority.

After a failed session, `expire-active` previews retirement of a known, expired
lease. Its `--execute` form requires the owned provider session to be stopped,
preserves the job files and archived authority, and never retires an unknown pick
or pending native submission. Try `recover` first. Retirement does not grant
credit or immediately request another job; normal polling resumes separately.

The object store must support atomic PUT, conditional creation with
`If-None-Match: *`, and HTTPS Signature V4 presigned GET/PUT. The controller
publishes immutable job inputs and a mutable, authenticated session mailbox;
each job has separate result objects. Use an operator-owned bucket/prefix and
credentials whose actual validity covers the configured URL lifetime; temporary
credentials can expire before a requested URL TTL. The SDK contracts are
[conditional PUT](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/put_object.html)
and [presigned URLs](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/generate_presigned_url.html).
The tooling creates neither buckets nor account permissions.

## Images

Build and publish the FRI-only CUDA base from the prover repository root:

```sh
docker build --platform linux/amd64 -f docker/zksync-os-prover-fri/Dockerfile -t REGISTRY/gpu-fri-base:RELEASE .
python3 scripts/prover-rental/build-image.py --serverless-fri \
  --base-image REGISTRY/gpu-fri-base@sha256:EXACT_DIGEST \
  --fri-release /secure/fri-release.json --tag REGISTRY/gpu-fri-serverless:RELEASE
```

Add `--execute` to build the adapter image. Publish it through the reviewed
release process and pin its final digest in `serverless-policy.example.json`.
Its binaries, guest and hash-locked SDK dependencies are baked into the image;
startup does no cloning, compilation or package installation. FRI needs no CRS.
The separate SNARK image carries its CRS. FlashBoot does not replace the image
registry or guarantee a GPU cache survives eviction.

Create a Runpod queue endpoint using the pinned Serverless FRI image and record
the endpoint/template IDs. Configure FlashBoot explicitly as `FLASHBOOT`, one
GPU, zero minimum/one maximum worker, five idle seconds, and `QUEUE_DELAY`
scaling with a four-second delay. Match the disk, timeout, exact GPU type and
observed GPU pool in the policy. Choose either allowed CUDA versions or a minimum
version, never both. Leave command, entrypoint, environment, ports and network
volumes unmodified. `validate-endpoint` reads both provider APIs and rejects
configuration drift; it creates no paid resources.

The provider API and console have differed in their FlashBoot defaults, so this
workflow requires it explicitly. See Runpod's
[endpoint settings](https://docs.runpod.io/serverless/endpoints/endpoint-configurations)
and [endpoint API](https://docs.runpod.io/api-reference-v2/serverless/create-a-serverless-endpoint).
Validate GPU memory, CPU/RAM allocation, cold initialization and actual native
CUDA resume on the selected hardware before production use. Local tests do not
measure FlashBoot latency or qualify a live GPU.

For the existing Pods path, build its GPU base:

```sh
docker build --platform linux/amd64 -f docker/zksync-os-prover-rental/Dockerfile -t REGISTRY/gpu-rental-base:RELEASE .
```

This recipe builds both standalone workers with GPU features, using the same
reviewed GPU32 backend, pinned toolchain, and compact GPU CRS as the default
SNARK image. CPU-only images require the explicit `cpu` target and are not rental
GPU bases. Publish the base through the operator's reviewed release process and
record its immutable digest and the actual file hashes in one
`release.example.json` copy per stage. Both manifests must bind the same guest,
program commitment, protocol and verification key.

```sh
python3 scripts/prover-rental/build-image.py --warm \
  --base-image REGISTRY/gpu-rental-base@sha256:EXACT_DIGEST \
  --fri-release /secure/fri-release.json --snark-release /secure/snark-release.json \
  --tag REGISTRY/gpu-rental:RELEASE
```

Add `--execute` to build, or `--execute --check` for Docker's static checks.
Role-specific warm images may omit one stage. The image validates the actual
native binaries, guest files and CRS against its baked manifests at build and
startup. Use the final adapter image's immutable digest in the rental policy.
No rented machine builds code or selects a release at startup.

## Existing and service workflows

The [single-job guide](single-job-README.md) documents the bounded legacy rental,
lease export, exact result import and provider recovery commands. The
[pool guide](pool-README.md) covers child/Gateway external service handoffs. Their
private state directories remain compatible; moving the tools does not reset
journals, budgets or ambiguous allocations.

For contract-selected service work, set `ZKSYNC_OS_SERVER_DIR` to the matching
zksync-os-server checkout containing `scripts/prover-service/keeper.py`. Native
compute operation does not import those tools. External SNARK work requires its
existing keeper-issued permit and fresh turn validation; the supervisor cannot
turn an arbitrary native compute job into an authorized service duty. Account
signatures, local native proof verification and canonical receipt checks stay in
the trusted service workflow; operators do not need to synchronize an execution node.

Tests use local mocked providers and workers. They do not qualify a GPU image,
create cloud resources or prove that a production deployment is ready.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/prover-rental -p 'test_*.py' -v
```

Set `ZKSYNC_OS_SERVER_DIR` for the optional cross-repository service/keeper tests;
install Foundry `cast` v1.7.1 for their real service signatures and install the
controller requirements to run the offline SDK contract test.
The Linux rental CI pins a companion server checkout, requires all tests to run
without skips, and installs the hash-locked Serverless SDK in Python 3.12. That
dependency check does not qualify the CUDA image or GPU snapshot restoration.
