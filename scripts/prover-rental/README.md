# Prover-owned GPU rentals

The prover operator runs the rental controller on a trusted machine. Runpod pods
execute one FRI or SNARK job at a time, reuse the same rental for successive jobs,
and stop after the configured idle grace period. The local supervisor remains
running to rent again when work arrives. Multiple supervisor state directories
can share one provider controller directory and its total concurrency and spending
limits; each supervisor owns at most one session and one active job.

`supervisor.py` is the continuous runner. It checks actual SNARK job claims before
FRI work, retains exact lease and submission state locally, and never interprets
an endpoint failure as an empty queue. `runpod.py watchdog` runs independently and
enforces the provider session deadline even if the supervisor exits. Ambiguous
allocation is reconciled without repeating a create request.

Workers claim asynchronously and retain only one outstanding job. A busy worker
does not reserve a backlog, so other polling workers can claim distinct available
jobs. Faster workers may complete more jobs; the scheduler does not wait for every
worker to finish a numbered round or promise equal counts.

The reusable image alternates the standalone GPU stage binaries inside one pod.
It retains the pod, image and files between jobs; each native subprocess currently
rebuilds its process-local setup caches. The native combined service separately
supports wrapping priority between FRI jobs and retains its existing host caches.
Neither worker interrupts an already leased proof to switch stages.

Provider credentials, object-store credentials, sequencer credentials, real leases
and signing keys remain on the operator's machine. The pod sees only a session
mailbox capability, authenticated commands, stripped hash-bound inputs and scoped
result-upload URLs. Every completed result is durably collected before its exact
native submission or external service handoff. A transport receipt is not proof
verification or service credit.

## Runtime and configuration

Use Python 3.10+ on Unix with durable local storage. The native one-job/pool tools
use the standard library; automatic S3-compatible storage plans additionally need
`requirements-controller.txt`. All CLI mutations remain dry-run unless `--execute` is given.
Hardware, CUDA, images, runtime and price limits are explicit operator choices in
`policy.example.json`; placeholders deliberately fail validation. Qualify both
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

Copy the appropriate example to a private operator file. Initialize the
shared provider policy before the supervisor, then validate the supervisor config
without `--execute`. The provider state and each supervisor state must be distinct
absolute paths, created on durable local storage with private permissions.

```sh
python3 -m pip install -r scripts/prover-rental/requirements-controller.txt

python3 scripts/prover-rental/runpod.py --state-dir /secure/prover/provider \
  --execute init --config /secure/prover/policy.json

python3 scripts/prover-rental/supervisor.py --state-dir /secure/prover/worker-1 \
  init --config /secure/prover/supervisor.json
python3 scripts/prover-rental/supervisor.py --state-dir /secure/prover/worker-1 \
  --execute init --config /secure/prover/supervisor.json
```

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
delete a remote pod.

The provider's live journal stays below 2 MiB. Once a warm job has a final native
or external disposition and a durable result receipt, its full record moves to
private `history/` files. Completed sessions retain a compact reference and their
original budget charge. Archive records, job lookup indexes, and proof files must
stay with the provider directory: recovery and exact retry checks still use them.
Active, uncertain, and failed attempts remain in the live journal.

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

Build the GPU base from the prover repository root:

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
install the controller requirements to run the offline SDK contract test.
