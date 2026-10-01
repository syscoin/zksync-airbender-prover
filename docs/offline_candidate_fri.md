# Offline candidate FRI diagnostic

`syscoin_offline_fri` proves real native-execution/Merkle witness words against a
hash-bound candidate guest without starting a server or changing production
release gates. It always selects GPU, Security100, and RecursionUnified. It does
not qualify server API/leases, durability/recovery, live contracts, throughput, or
actual 24 GB hardware when running the Low preset on a 32 GB card.

First freeze the owner-bound guest and fresh genesis. Generate a real witness
with the patched server's opt-in external-genesis utility, outside
`local-chains/v32.0`. Do not reuse stock guest proofs, synthetic storage, or an old
owner's guest as evidence for a new candidate. Independently compute the guest's
Security100 commitment with the pinned Security100 wrapper.

The witness handoff manifest has exactly these top-level fields:

```json
{
  "schema_version": 1,
  "app_bin_sha256": "<64 lowercase hex digits>",
  "app_text_sha256": "<64 lowercase hex digits>",
  "prover_input_sha256": "<64 lowercase hex digits>",
  "prover_input_words": 1,
  "batch_id": 1,
  "expected_public_input_hash": "0x<64 lowercase hex digits>",
  "expected_security100_program_commitment": "0x<64 lowercase hex digits>",
  "context": {"<native witness provenance>": "<generator output>"}
}
```

The example is illustrative, not a usable witness. Context records the source
tree, genesis hash, chain/settlement IDs, protocol/execution versions, DA mode,
compiled target, block range, state roots, and native output commitments. Obtain
the manifest's SHA-256 from the trusted generation handoff; merely hashing an
unknown input alongside itself does not authenticate its expected output.

Build through the [isolated source overlay](airbender-build-overlay.md), which preserves the
locked dependency versions and normal artifact location:

```bash
bash scripts/cargo-with-patched-airbender.sh offline-fri-build -- cargo build --locked --profile release --target x86_64-unknown-linux-gnu \
  -p zksync_os_fri_prover --features gpu --example syscoin_offline_fri
bash scripts/cargo-with-patched-airbender.sh offline-fri-test -- cargo test --locked --profile release --target x86_64-unknown-linux-gnu \
  -p zksync_os_fri_prover --features gpu --example syscoin_offline_fri
```

Run one GPU process at a time with externally recorded GPU/host memory, timing,
driver/runtime, device, CPU affinity, and OOM/pressure observations. The output
parent must exist; the output directory itself must not exist.

```bash
ulimit -s 300000
CUDA_VISIBLE_DEVICES=0 RUST_MIN_STACK=268435456 \
  target/x86_64-unknown-linux-gnu/release/examples/syscoin_offline_fri \
  --metadata /absolute/candidate/witness.json \
  --metadata-sha256 <trusted-manifest-sha256> \
  --bin /absolute/candidate/app.bin --text /absolute/candidate/app.text \
  --input /absolute/candidate/prover-input.le.bin \
  --output-dir /absolute/new-normal-run --gpu-memory-preset normal
```

Repeat with a separate fresh directory and `--gpu-memory-preset low`. Auto is not
accepted. A single execution includes setup/cold-start costs and is not a warm
steady-state throughput benchmark. `VERIFIED.json` separates setup, proving and
independent verification times, preserves upstream stage timings/cycle counts,
and records the proof hash and manifest. Only its successful creation marks a
pass; a retained `proof.json` without it may be unverified or rejected.

All metadata, guest sections and little-endian input words are validated before
GPU setup. Verified bytes are staged privately under the new output directory.
The native verifier receives explicit trusted Security100/RecursionUnified policy;
both its public-input registers and program-commitment registers must match the
manifest. This diagnostic does not submit or promote any artifact.
