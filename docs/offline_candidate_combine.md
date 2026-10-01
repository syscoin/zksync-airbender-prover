# Offline two-batch combine diagnostic

`syscoin_offline_combine` exercises the same upstream `CarriedChainCombiner` used by
production `merge_fris`, without inventing a server lease or changing the production
registry. It requires two distinct, consecutive, real native-execution witnesses and
their Security100/RecursionUnified FRI artifacts. Re-proving one witness twice is not
a two-batch range and is rejected.

A first-pass unified proof may carry a chain one fold shorter than the program
commitment returned by its verification. Passing that bare proof directly to the
SNARK wrapper with `--check-aux-params` can therefore correctly fail. Do not alter
registers, disable the check, or label an uncombined proof wrapper-ready. The genuine
combine stage produces a RecursionCombined proof whose raw registers carry the full
program commitment required by the wrapper.

Build with the reviewed source overlay and the existing FRI package's GPU feature:

```bash
bash scripts/cargo-with-patched-airbender.sh offline-combine-build -- \
  cargo build --locked --profile release --target x86_64-unknown-linux-gnu \
  -p zksync_os_fri_prover --features gpu --example syscoin_offline_combine
```

The externally authenticated combine manifest has this exact shape (placeholders
are not usable proof inputs):

```json
{
  "schema_version": 1,
  "app_bin_sha256": "<64 lowercase hex digits>",
  "app_text_sha256": "<64 lowercase hex digits>",
  "expected_security100_program_commitment": "0x<64 lowercase hex digits>",
  "from_batch_number": 1,
  "to_batch_number": 2,
  "expected_combined_public_input_hash": "0x<64 lowercase hex digits>",
  "inputs": [
    {
      "proof": "/absolute/batch-1/proof.json",
      "proof_sha256": "<64 lowercase hex digits>",
      "metadata": "/absolute/batch-1/native-manifest.json",
      "metadata_sha256": "<64 lowercase hex digits>"
    },
    {
      "proof": "/absolute/batch-2/proof.json",
      "proof_sha256": "<64 lowercase hex digits>",
      "metadata": "/absolute/batch-2/native-manifest.json",
      "metadata_sha256": "<64 lowercase hex digits>"
    }
  ]
}
```

Use each witness's original [native handoff metadata](offline_candidate_fri.md).
Chain, settlement, protocol, DA, genesis, source-tree, compiled-target, and chain-config
context must match; batch IDs and block ranges must be consecutive, and batch one's
ending state root must equal batch two's starting root. The expected combined public
input is Keccak-256 of the two public-input hashes' bytes concatenated in batch order,
not SHA3-256 and not a truncation. Independently calculate it from the trusted native
handoff. The example also compares it with upstream's canonical word-based calculation.

Run only after other heavy work is idle, under the same host/GPU metrics supervision
as individual FRI proofs. The output parent must exist and the output itself must not.

```bash
ulimit -s 300000
CUDA_VISIBLE_DEVICES=0 RUST_MIN_STACK=268435456 \
  target/x86_64-unknown-linux-gnu/release/examples/syscoin_offline_combine \
  --manifest /absolute/combine-manifest.json \
  --manifest-sha256 <trusted-manifest-sha256> \
  --bin /absolute/candidate/app.bin --text /absolute/candidate/app.text \
  --output-dir /absolute/new-combine-run --gpu-replay-threads 8
```

The diagnostic authenticates and privately stages inputs, independently verifies each
FRI proof against the guest and its native public input, then runs a real combination.
It independently verifies the resulting RecursionCombined artifact and checks all 16
output words plus raw registers 10–25 against the expected public input and program
commitment. Only then does it write `combined-proof.json`, a typed/lossless bare
`snark-input.json`, and `COMBINED_VERIFIED.json` with their hashes and provenance.

The combiner uses upstream's fixed 21,820-MiB Normal arena; it does not exercise the
FRI Low preset. This result qualifies a real two-batch combination only, not SNARK
proving, server/API operation, deployment, throughput, or actual 24-GB hardware.
The subsequent CPU wrapper still requires the pinned full Security100 CRS, frozen
guest, `--check-aux-params`, and independent verification against the candidate VK.
