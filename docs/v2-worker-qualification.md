# V2 worker qualification

The source graph is pinned in Cargo.lock and patches/v2-proving-sources.json. The worker uses the Syscoin v32 guest, Security100 and the app-bound log22 wrapper. The candidate key registry stays inactive until qualification completes.

## Derive the guest commitment on the build server

Use the released guest binary and its text section. The example derives the base, unrolled and unified setups independently on CPU and reports their full chain commitment.

```sh
bash scripts/cargo-with-patched-airbender.sh --cpu v2-identity -- \
  cargo run --locked --release -p zksync_os_snark_prover --no-default-features \
  --example syscoin_v2_identity -- --app-bin "$APP_BIN" --app-text "$APP_TEXT"
```

Compare the app hashes with the retained witness manifests. Generate the app-bound VK using the same pinned wrapper and guest, then check the generated verifier reports that VK. Record the new commitment in a **copy** of the witness manifests before hashing each copy for the offline driver. Keep the execution statements and oracle words byte-for-byte intact.

## GPU rehearsal

Build the native Bellman source with the rental GPU's compute architecture and release optimization. The repository's pinned compact CRS digest is recorded in docker/prover-build-pins.json. Use the normal source entry point to build the FRI driver, combiner and SNARK worker. The compact CRS is necessary for GPU SNARK key generation and proving.

```sh
python3 scripts/prepare-v2-proving-sources.py --prepare-bellman "$BELLMAN_CUDA_DIR"
cmake -S "$BELLMAN_CUDA_DIR" -B "$BELLMAN_CUDA_DIR/build" -DCMAKE_BUILD_TYPE=Release -DCMAKE_CUDA_ARCHITECTURES=120
cmake --build "$BELLMAN_CUDA_DIR/build" --parallel 4
bash scripts/cargo-with-patched-airbender.sh v2-fri -- cargo build --locked --release \
  -p zksync_os_fri_prover --features gpu --example syscoin_offline_fri --example syscoin_offline_combine
bash scripts/cargo-with-patched-airbender.sh --gpu32 v2-snark -- cargo build --locked --release \
  -p zksync_os_snark_prover --bin zksync_os_snark_prover
```

Generate and independently verify both FRI proofs over the retained consecutive batches. Combine them in order and check the combined public input and registered program commitment. Prove the app-bound wrapper and save the native proof, VK, serialized contract calldata, measurements and source receipts before cancelling the rental. The qualification controller can test the production-mode Gateway router with that calldata on an isolated EVM and repeat the check on a production-verifier rehearsal.

[FRI driver](offline_candidate_fri.md) · [Combine driver](offline_candidate_combine.md)
