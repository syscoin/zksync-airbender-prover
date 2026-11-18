# V2 worker qualification

## Reproducibly rebuilt Syscoin v32 guest

The candidate guest binary has SHA-256 `9727a6d5c1301bc0fdb9ef7b46027917aef51c9158a7678dec1287bffb9b3e4d`. Its text section has SHA-256 `4648aea720d7acb9317d90047b2640f85baacf15bfdfe340c21c03dc3984f932`. The default Security100 base, unrolled and unified recursion fold produces `0xbf5be160cc4b6fff331c10d591691e0c5f62df1be058b2e0ee9c8fc8c8640c66`. A second Docker build reproduced the ELF, binary and text section. Two independent simulators returned the expected native statement for all eight contiguous v32 batch witnesses.

The separately generated settlement key for this guest is `0x8e6285da659dac3cfff56dbae3bf445e1524b9f08a9270f19d3361a97f8ce990`.

## Retained v32 guest comparison

The earlier rehearsal used the retained Syscoin v32 guest, Security100 and the app-bound log22 wrapper. Its app-bound verification key hash was `0x9bb49673b5437ada0c0941bb7f35422456a5c7833dd8292bf17f29fe1e9baa97`. The retained guest SHA-256 was `0d69bb7bc5207041c737def52d8858bab261b2ccf0afadbf2ceed14aa86d7cf6` and its Security100 program commitment was `0x05080df2ee1edeb1d3d13f9a193a00a3bf5ca2115bfa675b29c1baaef289d7e9`. A different guest requires its own key and verifier.

## Derive the guest commitment on the build server

Use the released guest binary and its text section. The example derives the base, unrolled and unified setups independently on CPU and reports their full chain commitment.

```sh
bash scripts/cargo-with-patched-airbender.sh --cpu v2-identity -- \
  cargo run --locked --release -p zksync_os_snark_prover --no-default-features \
  --example syscoin_v2_identity -- --app-bin "$APP_BIN" --app-text "$APP_TEXT"
```

Compare the app hashes with the retained witness manifests. Generate the app-bound VK using the same pinned wrapper and guest, then check the generated verifier reports that VK. Record the new commitment in a **copy** of the witness manifests before hashing each copy for the offline driver. Keep the execution statements and oracle words byte-for-byte intact.

The CPU key-generation CRS uses the official log22 object at storage generation `1682086004975644`. Its SHA-256 is `f004b339bc9e05d81f87a82095e19984c2555826a5459e651b8b893aa5422ae5`. On the build server, all 4,194,304 uncompressed G1 encodings matched the corresponding prefix of the previously pinned log25 CRS, and the complete 264-byte two-G2 section matched (SHA-256 `2e43433b69004a905ab559d398f468cf973b88ce65a0881f762d6320d9c3782f`). The CPU download and point-decoding inputs shrink from 2,147,483,920 bytes to 268,435,728 bytes. GPU workers use the compact-format CRS.

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

## Measured default prover

The released v0.9.1 executables and the V2 worker processed the same ordered pair of native v32 batch witnesses on one RTX 5090 with 32,607 MiB visible VRAM, CUDA 12.9, and 32 logical processors available to each worker. A separate CPU host verified both FRI packets against the native witness statements and candidate commitment. The first V2 settlement proof passed all three native wrapper checks. On an isolated Prague EVM, the generated PLONK verifier and the production-mode dual router each accepted that proof. The reserved-header check reverted with selector `0x31967fc6`. The deployed PLONK runtime SHA-256 was `7b80b9e3407b30ed85491b4933aa542dc3dadef654314cc9ea39e458e56e47df`. Its canonical 44 contract words matched the submitted worker packet, and its one public input matched the trusted two-batch settlement statement. These minimal batches cover the native v32/V8 proving path.

| Same two native batches | Released v0.9.1 | V2 candidate |
| --- | ---: | ---: |
| FRI process start to first lease | 104.351 s | 51.373 s |
| FRI batch 1 from lease to submission | 7.647 s | 7.313 s |
| FRI batch 2 from lease to submission | 4.035 s | 4.835 s |
| First two-batch merge in the worker | 7.769 s | 5.605 s |
| First RISC wrapper GPU proving pass | 52.514 s | 50.785 s |
| First compression GPU proving pass | 1.252 s | 1.402 s |
| First final PLONK GPU proving pass | 99.406 s | 13.405 s |
| First SNARK job, full native worker measurement | 164.010 s | 71.611 s |

The final PLONK domain shrank from 2²⁵ to 2²². Phase-3 key setup fell from 133.161 s to 16.702 s. The RISC wrapper still reserved 33,139,720,192 device bytes during setup. Across six additional contiguous minimal batches, Airbender's FRI allocator recorded 27.049 GiB of live suballocations in its 28 GiB normal arena. NVIDIA sampled 29,432 MiB of total card use in that run at 500 ms intervals. Arena high-water and total board residency measure different quantities.

| Retained identity | SHA-256 |
| --- | --- |
| Final CPU-generated SNARK VK JSON | `2340c5d66845ebc6d9bf85cebbfdc199d730d42caf4d2902809319f0a2624146` |
| Ordered V2 FRI payload checked on CPU | `54099da5001d9ad2f686a76fa043610133d733c9fc3f313c14d2a23f17ef09e5` |
| First V2 native SNARK JSON | `1609630e96afe9216176f59b30d2976514ccafaaa6fe0f8721e40021488c5c36` |
| First V2 canonical calldata JSON | `12a9af9a1677da40d14b38e8423274ca1b69cf6b60b5a2af53a84eaa9db85b51` |

## Host memory source selection

The guest binaries, recursion artifacts, Security100 commitment, log22 domain and registered verification key remain unchanged by this source selection. Historical measurements above retain their original source attribution.

The pinned protocol source transfers owned setup storage into GPU conversion and releases unused host permutation columns. It changes host allocation lifetimes without changing the RISC, compression or SNARK circuit definitions.

Pinned simulator memory remains the default. On qualified Linux GPU workers, explicitly set `AIRBENDER_SIMULATOR_MEMORY=demand-paged` to use anonymous demand-paged host RAM; set `pinned` or omit the variable to retain pinned memory. This affects host memory residency, not VRAM capacity or proof security parameters. The setting applies to FRI simulation and the SNARK worker's Airbender combiner. Compare complete corrected-guest workloads before enabling it for a fleet.
