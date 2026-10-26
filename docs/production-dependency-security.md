# Native prover dependency review

Reviewed 2026-10-26 against Syscoin prover `270bdb691af21307244bbe39b4c861dacc006299`
and RustSec database `a78282a1414d6c28cc228c4eae3570451affb0dc`.
This review covers the checked-in native FRI, SNARK and combined workers, including
their CPU/GPU variants and the native executables launched by rental/Serverless.
Production images build for `x86_64-unknown-linux-gnu`. It does not qualify arbitrary
`PROVER_SOURCE_DIR` inputs, modified dependencies, guest-program internals, or
deployed images.

## Transport updates

The canonical application lock and the derived build overlay now select:

| Component | Before | After |
| --- | --- | --- |
| Tokio | 1.47.1 | 1.53.3 |
| async-compression | 0.4.43 | 0.4.51 |
| compression-codecs | 0.4.38 | 0.4.46 |
| compression-core | 0.4.32 | 0.4.34 |
| zstd | 0.13.3 | 0.14.3 |
| zstd-safe | 7.2.4 | 8.2.0 |
| zstd-sys | 2.0.16+zstd.1.5.7 | 2.1.2+zstd.1.5.7 |

Tokio 1.53.3 is patched for [RUSTSEC-2026-0386](https://rustsec.org/advisories/RUSTSEC-2026-0386.html).
The affected `AsyncFd` constructors were not found in this application's callers or
the reviewed dependency source trees. The update nevertheless removes the affected
package version. Tokio 1.54.0 is deliberately not selected: it introduces the separate
[`Interval` race](https://rustsec.org/advisories/RUSTSEC-2026-0384.html), fixed in 1.54.1.
The workspace minimum is raised so a newly resolved application cannot select 1.47.1.

Zstd is active, not an unused lockfile entry. Each worker constructs
`SequencerProofClient`; its Reqwest client accepts compressed sequencer responses.
Reqwest 0.12.23 constructs a fresh async-compression `ZstdDecoder` for each response,
then the shared `read_json_bounded` reads decompressed bytes before JSON/proof parsing.
An application allocation limit is not a defense against a decoder memory-safety bug.

The old compression adapter required `zstd ^0.13` and `zstd-safe ^7`. Updating
async-compression within its existing compatible 0.4 series selects an adapter that
supports the patched Zstd releases. Its required Brotli/allocator dependencies also
advance; all advertised HTTP content encodings remain enabled. No Zstd advisory is
ignored by policy.

The individual Zstd advisories were checked, rather than treating them as one bug:

| RustSec ID(s), all 2026 | Old native-path prerequisite | Disposition |
| --- | --- | --- |
| 0391 | Reborrow an abandoned encoder/decoder context using `with_context` | HTTP used fresh owned contexts; updated to patched zstd anyway. |
| 0392, 0393 | Older zstd versions, respectively before 0.8.0 and 0.4.10 | Did not match 0.13.3; related newer issues are covered below. |
| 0395, 0399, 0402, 0404 | Experimental stable-input, dictionary lifetime or context-clone APIs | Experimental APIs were disabled; updated to patched zstd-safe. |
| 0396, 0398, 0405 | Seekable APIs with invalid initialization, index or buffer position | Seekable feature was disabled; updated to patched zstd-safe. |
| 0397 | Output position beyond initialized data | Adapter used `OutBuffer::around_pos` with its written prefix; API is now patched. |
| 0400 | Mix one-shot and streaming operations on an unfinished context | HTTP decoder used a streaming-only owned context; updated to patched zstd-safe. |
| 0401 | Dictionary training with overflowing external sample sizes | Dictionary training was disabled; updated to patched zstd-safe. |
| 0403 | Failed legacy-frame streaming decode commits unwritten output | Streaming API is active, but bundled legacy support was disabled; API is now patched. |
| 0406 | Reconfigure unfinished multithreaded compression | Multithreaded compression was disabled; updated to patched zstd-safe. |
| 0410 | wasm32 allocator shim on allocation failure | Native Linux does not use that shim; updated to patched zstd-sys anyway. |

These prerequisite exclusions describe the old bundled build only. In particular,
`ZSTD_SYS_USE_PKG_CONFIG` can select a system C library, and output/error propagation
would not independently make the old legacy-frame bug safe if legacy decoding were
enabled later. The update avoids needing to carry those conditional exceptions.

Regression coverage in `sequencer_proof_client.rs` exercises single and concatenated
Zstd frames at the exact decompressed limit and one byte over, malformed/truncated
responses, post-acquisition failure classification for both FRI/SNARK picks, and
successful compressed FRI payload/lease preservation. Existing gzip coverage remains.

## crypto-bigint: one scoped exception

[`RUSTSEC-2026-0387`](https://rustsec.org/advisories/RUSTSEC-2026-0387.html) covers
secret-dependent timing in operations advertised as constant-time. It does not claim
incorrect arithmetic or proof-verification bypass. Exploitability requires affected
operations on secret values and an observable side channel.

`crypto-bigint 0.5.5` is present through Boojum in every worker. GPU SNARK and combined
workers also reach it through `elliptic-curve` and legacy k256/p256 dependencies.
Both immediate consumers require the 0.5 series, so changing the lock to 0.7.6 is not
a compatible upgrade. The 0.5 implementation differs from the later implementation
patched upstream; blindly applying the later diff is not a reviewed backport.

The exception relies on these specific production call paths:

* Boojum's `NonNativeFieldOverU16` really does perform bigint arithmetic on witness
  values. It must not be described as only public modulus calculations. However,
  the pinned wrapper's production RISC/compression circuits do not instantiate that
  gadget. Compression fixes its verifier to `RiscWrapperCircuitBuilder`, and the
  SNARK wrapper fixes its builder to that compression circuit.
* GPU phases explicitly synthesize these same RISC and compression circuits, then
  pass their external witness data to generic shivini proving code. Phase three
  constructs this wrapper's `SnarkWrapperCircuit`. The availability of legacy EraVM
  base-circuit dispatch in dependencies does not select it on these paths.
* k256/p256 signing features are enabled in the legacy dependency graph. Their
  presence is not the exclusion. The reviewed callers are signature recovery and
  verification, not host signing-key/nonce arithmetic; they are also outside the
  fixed wrapper circuits above.
* Private SNARK padding randomness is handled by Bellman/BN256 field arithmetic.
  No route from that randomness into crypto-bigint was found. The guest program is
  an already-built input to the FRI simulator/prover; this host lockfile neither
  establishes nor changes that guest's timing properties.

Review anchors, bound to the exact fork commits and trees in `patches/*-fork-source.json`:

| Source | Locations |
| --- | --- |
| Boojum | `gadgets/non_native_field/implementations/mod.rs`; `implementation_u16.rs` witness multiplication, inversion and conversion |
| zkos-wrapper | `wrapper/src/circuits/compression.rs`; `circuits/snark_wrapper.rs`; `gpu/risc_wrapper.rs`; `gpu/compression.rs`; `gpu/snark.rs`; CPU padding in `wrapper/src/lib.rs` |
| Legacy protocol | `zk_evm_abstractions/src/precompiles/ecrecover.rs` and `secp256r1_verify.rs`; k256/p256 features in `zkevm_opcode_defs/Cargo.toml` |
| Native adapters | `scripts/prover-rental/job.py`, `worker.py`, `fri_session.py`, `serverless_worker.py` |

The reviewed production wrapper does not invoke an affected host-secret arithmetic
path. This is a static applicability conclusion, not a constant-time certification
of the entire dependency, CPU, guest program or prover.

CI permits only this advisory under this conclusion. Before cargo-deny runs,
`.github/scripts/check_crypto_bigint_scope.py` checks both exact locked package
identities/parents and the reviewed application source/manifests, proving-fork pins,
build overlay tools/patches and optional Cargo override configuration against
`docs/crypto-bigint-scope.json`. New source files or changed inputs fail closed.
The guard has no automatic refresh command. Review the paths again before updating
the scope record; remove the exception when upgrading the consumers to patched bigint.

Source preparation still verifies the actual dependency fork trees and patch hashes.
No proving source identity, guest bytes, circuit definition, CRS or verification key
is changed by this transport update. Rebuilding a worker is distinct from regenerating
proving keys. GPU execution and deployed-image qualification remain separate checks.
