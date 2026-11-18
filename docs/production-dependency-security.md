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

## crypto-bigint 0.7.11

The worker lock uses the reviewed crates.io release `crypto-bigint 0.7.11` for
Boojum, elliptic-curve, primefield and RFC 6979. The worker removes its previous
exception for [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html).
The pinned Syscoin protocol revision supplies the wrapper and host crypto crates.
The protocol's platform fork is used by its other workspaces and does not enter
this worker's resolved dependency graph.

CI checks the package's version, source, checksum and exact direct parents,
rejects the advisory ignore and runs cargo-deny against the locked graph.
`docs/crypto-bigint-scope.json` binds the reviewed lock, source pins, manifests
and build inputs. Changes require a new scope review.

The worker's bundled commitment records the new protocol source revision and
tree. Its guest, program commitment and verification-key digests are retained.
