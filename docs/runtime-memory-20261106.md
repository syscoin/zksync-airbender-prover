# V32 runtime memory qualification

## Compared sources

The controlled comparison on 2026-11-07 UTC used the same RTX 5090 host and
the same two contiguous native-execution/Merkle witnesses for both versions.

| Component | Baseline | Runtime candidate |
| --- | --- | --- |
| Airbender | `0d8c852954afcae1f160151a17fe80886f1755b0` | `b91eeaecc4d1b9a42ea6843432bb3e014899b303` |
| Prover executable source | `15da5990e6a6fefbc36de069eef2e90cdbab0964` | `7c6d95964c481724f17b932e56e4399eef921c5d` |

The candidate's later policy and documentation commits retain those executable
inputs. The builds used the normal locked source-overlay path on
`x86_64-unknown-linux-gnu`, nightly Rust 2026-02-10 and CUDA 13.2.86, targeting
SM 120. The host had 124.46 GiB total physical memory, no swap, 52 logical
Xeon 8263C threads and an RTX 5090 reporting 32,607 MiB device memory.
The release build used the repository's optimization settings, including
overflow checks and disabled LTO, with no `target-cpu` or `RUSTFLAGS` override.

Both runs selected Security100, RecursionUnified, bundled authenticated setup
summaries, the Normal GPU preset and eight replay threads. Each process retained
one prover across both jobs. Its default host memory pool contained 384 chunks
of 64 MiB, totaling 24 GiB. Builds and other proving processes were stopped
during the comparison.

## Measured standalone FRI memory

| Measurement | Baseline | Runtime candidate |
| --- | ---: | ---: |
| Kernel peak RSS through setup and both proofs | 70.15 GiB | 45.56 GiB |
| Resident memory after the second proof | 69.99 GiB | 45.41 GiB |
| Setup time | 54.336 s | 35.793 s |
| First proof time | 8.176 s | 8.230 s |
| Second proof time | 4.214 s | 4.186 s |
| Sampled device memory peak | 29,278 MiB | 29,278 MiB |

The measured peak reduction is 24.59 GiB. The source-derived reduction consists
of 13.1484375 GiB of discarded setup padding and 11.4375 GiB of CPU LDE power
caches. The small coset constants reconstructed by the candidate are identical
to the values selected from those caches.

These are one baseline run and one candidate run, each with two minimal
correctness inputs. The first input executes `SetSLChainId`, and the second is
an empty continuation. They contain 1,355,893 and 980,910 guest cycles. Peak RSS
is the kernel's cumulative `VmHWM` captured before independent CPU verification,
so it includes initialization and both GPU proof jobs. It does not include
separate wrapper/SNARK execution. The timing observations do not establish
sustained production throughput or the peak for a larger workload.

Both proofs from each version passed independent CPU verification with the
expected public-input and program-commitment registers. The first and second
candidate proof SHA-256 values are
`6d39b8b69de6bc1c7b94f22a1491e211205bd3cbf189e7d66b432490a25f4f55`
and `bef6895925eacaf1df4f13f679c4694f317c5330aa174155e1a8aaffeef224ae`.
The same initialized prover handled both jobs. Per-job timings include the
preparation performed inside `prove_words`; the 35.793-second process setup is
paid once. Proof serialization, submission and independent verification are
outside the per-job timer.

A 64 GB host is a plausible standalone FRI candidate for this configuration.
Physical 64 GB hardware and production-size batches require their own resource
qualification. Process concurrency, larger traces, additional resident jobs,
the operating system and other services all consume additional headroom.
The 24 GiB trace pool provides backpressure, but teardown vectors, replay
nondeterminism and proof collections can grow outside that pool.
The test host exposed a read-only cgroup hierarchy, so a separate memory-limited
run was unavailable.

## SNARK memory

The SNARK runs set `RAYON_NUM_THREADS`, `BELLMAN_NUM_THREADS` and
`OMP_NUM_THREADS` to 16 and used the production GPU32 wrapper preparation.
The standalone wrapper process peaked at 49.13 GiB RSS for the combined two-batch
statement. Setup took 146.536 seconds, the RISC stage 48.834 seconds, compression
0.960 seconds and the final SNARK stage 74.165 seconds. The three stage timings
include independent CPU verification. Total process wall time was 296.534 seconds.
The unchanged app-bound VK accepted the result, and an altered public input was
rejected. Auxiliary-parameter checking and zero knowledge were enabled.

The production warm GPU SNARK worker also retains its Airbender combiner across
jobs. That combiner uses the four common circuit setups and the unified recursion
setup. Its source-derived persistent cache reduction is 5.0859375 GiB, consisting
of 3.1484375 GiB of setup padding and 1.9375 GiB of CPU LDE arrays. The wrapper
backend itself is unchanged. The standalone wrapper measurement excludes this
resident combiner.

A second process used the production combiner constructor, performed an actual
merge of the two authenticated FRI proofs, and kept that same combiner alive
through all wrapper stages. It then retired the wrapper into its normal warm
host cache before measuring idle residency.

| Retained-combiner measurement | Observed RSS |
| --- | ---: |
| Combiner after actual merge | 33.14 GiB |
| Full process peak | 81.99 GiB |
| Warm idle with combiner and wrapper host cache | 68.01 GiB |

That process completed in 338.698 seconds. Wrapper setup took 146.230 seconds,
the RISC stage 47.553 seconds, compression 0.946 seconds and the final SNARK
stage 74.315 seconds. Each proof passed independent CPU verification using the
existing keys. The combined statement and program commitment matched the
independently verified offline merge, and an altered SNARK public input was
rejected.

The measured full worker exceeds a 64 GB host's capacity. A 96 GB host has
limited margin above this workload after accounting for the operating system.
The 128 GB test host provided additional headroom. These measurements cover one
offline two-batch job with the production cache lifetime. They do not establish
a maximum across larger ranges, other workloads or multiple concurrent workers.

## Identity and verification

The Airbender circuit definitions, constraint system, CPU prover and verifier,
verifier-common code, field and FFT arithmetic, transcript, embedded recursive
verifier binaries and native GPU kernels are byte-identical to the baseline.
The setup source identity metadata changes to record the runtime fork. Its
cryptographic setup caps, program commitment and app-bound VK retain their
previous values.

The app-bound Security100 program commitment is
`0xff43db6564b43491d6c25a613270e7802a4fca2bc67ad621e5cb08dd57d22975`.
The app-bound final VK is
`0x22b4a58c40ab11839bfc79c96957f24711776f3e1992fa3cf14c1c3b898a2153`.

## Targeted regression tests

Eighteen optimized Linux tests passed against the exact Airbender source above.
They cover compact setup transposition, direct coset constant equivalence,
disjoint teardown collection and holder reuse, empty initialization/teardown
streaming, adversarial degree-lift cases, RAM bounds and the generated JIT
nondeterminism callback.

The GPU crate tests linked CUDA. Their auxiliary workspace restricted membership
to the tested crates and added their development dependencies to a recorded test
lock. The production worker and proof-driver builds used the normal locked
application graph. The test archive SHA-256 is
`a4f75d312c8ba9f093478517d65fb7ab3334f843f59db5f64a48e5c667c5946b`.
The standalone FRI A/B evidence archive SHA-256 is
`ffedad7cb1e90fa3ebcd76c9ab09841cfdee195140a6ca74645970f48995e599`.
The final qualification archive includes the proofs, keys, phase measurements,
commands, source attestations and 218 verified file hashes. Its SHA-256 is
`3e11a42ac530d9c2670e592b70db1f561bb49f858064bd0b561c69069dccf8d7`.

The existing native verifier accepted the unmodified candidate proof and rejected
four separate mutations. A changed FRI leaf failed Merkle inclusion, a changed
query index failed setup Merkle inclusion, and changed terminal coefficients and
quotient openings failed transcript proof-of-work validation. These controls
check rejection of altered proof material. They do not construct fully regenerated
adversarial proofs.

The removed CPU LDE arrays are public power caches. Proof-supplied evaluations,
Merkle openings and terminal coefficients continue through the unchanged verifier,
which derives its geometry, challenges and degree bounds independently. The
direct-constant regression verifies equivalence with the old cache construction.
The low-level circuit verifier returns the supplied setup caps with its verified
proof state. Binding those caps to the expected setup and program belongs to the
full-statement and caller layers. These runs exercised `verify_artifact`, including
its expected-program recursion-chain checks, and the app-bound SNARK wrapper with
auxiliary-parameter checks enabled.
The completed offline proof jobs exercised successful execution. Job-abort and
simulator-reset recovery remain outside this runtime measurement.

## Rental cost context

The qualification host cost $0.525 per hour plus a $0.10 creation fee. At the
2026-11-07 02:42 UTC Clore listing snapshot, 64 GB RTX 5090 hosts started at
$0.39375 per hour. Restricting that snapshot to reliability of at least 0.95
raised the cheapest 64 GB offer to $0.525 per hour. The cheapest listed 128 GB
offer meeting that reliability level was $0.48125 per hour. GPU power limits
and reliability also differed between offers.

The measured reduction allows consideration of smaller hosts, but RAM capacity
alone does not determine rental price. These prices are a timestamped snapshot.
The qualification order was cancelled and confirmed expired at 04:04:13 UTC.
Its cancellation receipt lists $0.770583 of spend and a $0.10 creation fee.
