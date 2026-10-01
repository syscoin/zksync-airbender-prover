# Opt-in standalone CPU wrapper memory lifecycle

The standalone SNARK worker accepts `--wrapper-cache-policy warm|cpu-cold`.
`warm` remains the default; existing library constructors, the shared run entry
point and the combined service keep their existing warm behavior. GPU and
non-Unix builds reject `cpu-cold` before creating clients or proving state.

Cold mode still derives the complete app-bound VK and validates it against the
registered protocol before any queue claim. It then drops all wrapper setup
caches before warming/using the CPU FRI combiner. After a successful real merge,
it retires the combiner's setup before constructing the cold wrapper. The
existing CPU `create_snark_wrapper_with_cache(..., None)` path constructs setups
lazily across the usual three proof phases. After verified compression, it
carries only that wrapper's compression VK into a new phase-3 wrapper, dropping
the phase-1/2 wrapper first. Reconstruction derives and checks the actual SNARK
VK against both the exact startup VK and the leased VK. After proving, the same
VK and input-immutability checks run again, and wrapper caches are dropped before
durable submission. Errors unwind owned caches normally; a failed merge or
compression does not take a successful-phase cleanup path. No verification or
lease gate is removed.

At successful CPU-cold ownership/phase boundaries, CPU-only Linux GNU builds
call `malloc_trim(0)` after owned objects have been dropped. This best-effort
allocator call can return already freed pages; it cannot release live proving
allocations and is not an RSS cap or an OOM cure. Other targets, warm callers
and GPU builds keep their original behavior. Consecutive FRI jobs keep their
existing prover, setups and GPU pools: this policy does not clear FRI-to-FRI
caches.

Cold reconstruction binds the app `.bin`, derived `.text` and trusted setup to
their initial canonical paths, Unix file identity, length, modification/change
times and streaming SHA-256. Capture checks file descriptor/path identity before
and after reading. Checks bracket initial validation, queue acquisition, cold
construction and completed proving. Missing, replaced, symlinked or changed
inputs fail closed; a failed post-proof check prevents submission. Inputs must be
task-owned and unchanged. These consistency checks and final VK rebinding do not
claim protection against a hostile same-owner transient writer.

The tradeoff is repeated setup work and input hashing, so startup/lease timing
must be measured again. Dropping caches is not a hard RSS limit or a guarantee
that an allocator instantly returns every page. This option avoids identified
live-cache overlap; it does not qualify CPU-combiner peak, 100-proof aggregation,
simultaneous FRI/SNARK, or physical 24 GiB GPU operation. Existing resource
admission and cooperative-drain thresholds remain unchanged.
