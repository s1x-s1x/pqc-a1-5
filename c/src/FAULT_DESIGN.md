# Stage 1 scalar checks and fault design

All execution in this package uses the toy parameter 201 for extended checks
and injected faults. The normal native smoke test also runs SHA2-128s and
SHA2-128f. It checks only the advertised lengths of 128-24 signatures; no full
128-24 key generation or signing belongs to these targets.

The fault executables require both `SLH_TEST_BUILD` and a compile-time
`SLH_TEST_FAULT_POINT` in 0..5. The production shared-library target defines
`SLH_RELEASE_BUILD`, rejects `SLH_TEST_BUILD`, and preprocesses all fault-site
macros to no-ops. There is no runtime setter, environment switch, public test
declaration, or injection ABI. Dedicated test state exists only in the internal
work structure of a test executable. Verification and key generation start
with inactive work state and do not execute injected mutations.

| Point | Calculation disturbed | Propagation being tested |
| --- | --- | --- |
| 0 | None, control build | Both entry points produce a valid signature |
| 1 | First H_msg MGF1 block before digest splitting | Signing chooses a different FORS message/indices from verification |
| 2 | PRF result for the selected secret in the first FORS tree | The emitted secret disagrees with the honest tree computation |
| 3 | First F result of the first nonempty top-layer WOTS chain | Remaining chain calculations carry the disturbed state into the signature |
| 4 | Computed WOTS leaf of the top-layer height-zero sibling subtree | The disturbed XMSS path changes the reconstructed public root |
| 5 | Computed selected FORS leaf after its secret hash | The disturbed FORS root is passed to WOTS signing while verification computes the honest root |

Points 3 and 4 operate at the top hypertree layer so a later layer cannot sign
the disturbed root and absorb the error. Point 3 selects a nonempty chain;
zero-step chains perform no F calculation. Point 4 uses cache levels 5 and 10
in the tests so the height-zero sibling is actually computed. It does not
inject into cache hits. The mutations occur at named calculation stages rather
than flipping a completed serialized signature after signing has finished.

`fault-test` runs six executables. Each executable uses thread counts 1 and 4,
cache levels 5 and 10, self-verification off and on, and both the public pure
message entry point and internal entry point. This gives 16 signing calls per
point, 96 total: 16 control calls and 80 injected calls. The 40 injected calls
with self-verification enabled must return `SLH_ERR_FAULT` and clear precisely
2320 signature bytes. Public calls must set the returned length to zero. The
40 calls without self-verification must return an invalid signature that a
separate context rejects. Guard bytes on both sides verify the wipe range.

`review-test` covers all 11 toy cache heights, root-only and leaf-cache forged
payloads with recomputed checksums, malformed header fields, both public-key
halves, parameter identity, truncation, trailing bytes, and failed-load
transactionality. A loaded public cache does not implicitly bind a secret key.
Cross-key signing bypasses stale cache data; explicit rebinding selects the
subtree key. Signatures must remain byte-identical across thread counts 1/2/4/8
with built, loaded, and unrelated caches. A changed SK.seed under the same
claimed public key exercises self-check failure in a production build.

Subtree equivalence covers WOTS and FORS at heights 0, 1, 4, 5, 8, and 10;
nonzero starts; first/last targets; the highest FORS tree; and root-only calls.
Each compares against the one-thread result at thread counts 1/2/4/8/32 and
checks output guards and the immutable input address. Fourteen subtree cases
have 70 thread configurations, 14 scalar baselines, 140 root/path calls, and
10 extra zero-height calls. Invalid argument checks must leave outputs intact.
These are deterministic equivalence cases, not 70 independent known-answer
vectors. Independent reference evidence is collected separately.

From the project root on Linux:

```sh
make -C c OUT=../build/stage1/ref all test review-test fault-test guard-test
make -C c OUT=../build/stage1/counters COUNTERS=1 all review-test
ASAN_OPTIONS=halt_on_error=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 make -C c OUT=../build/stage1/ref SAN_OUT=../build/stage1/sanitizer sanitizer
```

Use separate output directories for counter, sanitizer, and optimized builds;
changing compiler flags alone does not invalidate an existing Make target.
`guard-test` preprocesses release/test variants, rejects four invalid macro
combinations, builds a release object, and inspects object/shared-library
symbols with `nm`. `python tools/check_native_guards.py --source-only` is a
compiler-independent source guard and does not constitute native execution.
