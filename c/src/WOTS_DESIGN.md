# WOTS x8 correctness checkpoint

This checkpoint finishes the CPU optimization implementation before any
optimization-performance testing. It contains no timing or speedup claim.
The scalar source snapshot remains in `c/scalar_snapshot_20261004`; the
FORS-only source snapshot remains in `c/fors_snapshot_20261004`. Both have
SHA256 manifests. The parent thread owns Linux acceptance and source freezes.

SM3 AUTO/AVX2 contexts now dispatch WOTS key generation, XMSS leaf generation,
WOTS signature generation and WOTS public-key recovery to eight independent
chain lanes. The full chains use lg(w)=2 or 4, with respectively 68 or 35
endpoints. Each group preserves the original keypair, chain and hash address.
The final group has four or three real lanes. Variable-length signing and
recovery chains use an active lane mask; completed lanes retain their prior
value and zero-step chains perform no logical F operation. Starts and steps
are independently represented, so recovery begins at the message digit.

The existing single-final-block AVX2 SM3 compression worker remains unchanged.
All eight hardware lanes have defined input buffers even when some lanes are
inactive. Only real active lanes contribute to PRF/F and compression counters,
and only those lanes are copied or receive a test fault. The seven counters
therefore express scalar-equivalent logical work, not executed SIMD vectors
or dummy-lane hardware work. REF and SHA2 retain their original scalar paths.
Runtime CPU/OS detection and `AVX2=0` continue to isolate AVX2 instructions.

For leaf generation and recovery, ordered endpoint groups are absorbed into
a single ordinary scalar T_len hash copied from the PK.seed midstate. The
22-byte compressed address is absorbed once; the complete message length is
preserved for padding. No endpoint is reordered and no group is finalized as
an independent T hash. The endpoint array for SIMD streaming has at most eight
16-byte endpoints; the REF branch retains the original full-endpoint array as
the independent comparison path. Upper XMSS H hashes and FORS verification
remain scalar. Existing treehash still determines chunk boundaries and cache
node addresses; SIMD changes leaf generation rather than treehash semantics.

Fault point 3 now disturbs the first F result of the selected active WOTS
signature chain, with the same absolute chain index and top-layer rule as REF.
Fault point 4 is applied once after the streamed WOTS leaf is formed. Other
FORS/digest fault stages are unchanged. The release two-macro test gate and
missing injection ABI remain in place. The expanded fault suite has 192 signing
calls over pure/internal/prehash/digest entry points, including 80 injected
self-check calls which must return SLH_ERR_FAULT and erase 2320 bytes.

Correctness targets, with no timer in any target:

```sh
make -C c OUT=../build/wots-check all test review-test avx2-test wots-test prehash-test fault-test guard-test
make -C c OUT=../build/wots-counts COUNTERS=1 all review-test avx2-test wots-test prehash-test
make -C c OUT=../build/wots-portable AVX2=0 all test avx2-test wots-test prehash-test fault-test guard-test
ASAN_OPTIONS=halt_on_error=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 make -C c OUT=../build/wots-check SAN_OUT=../build/wots-sanitizer sanitizer
```

`test_wots` is a standalone private-algorithm harness. It includes the engine
source only inside that executable so the production ABI gains no testing
entry point. It has 768 REF comparisons across pid 201/1/2/3: tail sizes 1..8;
zero, maximum and divergent chain lengths; arbitrary nonzero starts; message
and checksum digits; streaming leaf, signing and recovery; XMSS authentication
paths; and seven-counter equivalence. `test_avx2` additionally has 342
FORS/WOTS subtree configurations and 25 cache heights across the toy/128s/128f
parameters, with key bytes, serialized cache bytes and complete cached
signatures compared against REF. The bounded pid3 subtree tests never build a
complete 128-24 tree; the parent controls the separate full-fixture regression.

Local Windows seeded correctness execution uses an unshipped RNG link stub
because the authoritative engine uses Linux getrandom. Linux runtime RNG,
shared-library symbols and sanitizer evidence must be recorded by the parent.
No benchmark results are produced or promoted by this checkpoint.
