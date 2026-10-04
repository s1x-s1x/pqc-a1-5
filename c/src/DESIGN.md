# Native engine stage 1

The algorithm skeleton follows FIPS 205 Algorithms 4-24 as implemented in
`slh-dsa/slhdsa-c`, pinned commit
`2b111e076a3bf0b6041651cf8746acf5ade56cc7`. The unmodified vendor SHA-256
implementation is compiled directly. The vendor license offers Apache-2.0,
ISC, or MIT; this project uses the MIT option. The vendor license is retained
in `third_party/slhdsa-c/LICENSE`.

SM3 is a native portable scalar implementation of the published compression,
expansion, and padding rules. A precomputed PK.seed block is copied for each
PRF/F/H/T, just as the upstream SHA-256 instantiation does. SM3 known-answer
tests cover `abc` and the 64-byte `abcd` example. No OpenSSL ABI or Python
runtime is used by the C library.

Supported backends are AUTO and REF. Both use this scalar C implementation;
AVX2/AVX512/NEON/CUDA requests return SLH_ERR_BACKEND. OpenMP thread counts
are explicit (default one); zero selects min(available processors, 48).
Threading splits an aligned tree into independently addressed chunks, then
combines their roots at the original absolute heights and indices.

## Cache semantics and format

`t` is height above the leaves. Retained nodes are heights t..hp inclusive in
memory, in bottom-up order. t=0 retains all leaves; t=hp retains the root only.
The default t is min(12,hp). A cache contains the highest XMSS layer, tree 0;
for d=1 this is the entire XMSS tree. Intermediate hypertree layers are not
cached. Key generation builds the configured cache in the same tree pass.

The on-disk format is 96 header bytes followed by only height-t nodes, ordered
by ascending absolute node index. All integer fields are big-endian uint32:

| Byte offset | Content |
| --- | --- |
| 0 | Eight ASCII bytes `A15CACHE` |
| 8 | Version 1 |
| 12 | Parameter ID |
| 16 | t |
| 20 | hp |
| 24 | n (16) |
| 28 | Payload byte count, n*2^(hp-t) |
| 32 | PK.seed (16 bytes) |
| 48 | PK.root (16 bytes) |
| 64 | SM3(header[0:64] || payload), 32 bytes |
| 96 | Payload |

Loading checks header dimensions, exact file size, parameter ID, public-key
binding, and the SM3 checksum. All upper nodes are recomputed with the selected
parameter hash and address rules; the computed root must equal PK.root.
A failed load preserves any existing valid cache. No secret seed is serialized.
Memory for hp=22,t=12 is 32,752 bytes; payload is 16,384 bytes, with a 96-byte
file header. Root-only hp=t has a 16-byte payload and no authentication-path
acceleration. Export paths are ordinary user files; callers should use secure
directories and avoid concurrent writers.

## Build and checks

From the authoritative server project root: `make -C c all test`, followed by
`make -C c sanitizer`. The shared library is `build/libslhdsa_sm3.so`.
The sanitizer executable is `build/sanitizer/test_native` (ASan + UBSan).
Counter builds are separate: `make -C c OUT=../build/counters COUNTERS=1`.
Counters are global atomics across contexts; timing builds leave them zero.

Native tests include SM3 known answers, full toy/SHA2-128s/SHA2-128f seeded
keygen-sign-verify, pure context, signature corruption/truncation, invalid
backend/context/subtree inputs, cache round trip/tampering, and thread-count
subtree equivalence. Independent reference and external-vector evidence is
collected outside these tests.

Contexts own mutable cache/key state and must not be mutated concurrently.
Bound-key subtree calls read immutable context data. The library does not
provide a production signature-budget ledger or secret-key file encryption.
