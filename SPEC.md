# A1-5 implementation specification

Version: 1.1-draft, 2026-10-04. Changes are tracked in LOG.md.
The current review boundary is CPU and CUDA optimization correctness, immediately before
formal performance testing. Version 1.0 evidence remains tied to its archived sources.

## Scope and parameter table

This is an experimental SM3 instantiation of the FIPS 205 algorithm framework.
The limited-use parameters follow SP 800-230 ipd, Table 1 (PDF page 10).
Neither the SM3 substitution nor these draft parameters are a FIPS 205
certification claim. A maximum of 2^24 signatures per limited-use key applies
across all copies and devices. The file CLI uses a shared experimental signing
reservation ledger. This does not enforce the limit on disconnected copies or
direct C ABI callers; operators must reconcile backups and separate deployments.

| pid | hash | n | h | d | h/d | a | k | lg(w) | len | m | signature bytes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | SM3 | 16 | 63 | 7 | 9 | 12 | 14 | 4 | 35 | 30 | 7856 |
| 2 | SM3 | 16 | 66 | 22 | 3 | 6 | 33 | 4 | 35 | 34 | 17088 |
| 3 | SM3 | 16 | 22 | 1 | 22 | 24 | 6 | 2 | 68 | 21 | 3856 |
| 101 | SHA-256 | 16 | 63 | 7 | 9 | 12 | 14 | 4 | 35 | 30 | 7856 |
| 102 | SHA-256 | 16 | 66 | 22 | 3 | 6 | 33 | 4 | 35 | 34 | 17088 |
| 103 | SHA-256 | 16 | 22 | 1 | 22 | 24 | 6 | 2 | 68 | 21 | 3856 |
| 201 | SM3 | 16 | 10 | 1 | 10 | 10 | 6 | 2 | 68 | 10 | 2320 |

All public keys are 32 bytes; secret keys are 64 bytes.
The toy parameter is for testing only and has no security-category claim.

## Primitive definitions

ADRS is 32 bytes, all integer fields are big endian. Types 0..6 are WOTS_HASH,
WOTS_PK, TREE, FORS_TREE, FORS_ROOTS, WOTS_PRF, FORS_PRF. The compressed address
is ADRS[3] || ADRS[8:16] || ADRS[19] || ADRS[20:32] (22 bytes).

For n=16, PRF/F/H/T use the first n bytes of
HASH(PK.seed || zero[48] || ADRSc || input). HASH is SM3 or SHA-256 as selected.
PRF_msg is truncated HMAC-HASH(SK.prf, opt_rand || M'). H_msg is
MGF1-HASH(R || PK.seed || HASH(R || PK.seed || PK.root || M'), m).

Pure-mode M' is 0x00 || context_length_byte || context || message. Context length
is at most 255. Internal APIs accept the already encoded M'. Deterministic
signing uses PK.seed as opt_rand; explicit randomization accepts n bytes.
Prehash-mode M' is 0x01 || context_length_byte || context || DER(OID) || PH(message).
Both message APIs (hash internally) and digest APIs (accept exactly the digest
length below) are exported. Pure, internal and prehash encodings are distinct.

| hash id | PH | digest bytes | OID |
|---|---|---|---|
| 1 | SHA-256 | 32 | 2.16.840.1.101.3.4.2.1 |
| 2 | SHA-512 | 64 | 2.16.840.1.101.3.4.2.3 |
| 3 | SHAKE128 | 32 | 2.16.840.1.101.3.4.2.11 |
| 4 | SHAKE256 | 64 | 2.16.840.1.101.3.4.2.12 |
| 5 | SM3 | 32 | 1.2.156.10197.1.401 |

The SM3 DER OID is `06 08 2a 81 1c cf 55 01 83 11`.
SM3 prehash is an experimental extension. Prehash work is separately reported
from the seven SLH primitive counters. Invalid digest sizes/hash ids return
SLH_ERR_PARAM; contexts above 255 return SLH_ERR_CTXLEN. Sign APIs initialize
the reported signature length to zero before message/digest validation.

SK = SK.seed || SK.prf || PK.seed || PK.root. PK = PK.seed || PK.root.
Signature = R || SIG_FORS || SIG_HT, with the exact parameter-derived lengths.

## ABI and backend policy

The API is declared in c/include/slhdsa_sm3.h. Backend ids are AUTO=0, REF=1,
AVX2=2; AVX512=3 and NEON=4 remain reserved and return SLH_ERR_BACKEND. The current
optimization checkpoint also implements B1 CUDA=5 as an explicitly selected
hybrid SM3 backend: FORS leaves and tree reductions execute on the GPU;
WOTS, upper XMSS, cache and message hashing retain CPU AVX2/REF execution.
CUDA requires a CUDA-enabled build and an available device; otherwise it returns
SLH_ERR_BACKEND. AUTO retains CPU selection. CUDA implementation and actual-device
correctness acceptance must both pass before this draft records support as frozen.
SM3 AUTO selects
AVX2 after CPU/OS capability detection, otherwise REF. Explicit AVX2 requires
a supported SM3 parameter, build and host. SHA2 AUTO selects REF and explicit
AVX2 returns SLH_ERR_BACKEND. `AVX2=0` builds retain portable REF behavior.
`slh_backend_available` reports the host/build capability; `slh_ctx_backend`
reports the selected context implementation. Backend and parameter support
must both be checked when constructing a context.

AVX2 code has a function-specific target attribute; release code has no global
`-mavx2` or `-march=native` requirement. Explicit unavailable backends return
SLH_ERR_BACKEND. Thread
counts are explicit; 0 selects a recorded sensible automatic allocation.
Verification validates signature length before reading its contents. ABI callers
must allocate key/signature buffers using the exported size functions.
Verify-after-sign failure clears the signature buffer and returns SLH_ERR_FAULT.
Contexts must be independently owned by concurrent callers. Context mutation,
cache operations and bound-key changes must not overlap a subtree/sign call.

slh_subtree requires leaf_start aligned to 2^z. target=UINT32_MAX requests only
the root. Otherwise target is an absolute leaf index inside that subtree; auth
is z*n bytes in bottom-up order. FORS base addresses include the global tree
offset. Bound-key contexts are immutable during a subtree call.

## Optimization and cache contract

The 64-byte `PK.seed || zero[48]` prefix is absorbed once per work initialization
and cloned for PRF/F/H/T. OpenMP partitions aligned subtrees and combines nodes
using their absolute addresses. Authentication paths remain in bottom-up order.
AVX2 FORS batches eight equal-length PRF/F/H inputs; short/upper tree sections
use REF. AVX2 WOTS batches eight chains within an XMSS leaf, signature or
public-key recovery. Active lane masks preserve completed chains, zero-step
chains and the 3/4-chain final groups. Endpoint groups enter one ordered scalar
T_len hash copied from the seed midstate. Upper XMSS H and FORS verification
remain scalar. Completion is determined by the optimization run manifest.

For subtree height hp and cache level t in 0…hp, disk format version 1 stores
only `2^(hp-t)` public nodes of height t, following a 96-byte header. The header
contains the magic A15CACHE, version, pid, t, hp, n, payload bytes, full PK and
an SM3 digest of header[0:64] plus payload. Integer header fields are big endian.
On load, the exact file length, digest and bound PK are checked; upper nodes
are reconstructed and must match PK.root. Node RAM is
`(2^(hp-t+1)-1)*n` bytes. For pid3, valid t is 0…22.

Keygen creates a cache at the configured level (default min(hp,12)). Setting a
level clears the previous cache. Loading public nodes does not bind an SK;
subtree callers bind the key explicitly. Signing applies a cache only for a
matching PK.seed and PK.root. A fresh signing context can select the uncached
path without changing the parameter or signature format.

The cache digest detects corruption; it is not a secret-key MAC. Files contain
public nodes and no secret seeds. Hardware lanes that serve as padding in a
partial SIMD batch do not count as SLH operations. Counter equivalence covers
logical operations, while performance measurements cover actual executed work.

## File CLI and signing reservations

`tools/cli.py` exposes keygen, sign, verify, cache-build, cache-load and
capabilities. Inputs and key/signature outputs are binary files. Key metadata
records the actual backend and shared-library hash. Existing output files are
rejected; secret-key creation requests mode 0600. The CLI enables
verify-after-sign and accepts pure or one of the five prehash modes.

Signing requires `--budget-db`. `tools/signing_budget.py` uses SQLite WAL,
FULL synchronous commits and BEGIN IMMEDIATE. A reservation consumes one use
before signing starts; failures and crashes retain the charge. Each reservation
has a receipt and ordinal, and may become committed or failed. The key identity
binds the algorithm name and public key. Per-key limits are stored as decimal
strings so 2^64 is representable. The limited-use 128-24 maximum is 2^24.
Changing a registered limit requires an explicit ledger migration. All
cooperating callers must share the same ledger. Benchmark reservations occur
outside the timed primitive region, and fixtures use separate experimental keys.

## Correctness evidence

- SHA2-128s/128f external ACVP keyGen/sigGen/sigVer: count actual downloaded
  cases in the manifest. The inspected official revision has 208 cases for these
  two parameters; 1248 describes all twelve parameter sets.
- SHA2-128-24: external xous-core vector, pinned by commit and content hashes.
- SM3-128s/128f: gmsm v0.44.1, both deterministic and explicit randomized inputs.
- SM3-128-24: C versus Python, at least three complete seeded cases.
- Toy inputs and subtrees: randomized differential tests, invalid inputs,
  cache tampering, and thread-count equivalence.
- Address/length boundary regressions include WOTS len=68, subtree height=22,
  d=1 zero-width tree index, w=4 checksum and uint32 FORS offsets.

Different source languages and external vectors provide complementary evidence;
they do not prove statistical independence or replace a security proof.
Unexpected formal-model results are preserved and investigated.

## Counts, measurements and safety claims

WOTS chain-step counts use the actual message and checksum digits. Fixed tree
costs, message-dependent costs and approximate expected values are separate.
The prior table's 276 verification calls is an approximate mean, not a per-case
exact count. Counter builds are separate from timing builds.

Stage 1 diagnostic timings are not final performance claims. Final results
record commit, build flags, CPU affinity, NUMA allocation, clock policy, backend,
sample count and dispersion. The host's enabled boost/schedutil configuration is
reported as observed; this account does not change those host controls.

FORS probability curves describe that attack term, not a full EUF-CMA security
level. SM3 adaptation is conditional on the needed underlying-function
assumptions. Full-hash and truncated-output quantum bounds are kept separate.

## Review boundary and provenance

The first scalar milestone is preserved in
`validation/stage1-20261004-0100/manifest.json`. The FORS/prehash Linux milestone
is preserved in `validation/native-stage2-20261004-0152/manifest.json`, including
an archived source package. WOTS and the expanded optimization matrix require
their own current-source acceptance before the CPU checkpoint is complete.

`docs/OPTIMIZATION_CHECKPOINT.md` records the user's current stop condition.
Formal timing, further TLS/network experiments and report drafting do not start
at this boundary. GPU correctness records must bind the CUDA source and library,
record the actual device and selected backend, compare signature bytes and all
seven logical counts with REF, and leave kernel event timing disabled.
Future GPU performance plans separately identify kernel event time and full
host ABI time; preparation creates no timing samples. Completed optimization
does not establish full TLS interoperability, formal performance results or
production CA operation.
