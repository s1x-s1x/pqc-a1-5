# Independent Python reference

This model inherits Algorithms 2-25 from `third_party/py-acvp-pqc/fips205.py`
at commit `1c859956c0217b04fa5ae76e338e5570aba622c5`. The upstream license is
the Unlicense. The only upstream source edit defers its data-loading test import
until `__main__`; the original algorithms and parameter table are intact.

`slhdsa.py` adds the seven SPEC parameter identifiers, SM3 and SHA-256 hashes
through hashlib with a copied 64-byte prefix state, input checks, an iterative
treehash, and process-pool subtrees with deterministic indexed merging. The
sequential keygen/sign/verify algorithms remain inherited from the upstream.
`sm3.py` supplies a pure Python fallback for bounded tests and verification.
The upstream import requires `pycryptodome` even though project hash operations
use hashlib. Python 3.10 or later is supported.

No project C source was read while implementing this model. Source-language
independence complements external test vectors; it is not proof that the
implementations are statistically independent or secure.

```python
from reference import ReferenceSlhDsa

with ReferenceSlhDsa(201, workers=1) as reference:
    pk, sk = reference.keygen_internal(sk_seed, sk_prf, pk_seed)
    sig = reference.sign(message, sk, context=b"", addrnd=None)
    assert reference.verify(message, sig, pk)
    # sign_internal/verify_internal accept the already encoded M'.
```

For large trees, use `workers=32` to `48`. A model owns its process pool and
must be closed with `close()` or a `with` statement. On Windows, callers that
use multiple workers must follow the normal multiprocessing `__main__` guard.
`subtree("wots" | "fors", sk_seed, pk_seed, adrs, leaf_start, z, target=None)`
returns the root and bottom-up path. FORS leaf_start includes the global offset.

Bounded checks and timing precede complete large-parameter vector generation:

```sh
python3 -m reference.selftest
python3 -m reference.acvp --workers 16 --output results/python-acvp.json
python3 tools/generate_reference_vectors.py --pid 3 --workers 48 smoke --kind fors --height 18
python3 tools/generate_reference_vectors.py --pid 3 --workers 48 smoke --kind wots --height 14
python3 tools/generate_reference_vectors.py --pid 3 --workers 48 vectors --count 3
```

JSONL records contain all three key seeds, the actual opt_rand, raw and encoded
messages, context, keys, signature, byte-content hashes, source fingerprints,
diagnostic timings, and a canonical record hash. Even indexes use deterministic
signing; odd indexes use an explicit seeded randomizer. Existing output requires
`--append --start-index N`, so a partial run can be resumed explicitly. A record
is appended only after complete keygen/sign/verify and a negative message check.
No full vector completion is inferred from a smoke test.

The ACVP runner uses the pinned upstream JSON snapshot: 20 keyGen, 104 sigGen,
and 84 sigVer cases (208 total). Prehash ACVP cases use upstream's unchanged
formatting helper before calling the project internal API. This tests the
internal signature framework and does not add a prehash project ABI.

## C/Python evidence and R1 accounting

`differential.py` invokes only `tools/native.py` and the public ABI. Its complete
suite checks the already-generated three 128-24 vectors without regenerating
the costly Python side. The toy suite gives every case a distinct seeded key
and message, signs deterministically or with an explicit randomizer, and checks
both positive verification and changed/malformed input rejection. Subtree
coverage is a separate auxiliary suite across all seven parameter identifiers,
both leaf types, and native thread counts 1 and 4.

```sh
python3 -m reference.differential --threads 48 --output results/sm3-128-24-differential.jsonl complete
python3 -m reference.differential --workers 32 --output results/toy-differential.jsonl toy --count 1000
python3 -m reference.differential --workers 16 --output results/subtree-differential-balanced.jsonl subtree --count 1000
python3 -m reference.r1_evidence
```

`evidence/R1-python.jsonl` contains four scoped rows: 208 external ACVP source
cases, 3 full SM3-128-24 cases, 1000 full toy cases, and 1000 auxiliary subtree
cases. Each input case is counted once even when it has multiple assertions.
The 32-case timing diagnostic and earlier unbalanced-height subtree diagnostic
are excluded. Running the same ACVP cases against C does not double the number
of source vectors. Eight bounded selftest methods are documented separately
in `evidence/python-selftests.log` and are not added to the vector total.

The toy suite ran against the source fingerprint in
`evidence_sources/differential_2736be1.py`; the later source change only balances
height selection in the separate subtree suite. This archived file has the
exact original source SHA-256 recorded in the toy evidence. Large-parameter
and final subtree evidence refer to the current source fingerprint.

All timings in these files are diagnostic correctness-run timings. Report
framework section 8 requires separately substantiated final performance claims;
these records do not claim formal implementation proof, certification,
absence of defects, or completed production deployment.
