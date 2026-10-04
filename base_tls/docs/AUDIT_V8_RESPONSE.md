# Response to the eighth review (`audit_v8`, the red-team pass)

The eighth package is the third **attack** package and the first with a red-team surface scan
next to the protocol cases: 21 case scripts, 134 cases, and a problem list that separates
"still broken" from "expected disagreement", "declared boundary" and "the auditor's own fixture
bug". This is the disposition of every item, with the evidence that decides it.

The improvement plan that arrived with it (`hybrid-tls13-v9-改进方案.md`) is the specification
this round follows, including its M0–M4 staging, its insistence that a non-zero exit is not
automatically a security verdict, and its rule that a declared boundary is documented rather
than "fixed".

## What this round changed, in one table

| Their id | Finding | Status | Evidence |
|---|---|---|---|
| **V8-01 / T1** | a declared dispatch site inside `if typing.TYPE_CHECKING:` passed the sweep | **fixed**: the sweep evaluates a small constant language (`False`, `0`, `while False`, the `else` of always-true tests, and `TYPE_CHECKING` through a resolved, unshadowed import alias), marks the branch that cannot run, and refuses a declaration whose site is in it | probe T1 now `exit=1` with the target named and the reason `is inside a statically dead branch`; `audit_v9/strict_results.json` S1 |
| **V8-01 / T2** | the same for a declared site inside a function nobody calls | **fixed**: a limited call graph from declared entries plus reviewed interface bindings, with nested functions keyed as `Class.method.<locals>.helper`; a nested body is reachable only when something loads its name | probe T2 now `exit=1` with `sits in HybridClient.receive_server_hello.<locals>._never_called_helper, which no path from a declared entry reaches`; S2 |
| **T5** | a *legal* multi-share ClientHello was refused with `69 trailing bytes`, which describes a framing problem where the cause is a capability limit | **fixed as a message and as a fixture**: the refusal is now a named profile limit ("this profile accepts exactly one classical share and implements no HelloRetryRequest"), and the corrected case builds the message properly (inner and outer lengths, second group added to `supported_groups`) | `tests/test_audit_v8_fixes.py::test_a_legal_multi_share_client_hello_is_refused_by_profile_not_by_framing`; `docs/CAPABILITIES.md` |
| **T6** | partial seed overlap (`seed = public_seed[16:] + unknown`) is still accepted | **kept as a declared boundary, deliberately**: neither the length rule the review sketched nor a string comparison can establish independence, so the contract is documented instead (deterministic entry point for tests and restores, random creation path for keys) and no "closed" claim is made | probe T6 stays `INFO-DEVIATION`; `docs/CAPABILITIES.md` |
| **W1** | one connection costs a whole XMSS key generation; the U-03 fix made it worse | **measured, not assumed**: a new `bench/measure_xmss_lifecycle.py` separates whole-tree keygen, certificate build, one sign/verify, the online handshake, and cold vs hot modes, with wall and CPU time and raw samples. The driver can now take pre-generated credentials (**credential reuse only**; transcript, ECDHE/KEM ephemeral keys, traffic secrets and record sequences stay per handshake) | below |
| **W2** | Finished verification was a content-dependent early exit on both sides | **fixed**: `hmac.compare_digest` on both roles, length checked first with its own message, plus behaviour tests (first/middle/last byte, wrong length, empty, both roles, one end-to-end tamper) and an AST guard that no plain equality on tag material returns | `tests/test_audit_v8_fixes.py` (10 tests); probe W2 now `PASS` |
| **W3** | the demo printed the first 12 bytes of every derived secret | **fixed**: the default output prints names, algorithms, lengths and status only; `--fingerprint` adds a labelled domain-separated hash; the raw-prefix mode is gone | output-capture tests plus their text scan; probe W3 now `PASS` |
| **W4** | a hash *count* is not an association | **fixed**: `tools/verify_dependency_lock.py` verifies per package (pin shape, ≥1 well-formed sha256, no conflicting duplicate, no duplicate hash) and refuses any downloaded artefact whose digest is not in a trusted lock; acceptance check 4c | `bench`-independent tests in `tests/test_audit_v8_fixes.py`; S7 |
| **TB-1** | the sandbox helper consulted its switch before the platform, so "explicitly enabled" widened permissions on Unix too | **fixed**: the platform check is unconditional and first; six combinations are tested | `tests/test_audit_v8_fixes.py::test_the_sandbox_helper_requires_windows_before_its_switch`; S8 |
| **TB-2** | the helper widens new directories' permissions | **documented and bounded**: the patch requires Windows, is inert unless a DSH sandbox is detected or explicitly asked for, and the independent-run record states that it is *not* on `PYTHONPATH` there | `validation/environment-independent.json`; S9 |
| **EX-1** | "ephemeral keys are destroyed after the handshake" cannot be guaranteed in CPython | **wording corrected**: forward secrecy is stated as a protocol property under the assumption that process memory is not recovered; `del`/GC are explicitly not erasure | `docs/CAPABILITIES.md` §"Key management and state" |
| **EX-2** | the single-share limit and the AAD deviation should be in one place | **fixed**: `docs/CAPABILITIES.md` is the matrix, and `PROTOCOL.md` points at it | `docs/CAPABILITIES.md`, `docs/PROTOCOL.md` |
| **EX-3** | the audit package's `fetch_*.py` downloaded wheels without hash verification | **fixed on the audit side**: the fetch helpers now call `verify_wheel` against a trusted lock before unpacking; an artefact without a matching pin is refused | `audit_v9/original/` keeps the originals byte-identical; `audit_v9/REVISION_DIFF.md` records the change |

Their four `VULNERABLE` cases that are **historical expectation disagreements** (B7, B8, B10, D4)
are untouched, as the plan instructs: a leaf that legally omits an optional extension, an EdDSA
issuer, and a record-limit model of `2**64` where RFC 8446 §5.5 says `2**24.5`. `J1`/`J3`
(`HARNESS-BROKEN`) are their stale expectation that an illegal `(aead, hash)` pair is accepted.
`K4`/`M1` (`HARNESS-BROKEN`) are the *fix* firing: the case can no longer construct the message
its finding needs.

`V2`/`V3`/`V4` (the 240-file integrity chain, the 28 patch hunks, the input package hashes)
report `HARNESS-BROKEN` here for a structural reason worth stating: they verify the *v8 package's*
file set against its own manifest, and this tree is not that package. The equivalent record for
v9 is `PACKAGE_MANIFEST.md` + `SHA256SUMS.txt` in the v9 package.

## W1 in numbers (this machine, one run, raw samples in `.bench-lifecycle/`)

| height | leaves | whole-tree keygen (median, 5 cold inits) | one sign | one verify | cold handshake | hot handshake (30 runs) | online share of hot |
|---|---|---|---|---|---|---|---|
| 8 | 256 | 544.0 ms (526.7–557.4) | 3.29 ms | 1.14 ms | 724.8 ms | 5.83 ms | 5.61 ms |
| 10 | 1024 | 3047.6 ms (2884.0–3073.7) | 3.67 ms | 1.14 ms | 3023.9 ms | 7.06 ms | 6.78 ms |

What this says, and what it does not:

* the cost is **the whole-tree key generation**, not the handshake: a h=10 cold connection is
  ~3.0 s and the same connection with a pre-generated credential is ~7 ms;
* "hot" reuses the **authentication credential only**. Each handshake still builds its own
  transcript, ECDHE and KEM ephemeral keys, traffic secrets and record sequences, and each
  signature still spends a fresh leaf (the accounting is in the JSON: `leaves_spent` equals the
  number of handshakes, and the leaf-index uniqueness itself is asserted by
  `tests/test_handshake.py`);
* the review's own 568 ms / 2286 ms and this run's 544 ms / 3048 ms are **different machines**,
  so no cross-version factor is claimed from them;
* this is still not a remote denial-of-service claim. There is no long-running listener in this
  repository: the loopback driver builds credentials once and then serves one connection. The
  trigger timeline is recorded in the JSON so a reader can check that; connection flooding,
  mid-handshake aborts and queue backpressure are **not measured** and are listed as gated work;
* **no persistence is enabled or claimed.** The plan's stage-2 state design (monotonic counter
  source, crash tests, rollback resistance) is a prerequisite for running XMSS credentials across
  processes, and none of it exists yet, so the mode stays single-process and temporary.

## Sweep A after the hardening: what it now decides

```
check-like definitions under tls/: 87
  live from implementation or drivers : 54
  reached only through an interface   : 25
  called by a framework               : 8
  referenced only through a variable  : 0
  referenced only from unreachable code: 0
  referenced nowhere                  : 0
  declared entries / reachable functions: 7 / 223
PASS  (limited static analysis)
```

The rules, in the order the review asked for them: lexical scope with `<locals>` in nested
names; a small constant evaluator that never imports or `eval`s the tree under test; a limited
call graph from declared entries (each verified to exist, each stating how it runs) plus reviewed
interface bindings; declarations verified against AST evidence **and** reachability, so free text
is never evidence; one rule for every reference syntax, so a dead branch cannot contribute a
caller; and three distinct exit codes (0 clean, 1 unverified evidence, 2 tool failure).

Two interface entries were added with the mechanism named, because the receiver's type is a
runtime configuration choice: `tls/pq/signature.py::Xmss.keygen` (key generation goes through
`config.pq()`) and `tls/classical/ecdh.py::EcdheKeyPair.public_key_bytes` (the pair is built by
`EcdheKeyPair.generate(...)`, so `self.ephemeral` has no statically known type). Both must still
have a variable-receiver reference from a live root, which the verifier checks.

**What the sweep still cannot do**: a name assembled at runtime, a callback registered by string,
a receiver needing real type inference, and anything that depends on values rather than syntax.
Those limits are in the module docstring and in `docs/AUDIT_SWEEPS.md`, and no pass should be
read as a runtime reachability proof.

## Their own open verification items (U-01…U-07)

| id | Item | What this round can say |
|---|---|---|
| U-01 | the rustls prototype was never built by them | unchanged: it is built and run here (`5/5` runs, two negative controls), and it covers the key exchange only |
| U-02 | Verifpal/Tamarin not re-run by them | unchanged: the six models run here; the mapping to the implementation is still independently unchecked |
| U-03 | they could not run the 21 acceptance checks | **addressed**: the acceptance script now also gates the lock association (4c), the environment manifest (4d) and the lifecycle separation (5c) — 35 checks, and `validation/environment.json` records what produced them |
| U-04 | 21 pytest errors in their environment | **explained, not "solved"**: they are the sandbox denying `pytest`'s base temp directory, not test failures. The independent-style record states exactly what was run and what the workaround was (`validation/README.md`) |
| U-05 | their hash/diff/coverage evidence was not re-derived here | **re-created for v9**: `SHA256SUMS.txt` over 127 files, a source patch, and the compat/strict runs below |
| U-06 | RFC 8446 not read end to end | unchanged; the sections this work relies on are quoted with section numbers, and the record-layer deviation is stated rather than argued |
| U-07 | leaf-reuse consequences not quantified | unchanged; `SECURITY.md` gap 14 and the plan's stage-2 gate keep it open |

## Evidence for this round

```
python -m pytest tests -q                     # 393 passed
tools\audit_live_checks.py                     # 87 checks, 0 dead, 0 unreachable
tools\verify_dependency_lock.py                # 2 locks, 11 packages, all pinned and hashed
tools\verify_all.ps1                           # 35 checks, 35 passed
bench\measure_xmss_lifecycle.py --heights 8 10 --cold 5 --hot 30   # .bench-lifecycle/
audit_v9/run_cases.py --mode compat            # the original 21 cases, unmodified
audit_v9/strict/...                            # 11 strict cases, 11 PASS
```

The compatibility run is the informative one for this round's claims, because the case scripts
are byte-identical to the audited versions: **T1 and T2 (`exit=1`, was 0), Q1/Q2/S (`exit=1`),
Q3 (`exit=0`), W2 and W3 (`PASS`, were INFO-DEVIATION), T6 (`INFO-DEVIATION`, kept)**. The
strict run adds the criteria the plan requires — exit 1 *and* the target named, exit 2 treated as
a tool error, positive controls for every regression — and all eleven pass.

## What remains open

* XMSS state across processes: no counter source, no crash tests, no rollback resistance. Not to
  be enabled or claimed until that design exists;
* Sweeps B and C (derived-value inputs, constraint scope) are still specifications;
* the certificate validator is still hand-written;
* no independent review of any v7, v8 or v9 fix — the same statement as every round before it.
  This round's own probe results are, by construction, the author running the auditor's scripts.
