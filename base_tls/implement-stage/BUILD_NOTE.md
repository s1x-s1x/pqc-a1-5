> **2026-09-21 U-03 follow-up:** this document retains historical analysis and measurements. The fixed constant-chain construction is superseded by the independently seeded/addressed/masked implementation documented in `docs/U03_WOTS_STEP_KEYS.md`. This change is not a completed security reduction; updated test and measurement evidence is in `validation/` and `.bench-u03/`.

# Build Note — hybrid-tls13

Request: *"我们先去实现这个东西，先不去想论文的事"* — build the hybrid TLS 1.3 handshake
the design note describes; `ASK=never`, `EFFORT=balanced`, one run.

## Ladder

| Rung | Feature | Acceptance check (ONE command) | Tier | Status |
|------|---------|-------------------------------|------|--------|
| F0 | spine: client/server exchange ClientHello → ServerHello → dual-signed CertificateVerify → Finished, with real ML-KEM/Falcon and real HKDF; PKI modelled | `python demo/run_handshake.py` → `application data round trip: ok`, exit 0 | MUST | ✅ |
| F1 | transcript binding + hybrid acceptance: both signatures over one input, conjunction, Finished over the full transcript | `python demo/run_handshake.py --tamper pq-signature` (and `classic-signature`, `certificate`, `kem-ciphertext`) → each rejects at the expected step | MUST | ✅ |
| F2 | pluggable PQ signature backends: ML-DSA 44/65/87, Falcon 512/1024/padded, WOTS+/XMSS | `python demo/run_handshake.py --pq xmss --xmss-height 10` → exits 0 with the same checks green | MUST | ✅ |
| F3 | byte accounting: per-message breakdown and per-addition PQ deltas | `python bench/measure_handshake.py --repeats 10` → 15 profiles, all `ok=True` | MUST | ✅ |
| F4 | primitive timings: KEM keygen/encaps/decaps, signature keygen/sign/verify, sizes | `python bench/measure_primitives.py --iterations 30` → `.bench-out/primitives.{json,md}` | MUST | ✅ |
| F5 | pytest suite pinning wire, key schedule, messages, and the tamper matrix | `python -m pytest tests -q` | MUST | ✅ |
| F6 | loopback TCP transport: latency includes syscalls, and the 1-RTT claim becomes an observed wait count | `python bench\measure_tcp.py --repeats 10` → every profile reports `waits_to_authenticated=[1]` | SHOULD | ✅ |
| F7 | wire interoperability with a real TLS stack (provider + draft binding) | not started | DEFERRED | ⬜ |
| F8 | symbolic verification of the hybrid authentication in Verifpal: baseline plus two single-half compromises and two failing controls | `.tools\verifpal\verifpal.exe verify verification\verifpal\hybrid_auth*.vp --sessions 1 --result-code` → baseline and both single-half models `c0a0a0f0a1`; both controls break | SHOULD | ✅ |
| F9 | byte-exact protocol specification, verified against a live handshake dump | `python tools\dump_wire.py` → layouts and sizes match `docs/PROTOCOL.md` | MUST | ✅ |
| F10 | classical TLS 1.3 baseline measured through the same code path (was an analytic estimate) | `python bench\measure_handshake.py --repeats 5` → every hybrid row carries `baseline_bytes` and `measured_pq_delta` | MUST | ✅ |
| F11 | real X.509 chain (root→intermediate→leaf, real validation, PQ key in a leaf extension) so absolute byte counts become comparable | `python tools\check_x509.py` → baseline 1404 B, hybrid 5272 B, ratio 3.75× | MUST | ✅ |
| F12 | network shaping (RTT, bandwidth, loss) around the loopback transport, with the link's own latency prediction checked against the measurement | `python bench\measure_shaped.py` → every profile `ok=True` and 1-RTT; paired hybrid-vs-classical difference reported per round | MUST | ✅ |
| F13 | real TLS stack integration (rustls): hybrid X25519+ML-KEM-768 group, negotiated and completed, with a share-size control | `powershell -File tools\build_rust_prototype.ps1 -Offline` → `hybrid key exchange negotiated in rustls: +2272 bytes over X25519 alone` | MUST | ✅ |
| F14 | wire interoperability with a deployed stack (provider + draft binding) | not started | DEFERRED | ⬜ |
| F15 | reduction skeleton for the hybrid authentication and key-secrecy claims, with the executable premises of each hop cited and the gaps listed | `docs/REDUCTION.md` exists and every premise it cites names a test that passes | MUST | ✅ (bounded: **not machine-checked, not second-read**) |
| F16 | handover package for an external reviewer: three tasks with acceptance criteria, environment, reporting format, and what not to inherit | `docs/HANDOVER.md` + `verification/tamarin/README.md` exist and every path and count they cite was checked | SHOULD | ✅ |
| F17 | the delivery package itself: reproducible builder, reviewer-facing documents, hashes, and a zip verified by extracting and running the suite from it | `powershell -File tools\make_review_package.ps1 -Force -Zip` → 2.09 MB zip; extracted copy runs `184 passed, 1 skipped` with no Falcon provider | MUST | ✅ |
| F18 | act on the external review: fix the four code defects, correct the two false claims, and record the three findings that remain open | `python -m pytest tests -q` → 186 passed; Rust self-check stable over 8 runs; `docs/REDUCTION.md` §1 and `docs/SECURITY.md` C1/C6 corrected | MUST | ✅ (three findings stay open, listed below) |
| F19 | act on the static security review: fix the trust-anchor bypass, the missing identity check, the key leak, the unbounded frame, three chain constraints, the exporter, and the unconditional directory patch | `python -m pytest tests -q` → 211 passed; `tools\verify_all.ps1` → 31/31; `tests/test_rfc8448_vectors.py` reproduces 7 RFC 8448 values byte for byte | MUST | ✅ (name constraints and the read deadline stay open, listed below) |
| F20 | act on the v3 audit: the wrong transcript prefix for the application and exporter secrets, a rustls client that verified nothing, three certificate-validator gaps, an XMSS leaf race, the frame deadline, the zero-shared-secret check, dependency locking, and the platform limit on the directory patch | `python -m pytest tests -q` → 233 passed; `tools\verify_all.ps1` → 31/31; `build_rust_prototype.ps1 -Offline` prints two negative controls and exits non-zero if either fails; `pip download --require-hashes -r requirements.lock.txt` verifies 10 packages | MUST | ✅ (six items stay open, listed below) |

| F21 | turn the three reading habits that found every defect so far into checkable inventories: Sweep A automated and enforced, Sweeps B and C specified | `tools\verify_all.ps1` check **4b** (`python tools\audit_live_checks.py`) → 78 checks, 76 live, 2 framework hooks, **0** unreachable; `docs/AUDIT_SWEEPS.md` records the tables | SHOULD | ✅ A done and enforced; **B and C specified but not written** |
| F22 | act on a fourth review — an independent attack package (82 cases) against v5: Sweep A's three misjudgements, the negotiation/echo gaps, the exception-escape paths, the codepoint decoupling, the record-layer limit, and the connection budget | their own suite, run against this revision: **V-01…V-09 all REJECTED** (was 10 VULNERABLE cases); `pytest tests -q` → 268 passed, `verify_all.ps1` → 32/32 | MUST | ✅ closed in F23: the exception boundary and U-03 were the two leftovers, and both are done there |
| F23 | act on a fifth review — a second attack package (104 cases, ten findings) — and adopt the collaborator's U-03 patch: the server-message extension rules (K2–K6), the path-length crash (K1), the session-id bound (K7b), the XMSS exhaustion escape (N1), the seed-overlap guard (M3/M1), and the two Sweep-A satisfiability holes (V6-10a/b) | `pytest tests -q` → **320 passed**; `verify_all.ps1` → **32/32** on the merged tree; `tools\audit_live_checks.py` → 86 checks, 65 live, 13 interfaces, 8 hooks, 0 unaccounted; U-03 claims re-measured here (`public_key_bytes=64`, `signature_bytes(h=10)=4612`, `scheme_id=0xFE00+h`) | MUST | ✅ all ten findings disposed of in `docs/AUDIT_V6_RESPONSE.md`; XMSS state rollback and Sweeps B/C stay open |
| F24 | act on an eighth review — a red-team pass with 134 cases and an improvement plan staged M0–M4: freeze the audit evidence, harden Sweep A into a limited reachability analysis (T1/T2), measure the XMSS lifecycle instead of asserting it (W1), compare Finished with `hmac.compare_digest` (W2), stop printing derived secrets in the driver (W3), verify dependency locks per package (W4), put the platform check first in the sandbox helper (TB-1), and write the capability matrix (EX-1/EX-2/T5/T6) | `pytest tests -q` → **393 passed** in both the author-side and the patch-free environment; `verify_all.ps1` → **35/35** (4b sweep, 4c locks, 4d environment, 5c lifecycle); original audit cases unmodified → **T1/T2 `PASS` (exit=1), Q3 `exit=0`, W2/W3 `PASS`**, T6 stays `INFO-DEVIATION`; 11/11 strict acceptance cases | MUST | ✅ disposed of in `docs/AUDIT_V8_RESPONSE.md`; XMSS state persistence, Sweeps B/C and the four historical disagreements stay as they are |

### Rung F24: the red-team round, and the two things it refused to over-claim (current revision)

The eighth package was the third attack package and the first with a red-team surface scan. Its
improvement plan carried two rules that shaped this round more than any finding: **a non-zero exit
is not automatically a security verdict**, and **a declared boundary is documented, not "fixed"**.
Both are visible in what the rung did *not* do.

**Sweep A became a limited reachability analysis.** v8 validated a declared dispatch site's
syntax; the review planted the same declaration inside `if typing.TYPE_CHECKING:` and inside a
function nobody calls, and both passed (T1/T2). v9 adds a lexical scope model that names nested
functions as `Class.method.<locals>.helper`, a small constant evaluator that never imports or
`eval`s the tree under test, a limited call graph from declared entries plus reviewed interface
bindings, verified declarations (one definition, stated mechanism, reachable site), one rule for
every reference syntax, and three exit codes: 0 clean, 1 unverified evidence, 2 tool failure. The
regression matrix is in `tests/test_live_checks.py` (26 tests, including the counterexamples the
plan listed: `False`/`0`/`while False`, the `else` of an always-true test, a shadowed
`TYPE_CHECKING`, a called versus an uncalled helper, a borrowed declaration, a wrong line).

**The cost question was measured, not asserted.** `bench/measure_xmss_lifecycle.py` separates
whole-tree keygen, certificate build, one sign/verify, the online handshake and cold versus hot
mode, with wall and CPU time and raw samples. On this machine: h=8 keygen 544 ms / cold 725 ms /
hot 5.8 ms, h=10 keygen 3048 ms / cold 3024 ms / hot 7.1 ms over 30 runs each. Hot mode reuses the
authentication credential **only**; every handshake still builds its own transcript, ephemeral
keys, traffic secrets and record sequences, and spends a fresh leaf. Their 568/2286 ms came from
another machine, so no cross-version factor is derived from the pair, and there is still no
long-running listener here — connection flooding, aborts and backpressure are unmeasured, and
**no XMSS state is persisted**: cross-process reuse waits for the plan's stage-2 design.

**What the round refused.** T6's partial seed overlap stays an `INFO-DEVIATION` (no length rule
can establish independence, so the contract is documented and no "closed" claim is made). The four
historical `VULNERABLE` cases (B7/B8/B10/D4) are untouched. The reviewer's stale fixtures
(J1/J3) are recorded rather than edited. And the 39 `tmp_path` setup errors in a patch-free
environment are recorded as an environment limit — with the before/after numbers — rather than
described as solved; all that changed is that the suite now provides its own fixture contract and
therefore runs in both environments.

**Evidence, both ways.** The compatibility run executes the 21 original case scripts
byte-identically (21/21 hash-checked) against this tree; the strict run applies the plan's
criteria to 11 cases. Both are in `02-审查记录/06-v8审计/audit_v9/`, with `compat_results.json`,
`strict_results.json` and `REVISION_DIFF.md`.

### Rung F23: a fifth review, and the U-03 patch adopted

A second attack package arrived: ten case scripts, 104 cases, ten new findings, plus a re-check
of the previous round's 22 items. Its own summary of where the defects were: *the client half of
the negotiation was complete, the two messages the **server** sends had no rules at all*. Same
shape as three reviews before it — a constraint enforced for one object and not its structural
neighbour — with the neighbour being the other direction of the handshake this time.

**Closed in this rung.** Ten findings, each with an executable test in
`tests/test_audit_v6_fixes.py` (14 tests: one per finding plus three positive controls). Four
earlier rounds had produced fixes without regression tests, which is exactly how the same shape
kept returning.

| Their id | What it was | Fix |
|---|---|---|
| V6-01 (K1) | the one `basicConstraints` lookup without the default its seven neighbours had, in the `pathLenConstraint` walk, so a legal leaf that omits the extension crashed validation with `ExtensionNotFound` | treated as `ca=False`, same reading as everywhere else |
| V6-02 (K2) | the client accepted a ServerHello carrying an extension it never offered | a closed allowed-set check (RFC 8446 §4.1.3), named `server_hello` rejection |
| V6-03 (K3) | the client accepted any extension in EncryptedExtensions | this profile offers none, so any is a named `server_flight` rejection |
| V6-04 (K4) | two `KeyShareEntry` values: the client read the first and dropped the rest | the extension body must be consumed exactly (`expect_end`) |
| V6-05 (K5) | four garbage bytes after the `pq_ciphertext` vector were dropped silently | same rule; the test appends **after** the vector on purpose, because appending inside it is caught by the KEM length check instead |
| V6-06 (K6) | a non-empty `certificate_request_context` was accepted | refused at decode in **both** certificate bodies (`Certificate`, `X509Chain`) |
| V6-07 (K7b) | the server echoed a 255-byte `legacy_session_id` | the 32-byte bound is enforced at decode on **both** messages, so neither role leans on the echo check |
| V6-08 (N1) | an exhausted XMSS key left the server flight as a bare `ValueError` | the flight is decorated **and** the signer's refusal is converted at the boundary, carrying the cause; the primitive keeps raising `ValueError` by contract |
| V6-09 (M3) | `keygen_from_seed` checked lengths only, so one string could be both seeds — and the public seed is published in the public key | overlapping seeds (equal, or either a prefix of the other) are refused; the auditor's reconstruct-and-forge probe can no longer build its key |
| V6-10a | Sweep A credited any variable-receiver call whose name has one defining class, so an unreachable call line could lift a dead check to `live` | kept as a documented trade-off and now **printed**: the count plus one `variable-sole` line per entry in every run, showing the live call site that carries the verdict |
| V6-10b | a `getattr(obj, "name", None)` literal that never calls anything counted as a reference and the sweep still passed | an undeclared `getattr`-only reference now fails the sweep; a real dispatcher must be declared in `GETATTR_DISPATCHED` |

**U-03 adopted, not re-derived.** The collaborator's patch is merged whole — the constant
`_TWEAK_SEED` is gone, WOTS+ chain keys and bitmasks come from `PRF(SEED, ADRS)` with the leaf
address, chain index, absolute step and key/mask role, and the public key is
`root || public_seed`. The three-way comparison (v6 baseline / this tree / their patch) had
**zero conflicts**: they touched `tls/pq/`, two test files, eight documents and new
`validation/` + `.bench-u03/` records, none of which this tree had modified since v6. I read the
diff line by line against RFC 8391 §2.5/§3.1.2/§5.1 before merging it, and re-measured their
claims on the merged tree rather than quoting them: `public_key_bytes = 64`,
`signature_bytes(h=10) = 4612`, `scheme_id = 0xFE00 + height`.

The wire format therefore breaks on purpose: 32-byte public keys and the old `0x0E00 + height`
scheme no longer exist, and old signatures fail closed. That is in `docs/PROTOCOL.md` §"the
XMSS profile" and in the migration table of `docs/U03_WOTS_STEP_KEYS.md`.

**Two report defects were found by writing the response, not by an auditor.** Sweep A's
`variable-sole` and verbose lines printed `check.references[0]`, which is often a call site in
`tests/` — so a check that is live because the demo calls it looked like a check reached only
from a test. `verdict_reference` now selects the live reference that carries the verdict.
Second, `.bench-out/README_U03_HISTORY.md` still said the whole directory was pre-fix history
after the acceptance run had regenerated it on the merged tree.

**Verification on the merged revision.**

```
python -m pytest tests -q                          # 320 passed
python -m pytest tests/test_audit_v6_fixes.py -q    # 14 passed
tools\audit_live_checks.py                          # 86 checks: 65 live, 13 interfaces, 8 hooks, 0 unaccounted
tools\verify_all.ps1                                # 32 checks, 32 passed
```

Handshake sizes move with the public key, as they must: the XMSS profile at h=8 goes
7512 → 7545 bytes (+32 for the seed, ±3 for DER-encoded ECDSA), the modelled-Certificate row
carries a 64-byte PQ key. The other profiles' ±3-byte variation is ECDSA signature jitter and
predates this round.

**Environment note for anyone re-running this under a confinement sandbox.** `pytest`'s
`tmp_path` fixture needs a writable base temp directory; in this harness the platform `%TEMP%`
is not writable by child processes, so the suite reports ten `PermissionError` errors at setup
unless `TEMP`/`TMP` point inside the workspace (`$env:TEMP="$pwd\.tmp"`). That is the sandbox,
not the code: the same suite is green with the default temp directory outside it.

**Still unreviewed.** This rung's fixes, the merge and its documentation have not been seen by
anyone outside this repository. The collaborator's `validation/` records are the author's own,
which is not independent review either.

### Rung F22: a fourth review arrived with an attack package

An independent attacker built `hybrid-tls13-攻击包.zip` against package v5: ten case scripts,
82 cases, a report, a hardening plan, and per-case raw evidence. Their tally is **23
VULNERABLE, 1 PARTIAL, 2 INFO-DEVIATION, 55 PASS**, and this repository reproduced it exactly
by running their scripts against a junctioned copy of the project. Their headline is worth
keeping: *the cryptographic core held; what broke was message-field validation and the
exception boundary.*

**Closed in this rung — Sweep A (their V-20…V-22).** They did what the round-5 checklist
invited and broke the tool in three ways, plus three more that surfaced while reproducing it:

| | Misjudgement | Fix |
|---|---|---|
| V-20 | a check named only inside a **comment** was reported live | references now come from AST **call sites**; a comment cannot be a caller |
| V-21 | a check called through `getattr(obj, "name")` was reported **dead** | a string literal in `getattr` counts as a reference and is reported as `getattr-only`, for hand verification |
| V-22 | **any** dead method called `verify` was exempted | exemptions keyed on `Class.method`; a variable-receiver call is attributed only when exactly one class defines that name, otherwise the check must be declared or is reported **`UNATTRIBUTED`** |
| — | `PASS` on an empty tree | a missing or empty tree exits 2 |
| — | crashed on a UTF-8 BOM | files are read with `utf-8-sig`; unparsable files are reported, not skipped |
| — | its report contained a non-ASCII dash | the report is ASCII-only, because their harness reads it as UTF-8 |

Verified on **their** fixture, not only on one of my own: their probe tree now yields `DEAD`
for the comment probe, `getattr-only` for the dynamic one, and `UNATTRIBUTED` for the planted
`verify`. `tests/test_live_checks.py` (11 tests) pins all of it, including the ambiguous-name
case that reproduced V-22 a second time. Acceptance 4b is green under the stricter rule:
78 checks — 57 live, 13 declared interfaces, 8 framework hooks, 0 unaccounted.

*(This is F22's measurement. Rung F23 tightened two of the labels: the dynamic probe now reads
`getattr-undeclared` and **fails** the sweep until its dispatcher is declared, and the current
counts are 86 checks / 65 live / 12 sole-implementation variable calls.)*

Two notes for the next reader. Their `case_I` decides its three booleans by looking for the
probe **names** in the output, so all three readings still fire whichever way the tool judges
them — the verdict labels are the answer, not the booleans. And their `summarize.py` reads
whatever `*.result.json` is on disk, so a case that crashes on a re-run is summarised from the
**previous** run's file; that is how `case_I` first appeared as VULNERABLE here after the fix.

**Closed later in this rung — the protocol-invariant findings.**

| Finding | Fix | Their case now |
|---|---|---|
| V-01 session-id echo | client compares the echo with what it sent | A1 REJECTED |
| V-02 `supported_versions` (wrong value *and* absent) | client requires exactly `0x0304` | A2, A8 REJECTED |
| V-03 `legacy_version` | client requires `0x0303`; decode checks it on ClientHello | A7 REJECTED |
| V-04 `signature_algorithms` | server requires the schemes it will sign with | A3 REJECTED |
| V-05 `key_share` ⊄ `supported_groups` | both roles check the group against the offer | A4 REJECTED |
| V-06 compression ≠ `[null]` | both roles require it | A5 REJECTED |
| V-07 suite not offered | server requires its choice in `cipher_suites` | A6 REJECTED |
| V-08 client did not offer TLS 1.3 | server requires `0x0304` in the offer | F6 REJECTED |
| V-09 duplicate extension | `_decode_extensions` refuses a repeated type | F7 REJECTED |
| V-10 codepoint vs parameters | `cipher_suite_id` is an explicit closed table; an unlisted pair raises | J1/J3 HARNESS-BROKEN* |
| V-17 AEAD usage limit | sealing/opening past `2**24.5` records raises a named `record` error | D4 VULNERABLE* |
| V-18 doc/implementation mismatch | `PROTOCOL.md` §8 no longer describes a record header the code lacks | D5 (documentation) |
| V-19 per-frame budget | one deadline per connection, both roles | J5 INFO-DEVIATION* |

\* **Their case cannot express the fix, and that is worth recording rather than working
around.** J1/J3 construct `HybridTLSConfig(aead=…, hash_name=…)` for four combinations and
expect `cipher_suite_id` to agree with the parameters; two of those now raise `ValueError` at
construction — the intended behaviour — and their runner reports the escaping exception as
`HARNESS-BROKEN`. D4 sets the sequence to `2**64 - 1` and treats *any* exception on the next
`seal` as a defect, because it models the limit as the counter's end rather than as RFC 8446
§5.5's `2**24.5`; the record is now refused far earlier than their case can distinguish. J5
calls `_frame_deadline` twice itself, never inspects the call sites, and records
`INFO-DEVIATION` unconditionally. In all three the implementation now does the stricter and
standard-conforming thing; each is pinned by a test in `tests/test_protocol_checks.py`
(25 tests) rather than by their verdict.

**Closed at the end of this rung — the exception boundary.** Seven case-B probes and D7 are
now named rejections rather than escapes: a 31-byte X25519 share (B2, B3), a truncated KEM
ciphertext (B4), a leaf certificate with no `subjectAltName` (B9), a truncated
CertificateVerify or an over-long handshake frame (B11, B12 — already named), and the
low-order point `cryptography` refuses (D7). Each site now raises a `HandshakeError` carrying
the step, and `tls/errors.py` gained `@named_errors`, the backstop applied to the four
methods that take peer input off the wire, so a *future* escape lands as
`unhandled <Type>: …` instead of crashing a caller that catches what the docs promise.

Two of the fixes were more than wrapping. `_verify_signature` hardcoded `ec.ECDSA` and would
have raised `TypeError` for any other issuer; it now dispatches on the issuer's key type and
**verifies EdDSA issuers** rather than refusing them. And `verify_chain` treated an absent
optional extension as a lookup error: an end-entity certificate without `basicConstraints`
(RFC 5280 §4.2.1.9) or without `EKU` (§4.2.1.12) is *legal* and is now accepted, while a leaf
with no SAN is refused by name because no DNS name can match.

That last distinction is why three of their cases stay VULNERABLE in their harness while the
behaviour is correct: B7, B8 and B10 all report "malformed input fully accepted", and
accepting a legal certificate that omits an optional extension — or one issued by an Ed25519
CA — is what the standard requires. My own tests assert the standard's behaviour
(`tests/test_protocol_checks.py`, 31 tests).

**Still open: their U-03.** `WotsPlus._step_key_prefixes()` derives the chain-step keys from a
fixed public constant, so every leaf shares one set of step keys, where RFC 8391 binds them to
the leaf address through `PRF(SEED, ADRS)`. Their report calls it a design deviation whose
exploitability they could not establish, and this rung did not establish it either. It is
**not** fixed here, deliberately: changing the step-key derivation changes every WOTS+
public key and signature, so it belongs with a security analysis of what the shared randomizer
costs (the WOTS+ proof wants the randomizer unpredictable before the public key is committed,
which a constant in the source is not) rather than in a boundary-hardening pass. It is now the
top item in `docs/AUDIT_V4_RESPONSE.md`'s open list.



Their boundary is respected in this record too: they did not build the rustls prototype
(U-01), could not exercise the hash-pinned install (U-11), and read the symbolic models without
re-running them (U-05).

### Rung F21: the defect class, as an assertion

Three reviews found the same shape of defect three times, in three places: a check that
exists, is correct, and is not on the path a handshake takes (`verify_hybrid_certificate_verify`
— **nothing called it**); a derivation right in isolation and wrong in context (the exporter
context, then its input transcript); a constraint enforced for one object and not its
structural neighbour (the issuer's key usage but not the leaf's, the leaf's EKU but not the
CA's). None was visible to a 233-test suite, because every one of those tests compares this
implementation against itself.

`tools/audit_live_checks.py` is the first of three sweeps that turn the reading habits behind
those findings into inventories. It collects every check-like definition under `tls/` — by
name pattern or by having a body that raises — and asks whether anything on the live path
references it, iterating to a fixed point because the interesting case is one level deeper
than "does anything mention this": `IssuedCertificate.verify` looked live only because the
unreachable `require_valid` called it, two functions telling each other they were on duty.

**What it found on its first run**, which is the evidence that the class was still here:
`IssuedCertificate.require_valid`, a validating method that **nothing in the repository
called**, not even a test; and `IssuedCertificate.verify`, called only from one test. Both
deleted — the client verifies the CA signature and the scheme itself, so they were a second,
unexercised copy of a live check, and the test now calls the authority directly. Two
`__post_init__` methods were false positives (called by `@dataclass`) and are exempted in the
tool with the mechanism named, and printed in every report.

It is now check **4b** in `tools/verify_all.ps1`, so the class cannot reappear without failing
the acceptance pass. Sweeps B (every derived value's inputs named against the standard) and C
(every constraint's scope) are specified in `docs/AUDIT_SWEEPS.md` and **not written**; that
document says why they matter — the evidence column for a value whose only support is "both
halves agree" is the row that matters, and it is empty.

**What this rung does not claim.** The sweep cannot tell whether a check that *is* called
checks the right thing, and textual reachability misses dynamically-built names (deliberately:
it over-reports dead code rather than hiding it). It closes one class, not the gap.

### Rung F20: what the v3 audit found

A third reviewer audited the package that answered the static review, reading source only.
Ten findings; `docs/AUDIT_V3_RESPONSE.md` is the record. Three of them matter more than
their severity ratings suggest.

**The application and exporter secrets were derived over the wrong transcript.** RFC 8446
§7.1 takes `c ap traffic`, `s ap traffic` and `exp master` over ClientHello…**server**
Finished, and only `res master` over …client Finished. Both roles here derived all four
after adding the client's Finished. The auditor rated it low-to-medium; it is the worst
finding in the report, because against a conformant peer the application keys would simply
be different secrets and the first record would fail to decrypt. Nothing in this repository
could see it: every test compares the two halves against each other, and both halves shared
the mistake. It is the exporter-context bug of the previous round one level up — the
*formula* was fixed then and vector-checked, while its *input* stayed wrong. Both stages are
now derived separately and pinned against a transcript the test builds itself.

**The rustls prototype verified nothing.** `verify_server_cert` and `verify_tls13_signature`
both returned success with every argument unused, so every byte-count row it printed said
nothing about authentication — and the configuration was copyable into a real client. It now
generates a throwaway CA and a leaf under it, serves both, and verifies through rustls's own
webpki path with no `dangerous()` escape hatch. The run carries a second handshake whose
client trusts a *different* CA and is required to fail:

```
negative control 1: an untrusted CA is rejected -> invalid peer certificate: BadSignature
```

**The XMSS leaf race is real, and its reproduction needed a knob.** Four barrier-started
threads signing different messages against the unfixed v3 code collided in **0 of 6** runs
at CPython's default GIL switch interval, and in **6 of 6** runs with
`sys.setswitchinterval(1e-6)` — all four threads handed leaf 0. So the window is masked by
the interpreter's scheduling rather than closed by anything the code does. The index is now
reserved under a lock before any hashing; the same amplified run against the fix gives
`[0, 1, 2, 3]` every time.

**The rest, briefly.** A leaf whose `keyUsage` forbids digital signatures was accepted
(the issuer was checked, the leaf was not); an intermediate CA's EKU did not bind the chain;
the strict scheme-identifier check existed in a function **nothing called**, so it is deleted
rather than left beside the live check; the frame reader had a size cap but no deadline; the
padded control group accepted the all-zero X25519 shared secret; dependencies were unpinned —
while fixing that, it turned out `cryptography` is imported from site-packages rather than
from the project's `.deps`, so the package's "self-contained" claim was false of the one
dependency everything needs; and the directory patch now requires Windows and honours an
explicit switch.

**A pattern across three reviews, which is the reason this rung ends pessimistically.** Every
round found the same shape: a check that exists but is not on the live path, a derivation
that is correct in isolation and wrong in context, a constraint enforced for one object and
not its neighbour. All of them were invisible to a suite that compares this implementation
against itself — 233 tests, and not one of them could see the transcript prefix. The
conclusion is not "more self-checks"; it is that this code needs a reader who did not write
it, and each round so far has been that reader finding something the last round's fixes
missed.

### Rung F19: what the static security review found

A second reviewer worked from the source only — no execution, no environment — and
returned nine repository-level findings: one critical, two high, three medium, one that
belongs to a different codebase, and one this pass found while fixing the rest. They
stated explicitly that nothing was reproduced dynamically and that the findings are not
exploits. `docs/STATIC_REVIEW_FIXES.md` is the full record; this is the short version.

**The critical one was a real bypass, and it is now reproduced executably.** `verify_chain`
compared the chain's top certificate against the trusted root by `subject` and
`serial_number`, and skipped the signature check when they matched. Both fields are public
and attacker-chosen. The regression test builds a forged root carrying the trusted root's
name and serial with the attacker's own key, asserts that it really does match on those two
fields, and shows the chain is rejected anyway — so the rejection can only come from the
DER comparison that replaced the field comparison.

**The two high findings were both "the check exists on one path only".** The modelled
certificate profile, which is the *default*, verified the CA signature and the scheme ID
but never compared the identity against `trusted_name`; and `key_fingerprint` returned the
first 12 bytes of the 16-byte traffic key while its docstring promised it would not print
the key. Both fixed, both with tests that fail against the old behaviour. On the
reviewer's follow-up about already-saved demo logs: every `*.md`, `*.txt`, `*.json` and
`*.log` in the repository was searched for stored fingerprint output and none contains a
value, so there is no log to scrub — recorded as a search result, not a guarantee about
copies outside the repository.

**The exporter finding is the one that justifies the whole review.** `state.py` mixed the
*current transcript hash* where RFC 8446 §7.5 puts the empty hash, and the *raw context*
where the section puts its hash. Both endpoints made the same mistake, and the handshake's
own exporter check compares client against server — so the peers agreed with each other
while disagreeing with the standard, and every test passed. The reviewer asked for standard
test vectors; that is now done properly: `tests/test_rfc8448_vectors.py` checks seven
published RFC 8448 values — `HKDF-Extract`, both `derived` expansions, `c/s hs traffic`,
`c ap traffic`, traffic keys and IVs, the Finished key, the **exporter master secret**, and
the resumption master secret — and all seven reproduce byte for byte. RFC 8448 publishes no
*exported keying material*, so the final Expand step still has no vector; it is covered by
an independent reimplementation of the expression plus those primitives. That gap is stated
in three places rather than left for a reader to discover.

**Three chain constraints were fixed, one was not.** `keyCertSign`, `pathLenConstraint`
(counting CA certificates below the issuer, not the leaf) and unknown-critical-extension
rejection are in. `nameConstraints` is not, and its practical behaviour is fail-closed
rather than permissive: being outside the understood set, a critical one rejects the chain.
Rejection is not enforcement and the difference is recorded as an open gap. The reviewer's
preferred answer — hand the path to a mature validator — was not taken, and that is listed
as a gap too.

**One finding was not in this repository.** `stack.c:15`'s `strcpy` overflow, in a
`_lab1_setup` teaching tree: there is no C source here at all.

**One defect this pass introduced and caught.** The first attempt to bound the TCP frame
length used a text substitution that silently did not match — the file has CRLF endings and
the search string had LF. The code was unchanged; the suite stayed green, because nothing
covered the bound; and the new regression test then hung for ten minutes reading 1 MiB + 1
bytes that never arrived. That hang is what exposed the non-applied edit. Six of the seven
fixes were written test-first; this one was not, and it is the one that went wrong.

**Two findings left open, deliberately:** the TCP reader has a size cap but no total read
deadline, which was the second half of the reviewer's advice — a wall-clock deadline over
the shaped-link runs is a flakiness source in the measurements and that trade has not been
analysed; and none of these fixes has been independently reviewed, being one party's
response to another party's findings verified by the first party's own tests.

### Rung F18: what the external review found

The review came back with nine repository-level findings, four of which were code defects,
two of which were **claims that were simply false**, and three of which are open. It
declined to sign off. This is what changed.

**The critical finding: the `min` bound was wrong.** The document claimed
`Adv_auth ≤ min(Adv_EUF-CMA(T), Adv_EUF-CMA(PQ))` for every adversary, including one that
may corrupt either signing key. The reviewer produced a counterexample: with the classical
scheme fully broken and the PQ scheme hard, an adversary that corrupts `sk_PQ`, signs the
post-quantum half honestly, and forges only the classical half wins with advantage ≈ 1 while
the bound says `min(1, ε) = ε`. The two reductions hold on *different branches* — a
reduction embedding `PK_T` cannot answer a `Corrupt` query revealing `sk_T`. §1 now states
the bound as a branch table, and the counterexample is recorded where the claim used to be.

**The second false claim: C1's evidence did not support C1.** C1 described compromise of the
*key exchange* while citing models that leak *signing* keys. **No model in this repository
leaks a KEX component at all.** C1 now says what the models actually test, and the KEX claim
is listed as an unverified gap.

**The third: C6's latency number is not reproducible.** The reviewer measured `+12.92 ms`
median over seven pairs with a range crossing zero, and only 14 of 20 instrumented pairs
positive, against this work's `+8.41 ms`, "7 of 7 positive". Their component measurements do
reproduce the decomposition (~5.7 ms server compute, ~0.7 ms client, ~3.1 ms serialization),
so C6 now claims the decomposition and explicitly not the total.

**Four code defects, all fixed and verified:**

1. `tls/transport/tcp.py` computed `predicted_authenticated_ms` from byte counters read at
   the *end* of the run, so the reported harness overhead subtracted a prediction for the
   wrong interval. The counters are now snapshotted at authentication.
2. `bench/measure_shaped.py` called itself interleaved but ran a fixed hybrid-then-classical
   order every round. Now AB/BA.
3. `high_resolution_sleep` was imported by `tcp.py` and **never called** — the Windows timer
   fix was not active in the shipped benchmark. Now applied.
4. `rust-prototype` inferred negotiation success from an exact byte threshold, and the
   reviewer measured it reporting "not negotiated" in 2 of 10 successful runs. It now reads
   the negotiated group from rustls. **Verified: 8 consecutive runs, 0 failures, deltas
   2269–2273 — four of which the old threshold would have rejected.**

**Three findings left open, deliberately:**

* The DFGS model is still not instantiated, and the reviewer established something sharper
  than this document knew: the `Corrupt(U)` query in the KEMTLS paper is *party-level*, not
  the "corrupt one component of a composite credential" interface the new branch table
  assumes. That interface does not exist yet and has to be defined before the table can be
  proved.
* ECDSA malleability means the authentication hop needs transcript-level agreement, SUF-CMA,
  or the Finished binding. Named in §3 H2; not closed.
* `tools/install_falcon_provider.ps1` and `tools/install_verifpal.ps1` fail in the current
  PowerShell because a here-string passed to native `python -c` loses the Python string
  quotes — the same class of quoting failure this project hit with `check_x509.py`, whose
  fix was to move the Python into a file. Not yet applied to those two scripts; manual
  installation works, and `PACKAGE_MANIFEST.md` documents the manual path.

**The Tamarin skeleton was invalid as a model** — the reviewer's third finding: no signature
verification conditions, the two single-key lemmas written backwards, mismatched `Flight`
and `Accept` terms, and a secrecy lemma with no adversary-knowledge conclusion. The two
inverted conditions are corrected and the file now opens with the defect list and points at
the reviewer's ProVerif models as the artefact to start from instead. It remains unparsed,
which is now stated as its primary property rather than a footnote.

Deferred-rung reasons: **F7** requires choosing a specific
`pq_key_share`/`pq_ciphertext` draft and writing an OpenSSL provider — a different
project from implementing the scheme.

## Run record

| # | Command | Exit | Artifact | Fix attempts |
|---|---------|------|----------|--------------|
| 1 | `python -m pip install --target .deps pqcrypto` | 1 | — | 3 |
| 2 | `powershell -File tools\bootstrap_env.ps1` (as first written, venv-based) | 1 | — | 1 |
| 3 | `python demo\run_handshake.py` | 1 | — | 3 |
| 4 | `python demo\run_handshake.py` | 0 | byte table + key schedule | 0 |
| 5 | `python demo\run_handshake.py --pq xmss --xmss-height 10` | 0 | 7577-byte handshake | 0 |
| 6 | `--tamper pq-signature` / `classic-signature` / `certificate` / `kem-ciphertext` | 0 | four distinct rejecting steps | 2 |
| 7 | `python bench\measure_primitives.py --iterations 30 --keygen-iterations 5 --xmss-height 8` | 0 | `.bench-out/primitives.{json,md}` | 1 |
| 8 | `python bench\measure_handshake.py --repeats 10 --xmss-height 10` | 0 | `.bench-out/handshake.{json,md}`, 15/15 profiles ok | 0 |
| 9 | `python tests\test_wots_xmss.py` | 0 | 24/24 XMSS tests | 0 |
| 10 | `python -m pytest tests -q` | 1 | 2 failed, 155 passed | 1 |
| 11 | `python -m pytest tests -q` | 0 | **157 passed** in 4.65 s | 0 |
| 12 | `python demo\run_handshake.py` over loopback TCP (ad-hoc driver) | 0 | 1 wait to authenticated, 2 waits total | 0 |
| 13 | `python bench\measure_tcp.py --repeats 10 --xmss-height 8` | 0 | `.bench-out/tcp.{json,md}`, 3/3 profiles 1-RTT | 0 |
| 14 | `powershell -File tools\verify_all.ps1 -Repeats 8 -XmssHeight 8 -Iterations 20 -TcpRepeats 5` | 0 | **23/23 acceptance checks pass** | 0 |
| 15 | `python -m pytest tests -q` (after fixing the reported decoder defect) | 0 | **157 passed** in 4.80 s | 1 |
| 16 | `.tools\verifpal\verifpal.exe verify verification\verifpal\hybrid_auth*.vp --sessions 1 --result-code` | 0 | baseline and both single-half compromises `c0a0a0f0a1`; `both_leaked` `c1a1a1f0a1`; `classical_only` `c1a1f0a1` | 6 |
| 17 | `python -m pytest tests -q` (after the classical-only profile landed) | 1 | 3 failed, 154 passed | 2 |
| 18 | `python -m pytest tests -q` | 0 | **157 passed** in 4.33 s | 0 |
| 19 | `python bench\measure_handshake.py --repeats 5 --kems ml-kem-512 ml-kem-768 ml-kem-1024 --signers falcon-512 falcon-1024 ml-dsa-44 xmss` | 0 | measured baseline 638 B; measured PQ deltas 3144–6877 B; size ratio 5.9×–11.8× | 0 |
| 20 | `powershell -File tools\verify_all.ps1` | 0 | **29/29 acceptance checks pass** | 0 |
| 21 | `python tools\check_x509.py` | 0 | real chain: baseline 1404 B, hybrid 5272 B, ratio 3.75× | 1 |
| 22 | `python bench\measure_handshake.py --x509 --repeats 5` | 0 | ratios 3.26×–5.90× across backends, plus a baseline row | 0 |
| 23 | `python -m pytest tests -q` (with `tests/test_x509.py`) | 0 | **173 passed** in 4.40 s | 1 |
| 24 | `powershell -File tools\verify_all.ps1` | 0 | **30/30 acceptance checks pass** | 0 |
| 25 | `python bench\measure_shaped.py --repeats 7` | 0 | wan-slow: +8.41 ms paired median [+6.93, +28.48]; wan-fast and lan below the noise floor | 4 |
| 26 | `python -m pytest tests -q` (with `tests/test_shaper.py`) | 0 | **184 passed** in 7.84 s | 0 |
| 27 | `powershell -File tools\build_rust_prototype.ps1` | 1 | cargo could not reach crates.io: schannel `SEC_E_NO_CREDENTIALS` | 1 |
| 28 | same, with the wider sandbox mode | 0 | crates fetched and compiled in 16.7 s; `toolchain ok` | 0 |
| 29 | `cargo run --release` (prototype) | 1 | `PeerMisbehaved(RefusedToFollowHelloRetryRequest)` with a share padded at X25519's own code point | 1 |
| 30 | `cargo run --release` (private code point, group appended) | 2 | handshake completes, ML-KEM round trip OK, **premise falsified** (958 vs 959 bytes) | 0 |
| 31 | `cargo run --release --offline` (KEM-shaped `start_and_complete`) | 0 | **hybrid group negotiated and completed**, +2272 B over X25519; padded control +2369 | 2 |
| 32 | `python -m pytest tests -q` + Verifpal + prototype, all re-run | 0 | 184 passed, 6/6 model verdicts, hybrid negotiated | 0 |
| 33 | premise check for `docs/REDUCTION.md` §5 | 0 | every cited test exists and passes; `encode(0102,03)=00020102000103 != encode(01,0203)=00010100020203` | 0 |
| 34 | suite run from a clean copy of the staged package | 1 | **25 failed** — Falcon is the default signer and its provider is excluded | 0 |
| 35 | same, after `conftest` skips Falcon-named tests and falls back | 1 | 5 failed — five tests hard-coded Falcon incidentally | 1 |
| 36 | same, after those five were rewritten to use an available signer | 0 | **184 passed, 1 skipped, 0 failed** without the provider; **186 passed** with it | 0 |
| 37 | `tools\make_review_package.ps1 -Force -Zip`, then extract and re-run | 0 | 2.09 MB zip; extracted copy runs the suite green | 2 |

### Rung F17: packaging, and the two traps it found

**Shipping without verifying the package would have hidden the first one.** Running the
suite from a clean copy of the staged package produced **25 failures**, because Falcon is the
default post-quantum signer and its provider is deliberately excluded from the package. A
reviewer's first command would have gone red for a reason that has nothing to do with the
work. The fix is in `tests/conftest.py`: the profile catalogue is built from what is
installed, every test whose node id names Falcon is skipped with the install command in the
reason, and the default signer falls back to ML-DSA. Five more tests then failed because they
had hard-coded Falcon *incidentally* — they needed *a* signer, not that one — and were
rewritten to use whatever is available. Both counts are now documented in `START_HERE.md` and
verified: 186 passed with the provider, 184 passed plus 1 skipped without it, **zero failures
either way**.

**The second trap was in the builder itself.** The first version of
`make_review_package.ps1 -Force` deleted the staging directory, which destroyed the three
hand-written reviewer documents it had been given. A builder that eats its own inputs on
re-run is a trap for whoever runs it next, so the documents now live in `packaging/` inside
the project as the source of truth and the script copies them in. Re-running is idempotent.

The package is verified the only way that counts: `Expand-Archive` into an empty directory,
then run the suite from the extracted copy. That is what shipped.

### Rung F15: the reduction skeleton, and what it is not

`docs/REDUCTION.md` states the two claims (server authentication, key secrecy), the nine
assumptions, and the game hops for each. Two things about it are worth naming.

**The bound is a minimum, not a sum.** An accepted forgery must contain *both* signatures,
so a reduction can embed its challenge key in either slot and succeed whenever the adversary
does: `Adv ≤ min(Adv_EUF-CMA(T), Adv_EUF-CMA(PQ))`. Writing it as a sum would understate the
construction; writing it as a minimum is what "hybrid" means formally, and it is the one
place where this document says something a reviewer would want to check first.

**§6 is the point of the document.** It lists nine things that are *not* proved, including
that the model is never instantiated, that nothing is machine-checked, that the
prefix-freeness step in the transcript hop is informal, that `ε_sim` is a placeholder, and
that for the XMSS backend the EUF-CMA assumption is conditional on an **operational**
property — index discipline — that no cryptographic argument can supply. A reader who cites
this must cite it as "a reduction skeleton with the gaps in §6", not as a proof.

Two design consequences fell out of writing it down. The length prefixes in
`Z_hybrid` are load-bearing in §4 H1 rather than cosmetic, and the corresponding test is
the one premise of that hop that executes; and A8's operational character is the reason
`tests/test_wots_xmss.py` tests index monotonicity and exhaustion at all.

Nothing in this rung is machine-checked: this machine cannot run Tamarin (no GHC, no
Windows binary) or ProVerif (no Windows binary, Docker not running, WSL inaccessible), and
the Verifpal models that do run are bounded symbolic checks that say nothing about the
bounds in §1.

### Rung F13: how the real-stack integration was finished

The previous round ended with a prototype that looked like it worked and had not: the
custom group carried 1184 extra bytes of share and the handshake grew by −1 byte, so
rustls's own X25519 had been negotiated. That run is recorded above rather than deleted,
because the diagnosis is the whole value of this rung.

The answer was in rustls's own post-quantum groups, `src/crypto/aws_lc_rs/pq/mlkem.rs` and
`hybrid.rs`:

* **A KEM group must implement `start_and_complete`.** The server's key share is a
  **ciphertext** and `start()` cannot produce one, because it takes no peer key. The
  default `start_and_complete` calls `start()` then `complete()`, which for a KEM puts a
  key where a ciphertext belongs; the client then decapsulates a key and everything
  silently fails to agree. Implementing the method so the server encapsulates and returns
  the ciphertext as `CompletedKeyExchange::pub_key` is the fix.
* **A hybrid group is a composition.** Shares concatenate post-quantum first and classical
  second, secrets in the same order. rustls's `Hybrid` is `pub(crate)`, so the prototype
  re-implements the composition in ~80 lines.

Result: rustls reports the negotiated group as `HybridX25519MlKem768 { classical: X25519,
post_quantum: MlKem768Group }` and the handshake **completes**, which means both endpoints
derived the same 64-byte hybrid secret — the Finished MAC is the evidence, not the byte
count. Hybrid +2272 B, ML-KEM alone +2206 B, and the padded-size control +2369 B, so the
hybrid's size is attributable to its shares.

**The cross-check that mattered most.** The harness independently predicts ΔCH = 1194 and
ΔSH = 1094 for ML-KEM-768; rustls measures +1184 and +1088. Ten bytes apart, and the ten
bytes are the extension header and length field the harness adds and a key-share slot does
not. Two independent implementations agreeing to within ten bytes on the same construction
is the anchor the harness's byte table needed.

Still not done, and now the only item left in this tier: **hybrid signatures**. rustls's
`SignatureScheme` is a closed enum, so a composite CertificateVerify needs a patched rustls
or the delegated-credentials route Celi et al. used. The prototype demonstrates the
key-exchange half only. *(Its certificate verifier used to accept anything on purpose —
rung F20 records the audit that found that, and the real verification that replaced it.)*

### Rung F13: the real stack, and what the prototype falsified about itself

Tier 3 is a **bounded advance**, and the bound is worth stating precisely because the
prototype looked like it worked.

Established: a `rustls::crypto::SupportedKxGroup` implemented outside rustls compiles,
links and runs; a real TLS 1.3 handshake completes in this harness (`TLS13_AES_256_GCM_SHA384`,
**958 bytes total** with a 354-byte self-signed certificate); `ml-kem`'s FIPS 203 round trip
works. That 958-byte figure is independently useful: it shows the Python harness's 4484-byte
modelled handshake and 5272-byte X.509 handshake are dominated by the harness's certificate
model, not by the protocol.

Not established: **the custom group was never negotiated.** The padded variant carries 1184
extra bytes of share, so a successful run would have grown the total by at least ~1184; it
measured **−1**. The prototype now detects this itself and exits non-zero with
`PREMISE FALSIFIED` rather than printing numbers from the wrong group — a real-stack number
from the wrong group would be worse than no number at all.

Two mechanisms are consistent with the evidence and both need rustls-internals reading:
a KEM's reply share is a **ciphertext**, which `ActiveKeyExchange::start()` cannot produce
(rustls 0.23.45 has `complete_hybrid_component` for exactly this), and group selection with
an unknown code point did not fall through the way the second attempt assumed. The route is
written out in `rust-prototype/README.md`.

Two environment facts were needed and are now scripted: the MSVC linker is installed but not
on PATH (the build imports `vcvars64.bat`), and **cargo cannot reach crates.io under the
restricted token** — libcurl uses schannel, which fails with `SEC_E_NO_CREDENTIALS` when the
process cannot obtain a credential handle. That is the same class of environment defect as
the `os.mkdir` DACL problem on the Python side, and it is why the build script documents the
wider mode instead of treating the failure as a misconfiguration. With the crates cached,
`-Offline` builds with no network at all.

The real-stack prototype is deliberately **not** part of `tools\verify_all.ps1`: it needs the
wider sandbox mode to fetch, so it cannot be a gate that runs unattended.

### Rung F12: shaping, and the three measurement bugs it exposed

Shaping was not the hard part; making the shaped number mean anything was. Each of the
first three attempts produced a plausible-looking table that was wrong.

1. **The delay was applied after the bytes were sent.** `_send_frame` wrote to the socket
   and *then* slept, so the peer could read the record while the sender was still waiting:
   the two threads slept in parallel and the measured time came out **below** the link's
   own arithmetic (99.9 ms measured against 196.8 ms predicted). Fixed by queueing a
   flight, sleeping, and only then writing (`_queue_frame`/`_flush`). The ordering is the
   whole mechanism, and it is named in the helper's docstring so it does not get "tidied"
   back.
2. **ServerHello and the server flight were two flushes.** Charging one propagation delay
   each made the client wait two one-way delays where TLS 1.3 spends one, and the measured
   time came out **above** prediction by exactly one leg. Fixed by sending ServerHello
   through Finished as one flight, which is what the protocol does.
3. **The two variants were measured sequentially.** Any drift in machine state between
   the hybrid block and the classical block was reported as the post-quantum cost, which
   is why an early run showed −6.44 ms for an addition that can only cost time. Fixed by
   interleaving the variants within each round and reporting the **paired** difference.

A fourth fix is platform-level and worth recording on its own: Windows schedules sleeps
on a ~15.6 ms tick, so a shaped run that sleeps for 97.8 ms overshoots by most of a tick,
several times per handshake. That noise was larger than the effect being measured. A
`timeBeginPeriod(1)` window around the shaped run (`high_resolution_sleep`) took the
harness overhead from ~24 ms to ~8 ms and is the reason the wan-slow difference is now
positive in every round rather than scattered around zero.

The honest state of the result: at 195.6 ms RTT and 10 Mbps the post-quantum material
costs **+8.41 ms** (paired median, 7 rounds, always positive), of which 3.09 ms is pure
serialization of the extra bytes; the rest is server compute the client waits through.
At 31.1 ms RTT and 1000 Mbps the effect is **below the noise floor**, which is the correct
answer when 3.9 KB serialize in 0.03 ms.

### Rung F11: the X.509 profile

The modelled certificate kept the handshake small and kept the symbolic models exact, but
it also made every absolute byte count unquotable, because the baseline had no chain. The
X.509 profile fixes exactly that:

- **What it cost.** `tls/pki.py` (chain building and real validation), one new message
  shape (`X509Chain`, same type 11), a profile switch, and one refactor in the client:
  the two public keys are now stored as `server_classical_public`/`server_pq_public` by
  whichever certificate shape arrived, so everything downstream of the certificate is
  identical in both profiles.
- **What it changed.** The measured ratio halved: with a real 1404-byte baseline the
  hybrid profile is 3.26×–5.90×, against 5.9×–11.8× with the modelled 638-byte baseline.
  The first number is the one a paper can quote.
- **What was rejected.** Putting the PQ key in the leaf's SubjectPublicKeyInfo (that
  would need a composite key type and a new OID arc), and adding a second PQ certificate
  to the chain (that doubles the chain and misrepresents what a hybrid deployment
  publishes). The leaf extension is what the design note suggests and what needs no
  change to the certificate's subject structure.
- **A test bug worth recording.** The expired-certificate test first tried to sign a
  hand-built stale leaf with the intermediate's *public* key, because the chain builder
  does not expose the intermediate's private key. The right fix was to let the builder
  take an explicit validity window, not to widen the API so a test could reach a signing
  key it has no business holding.

### Rung F10: what the classical-only baseline cost to add

1. **Optional post-quantum fields in four message types.** Making the fields optional
   forced a real wire-format fix, not a workaround: the certified body had to gain a
   length prefix, because the optional key sits *before* the CA signature and a decoder
   cannot otherwise tell an absent key from the start of the signature. `docs/PROTOCOL.md`
   §5 was updated to match.
2. **Three tests asserted the old contract**, that decoding a ClientHello without
   `pq_key_share` must raise. That contract was wrong once a classical-only profile
   exists: the *codec* must accept such a message, and the *profile* must reject it, or a
   classical server could never read a classical ClientHello. The tests were rewritten to
   the new contract rather than deleted, and the handshake-level test that covers the
   rejection still passes.
3. **The rejection mutated server state.** That same test failed on
   `transcript.byte_count` after the strip: `receive_client_hello` was adding the frame to
   the transcript *before* validating it. A rejected message must leave no trace, so the
   validation now happens first. Found by a test that already existed.
4. **The analytic estimate was one byte off** the measured difference (Falcon signatures
   vary in length, so a per-field formula cannot be exact). Rather than tune the formula,
   `measured_pq_deltas()` now runs both profiles and subtracts, and the estimate is
   documented as an estimate. The test asserts the measured per-message values and that
   the estimate is within four bytes of the measurement.

### Verification-model fixes and what they cost (rung F8)

The tool rejects models that would have produced a vacuous or meaningless query, and
each rejection was worth having:

1. **Constants both sides already hold cannot be sent.** The CA already knows the
   server name, so `Server -> CA: [serverName]` was a no-op and Verifpal said so.
2. **A value cannot be both computed and declared public.** `caPk` was defined by the
   CA and declared `knows public` by the client; it has to arrive over a guarded
   message instead, which is also how a trust anchor actually reaches a client.
3. **`CONCAT` takes at most five arguments, `HASH` at most five, `SIGN` two.** The
   flight had to become two records, which is closer to what the implementation
   emits anyway.
4. **A principal can only compute with values it declares, generates, computes, or
   receives.** The client has to `SPLIT` the certificate it receives rather than
   refer to the server's local names — the same mistake as reading a peer's variables
   in real code.
5. **An authentication query cannot be asked about a value nobody computes with.**
   The `classical_only` control initially kept `authentication? Server -> Client:
   sigPQ1` while removing the client's PQ check; Verifpal refused, correctly: there is
   no such authentication to break. The control's query set is now generated from its
   check set.
6. **Two handshakes in one file do not finish**, and neither does Verifpal's own
   bundled `tls13.vp`, at any session count this machine afforded. The model set was
   restructured to a single handshake with the compromise declared *before* it, which
   is both faster and more honest: a leak declared after the handshake cannot affect a
   signature that was already made, so the original ordering would have made every
   query hold vacuously.

### Fixes and what they cost

1. **pip could not write inside the sandbox (3 attempts).** `PermissionError` on a
   file pip had just downloaded. Root cause found by direct probe: CPython's
   `os.mkdir(path, 0o700)` — which `tempfile.mkdtemp` uses — writes a DACL granting
   only the process owner, while the DSH sandbox authorizes through an inherited
   capability SID. Any directory a sandboxed Python creates for itself becomes
   untraversable. `os.makedirs` with the default mode works because it inherits the
   parent ACEs. Fixed with `tools/sandbox_pyfix/sitecustomize.py`. Escalating the
   sandbox would have "fixed" it too and hidden a real property of the environment.
2. **`ensurepip` failed in a venv (1 attempt).** Same root cause, one layer up.
   Abandoned the venv and installed with `pip --target` inside the workspace.
3. **ClientHello key_share decoded the vector length as the group (1 attempt).**
   A ClientHello carries a *vector* of key shares and a ServerHello carries one; the
   decode path read the length prefix. Fixed in `ClientHello.decode`.
4. **AEAD nonce construction (1 attempt).** The 8-byte sequence number was XORed
   against a 12-byte IV without left-padding. Fixed in `RecordLayer._nonce`.
5. **Transcript position of CertificateVerify (1 attempt).** The server built the
   dual signature before EncryptedExtensions and Certificate entered the transcript,
   so both signatures failed to verify. This is the bug the ledger's provenance
   warning points at: the code had silently chosen a transcript position, and the
   failure surfaced only as "both signatures invalid". Fixed by making the flight
   emit messages in order with an explicit `emit()` that filters, hashes, and seals
   in that order.
6. **Tamper harness re-sealed records out of order (2 attempts).** Re-sealing a
   record after the flight advanced the sequence number, so the tamper surfaced as a
   record-authentication failure instead of a signature failure. Fixed by adding the
   `frame_filter` seam to `send_authenticated_flight`, which corrupts a frame before
   it is hashed and sealed.
7. **`ClientHello.decode` ate two `vec16` length prefixes (1 attempt).** Reported by
   the delegated test author, not found by the implementer: `encode` wrote
   `supported_groups` and `signature_algorithms` as `vector<u16>`, but `decode` read
   the extension payloads as bare code points, so `(29,)` came back as `(2, 29)`.
   Latent for the handshake — the server reads only `key_share`, `kem_scheme` and
   `pq_key_share` — but a real codec-fidelity bug, and the same class of mistake as
   fix 3, which is why fixing `key_share` alone was not enough. Fixed by decoding both
   lists through the `vec16` prefix (`_decode_u16_list`); the test that had pinned the
   buggy behaviour was replaced by `test_client_hello_vec16_lists_roundtrip_exactly`,
   which asserts the whole message round-trips. This is the clearest evidence in the
   run for why the ledger's `Source` column matters: the defect was visible only to a
   reader who had not written the encoder.

## Blockers

None outstanding. The one that existed — F5, the pytest suite — was cleared at rung F5 and
has been green on every run since. The suite is `tests/conftest.py` plus `test_wire.py`,
`test_key_schedule.py`, `test_messages.py`, `test_handshake.py`, `test_wots_xmss.py`,
`test_x509.py`, `test_shaper.py`, `test_rfc8448_vectors.py` (7 RFC 8448 vectors),
`test_security_fixes.py` (18 regression tests, one per finding of the static review),
`test_audit_v3_fixes.py` (22), `test_protocol_checks.py` (31), `test_live_checks.py` (11),
`test_u03_wots_context.py` (U-03, the collaborator's) and `test_audit_v6_fixes.py` (14, one per
finding of the fifth review), and `python -m pytest tests -q` exits 0 with **393 passed** — in both the author-side
environment and one that does not load `tools/sandbox_pyfix` (see `validation/README.md`). (This paragraph said `157 passed` until rung
F19, `233` until rung F22 and `320` until rung F24: a count in a "current state" section that nobody had updated
after the suite grew, which is the same failure mode as the false claims the two reviews
found.)

Single success command for the whole build:
`powershell -File tools\verify_all.ps1` — 32 checks covering the backend inventory,
five end-to-end handshakes, the four-case tamper matrix, the pytest suite, both
benchmarks, the real X.509 chain, the loopback round-trip count, six Verifpal verdicts,
and the shaped-link runs.

## Live stubs

None. Every backend in the reported paths is real: ML-KEM/HQC through `pqcrypto` 1.0.0,
Falcon through the PQClean provider, WOTS+/XMSS in this package, ECDHE/ECDSA/AES-GCM
through `cryptography`. `ecdh-kem-placeholder` is not a stub in the "fake result" sense
— it is a complete, working, explicitly non-post-quantum KEM that reports
`post_quantum = False`, and it appears in the benchmark table under its own name
rather than being silently substituted.
