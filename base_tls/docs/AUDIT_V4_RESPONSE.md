# Response to the v4 attack package

`hybrid-tls13-攻击包.zip` is a fourth, independent review — this time an *attack* package:
ten case scripts, 82 cases, a report, a hardening plan and per-case raw evidence. This is the
disposition. It was written while acting on the findings, so the "now" columns are measured
with the package's own scripts against a junctioned copy of this project.

## What they found, and what happened to it

| Their id | Finding | Status |
|---|---|---|
| V-01…V-09 | Neither role validated the TLS 1.3 negotiation fields (session-id echo, `supported_versions` — wrong *and* absent, `legacy_version`, `signature_algorithms`, `key_share` vs `supported_groups`, compression, suite not offered, duplicate extensions) | **fixed**: all ten cases now `REJECTED` with named steps |
| V-10 | `cipher_suite_id` returned `0x1302` for every pair except one, so the suite name disagreed with the key length and hash | **fixed**: an explicit closed table; an unlisted pair raises at construction |
| V-11…V-16 | Six classes of peer-controlled input left the documented error contract as `KeyError`/`ValueError`/`TypeError`/`x509.ExtensionNotFound` | **fixed at seven of the eight sites**: named rejections at each site, plus `@named_errors` as a backstop. The eighth — the `basicConstraints` lookup inside `_enforce_path_length` — was missed, and the fifth review found it by reading this very row against the code (their V6-01). It is fixed now, with a test, in [AUDIT_V6_RESPONSE.md](AUDIT_V6_RESPONSE.md) |
| V-17 | No AEAD usage limit; the counter ran to `2**64` before anything objected | **fixed**: sealing/opening past RFC 8446 §5.5's `2**24.5` records raises a named `record` error |
| V-18 | `PROTOCOL.md` §8 described a record header the code does not produce | **fixed**: the document now says the harness produces no record header, and what the AAD deviation actually is |
| V-19 | The loopback driver rebuilt its read deadline per frame, so a slow peer multiplies the budget | **fixed**: one deadline per connection, both roles |
| V-20…V-22 | Sweep A misjudged a comment as a call, a `getattr` dispatch as dead, and exempted any method named `verify` | **fixed**: AST call sites, `getattr` literals recorded and flagged, exemptions keyed on `Class.method`, and an ambiguous variable-receiver call must be declared or it fails as `UNATTRIBUTED`. Ten tests in `tests/test_live_checks.py` |

Their headline is the one to keep: *the cryptographic core held; what broke was message-field
validation and the exception boundary.* Nothing in this package broke the key schedule, the
AEAD layer, the X.509 validator's chain checks or the PQ signature verification, and their
independent recomputation of the key schedule (§3.1 of their report) is the strongest evidence
this project has that the round-4 transcript-stage fix is right — it is the Sweep B row this
repository had listed as owed.

## Where their verdict and the standard disagree

Three of their cases still report `VULNERABLE`, and one reports `HARNESS-BROKEN`, while the
implementation does what the standard requires. These are recorded rather than worked around;
each is pinned by a test of my own instead.

| Case | Their reading | Why the implementation is right |
|---|---|---|
| B7, B8 | "malformed input fully accepted" for a leaf with no `basicConstraints` / no `EKU` | Both omissions are **legal** (RFC 5280 §4.2.1.9 makes `basicConstraints` optional for an end entity; §4.2.1.12 reads an absent `EKU` as "no restriction"), so completing is correct. Their own titles say so |
| B10 | "malformed input fully accepted" for an Ed25519 issuer | An EdDSA issuer is legitimate PKI. The old code hardcoded `ec.ECDSA` and raised `TypeError`; it now verifies the chain. Refusing a legal chain would be the bug |
| D4 | `VULNERABLE` because a `seal` after `2**64 - 1` raised | Their case models the limit as the counter's end. RFC 8446 §5.5 puts it at `2**24.5` records for AES-GCM, and refusing *earlier*, by name, is the stricter and correct behaviour |
| J1, J3 | `HARNESS-BROKEN` | Their case loops four `(aead, hash)` pairs and expects `cipher_suite_id` to agree with the parameters; two now raise at construction — the behaviour their own hardening note asked for — and the escaping exception is what their runner reports |
| J5, D5 | `INFO-DEVIATION` | `j5` calls `_frame_deadline` twice itself and never inspects the call sites, so its verdict cannot change; `d5` records a documented AAD deviation, which `PROTOCOL.md` §8 now states precisely |

## Follow-up status (U-03 closed; remaining items open)

1. **U-03 — closed in the 2026-09-21 follow-up at implementation level.** The global
   constant is removed; independently sampled public seeds, RFC chain addresses and
   separate key/bitmask derivation are implemented. Public keys carry the authenticated
   seed and scheme identifiers changed. Full proof/standard interoperability is not claimed.
   See [U03_WOTS_STEP_KEYS.md](U03_WOTS_STEP_KEYS.md) for evidence and migration.
2. **No vector covers a whole handshake's derivation chain** (their U-10, this project's gap
   13). Their §3.1 is an independent recomputation, which is better than nothing and not the
   same as published vectors.
3. **XMSS index persistence is still the caller's duty** and the lock is in-process (their
   U-02, gap 14).
4. **The certificate validator is still hand-written** (their U-09, gap 11) — their eleven
   attack cases found no bypass, which is evidence and not proof.
5. **The rustls prototype was not built by them** (their U-01). It was built and run here
   after the round-5 fixes: two negative controls fire, the positive control passes, five
   consecutive runs stable.
6. **They could not exercise the hash-pinned install** (their U-11); it was verified here with
   `pip download --require-hashes`, which downloads and hash-checks all ten packages.
7. **None of this round's fixes has been independently reviewed** — the same statement as
   every round before it.

## Evidence

```
python -m pytest tests -q                        # 320 passed
powershell -File tools/verify_all.ps1            # 32 checks, 32 passed (4b = the sweep)
tools\audit_live_checks.py                       # 86 checks: 65 live, 13 declared interfaces, 8 hooks, 0 unaccounted
```

Their suite, run against this revision: **V-01…V-09 REJECTED**, case-B down to three cases
whose expectation is narrower than RFC 5280, G2 PASS, D7 PASS, D4/J1/J3/J5 as tabulated above.
The baseline before this round was 23 `VULNERABLE`; what remains is either a disagreement about
what the standard requires or an item on the open list above.

The fifth package (round 7) re-checked this table itself and split V-14 into "the direct paths
are handled, `_enforce_path_length` is not" — which is what the row above now says. Its own
findings are disposed of in [AUDIT_V6_RESPONSE.md](AUDIT_V6_RESPONSE.md).
