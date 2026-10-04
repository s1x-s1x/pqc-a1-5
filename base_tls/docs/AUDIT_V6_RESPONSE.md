# Response to the fifth review (`hybrid-tls13-v6-攻击包`)

The fifth package is the second **attack** package: ten case scripts, 104 cases, and a report
that separates what it reproduced from what it merely read. It confirmed the client half of
the negotiation checks, re-checked the previous round's 22 items, and then found ten new
defects. This is the disposition of each, with the test that pins it.

Two properties of this round are worth stating before the table:

* **Every K-finding is now an executable test.** Four earlier rounds produced fixes without
  regression tests, which is how the same shape came back; `tests/test_audit_v6_fixes.py` is
  the fifth round's answer, one test per finding plus three positive controls.
* **No fix in this round has been independently reviewed.** Same statement as every round
  before it. The reviewer's own §7 boundary applies unchanged.

## Disposition

| Their id | Case | Finding | Status | Pinned by |
|---|---|---|---|---|
| V6-01 | K1 | `_enforce_path_length` looked up `basicConstraints` without the default its seven neighbours use, so a **legal** leaf that omits the extension crashed path validation with `ExtensionNotFound` | **fixed**: the lookup now treats an absent extension as `ca=False`, which is the same reading `verify_chain` applies elsewhere | `test_a_leaf_without_basic_constraints_under_a_constrained_intermediate`, `test_the_same_chain_with_the_extension_present_still_verifies` (their K1b control) |
| V6-02 | K2 | The client accepted a ServerHello carrying an extension it never offered | **fixed**: RFC 8446 §4.1.3's rule is enforced against the decoded extension set; a not-offered type aborts with a named `server_hello` error | `test_a_server_hello_with_an_unoffered_extension_is_rejected` |
| V6-03 | K3 | The client accepted an EncryptedExtensions carrying an extension at all | **fixed**: this profile offers no EE extension, so any is a named `server_flight` rejection | `test_an_encrypted_extensions_with_an_unknown_extension_is_rejected` |
| V6-04 | K4 | Two `KeyShareEntry` values in the ServerHello's `key_share`: the client read the first and dropped the rest | **fixed**: the entry list must be consumed exactly (`expect_end`), a `DecodeError` | `test_two_key_shares_in_the_server_hello_are_rejected` |
| V6-05 | K5 | Four garbage bytes after the `pq_ciphertext` vector were dropped silently | **fixed**: same rule — the extension body is consumed exactly | `test_trailing_bytes_in_the_pq_ciphertext_extension_are_rejected` |
| V6-06 | K6 | A non-empty `certificate_request_context` in the server's Certificate was accepted | **fixed** in **both** Certificate bodies (modelled and `X509Chain`), since no CertificateRequest is ever sent | `test_a_non_empty_certificate_request_context_is_rejected`, `test_the_x509_chain_message_applies_the_same_rule` |
| V6-07 | K7b | The server accepted and echoed a 255-byte `legacy_session_id`; §4.1.2 caps the field at 32 | **fixed** on both sides: `ClientHello.decode` and `ServerHello.decode` refuse it structurally, so neither role depends on the echo check | `test_an_oversized_session_id_in_the_client_hello_is_rejected`, `test_an_oversized_session_id_in_the_server_hello_is_rejected` |
| V6-08 | N1 | An exhausted XMSS key escaped `send_authenticated_flight` as a bare `ValueError`, breaking the single error contract | **fixed**: the flight is decorated **and** the signer call is converted at the boundary into a named `server_flight` refusal that carries the cause | `test_an_exhausted_xmss_key_is_a_named_refusal_not_a_bare_value_error` |
| V6-09 | M3 | `keygen_from_seed(seed, public_seed=...)` validated lengths only, so one string could be both seeds — and the public seed is published inside the public key | **fixed**: overlapping seeds are refused outright (equality, and either being a prefix of the other), so the misuse their M1 chain needs cannot be constructed | `test_the_public_seed_may_not_share_material_with_the_secret_seed`, `test_independent_seeds_still_build_a_key_pair` |
| V6-10a | — | The `sole_implementation` rule credits any variable-receiver call whose name has one defining class, so a call line that never executes can lift a dead check to `live` | **documented and reported, not removed** — see `AUDIT_SWEEPS.md` §"V6-10a" and the new `variable-sole` lines in the report | `test_a_sole_implementation_called_on_a_variable_is_live` |
| V6-10b | — | A `getattr(obj, "name", None)` literal that never calls anything counted as a reference and the sweep still passed | **fixed**: an undeclared `getattr`-only reference now **fails** the sweep, and a real dispatcher must be declared in `GETATTR_DISPATCHED` with its mechanism | `test_a_getattr_dispatched_check_is_live_and_flagged` (now asserts exit 1), `test_a_declared_getattr_check_passes` |

Two of their tables needed a note rather than an action: their §3 re-check of the previous 22
items matches this repository's record, and their §5 lists what their environment could not
exercise — unchanged from the round before.

## V6-09 in detail: why the guard is a prefix rule

Their M1 chain is: read the second half of the public key (it is `root || public_seed`), use it
as the secret seed, rebuild the tree, sign. It works because the two arguments derive the *same*
key material, and the only thing the code checked was length.

Refusing equality alone would leave the truncated copy: a 16-byte `public_seed` that is a prefix
of a 32-byte secret seed still publishes half the secret, and `WotsPlus` accepts any non-empty
secret seed. The guard therefore refuses any overlap — `shorter` being a prefix of `longer` —
which covers equality, truncation and the other order. The message names the rule, and
`keygen_from_seed`'s docstring states it where a persistence call site will read it.

The boundary is unchanged: `keygen()` draws two independent `os.urandom(n)` values, so the
handshake path never depended on this, and their observation that the defect is "misuse-driven"
still holds. What changed is that the misuse now fails loudly instead of silently publishing a
long-term secret.

## Their suggested fix that was implemented differently

V6-08 asked for two things: wrap `send_authenticated_flight` in `@named_errors`, and have the
signature backend report exhaustion as a named rejection. The first is done. The second is done
at the boundary instead of in the primitive:

* `tls/pq/wots_xmss.py` keeps raising `ValueError` — that is its documented contract, its
  verifier depends on it (`except ValueError: return False`), and it is not a TLS layer;
* `HybridServer._build_certificate_verify` converts a backend refusal into
  `HandshakeError("server_flight", "the post-quantum signer Xmss refused to sign: …")`, so the
  caller sees the reason rather than the decorator's generic "unhandled ValueError" backstop.

The observable property they asked for — no bare `ValueError` reaches a caller that catches only
`HybridTLSError` — holds, and the test asserts the *reason* survives, not just the type.

## What this round did **not** close

| Item | Why it stays open |
|---|---|
| XMSS index persistence and rollback | unchanged: the lock is in-process, a restored `next_index` can replay a leaf, and nothing detects it (`SECURITY.md` gap 14) |
| The whole-handshake derivation-chain vector | still owed; the fifth review did not supply one either |
| The hand-written certificate validator | unchanged (`SECURITY.md` gap 11) — their eleven X.509 cases are evidence, not proof |
| Independent review of these fixes | not obtained; the same statement as rounds 1–4 |
| Sweep B and Sweep C | still not written (`AUDIT_SWEEPS.md`) |

## U-03: what was adopted, from whom, and what was added

The U-03 correction in this revision is **the collaborator's patch**, adopted whole — the
constant `_TWEAK_SEED` is gone, WOTS+ chain keys and bitmasks are derived per
`PRF(SEED, ADRS)` with the leaf address, chain index, absolute step and key/mask role, and the
public key carries `root || public_seed` (`2n` bytes, scheme `0xFE00 + height`). Adopted files:
`tls/pq/wots_xmss.py`, `tls/pq/signature.py`, `tests/test_wots_xmss.py`,
`tests/test_u03_wots_context.py`, the migration vectors, the eight documents and the
`validation/` records.

What this repository added on top, and what it verified itself:

* the V6-09 seed-overlap guard above (their patch has the invariant in prose only);
* an independent read of the diff, line by line, against RFC 8391 §2.5/§3.1.2/§5.1 — the
  address layout, the two roles and the `toByte(3,·)`/`toByte(0,·)` domains match;
* the acceptance run below on the merged tree, including their 31 U-03 regressions and the
  legacy-vector fail-closed test.

Their own boundary is preserved in the documents: this is **not** a claim that the construction
now conforms to RFC 8391 as a whole — the unkeyed Merkle hashes, the missing OID, the WOTS+
public key on the wire and the byte-level encodings remain this prototype's own.

## Evidence

```
python -m pytest tests -q                       # 320 passed
python -m pytest tests/test_audit_v6_fixes.py -q  # 14 passed (one per finding, plus controls)
python tools/audit_live_checks.py               # 86 checks: 65 live, 13 interfaces, 8 hooks, 0 unaccounted
powershell -File tools/verify_all.ps1           # 32 checks, 32 passed (4b = the sweep)
```

Their probe expectations, re-run here: K1 verifies (and K1b still verifies), K2/K3 abort with
named steps, K4/K5 abort at decode, K6 aborts in both certificate bodies, K7b is refused at
both roles, N1 raises `HandshakeError` with step `server_flight`, M1 cannot build its key, and
the two sweep probes now produce `getattr-undeclared` (exit 1) and a `variable-sole` line
instead of a silent pass.

## Where their reading and this implementation still differ

* **V6-10a is kept, not removed.** Their suggested alternatives were to limit the rule's scope
  or to report the bucket as `UNVERIFIED`. Reporting is what changed: the count and every line
  are printed, and the report shows a *live* call site for each entry rather than whichever
  reference came first. Type inference would be needed to eliminate the residual risk, and a
  wrong inference here produces false `DEAD` verdicts on the real interfaces — the failure this
  sweep exists to prevent.
* **K5's shape matters.** Appending bytes *inside* the ciphertext vector is caught by the KEM's
  own length check (their B4/G2); the case that needed the `expect_end` rule is garbage *after*
  the vector. The test uses that second shape on purpose.
