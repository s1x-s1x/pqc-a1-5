# Response to the v3 security audit

A third reviewer audited `hybrid-tls13-review-package-v3.zip` — the revision that answered
the *static security review* — and returned ten findings, F1–F10. This document records,
per finding: what was claimed, what the code actually did when this pass checked it, what
changed, and which command or test now pins it.

Two framing points, as with the previous two rounds.

**The auditor's boundary is honoured.** Their §6 states that every conclusion came from
reading source, that no dynamic test ran, and that no attack is claimed; F1, F7 and F8
each carry an explicit statement of the deployment shape that limits them. Nothing below
claims an exploit the auditor did not claim. Where this pass *did* run something — F5's
leaf reuse, F6's transcript stages, F1's negative control — it is named as such.

**Nobody independent has checked these fixes.** This pass was written by the same party
that wrote the code. The fixes are new, unreviewed code, verified by that party's own
tests. `docs/SECURITY.md` records that same-family review cannot substitute for
independent review, and that applies here.

## Summary

| # | Severity (auditor) | Finding | Verified here | Status |
|---|---|---|---|---|
| F1 | high | The rustls prototype skipped certificate *and* handshake-signature verification | confirmed by reading; **reproduced as a negative control** | **fixed** |
| F2 | medium | The X.509 validator accepted a leaf whose KeyUsage forbids digital signatures | confirmed; reproduced | **fixed** |
| F3 | medium | An intermediate CA's EKU restriction was not enforced down the chain | confirmed; reproduced | **fixed** |
| F4 | medium | CertificateVerify's scheme identifiers were parsed and never checked | confirmed; reproduced | **fixed** |
| F5 | medium | XMSS leaf allocation was a read-then-write race; the seed leaked through `repr` | confirmed; **reproduced at 6/6 rounds** | **fixed** |
| F6 | low–medium | Application traffic and exporter secrets used the wrong transcript prefix | confirmed; **reproduced** | **fixed** — rated too low |
| F7 | low | A frame read had a size cap but no total deadline | confirmed | **fixed** |
| F8 | low | The padded control group accepted the all-zero X25519 shared secret | confirmed | **fixed** |
| F9 | low | Dependencies were not pinned or hashed | confirmed | **fixed** |
| F10 | low | The directory patch lacked a platform limit and an explicit switch | confirmed (partially fixed in v3) | **fixed** |

Test count: 211 → **233** (`python -m pytest tests -q`); `tools/verify_all.ps1` reports
**31 checks, 31 passed**; the Rust prototype now reports two negative controls of its own.
*(That was the count when this round closed. It is 32 now: round 5 added the live-check sweep
as check 4b — `tools/audit_live_checks.py`, described in `docs/AUDIT_SWEEPS.md`.)*

## F6 first, because the severity is wrong

The auditor rated F6 "low–medium". It is the most consequential finding in the report, and
the reason is the same one that made the earlier exporter bug invisible.

**Claimed:** `c ap traffic`, `s ap traffic` and `exp master` must be derived over the
transcript through the **server** Finished; `res master` over the transcript through the
**client** Finished. The code derived all four after adding the client's Finished.

**Verified:** correct, and the RFC is unambiguous — §7.1's key schedule names both
prefixes, and RFC 8448's own trace shows two different hashes for the two stages (which is
why the vector file added in the previous round already carries them as two constants:
`9608102a…` for `c ap traffic`, `0e8b3491…` for `res master`).

**Why it is worse than "low":** the application traffic keys are what protect every byte
after the handshake. Against a conformant TLS 1.3 peer — the integration this project
claims as its next step — our application keys and our exporter would be *different
secrets*, so the first application record would fail to decrypt. The harness cannot see
it, because both halves derive the same wrong value and every test here compares one half
with the other. This is precisely the failure mode of the exporter-context bug found in
the previous round, one level up: **a value the standard fixes, checked only against
itself.**

It also corrects a claim this repository made last round. `docs/STATIC_REVIEW_FIXES.md` §6
says the exporter "now follows the section's construction exactly". The *formula* did and
does; its *input* — which transcript the master secret came from — did not. The vector
tests could not catch that, because RFC 8448's exporter master secret is a vector for the
derivation, not for the handshake that feeds it. The auditor's own phrasing is the right
one: "独立测试 exporter 公式，并不能验证真实握手提供给它的 master secret 正确."

**Fixed:** `KeySchedule.derive_application_traffic` now documents and takes the
server-Finished prefix, and a separate `derive_resumption_master_secret` takes the
client-Finished one. The client derives the application keys in `receive_server_flight`
(where the transcript ends at the server Finished) and the resumption secret in
`send_client_finished`; the server derives them after emitting its own Finished and before
the client's arrives. `docs/PROTOCOL.md` §7 — the byte-exact specification of record —
was stating one hash for all four and is corrected, with the reason recorded at the site.

**Pinned by:** `tests/test_audit_v3_fixes.py::test_application_and_exporter_secrets_use_the_server_finished_transcript`
and `test_resumption_secret_uses_the_client_finished_transcript`. Both build a transcript
of their own from the frames the two roles exchanged, so the assertion is against the byte
string the standard names rather than against either role's bookkeeping. Each carries a
negative control asserting the *other* prefix gives a different value.

**One test had to change, which is the point.** `test_key_schedule.py` asserted that
`derive_application_traffic` also produced `res master` from the same hash. That assertion
encoded the defect; it now checks the two stages separately.

## F1 — the rustls prototype verified nothing

**Claimed:** `AcceptAnyCertificate` returns success from `verify_server_cert` and
`verify_tls13_signature` unconditionally, with every argument unused.

**Verified:** correct — both methods returned assertions, and the unused-parameter names in
the source (`_end_entity`, `_cert`, `_message`) make the auditor's point for them. An
active MITM could have completed a handshake with this client, and the hybrid key exchange
would not have noticed, because it provides no authentication of its own.

**Fixed as the auditor recommended:** the prototype now generates a throwaway CA and a leaf
it signed, serves `[leaf, CA]`, and the client verifies through **rustls's own webpki
verifier** with that CA in a root store — `.with_root_certificates(roots)` replaces
`.dangerous().with_custom_certificate_verifier(...)`. The `AcceptAnyCertificate` type is
deleted, so there is no longer a verifier in the file that accepts anything.

**Evidence, from the run itself:**

```
negative control 1: an untrusted CA is rejected -> invalid peer certificate: BadSignature
```

That line is a second `handshake()` call whose client trusts a *different* CA: it is
required to fail, and the process exits non-zero if it succeeds. Five consecutive runs
report both negative controls firing, the positive control completing, and the hybrid
group negotiating with deltas of 2271–2273 bytes.

**Residual, stated rather than hidden:** the prototype still does not exercise *hybrid
signatures* — rustls's `SignatureScheme` is a closed enum, so a composite
CertificateVerify needs a patched rustls or the delegated-credentials route. That was
documented before this audit and is unchanged.

## F2 — a leaf that forbids signing was accepted

**Claimed:** the validator checked the issuer's `keyCertSign` but never the leaf's
`digital_signature`, while `KEY_USAGE` counted as an understood critical extension.

**Verified:** correct. The leaf's private key signs regardless of what its certificate
permits, so a certificate with `digital_signature=False` verified cleanly.

**Fixed:** the leaf must now permit digital signatures *if it states a key usage at all* —
an absent extension means "no stated restriction" and stays allowed, which is RFC 5280's
reading and keeps certificates without the extension working.

**Pinned by:** `test_leaf_whose_key_usage_forbids_digital_signatures_is_rejected` (the
certificate is otherwise perfect: trusted CA, right name, right validity, serverAuth EKU)
plus a positive control.

## F3 — an intermediate's EKU did not bind the chain

**Claimed:** the loop checked CA flag, `keyCertSign`, path length and signature; only the
leaf's EKU was inspected, so an intermediate restricted to `clientAuth` could still
validate a server.

**Verified:** correct.

**Fixed:** every issuer that carries an EKU must permit server authentication, as RFC 5280
§4.2.1.12 intends — `anyExtendedKeyUsage` counts as permitting everything. The leaf keeps
its own check.

**Pinned by:** `test_intermediate_ca_restricted_to_client_auth_cannot_issue_a_server_certificate`,
with positive controls for an intermediate that permits `serverAuth` and one with no EKU.

## F4 — the scheme check existed but nothing called it

**Claimed:** `verify_hybrid_certificate_verify()` checks the announced scheme identifiers;
the live client path calls the signers directly and skips it.

**Verified:** correct, and sharper than the finding states: **nothing in the repository
called that function at all** — not the client, not the server, not any test. It was dead
code whose only effect was to make the check look present.

**Fixed:** the client now compares `classic_scheme` and `pq_scheme` against the negotiated
identifiers *before* verifying any signature, on both the classical-only and hybrid paths.
The dead helper is deleted rather than left beside the live check, for the same reason the
decoy `issuer_public_key` parameter was deleted in the previous round: a second,
unexercised implementation of a security check is a liability, not a spare.

**Pinned by:** `test_certificate_verify_with_a_wrong_scheme_identifier_is_rejected[classic]`
and `[pq]`, which rewrite one identifier in the frame and leave the (valid) signature
bytes untouched, so the test isolates the identifier check from the signature check.

## F5 — one leaf, four signatures

**Claimed:** `sign()` read `sk.next_index` at the top, did the WOTS+ work, and wrote the
index back at the bottom, with no lock — so two concurrent signers can share a leaf. Also,
`XmssSecretKey` is a dataclass whose `seed` had no `repr=False`.

**Verified:** correct on both counts, by reading.

**Reproduced, and the reproduction is more precise than the claim.** Four threads signing
different messages under a barrier, against the **unfixed v3 code**:

* at CPython 3.13's default GIL switch interval: **0 of 6 rounds collided**;
* with `sys.setswitchinterval(1e-6)`: **6 of 6 rounds handed all four threads leaf 0** —
  one WOTS+ leaf signing four different messages, which is the failure that breaks the
  scheme outright.

So the defect is real but was *masked* on this machine: the read-to-write span is shorter
than a GIL switch, so the interpreter happened not to switch inside the window. It is not
masked by anything the code does, and the protection disappears wherever that assumption
does — a free-threaded build, a C extension that releases the GIL inside the window, or a
longer derivation. Against the fixed code, the same amplified run gives `[0, 1, 2, 3]` in
6 of 6 rounds.

**Fixed:** the index is reserved under a lock **before** any hashing, so the counter
advances even if the signature never completes — burning a leaf, which fails in the safe
direction. The lock covers only the allocation, never the derivation, so signing still
runs concurrently. `seed` is `field(repr=False)`.

**Pinned by:** `test_xmss_indices_are_unique_under_concurrent_signing` (four barrier-started
threads, distinct indices, counter at 4) and three `repr` tests.

**Residual:** the auditor also asked for a crash- and rollback-resistant *persistent*
counter. That remains the caller's duty, as it was before this audit and as
`docs/SECURITY.md` states; this fix makes allocation atomic within one process only.

## F7 — a size cap is not a deadline

**Claimed:** the frame bound from the previous round limits how much may arrive, not how
long it may take; a peer dribbling bytes keeps the reader alive.

**Verified:** correct, and it was already listed as an open item in
`docs/STATIC_REVIEW_FIXES.md` §"What is still open" item 3. The auditor supplied the reason
to close it rather than the reason to keep deferring it.

**Fixed:** `_recv_exactly` and `_recv_frame` take an absolute monotonic `deadline`. The
socket timeout is clamped to the remaining budget, so a single blocking `recv` cannot
overshoot it, and restored afterwards. Every read in the loopback driver passes
`timeout_seconds`, the driver's own budget; a frame that takes 30 seconds is a peer that
has stopped talking. Callers that pass no deadline keep the old permissive behaviour.

**Pinned by:** `test_a_slow_frame_read_gives_up_on_the_deadline` (a peer announces 4096
bytes and sends 8; the reader must give up in under 5 seconds), plus two positive controls
including one with no deadline at all.

## F8 — the all-zero shared secret

**Claimed:** the padded share-size control calls `diffie_hellman` and uses the result with
no contributory check.

**Verified:** correct. The finding's own scope note is right too: the *hybrid* group's
classical half is rustls's X25519, which already rejects this, so only the control group
was affected.

**Fixed:** `reject_zero_shared` is applied on both paths, with the RFC 7748 §6.1 citation.
The prototype's self-check now feeds it an all-zero peer share and requires an error:

```
negative control 2: all-zero X25519 share rejected -> unexpected error: padded share-size
control: X25519 produced the all-zero shared secret, which RFC 7748 section 6.1 requires
be rejected
```

with a positive control that an honest share still completes.

## F9 — dependencies were not reproducible

**Claimed:** `bootstrap_env.ps1` installed with lower bounds and `--upgrade`, with no hash
locking.

**Verified:** correct. While fixing it, something else surfaced: `cryptography` is
installed in the interpreter's site-packages on this machine, not in the project's `.deps`
— so the package manifest's claim that "the repository is self-contained, dependencies
install inside the project" was not true of the one dependency everything imports.

**Fixed:** `requirements.lock.txt` and `requirements-falcon.lock.txt` pin exact versions
and carry the SHA-256 of **every file PyPI publishes for them** (155 and 49 files), so the
locks are platform independent rather than Windows-only. `tools/make_requirements_lock.py`
regenerates them. `bootstrap_env.ps1` installs from the lock with `--require-hashes` and
gains an explicit `-Unpinned` escape hatch for deliberately testing newer versions;
`install_falcon_provider.ps1` does the same for the 0.4.0 provider — which is pinned as a
*literal* version in the generator, because reading "whatever is installed" would rewrite
the pin to 1.0.0, which has no Falcon.

**Verified by running pip's own hash checking**, not by re-reading my own metadata:

```
python -m pip download --require-hashes -r requirements.lock.txt --dest <tmp>
→ Successfully downloaded cryptography cffi pycparser pqcrypto pytest pluggy iniconfig
  packaging colorama pygments   (10 files, every hash matched)
```

The package manifest now states where `cryptography` actually comes from and how to
install the locked set.

## F10 — the directory patch

**Claimed:** v3 gated the patch on environment variables but did not limit it to Windows
or require an explicit switch.

**Verified:** correct; this was the "partial fix" the summary table records.

**Fixed:** the patch now requires `os.name == "nt"`, and carries a three-state switch:
`DSH_SANDBOX_PYFIX=0/false/no/off` disables it even inside the sandbox,
`=1/true/yes/on` forces it on, and unset means "on only if Windows *and* a DSH sandbox
marker is present". The auto-detection stays because the module exists for exactly that
environment and this repository's own test runs depend on it; what changed is that the
platform is now part of the condition and there is a documented way to force either state.

**Pinned by:** three tests importing the module in a child interpreter (no marker → inert;
explicit off → inert; sandbox on Windows → patched) plus a source check that the platform
condition and the switch name are present.

## What this pass also changed

* **`docs/PROTOCOL.md` §7** — the specification of record stated one transcript prefix for
  all four secrets. Corrected, with the reason recorded in place.
* **`docs/SECURITY.md`** — new gap items for what remains unproven after this round, and
  the previous round's exporter statement corrected.
* **BOM removal** — nine project files carried a UTF-8 byte-order mark (a side effect of
  how earlier edits were written). Nothing read them incorrectly, but a BOM is invisible in
  review and does change the first bytes of a file; all nine are now plain UTF-8.
* **The animated demo** (`hybrid-tls13-prototype-demo.html`, workspace root) stated the old
  key derivation in its schedule panel. It now shows `TH_SF` for the application and
  exporter secrets and `TH_full` for the resumption secret.

## What is still open

1. **No vector covers the whole handshake's derivation chain.** The RFC 8448 tests check
   the primitives and the exporter master secret against published values, and
   `test_audit_v3_fixes.py` now checks the two transcript *stages* against a transcript the
   test builds. What no test does is drive a complete handshake and compare every derived
   secret against a published trace — which is what the auditor asked for, and what would
   have caught F6 without an auditor.
2. **XMSS index persistence is still the caller's duty**, and the new lock is in-process
   only. A crash between reserving an index and persisting it is safe (the leaf is burned);
   a rollback of the counter is not, and nothing here detects it.
3. **The certificate validator is still hand-written.** Two more checks arrived this round
   (leaf key usage, CA EKU chaining), and the auditor repeats the earlier reviewer's advice
   to hand the path to a mature validator. Still not done, still the better answer.
4. **No revocation checking** (no CRL, no OCSP, no stapling) and **`nameConstraints` is
   refused rather than enforced** — both unchanged from the previous round.
5. **The rustls prototype still covers the key exchange only**, not hybrid signatures.
6. **None of these fixes has been independently reviewed.** Three rounds of findings have
   each been fixed by the party that wrote the code, and each round has found another
   defect of the same kind — a check that existed but was not wired, a wrong transcript
   prefix, a leaf the validator did not look at. That pattern is itself information about
   how much independent review this code still needs.

## Reproducing this pass

```
python -m pytest tests -q                        # 233 passed
powershell -File tools\verify_all.ps1            # 32 checks, 32 passed
powershell -File tools\build_rust_prototype.ps1 -Offline
python -m pip download --require-hashes -r requirements.lock.txt --dest <tmp>
```

The Rust run is the one to read: it prints the two negative controls, the positive control
and the hybrid byte delta, and exits non-zero if any of them fails.
