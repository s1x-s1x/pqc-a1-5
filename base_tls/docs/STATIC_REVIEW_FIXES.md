# Response to the static security review

A second reviewer — working from the source only, without running it — produced *源码安全
审查整理* (`源码安全审查整理 - DeepSeek(1).pdf`), a static review of this repository. It
found one critical issue, two high, three medium, and one defect that turned out not to be
in this codebase at all. This document records, per finding: what the reviewer claimed,
what the code actually did when this pass checked it, what changed, and which test now
pins it.

Two framing notes, because they decide how much the rest is worth.

**The reviewer's own caveat is honoured.** Their conclusion states that these are static
findings, that no source was modified and no dynamic attack was performed, and that they
must not be described as successful exploits. Nothing below claims an exploit. Where this
pass *did* reproduce a finding, the reproduction is an executable test, and it is named.

**Nobody independent has checked these fixes.** This pass was written by the same party
that wrote the code under review. The reviewer's findings are addressed, and the claim
"addressed" rests on tests written in the same pass. `docs/SECURITY.md` already records
that same-family review cannot substitute for independent review, and that applies here
too: the fixes are new, unreviewed code.

## Summary

| # | Severity | Finding | Verified? | Status |
|---|----------|---------|-----------|--------|
| 1 | critical | X.509 trust anchor matched on `subject` + `serial_number`, skipping the signature check | reproduced | **fixed** |
| 2 | high | The default (modelled) certificate path never compared the identity | reproduced | **fixed** |
| 3 | high | `key_fingerprint` returned the first 12 bytes of the traffic key | reproduced | **fixed** |
| 4 | medium | TCP frame length had no upper bound | confirmed by reading | **fixed** |
| 5 | medium | Chain validation missed `pathLenConstraint`, `keyCertSign`, name constraints, unknown critical extensions | confirmed by reading | **3 of 4 fixed**, 1 fail-closed |
| 6 | medium | The exporter did not follow RFC 8446 §7.5 | reproduced | **fixed**, now vector-checked |
| 7 | medium | `sitecustomize.py` forced `0o777` unconditionally | confirmed by reading | **fixed** |
| 8 | — | `stack.c:15`, `strcpy` overflow, `_lab1_setup` | **not this repository** | not applicable |
| 9 | — | (found during this pass) `verify_chain` accepted an `issuer_public_key` it discarded | reproduced | **parameter removed** |

Test count: 186 → **211** (`python -m pytest tests -q`), and `tools/verify_all.ps1`
reports **31 checks, 31 passed**. *(The count is 32 as of round 5, which added the
live-check sweep as check 4b; see `docs/AUDIT_SWEEPS.md`.)*

## 1. Trust anchor bypass — critical

**Claimed:** `pki.py` matched the chain's top certificate against the trusted root by
comparing `subject` and `serial_number`, and skipped the signature check when they agreed.
Both fields are public and attacker-chosen, so a fabricated root carrying the trusted
root's name and serial number, with the attacker's own key, would end a chain the client
accepts.

**Verified, in code:** correct. The old check was a field comparison, and the file's own
comment now records it. This is the one finding that was reproduced executably rather than
by reading: the test below builds the forged root, asserts that it really does match the
trusted root on `subject` and `serial_number`, and shows that the chain is rejected anyway
— which can only be because the anchor check no longer trusts those fields.

**Fixed:** the anchor comparison now compares the **full DER encoding** of the top
certificate against the trusted root's, and only skips the signature check when the two
are byte-identical. Anything else is verified as a signature over the top certificate by
the anchor's key. An attacker cannot forge a DER encoding that hashes to the anchor's.

**Pinned by:** `tests/test_security_fixes.py::test_forged_root_with_the_trusted_roots_name_and_serial_is_rejected`,
with `test_honest_chain_still_verifies` as the positive control.

The reviewer also recommended "更稳妥的是使用成熟的证书路径验证器" (use a mature path
validator). That is not what happened: this remains a small hand-written validator with
only the checks listed in §5 and §"What is still open". Handing this to OpenSSL or
`cryptography`'s `pkix` path would remove a class of bugs, and it is named below as the
better long-term answer rather than quietly declined.

## 2. The modelled certificate path had no identity check — high

**Claimed:** `_check_modelled_certificate()` verified the CA signature and the classical
scheme ID but never compared `certificate.body.server_identity` with the client's
`trusted_name`; `trusted_name` was used only on the X.509 path, while the default
configuration is `x509=False`. A party holding a certificate the same CA issued for
*another* identity could therefore impersonate the target.

**Verified, in code:** correct, and the severity is right — the modelled profile is the
default, so this was the default authentication path.

**Fixed:** the modelled path now compares the body's identity against `trusted_name` byte
for byte before extracting any key, matching what the X.509 path does through the SAN.
There is no wildcard matching and no SAN-list logic: a name either matches or the
handshake fails. The reviewer additionally asked for a negative test for "valid
certificate, wrong identity" — that test exists now, and it drives a real handshake with a
deliberate identity mismatch, so it exercises the path a real attacker would take rather
than calling the checker directly.

**Pinned by:** `tests/test_security_fixes.py::test_modelled_certificate_for_another_identity_is_rejected`,
positive control `test_modelled_certificate_for_the_expected_identity_is_accepted`.

## 3. The key "fingerprint" leaked the key — high

**Claimed:** `aead.py:87`'s `key_fingerprint()` returned `self._key[:length].hex()` with a
default `length=12`, i.e. 12 bytes of a 16-byte AES-128 key — 96 bits disclosed, leaving
four bytes unknown — while its docstring claimed it must not print the key. Call site:
`demo/run_handshake.py:184`.

**Verified, in code:** correct, including the arithmetic. The docstring said the value
"must not print the key" and the function printed three quarters of it.

**Fixed:** the function returns a domain-separated SHA-256 digest of the key, truncated for
display: `SHA-256("hybrid-tls13 traffic key fingerprint|" ‖ key)`. It identifies a key for
the demonstration log and reveals nothing invertible about it.

**Pinned by:** `tests/test_security_fixes.py::test_traffic_key_fingerprint_is_a_hash_and_not_a_prefix_of_the_key`,
which asserts the output is neither the key's hex prefix nor its first bytes, and that the
digest matches an independently computed expression.

**On the reviewer's follow-up — "已经保存或共享的演示日志也应按敏感信息处理":** every
`*.md`, `*.txt`, `*.json` and `*.log` file in the repository was searched for stored
fingerprint output and for `key_fingerprint`, and **none contains a value**. The demo
prints to stdout and nothing captures it, so there is no saved log to scrub. The
`hybrid-tls13-review-package*.zip` deliveries contain no logs either. This is stated as a
search result, not as a guarantee about copies taken outside the repository.

## 4. The TCP frame reader had no size bound — medium

**Claimed:** `tcp.py:70` read a four-byte length and then read that many bytes with no
upper bound. The reviewer also stated, correctly, that this must **not** be presented as a
denial-of-service vulnerability in the shipped harness: the driver is loopback-only and has
a socket timeout, so the exposure appears only if the reader is reused in a server.

**Verified, in code:** correct.

**Fixed:** `_recv_frame` now refuses any announced length above `_MAX_FRAME_BYTES`
(1 MiB) and raises `ConnectionError` naming the value, instead of allocating it. The
constant is documented as a harness guard, not a protocol rule, since TLS's own record
layer already bounds records at 2^14 + 256 bytes.

**Pinned by:** `tests/test_security_fixes.py::test_oversize_frame_is_refused_without_allocating_it`
and `test_frame_at_the_limit_still_arrives`.

**A process note worth recording.** The first attempt to apply this fix used a text
substitution that silently did not match (the file has CRLF line endings and the search
string had LF). The code was unchanged, the suite was still green — because no test
covered the bound — and the new regression test then hung for ten minutes reading 1 MiB + 1
bytes that never arrived. That hang is what found the non-applied edit. The lesson is
already this project's own: a fix without a test that fails before it is a claim, not a
fix. The test came first in the other six cases; here it arrived second and caught its own
absence.

## 5. Missing chain constraints — medium

**Claimed:** `pki.py:253` did not enforce `pathLenConstraint`, CA `keyCertSign`, name
constraints, or the unknown-critical-extension rule.

**Verified, in code:** correct on all four counts; the validator checked signatures,
validity windows, CA basic constraints, the anchor, EKU and the SAN name, and nothing else.

**Fixed — three of four:**

* **`keyCertSign`** — an issuer must now carry a key usage extension that permits signing
  certificates. `basicConstraints: CA` alone no longer authorises issuance.
* **`pathLenConstraint`** — enforced, counting the **CA** certificates below the issuer and
  not the end-entity leaf, because counting the leaf would reject every chain whose
  intermediate carries `path_length=0` (which is what this project's own chain does).
* **Unknown critical extensions** — a critical extension outside the understood set is
  refused, per RFC 5280 §4.2. The understood set is explicit and includes the private-use
  PQ-key OID.

**Not fixed — name constraints.** `nameConstraints` is not implemented. The practical
behaviour is fail-closed rather than permissive: `nameConstraints` is not in the understood
set, so a *critical* name-constraints extension — which is how RFC 5280 requires it to be
marked — causes the chain to be rejected. A non-critical `nameConstraints` extension would
be ignored, which is a standards violation that no real CA commits. Rejection is not
enforcement: a chain that a correct validator would accept with the constraint applied is
refused here. This is recorded in `docs/SECURITY.md` as an open gap, not as coverage.

**Pinned by:** `test_intermediate_whose_key_usage_forbids_signing_certificates_is_rejected`,
`test_intermediate_with_path_length_zero_cannot_issue_another_ca`,
`test_unknown_critical_extension_is_rejected`, and
`test_chain_for_another_identity_is_rejected`.

## 6. The exporter did not follow RFC 8446 §7.5 — medium

**Claimed:** `state.py:97`, documented as the RFC 8446 exporter, derived with the *current
transcript hash* where the standard uses the empty-message hash, and with the *raw
context* where the standard uses the context's hash. The reviewer asked for standard test
vector verification.

**Verified, in code:** correct on both counts — and worth stating why it survived: both
endpoints made the same mistake, and the handshake's own exporter check compares client
against server, so it passed while the value was wrong. An equality test between two
implementations that share a bug is not a test of the standard.

**Fixed:** the implementation now follows the section's construction exactly:

```
Exported Keying Material = HKDF-Expand-Label(
        Derive-Secret(ExporterMasterSecret, label, ""),
        "exporter", Hash(context_value), key_length)
```

**Verified against standard vectors.** RFC 8448 (*Example Handshake Traces for TLS 1.3*)
publishes the IETF's own intermediate values, including the **exporter master secret**, and
`tests/test_rfc8448_vectors.py` now checks this project's primitives against seven of its
vectors: `HKDF-Extract`, both `derived` expansions, `c/s hs traffic`, `c ap traffic`,
traffic keys and IVs, the Finished key, `exp master`, and `res master`. All seven
reproduce the RFC's values byte for byte.

**What the vectors do not cover, stated plainly:** RFC 8448 publishes no *exported keying
material* — the output of the final `HKDF-Expand-Label(..., "exporter", Hash(context), L)`
step — anywhere in its 68 pages, and no ACVP TLS 1.3 exporter vector set was located
during this pass. So the final Expand step has no published vector to check it against. It
is covered by two things instead: `test_exporter_matches_the_rfc_expression` compares the
implementation against an independent reimplementation of the RFC expression (cross-checked
against another implementation's documentation of the same section), and the vectors above
pin every primitive that expression is built from. That is weaker than a vector for the
final step, and the reviewer's request is only partly satisfied.

**Pinned by:** `tests/test_rfc8448_vectors.py` (7 tests), plus three tests in
`tests/test_security_fixes.py` including two negative controls that assert the pre-fix
construction differs from the correct one.

## 7. The sandbox compatibility patch was unconditional — medium

**Claimed:** `sitecustomize.py:26` forced `mode=0o777` on every `os.mkdir` with no platform
or environment check. As a deliberate compatibility patch it is reasonable, but it should
not load unconditionally into other environments, where it weakens temporary-directory
permissions.

**Verified, in code:** correct; the patch applied at import time, with no condition.

**Fixed:** the patch now applies only when the environment identifies the sandbox it exists
for (`DSH_SESSION_ID`, or any `DSH_SANDBOX*` variable). Imported anywhere else it is inert,
so the module can no longer widen a directory DACL on an unrelated machine or in an
unrelated process tree.

**Pinned by:** `tests/test_security_fixes.py::test_sandbox_mkdir_patch_is_inert_without_the_sandbox_environment`
and `test_sandbox_mkdir_patch_applies_under_the_sandbox_environment`, which import the
module in a child interpreter with and without the marker.

## 8. `stack.c` / `_lab1_setup` — not this repository

**Claimed:** `stack.c:15` contains an obvious `strcpy` stack overflow and an `fread` whose
result is not NUL-terminated, in an independent `_lab1_setup` teaching directory.

**Checked:** this repository contains **no C source files at all** — no `stack.c`, no
`_lab1_setup` directory, and no `Makefile` building C. The reviewer's own text bounds the
finding correctly ("不能把它计作 TLS 远程代码执行漏洞", and no evidence that the TLS project
calls it). Nothing was changed, because there is nothing here to change. Recorded so that a
later reader does not assume it was silently dropped, and so that if a `_lab1_setup` tree
exists elsewhere in the reviewer's checkout it is understood to belong to different
material.

## 9. Found while fixing: a parameter that promised what it did not do

`verify_chain` accepted an `issuer_public_key` argument, documented as "how a caller
holding only the anchor's public key would use this" — and then discarded it, because the
anchor check needs the certificate to compare against. No caller anywhere passed it.

A security review is the wrong place to leave a documented capability that does not exist,
so the parameter and the sentence are gone. It is removed rather than implemented on
purpose: a second verification path shipped without tests, inside a security fix, would be
a worse answer to this review than one honest path. Trust-anchor-by-key is a real feature
for the rustls integration and it would need its own tests.

## What is still open

Ordered by what a reader would most likely assume is covered and is not.

1. **No revocation at all.** No CRL, no OCSP, no stapling, no distrust list. A revoked
   certificate is accepted. This is a scope decision (`ASSUMPTIONS.md` A-024), not an
   oversight, and it means "the X.509 profile validates chains" must never be written as
   "full validation".
2. **Name constraints are refused, not enforced** (§5). Fail-closed, still wrong.
3. **No total read deadline on the TCP frame reader** — the half of the reviewer's advice
   that was not implemented; only the size cap is in. The socket carries a per-operation
   timeout, and the driver is a loopback harness with exactly one peer, but the reviewer's
   point stands for any reuse as a server. It is not implemented because a wall-clock
   deadline over the deliberately delayed shaped-link runs is a source of flakiness in the
   measurements, and that trade has not been analysed.
4. **The exporter's final Expand step has no published vector** (§6).
5. **The hand-written validator itself.** Three constraints were added; the reviewer's own
   preference was a mature path validator. Five checks written by hand is five chances to
   be wrong, and the anchor bug was exactly that kind of mistake.
6. **These fixes have not been independently reviewed.** They are one party's response to
   another party's findings, verified by that same party's tests.

## Reproducing this pass

```
python -m pytest tests -q                       # 211 passed
powershell -File tools\verify_all.ps1           # 32 checks, 32 passed
python -m pytest tests/test_security_fixes.py tests/test_rfc8448_vectors.py -q
```

The two new test modules exist to fail against the code as reviewed: each test names the
finding it pins, and the exporter tests carry negative controls that assert the pre-fix
construction differs from the correct one.
