# Assumption Ledger — hybrid-tls13
<!-- ASK mode: never -->

> **Provenance warning.** This ledger was reconstructed after the code existed, not
> written row-by-row before it. That is the anti-pattern the skill names, and it is
> recorded here as a fact rather than hidden: the rows below are the decisions the
> code demonstrably makes, and the two bugs found during the build (see
> `BUILD_NOTE.md`, run record) are direct evidence that at least one silent choice —
> the transcript position of CertificateVerify — was made by the code before anyone
> wrote it down.

| ID | Under-determined by the request | Chosen | Class | Source |
|----|--------------------------------|--------|-------|--------|
| A-001 | the note lists Falcon as the PQ signature backend; the installed `pqcrypto` 1.0.0 has no Falcon | install `pqcrypto==0.4.0` (PQClean) beside it under the renamed top-level package `pqcrypto_pqclean` | interface | default |
| A-002 | the note says "论文里把这个范围写清楚" about PKI, but not whether to implement chain validation | model the CA as a test signer over the hybrid body; no X.509 chain | semantic | default |
| A-003 | no KEM named for the main profile | ML-KEM-768 (FIPS 203 category 3), matching the note's "后量子 KEM" without further constraint | semantic | default |
| A-004 | no classical group named | X25519 (32-byte share, smallest ClientHello addition) | interface | default |
| A-005 | no classical signature named | ECDSA P-256 with SHA-256 (the note's own `classic_scheme` example) | interface | default |
| A-006 | no AEAD named | AES-128-GCM, the TLS 1.3 mandatory suite | interface | default |
| A-007 | the note's `HybridCertificateVerify` shows `uint16` length fields; it does not say what happens when a signature exceeds 65535 bytes | `vec16` everywhere; a backend exceeding it raises at encode time | interface | default |
| A-008 | scheme identifiers for the private-use extensions are not specified | private-use code points, one per backend, carried in the extension so a KEM or signature mismatch fails on the first flight | interface | default |
| A-009 | "两份签名都验证通过" does not state the failure semantics | `accepted = classic_ok AND pq_ok`; the failing half is named in the error | semantic | default |
| A-010 | the note's XMSS sketch sends WOTS+ public key + auth path; it does not fix the tree height | default `height=10` (1024 one-time keys), overridable per run | interface | default |
| A-011 | no requirement on whether a stateful XMSS key may be reused across handshakes | `next_index` advances per signature and raises when exhausted; index persistence is the caller's duty | semantic | default |
| A-012 | "端到端握手延迟" does not say whether the network is in the loop | both: in-process for crypto-only stage timings, loopback TCP for transport-inclusive latency, reported side by side | semantic | default |
| A-013 | the note asks for handshake size per field but not for a classical baseline | PQ deltas decomposed analytically from the measured messages; no second classical handshake is run | semantic | default |
| A-014 | environment has no post-quantum library guarantee | `ecdh-kem-placeholder` (ECIES over X25519) keeps the spine runnable and reports `post_quantum = False` | semantic | default |
| A-015 | no requirement about where dependencies live | installed inside the workspace (`.deps`, `.deps-falcon`) because the sandbox denies writes elsewhere | interface | default |
| A-016 | the record layer's outer content type is not discussed in the note | outer header carries the true content type rather than always `application_data`; sizes and AAD length are unchanged | interface | default |
| A-017 | the note asks for a security argument but names no model or tool | Verifpal; Tamarin (needs GHC), ProVerif (no Windows build), Docker and WSL (unavailable here) were each ruled out by what this machine can run | semantic | default |
| A-018 | symbolic analysis is bounded but the bound is not given | `--sessions 1`; **replay across concurrent sessions is not covered**, and every "holds" is "no attack found within that bound" | semantic | default |
| A-019 | a compromise could be declared before or after the handshake | before it — a leak declared after cannot affect a signature already made, so the queries would hold vacuously | interface | default |
| A-020 | the design authenticates the server only, which no query states | `authentication? Client -> Server: c1` is kept in every model and is expected to fail, so the non-claim is visible rather than assumed | semantic | default |
| A-021 | the note says PKI migration is out of scope but still wants comparable sizes | two certificate profiles: `x509=False` (modelled, what the symbolic models describe) and `x509=True` (real chain, **the only one whose absolute numbers may be quoted**) | semantic | default |
| A-022 | where the post-quantum public key lives in a real certificate | a private-extension OID on the leaf (`1.3.6.1.4.1.99999.1`), not a composite key in the SPKI and not a second certificate | interface | default |
| A-023 | the X.509 profile certifies an ECDSA P-256 leaf key | other classical signers raise early rather than producing a chain whose signature algorithm disagrees with the handshake | interface | default |
| A-024 | the review asks for "real chain validation" but not for revocation or a trust-store model | path validation only: signatures, windows, CA constraints, key usage, path length, critical extensions, name. **No CRL, no OCSP, no stapling, no distrust list.** A revoked certificate is accepted | semantic | default |
| A-025 | the review does not say how a trust anchor is identified | the anchor is a certificate the client holds out of band, and the chain's top is compared to it **byte for byte**; if it differs the top's signature is verified against the anchor's key. Anchors identified by public key alone are not supported (a decoy `issuer_public_key` argument was removed rather than implemented) | interface | static review |
| A-026 | the modelled certificate profile is the default one, but nothing said it must check identity | the modelled path compares `server_identity` against the client's `trusted_name` byte for byte, matching what the X.509 path does through the SAN. No wildcard or SAN-matching rules — a name either matches or the handshake fails | semantic | static review |
| A-027 | the harness's own record framing has no size bound in TLS 1.3 (the record layer bounds it at 2^14+256) | `_MAX_FRAME_BYTES = 1 MiB` on `_recv_frame`, which raises rather than allocating an announced length. A guard for the harness, not a protocol rule, and it is **not** exercised by any deployed peer | interface | static review |
| A-028 | the exporter's `context` is caller-supplied and unbounded | the RFC's expression is followed exactly: `HKDF-Expand-Label(Derive-Secret(EMS, label, ""), "exporter", Hash(context), length)`. A context longer than the hash block is hashed, not truncated, so no caller input can collide by length | interface | static review |
| A-029 | the review flags directory permissions, but the fix must not change behaviour on a machine without the sandbox | `tools/sandbox_pyfix/sitecustomize.py` patches `os.mkdir` **only** when `DSH_SESSION_ID` or a `DSH_SANDBOX*` variable is present. Imported anywhere else it is inert, so it can no longer widen a directory DACL on an unrelated machine | interface | static review |
| A-030 | RFC 8446 §7.1 names two different transcript prefixes, but the code derives all four secrets at one call site | `c ap traffic`, `s ap traffic` and `exp master` over ClientHello…server Finished; `res master` over …client Finished, in a separate method. Deriving them together is what allowed the two stages to be conflated for three revisions | semantic | v3 audit F6 |
| A-031 | the audit asks the rustls prototype to verify certificates, and the prototype has no PKI | a throwaway CA plus a leaf it signed is generated per run; the client trusts only that CA and verifies through rustls's own webpki path. Each run also performs a handshake against a *different* CA and requires it to fail | interface | v3 audit F1 |
| A-032 | the audit asks for atomic XMSS index allocation and a crash-resistant counter | atomicity is provided in-process by a module lock held only for the read-reserve-write; **durability is not**, and persisting `next_index` across crashes and rollbacks stays the caller's duty (now listed as a gap rather than an assumption) | semantic | v3 audit F5 |
| A-033 | the padded share-size control calls `x25519-dalek` directly; the audit asks for a contributory check | the all-zero shared secret is rejected on both paths of that control, per RFC 7748 §6.1. The *hybrid* group needs nothing: its classical half is rustls's X25519, which already rejects it | interface | v3 audit F8 |
| A-034 | the audit says a frame size cap is not a deadline | `_recv_frame`/`_recv_exactly` take an absolute deadline and clamp the socket timeout to the remaining budget; the loopback driver passes its own `timeout_seconds` per frame. Callers that pass no deadline keep the old permissive behaviour | interface | v3 audit F7 |
| A-035 | the audit asks for pinned, hashed dependencies, and the lock must also work off Windows | exact versions plus the SHA-256 of **every** distribution file PyPI publishes for them (155 and 49 files), installed with `--require-hashes`; `-Unpinned` restores the old behaviour deliberately. The Falcon provider is pinned as a literal 0.4.0 in the generator, because reading "what is installed" rewrote it to 1.0.0, which ships no Falcon | interface | v3 audit F9 |
| A-036 | the audit asks the directory patch to be limited to Windows and to have an explicit switch | the patch requires `os.name == "nt"`, honours `DSH_SANDBOX_PYFIX=0/1` in both directions, and otherwise auto-enables only inside a DSH sandbox. Auto-enabling stays, because that environment is the only reason the module exists and this repository's own test runs depend on it | interface | v3 audit F10 |
| A-037 | the audit notes that `cryptography` is imported from site-packages rather than the project's `.deps` | the lock file installs it into `.deps` like everything else, and the package manifest now states where it actually comes from instead of claiming the checkout is self-contained | interface | v3 audit F9 |
| A-038 | three reviews each found "a check that exists but is not on the live path", and the discovery method was a reader's habit rather than anything mechanical | the habit is now an inventory: `tools/audit_live_checks.py` (Sweep A) is enforced as acceptance check 4b, with interface and framework-call exemptions declared and printed. Checks that nothing on the live path calls are **deleted**, not exempted — `IssuedCertificate.require_valid` and `.verify` went that way | semantic | round 5 |
| A-039 | nobody has written the analogous inventories for derived values and for certificate constraints | specified in `docs/AUDIT_SWEEPS.md` with the exact columns, and stated there as **not written**; the evidence column (which test proves the input is the standard's rather than the peer's) is the reason they exist | semantic | round 5 |
| A-040 | an audit broke Sweep A with three planted probes, so what counts as a reference to a check? | a reference is an **AST call site**, never a mention. A `getattr(obj, "name")` literal counts and is labelled `getattr-only` for hand verification; exemptions are keyed on `Class.method`; a call on a variable is attributed only when exactly one class in the tree defines that name, otherwise the check must be declared as an interface or it fails as `UNATTRIBUTED` | semantic | v4 audit V-20…V-22 |
| A-041 | Sweep A's report is consumed by other programs (the acceptance runner and the auditor's harness) | the report is ASCII-only, an empty or unreadable tree is a tool error rather than a pass, and an unparsable file is reported rather than skipped. Each of those three was a defect the audit's reproduction exposed | interface | v4 audit V-20…V-22 |
| A-042 | the fifth review asks the client to enforce RFC 8446 §4.1.3/§4.3.1 against the messages the *server* sends: which extension set is allowed there? | the profile's own offer set, written as an explicit closed set — ServerHello may carry `supported_versions`, `key_share` and `pq_ciphertext` only; EncryptedExtensions may carry **nothing**, because this profile offers no EE extension. Hardcoding the set is deliberate: it is what this implementation offers, and a new extension has to be added in both places | semantic | v6 attack K2/K3 |
| A-043 | the server sends no CertificateRequest, so what does the client do with a Certificate whose `certificate_request_context` is non-empty? | it is refused at decode, in **both** certificate bodies (`Certificate` and `X509Chain`), before any key material is read. If a CertificateRequest is ever added, the two decoders must take the expected context as a parameter and compare instead of requiring emptiness — recorded here so the rule is not silently inherited | semantic | v6 attack K6 |
| A-044 | RFC 8391's public SEED is public, so what stops a caller from passing the secret seed as the public seed? | nothing did: `keygen_from_seed` validated lengths only, and the auditor built the full reconstruct-and-forge chain from the public key (their M1/M3). Overlapping seeds — equal, or either a prefix of the other — are now refused with a named `ValueError`; the handshake path is unaffected because `keygen()` draws two independent `os.urandom(n)` values | semantic | v6 attack V6-09 |
| A-045 | the U-03 correction arrived as a patch from the reviewer-collaborator, and it changes the wire format | adopted whole, file by file (zero conflicts against this tree's post-v6 edits), on the strength of my own line-by-line read against RFC 8391 §2.5/§3.1.2/§5.1 plus the merged tree's acceptance run. The public key becomes `root \|\| public_seed` (32→64 bytes at n=32) and the scheme id `0x0E00+h` → `0xFE00+h`, so **old keys and certificates are incompatible by design** and both peers have to upgrade together | interface | U-03 follow-up |
| A-046 | Sweep A credits a variable-receiver call when exactly one class in the tree defines that name, which is the tool's main residual blind spot | kept and made visible rather than removed: the rule cannot distinguish a reachable call line from an unreachable one, so a dead check could still be lifted to `live`. The count and every entry are printed in every report (`variable-sole`, `of those: sole-implementation variable calls : 12`), and the call site shown is the live one that carries the verdict. Type inference would be needed to close it; a wrong inference would produce false `DEAD` verdicts on the live interfaces, which is the failure mode the sweep exists to prevent | semantic | v6 attack V6-10a |
| A-047 | a `getattr(obj, "name")` literal names a check without calling it, so what counts as evidence there? | an **undeclared** `getattr`-only reference now fails the sweep (`getattr-undeclared`, exit 1). A dispatcher that truly calls a check through a string literal must be declared in `GETATTR_DISPATCHED` with the mechanism, the same shape as `INTERFACE_METHODS`. The table is empty on this revision because nothing under `tls/` is reached only that way | semantic | v6 attack V6-10b |
| A-048 | the eighth review showed a *declared* dispatch site could sit in code that never runs, so what does the sweep now accept as a caller? | a reference counts only if its site is reachable: not inside a statically dead branch (`False`, `0`, `while False`, the `else` of always-true tests, `typing.TYPE_CHECKING` through a resolved unshadowed alias) and inside a function the limited call graph reaches from a declared entry or a reviewed interface binding. Nested scopes are keyed `Class.method.<locals>.helper`, and a nested body is reachable only when a reachable function loads its name | semantic | v8 attack V8-01 / T1 / T2 |
| A-049 | where do the sweep's execution roots come from, and how are they checked? | `ENTRY_POINTS` names seven drivers with the command that runs each; every entry must resolve to exactly one definition, module-level code is a root only in a module an entry imports, and test modules are never roots. Interface declarations additionally need a variable-receiver reference from a live root, so a fabricated declaration fails | semantic | v8 attack V8-01 |
| A-050 | the sweep now infers receiver types for call-graph edges. How far does that go, and what does it not claim? | three narrow sources only: a local name whose every assignment in that function is a constructor call to the same in-tree class (or an annotated parameter), `self.<attr>` whose every assignment in the class is such a call or a matching annotation, and a `Class(...)` call used directly as the receiver. References keep their syntactic `via`, so attribution and reachability stay separate answers; anything else resolves to nothing and is reported as unverified | semantic | v8 attack V8-01 |
| A-051 | a legal multi-share ClientHello is refused by this profile. Is that a wire rule or a capability limit? | a capability limit, stated as one: the refusal names "exactly one classical share" and "no HelloRetryRequest" instead of reporting trailing bytes, and the corrected fixture builds a well-formed two-entry message. The single share is kept this round per the plan; multi-share decoding, duplicate-group rejection and selection are listed as future work | interface | v8 attack T5 |
| A-052 | the seed-overlap guard still accepts *partial* overlap (`seed = public_seed[16:] + unknown`) | kept as a declared boundary, not closed: no length rule and no string comparison can establish independence, so the contract is documented instead (deterministic entry point for tests and restores; the random creation path cannot inject seeds). Their T6 stays `INFO-DEVIATION`, and no "fixed" claim is made | semantic | v8 attack T6 |
| A-053 | the red-team pass measured a whole-tree keygen per connection; what may the driver reuse? | **the authentication credential only**. `HybridConnection.run` accepts pre-built authority/credentials/certificate, while transcripts, ECDHE and KEM ephemeral keys, traffic secrets and record sequences stay per handshake, and each signature still spends a fresh leaf. No key state is persisted or shared across processes: that stays gated behind the plan's stage-2 design | semantic | v8 attack W1 |
| A-054 | the sweep reported 39 `tmp_path` setup errors in a patch-free environment; is that a test problem? | no: pytest creates its base temp directory with mode `0o700`, which a capability-SID sandbox cannot traverse. Rather than call it "solved", `tests/conftest.py` provides the same fixture contract from a checkout-local scratch root, and the before/after numbers (354 passed + 39 errors → 393 passed) are recorded in `validation/README.md`. The sandbox limitation itself remains | interface | v8 attack TB-1 |

## Notes

- **A-001** — the alternative was to drop Falcon and use ML-DSA, which is available in
  1.0.0. Rejected because the design note names Falcon as the main implementation and
  treats WOTS+/XMSS as the comparison; the provider is one install command
  (`tools/install_falcon_provider.ps1`) and one `sys.path` append.
- **A-002** — this is the row most likely to change what a result means. Absolute
  handshake byte totals here are far below a deployed TLS 1.3 handshake because there
  is no certificate chain; only the per-field deltas transfer. Reversing it means
  building a real X.509 path, which is a different project.
- **A-009** — the rejected alternative is `OR` semantics ("either signature
  suffices"), which is a legitimate design used by some hybrid deployments but is
  strictly weaker and contradicts the note's own `ok_T && ok_PQ`.
- **A-012** — reversed during the build. The original choice was in-process only;
  rung F6 added a loopback TCP transport because the 1-RTT claim cannot be observed
  from an in-process driver, and "no extra round trip" is a headline property of the
  design note. Both numbers are now reported, and the TCP benchmark asserts the wait
  count rather than restating the claim.
- **A-013** — the rejected alternative, running a parallel classical-only handshake,
  would produce a second measurement subject to its own noise; the analytic
  decomposition is exact for the fields it names.
- **A-014** — the placeholder uses the same interface and failure modes but a
  different assumption. It is deliberately not named "pq" anywhere and reports
  `post_quantum = False` so no report can present it as post-quantum.
- **A-024** — this is the largest remaining gap in the certificate story, and it is a
  scope decision rather than an oversight: revocation needs a distribution mechanism
  this harness has no representation for. It is listed here so that no report describes
  the X.509 profile as "full" chain validation.
- **A-025** — reversing it means accepting a trust anchor as a bare public key, which is
  what a deployed trust store would hand over. That is a real feature with its own
  failure mode (a key that matches two certificates), so it was not added inside a
  security fix.
- **A-027** — the bound is deliberately static. A negotiated limit would have to be
  plumbed through both roles to be meaningful, and the only peer here is this repository.
- **A-030** — the reversed alternative is the one the code used to take: derive all four
  secrets from the transcript that includes the client's Finished. That is self-consistent
  and non-conformant, and it took an external reader to notice, because every test in this
  repository compares this implementation against itself.
- **A-032** — the rejected alternative was to make the counter durable inside the backend
  (write a file, fsync, refuse to sign if the file is unreadable). That changes the backend's
  contract from "stateful" to "stateful and I own your disk", and the right place for it is
  the deployment that stores the key. Recorded as gap 14 in `docs/SECURITY.md` instead.
- **A-034** — the deadline is the driver's own `timeout_seconds`, not a new constant. A
  frame that takes 30 seconds on a loopback socket is a peer that has stopped talking, and
  the slowest shaped link in the benchmark moves a whole flight in tens of milliseconds.
- **A-035** — the lock lists every file PyPI publishes for each pinned version rather than
  only the Windows wheels this machine happens to use, so a reviewer on Linux or macOS gets
  the same pin guarantees instead of a hash mismatch.

## Sweep status

`SWEEP_UNAVAILABLE` — this deployment has exactly one model provider configured
(`deepseek-official`). Phase 4 requires a different model family, and the skill
forbids substituting a second pass by the same family. Nothing in this ledger has
been externally acquitted; the `undeclared` rows a sweep would have found are, by
construction, still unknown.

## U-03 follow-up (2026-09-21)

Public WOTS+ step material is derived from a fresh, independent public seed and
leaf/chain/step/role address, with a separate bitmask. It is not a secret seed.
XMSS public keys now carry `root || public_seed`; both seeds and the latest counter
are required for restoration. Only the default SHA-256/n=32 chain calculation is
compared to RFC 8391 here; the remaining custom XMSS components still need their
own security analysis. No full reduction follows from a passing test suite.

## Fifth review (2026-09-22)

The attack package's ten findings are disposed of in `docs/AUDIT_V6_RESPONSE.md`; the
rows above record the four decisions that carry an assumption into the code (A-042…
A-045) and the two that decide what the sweep is allowed to conclude (A-046, A-047).
Two things in this revision are worth separating when quoting it:

- **Adopted, not authored here**: the U-03 chain change (`tls/pq/wots_xmss.py`,
  `tls/pq/signature.py`, their tests, docs and measurement records). It was read line by
  line here and it is exercised by the acceptance run, but its authorship is the
  collaborator's.
- **Authored here, unreviewed**: every K-fix, the seed-overlap guard, the sweep changes
  and all of this round's documentation. No party outside this repository has seen them.

The suite this revision ships is **393 tests**; `tools/verify_all.ps1` is **35 checks** and passes
35/35 on this tree (4c locks, 4d environment manifest and 5c lifecycle joined in v9).

## Eighth review (2026-09-22) — the red-team round

Rows A-048…A-054 record the decisions this round's code makes. Two things are worth separating
when this revision is quoted:

- **Measured, not inferred**: the XMSS cost decomposition (whole-tree keygen, one sign/verify,
  cold and hot handshakes, wall and CPU time, raw samples). The plan's own rule applies: it is a
  cost measurement, not a remote denial-of-service finding, and no cross-version factor is claimed
  from another machine's numbers.
- **Deliberately not enabled**: any cross-process reuse of XMSS state. The plan gates it behind a
> monotonic counter source plus crash and rollback tests, and none of that exists, so the hot mode
> is single-process, credential-only, and temporary.

The review's four historical expectation disagreements (B7/B8/B10/D4) stay as they are, and its
own two stale fixtures (J1/J3) are recorded rather than "fixed".
