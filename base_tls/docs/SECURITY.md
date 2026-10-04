> **U-03 implementation update, 2026-09-21:** fixed constant WOTS+ step material by introducing independently sampled public seeds, leaf/chain/step/role addresses and bitmasks. Public keys now authenticate `root || public_seed`. See [U-03](U03_WOTS_STEP_KEYS.md). This is a tested implementation correction, not a proof of the whole custom XMSS construction. State persistence/rollback remains open. The bench numbers in this file's older sections are historical; `.bench-out/` is regenerated on the merged revision (v7), and `.bench-u03/` holds the pre-merge record.

# Security claims, assumptions, and gaps

What this implementation claims, what it assumes, what has been checked, and — the
part that decides whether it can carry a paper — what has **not**.

Companion documents: `docs/PROTOCOL.md` (byte-exact wire format), `docs/CAPABILITIES.md` (what
is implemented and verified, what is implemented but unverified, and what is absent — read it
before quoting a byte count or an RFC section), `docs/REDUCTION.md` (the
reduction skeleton for C1–C2, with its gaps listed in its §6),
`docs/STATIC_REVIEW_FIXES.md` (the second review: nine findings, what was verified, what
was fixed, what is still open), `docs/AUDIT_V3_RESPONSE.md` (the third review, of v3: ten
findings, including a wrong transcript prefix in the application and exporter secrets),
`docs/AUDIT_V4_RESPONSE.md` and `docs/AUDIT_V6_RESPONSE.md` (the fourth and fifth),
`docs/AUDIT_V8_RESPONSE.md` (the eighth: the red-team pass, its cost decomposition, and the
staged plan for what is deliberately not enabled),
`docs/AUDIT_SWEEPS.md` (the three inventories that turn the reviewers' reading habits into
tables a reviewer can check; Sweep A is enforced as acceptance check 4b),
`verification/verifpal/README.md` (the models and their exact scope), `rust-prototype/README.md` (the real-stack integration),
`implement-stage/ASSUMPTIONS.md` (every under-determined decision),
`implement-stage/BUILD_NOTE.md` (what was built and what broke).

## The construction

A TLS 1.3 full handshake that keeps the message flow and adds post-quantum material
in exactly two places:

| | classical | post-quantum | combined by |
|---|---|---|---|
| key exchange | X25519 ephemeral share in `key_share` | ML-KEM ephemeral public key in `pq_key_share`, ciphertext in `pq_ciphertext` | `Z_hybrid = uint16(len)‖Z_ecdh‖uint16(len)‖ss_pq` into `HKDF-Extract` as the `handshake_secret` input |
| server authentication | ECDSA P-256 in CertificateVerify | Falcon-512 / ML-DSA / WOTS+-XMSS in the same message | both signatures over one `M_CV`; client accepts iff `ok_T ∧ ok_PQ` |

`M_CV = 0x20×64 ‖ "TLS 1.3, server CertificateVerify" ‖ 0x00 ‖ TH_S`, and `TH_S` covers
ClientHello through Certificate, so both signatures bind the same transcript — which
is what makes each half non-strippable rather than merely redundant.

## Claims

Numbered so they can be attacked individually; each names its evidence and its status.

**C1 — Key secrecy survives compromise of the long-term signing keys.** The handshake and
application traffic secrets stay secret when either or both long-term *signing* keys are
revealed, because neither is an ingredient of the key schedule.
*Evidence*: `verification/verifpal/hybrid_auth*.vp` and the reviewer's ProVerif models —
application-key secrecy is TRUE in the baseline and both single-key models, FALSE only when
both are revealed. *Status*: **symbolically verified (unbounded replication in ProVerif)**.

> **Correction.** This claim previously described compromise of the *key exchange* — "secret
> unless both the ephemeral ECDHE secret and the KEM secret are recovered" — while citing
> models that leak signing keys. An external review caught the mismatch: **no model here
> leaks a key-exchange component at all**, so that claim has no symbolic evidence behind it.
> It is restated above as what the models actually test. The hybrid-KEX
> partial-compromise statement survives in `docs/REDUCTION.md` §1 as a branch table, and it
> is listed as an unverified gap in §"What is not established" item 9 below.

**C2 — Server authentication is a conjunction.** An adversary holding one of the two
long-term signing keys cannot make a client accept a server flight.
*Evidence*: the same model set — `c0a0a0f0a1` for the baseline and for each single-half
compromise, `c1a1a1f0a1` only when both are lost, and the two controls that *do* break
(`classical_only` with the PQ check removed; `kex_only_no_auth` with authentication
removed entirely). *Status*: **symbolic, bounded**; symbolic signatures are unforgeable
without the key by construction, so this establishes the *structure* of the claim, not
the unforgeability of Falcon, ML-DSA, or XMSS.

**C3 — No extra round trip.** The post-quantum material is carried inside messages TLS
1.3 already sends. *Evidence*: `bench/measure_tcp.py` counts the client's blocking
waits from the socket; every measured profile reports `waits_to_authenticated = [1]`.
*Status*: **measured**, on loopback.

**C4 — Transcript binding rejects tampering.** Changing the KEM ciphertext, either
signature, or the CA signature is detected before any application data is exchanged.
*Evidence*: the four-case tamper matrix in `tools/verify_all.ps1` and
`tests/test_handshake.py`. *Status*: **executable tests**, i.e. the *observable
consequence* of the binding, not the binding itself as a theorem.

**C5 — Cost.** The post-quantum additions cost a measurable, decomposable number of
bytes and microseconds. *Evidence*: `.bench-out/handshake.{json,md}` (15 profiles plus
the X.509 sweep), `.bench-out/primitives.{json,md}`, and `.bench-out/shaped.{json,md}`.
With a real X.509 chain the measured baseline is 1402–1405 bytes across runs (the chain is
regenerated per run, so the count is not bit-stable) and the hybrid profile is
4571–8295 bytes, a ratio of 3.26×–5.90× depending on the backend; with the modelled
certificate the same ratios are 5.9×–11.8×, which is why the chain profile is the one to
quote. *Status*: **measured**, with the caveats in §6 and §8.

**C6 — The post-quantum material does not buy a round trip, and on a slow link its
decomposed cost is small next to the round trip itself.** *Evidence*:
`bench/measure_shaped.py` at the KEMTLS conditions (195.6 ms RTT, 10 Mbps). *Status*:
**the total is not reproducible; the decomposition is.** See the correction below.

> **Correction after external review.** This claim previously reported `+8.41 ms` paired
> median, "positive in 7 of 7 rounds". The reviewer measured **+12.92 ms median over seven
> pairs, range −12.58 to +21.88**, and their instrumented AB/BA run gave +10.44 ms median,
> +7.58 ms mean, only **14 of 20 pairs positive**, with the same sign instability. Their
> component measurements do reproduce this work's decomposition — roughly 5.7 ms of server
> compute, 0.7 ms of client compute, and 3.1 ms of serialization for the extra bytes — so
> the decomposition stands while the total and its sign do not.
>
> The defensible claim is therefore: **the post-quantum bytes cost about 3.1 ms of
> serialization on a 10 Mbps link, plus roughly 5–6 ms of server compute that the client
> waits through, and the pair-by-pair total is not distinguishable from scheduling noise.**
> The earlier wording was an overstatement, and it is corrected here rather than in a
> footnote because it is exactly the kind of number a paper would quote.
>
> Two defects in this harness made the overstatement possible: the prediction compared a
> byte count read at the *end* of the run against an interval that ends at *authentication*,
> and the "interleaved" loop ran a fixed hybrid-then-classical order every round. Both are
> fixed (`tls/transport/tcp.py`, `bench/measure_shaped.py`), and `high_resolution_sleep` —
> imported but never called — is now actually applied. **The corrected harness has not been
> re-measured under the reviewer's conditions**, so this claim is left as unverified rather
> than revised optimistically.

## Assumptions

Cryptographic: ML-KEM IND-CCA2; both signature schemes EUF-CMA; HKDF a dual-PRF in its
salt position; SHA-256 collision-resistant; AES-128-GCM an AEAD. None of these is
analysed here — they are inherited, and the paper's argument has to say so.

Protocol: the client's two signature checks are not optional (this is a design
commitment, and the whole of C2 rests on it); the trust anchor reaches the client out
of band; the private ephemeral values are destroyed after the handshake, which is what
makes the forward-secrecy claim meaningful; for XMSS, `next_index` is persisted
atomically, because a replayed index destroys WOTS+ outright.

## What is not established

This is the section that decides whether the work can carry a paper, so it is a list
rather than a caveat.

1. **No computational proof — a skeleton exists, and it says so.** `docs/REDUCTION.md`
   states the two claims, the nine assumptions, and the hops, with the bound on server
   authentication written as `min(Adv_EUF-CMA(classical), Adv_EUF-CMA(PQ))` rather than a
   sum, because a reduction can embed its challenge key in either signature slot. But the
   model is never instantiated, nothing is machine-checked, the transcript hop's
   prefix-freeness step is informal, `ε_sim` is a placeholder, and §6 of that file lists
   nine things that are not proved. KEMTLS and KEMTLS-PDK do prove Match and Multi-Stage
   security in that model; this is not that, and the difference is the work still owed.
2. **No multi-session or replay analysis.** The Verifpal models run at `--sessions 1`;
   the two-session configuration did not finish, nor did Verifpal's own bundled TLS 1.3
   model, on this machine. Every "holds" above means "no attack found within that
   bound".
3. **Downgrade is modelled as a missing check, not as negotiation.** The models show
   what a client without the PQ check is worth; they do not show that a hybrid-capable
   client cannot be negotiated down. The implementation's actual defence is transcript
   binding plus rejection of a `ClientHello` without `pq_key_share`, tested executably
   but not proved.
4. **No key compromise impersonation analysis**, and no forward-secrecy analysis in the
   symbolic models — both need a handshake after the leak, which is the two-session
   structure that timed out.
5. **XMSS statefulness is not modelled at all.** Index reuse is the property that
   actually breaks WOTS+; it has no representation in the symbolic language and is
   covered only by `tests/test_wots_xmss.py`.
6. **Post-quantum chain migration is out of scope.** Two certificate profiles exist.
   The modelled one (default) is a single CA signature over a name and two keys — no
   chain, no validity, no revocation — so its byte counts are **not comparable** to a
   deployment. The X.509 profile (`x509=True`) carries a real root→intermediate→leaf
   chain, validates it for real, and puts the PQ key in a leaf extension; every
   signature in that chain is still classical. **The X.509 profile is the one whose
   absolute numbers may be quoted**, and even then only with the profile stated, since
   the baseline depends on the chain depth.
7. **The real-stack integration covers the key exchange, not the signatures, and measures
   no latency.** In rustls, the hybrid X25519+ML-KEM-768 group is negotiated and the
   handshake completes (the Finished MAC proves both sides derived the same 64-byte hybrid
   secret), and its byte cost matches the harness's independent prediction to within ten
   bytes. But the **signature half is not integrated**: rustls's `SignatureScheme` is a
   closed enum, so a composite CertificateVerify needs a patched rustls or the
   delegated-credentials route. Certificate and handshake-signature verification **are**
   real as of the v3 audit — that audit found them switched off, and the prototype now
   verifies against a generated CA with a negative control in every run (§"After the v3
   audit"). There is no interoperability with a deployed stack, no provider, no fuzzing,
   no concurrency, and no failure paths (alerts, HelloRetryRequest, retransmission).
   Latency is measured over an **emulated** link (§C6), not a real one: the shaper adds
   propagation and serialization delays and models loss as a retransmission timeout, so it
   reproduces loss's latency cost and none of TCP's recovery behaviour. TCP itself is not
   modelled.
8. **No comparison against prior work measured under identical conditions.** The
   numbers in KEMTLS (CCS '20) and Celi et al. (LATINCRYPT 2021) come from a Rustls
   implementation over Linux NetEm and from a Go deployment on a transatlantic link.
   The shaped benchmark deliberately uses **their** link conditions — 31.1 ms and
   195.6 ms RTT at 1000 Mbps and 10 Mbps — so the conditions match even though the
   stacks do not. What still does not match is the implementation: this is a Python
   harness with a minimal certificate profile, not a TLS stack, so its latency carries
   ~8 ms of harness overhead and its CPU numbers are Python-level. **The key-exchange
   byte accounting has been anchored to a real stack**: rustls measures +1184 bytes in
   the ClientHello and +1088 in the ServerHello for ML-KEM-768, against the harness's
   independent prediction of +1194 and +1094 — ten bytes apart, and the ten bytes are
   framing the harness adds and a key-share slot does not.
9. **No model leaks a key-exchange component.** The hybrid-KEX partial-compromise claim in
    `docs/REDUCTION.md` §1 has *no* symbolic evidence: every model here — the six Verifpal
    ones and the reviewer's ProVerif ones — leaks long-term **signing** keys. C1 was
    restated to match what they test, and the KEX branch table remains an unverified claim.
    An external review identified this mismatch, and it is recorded rather than papered over
    because the surrounding prose had implied coverage that does not exist.
10. **No revocation checking, and name constraints are refused rather than enforced.** The
    X.509 profile validates a path — signatures, windows, CA constraints, key usage, path
    length, unknown critical extensions, name — and nothing else. There is no CRL, no OCSP,
    no stapling and no distrust list, so a revoked certificate is accepted
    (`ASSUMPTIONS.md` A-024). A `nameConstraints` extension is not implemented: being
    outside the understood set, a critical one causes rejection, which is fail-closed but
    is not enforcement. A static security review found the missing constraints, and the
    three that could be implemented were; the fourth is listed here because "the X.509
    profile does real chain validation" is true and "full path validation" would not be.
    See `docs/STATIC_REVIEW_FIXES.md` §5.
11. **The certificate validator is hand-written.** It is about five checks in
    `tls/pki.py`, and the trust-anchor bug a static review found in it was exactly the kind
    of mistake a mature path validator does not make. The reviewer's own recommendation
    was to use one (`cryptography`'s PKIX path builder or an OpenSSL binding); that is the
    better long-term answer and it has not been done.
12. **The exporter's final step has no published test vector.** `tests/test_rfc8448_vectors.py`
    reproduces seven RFC 8448 vectors byte for byte, including the **exporter master
    secret**, which pins every primitive the exporter is built from. But RFC 8448 publishes
    no exported keying material, and no ACVP TLS 1.3 exporter vector set was located, so the
    last `HKDF-Expand-Label(..., "exporter", Hash(context), L)` step is checked against an
    independent reimplementation of the RFC expression rather than against a standard
    vector. See `docs/STATIC_REVIEW_FIXES.md` §6.
13. **No vector covers a whole handshake's derivation chain.** The two transcript *stages*
    are pinned by `tests/test_audit_v3_fixes.py`, which builds its own transcript, and the
    primitives are pinned by the RFC 8448 vectors. Nothing drives a complete handshake and
    compares every derived secret against a published trace — which is what the v3 auditor
    asked for and what would have caught the wrong-prefix bug without an auditor.
14. **XMSS index persistence is the caller's duty, and the new lock is in-process only.**
    A v3-audit finding: allocation was a read-then-write race, now fixed by reserving the
    index under a lock before any hashing. What is still missing is a crash- and
    rollback-resistant counter — the same leaf can be spent again if a persisted
    `next_index` is restored to an older value, and nothing here detects that. Leaf reuse
    breaks WOTS+ outright, so this is the most serious remaining item in the stateful
    backend.
15. **The rustls prototype covers the key exchange, not hybrid signatures.** Its
    certificate and handshake-signature verification are now real (the v3 audit found them
    switched off; there is a negative control in every run), but a composite
    CertificateVerify still needs a patched rustls or the delegated-credentials route. See
    `docs/AUDIT_V3_RESPONSE.md` F1.


## Consequences for a paper

With items 1–8 open, the honest paper this implementation can support **today** is a
construction-and-verification paper: the hybrid CertificateVerify profile, its
symbolic verification with controls, and the stateful-hash-signature question that
prior work does not address (KEMTLS moves signatures out of the online path precisely
so that XMSS/LMS become viable; this design puts one back in, and the backend
comparison is where the unexplored ground is).

It cannot yet support: a performance paper with absolute claims (6, 7, 8), or a
security paper claiming a reduction (1, 2, 4).

## After external review

An independent reviewer worked through the package (ProVerif 2.05) and **declined to put
their name on these claims as they stood**. Their outcomes, and what changed here:

* **T1 completed.** Symbolic verification of the hybrid authentication in ProVerif with
  **unbounded replication**, so the bounded-session limitation no longer applies to the
  symbolic layer. The baseline and both single-signing-key models agree with this work's
  verdicts, and both negative controls fire.
* **T2 found the `min` bound false** under partial corruption, with a counterexample.
  `docs/REDUCTION.md` §1 now states a branch table and records the counterexample.
* **T2 found a second gap**: ECDSA malleability means `EUF-CMA` cannot yield byte-level
  flight agreement. §3 H2 now states three ways to close it.
* **T3 partly falsified C6 above.** Their measurement could not reproduce `+8.41 ms` or its
  sign stability.
* **Four repository-level defects** were found and fixed: the shaped-latency prediction
  compared the wrong interval, the "interleaved" loop was not interleaved,
  `high_resolution_sleep` was imported but never called, and the Rust prototype's byte
  self-check produced false negatives in 2 of 10 runs.

**Their recommended description, which this repository adopts**: *unbounded symbolic
verification plus prototype measurement*, not a computational security theorem.

## After a static security review

A second reviewer worked from the source alone — no execution, no environment — and
produced nine findings, one of them critical. Their own conclusion states they did not
modify the code, did not perform a dynamic attack, and that the findings must not be
described as successful exploits; that framing is kept. `docs/STATIC_REVIEW_FIXES.md` is
the full record. In short:

* **Critical — the trust anchor was matched on `subject` + `serial_number`**, so a forged
  root carrying the trusted root's name and serial with the attacker's own key ended the
  chain. Now the full DER encoding is compared, and anything else is verified as a
  signature. **Reproduced executably** as a regression test.
* **High — the default (modelled) certificate path never checked the identity**, so a
  certificate the same CA had issued for another name was accepted. Now compared, on the
  default path, before any key is used.
* **High — `key_fingerprint` returned 12 bytes of the 16-byte traffic key** while claiming
  not to print the key. Now a domain-separated SHA-256 digest, with a test that fails
  against the old behaviour. Every stored artefact was searched: no saved log contains one.
* **Medium — three more**, all fixed: an unbounded TCP frame length, missing chain
  constraints (`keyCertSign`, `pathLenConstraint`, unknown critical extensions), and an
  unconditional `0o777` directory patch in the sandbox helper that now applies only under
  the sandbox environment.
* **Medium — the exporter did not follow RFC 8446 §7.5.** Both endpoints made the same
  mistake, so the peers agreed with each other while disagreeing with the standard. The
  *formula* was fixed here and anchored to seven RFC 8448 vectors that the key schedule
  reproduces byte for byte, including the exporter master secret. **Its input was not**:
  see the correction under "After the v3 audit" — the exporter master secret was being
  taken over the wrong transcript, which those vectors cannot see.
* **One finding was not this repository**: a `strcpy` overflow at `stack.c:15` in a
  `_lab1_setup` teaching tree. There is no C source here at all.

**One independent check of this work's own claim is worth recording as a negative.** The
reviewer's *"更稳妥的是使用成熟的证书路径验证器"* — use a mature path validator — was not
followed. The validator is still hand-written, and gaps 10 and 11 above are the price.

**None of these fixes has been independently reviewed.** They are one party's response to
another party's findings, verified by that same party's tests — which is the arrangement
this document already refuses to accept as review.

## After the v3 audit

A third reviewer audited the revision that answered the static review — the package v3 —
and returned ten findings. Their §6 states, as the previous reviewer did, that everything
came from reading source and that no attack is claimed. `docs/AUDIT_V3_RESPONSE.md` is the
full record. The part that belongs in this document:

* **The application traffic secrets and the exporter were derived over the wrong transcript
  prefix.** `c ap traffic`, `s ap traffic` and `exp master` must cover ClientHello through
  the **server** Finished; the code took all four — including `res master`, which is the one
  that does use the longer prefix — after adding the client's Finished. The auditor rated it
  low-to-medium; **that rating is too low**, and the correction is recorded here because it
  invalidates part of the previous section: against a conformant TLS 1.3 peer the
  application keys and the exporter would be *different secrets*, which no test in this
  repository can observe, since both halves make the same mistake. It is the exporter-context
  bug one level up. Fixed, and both stages are now pinned against a transcript the test
  builds itself.
* **The rustls prototype verified nothing.** Its client installed a certificate verifier
  that accepted any chain and any handshake signature, so every byte-count row it produced
  said nothing about authentication. It now generates a throwaway CA, serves a leaf under
  it, and verifies through rustls's own webpki path — with a second handshake required to
  *fail* against an untrusted CA, printed in the run and enforced by a non-zero exit.
* **Three certificate-validator gaps**: a leaf whose `keyUsage` forbids digital signatures
  was accepted; an intermediate CA's EKU restriction did not bind the chain; and a strict
  scheme-identifier check existed in a function **nothing called**. All three fixed; the
  dead function is deleted rather than left beside the live check.
* **XMSS leaf allocation was a read-then-write race.** Reproduced here: at CPython's default
  GIL switch interval 0 of 6 runs collided, and with `sys.setswitchinterval(1e-6)` **6 of 6
  runs handed all four threads the same leaf** — one WOTS+ leaf signing four messages. The
  defect was masked by the interpreter's scheduling, not by anything the code did. The index
  is now reserved under a lock before any hashing.
* **A size cap is not a deadline** (gap 3 in the previous round's list, now closed), **the
  padded control group accepted the all-zero X25519 shared secret**, **dependencies were
  unpinned and unhashed** (both locks now carry hashes over every file PyPI serves, verified
  by running pip's own checker), and **the directory patch now requires Windows and honours
  an explicit switch**.

**A pattern worth naming, because three reviews have now produced it.** Each round has found
the same *shape* of defect: a check that exists but is not on the live path
(`verify_hybrid_certificate_verify`), a derivation that is right in isolation and wrong in
context (the exporter context, then its input transcript), a constraint that is enforced for
one object and not its neighbour (the issuer's key usage but not the leaf's, the leaf's EKU
but not the CA's). Every one of them was invisible to a test suite that compares this
implementation against itself. That is what the eleven open items above have in common, and
it is the argument for an independent reader rather than another self-check.

Closing 6 and 7 is engineering on this harness (real X.509 chain, measured classical
baseline, network shaping, then a rustls integration — `cargo` and `rustc` are present
on this machine, and rustls is the same stack KEMTLS measured). Closing 1 and 4 is a
different kind of work: a Tamarin or ProVerif model on a machine that can run one, and
a reduction written against the DFGS model.

## After the fifth review (an attack package, round 7)

A fifth reviewer sent a second attack package: 104 cases, ten new findings, and a re-check of
the previous round's 22 items. `docs/AUDIT_V6_RESPONSE.md` is the full disposition. The parts
that belong in this document:

* **The two messages the *server* sends had no extension rules.** The previous round closed the
  ClientHello half (a server must reject what the client did not offer); the client was still
  accepting a ServerHello carrying an extension it never offered, an EncryptedExtensions
  carrying one at all, a `key_share` with two entries, trailing bytes inside `pq_ciphertext`,
  and a non-empty `certificate_request_context`. All fixed, each with a test in
  `tests/test_audit_v6_fixes.py`. This is the "constraint enforced for one object and not its
  structural neighbour" shape again — here the neighbour was the other direction of the
  handshake.
* **A legal chain crashed validation.** The one `basicConstraints` lookup that lacked the
  default its seven neighbours had sat in the `pathLenConstraint` walk, so an end-entity
  certificate that legally omits the extension (`RFC 5280 §4.2.1.9`) plus an intermediate with a
  constraint raised `ExtensionNotFound` out of path validation. Fixed.
* **`AUDIT_V4_RESPONSE.md` had over-claimed this one.** Its V-11…V-16 row said the exception
  boundary was fixed; seven of the eight sites were. The auditor located the surviving site by
  reading that row against the code, which is the most useful thing an over-claim can do, and
  the row now says "seven of the eight" with a pointer to the fix.
* **The XMSS key-exhaustion path left the error contract.** A spent key raised a bare
  `ValueError` out of the server's authenticated flight. The flight is now decorated and the
  signer's refusal is converted at the boundary into a named `server_flight` error carrying the
  cause. (The primitive keeps raising `ValueError` on purpose: that is its documented contract
  and its verifier depends on it.)
* **U-03 is closed by adopting the collaborator's patch**, and one gap *in that patch* is fixed
  here: `keygen_from_seed` validated lengths only, so one string could serve as both the secret
  and the public seed — and the public seed is published inside the public key, which makes the
  reconstruction-and-forge chain the auditor demonstrated possible. Overlapping seeds are now
  refused. See `docs/U03_WOTS_STEP_KEYS.md`.

**A residual limitation is now printed rather than assumed.** Sweep A credits a
variable-receiver call (`signer.verify(...)`) when exactly one class in the tree defines that
name. That keeps the real interfaces from being reported dead, and it also means a call line
that never executes can lift a dead check to `live`. The count and every entry are now printed
in every report (`variable-sole`, `of those: sole-implementation variable calls : 12`), and an
undeclared `getattr`-only reference now fails the sweep instead of being forgiven. Removing the
assumption needs type inference; the trade-off is recorded in `docs/AUDIT_SWEEPS.md`.

**None of these fixes has been independently reviewed.** Same statement as every round before
it: this is one party's response to another party's findings, verified by that same party's
tests.

## After the eighth review (a red-team pass, round 9)

The eighth reviewer added a red-team surface scan next to the protocol cases, and sent an
improvement plan with a staging rule: a non-zero exit is not automatically a security verdict, a
declared boundary is documented rather than "fixed", and a measurement is not a DoS finding.
`docs/AUDIT_V8_RESPONSE.md` is the full disposition; `docs/CAPABILITIES.md` is the matrix the
review asked for. The parts that belong in this document:

* **The live-check sweep was satisfiable again, and is now a limited reachability analysis.**
  A declared dispatch site was validated in the AST but not for reachability: planting it inside
  `if typing.TYPE_CHECKING:` or inside a function nobody calls passed. The sweep now evaluates a
  small constant language (never importing or `eval`ing the tree), builds a limited call graph
  from declared entries and reviewed interface bindings, names nested scopes as
  `Class.method.<locals>.helper`, refuses a declaration whose site is unreachable, applies the
  same rule to every reference syntax, and distinguishes exit 1 (unverified evidence) from exit 2
  (tool failure). What it still cannot see is listed in `docs/AUDIT_SWEEPS.md`; a pass is not a
  runtime reachability proof.
* **Both Finished comparisons use `hmac.compare_digest`**, with the length checked first and its
  own message, on both roles.
* **The demo no longer prints derived secrets.** By default it prints names, algorithms, lengths
  and status; `--fingerprint` adds a labelled, domain-separated hash. The earlier behaviour
  printed the first 12 bytes of every key-schedule value.
* **The sandbox helper's platform check now precedes its switch**, so `DSH_SANDBOX_PYFIX=1`
  cannot widen directory permissions on a non-Windows platform.
* **Dependency locks are verified per package**, and the audit-side fetch helpers now refuse any
  artefact whose digest is not in a trusted lock.

**On "erasure" and forward secrecy (EX-1).** Forward secrecy here is a protocol property: the
ephemeral ECDHE and KEM secrets are not derivable from the long-term keys, *assuming the process
memory is not recovered*. It is **not** a claim that keys are erased: `bytes` is immutable in
CPython, `del` and the garbage collector do not wipe, and a swap file, hibernation image or core
dump may retain a copy. The same wording applies to the stateful XMSS key.

**On the XMSS lifecycle (W1).** `bench/measure_xmss_lifecycle.py` separates whole-tree key
generation from the handshake and measures cold against hot: on this machine h=10 is ~3.0 s cold
and ~7 ms hot over 30 runs, with raw samples in `.bench-lifecycle/`. Hot mode reuses **the
authentication credential only**; transcripts, ephemeral keys, traffic secrets and record
sequences stay per handshake. There is no long-running listener in this repository, so this is a
cost decomposition and not a remote denial-of-service claim, and **no XMSS state is persisted**:
cross-process reuse stays disabled until a monotonic counter source and its crash tests exist
(gap 14).
