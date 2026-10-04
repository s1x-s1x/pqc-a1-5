> **2026-09-21 U-03 follow-up:** this document retains historical analysis and measurements. The fixed constant-chain construction is superseded by the independently seeded/addressed/masked implementation documented in `docs/U03_WOTS_STEP_KEYS.md`. This change is not a completed security reduction; updated test and measurement evidence is in `validation/` and `.bench-u03/`.

# Reduction skeleton — hybrid authentication and key secrecy

**This is a skeleton for a proof, not a proof.** It has been written carefully and
checked against the implementation, but: it has never been machine-checked, it has not
been read by a second reader, and no Tamarin or ProVerif model backs it (this machine can
run neither — see the note at the end). Every step below is a claim someone still has to
verify. §6 lists exactly which ones, and that section is the honest part of this document.

## 1. Statement

Let Π be the handshake in `docs/PROTOCOL.md`: TLS 1.3 with a hybrid key exchange
(`Z_hybrid = Z_ecdh ‖ ss_pq`, of which one half is a KEM) and a dual-signature
CertificateVerify (`accepted = ok_T ∧ ok_PQ`).

**Claim (server authentication).** In the Dowling–Fischlin–Günther–Stebila multi-stage
AKE model, Π provides Match security for server-to-client authentication, with **one bound
per corruption branch**:

| Branch | Bound |
|---|---|
| neither signing key corrupted | `min( Adv_EUF-CMA(classical), Adv_EUF-CMA(PQ) ) + ε_sim` |
| `sk_PQ` corrupted (adversary holds it) | `Adv_EUF-CMA(classical) + ε_sim` |
| `sk_T` corrupted | `Adv_EUF-CMA(PQ) + ε_sim` |

**Claim (key secrecy).** Under the same model, Π provides Multi-Stage security, again
branch-wise over which half of the key exchange the adversary may reveal:

| Branch | Bound |
|---|---|
| neither KEX half revealed | `min( Adv_IND-CCA(KEM), Adv_PRF(ECDH) ) + Adv_dual-PRF + ε_sim` |
| the KEM half revealed | `Adv_PRF(ECDH) + Adv_dual-PRF + ε_sim` |
| the ECDHE half revealed | `Adv_IND-CCA(KEM) + Adv_dual-PRF + ε_sim` |

> ### Correction: the earlier unconditional `min` was wrong
>
> The first version of this document claimed a single unconditional bound
> `Adv_auth(Π) ≤ min(Adv_EUF-CMA(T), Adv_EUF-CMA(PQ)) + ε_sim` for *every* adversary,
> including one that may corrupt either signing key. **An external review showed that is
> false**, with this counterexample: let the classical scheme be completely broken
> (`Adv_T ≈ 1`) and the PQ scheme hard (`Adv_PQ = ε`). An adversary that corrupts `sk_PQ`,
> signs the post-quantum half honestly with the stolen key, and forges only the classical
> half wins with advantage ≈ 1 — while the claimed bound says `min(1, ε) = ε`.
>
> The error is that the two reductions are valid on *different branches*, not on all of
> them: a reduction that embeds its challenge key in `PK_T` cannot also answer a `Corrupt`
> query that reveals `sk_T`. The `min` is correct only in the branch where neither key is
> corrupted, and that is where it is now stated. An adaptive adversary that chooses which
> key to corrupt needs the table above, or a single weighted bound with the losses written
> out — not an unconditional minimum.
>
> The same defect applied to the key-secrecy bound whenever the adversary chooses which key
> exchange component to reveal, and it is corrected the same way.
>
> **The intuitive claim survives; the formula did not.** "An adversary that holds neither
> key must break both" is exactly the no-corruption branch. What was wrong was generalising
> it to an adversary that may hold one.

## 2. Assumptions

| | Assumption | Where it is used |
|---|---|---|
| A1 | ML-KEM-768 is IND-CCA2 (FIPS 203) | §3 H1, §4 H1 |
| A2 | ECDSA P-256 with SHA-256 is EUF-CMA | §3 H2 |
| A3 | The PQ signature scheme (Falcon-512, ML-DSA-44, or WOTS+/XMSS) is EUF-CMA | §3 H2 |
| A4 | HKDF-Extract is a dual-PRF: `HKDF-Extract(salt, ·)` is a PRF when the IKM is uniform, and `HKDF-Extract(·, ikm)` is a PRF when the salt is uniform | §4 H2 |
| A5 | SHA-256 is collision-resistant, and HMAC-SHA-256 is a PRF | §3 H3, §4 H3 |
| A6 | AES-128-GCM is an AEAD with the usual confidentiality and integrity bounds | §3 H3, §4 H3 |
| A7 | The X25519 ephemeral secret is a PRF-grade Diffie–Hellman secret, i.e. the CDH/PRF-ODH assumption TLS 1.3 analyses use for the classical half | §4 H1 |
| **A8** | **For the XMSS backend: no WOTS+ leaf index is ever reused, and `next_index` is persisted atomically** | §3 H2 |
| A9 | The certificate layer binds the identity and both public keys, and the client's trust anchor reaches it out of band | §3 H2 |

**A8 is not a mathematical assumption, it is an operational one.** A WOTS+ leaf reuse lets
an adversary forge outright (that is what breaks the one-time property), so A3 is simply
false for XMSS if A8 fails. No purely cryptographic argument can supply A8; the
implementation's `next_index` discipline is the whole of it, which is why
`tests/test_wots_xmss.py` tests index monotonicity and exhaustion rather than treating
them as details. A reader should treat the XMSS instantiation as conditional on A8 in a way
the Falcon and ML-DSA instantiations are not.

## 3. Authentication — the hops

**H0 (real game).** The adversary controls the network, may corrupt either long-term
signing key through the model's `Corrupt` query, and wins by making a client accept a
server flight the honest server never sent.

**H1 (the transcript decides `M_CV`).** Replace the client's and server's computation of
`M_CV = 0x20×64 ‖ ctx ‖ 0x00 ‖ TH_S` with an oracle that returns the same value for the
same transcript and a different value for a different transcript. Indistinguishable by A5,
because `TH_S` is a SHA-256 digest over the same byte string on both sides and the context
string is a fixed constant.

> *Informal step.* A5 gives collision resistance, not injectivity of the *construction*;
> the argument that two different transcripts cannot yield the same `M_CV` needs the
> prefix-free structure of `M_CV` and the fixed-length digest. That is standard but it is
> not written out here.

**H2 (forging the flight needs one signature, on the right branch).** Suppose a client
accepts a flight in H1 that the honest server did not send. That flight contains
`(sigT, sigPQ)` and the client verified both. Separate the branches, because the reduction
depends on which keys the adversary holds:

* **Neither key corrupted.** Neither signature can be produced by the adversary, and a valid
  one on a fresh `M_CV` cannot be obtained from the signing oracle without a transcript
  collision (H1). So the adversary must forge both, and
  `Pr[break] ≤ min(Adv_EUF-CMA(T), Adv_EUF-CMA(PQ))` because `P(A ∧ B) ≤ min(P(A), P(B))`.
  That is the hybrid property, and it is a statement about this branch only.
* **`sk_PQ` corrupted.** The adversary signs the post-quantum half honestly with the stolen
  key; the binding constraint is the classical forgery, so `Pr[break] ≤ Adv_EUF-CMA(T)`.
* **`sk_T` corrupted.** Symmetrically `Pr[break] ≤ Adv_EUF-CMA(PQ)`.

> ### Correction: EUF-CMA does not give byte-level agreement
>
> The first version of this hop concluded "agreement on the flight" directly from the
> forgery bound. **An external review found a concrete gap**: ECDSA is malleable — a
> verifier accepts `(r, n − s)` for the same message — so a valid signature is not
> necessarily the *bytes* the honest server emitted. `EUF-CMA` therefore cannot yield
> agreement on the flight bytes, only on what was signed.
>
> Three ways to close it, in order of preference: define agreement over the signed
> transcript (`M_CV`) rather than over flight bytes; require *strong* unforgeability
> (SUF-CMA) or canonical encoding from the signature scheme, which ECDSA alone does not
> give; or route the claim through Finished, which binds the complete transcript under a
> key the adversary does not hold in the no-corruption branch, and then argue agreement at
> that layer. **`docs/PROTOCOL.md` says the wire format is length-framed but never
> formalises that framing in a security game**, which is the other half of this hop: what
> actually needs proving is injectivity of the transcript serialisation, not the
> prefix-freeness of `M_CV`.

`ε_sim` covers the model's bookkeeping: how the certificate's two keys are registered, how
`Corrupt` reveals a signing key, and how the flight is assigned to a session identifier.

**H3 (everything after the flight).** Finished is an HMAC under a key derived from the
handshake traffic secret; the client accepts only if it matches. An adversary that did not
compute the server's traffic secret cannot produce it except with probability bounded by
A5's PRF bound plus A6's integrity bound. The transcript binding means a flight replayed
into a different session fails at H1.

**Conclusion.** The bound is the table in §1: `min(Adv_EUF-CMA(T), Adv_EUF-CMA(PQ))` when
neither key is corrupted, and the surviving scheme's advantage when one is. It is *not* an
unconditional minimum, and stating it as one was the first version's error.

## 4. Key secrecy — the hops

**H0 (real game).** The adversary may corrupt either signature key and may reveal
ephemerals via the model's session-state queries, but does not corrupt both halves of the
key exchange for the same session.

**H1 (the hybrid secret is uniform if either half is).** `Z_hybrid` is the length-prefixed
concatenation `Z_ecdh ‖ ss_pq`, and `handshake_secret = HKDF-Extract(Derive-Secret(...),
Z_hybrid)`. Two cases:

* The KEM half remains secret: `ss_pq` is uniform by A1, so by A4's dual-PRF property —
  applied to the IKM — `handshake_secret` is pseudorandom. The ECDHE half, and even its
  public value, is irrelevant.
* The ECDHE half remains secret: `Z_ecdh` is uniform by A7, and the same dual-PRF
  application gives the same conclusion.

The length prefixes matter here and are not cosmetic: the argument treats `Z_hybrid` as a
single IKM string, and the encoding has to be injective for two different pairs never to
collide in `HKDF-Extract`'s input. `tests/test_key_schedule.py` pins that injectivity,
which is the one premise of this hop that is executed rather than argued.

**H2 (the rest of the schedule).** Every later secret is `Derive-Secret` from
`handshake_secret` or `master_secret` under a distinct label with the transcript hash as
context, so a standard hybrid argument over A4 and A5 replaces each with an independent
uniform value. Distinct labels are what keep the client and server directions and the
handshake and application epochs independent.

**H3 (records).** Record confidentiality follows from A6 with keys drawn from the values
H2 made uniform, and the per-direction traffic secrets are the reason a record sealed in
one direction does not open in the other.

**Conclusion.** The branch table in §1, for the same reason as §3: an adversary that may
choose which KEX component to reveal forces a per-branch statement rather than one
minimum.

## 5. What the implementation actually supports, and how

Nothing here is proved by the code, but the code pins the *falsifiable premises* of §3 and
§4, and a reader should treat these as the executable half of this document:

| Premise | Where it is checked |
|---|---|
| `Z_hybrid`'s encoding is injective (§4 H1) | `tests/test_key_schedule.py`: `encode_hybrid_secret(0x0102, 0x03) != encode_hybrid_secret(0x01, 0x0203)` |
| Both halves are needed for the secret (§4 H1) | `verification/verifpal/`: `hybrid_auth_both_leaked.vp` breaks, each single-half model is verdict-identical to the baseline |
| Both signatures are needed (§3 H2) | the tamper matrix in `tools/verify_all.ps1`: a bad classical signature and a bad PQ signature each reject at `certificate_verify` |
| The transcript binds every post-quantum byte (§3 H1) | the same matrix: a corrupted KEM ciphertext rejects at the record layer |
| No downgrade by stripping | `tests/test_messages.py`: a stripped ClientHello decodes, and the hybrid server rejects it; a classical-only server accepts it |
| Both sides derive the same secret | every handshake test asserts equal traffic secrets and a successful Finished |

## 6. What is NOT proved — read this before citing anything above

1. **No model instantiation.** §3 and §4 name the DFGS multi-stage model but do not
   instantiate it: session identifiers, the partner-function definition, the exact
   freshness predicates, and how TLS 1.3's labels enter the state are all left to the
   reader. A real proof has to fix these, and fixing them is where most of the work is.
   **An external review confirmed this and sharpened it**: the `Corrupt(U)` query in the
   KEMTLS paper's model is *party-level* — it returns a party's long-term private key — and
   is not the "corrupt one component of a composite credential" interface that §1's branch
   table now needs. No DFGS instantiation exists for this protocol, and the branch table
   above presumes an interface nobody has defined yet. That is the first thing to build.
2. **No machine check.** No Tamarin or ProVerif model accompanies §3 or §4. The Verifpal
   models in `verification/` are *bounded symbolic* models of the same construction; they
   are evidence about structure, not about these bounds, and §1's `min(...)` expressions
   appear nowhere in them.
3. **No second reader.** The process rules that produced this project forbid substituting a
   same-family pass for independent review. Nothing in this document has been read by
   anyone other than its author.
4. **No tightness analysis.** `ε_sim` is a placeholder. The reductions in H2 are not
   written out, so loss factors — in particular anything arising from how `Corrupt` and the
   session-state queries interact with the two signature keys — are unknown.
5. **The prefix-freeness step in §3 H1 is informal**, and it is the kind of step that
   reviewers of TLS 1.3 proofs have historically found gaps in.
6. **A8 is operational, not cryptographic.** For the XMSS backend, the claim is
   conditional on index discipline in a way Falcon's and ML-DSA's are not, and no
   cryptographic argument can discharge it.
7. **The certificate and PKI layer is assumed away.** §3 H2's reduction embeds verification
   keys; nothing here analyses chain validation, and the implementation's X.509 profile
   exists only to make byte counts comparable.
8. **Forward secrecy is not addressed beyond what §4 gives.** Compromise of a long-term
   signing key after a session ends is outside these hops; `docs/SECURITY.md` C1–C6 record
   what is claimed where.
9. **Downgrade is not a theorem here.** §3 assumes the client's check set; the argument that
   a *negotiation* cannot talk a hybrid-capable client out of the PQ half is not made,
   because the implementation does not negotiate.
10. **The shaped-latency claim in `docs/SECURITY.md` C6 does not survive independent
    reproduction.** An external review measured `+12.92 ms` median over seven pairs
    (range −12.58 to +21.88) against the `+8.41 ms` reported here, and their instrumented
    AB/BA run reproduced the *component* magnitudes (~5.7 ms server compute + 0.7 ms client
    + 3.1 ms serialization) while finding the sign unstable across runs. The honest claim is
    the decomposition, not the total, and `docs/SECURITY.md` C6 has been amended.

## 7. Why there is no machine-checked proof here

This machine cannot run a computational-proof assistant (there is no such thing) and cannot
run the symbolic tools that would at least check the structural claims:

* **Tamarin** needs GHC; there is no Haskell toolchain here, and it publishes no Windows
  binary.
* **ProVerif** publishes no Windows binary, and Docker's daemon is not running while WSL is
  not accessible from this account.
* **Verifpal** does run — it is what `verification/` uses — and it is a *bounded symbolic*
  checker. It found no attack on the construction within its bound and it produced the
  failing controls that give those results meaning, but it says nothing about §1's bounds.

Finishing this document therefore needs two things this environment cannot supply: a
machine with Tamarin or ProVerif for the symbolic layer, and a second reader or a proof
assistant for the computational layer. Until then, the honest citation is
"a reduction skeleton with the gaps listed in §6", not "a proof".

**Handing it over.** `docs/HANDOVER.md` is the brief for whoever does that work: the three
tasks, the acceptance criterion for each, the environment they need, what to send back, and
a list of the things they should not inherit from this author. A Tamarin skeleton —
never parsed, and with the KEM-representation choice deliberately left open — is at
`verification/tamarin/hybrid_tls13.spthy`.

## 8. External review, and what it changed

An independent reviewer (OpenAI Codex, ProVerif 2.05) worked through this document and the
models. Their verdict and the resulting changes:

| Their finding | Severity | What changed here |
|---|---|---|
| The unconditional `min` bound is false under partial corruption, with a counterexample | **critical** | §1 now states a branch table, with the counterexample recorded above it |
| EUF-CMA cannot yield byte-level flight agreement: ECDSA accepts `(r, n−s)` | major | §3 H2 now states three ways to close the gap and names the unformalised transcript serialisation |
| The DFGS `Corrupt` is party-level, so no model instantiation exists here | major | §6 item 1 now says so explicitly |
| The claim that the minimum is governed by the "weaker" scheme is numerically backwards | minor | removed; the minimum is the *smaller advantage*, i.e. the stronger scheme's level |

They also **completed T1** in ProVerif with unbounded replication, so the bounded-session
limitation recorded above is gone for the symbolic layer; and they falsified part of T3 by
showing the shaped-latency result is not stable (§6 item 9 in `docs/SECURITY.md`).

**They declined to put their name on the security claims as they stood.** Their summary:
the result should be described as *unbounded symbolic verification plus prototype
measurement*, not as a computational security theorem, until the branch-wise game is
instantiated and the computational proof is done by an independent cryptographer. That is
the correct description and this document does not claim otherwise.
