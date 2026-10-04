> **2026-09-21 U-03 follow-up / 2026-09-22 fifth review:** this document retains historical analysis and measurements. The fixed constant-chain construction is superseded by the independently seeded/addressed/masked implementation documented in `docs/U03_WOTS_STEP_KEYS.md`; the fifth review's ten findings and their fixes are in `docs/AUDIT_V6_RESPONSE.md`. `.bench-out/` was regenerated on the merged revision, so it is the current data; `validation/` and `.bench-u03/` are the patch author's own records. Neither change is a completed security reduction.

# Handover: independent verification of the hybrid TLS 1.3 claims

You are being asked to do the part that could not be done on the machine this project was
built on. This document is the whole brief: what to read, what to run, what counts as done,
and what **not** to inherit from the author.

## 1. The ask, in one paragraph

`hybrid-tls13` implements a TLS 1.3 profile whose key exchange is hybrid (X25519 + ML-KEM-768
into one HKDF input) and whose server authentication is hybrid (a classical *and* a
post-quantum signature over one CertificateVerify input, both required). Two security claims
are made about it — server authentication and key secrecy, each with a `min(...)` bound over
the two halves — and **neither has been proved on a machine**. `docs/REDUCTION.md` is a
skeleton with nine listed gaps. Your job is to close them or to break them: produce the
machine-checked (or at least independently reasoned) verification, and report any claim that
does not survive.

## 2. Read these first, in this order

| # | File | What it gives you | ~time |
|---|---|---|---|
| 1 | `docs/PROTOCOL.md` | the exact construction, byte level | 20 min |
| 2 | `docs/SECURITY.md` | claims C1–C6, the assumptions, and the 8 things **not** established | 20 min |
| 3 | `docs/REDUCTION.md` | the two claims, 9 assumptions, the hops — and §6, the 9 gaps | 30 min |
| 4 | `verification/verifpal/README.md` | what the existing symbolic models do and do not cover | 15 min |
| 5 | `verification/verifpal/*.vp` | the six models; each is ~100 lines | 30 min |

Do not skip 3's §6 — it is the list of what you are being asked to fix, written by the
author, and it is more useful to you than any summary in this file.

## 3. Three tasks, each with an acceptance criterion

### T1 — Symbolic verification of the hybrid authentication

**What exists.** Six Verifpal models at `--sessions 1`, whose verdict codes are pinned in
`tools/verify_all.ps1`. The result they establish: losing either signing key leaves the
verdict set identical to the uncompromised baseline (`c0a0a0f0a1`), and only losing both
(`c1a1a1f0a1`) or dropping the PQ check (`c1a1f0a1`) changes it. Two controls exist and fail
as designed.

**What is missing.** The models are bounded and symbolic, and `--sessions 2` did not finish
here, so **replay across concurrent sessions is not covered at all**. Downgrade is modelled
as "the check is absent", not as a negotiation that is attempted and refused.

**Acceptance criterion.**

* Tamarin or ProVerif models that cover at least: injective agreement on the server flight,
  agreement on the client's post-acceptance message, secrecy of the application traffic
  secret, and — the point of the whole exercise — **that neither single-key compromise
  suffices**.
* The concurrency bound is stated explicitly, and raised until verdicts stop moving.
* Every "verified" comes with the tool's own output, and every counterexample comes with the
  trace.
* If the construction survives, say so plainly; a clean result is a result.

**Start from** `verification/tamarin/hybrid_tls13.spthy` in this repository. **Read its
header before trusting it**: it has never been parsed by Tamarin, and it flags one modelling
choice (how a KEM is represented) that you must make deliberately rather than inherit.

### T2 — The computational reduction

**What exists.** `docs/REDUCTION.md`: two claim statements, nine assumptions, hops for each,
and the bound written as `min(Adv_EUF-CMA(classical), Adv_EUF-CMA(PQ))` rather than a sum.

**What is missing.** Everything in §6 of that file, of which the load-bearing ones are: the
model is never instantiated (session identifiers, partner function, freshness predicates are
all hand-waved), the transcript hop's prefix-freeness step is informal, `ε_sim` is a
placeholder, and no tightness analysis exists.

**Acceptance criterion.** Either a completed reduction against a named model (the
Dowling–Fischlin–Günther–Stebila multi-stage model is what the KEMTLS line uses and is the
natural target), or a precise statement of which hop does not close and why. **A list of
places the proof fails is a successful outcome of this task**, not a failure of it.

**Attack the bound first.** If the `min(...)` is wrong — if the two reductions cannot both
be run against the same adversary because the model's `Corrupt` query interacts with the
signature keys in a way that forces a hybrid argument — that is the most valuable single
finding available here.

### T3 — Reproduce the measurements, and try to break them

**What exists.** Byte counts (real X.509 chain: baseline 1402–1405 B across runs, hybrid
4571–8295 B), and an independent anchor: rustls measures +1184 and +1088 bytes for the
ML-KEM-768 shares against the harness's prediction of +1194 and +1094.

> **Correction, after this task was run.** This section used to state the latency result as
> fact: "post-quantum cost +8.41 ms paired median, positive in 7 of 7 rounds" under an
> emulated 195.6 ms / 10 Mbps link. **The reviewer could not reproduce it** — their seven
> pairs gave +12.92 ms median with a range crossing zero, and only 14 of 20 instrumented
> pairs positive. The decomposition reproduces (≈3.1 ms serialization, ≈5.7 ms server
> compute, ≈0.7 ms client); the total does not, and the project no longer claims it. See
> `docs/SECURITY.md` C6. The claim is left visible here rather than deleted so that the
> handover record shows what was asked and what came back.

**Acceptance criterion.**

* `python -m pytest tests -q` → **211 passed** with the Falcon provider installed, or
  **209 passed, 1 skipped** without it, on your machine, from your checkout.
* `powershell -File tools\verify_all.ps1` (Windows) → 32 checks pass; on Linux, run its parts
  directly — the pytest suite, both benchmarks, and the Verifpal models.
* **Attempt at least one falsification.** The author's own guess at what is weakest: the
  shaped-latency harness overhead (~8–23 ms) is of the same order as the effect being
  measured. If you can show the effect is really harness noise, that changes what the paper
  may claim. *(That guess was correct: it is what the reviewer's own numbers showed.)*

## 4. Environment

**The repository is self-contained.** Python dependencies install inside the project by
design (`.deps/`, `.deps-falcon/`), because the build machine's sandbox denies writes
outside the workspace. On your machine:

```bash
pip install cryptography pqcrypto pytest          # pqcrypto 1.0.0 has ML-KEM but NOT Falcon
python -m pytest tests -q
```

Two environment quirks of the original machine that you should **not** reproduce blindly:

* `tools/sandbox_pyfix/sitecustomize.py` patches `os.mkdir` because the DSH sandbox's
  capability SID cannot traverse directories created with mode `0o700`. On a normal machine
  it is inert; you do not need it.
* The Verifpal binary in `.tools/` is a **windows-amd64** build. Download the Linux or macOS
  build from <https://github.com/symbolicsoft/verifpal/releases> (v1.4.12), or use the
  package from the same release page.

Tooling you will need that this machine did **not** have: a Haskell toolchain (Tamarin), or
OCaml/opam (ProVerif), or any Docker/WSL setup that can run either. Nothing else in the
project requires them.

## 5. What to send back

One file, or a short thread, containing:

1. **T1**: the model files, the tool versions, the raw verdict output, and any attack traces.
2. **T2**: either the completed reduction or the precise list of hops that do not close.
3. **T3**: the test summary line, the benchmark outputs, and whatever falsification you
   attempted with its result — *including a null result*.
4. **A list of things in this repository that you believe are wrong.** Corrections to the
   claims, the models, the measurements, or the ledger are all in scope and all welcome.

## 6. Please do not

* **Trust any summary in this repository over the artifact it describes.** The author wrote
  both. `docs/REDUCTION.md` says this about itself; it applies to every other document too.
* **Treat the Verifpal results as evidence for the bounds in `docs/REDUCTION.md`.** They are
  not: one is a bounded symbolic search, the other is a claim about advantages. The
  `min(...)` expressions appear nowhere in the models.
* **Treat `docs/REDUCTION.md` as a proof.** It is a skeleton whose author listed nine reasons
  it is not one. If you cite it in a paper before finishing T2, cite the gaps with it.
* **Assume the measurements are clean because they are reproducible.** They are reproducible
  and their methodology is documented, but the harness overhead is close to the effect size,
  and that is a real limitation rather than a presentation detail.
