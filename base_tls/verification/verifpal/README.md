# Symbolic verification of the hybrid authentication

Model set, results, and — more importantly — the exact scope of what these results do
and do not establish.

## Tooling

[Verifpal](https://verifpal.com) 1.4.12, the official Windows build, installed into
`.tools/verifpal/` (not committed; `tools/install_verifpal.ps1` fetches it). Verifpal
is a symbolic protocol verifier: it searches for a Dolev-Yao adversary that breaks a
stated query, and reports the minimized trace when it finds one.

Analysis is **bounded and incomplete**: every principal runs as many concurrent
sessions as `--sessions` asks for (default 2), and a query that holds means *no
attack was found within that bound*, never that none exists. The tool is sound in the
other direction — every attack it prints is real.

All models here were run at `--sessions 1`. Two handshakes in one file at
`--sessions 2` did not finish inside ten minutes on this machine, and neither did
Verifpal's own bundled `transport-layer/tls13.vp`, so this is a limit of the search,
not of the model. **Replay across concurrent sessions is therefore not covered**;
that is the first thing to raise here if a machine with more headroom is available
(`--saturate` exists for exactly that).

## The models

`generate_models.py` emits all five from one template, so the wire format is
byte-identical across them and the only differences are the client's check set and
which keys the adversary holds. Each model is one handshake:

```
ClientHello            gx, ekPQ                    (ECDHE share + ephemeral KEM public key)
ServerHello + flight   gy, ct, sigT, sigPQ         (KEM ciphertext + both signatures)
Client                 c                           (sent only after every check passed)
```

Both signatures cover one input, `mcv = CONCAT(ctx, HASH(gx, ekPQ, gy, ct, serverCert))`,
which is the modelled form of `M_CV = 0x20×64 ‖ context ‖ 0x00 ‖ TH_S`.

| Model | Client's checks | Adversary holds |
|---|---|---|
| `hybrid_auth.vp` | cert, **sigT and sigPQ** | nothing |
| `hybrid_auth_classical_leaked.vp` | cert, **sigT and sigPQ** | `skT` |
| `hybrid_auth_pq_leaked.vp` | cert, **sigT and sigPQ** | `skPQ` |
| `hybrid_auth_both_leaked.vp` | cert, **sigT and sigPQ** | `skT`, `skPQ` |
| `hybrid_auth_classical_only.vp` | cert, **sigT only** | `skT` |

The compromise is declared **before** the handshake. A leak declared after it could
not affect a signature that was already made and every query would hold vacuously.

## Results

`verifpal verify <model>.vp --sessions 1 --result-code`. One letter and one digit per
query, in the order the queries appear: `c` confidentiality, `a` authentication,
`f` freshness; `0` holds, `1` broken.

Query order is: `c` = `m1` secrecy restricted to runs where the client sent it ·
`a` = agreement on `sigT` · `a` = agreement on `sigPQ` · `f` = per-session key ·
`a` = agreement on the client's message (the deliberate non-claim, see below).

| Model | Code | Reading |
|---|---|---|
| `hybrid_auth` | `c0a0a0f0a1` | baseline: secrecy, both signature agreements, and freshness hold |
| `hybrid_auth_classical_leaked` | `c0a0a0f0a1` | **identical to the baseline** |
| `hybrid_auth_pq_leaked` | `c0a0a0f0a1` | **identical to the baseline** |
| `hybrid_auth_both_leaked` | `c1a1a1f0a1` | control: every claim breaks |
| `hybrid_auth_classical_only` | `c1a1f0a1` | downgrade control: secrecy and classical agreement break |

Full logs are in `results/<model>.txt`, each ending with its compact code.

### The control that shows why authentication is the whole point

`kex_only_no_auth.vp` is the same hybrid key exchange with **both signature checks
removed** and no compromise at all. It reports `c1f0`: the client's message is no
longer secret, with no key leaked. The trace is short and worth reading — an active
adversary substitutes `PUBKEY(nil)` for both client shares, encapsulates to the key
it just chose, derives the same hybrid secret the server derives, and reads the
record. Hybridising the key exchange buys nothing on its own: it is the dual
signature that makes the key exchange *authenticated*, and therefore the secrecy
real.

**The result that matters is the comparison, not any single run.** Losing either half
of the authentication produces a verdict set indistinguishable from losing nothing;
only losing both, or dropping the post-quantum check, changes a verdict. The two
controls are what make that readable: a query that cannot fail establishes nothing,
and here it demonstrably can.

### Why the controls fail

`hybrid_auth_both_leaked` and `hybrid_auth_classical_only` both fall to the same
mechanism, and it is worth stating plainly because it is the attack the design exists
to stop: with the classical signing key in hand the adversary answers the
CertificateVerify half, and the client proceeds. In `classical_only` the
post-quantum signature is still on the wire — the message is byte-identical — it is
simply never checked, which is exactly what a client accepting `ok_T || ok_PQ`, or
skipping the PQ check for compatibility, would be running.

### The last query fails by design

`authentication? Client -> Server: c1` fails in **every** model, including the
baseline, and that is correct: this design authenticates the server to the client and
not the client to the server, matching the design note's scope. An adversary that
completes an unauthenticated key exchange (the trace shows it substituting
`PUBKEY(nil)` for both client shares, deriving the same hybrid secret, and sending its
own record) may talk to the server. It cannot learn the client's message, which is
why `c` still holds. The query is kept in the models so the non-claim is visible
rather than assumed.

## What these results do not establish

- **Nothing computational.** Symbolic signatures are unforgeable without the key by
  construction; the models say nothing about Falcon, ML-DSA, XMSS, or ML-KEM beyond
  "the protocol uses them in these positions". A computational proof needs a
  reduction, and this is not one.
- **No multi-session or replay analysis**, for the reason in Tooling.
- **Downgrade is modelled as "the check is absent", not as negotiation.** The models
  do not model cipher-suite or extension negotiation, so they do not show that a
  hybrid-capable client cannot be *talked into* the classical-only path. What they
  show is what that path would cost if it existed. The implementation's actual
  downgrade defence is the transcript binding plus `SILENT` rejection of a
  `ClientHello` without `pq_key_share`, which is tested executably in
  `tests/test_messages.py`, not here.
- **XMSS statefulness is not modelled.** Index reuse, the property that actually
  breaks WOTS+, has no representation in this language; it is covered by
  `tests/test_wots_xmss.py`.
- **Key compromise impersonation is not tested.** It needs a handshake run *after* a
  leak, which is the two-session structure that timed out.
- **The certificate model is a single signature over a name and two keys.** There is
  no chain, no validity period, no revocation.

## Reproducing

```powershell
powershell -File tools\install_verifpal.ps1          # fetches Verifpal into .tools/
python verification\verifpal\generate_models.py      # rewrites the five models
.tools\verifpal\verifpal.exe verify verification\verifpal\hybrid_auth*.vp --sessions 1 --result-code
```

Edit `generate_models.py`, never the `.vp` files: they are generated.
