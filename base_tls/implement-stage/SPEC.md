# SPEC — hybrid-tls13

**Target.** `hybrid-tls13/` — a runnable implementation of the hybrid TLS 1.3
handshake described in `TLS1.3_混合后量子签名方案_详细讲解_博客版(1).html`: the
classical ECDHE share paired with a post-quantum KEM public key in ClientHello and a
KEM ciphertext in ServerHello, both shared secrets concatenated into the TLS 1.3 key
schedule, and the classical signature paired with a post-quantum signature over the
same CertificateVerify input with the client accepting only when both verify.

**Inputs.** The design note (HTML, Chinese) as the specification of record;
`kemtls.pdf`, `KEMTLS-PDK.pdf`, `Celi2021.pdf` as background, not as instructions.

**Outputs.**

| Path | Schema |
|---|---|
| `tls/**` | importable package; `HybridConnection.run(config) -> HandshakeResult` |
| `demo/run_handshake.py` | CLI; prints per-message byte table, key schedule values, verification outcome; `--tamper` prints the rejecting step |
| `bench/measure_primitives.py` | `.bench-out/primitives.{json,md}` — per-primitive median ms and sizes |
| `bench/measure_handshake.py` | `.bench-out/handshake.{json,md}` — per-profile bytes, PQ deltas, stage latencies |
| `tests/**` | pytest suite, one command, exit code |

**Success command.**
`python demo/run_handshake.py` → exit 0, prints `application data round trip: ok` and
`exporter secrets agree: yes`.

**Base commit.** `none (not a git repo)`.

**Scope cuts.**

- **No wire interoperability.** `pq_key_share` and `pq_ciphertext` are private-use
  extension types; no OpenSSL/BoringSSL provider is built. Interop would require
  binding to a specific draft.
- **PKI migration is out of scope.** The certificate authority is a modelled test CA
  signing a two-key body. Real post-quantum X.509 operation is not attempted.
- **No formal security proof.** The design note's stated properties are implemented
  and their observable consequences are tested by tampering; no reduction is written.
- **Transport is in-process.** Latency excludes network and syscalls by construction.
