# Capabilities: what this prototype implements, what is verified, and what is absent

Written for v9, because the eighth review asked for the three states to be in one place instead
of spread across `PROTOCOL.md`, `SECURITY.md` and the response documents. Read this before
quoting any byte count or RFC section number.

Three states, and the difference matters when a paper is written:

* **implemented and verified here** -- there is a test or an acceptance check in this
  repository, and the check is on the path a handshake takes (Sweep A enforces the second half);
* **implemented, not independently verified** -- the code exists and runs; no party outside this
  repository has checked it;
* **absent** -- not implemented at all, and nothing here should be read as if it were.

## Protocol surface

| Area | State | Evidence / reason |
|---|---|---|
| TLS 1.3 handshake shape (ClientHello, ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished) | implemented and verified | `tests/test_handshake.py`, `tests/test_messages.py`, `tools/verify_all.ps1` profile runs |
| Hybrid key exchange: X25519 + ML-KEM-768 into one `HKDF-Extract` input | implemented and verified | `tests/test_key_schedule.py`, RFC 8448 vectors, the rustls prototype's byte delta |
| Hybrid authentication: classical **and** post-quantum signature over one `CertificateVerify` input, both required | implemented and verified | `tests/test_handshake.py`, the `pq-signature`/`classic-signature` tamper cases |
| Key schedule per RFC 8446 §7.1, including the two transcript stages | implemented and verified | `tests/test_audit_v3_fixes.py`, `tests/test_rfc8448_vectors.py` |
| Record layer: AES-GCM, sequence-bound nonce | implemented and verified | `tests/test_wire.py`, `tests/test_key_schedule.py` |
| AEAD usage limit (`2**24.5` records, RFC 8446 §5.5) | implemented and verified | `tests/test_protocol_checks.py` |
| Negotiation-field validation (both directions) | implemented and verified | `tests/test_protocol_checks.py`, `tests/test_audit_v6_fixes.py` |
| Server-message extension rules (§4.1.3, §4.3.1) | implemented and verified | `tests/test_audit_v6_fixes.py` |
| X.509 profile: root → intermediate → leaf, path validation, PQ key in a leaf extension | implemented and verified | `tests/test_x509.py`, `tests/test_security_fixes.py`, `tools/check_x509.py` in acceptance 5b |
| **`key_share` with exactly one classical entry** | implemented and verified | `ClientHello.decode` refuses a second entry *by profile*: this is a **capability limit**, not a framing rule. RFC 8446 §4.2.8 makes `key_share` a vector, so a legal multi-share ClientHello is refused with a message that says so (`tests/test_audit_v8_fixes.py::test_a_legal_multi_share_client_hello_is_refused_by_profile_not_by_framing`) |
| **HelloRetryRequest** | absent | No HRR path exists, so a client that offers no group the server supports cannot be converged. This is why the single-share limit bites: without HRR, refusing a multi-share offer is the honest answer |
| **PSK, session resumption, 0-RTT** | absent | The `res master` secret is derived (RFC 8446 §7.1) but no PSK is ever offered or accepted |
| **Alerts, `close_notify`** | absent | Rejections are Python exceptions that terminate the driver; nothing is sent on the wire |
| **KeyUpdate** | absent | No post-handshake messages |
| **Record-layer framing (§5.2)** | deviates | The harness produces no record header, and the AAD's first byte is the real content type where RFC 8446 fixes it to `application_data`. Documented in `PROTOCOL.md` §8 and `SECURITY.md`; unobservable from outside this harness because no header is produced. The v4 review recorded it as D5 and this repository keeps it as a stated deviation |
| **Private codepoints** | by design | Extensions `0xFE01`, `0xFE02`, `0xFE00 + height` and the PQ-key certificate extension OID are private-use; no other stack can interoperate. See `PROTOCOL.md` §"Codepoints" |
| **Revocation (CRL/OCSP/stapling/distrust lists)** | absent | `SECURITY.md` gap 10; a revoked certificate is accepted |
| **`nameConstraints`** | refused, not enforced | A critical one causes rejection (fail-closed); the semantics are not implemented |
| **Concurrent connections, retransmission, fuzzing** | absent | The loopback driver runs one handshake at a time; nothing models loss beyond the shaper's timeout |

## Key management and state

| Area | State | Evidence / reason |
|---|---|---|
| XMSS leaf allocation: reserved under a lock before hashing | implemented and verified | `tests/test_wots_xmss.py`, `tests/test_u03_wots_context.py` |
| **XMSS index persistence across processes, and rollback resistance** | absent | The lock is in-process only; restoring an older `next_index` reuses a leaf and WOTS+ leaf reuse weakens the scheme badly. `SECURITY.md` gap 14, and the improvement plan's stage-2 gate: **no persistence may be enabled or claimed until the state tests exist** |
| Authentication-key reuse across connections (hot mode) | implemented and verified | `HybridConnection.run` accepts pre-built credentials; each connection still builds its own `HybridServer`/transcript/ECDHE/KEM ephemeral keys/traffic secrets/record sequences (`tests/test_audit_v8_fixes.py` and `bench/measure_xmss_lifecycle.py`) |
| Forward secrecy | implemented, with a limit on the word "erased" | Ephemeral ECDHE and KEM secrets are dropped when the handshake object goes away, but CPython offers no secure-erasure guarantee: `bytes` is immutable, `del` and the garbage collector are not wiping, and a swap file or core dump may retain a copy. Say "forward secrecy under the protocol's assumption that the process memory is not recovered", not "keys are erased" |
| Key rotation after XMSS exhaustion | implemented by refusing | A spent tree raises a named refusal; the caller must issue a new key and certificate. Nothing rotates automatically |

## Verification state of the verification

| Component | State |
|---|---|
| pytest suite | 393 tests, run in this repository on every change |
| `tools/verify_all.ps1` acceptance | 32 checks, including the live-check sweep as 4b |
| Verifpal models (6) | run here at `--sessions 1`; no independent re-run since |
| ProVerif model (external reviewer) | ran once, unbounded replication, verdicts recorded in `SECURITY.md` |
| rustls prototype | built and run here; covers the **key exchange only** |
| Tamarin skeleton | never parsed |
| Sweep B (derived-value inputs) / Sweep C (constraint scope) | specified, **not written** |
| Independent review of v7/v8/v9 fixes | **none** |

## What a paper may say today

* the construction, its symbolic verification at the stated bounds, and the prototype's
  measurements -- with the profile named, because the modelled certificate is not a deployment;
* that the hybrid authentication requires both signatures over one input, and that the transcript
  binds every post-quantum byte;
* that the WOTS+/XMSS backend is a *research* construction: its chain function now follows
  RFC 8391's `PRF(SEED, ADRS)` shape with a fresh public seed, while the Merkle hashes, the
  message digest and the encodings remain this prototype's own. **Not** "RFC 8391 compliant";
* that the stateful-signature question (what a one-time signature costs on the online path) is
  where this work's unexplored ground is.

## What it may not say

* that the implementation is RFC 8446 interoperable (private codepoints, no HRR/PSK/0-RTT/alerts,
  single-share `key_share`, no record header);
* that it has a computational security proof (`REDUCTION.md` §6 lists what is not proved);
* that keys are erased, or that memory forensics is out of scope by design;
* that XMSS state is safe across restarts -- it is not managed at all;
* any absolute handshake-size or latency claim without naming the profile and saying that the
  modelled certificate is a research shape, not a deployment one.
