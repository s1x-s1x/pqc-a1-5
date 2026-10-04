# Wire protocol specification

Byte-exact description of what `hybrid-tls13` puts on the wire, as implemented.

Every layout and size below was read off a real handshake with `python tools/dump_wire.py`
(default profile: X25519, ML-KEM-768, Falcon-512, ECDSA P-256/SHA-256, AES-128-GCM/SHA-256),
so the document can be re-verified rather than trusted. Where a value is a private-use code
point, it is marked as such: **this is not interoperable with a deployed TLS stack**, and
`docs/SECURITY.md` §6–7 says why.

Notation follows RFC 8446 §3: `uint8`, `uint16`, `uint24`, `opaque<lo..hi>` for
length-prefixed vectors (`vec8`/`vec16`/`vec24` below), and `Handshake { type, length, body }`
framing with a one-byte type and a three-byte length.

## 1. Handshake framing

Every handshake message is `type:uint8 ‖ length:uint24 ‖ body`, and that whole frame — not
just the body — enters the transcript hash. Verified on ClientHello: frame 1306 bytes =
`01 00 05 16` + 1302 body, with `0x000516 = 1302`.

| type | message | source |
|---|---|---|
| 1 | ClientHello | RFC 8446 |
| 2 | ServerHello | RFC 8446 |
| 8 | EncryptedExtensions | RFC 8446 |
| 11 | Certificate | RFC 8446 |
| 15 | CertificateVerify | RFC 8446 |
| 20 | Finished | RFC 8446 |

## 2. Extensions

`Extension = uint16 type ‖ vec16 data`; a message's extensions are `vec16` of those.

| type | name | in | data |
|---|---|---|---|
| 10 | `supported_groups` | ClientHello | `vec16` of `uint16` group |
| 13 | `signature_algorithms` | ClientHello | `vec16` of `uint16` scheme |
| 43 | `supported_versions` | both | `vec8` of `uint16`; `0x0304` |
| 51 | `key_share` | both | client: `vec16` of `KeyShareEntry`; server: one `KeyShareEntry` |
| **0xFE01** | **`pq_key_share`** *(private use)* | ClientHello | `uint16 kem_scheme ‖ vec16 qpk` |
| **0xFE02** | **`pq_ciphertext`** *(private use)* | ServerHello | `vec16 ct` |

`KeyShareEntry = uint16 group ‖ vec16 key_exchange`. Named groups: `x25519 = 0x001D`,
`secp256r1 = 0x0017`.

Private-use scheme identifiers, so that a client and server which selected different
algorithms fail on the first flight rather than deriving different secrets silently:

| slot | identifier | value |
|---|---|---|
| KEM | `ml-kem-512/768/1024` | `0x0A01` / `0x0A02` / `0x0A03` |
| KEM | `hqc-128/192/256` | `0x0A11` / `0x0A12` / `0x0A13` |
| KEM | `ecdh-kem-placeholder` *(not post-quantum)* | `0x0AFF` |
| classical signature | `ecdsa-p256-sha256` / `ed25519` | `0x0403` / `0x0807` (IANA values) |
| PQ signature | `ml-dsa-44/65/87` | `0x0904` / `0x0905` / `0x0906` |
| PQ signature | `falcon-512/1024`, padded variants | `0x0F51` / `0x0F52` / `0x0F53` / `0x0F54` |
| PQ signature | `xmss-sha256-hH-wW` (U-03 v2) | `0xFE00 + H` |

## 3. ClientHello (type 1)

```
uint16 legacy_version = 0x0303
opaque random[32]
vec8   legacy_session_id            (empty in this profile)
vec16  cipher_suites                (one: 0x1301 for AES-128-GCM/SHA-256)
vec8   legacy_compression_methods   (one: 0x00)
vec16  extensions                   (supported_versions, supported_groups,
                                     signature_algorithms, key_share, pq_key_share)
```

Observed layout for the default profile, body 1302 bytes:

| offset | bytes | field |
|---|---|---|
| 0 | 2 | `legacy_version` = `03 03` |
| 2 | 32 | `random` |
| 34 | 1 | `legacy_session_id` length = `00` |
| 35 | 3 | `cipher_suites` length `00 02` + `13 01` |
| 38 | 2 | `legacy_compression_methods` = `01 00` |
| 40 | 2 | extensions length |
| 42 | — | the five extensions |

The only field a classical-only ClientHello would not carry is the `pq_key_share`
extension: `4 + 2 + 2 + |qpk|` bytes, i.e. **1192 bytes** for ML-KEM-768.

**`key_share` in this profile holds exactly one entry.** RFC 8446 §4.2.8 makes the extension a
vector, so a client may legally offer one share per group; this profile refuses a second entry,
and the refusal says so ("this profile accepts exactly one classical share and implements no
HelloRetryRequest") rather than reporting a framing error. The two limits are not the same
thing: several shares are legal and only *this profile* rejects them, while HelloRetryRequest is
simply absent, so a client offering no usable group cannot be converged. A legal multi-share
ClientHello therefore fails here, and that is a capability limit, not a wire-format rule —
`docs/CAPABILITIES.md` lists it with the rest of the protocol surface.

## 4. ServerHello (type 2)

```
uint16 legacy_version = 0x0303
opaque random[32]
vec8   legacy_session_id            (echoed from the ClientHello)
uint16 cipher_suite
vec8   legacy_compression_methods
vec16  extensions                   (supported_versions, key_share, pq_ciphertext)
```

Body 1181 bytes for the default profile. The classical-only field is
`pq_ciphertext`: `4 + 2 + |ct|` = **1094 bytes** for ML-KEM-768.

## 5. Certificate (type 11)

Two certificate shapes exist, chosen by `HybridTLSConfig.x509`, and both use message
type 11. A peer that receives the shape its profile does not expect fails at decode
rather than being silently accepted. A client and server must agree on the shape out of
band; there is no negotiation.

### 5a. Modelled certificate (`x509=False`, the default)

```
vec8   certificate_request_context  (empty)
vec24  certificate_list             (exactly one entry here)
       CertificateEntry:
         vec24 cert_data
         vec16 extensions            (empty)
```

`cert_data` encodes a self-delimiting certified body followed by the CA signature:

```
vec16  certified_body
vec16  ca_signature
```

The length prefix around `certified_body` is load-bearing: the post-quantum key is
optional (absent in the classical-only profile) and sits *before* the CA signature, so
without it a decoder could not tell an absent key from the start of the signature. A
real certificate is a self-delimiting blob for the same reason.

The certified body is **not X.509**:

```
vec16  server_identity
uint16 classical_scheme
vec16  classical_public_key
[ uint16 pq_scheme ‖ vec16 pq_public_key ]      present only in the hybrid profile
```

The CA signs `CA_name ‖ certified_body` with the classical signature scheme.

Observed: body 1067 bytes; entry `00 04 22` = 1058; the certified body begins `00 0e`
then `server.example`. The model is deliberate: no chain, no validity period, no
revocation, and therefore **no absolute byte count from this profile is comparable to a
deployed handshake**. The classical-only field is `2 + 2 + |PK_PQ|` plus the two-byte
body prefix — measured at **902 bytes** for Falcon-512.

### 5b. Real X.509 chain (`x509=True`, the comparable profile)

```
vec8   certificate_request_context  (empty)
vec24  certificate_list             (leaf first, then issuers)
       CertificateEntry:
         vec24 DER certificate
         vec16 extensions            (empty; entry extensions are not used)
```

The chain is root CA → intermediate CA → leaf, all ECDSA P-256, built by `tls/pki.py`;
the client receives the leaf and the intermediate and already trusts the root. The leaf
carries `serverAuth`, a SAN for the server name, and the post-quantum public key in a
private-extension OID:

```
OID 1.3.6.1.4.1.99999.1  →  uint16 pq_scheme ‖ vec16 pq_public_key
```

Validation is real: signatures up the chain, validity windows, `basicConstraints` on
every issuer, `extendedKeyUsage`, and the expected name against the SAN. Observed sizes
for the default profile: leaf 1525 bytes (897 of them the PQ key plus DER wrapping),
intermediate 444, so the Certificate message is 1860 bytes plaintext; the classical-only
leaf is 940 bytes in a 940-byte message. Post-quantum *chain* migration is still out of
scope — every signature in the chain is classical.

## 6. CertificateVerify (type 15)

```
uint16 classic_scheme
vec16  classic_signature
uint16 pq_scheme
vec16  pq_signature
```

Both signatures cover the *same* input, built exactly as RFC 8446 §4.4.3 requires:

```
M_CV = 0x20 × 64  ‖  "TLS 1.3, server CertificateVerify"  ‖  0x00  ‖  TH_S
```

where `TH_S = Hash(ClientHello ‖ ServerHello ‖ EncryptedExtensions ‖ Certificate)`.
The context string differs by role (`TLS 1.3, client CertificateVerify`), so a signature
made in one role cannot be replayed in the other; the client role is defined but unused,
since this profile authenticates the server only.

Observed body 730 bytes for the default profile, beginning:

```
04 03 | 00 47 | 30 45 02 20 …   classic_scheme = 0x0403, signature length 71, DER
0f 51 | 02 8c | 46 41 …          pq_scheme = 0x0F51, signature length 652, Falcon
```

The classical-only field is `2 + 2 + |sig_PQ|` = **661 bytes** for Falcon-512. Falcon
signatures are variable-length within an encoding maximum, so this is measured per
handshake, not fixed.

## 7. Key schedule

Standard TLS 1.3 (RFC 8446 §7.1) with one substitution: the value fed to the
`HKDF-Extract` that produces `handshake_secret` is the hybrid input rather than a single
ECDHE secret.

```
Z_hybrid       = uint16 |Z_ecdh| ‖ Z_ecdh ‖ uint16 |ss_pq| ‖ ss_pq
early_secret   = HKDF-Extract(0, PSK)                        PSK = 0 for a full handshake
derived_early  = Derive-Secret(early_secret, "derived", Hash(""))
handshake_secret = HKDF-Extract(derived_early, Z_hybrid)     ← the only change
c hs traffic   = Derive-Secret(handshake_secret, "c hs traffic", Hash(CH‖SH))
s hs traffic   = Derive-Secret(handshake_secret, "s hs traffic", Hash(CH‖SH))
derived_hs     = Derive-Secret(handshake_secret, "derived", Hash(""))
master_secret  = HKDF-Extract(derived_hs, 0)
c ap traffic   = Derive-Secret(master_secret, "c ap traffic", TH_SF)
s ap traffic   = Derive-Secret(master_secret, "s ap traffic", TH_SF)
exp master     = Derive-Secret(master_secret, "exp master", TH_SF)
res master     = Derive-Secret(master_secret, "res master", TH_full)
finished_key   = HKDF-Expand-Label(traffic_secret, "finished", "", Hash.length)
key, iv        = HKDF-Expand-Label(traffic_secret, "key"/"iv", "", 16/12)
```

**The two transcript prefixes are not the same, and the difference is load-bearing.**
`TH_SF = Hash(ClientHello … server Finished)` and `TH_full = Hash(ClientHello … client
Finished)`. RFC 8446 §7.1 takes the application traffic secrets and the exporter master
secret over `TH_SF`, and only `res master` over `TH_full`. This section documented a
single hash — `TH_full` — for all four until a third review (the v3 audit) found both
roles deriving them from the longer prefix. Every test in this repository compares the two
halves of *this* harness against each other, so the handshake stayed self-consistent
while disagreeing with the standard: the same failure mode as the earlier
exporter-context bug, one level up. `tests/test_audit_v3_fixes.py` now pins both stages
against a transcript the test builds itself.
`HKDF-Expand-Label` is
the RFC 8446 §7.1 construction: `HkdfLabel = uint16 length ‖ vec8("tls13 " + label) ‖ vec8(context)`.
Both length prefixes in `Z_hybrid` are load-bearing: without them the pair
`(0x0102, 0x03)` and `(0x01, 0x0203)` would encode identically, and the transcript would
no longer determine the keys.

`res master` is derived but unused — this profile implements no resumption.

## 8. Record layer

`nonce = iv XOR (0x00…00 ‖ seq)` with the eight-byte sequence number right-aligned in a
twelve-byte IV; `AAD = uint8 content_type ‖ 0x0303 ‖ uint16 length`; the inner plaintext
is `content ‖ uint8 content_type`. AES-128-GCM, so a record grows by a 16-byte tag. No
padding is used, which makes the byte counts in `bench` a faithful lower bound.

**This harness produces no TLS record header.** `RecordLayer.seal` returns the ciphertext
alone (`len(plaintext) + 1 + 16`); record boundaries on the loopback transport come from the
driver's own four-byte length prefix, not from a five-byte TLS record header. An earlier
version of this section said "the outer record header carries the true content type", which
described a component the code does not have — an independent audit caught the discrepancy
(their V-18) and, correctly, treated the implementation as the source of truth.

**One real deviation from RFC 8446 §5.2** remains: the AAD's first byte is the *true* content
type (22 for handshake, 23 for application data) where the standard fixes the outer type at
`application_data` and carries the real one in the inner plaintext's last byte. This
implementation also writes that inner byte, so sizes and the AAD length match the standard
and only the AAD's type byte differs. An interop attempt would have to resolve that; nothing
inside this harness can observe it, because both ends agree.

A record-count limit is enforced at the AEAD usage bound of RFC 8446 §5.5 (`2**24.5` records
for AES-GCM) rather than at the sequence counter's end: sealing past it raises a named
`record` error. There is no KeyUpdate, so the connection ends there — see `docs/SECURITY.md`.

## 9. State machine

```
Client                                              Server
  generate x (ECDHE), (qpk, qsk) (KEM)
  → ClientHello{key_share=X, pq_key_share=qpk}
                                            generate y, encapsulate to qpk → (ct, ss_pq)
                                            Z_ecdh = X^y
                                      ← ServerHello{key_share=Y, pq_ciphertext=ct}
  Z_ecdh = Y^x ; ss_pq = Decaps(qsk, ct)
  Z_hybrid = encode(Z_ecdh, ss_pq)
  derive handshake keys --------------------------------- derive handshake keys
                                      ← EncryptedExtensions          (record 0)
                                      ← Certificate                  (record 1)
                                      ← CertificateVerify            (record 2)
                                      ← Finished                     (record 3)
  verify CA signature, then BOTH signature checks over M_CV
  verify server Finished
  → Finished (record 0)  ‖  application data (record 1)
                                            verify client Finished
  derive application keys ------------------------------ derive application keys
```

Records are numbered from zero per direction and renumbered when the keys change; the two
directions use different traffic secrets, so a record sealed in one direction never opens
in the other.

## 10. Rejections

Each check fails with a named step, which is what the tamper matrix in
`tools/verify_all.ps1` asserts:

| step | condition |
|---|---|
| `client_hello` | missing `pq_key_share`; KEM scheme or key length mismatch; wrong group |
| `server_hello` | missing `pq_ciphertext`; cipher suite not offered; wrong group |
| `certificate` | CA signature invalid; announced scheme is not the negotiated one |
| `certificate_verify` | either signature invalid, or a scheme field disagrees with the negotiated one |
| `server_finished` | `verify_data` mismatch |
| `client_finished` | `verify_data` mismatch |
| `record` | AEAD tag failure, including a corrupted KEM ciphertext, which surfaces here rather than at ServerHello because ML-KEM decapsulation never fails — implicit rejection yields a different secret |

## 11. What is absent

Relative to RFC 8446: parameter negotiation (one cipher suite and one group), HelloRetryRequest
and cookies, PSK and 0-RTT, session resumption (the secret is derived, nothing uses it),
post-handshake messages (KeyUpdate, NewSessionTicket), client authentication, alerts and
`close_notify`, record padding, the exporter interface, and any real X.509 handling.
Relative to a deployment: no interop, no concurrency, no retransmission, no fuzzing.

Two further limits belong here rather than in a footnote, because a reader comparing this
document against RFC 8446 will hit them:

* **`key_share` is single-entry** (§3): legal multi-share offers are refused by profile;
* **the record layer produces no record header** and its AAD takes the real content type where
  RFC 8446 §5.2 fixes the first byte to `application_data` (§8). Both are stated in
  `docs/CAPABILITIES.md`, together with the private codepoints and everything else a paper
  should not quote as interoperable.

## U-03 revision: XMSS verification context and version boundary

The XMSS profile now uses scheme `0xFE00 + height`, replacing `0x0E00 + height`.
Its public key is `root[n] || public_seed[n]` (64 bytes at n=32), and the entire
value is authenticated by the existing modelled certificate or X.509 extension.
The signature layout remains `index:u32 || wots_signature || wots_public_key || auth_path`;
at h=10/n=32/w=16 it remains 4612 bytes. Every WOTS+ chain step uses the public seed
and a 32-byte address containing that index, chain number, absolute step and
key/mask selector. There is no v1 fallback. Both peers must upgrade and old keys
and certificates must be replaced. Rebuilding a v2 key requires both seeds and
restoring its latest counter before signing. See [U-03](U03_WOTS_STEP_KEYS.md).

Earlier observed packet sizes in this document are historical. The public-key field
now grows by n bytes; DER encoding and variable classical signatures can affect
whole-certificate/handshake deltas. Updated measurements live in `.bench-u03/`.
