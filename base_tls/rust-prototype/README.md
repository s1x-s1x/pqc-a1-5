# Real-stack prototype: hybrid key exchange in rustls

Tier 3 of the project. **The hybrid key exchange negotiates and completes inside a real
rustls handshake**, with no patch to rustls.

```powershell
powershell -File tools\build_rust_prototype.ps1            # fetches crates, needs the wider sandbox mode
powershell -File tools\build_rust_prototype.ps1 -Offline   # once cached, no network at all
```

## Result

```
rustls TLS 1.3 group                       client   server    total      delta
X25519 only (classical baseline)              292      663      955         +0
X25519, share padded to 1216 B               1476     1848     3324      +2369
ML-KEM-768 only (pure post-quantum)          1444     1717     3161      +2206
X25519 + ML-KEM-768 (hybrid)                 1476     1751     3227      +2272

hybrid key exchange negotiated in rustls: +2272 bytes over X25519 alone
```

The negotiated group rustls reports is `HybridX25519MlKem768 { classical: X25519,
post_quantum: MlKem768Group }`, and the handshake **completes**. That second fact is the
important one: both endpoints derived the same 64-byte hybrid secret, or the Finished MAC
would have failed. A byte count would only show that something large travelled; a completed
handshake shows the composition is correct.

### The control row earns its place

The padded row is X25519 with a 1216-byte share and **no post-quantum cryptography at all**.
It costs +2369 against the hybrid's +2272, so the hybrid's size is explained by its shares
rather than by the mere presence of a custom group. Without that row, "+2272" could have
been an artefact of any group being in play.

### What the two halves contribute

| | client | server |
|---|---|---|
| share sizes | `ek(1184) ‖ x_pub(32)` = 1216 | `ct(1088) ‖ y_pub(32)` = 1120 |
| measured growth | +1184 | +1088 |

and the Python harness's independent accounting for the same KEM predicts ΔCH = 1194 and
ΔSH = 1094 — each **10 bytes** more, which is the extension and length framing the harness
adds and a key-share slot does not. Two independent implementations agreeing to within ten
bytes on the same construction is the cross-check the harness's byte table needed.

## What made it work

Two facts, both written down in rustls's own post-quantum groups
(`src/crypto/aws_lc_rs/pq/{mlkem,hybrid}.rs`):

1. **A KEM group must implement `SupportedKxGroup::start_and_complete`.** The server's share
   is a **ciphertext**, and `start()` cannot produce one — it takes no peer key. The default
   `start_and_complete` calls `start()` then `complete()`, which publishes a key where a
   ciphertext belongs. The first version of this file did exactly that, and negotiated
   nothing while looking like it worked; the prototype now detects that case and exits
   non-zero rather than printing numbers from the wrong group.
2. **A hybrid group is a composition.** Both sub-groups run; shares concatenate
   post-quantum first and classical second, and so do the secrets. rustls's own `Hybrid`
   type is `pub(crate)`, so this file re-implements the same composition in about eighty
   lines rather than reusing it.

The ordering is a documented choice, not an accident: rustls's source cites SP 800-56C
rev 2, where the element appearing first is the one that controls approval.

## What is still not done

**Hybrid signatures.** rustls's `SignatureScheme` is a closed enum, so a composite
CertificateVerify needs either a patched rustls or the delegated-credentials route that
Celi et al. used to advertise post-quantum signatures without new certificates. The
prototype therefore demonstrates the key-exchange half of the design only.

**Certificate and handshake-signature verification are real now.** An audit of the v3
package found the opposite: this file used to install an `AcceptAnyCertificate` verifier
that returned success from both `verify_server_cert` and `verify_tls13_signature`, with
every argument unused — so every byte-count row it printed said nothing about
authentication, and a reader could have copied that configuration into a real client. It
now generates a throwaway CA and a leaf it signed, serves `[leaf, CA]`, and verifies
through rustls's own webpki path with that CA in a root store. No `dangerous()` escape
hatch remains in the file.

The run proves it rather than asserting it: a second handshake is performed whose client
trusts a **different** CA and is required to fail —

```
negative control 1: an untrusted CA is rejected -> invalid peer certificate: BadSignature
```

— and the process exits non-zero if it succeeds. A second negative control feeds the
padded share-size group an all-zero X25519 share (RFC 7748 §6.1) and requires rejection.

**No performance numbers from this prototype.** It runs one handshake per group in-process
and times nothing. The harness is where latency is measured; this file is where the byte
counts are anchored to a stack that is not this project.

## Environment notes

Two facts this machine needed, now scripted:

1. **The MSVC linker is not on PATH.** Visual Studio 2022 Community is installed, so the
   build imports `vcvars64.bat` first; without it `cargo build` fails looking for `link.exe`.
2. **cargo cannot reach crates.io under the restricted token.** libcurl uses schannel, which
   fails with `SEC_E_NO_CREDENTIALS` when the process cannot obtain a credential handle. The
   same command succeeds with the wider sandbox mode. This is the same class of environment
   defect as the `os.mkdir` DACL problem the Python side works around; Python's TLS is
   unaffected because it uses OpenSSL with its own credentials. With the crates cached,
   `-Offline` needs neither the network nor the wider mode.

This prototype is deliberately not part of `tools\verify_all.ps1`: it needs the wider mode
to fetch dependencies, so it cannot be a gate that runs unattended.
