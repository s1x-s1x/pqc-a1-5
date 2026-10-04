"""Hybrid TLS 1.3 handshake implementation.

The package keeps the TLS 1.3 message flow and adds post-quantum material in two
places only:

* key exchange -- the classical ECDHE share is paired with a post-quantum KEM
  public key in ClientHello and a KEM ciphertext in ServerHello; both shared
  secrets are concatenated into one hybrid input for the key schedule.
* server authentication -- the classical signature is paired with a post-quantum
  signature over the same CertificateVerify input, and the client accepts only
  when both signatures verify.

Nothing here is wire-compatible with a deployed TLS stack: the post-quantum
extensions are not standardized, so the implementation is a self-contained
client/server pair used to exercise the design and to measure its cost.
"""

from __future__ import annotations

from ._deps import ensure_dependency_paths

# Dependencies installed beside the checkout (see tls/_deps.py) must be reachable
# before any backend module imports cryptography or pqcrypto.
ensure_dependency_paths()

__all__ = [
    "AEAD",
    "ClassicalSigner",
    "HybridConnection",
    "HybridTLSConfig",
    "KemBackend",
    "PqSigner",
]
