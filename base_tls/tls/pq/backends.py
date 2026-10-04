"""Backend contracts for the post-quantum half of the scheme.

Both protocols are structural: any object with the right attributes and methods
can serve as a KEM or signature backend, so a new algorithm is added by writing a
small wrapper and registering it, not by changing the handshake.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

__all__ = ["KemBackend", "PqSigner"]


@runtime_checkable
class KemBackend(Protocol):
    """A key-encapsulation mechanism."""

    name: str
    #: Private-use code point carried in the pq_key_share extension so a client and
    #: server that selected different KEMs fail on the first flight.
    scheme_id: int
    #: ``True`` only for mechanisms believed to resist quantum attack; a classical
    #: stand-in sets this to ``False`` so reports cannot present it as post-quantum.
    post_quantum: bool
    public_key_bytes: int
    ciphertext_bytes: int
    shared_secret_bytes: int

    def keygen(self) -> tuple[bytes, bytes]:
        """Return ``(public_key, secret_key)``."""

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Return ``(ciphertext, shared_secret)`` for ``public_key``."""

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Recover the shared secret from ``ciphertext``."""


@runtime_checkable
class PqSigner(Protocol):
    """A signature scheme used as the post-quantum half of CertificateVerify."""

    name: str
    #: TLS SignatureScheme code point this backend reports on the wire. Values in
    #: the private-use range keep the hybrid payload self-describing until the
    #: corresponding code points are assigned.
    scheme_id: int
    post_quantum: bool
    public_key_bytes: int
    signature_bytes: int

    def keygen(self) -> tuple[object, bytes]:
        """Return ``(secret_key, public_key)``; the secret key may be a stateful object."""

    def sign(self, secret_key: object, message: bytes) -> bytes:
        """Sign ``message`` with ``secret_key``."""

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Return whether ``signature`` is valid; never raise on a bad signature."""
