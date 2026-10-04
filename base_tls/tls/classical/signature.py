"""Classical signature backends for the traditional half of CertificateVerify."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from ..errors import BackendUnavailableError

__all__ = [
    "CLASSICAL_SIGNERS",
    "ClassicalSigner",
    "EcdsaP256Sha256",
    "Ed25519",
    "get_classical_signer",
]


@runtime_checkable
class ClassicalSigner(Protocol):
    """A signature scheme usable in the traditional half of CertificateVerify."""

    name: str
    scheme_id: int
    public_key_bytes: int
    signature_bytes: int
    #: Always ``False`` here: these are the schemes the hybrid construction pairs with
    #: a post-quantum signature rather than replaces.
    post_quantum: bool

    def keygen(self) -> tuple[object, bytes]:
        """Return ``(secret_key, public_key)`` with the public key wire-encoded."""

    def sign(self, secret_key: object, message: bytes) -> bytes:
        """Sign ``message`` and return the wire-encoded signature."""

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Return whether ``signature`` is valid; never raise on a bad signature."""


class EcdsaP256Sha256:
    """ECDSA over NIST P-256 with SHA-256, DER-encoded signatures."""

    name = "ecdsa-p256-sha256"
    scheme_id = 0x0403
    public_key_bytes = 65
    signature_bytes = 72  # DER maximum for P-256; the real length is measured per signature
    post_quantum = False

    def keygen(self) -> tuple[object, bytes]:
        """Generate an ECDSA key pair."""
        secret = ec.generate_private_key(ec.SECP256R1())
        public = secret.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        return secret, public

    def sign(self, secret_key: object, message: bytes) -> bytes:
        """Sign ``message`` with ECDSA/SHA-256."""
        return secret_key.sign(message, ec.ECDSA(hashes.SHA256()))  # type: ignore[attr-defined]

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify an ECDSA/SHA-256 signature."""
        try:
            key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key)
            key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        except (InvalidSignature, ValueError):
            return False
        return True


class Ed25519:
    """Ed25519, a 32-byte public key with 64-byte signatures."""

    name = "ed25519"
    scheme_id = 0x0807
    public_key_bytes = 32
    signature_bytes = 64
    post_quantum = False

    def keygen(self) -> tuple[object, bytes]:
        """Generate an Ed25519 key pair."""
        secret = ed25519.Ed25519PrivateKey.generate()
        public = secret.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return secret, public

    def sign(self, secret_key: object, message: bytes) -> bytes:
        """Sign ``message`` with Ed25519."""
        return secret_key.sign(message)  # type: ignore[attr-defined]

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify an Ed25519 signature."""
        try:
            key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            key.verify(signature, message)
        except (InvalidSignature, ValueError):
            return False
        return True


CLASSICAL_SIGNERS: dict[str, type] = {
    EcdsaP256Sha256.name: EcdsaP256Sha256,
    Ed25519.name: Ed25519,
}


def get_classical_signer(name: str) -> ClassicalSigner:
    """Instantiate the classical signer called ``name``."""
    try:
        return CLASSICAL_SIGNERS[name]()  # type: ignore[return-value]
    except KeyError:
        raise BackendUnavailableError(
            f"unknown classical signer {name!r}; available: {sorted(CLASSICAL_SIGNERS)}"
        ) from None
