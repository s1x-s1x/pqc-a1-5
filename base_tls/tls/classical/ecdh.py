"""Ephemeral elliptic-curve Diffie-Hellman for the classical branch of the key exchange.

X25519 is the default because its 32-byte share is the smallest realistic
ClientHello/ServerHello addition; secp256r1 is available for parity with the
ECDSA certificate used in the classical signature branch.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519

from ..errors import HandshakeError

__all__ = ["ECDHE_GROUPS", "EcdheKeyPair", "group_public_key_bytes"]

#: Wire size of one public share per named group.
ECDHE_GROUPS: dict[str, int] = {"x25519": 32, "secp256r1": 65}


def group_public_key_bytes(group: str) -> int:
    """Return the encoded public-share size for ``group``."""
    try:
        return ECDHE_GROUPS[group]
    except KeyError:
        raise ValueError(f"unsupported group {group!r}; expected one of {sorted(ECDHE_GROUPS)}") from None


class EcdheKeyPair:
    """One ephemeral ECDHE key pair.

    The private key is never serialized: it exists only inside this object, which
    is what a caller discards after the handshake to get forward secrecy.
    """

    __slots__ = ("_group", "_private")

    def __init__(self, group: str, private: object) -> None:
        self._group = group
        self._private = private

    @classmethod
    def generate(cls, group: str = "x25519") -> "EcdheKeyPair":
        """Generate a fresh ephemeral key pair for ``group``."""
        if group == "x25519":
            return cls(group, x25519.X25519PrivateKey.generate())
        if group == "secp256r1":
            return cls(group, ec.generate_private_key(ec.SECP256R1()))
        raise ValueError(f"unsupported group {group!r}; expected one of {sorted(ECDHE_GROUPS)}")

    @property
    def group(self) -> str:
        """The named group this pair belongs to."""
        return self._group

    @property
    def public_key_bytes(self) -> int:
        """Encoded length of the public share."""
        return group_public_key_bytes(self._group)

    def public_bytes(self) -> bytes:
        """Encode the public share for the wire."""
        if self._group == "x25519":
            return self._private.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        return self._private.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )

    def exchange(self, peer_public: bytes, step: str = "key_exchange") -> bytes:
        """Compute the raw shared secret against a peer's encoded public share.

        The secret is the raw X coordinate (or X25519 output); the key schedule receives it
        inside the hybrid encoding, so no extra KDF is applied here.

        Everything a *peer* controls about this input is turned into a
        :class:`HandshakeError` carrying ``step``: a share of the wrong length, an encoding
        that will not parse, and — importantly — the low-order point that ``cryptography``
        refuses by raising a bare ``ValueError``. An independent audit showed a caller that
        catches what this package documents (`HybridTLSError`) would instead see a
        ``ValueError`` escape from a value the peer chose (their B2, B3, D7).
        """
        if self._group == "x25519":
            if len(peer_public) != 32:
                raise HandshakeError(
                    step, f"the peer's x25519 share is {len(peer_public)} bytes, not 32"
                )
            try:
                peer = x25519.X25519PublicKey.from_public_bytes(peer_public)
                return self._private.exchange(peer)
            except ValueError as error:
                raise HandshakeError(step, f"the peer's x25519 share was refused: {error}") from error
        if self._group == "secp256r1":
            try:
                peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_public)
                return self._private.exchange(ec.ECDH(), peer)
            except ValueError as error:
                raise HandshakeError(step, f"the peer's secp256r1 share was refused: {error}") from error
        raise HandshakeError(step, f"unsupported group {self._group!r}")
