"""The CertificateVerify input and the hybrid signature payload.

TLS 1.3 does not sign the transcript hash directly: it signs a context string that
pads 64 space bytes, names the protocol and role, separates with a zero byte, and
ends with the transcript hash. Both signatures cover this identical input, so
verifying them establishes that the two authentication mechanisms signed the same
connection rather than two different views of it.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..errors import DecodeError
from ..wire import Reader, u16, vec16

__all__ = [
    "CERTIFICATE_VERIFY_CONTEXTS",
    "HybridCertificateVerify",
    "HybridVerificationResult",
    "build_certificate_verify_input",
]

#: Role-specific context strings. A client signature uses a different one, so a
#: signature made in one role can never be replayed in the other.
CERTIFICATE_VERIFY_CONTEXTS: dict[str, bytes] = {
    "server": b"TLS 1.3, server CertificateVerify",
    "client": b"TLS 1.3, client CertificateVerify",
}

_PADDING = b"\x20" * 64


def build_certificate_verify_input(transcript_hash: bytes, role: str = "server") -> bytes:
    """Build ``M_CV = 64 * 0x20 || context || 0x00 || transcript_hash``."""
    try:
        context = CERTIFICATE_VERIFY_CONTEXTS[role]
    except KeyError:
        raise ValueError(
            f"unknown role {role!r}; expected one of {sorted(CERTIFICATE_VERIFY_CONTEXTS)}"
        ) from None
    return _PADDING + context + b"\x00" + transcript_hash


@dataclass(frozen=True)
class HybridCertificateVerify:
    """The dual-signature payload carried by one CertificateVerify message.

    The structure is length-prefixed at every field so a decoder never has to guess
    where one signature ends and the next begins, and so a scheme that produces
    variable-length signatures (Falcon, XMSS with an authentication path) fits the
    same container.
    """

    classic_scheme: int
    classic_signature: bytes
    #: ``None`` for the classical-only baseline, whose CertificateVerify carries one
    #: signature. The container stays length-prefixed either way, so a decoder never
    #: guesses where a field ends.
    pq_scheme: int | None
    pq_signature: bytes | None

    def encode(self) -> bytes:
        """Encode the payload body."""
        body = u16(self.classic_scheme) + vec16(self.classic_signature)
        if self.pq_scheme is not None and self.pq_signature is not None:
            body += u16(self.pq_scheme) + vec16(self.pq_signature)
        return body

    @classmethod
    def decode(cls, body: bytes) -> "HybridCertificateVerify":
        """Decode a payload body, with or without the post-quantum signature."""
        reader = Reader(body)
        classic_scheme = reader.read_u16()
        classic_signature = reader.read_vec16()
        pq_scheme: int | None = None
        pq_signature: bytes | None = None
        if not reader.at_end():
            pq_scheme = reader.read_u16()
            pq_signature = reader.read_vec16()
        reader.expect_end()
        return cls(classic_scheme, classic_signature, pq_scheme, pq_signature)

    @property
    def byte_count(self) -> int:
        """Encoded length of the payload body."""
        return len(self.encode())

    def overhead_bytes(self) -> int:
        """Bytes spent on framing rather than on the signatures themselves."""
        signature_bytes = len(self.classic_signature) + (
            len(self.pq_signature) if self.pq_signature is not None else 0
        )
        return self.byte_count - signature_bytes


@dataclass(frozen=True)
class HybridVerificationResult:
    """Outcome of checking both signatures over one CertificateVerify input."""

    classic_ok: bool
    pq_ok: bool

    @property
    def accepted(self) -> bool:
        """Accept only when both signatures verify.

        This is the conjunction that makes the authentication hybrid: defeating it
        requires breaking the classical scheme *and* the post-quantum scheme, not
        whichever is weaker.
        """
        return self.classic_ok and self.pq_ok
