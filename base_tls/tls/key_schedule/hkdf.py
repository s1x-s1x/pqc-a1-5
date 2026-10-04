"""HKDF and the TLS 1.3 key schedule, with the hybrid secret as its input.

The only structural change to RFC 8446 section 7.1 is the value fed to
``HKDF-Extract`` that produces ``handshake_secret``: instead of a single ECDHE
shared secret it receives ``Z_hybrid`` -- the length-prefixed concatenation of the
ECDHE secret and the KEM secret. Every derivation after that point is unchanged,
so handshake and application traffic secrets, Finished keys, and the exporter
master secret all inherit from both branches of the key exchange.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from ..wire import u16, vec8

__all__ = [
    "HASH_NAMES",
    "KeySchedule",
    "TrafficSecretPair",
    "derive_secret",
    "encode_hybrid_secret",
    "hash_length",
    "hkdf_expand",
    "hkdf_expand_label",
    "hkdf_extract",
]

HASH_NAMES: dict[str, str] = {"sha256": "sha256", "sha384": "sha384"}

_LABEL_PREFIX = b"tls13 "


def _hash(hash_name: str, data: bytes) -> bytes:
    if hash_name not in HASH_NAMES:
        raise ValueError(f"unsupported hash {hash_name!r}; expected one of {sorted(HASH_NAMES)}")
    return hashlib.new(hash_name, data).digest()


def hash_length(hash_name: str = "sha256") -> int:
    """Return the digest length in bytes for ``hash_name``."""
    return hashlib.new(hash_name).digest_size


def hkdf_extract(salt: bytes, ikm: bytes, hash_name: str = "sha256") -> bytes:
    """HKDF-Extract: ``PRK = HMAC(salt, IKM)`` (RFC 5869 section 2.2)."""
    return hmac.new(salt, ikm, hash_name).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int, hash_name: str = "sha256") -> bytes:
    """HKDF-Expand to ``length`` bytes (RFC 5869 section 2.3)."""
    digest_size = hash_length(hash_name)
    if length > 255 * digest_size:
        raise ValueError(f"requested {length} bytes exceeds HKDF-Expand limit of {255 * digest_size}")
    output = bytearray()
    block = b""
    counter = 1
    while len(output) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hash_name).digest()
        output.extend(block)
        counter += 1
    return bytes(output[:length])


def hkdf_expand_label(
    secret: bytes,
    label: str | bytes,
    context: bytes,
    length: int,
    hash_name: str = "sha256",
) -> bytes:
    """TLS 1.3 ``HKDF-Expand-Label`` (RFC 8446 section 7.1).

    The ``HkdfLabel`` struct is ``uint16 length; opaque label<7..255>; opaque
    context<0..255>`` with ``"tls13 "`` prefixed to every label.
    """
    label_bytes = label.encode("ascii") if isinstance(label, str) else label
    full_label = _LABEL_PREFIX + label_bytes
    info = u16(length) + vec8(full_label) + vec8(context)
    return hkdf_expand(secret, info, length, hash_name)


def derive_secret(
    secret: bytes,
    label: str,
    transcript_hash: bytes,
    hash_name: str = "sha256",
) -> bytes:
    """TLS 1.3 ``Derive-Secret``: expand a labelled secret over a transcript hash."""
    return hkdf_expand_label(secret, label, transcript_hash, hash_length(hash_name), hash_name)


def encode_hybrid_secret(z_ecdh: bytes, ss_pq: bytes) -> bytes:
    """Encode the two shared secrets as an unambiguous hybrid input.

    Each component is length-prefixed, so no two distinct pairs can encode to the
    same byte string even when the components have equal length.
    """
    return u16(len(z_ecdh)) + z_ecdh + u16(len(ss_pq)) + ss_pq


@dataclass(frozen=True)
class TrafficSecretPair:
    """The client- and server-direction traffic secrets derived at one stage."""

    client: bytes
    server: bytes


class KeySchedule:
    """The TLS 1.3 key schedule, seeded by the hybrid shared secret.

    Derivation is split across the handshake so each stage hashes exactly the
    transcript prefix RFC 8446 prescribes: ``c hs traffic``/``s hs traffic`` over
    ClientHello..ServerHello, then the application secrets over the full
    handshake transcript including the client Finished.
    """

    def __init__(
        self,
        hash_name: str = "sha256",
        aead_key_length: int = 16,
        aead_iv_length: int = 12,
        psk: bytes | None = None,
    ) -> None:
        self.hash_name = hash_name
        self.aead_key_length = aead_key_length
        self.aead_iv_length = aead_iv_length
        self._psk = psk if psk is not None else bytes(hash_length(hash_name))
        self._empty_hash = _hash(hash_name, b"")
        self.early_secret: bytes | None = None
        self.handshake_secret: bytes | None = None
        self.master_secret: bytes | None = None
        self.client_handshake_traffic: bytes | None = None
        self.server_handshake_traffic: bytes | None = None
        self.client_application_traffic: bytes | None = None
        self.server_application_traffic: bytes | None = None
        self.exporter_master_secret: bytes | None = None
        self.resumption_master_secret: bytes | None = None

    def _require(self, value: bytes | None, stage: str) -> bytes:
        if value is None:
            raise ValueError(f"{stage} is unavailable: run the earlier key schedule stage first")
        return value

    def derive_early_secret(self) -> bytes:
        """``early_secret = HKDF-Extract(0, PSK)``; a zero PSK for full handshakes."""
        self.early_secret = hkdf_extract(bytes(hash_length(self.hash_name)), self._psk, self.hash_name)
        return self.early_secret

    def derive_handshake_secret(self, z_hybrid: bytes) -> bytes:
        """``handshake_secret = HKDF-Extract(Derive-Secret(early, "derived", ""), Z_hybrid)``."""
        early = self._require(self.early_secret or self.derive_early_secret(), "early_secret")
        salt = derive_secret(early, "derived", self._empty_hash, self.hash_name)
        self.handshake_secret = hkdf_extract(salt, z_hybrid, self.hash_name)
        return self.handshake_secret

    def derive_handshake_traffic(self, transcript_hash: bytes) -> TrafficSecretPair:
        """Derive ``c hs traffic`` and ``s hs traffic`` over ClientHello..ServerHello."""
        handshake = self._require(self.handshake_secret, "handshake_secret")
        self.client_handshake_traffic = derive_secret(handshake, "c hs traffic", transcript_hash, self.hash_name)
        self.server_handshake_traffic = derive_secret(handshake, "s hs traffic", transcript_hash, self.hash_name)
        return TrafficSecretPair(self.client_handshake_traffic, self.server_handshake_traffic)

    def derive_master_secret(self) -> bytes:
        """``master_secret = HKDF-Extract(Derive-Secret(handshake, "derived", ""), 0)``."""
        handshake = self._require(self.handshake_secret, "handshake_secret")
        salt = derive_secret(handshake, "derived", self._empty_hash, self.hash_name)
        self.master_secret = hkdf_extract(salt, bytes(hash_length(self.hash_name)), self.hash_name)
        return self.master_secret

    def derive_application_traffic(self, transcript_hash: bytes) -> TrafficSecretPair:
        """Derive ``c ap traffic``/``s ap traffic`` plus the exporter master secret.

        ``transcript_hash`` must cover ClientHello through the **server** Finished: that
        is what RFC 8446 section 7.1 specifies for all three of these secrets. Passing a
        hash that also covers the client Finished yields values no conformant peer will
        compute. :meth:`derive_resumption_master_secret` is the one secret that does take
        the longer transcript; keeping both in this method is what allowed them to be
        conflated, and an independent audit caught the result.
        """
        master = self._require(self.master_secret or self.derive_master_secret(), "master_secret")
        self.client_application_traffic = derive_secret(master, "c ap traffic", transcript_hash, self.hash_name)
        self.server_application_traffic = derive_secret(master, "s ap traffic", transcript_hash, self.hash_name)
        self.exporter_master_secret = derive_secret(master, "exp master", transcript_hash, self.hash_name)
        return TrafficSecretPair(self.client_application_traffic, self.server_application_traffic)

    def derive_resumption_master_secret(self, transcript_hash: bytes) -> bytes:
        """Derive ``res master`` over the transcript through the **client** Finished.

        RFC 8446 section 7.1's key schedule takes this secret after the client's Finished,
        while the application traffic and exporter secrets are taken before it. This
        profile implements no resumption, so the value is derived and left unused; it is
        separated anyway, because deriving it from the wrong transcript is exactly the
        defect the audit found in this method.
        """
        master = self._require(self.master_secret or self.derive_master_secret(), "master_secret")
        self.resumption_master_secret = derive_secret(master, "res master", transcript_hash, self.hash_name)
        return self.resumption_master_secret

    def finished_key(self, traffic_secret: bytes) -> bytes:
        """Derive the Finished HMAC key from a traffic secret."""
        return hkdf_expand_label(
            traffic_secret, "finished", b"", hash_length(self.hash_name), self.hash_name
        )

    def traffic_keys(self, traffic_secret: bytes) -> tuple[bytes, bytes]:
        """Derive ``(key, iv)`` for the AEAD record layer from a traffic secret."""
        key = hkdf_expand_label(
            traffic_secret, "key", b"", self.aead_key_length, self.hash_name
        )
        iv = hkdf_expand_label(traffic_secret, "iv", b"", self.aead_iv_length, self.hash_name)
        return key, iv

    def compute_finished(self, traffic_secret: bytes, transcript_hash: bytes) -> bytes:
        """``verify_data = HMAC(finished_key, transcript_hash)``."""
        return hmac.new(
            self.finished_key(traffic_secret), transcript_hash, self.hash_name
        ).digest()

    def hash_bytes(self, data: bytes) -> bytes:
        """Hash ``data`` with the schedule's hash."""
        return _hash(self.hash_name, data)
