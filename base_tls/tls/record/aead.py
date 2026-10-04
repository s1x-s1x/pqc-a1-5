"""AEAD record layer.

The construction follows RFC 8446 section 5.2/5.3: the nonce is the static IV
XORed with the 64-bit record sequence number, the additional data is the record
header, and the plaintext is the content followed by its real content type. Padding
is not used, so ciphertext length is exactly plaintext length plus the tag; that
keeps the byte accounting in ``bench`` a faithful lower bound.

One deviation from RFC 8446: the outer record header carries the true content type
instead of always ``application_data``. Sizes and the AAD length are unchanged,
because the unencrypted content type byte is exactly what the real convention pays
for as well.
"""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..errors import HandshakeError
from ..wire import u8, u16

__all__ = ["AEAD_SUITES", "AeadSuite", "RecordLayer", "get_aead_suite"]

#: Content types this implementation distinguishes.
CONTENT_TYPE_HANDSHAKE = 22
CONTENT_TYPE_APPLICATION_DATA = 23
CONTENT_TYPE_ALERT = 21

_LEGACY_VERSION = b"\x03\x03"

#: Records one key may protect before the AEAD usage limit of RFC 8446 section 5.5 is
#: reached: ``2**24.5`` for AES-GCM with a 16-byte tag. Held as a float because the section
#: states it as a fractional power of two; compared as an integer bound.
_RECORD_LIMIT = 2 ** 24.5


class AeadSuite:
    """Metadata and factory for one AEAD algorithm."""

    def __init__(self, name: str, key_length: int, iv_length: int, tag_length: int) -> None:
        self.name = name
        self.key_length = key_length
        self.iv_length = iv_length
        self.tag_length = tag_length

    def new(self, key: bytes) -> AESGCM:
        """Build the AEAD primitive for ``key``."""
        if len(key) != self.key_length:
            raise ValueError(f"{self.name} needs a {self.key_length}-byte key, got {len(key)}")
        return AESGCM(key)


AEAD_SUITES: dict[str, AeadSuite] = {
    "aes-128-gcm": AeadSuite("aes-128-gcm", 16, 12, 16),
    "aes-256-gcm": AeadSuite("aes-256-gcm", 32, 12, 16),
}


def get_aead_suite(name: str) -> AeadSuite:
    """Return the AEAD suite called ``name``."""
    try:
        return AEAD_SUITES[name]
    except KeyError:
        raise ValueError(f"unknown AEAD {name!r}; available: {sorted(AEAD_SUITES)}") from None


class RecordLayer:
    """One direction's record protection state.

    Both peers build this object twice -- once per direction -- from the traffic
    secret the key schedule derived for that direction, which is why a client key
    and a server key never coincide even though the root secret does.
    """

    def __init__(self, suite: AeadSuite, key: bytes, iv: bytes) -> None:
        if len(iv) != suite.iv_length:
            raise ValueError(f"{suite.name} needs a {suite.iv_length}-byte IV, got {len(iv)}")
        self.suite = suite
        self._key = key
        self._iv = iv
        self._aead = suite.new(key)
        self._sequence = 0
        self.records_sealed = 0
        self.records_opened = 0

    @property
    def sequence(self) -> int:
        """Next record sequence number."""
        return self._sequence

    def key_fingerprint(self, length: int = 12) -> str:
        """A short digest that identifies this traffic key without revealing any of it.

        This is a hash, not a prefix. An earlier version returned the first `length` bytes
        of the key, which for the default AES-128 key left only four bytes unknown — and
        its docstring claimed it "must not print the key" while printing most of it. A
        static security review found it; the demonstration log is the only consumer, and
        such a log plus a ciphertext is exactly what a key search wants.
        """
        digest = hashlib.sha256(b"hybrid-tls13 traffic key fingerprint|" + self._key).hexdigest()
        return digest[: length * 2]

    def _nonce(self) -> bytes:
        """The static IV XORed with the 64-bit sequence number, left-padded to the IV length."""
        if self.suite.iv_length < 8:
            raise ValueError(f"{self.suite.name} has a {self.suite.iv_length}-byte IV, too short for a sequence number")
        padded = bytes(self.suite.iv_length - 8) + self._sequence.to_bytes(8, "big")
        return bytes(a ^ b for a, b in zip(self._iv, padded, strict=True))

    @staticmethod
    def _additional_data(content_type: int, length: int) -> bytes:
        return u8(content_type) + _LEGACY_VERSION + u16(length)

    def _check_usage_limit(self, record_number: int) -> None:
        """Refuse to exceed the AEAD record limit of RFC 8446 section 5.5.

        AES-GCM in TLS 1.3 has a limit of ``2**24.5`` records per key; past it the
        confidentiality guarantee no longer holds and the sender must rekey. This profile has
        no KeyUpdate, so the correct behaviour at the limit is to **stop**, with a named error
        rather than an ``OverflowError`` from the sequence counter — which is what happened
        before: an independent audit pushed the sequence to ``2**64 - 1`` and observed the
        counter overflow instead of a protocol error.
        """
        if record_number >= _RECORD_LIMIT:
            raise HandshakeError(
                "record",
                f"the AEAD usage limit for {self.suite.name} is {int(_RECORD_LIMIT)} records and "
                "this profile implements no KeyUpdate, so the connection must end here",
            )

    def seal(self, content_type: int, payload: bytes) -> bytes:
        """Encrypt ``payload`` into one record."""
        self._check_usage_limit(self._sequence)
        inner = payload + u8(content_type)
        ciphertext = self._aead.encrypt(self._nonce(), inner, self._additional_data(content_type, len(inner)))
        self._sequence += 1
        self.records_sealed += 1
        return ciphertext

    def open(self, record: bytes, expected_type: int | None = None) -> tuple[int, bytes]:
        """Decrypt one record and return ``(content_type, payload)``.

        A failed tag check is a handshake failure, not a caller mistake, so it is
        reported as :class:`HandshakeError` carrying the record number.
        """
        record_number = self._sequence
        self._check_usage_limit(record_number)
        header_type = expected_type if expected_type is not None else CONTENT_TYPE_APPLICATION_DATA
        inner_length = len(record) - self.suite.tag_length
        if inner_length < 1:
            raise HandshakeError("record", f"record {record_number} is shorter than its tag")
        try:
            inner = self._aead.decrypt(
                self._nonce(), record, self._additional_data(header_type, inner_length)
            )
        except InvalidTag as error:
            raise HandshakeError("record", f"record {record_number} failed authentication") from error
        self._sequence += 1
        self.records_opened += 1
        return inner[-1], inner[:-1]
