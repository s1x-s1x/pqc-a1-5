"""Handshake transcript hashing.

The transcript is the concatenation of complete handshake messages *including*
their type and length headers, exactly as RFC 8446 section 4.4.1 defines it. Every
derivation and both signatures bind to a prefix of this byte string, which is what
makes the post-quantum additions non-strippable: dropping the KEM ciphertext or a
signature changes every later transcript hash.
"""

from __future__ import annotations

import hashlib

__all__ = ["Transcript"]


class Transcript:
    """Accumulates handshake messages and hashes chosen prefixes of them."""

    __slots__ = ("_buffer", "hash_name")

    def __init__(self, hash_name: str = "sha256") -> None:
        self.hash_name = hash_name
        self._buffer = bytearray()

    def __len__(self) -> int:
        return len(self._buffer)

    @property
    def byte_count(self) -> int:
        """Number of transcript bytes accumulated."""
        return len(self._buffer)

    def add(self, message: bytes) -> None:
        """Append one complete handshake message."""
        self._buffer.extend(message)

    def hash(self) -> bytes:
        """Hash everything accumulated so far."""
        return hashlib.new(self.hash_name, bytes(self._buffer)).digest()

    def copy(self) -> "Transcript":
        """Return an independent copy, used to hash a prefix without disturbing the transcript."""
        clone = Transcript(self.hash_name)
        clone._buffer = bytearray(self._buffer)
        return clone
