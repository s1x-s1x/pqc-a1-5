"""TLS-style wire encoding: fixed-width integers, length-prefixed vectors, handshake framing.

The encoding mirrors RFC 8446 section 3 so that the byte accounting in
``bench`` reflects realistic overhead instead of a toy format.
"""

from __future__ import annotations

from .errors import DecodeError

__all__ = [
    "Reader",
    "handshake_message",
    "split_handshake_message",
    "u8",
    "u16",
    "u24",
    "u32",
    "vec8",
    "vec16",
    "vec24",
]


def u8(value: int) -> bytes:
    """Encode ``value`` as one byte."""
    return value.to_bytes(1, "big")


def u16(value: int) -> bytes:
    """Encode ``value`` as a two-byte big-endian integer."""
    return value.to_bytes(2, "big")


def u24(value: int) -> bytes:
    """Encode ``value`` as a three-byte big-endian integer."""
    return value.to_bytes(3, "big")


def u32(value: int) -> bytes:
    """Encode ``value`` as a four-byte big-endian integer."""
    return value.to_bytes(4, "big")


def vec8(data: bytes) -> bytes:
    """Encode ``data`` as a one-byte-length-prefixed vector."""
    if len(data) > 0xFF:
        raise ValueError(f"vec8 payload of {len(data)} bytes exceeds 255")
    return u8(len(data)) + data


def vec16(data: bytes) -> bytes:
    """Encode ``data`` as a two-byte-length-prefixed vector."""
    if len(data) > 0xFFFF:
        raise ValueError(f"vec16 payload of {len(data)} bytes exceeds 65535")
    return u16(len(data)) + data


def vec24(data: bytes) -> bytes:
    """Encode ``data`` as a three-byte-length-prefixed vector."""
    if len(data) > 0xFFFFFF:
        raise ValueError(f"vec24 payload of {len(data)} bytes exceeds 16777215")
    return u24(len(data)) + data


def handshake_message(message_type: int, body: bytes) -> bytes:
    """Frame ``body`` as ``Handshake { type: u8, length: u24, body }``."""
    return u8(message_type) + vec24(body)


def split_handshake_message(frame: bytes) -> tuple[int, bytes]:
    """Split a framed handshake message into ``(type, body)``."""
    reader = Reader(frame)
    message_type = reader.read_u8()
    body = reader.read_vec24()
    reader.expect_end()
    return message_type, body


class Reader:
    """Cursor over a byte string with TLS-shaped readers.

    Every reader raises :class:`DecodeError` on truncation, so a malformed
    message fails at the field that ran out rather than returning short data.
    """

    __slots__ = ("_data", "_offset")

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._offset = 0

    @property
    def offset(self) -> int:
        """Number of bytes consumed so far."""
        return self._offset

    def remaining(self) -> int:
        """Number of bytes left."""
        return len(self._data) - self._offset

    def at_end(self) -> bool:
        """Whether every byte has been consumed."""
        return self._offset == len(self._data)

    def _take(self, count: int) -> bytes:
        if count < 0:
            raise DecodeError(f"negative read of {count} bytes")
        end = self._offset + count
        if end > len(self._data):
            raise DecodeError(
                f"truncated input: need {count} bytes at offset {self._offset}, "
                f"only {self.remaining()} remain"
            )
        chunk = self._data[self._offset : end]
        self._offset = end
        return chunk

    def read_u8(self) -> int:
        """Read one byte as an integer."""
        return int.from_bytes(self._take(1), "big")

    def read_u16(self) -> int:
        """Read a two-byte big-endian integer."""
        return int.from_bytes(self._take(2), "big")

    def read_u24(self) -> int:
        """Read a three-byte big-endian integer."""
        return int.from_bytes(self._take(3), "big")

    def read_u32(self) -> int:
        """Read a four-byte big-endian integer."""
        return int.from_bytes(self._take(4), "big")

    def read_bytes(self, count: int) -> bytes:
        """Read exactly ``count`` bytes."""
        return self._take(count)

    def read_vec8(self) -> bytes:
        """Read a one-byte-length-prefixed vector."""
        return self._take(self.read_u8())

    def read_vec16(self) -> bytes:
        """Read a two-byte-length-prefixed vector."""
        return self._take(self.read_u16())

    def read_vec24(self) -> bytes:
        """Read a three-byte-length-prefixed vector."""
        return self._take(self.read_u24())

    def expect_end(self) -> None:
        """Raise unless every byte has been consumed."""
        if not self.at_end():
            raise DecodeError(f"{self.remaining()} trailing bytes after message body")
