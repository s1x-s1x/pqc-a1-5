"""Wire-format contract tests for :mod:`tls.wire`.

What each test pins:

* the ``uN`` encoders are fixed-width, big-endian, and reject out-of-range values;
* every ``Reader`` method consumes exactly the field it names and reports
  truncation as :class:`~tls.errors.DecodeError` whose message carries the offset;
* length-prefixed vectors write the RFC 8446 prefix and refuse payloads the
  prefix cannot represent;
* handshake framing round-trips ``(type, length, body)`` and rejects trailing bytes.
"""

from __future__ import annotations

import pytest

from tls.errors import DecodeError
from tls.wire import (
    Reader,
    handshake_message,
    split_handshake_message,
    u8,
    u16,
    u24,
    u32,
    vec8,
    vec16,
    vec24,
)

INT_CODECS = [
    pytest.param(u8, "read_u8", 1, 0xFF, id="u8"),
    pytest.param(u16, "read_u16", 2, 0xFFFF, id="u16"),
    pytest.param(u24, "read_u24", 3, 0xFFFFFF, id="u24"),
    pytest.param(u32, "read_u32", 4, 0xFFFFFFFF, id="u32"),
]

VECTOR_CODECS = [
    pytest.param(vec8, "read_vec8", 0xFF, id="vec8"),
    pytest.param(vec16, "read_vec16", 0xFFFF, id="vec16"),
    pytest.param(vec24, "read_vec24", 0xFFFFFF, id="vec24"),
]


# --------------------------------------------------------------- integer codecs


@pytest.mark.parametrize(("encoder", "reader_name", "width", "maximum"), INT_CODECS)
def test_fixed_width_integers_are_big_endian_at_both_boundaries(encoder, reader_name, width, maximum):
    """Each ``uN`` spends exactly N bytes on 0, 1 and its maximum, most significant first."""
    assert encoder(0) == bytes(width)
    assert encoder(1) == bytes(width - 1) + b"\x01"
    assert encoder(maximum) == b"\xff" * width
    assert {len(encoder(value)) for value in (0, 1, maximum // 2, maximum)} == {width}


@pytest.mark.parametrize(("encoder", "reader_name", "width", "maximum"), INT_CODECS)
def test_fixed_width_integers_round_trip_through_reader(encoder, reader_name, width, maximum):
    """A value written by ``uN`` is read back unchanged by the matching ``read_uN``."""
    reader_method = reader_name
    for value in (0, 1, maximum // 2, maximum - 1, maximum):
        encoded = encoder(value)
        assert encoded == value.to_bytes(width, "big")
        reader = Reader(encoded)
        assert getattr(reader, reader_method)() == value
        assert reader.at_end() and reader.offset == width
        # A second field after the first must still be reachable.
        reader = Reader(encoded + b"\x7f")
        assert getattr(reader, reader_method)() == value
        assert reader.read_u8() == 0x7F


@pytest.mark.parametrize(("encoder", "reader_name", "width", "maximum"), INT_CODECS)
def test_fixed_width_integers_reject_out_of_range_values(encoder, reader_name, width, maximum):
    """``int.to_bytes`` semantics are inherited: no silent truncation of oversized values."""
    with pytest.raises(OverflowError):
        encoder(maximum + 1)
    with pytest.raises(OverflowError):
        encoder(-1)


# ------------------------------------------------------------------ reader edges


def test_reader_bookkeeping_tracks_the_cursor():
    """``offset``, ``remaining``, ``at_end`` and ``expect_end`` agree at every step."""
    reader = Reader(b"\x01\x02\x03\x04")
    assert (reader.offset, reader.remaining(), reader.at_end()) == (0, 4, False)
    assert reader.read_bytes(3) == b"\x01\x02\x03"
    assert (reader.offset, reader.remaining(), reader.at_end()) == (3, 1, False)
    with pytest.raises(DecodeError):
        reader.expect_end()
    assert reader.read_u8() == 0x04
    reader.expect_end()
    assert reader.at_end() and reader.remaining() == 0


@pytest.mark.parametrize(("method", "encoded", "width"), [
    pytest.param("read_u8", u8(7), 1, id="u8"),
    pytest.param("read_u16", u16(7), 2, id="u16"),
    pytest.param("read_u24", u24(7), 3, id="u24"),
    pytest.param("read_u32", u32(7), 4, id="u32"),
])
def test_truncated_reads_raise_decode_error_naming_the_offset(method, encoded, width):
    """A short field raises ``DecodeError`` that states the offset it ran out at."""
    for short in (encoded[: width - 1], b""):
        with pytest.raises(DecodeError) as excinfo:
            getattr(Reader(short), method)()
        assert "offset 0" in str(excinfo.value)


def test_truncation_error_names_the_offset_after_a_successful_read():
    """The offset in the message is the position of the *missing* field, not of the reader."""
    reader = Reader(b"\x01\x02\x03")
    assert reader.read_u16() == 0x0102
    with pytest.raises(DecodeError) as excinfo:
        reader.read_u16()
    message = str(excinfo.value)
    assert "offset 2" in message
    assert "only 1 remain" in message


def test_read_bytes_rejects_a_negative_count_without_moving():
    """A negative read is a caller bug, reported as ``DecodeError``, and consumes nothing."""
    reader = Reader(b"abc")
    with pytest.raises(DecodeError) as excinfo:
        reader.read_bytes(-1)
    assert "negative" in str(excinfo.value)
    assert (reader.offset, reader.remaining(), reader.read_bytes(3)) == (0, 3, b"abc")


# ----------------------------------------------------------------- vector codecs


@pytest.mark.parametrize(("encoder", "reader_name", "maximum"), VECTOR_CODECS)
def test_length_prefixed_vectors_write_the_prefix_and_round_trip(encoder, reader_name, maximum):
    """The payload is preceded by its own length in the width the encoder names."""
    prefix_width = {"read_vec8": 1, "read_vec16": 2, "read_vec24": 3}[reader_name]
    for payload in (b"", b"\x00", b"x" * 7, bytes(range(255))):
        encoded = encoder(payload)
        assert encoded == len(payload).to_bytes(prefix_width, "big") + payload
        assert getattr(Reader(encoded), reader_name)() == payload


@pytest.mark.parametrize(("encoder", "reader_name", "maximum"), VECTOR_CODECS)
def test_length_prefixed_vectors_accept_the_maximum_and_reject_one_more(encoder, reader_name, maximum):
    """The largest representable payload encodes; one byte more raises ``ValueError``."""
    prefix_width = {"read_vec8": 1, "read_vec16": 2, "read_vec24": 3}[reader_name]
    encoded = encoder(b"\x5a" * maximum)
    assert len(encoded) == maximum + prefix_width
    assert encoded[:prefix_width] == maximum.to_bytes(prefix_width, "big")

    with pytest.raises(ValueError):
        encoder(b"\x5a" * (maximum + 1))


@pytest.mark.parametrize(("encoder", "reader_name", "maximum"), VECTOR_CODECS)
def test_reader_rejects_a_length_prefix_that_exceeds_the_buffer(encoder, reader_name, maximum):
    """A prefix promising more bytes than remain is a truncation, not a short read."""
    prefix_width = {"read_vec8": 1, "read_vec16": 2, "read_vec24": 3}[reader_name]
    body = b"abc"
    assert getattr(Reader(len(body).to_bytes(prefix_width, "big") + body), reader_name)() == body

    over_long = (len(body) + 5).to_bytes(prefix_width, "big") + body
    reader = Reader(over_long)
    with pytest.raises(DecodeError) as excinfo:
        getattr(reader, reader_name)()
    message = str(excinfo.value)
    assert f"need {len(body) + 5} bytes at offset {prefix_width}" in message
    assert "only 3 remain" in message


def test_read_vec16_rejects_a_prefix_larger_than_the_remaining_bytes():
    """Pins the exact over-length case used by the handshake decoders."""
    with pytest.raises(DecodeError) as excinfo:
        Reader(u16(5) + b"abc").read_vec16()
    assert "need 5 bytes at offset 2" in str(excinfo.value)


# --------------------------------------------------------------- handshake framing


@pytest.mark.parametrize(("message_type", "body"), [
    pytest.param(1, b"", id="empty-body"),
    pytest.param(20, b"\x00" * 32, id="finished"),
    pytest.param(11, b"x" * 300, id="certificate-sized"),
])
def test_handshake_framing_round_trips_type_and_body(message_type, body):
    """Framing is ``type || u24 length || body`` and splits back to the same pair."""
    frame = handshake_message(message_type, body)
    assert frame == u8(message_type) + u24(len(body)) + body
    assert split_handshake_message(frame) == (message_type, body)


def test_split_handshake_message_rejects_trailing_bytes():
    """A frame with bytes after the declared body is malformed, not merely longer."""
    frame = handshake_message(20, b"abc")
    with pytest.raises(DecodeError) as excinfo:
        split_handshake_message(frame + b"\x00")
    assert "trailing" in str(excinfo.value)

    with pytest.raises(DecodeError):
        split_handshake_message(b"")


def test_split_handshake_message_rejects_a_body_shorter_than_its_header():
    """A declared length longer than the buffer is reported as truncation at the body."""
    with pytest.raises(DecodeError) as excinfo:
        split_handshake_message(u8(20) + u24(8) + b"abc")
    assert "need 8 bytes at offset 4" in str(excinfo.value)
