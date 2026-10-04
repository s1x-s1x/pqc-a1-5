"""Bounded, canonical DER operations for the X.509 alternative signature profile.

Untouched fields are copied byte-for-byte. Only enclosing lengths are rebuilt;
no search/replace on arbitrary certificate bytes is used.
"""
from __future__ import annotations

from dataclasses import dataclass

MAX_DER_BYTES = 1 << 20
ALT_VALUE_OID = "2.5.29.74"


class DerError(ValueError):
    pass


@dataclass(frozen=True)
class Element:
    tag: int
    value: bytes
    encoded: bytes


def tlv(tag: int, value: bytes) -> bytes:
    value = bytes(value)
    if not 0 <= tag <= 255 or tag & 31 == 31 or len(value) > MAX_DER_BYTES:
        raise DerError("unsupported DER tag or length")
    n = len(value)
    length = bytes([n]) if n < 128 else bytes([0x80 + (n.bit_length() + 7) // 8]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + length + value


def elements(data: bytes) -> tuple[Element, ...]:
    data = bytes(data)
    if len(data) > MAX_DER_BYTES:
        raise DerError("DER exceeds profile limit")
    offset, result = 0, []
    while offset < len(data):
        start = offset
        if offset + 2 > len(data):
            raise DerError("truncated DER header")
        tag, first = data[offset:offset + 2]
        offset += 2
        if tag & 31 == 31:
            raise DerError("high-tag-number DER is outside this profile")
        if first < 128:
            length = first
        else:
            count = first & 127
            if count == 0 or count > 4 or offset + count > len(data):
                raise DerError("indefinite or truncated DER length")
            raw = data[offset:offset + count]
            if raw[0] == 0:
                raise DerError("nonminimal DER length")
            length = int.from_bytes(raw, "big")
            if length < 128:
                raise DerError("nonminimal long DER length")
            offset += count
        if length > len(data) - offset:
            raise DerError("truncated DER value")
        end = offset + length
        result.append(Element(tag, data[offset:end], data[start:end]))
        offset = end
    return tuple(result)


def single(data: bytes, tag: int) -> Element:
    items = elements(data)
    if len(items) != 1 or items[0].tag != tag:
        raise DerError(f"expected one DER tag {tag:#x}")
    return items[0]


def _base128(number: int) -> bytes:
    if number < 0:
        raise DerError("negative OID arc")
    values = [number & 127]
    while number >> 7:
        number >>= 7
        values.append(128 | (number & 127))
    return bytes(reversed(values))


def oid(dotted: str) -> bytes:
    arcs = [int(x) for x in dotted.split(".")]
    if len(arcs) < 2 or arcs[0] not in (0, 1, 2) or arcs[1] < 0 or (arcs[0] < 2 and arcs[1] > 39):
        raise DerError("invalid OID")
    return tlv(6, b"".join(_base128(x) for x in [40 * arcs[0] + arcs[1], *arcs[2:]]))


def oid_text(encoded: bytes) -> str:
    value = single(encoded, 6).value
    if not value:
        raise DerError("empty OID")
    arcs, number, continued = [], 0, False
    for byte in value:
        if not continued and byte == 128:
            raise DerError("nonminimal OID arc")
        number = (number << 7) | (byte & 127)
        continued = bool(byte & 128)
        if not continued:
            arcs.append(number)
            number = 0
    if continued:
        raise DerError("truncated OID arc")
    first = min(arcs[0] // 40, 2)
    return ".".join(map(str, [first, arcs[0] - first * 40, *arcs[1:]]))


def algorithm_identifier(dotted: str) -> bytes:
    return tlv(0x30, oid(dotted))


def algorithm_oid(data: bytes) -> str:
    fields = elements(single(data, 0x30).value)
    if len(fields) != 1:
        raise DerError("this profile requires absent AlgorithmIdentifier parameters")
    return oid_text(fields[0].encoded)


def bit_string(data: bytes) -> bytes:
    return tlv(3, b"\0" + bytes(data))


def bit_string_bytes(encoded: bytes) -> bytes:
    value = single(encoded, 3).value
    if not value or value[0] != 0:
        raise DerError("public keys and signatures require zero unused bits")
    return value[1:]


def extension_fields(encoded: bytes) -> tuple[str, bool, bytes]:
    fields = elements(single(encoded, 0x30).value)
    if len(fields) not in (2, 3):
        raise DerError("invalid Extension field count")
    identifier = oid_text(fields[0].encoded)
    critical = False
    if len(fields) == 3:
        if fields[1].tag != 1 or fields[1].value != b"\xff":
            raise DerError("critical BOOLEAN must be canonical TRUE; default FALSE is omitted")
        critical = True
    if fields[-1].tag != 4:
        raise DerError("Extension requires OCTET STRING")
    return identifier, critical, fields[-1].value


def tbs_fields(data: bytes) -> tuple[tuple[Element, ...], int]:
    fields = elements(single(data, 0x30).value)
    start = 1 if fields and fields[0].tag == 0xA0 else 0
    if start:
        version = single(fields[0].value, 2).value
        if version != b"\x02":
            raise DerError("alternative-signature profile requires X.509 v3")
    if len(fields) < start + 6:
        raise DerError("truncated TBSCertificate")
    tags = [2, 0x30, 0x30, 0x30, 0x30, 0x30]
    if [x.tag for x in fields[start:start + 6]] != tags:
        raise DerError("unexpected TBSCertificate mandatory fields")
    previous = 0x80
    for field in fields[start + 6:]:
        if field.tag not in (0x81, 0x82, 0xA3) or field.tag <= previous:
            raise DerError("unexpected or duplicate optional TBSCertificate fields")
        previous = field.tag
    return fields, start + 1


def tbs_extensions(data: bytes) -> tuple[Element, ...]:
    fields, _ = tbs_fields(data)
    wrapper = next((x for x in fields if x.tag == 0xA3), None)
    if wrapper is None:
        return ()
    items = elements(single(wrapper.value, 0x30).value)
    identifiers = [extension_fields(x.encoded)[0] for x in items]
    if len(set(identifiers)) != len(identifiers):
        raise DerError("duplicate certificate extension OID")
    return items


def pre_tbs(tbs_certificate: bytes) -> bytes:
    """Remove TBS.signature and extension 74, retaining extension 73 and all else."""
    fields, signature_index = tbs_fields(tbs_certificate)
    exts = tbs_extensions(tbs_certificate)
    kept = b"".join(x.encoded for x in exts if extension_fields(x.encoded)[0] != ALT_VALUE_OID)
    result = []
    for index, field in enumerate(fields):
        if index == signature_index:
            continue
        if field.tag == 0xA3:
            # All profile certificates have ordinary extensions. Remove an empty
            # wrapper if the only extension was altSignatureValue.
            if kept:
                result.append(tlv(0xA3, tlv(0x30, kept)))
        else:
            result.append(field.encoded)
    return tlv(0x30, b"".join(result))
