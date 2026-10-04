"""Canonical DER boundaries and the exact X.509 alternative signing input."""
import pytest

from tls.der import (DerError, algorithm_identifier, algorithm_oid, bit_string,
                     bit_string_bytes, elements, extension_fields, oid, oid_text,
                     pre_tbs, single, tbs_extensions, tlv)


@pytest.mark.parametrize("length", [0, 1, 127, 128, 255, 256, 65535, 65536])
def test_length_boundaries(length):
    data = b"x" * length
    encoded = tlv(4, data)
    assert single(encoded, 4).value == data
    assert single(encoded, 4).encoded == encoded
    assert encoded[1] == (length if length < 128 else 0x80 + (length.bit_length()+7)//8)


@pytest.mark.parametrize("data", [b"\x04", b"\x04\x80\x00\x00", b"\x04\x81\x01x",
    b"\x04\x82\x00\x80" + b"x"*128, b"\x04\x81", b"\x04\x02x", b"\x1f\x00",
    b"\x04\x85\x01\x00\x00\x00\x00", b"\x04\x00x"])
def test_malformed_lengths_and_tags(data):
    with pytest.raises(DerError):
        single(data, 4)


@pytest.mark.parametrize("identifier", ["2.5.29.72", "2.5.29.73", "2.5.29.74",
    "1.3.6.1.4.1.99999.2.3", "2.16.840.1.101.3.4.3.17", "2.999.0.123456"])
def test_oid_round_trip(identifier):
    assert oid_text(oid(identifier)) == identifier
    assert algorithm_oid(algorithm_identifier(identifier)) == identifier


@pytest.mark.parametrize("data", [b"\x06\x00", b"\x06\x01\x80", b"\x06\x02\x80\x01",
    tlv(0x30, oid("2.5.29.73")+tlv(5, b"")), tlv(3, b"\x01\x00")])
def test_noncanonical_oid_algid_and_bit_string(data):
    operation = oid_text if data[0] == 6 else (algorithm_oid if data[0] == 0x30 else bit_string_bytes)
    with pytest.raises(DerError):
        operation(data)


def extension(identifier, value, critical=False):
    return tlv(0x30, oid(identifier) + (tlv(1, b"\xff") if critical else b"") + tlv(4, value))


def tbs(exts, version=True):
    mandatory = tlv(2, b"\x01") + algorithm_identifier("1.2.840.10045.4.3.2")
    mandatory += tlv(0x30, b"")*4  # issuer, validity, subject, SPKI are opaque here
    return tlv(0x30, (tlv(0xA0, tlv(2, b"\x02")) if version else b"") + mandatory
               + tlv(0xA3, tlv(0x30, b"".join(exts))))


@pytest.mark.parametrize("version", [False, True])
def test_pre_tbs_removes_signature_and_74_but_retains_73(version):
    exts = [extension("2.5.29.72", b"key"), extension("2.5.29.73", b"algorithm"),
            extension("2.5.29.74", bit_string(b"signature")), extension("1.2.3", b"other")]
    before = tbs(exts, version)
    expected_fields = list(elements(single(before, 0x30).value))
    del expected_fields[2 if version else 1]
    expected_fields[-1] = single(tlv(0xA3, tlv(0x30, exts[0]+exts[1]+exts[3])), 0xA3)
    assert pre_tbs(before) == tlv(0x30, b"".join(x.encoded for x in expected_fields))
    assert exts[1] in pre_tbs(before)
    assert pre_tbs(before) == pre_tbs(tbs([exts[0], exts[1], exts[3]], version))


def test_extension_duplicates_and_explicit_default_false_are_rejected():
    duplicate = extension("2.5.29.73", b"algorithm")
    with pytest.raises(DerError, match="duplicate"):
        tbs_extensions(tbs([duplicate, duplicate]))
    with pytest.raises(DerError, match="BOOLEAN"):
        extension_fields(tlv(0x30, oid("1.2.3")+tlv(1, b"\0")+tlv(4, b"")))


def test_pre_tbs_removes_empty_extension_wrapper():
    before = tbs([extension("2.5.29.74", bit_string(b"signature"))])
    assert all(x.tag != 0xA3 for x in elements(single(pre_tbs(before), 0x30).value))
