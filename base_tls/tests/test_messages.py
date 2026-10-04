"""Contract tests for :mod:`tls.handshake.messages`.

What each test pins:

* every handshake message the hybrid handshake uses encodes to the RFC 8446 shape
  and decodes back to the same field values;
* the two post-quantum extensions are mandatory: a ClientHello without
  ``pq_key_share`` and a ServerHello without ``pq_ciphertext`` are rejected at
  decode time, so a peer cannot silently fall back to a classical-only exchange;
* truncation and trailing bytes are :class:`~tls.errors.DecodeError`, never a
  short or padded value;
* ``Certificate`` preserves the CA signature bytes that authenticate both public
  keys, and ``HybridCertificateVerify`` spends exactly eight bytes on framing.

``CertificateVerify`` and ``Finished`` carry opaque bodies at this layer: the
dual-signature structure lives in ``HybridCertificateVerify``, so those two
decoders are tested as pass-through containers.
"""

from __future__ import annotations

import pytest

from tls.config import HybridTLSConfig
from tls.credentials import CertificateAuthority, ServerCredentials
from tls.errors import DecodeError, HybridTLSError
from tls.handshake.certificate_verify import HybridCertificateVerify
from tls.handshake.client import HybridClient
from tls.handshake.messages import (
    CERTIFICATE,
    CERTIFICATE_VERIFY,
    CLIENT_HELLO,
    ENCRYPTED_EXTENSIONS,
    EXTENSION_KEY_SHARE,
    EXTENSION_PQ_CIPHERTEXT,
    EXTENSION_PQ_KEY_SHARE,
    EXTENSION_SIGNATURE_ALGORITHMS,
    EXTENSION_SUPPORTED_GROUPS,
    EXTENSION_SUPPORTED_VERSIONS,
    FINISHED,
    GROUPS,
    LEGACY_VERSION,
    SERVER_HELLO,
    TLS13_VERSION,
    Certificate,
    CertificateVerify,
    ClientHello,
    EncryptedExtensions,
    Finished,
    HybridCertificateBody,
    KeyShareEntry,
    ServerHello,
)
from tls.handshake.server import HybridServer
from tls.wire import Reader, handshake_message, split_handshake_message, u16, vec8, vec16, vec24

# Sizes taken from the backends the profiles use, so the byte counts here are real.
ML_KEM_768_PUBLIC_KEY_BYTES = 1184
ML_KEM_768_CIPHERTEXT_BYTES = 1088
ML_KEM_768_SCHEME_ID = 0x0A02
FALCON_512_PUBLIC_KEY_BYTES = 897
FALCON_512_SCHEME_ID = 0x0F51
FALCON_512_SIGNATURE_BYTES = 666
ECDSA_P256_SCHEME_ID = 0x0403
ECDSA_P256_SIGNATURE_BYTES = 70
X25519 = GROUPS["x25519"]


# ------------------------------------------------------------------- test data


def realistic_client_hello() -> ClientHello:
    """A ClientHello with production-shaped field values (X25519 + ML-KEM-768)."""
    return ClientHello(
        random=bytes(range(32)),
        cipher_suites=(0x1301,),
        supported_groups=(X25519,),
        key_share=KeyShareEntry(X25519, bytes(range(32, 64))),
        kem_scheme=ML_KEM_768_SCHEME_ID,
        pq_key_share=bytes(ML_KEM_768_PUBLIC_KEY_BYTES),
        signature_algorithms=(ECDSA_P256_SCHEME_ID, FALCON_512_SCHEME_ID),
        legacy_session_id=b"\x01\x02\x03\x04",
    )


def realistic_server_hello() -> ServerHello:
    """A ServerHello answering :func:`realistic_client_hello`."""
    return ServerHello(
        random=bytes(range(32, 64)),
        cipher_suite=0x1301,
        key_share=KeyShareEntry(X25519, bytes(range(64, 96))),
        pq_ciphertext=b"\x5a" * ML_KEM_768_CIPHERTEXT_BYTES,
        legacy_session_id=b"\x01\x02\x03\x04",
    )


def realistic_certificate_body() -> HybridCertificateBody:
    """The certified body: one identity binding an ECDSA key and a Falcon key."""
    return HybridCertificateBody(
        server_identity=b"server.example",
        classical_scheme=ECDSA_P256_SCHEME_ID,
        classical_public_key=b"\x04" + bytes(range(64)),
        pq_scheme=FALCON_512_SCHEME_ID,
        pq_public_key=bytes(FALCON_512_PUBLIC_KEY_BYTES),
    )


def realistic_certificate() -> Certificate:
    """A Certificate message carrying that body plus a DER-shaped CA signature."""
    return Certificate(
        body=realistic_certificate_body(),
        ca_signature=b"\x30\x45" + bytes(ECDSA_P256_SIGNATURE_BYTES - 2),
        extensions=((EXTENSION_SUPPORTED_VERSIONS, u16(TLS13_VERSION)),),
        certificate_request_context=b"",
    )


def realistic_certificate_verify() -> HybridCertificateVerify:
    """A dual-signature payload with one ECDSA signature and one Falcon signature."""
    return HybridCertificateVerify(
        classic_scheme=ECDSA_P256_SCHEME_ID,
        classic_signature=b"\x30\x44" + bytes(ECDSA_P256_SIGNATURE_BYTES - 2),
        pq_scheme=FALCON_512_SCHEME_ID,
        pq_signature=bytes(FALCON_512_SIGNATURE_BYTES),
    )


def build_extensions(entries: list[tuple[int, bytes]]) -> bytes:
    """Encode an extension block the way RFC 8446 section 4.2 lays it out."""
    return vec16(b"".join(u16(kind) + vec16(data) for kind, data in entries))


def split_extensions(block: bytes) -> list[tuple[int, bytes]]:
    """Parse an extension block back into ``(type, data)`` pairs."""
    reader = Reader(block)
    entries: list[tuple[int, bytes]] = []
    while not reader.at_end():
        kind = reader.read_u16()
        entries.append((kind, reader.read_vec16()))
    return entries


def client_hello_body_without_pq_key_share(body: bytes) -> bytes:
    """Re-encode a ClientHello body with the ``pq_key_share`` extension removed.

    The fixed prefix is copied verbatim from ``body``; only the extension block is
    rebuilt, so everything except the dropped extension is byte-identical.
    """
    reader = Reader(body)
    prefix = reader.read_bytes(2 + 32)
    session_id = reader.read_vec8()
    cipher_suites = reader.read_vec16()
    compression = reader.read_vec8()
    entries = split_extensions(reader.read_vec16())
    kept = [(kind, data) for kind, data in entries if kind != EXTENSION_PQ_KEY_SHARE]
    assert len(kept) == len(entries) - 1, "the pq_key_share extension was not present"
    return prefix + vec8(session_id) + vec16(cipher_suites) + vec8(compression) + build_extensions(kept)


def server_hello_body_without_pq_ciphertext(body: bytes) -> bytes:
    """Re-encode a ServerHello body with the ``pq_ciphertext`` extension removed."""
    reader = Reader(body)
    prefix = reader.read_bytes(2 + 32)
    session_id = reader.read_vec8()
    cipher_suite = u16(reader.read_u16())
    compression = reader.read_vec8()
    entries = split_extensions(reader.read_vec16())
    kept = [(kind, data) for kind, data in entries if kind != EXTENSION_PQ_CIPHERTEXT]
    assert len(kept) == len(entries) - 1, "the pq_ciphertext extension was not present"
    return prefix + vec8(session_id) + cipher_suite + vec8(compression) + build_extensions(kept)


# ------------------------------------------------------------------- round trips


def test_client_hello_round_trips_every_field_the_codec_defines():
    """Decode(encode(hello)) returns the same random, suites, shares and PQ fields."""
    hello = realistic_client_hello()
    decoded = ClientHello.decode(hello.encode())

    assert decoded.random == hello.random == bytes(range(32))
    assert decoded.cipher_suites == hello.cipher_suites == (0x1301,)
    assert decoded.key_share == hello.key_share
    assert decoded.key_share.group == X25519
    assert len(decoded.key_share.key_exchange) == 32
    assert decoded.kem_scheme == ML_KEM_768_SCHEME_ID
    assert decoded.pq_key_share == hello.pq_key_share
    assert len(decoded.pq_key_share) == ML_KEM_768_PUBLIC_KEY_BYTES
    assert decoded.legacy_session_id == hello.legacy_session_id == b"\x01\x02\x03\x04"
    assert decoded.supported_groups == hello.supported_groups == (X25519,)
    assert decoded.signature_algorithms == hello.signature_algorithms


def test_client_hello_vec16_lists_roundtrip_exactly():
    """A ClientHello survives encode/decode with every field intact.

    ``supported_groups`` and ``signature_algorithms`` are ``vector<u16>`` on the
    wire, so a decoder that reads the extension payload as bare code points eats the
    inner length prefix and returns ``(2, 29)`` instead of ``(29,)``. This test pins
    the whole message, which is the assertion that catches that class of defect.
    """
    hello = realistic_client_hello()
    decoded = ClientHello.decode(hello.encode())

    assert decoded == hello
    assert decoded.supported_groups == (X25519,)
    assert decoded.signature_algorithms == (ECDSA_P256_SCHEME_ID, FALCON_512_SCHEME_ID)


def test_client_hello_framing_round_trips_through_the_message_layer():
    """The framed message keeps its type byte and body length."""
    hello = realistic_client_hello()
    frame = hello.to_message()
    message_type, body = split_handshake_message(frame)
    assert message_type == CLIENT_HELLO == 1
    assert len(body) == len(hello.encode())
    assert ClientHello.decode(body) == ClientHello.decode(hello.encode())


def test_server_hello_round_trips_every_field():
    """Decode(encode(server_hello)) returns the same share and KEM ciphertext."""
    hello = realistic_server_hello()
    decoded = ServerHello.decode(hello.encode())

    assert decoded == hello
    assert decoded.random == hello.random
    assert decoded.cipher_suite == 0x1301
    assert decoded.key_share == hello.key_share
    assert len(decoded.pq_ciphertext) == ML_KEM_768_CIPHERTEXT_BYTES
    assert decoded.legacy_session_id == hello.legacy_session_id
    # The extension transcript is decode-side metadata, so it is compared explicitly
    # instead of by ``==``. It is what the client's unsupported_extension check reads:
    # the set must be exactly what the encoder emitted, no more and no less.
    assert decoded.extension_types == (
        EXTENSION_SUPPORTED_VERSIONS,
        EXTENSION_KEY_SHARE,
        EXTENSION_PQ_CIPHERTEXT,
    )
    message_type, body = split_handshake_message(hello.to_message())
    assert message_type == SERVER_HELLO == 2 and ServerHello.decode(body) == hello


def test_encrypted_extensions_round_trips_its_extension_list():
    """EncryptedExtensions preserves extension order and empty payloads."""
    empty = EncryptedExtensions()
    assert EncryptedExtensions.decode(empty.encode()) == empty
    assert empty.encode() == vec16(b"")

    populated = EncryptedExtensions(extensions=((7, b"a"), (EXTENSION_PQ_KEY_SHARE + 1, b"")))
    decoded = EncryptedExtensions.decode(populated.encode())
    assert decoded == populated
    assert decoded.extensions == populated.extensions
    assert split_handshake_message(populated.to_message())[0] == ENCRYPTED_EXTENSIONS == 8


def test_certificate_round_trips_the_body_and_the_ca_signature_bytes():
    """The CA signature survives the round trip byte for byte, framing included."""
    certificate = realistic_certificate()
    decoded = Certificate.decode(certificate.encode())

    assert decoded == certificate
    assert decoded.ca_signature == certificate.ca_signature
    assert len(decoded.ca_signature) == ECDSA_P256_SIGNATURE_BYTES
    assert decoded.body == certificate.body
    assert decoded.body.classical_public_key == certificate.body.classical_public_key
    assert decoded.body.pq_public_key == certificate.body.pq_public_key
    assert decoded.extensions == certificate.extensions
    assert decoded.certificate_request_context == certificate.certificate_request_context
    assert split_handshake_message(certificate.to_message())[0] == CERTIFICATE == 11


def test_hybrid_certificate_body_round_trips_both_public_keys():
    """The signed body decodes back to the identity, both schemes and both keys."""
    body = realistic_certificate_body()
    decoded = HybridCertificateBody.decode(body.encode())

    assert decoded == body
    assert decoded.server_identity == b"server.example"
    assert decoded.classical_scheme == ECDSA_P256_SCHEME_ID
    assert len(decoded.classical_public_key) == 65
    assert decoded.pq_scheme == FALCON_512_SCHEME_ID
    assert len(decoded.pq_public_key) == FALCON_512_PUBLIC_KEY_BYTES
    # The encoded body is the exact byte string the CA signs.
    assert body.encode() == (
        vec16(b"server.example")
        + u16(ECDSA_P256_SCHEME_ID)
        + vec16(body.classical_public_key)
        + u16(FALCON_512_SCHEME_ID)
        + vec16(body.pq_public_key)
    )


def test_certificate_verify_payload_round_trips_both_signatures():
    """The dual-signature container preserves both schemes and both signature bytes."""
    payload = realistic_certificate_verify()
    decoded = HybridCertificateVerify.decode(payload.encode())
    assert decoded == payload

    message = CertificateVerify(payload=payload.encode()).to_message()
    message_type, body = split_handshake_message(message)
    assert message_type == CERTIFICATE_VERIFY == 15
    assert HybridCertificateVerify.decode(CertificateVerify.decode(body).payload) == payload


def test_finished_round_trips_its_verify_data():
    """Finished carries exactly the verify_data bytes it was given."""
    finished = Finished(verify_data=bytes(range(32)))
    assert Finished.decode(finished.encode()) == finished
    message_type, body = split_handshake_message(finished.to_message())
    assert message_type == FINISHED == 20 and body == finished.verify_data


def test_opaque_bodies_are_passed_through_unchanged():
    """CertificateVerify/Finished are containers: their structure is not at this layer.

    This is why the truncation tests below cannot cover them -- a bare body is
    accepted as-is, and only ``HybridCertificateVerify`` can reject a malformed
    dual-signature payload.
    """
    for raw in (b"", b"\x00", b"not-really-a-signature"):
        assert CertificateVerify.decode(raw).payload == raw
        assert Finished.decode(raw).verify_data == raw


# --------------------------------------------------------------- downgrade cases


def test_the_extension_rewriting_helpers_are_byte_faithful():
    """Control: rebuilding an extension block with nothing dropped reproduces the body."""
    hello = realistic_client_hello()
    reader = Reader(hello.encode())
    prefix = reader.read_bytes(2 + 32)  # legacy_version || random
    session_id = reader.read_vec8()
    cipher_suites = reader.read_vec16()
    compression = reader.read_vec8()
    entries = split_extensions(reader.read_vec16())
    assert reader.at_end()
    rebuilt = prefix + vec8(session_id) + vec16(cipher_suites) + vec8(compression) + build_extensions(entries)
    assert rebuilt == hello.encode()
    assert [kind for kind, _ in entries] == [
        EXTENSION_SUPPORTED_VERSIONS,
        EXTENSION_SUPPORTED_GROUPS,
        EXTENSION_SIGNATURE_ALGORITHMS,
        EXTENSION_KEY_SHARE,
        EXTENSION_PQ_KEY_SHARE,
    ]

    server_hello = realistic_server_hello()
    reader = Reader(server_hello.encode())
    prefix = reader.read_bytes(2 + 32)  # legacy_version || random
    session_id = reader.read_vec8()
    cipher_suite = u16(reader.read_u16())
    compression = reader.read_vec8()
    server_entries = split_extensions(reader.read_vec16())
    assert reader.at_end()
    rebuilt_server = prefix + vec8(session_id) + cipher_suite + vec8(compression) + build_extensions(server_entries)
    assert rebuilt_server == server_hello.encode()
    assert [kind for kind, _ in server_entries] == [
        EXTENSION_SUPPORTED_VERSIONS,
        EXTENSION_KEY_SHARE,
        EXTENSION_PQ_CIPHERTEXT,
    ]


def test_client_hello_without_the_pq_key_share_decodes_as_classical_only():
    """A stripped ClientHello is well formed, and the PROFILE decides its fate.

    The decoder must accept it — a classical-only server has to be able to read such a
    message — and report the absence as ``None``. Rejecting it is the hybrid server's
    call, which is where the downgrade is actually blocked.
    """
    hello = realistic_client_hello()
    stripped = client_hello_body_without_pq_key_share(hello.encode())

    assert stripped != hello.encode()
    decoded = ClientHello.decode(stripped)

    assert decoded.pq_key_share is None
    assert decoded.kem_scheme is None
    # Everything else survives the strip, so the absence is the only difference.
    assert decoded.key_share == hello.key_share
    assert decoded.cipher_suites == hello.cipher_suites


def test_client_hello_without_a_classical_key_share_is_rejected_too():
    """The classical share is equally mandatory: dropping it is not a valid message."""
    hello = realistic_client_hello()
    reader = Reader(hello.encode())
    prefix = reader.read_bytes(2 + 32)
    session_id = reader.read_vec8()
    cipher_suites = reader.read_vec16()
    compression = reader.read_vec8()
    entries = split_extensions(reader.read_vec16())
    kept = [(kind, data) for kind, data in entries if kind != EXTENSION_KEY_SHARE]
    assert len(kept) == len(entries) - 1
    stripped = prefix + vec8(session_id) + vec16(cipher_suites) + vec8(compression) + build_extensions(kept)

    with pytest.raises(DecodeError) as excinfo:
        ClientHello.decode(stripped)
    assert "key_share" in str(excinfo.value)


def test_server_hello_without_the_pq_ciphertext_decodes_as_classical_only():
    """The mirror of the ClientHello case: the profile, not the codec, rejects it."""
    server_hello = realistic_server_hello()
    stripped = server_hello_body_without_pq_ciphertext(server_hello.encode())

    assert stripped != server_hello.encode()
    decoded = ServerHello.decode(stripped)

    assert decoded.pq_ciphertext is None
    assert decoded.key_share == server_hello.key_share
    assert decoded.cipher_suite == server_hello.cipher_suite
    # Rebinding every other extension changes nothing: the missing one is fatal.
    reader = Reader(stripped)
    reader.read_bytes(2 + 32)
    reader.read_vec8()
    reader.read_u16()
    reader.read_vec8()
    remaining_kinds = [kind for kind, _ in split_extensions(reader.read_vec16())]
    assert EXTENSION_PQ_CIPHERTEXT not in remaining_kinds
    assert remaining_kinds == [EXTENSION_SUPPORTED_VERSIONS, EXTENSION_KEY_SHARE]


def test_the_server_refuses_a_client_hello_that_dropped_the_pq_key_share(default_profile):
    """The downgrade is blocked at the handshake boundary, not only by the codec."""
    authority = CertificateAuthority(default_profile.classical())
    credentials = ServerCredentials(default_profile)
    server = HybridServer(default_profile, credentials, credentials.bind_to(authority))
    client = HybridClient(default_profile, authority)

    # Control: the same server accepts the untouched ClientHello.
    untouched = client.create_client_hello()
    assert split_handshake_message(server.receive_client_hello(untouched))[0] == SERVER_HELLO

    original_body = split_handshake_message(untouched)[1]
    stripped_frame = handshake_message(
        CLIENT_HELLO, client_hello_body_without_pq_key_share(original_body)
    )
    before = (server.transcript.byte_count, server.client_kem_public, server.hybrid_secret)
    with pytest.raises(HybridTLSError) as excinfo:
        server.receive_client_hello(stripped_frame)
    assert "pq_key_share" in str(excinfo.value)

    # The rejected message must leave no trace: no transcript entry, no key material.
    assert server.transcript.byte_count == before[0]
    assert server.client_kem_public is before[1]
    assert server.hybrid_secret is before[2]


# ------------------------------------------------------ truncation and padding


MESSAGE_BODIES = [
    pytest.param(ClientHello.decode, realistic_client_hello, id="ClientHello"),
    pytest.param(ServerHello.decode, realistic_server_hello, id="ServerHello"),
    pytest.param(
        EncryptedExtensions.decode,
        lambda: EncryptedExtensions(extensions=((1, b"a"), (2, b"bb"))),
        id="EncryptedExtensions",
    ),
    pytest.param(Certificate.decode, realistic_certificate, id="Certificate"),
    pytest.param(HybridCertificateBody.decode, realistic_certificate_body, id="HybridCertificateBody"),
    pytest.param(HybridCertificateVerify.decode, realistic_certificate_verify, id="HybridCertificateVerify"),
]


@pytest.mark.parametrize(("decoder", "builder"), MESSAGE_BODIES)
def test_a_truncated_body_raises_decode_error(decoder, builder):
    """Removing the last byte of a framed body is a truncation, never a short value."""
    body = builder().encode()
    assert decoder(body) is not None
    with pytest.raises(DecodeError):
        decoder(body[:-1])


@pytest.mark.parametrize(("decoder", "builder"), MESSAGE_BODIES)
def test_a_body_with_trailing_bytes_raises_decode_error(decoder, builder):
    """Extra bytes after the declared body are rejected rather than ignored."""
    body = builder().encode()
    for padding in (b"\x00", b"\x00\x01\x02"):
        with pytest.raises(DecodeError) as excinfo:
            decoder(body + padding)
        assert "trailing" in str(excinfo.value)


def test_an_empty_body_raises_decode_error():
    """Every structured decoder rejects an empty body instead of returning defaults."""
    for decoder in (ClientHello.decode, ServerHello.decode, HybridCertificateBody.decode):
        with pytest.raises(DecodeError):
            decoder(b"")


def test_a_certificate_message_with_no_entry_is_rejected():
    """``Certificate`` requires exactly one certificate; an empty list is malformed."""
    empty_body = vec8(b"") + vec24(b"")
    with pytest.raises(DecodeError) as excinfo:
        Certificate.decode(empty_body)
    assert "no certificate" in str(excinfo.value)


def test_a_client_hello_with_a_wrong_legacy_version_is_rejected():
    """The legacy_version check runs first, before any extension is read."""
    body = realistic_client_hello().encode()
    wrong = u16(LEGACY_VERSION ^ 0x0001) + body[2:]
    with pytest.raises(DecodeError) as excinfo:
        ClientHello.decode(wrong)
    assert "legacy_version" in str(excinfo.value)


# ------------------------------------------------------------- payload accounting


def test_certificate_verify_payload_length_is_the_sum_of_fields_plus_framing():
    """The payload is ``u16 scheme || vec16 sig`` twice: eight framing bytes exactly."""
    payload = realistic_certificate_verify()
    encoded = payload.encode()
    expected_framing = 2 + 2 + 2 + 2  # classic scheme, classic length, pq scheme, pq length

    assert len(encoded) == (
        len(payload.classic_signature) + len(payload.pq_signature) + expected_framing
    )
    assert len(encoded) == ECDSA_P256_SIGNATURE_BYTES + FALCON_512_SIGNATURE_BYTES + 8
    assert payload.byte_count == len(encoded)
    assert payload.overhead_bytes() == expected_framing == 8
    assert sum(
        len(field)
        for field in (payload.classic_signature, payload.pq_signature)
    ) == len(encoded) - payload.overhead_bytes()


def test_certificate_verify_overhead_is_independent_of_the_signature_sizes():
    """Framing is a constant eight bytes whatever the two backends produce."""
    for classic_size, pq_size in ((8, 0), (0, 8), (70, 666), (72, 4626)):
        payload = HybridCertificateVerify(
            classic_scheme=ECDSA_P256_SCHEME_ID,
            classic_signature=bytes(classic_size),
            pq_scheme=FALCON_512_SCHEME_ID,
            pq_signature=bytes(pq_size),
        )
        assert payload.overhead_bytes() == 8
        assert len(payload.encode()) == classic_size + pq_size + 8
        assert HybridCertificateVerify.decode(payload.encode()) == payload
