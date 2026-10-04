"""Regression tests for the negotiation, codepoint, record-limit and budget fixes.

An independent attack package (`hybrid-tls13-攻击包.zip`, cases A/F/D/J) showed that this
implementation never looked at the TLS 1.3 negotiation fields at all: a server could echo a
session id the client never sent, answer in TLS 1.2, omit ``supported_versions`` entirely,
put its ``key_share`` group outside the ``supported_groups`` it offered, announce ``[zlib]``
compression, or select a suite the client never offered — and the handshake completed. It
also showed that the cipher-suite code point was decoupled from the parameters it names, that
the record counter could run to ``2**64`` before anything objected, and that the loopback
driver rebuilt its read deadline for every frame.

Each test below is one of those, written against the message objects or the layer directly
rather than by tampering with bytes, so a failure names the check that went missing.
"""

from __future__ import annotations

import pytest
from dataclasses import replace

from conftest import PROFILES
from cryptography.hazmat.primitives.asymmetric import ec

from tls.classical.ecdh import EcdheKeyPair
from tls.config import HybridTLSConfig
from tls.credentials import CertificateAuthority, ServerCredentials
from tls.errors import DecodeError, HandshakeError
from tls.handshake.client import HybridClient
from tls.handshake.messages import (
    EXTENSION_KEY_SHARE,
    EXTENSION_SUPPORTED_GROUPS,
    EXTENSION_SUPPORTED_VERSIONS,
    TLS13_VERSION,
    ClientHello,
    KeyShareEntry,
    ServerHello,
    _encode_extensions,
)
from tls.wire import u16, u8, vec8, vec16
from tls.handshake.server import HybridServer
from tls.record.aead import CONTENT_TYPE_APPLICATION_DATA, RecordLayer, get_aead_suite
from tls.transport import tcp as tcp_module

PROFILE = "ml-kem-768+ml-dsa-44"
SERVER_NAME = "server.example"
X25519 = 0x001D
SECP256R1 = 0x0017


def _server(config: HybridTLSConfig) -> HybridServer:
    authority = CertificateAuthority(config.classical())
    credentials = ServerCredentials(config, identity=SERVER_NAME.encode())
    return HybridServer(config, credentials, credentials.bind_to(authority))


def _client(config: HybridTLSConfig) -> HybridClient:
    return HybridClient(config, CertificateAuthority(config.classical()), trusted_name=SERVER_NAME)


def _hello(config: HybridTLSConfig, **overrides) -> ClientHello:
    """A real ClientHello for this profile, with fields the tests can break.

    Built by running this profile's own client, so every field holds genuine key material: a
    hand-built stand-in with an all-zero X25519 share is a low-order point and fails for
    reasons unrelated to the check under test.
    """
    client = _client(config)
    decoded = ClientHello.decode(client.create_client_hello()[4:])
    return replace(decoded, **overrides)


def _server_hello(config: HybridTLSConfig, **overrides) -> ServerHello:
    """A real ServerHello for this profile, built by running this profile's own server."""
    frame = _server(config).receive_client_hello(_hello(config).to_message())
    return replace(ServerHello.decode(frame[4:]), **overrides)


# ------------------------------------------------- the server checks what the client offered


def test_client_hello_without_tls13_in_supported_versions_is_rejected():
    """V-08: the client offered only TLS 1.2 and the server used TLS 1.3 anyway."""
    config = PROFILES[PROFILE]
    frame = _hello(config, supported_versions=(0x0303,)).to_message()
    with pytest.raises(HandshakeError) as excinfo:
        _server(config).receive_client_hello(frame)
    assert excinfo.value.step == "client_hello"
    assert "did not offer TLS 1.3" in excinfo.value.reason


def test_client_hello_without_the_supported_versions_extension_is_rejected():
    """The same check has to fire when the extension is absent, not only when it is wrong."""
    config = PROFILES[PROFILE]
    frame = _hello(config, supported_versions=()).to_message()
    with pytest.raises(HandshakeError) as excinfo:
        _server(config).receive_client_hello(frame)
    assert "no extension" in excinfo.value.reason


def test_client_hello_with_zlib_compression_is_rejected():
    """V-06: RFC 8446 section 4.1.2 requires the null compression method alone."""
    config = PROFILES[PROFILE]
    frame = _hello(config, legacy_compression_methods=(0x01,)).to_message()
    with pytest.raises(HandshakeError) as excinfo:
        _server(config).receive_client_hello(frame)
    assert "compression" in excinfo.value.reason


def test_key_share_outside_the_offered_supported_groups_is_rejected():
    """V-05: the group in ``key_share`` must be one the client said it supports."""
    config = PROFILES[PROFILE]
    frame = _hello(config, supported_groups=(SECP256R1,)).to_message()
    with pytest.raises(HandshakeError) as excinfo:
        _server(config).receive_client_hello(frame)
    assert "supported_groups" in excinfo.value.reason


def test_a_cipher_suite_the_client_never_offered_is_rejected():
    """V-07: the server may only select a suite the client listed."""
    config = PROFILES[PROFILE]
    frame = _hello(config, cipher_suites=(0x1302,)).to_message()
    with pytest.raises(HandshakeError) as excinfo:
        _server(config).receive_client_hello(frame)
    assert "did not offer cipher suite" in excinfo.value.reason


def test_signature_algorithms_missing_the_scheme_the_server_uses_is_rejected():
    """V-04: a server must not sign with a scheme the client never offered."""
    config = PROFILES[PROFILE]
    frame = _hello(config, signature_algorithms=(0x0807,)).to_message()  # ed25519 only
    with pytest.raises(HandshakeError) as excinfo:
        _server(config).receive_client_hello(frame)
    assert "signature scheme" in excinfo.value.reason


def test_a_well_formed_client_hello_is_still_accepted():
    """Positive control: the checks must not reject this profile's own ClientHello."""
    config = PROFILES[PROFILE]
    server_hello = _server(config).receive_client_hello(_hello(config).to_message())
    assert ServerHello.decode(server_hello[4:]).cipher_suite == config.cipher_suite_id


# ------------------------------------------- the client checks what the server answered


def test_server_hello_with_a_legacy_version_other_than_tls12_is_rejected():
    """V-03: ``legacy_version`` is 0x0303 even in TLS 1.3, and the client never looked."""
    config = PROFILES[PROFILE]
    client = _client(config)
    client.create_client_hello()
    frame = _server_hello(config, legacy_version=0x0301).to_message()
    with pytest.raises(HandshakeError) as excinfo:
        client.receive_server_hello(frame)
    assert excinfo.value.step == "server_hello"
    assert "legacy_version" in excinfo.value.reason


def test_server_hello_selecting_tls12_is_rejected():
    """V-02: a ``supported_versions`` that says 0x0303 is not a TLS 1.3 answer."""
    config = PROFILES[PROFILE]
    client = _client(config)
    client.create_client_hello()
    frame = _server_hello(config, supported_versions=(0x0303,)).to_message()
    with pytest.raises(HandshakeError) as excinfo:
        client.receive_server_hello(frame)
    assert "did not select TLS 1.3" in excinfo.value.reason


def test_server_hello_without_supported_versions_is_rejected():
    """V-02, second form: the extension being absent entirely used to be accepted."""
    config = PROFILES[PROFILE]
    client = _client(config)
    client.create_client_hello()
    frame = _server_hello(config, supported_versions=()).to_message()
    with pytest.raises(HandshakeError) as excinfo:
        client.receive_server_hello(frame)
    assert "no extension" in excinfo.value.reason


def test_a_forged_legacy_session_id_echo_is_rejected():
    """V-01: the client sent an empty session id and used to accept any echo."""
    config = PROFILES[PROFILE]
    client = _client(config)
    client.create_client_hello()
    frame = _server_hello(config, legacy_session_id=b"FORGED-SESSION-ID").to_message()
    with pytest.raises(HandshakeError) as excinfo:
        client.receive_server_hello(frame)
    assert "echo mismatch" in excinfo.value.reason


def test_a_group_the_client_never_offered_is_rejected():
    """The client-side mirror of V-05."""
    config = PROFILES[PROFILE]
    client = _client(config)
    client.create_client_hello()
    frame = _server_hello(config, key_share=KeyShareEntry(SECP256R1, bytes(65))).to_message()
    with pytest.raises(HandshakeError) as excinfo:
        client.receive_server_hello(frame)
    assert "never offered" in excinfo.value.reason


def test_a_non_null_compression_method_in_server_hello_is_rejected():
    config = PROFILES[PROFILE]
    client = _client(config)
    client.create_client_hello()
    frame = _server_hello(config, legacy_compression_methods=(0x01,)).to_message()
    with pytest.raises(HandshakeError) as excinfo:
        client.receive_server_hello(frame)
    assert "compression" in excinfo.value.reason


def test_a_server_hello_the_client_did_ask_for_is_still_accepted():
    """Positive control on the client side."""
    config = PROFILES[PROFILE]
    client = _client(config)
    client.create_client_hello()
    client.receive_server_hello(_server_hello(config).to_message())
    assert client.server_hello is not None


# ------------------------------------------------------------- structural: duplicate extensions


def test_a_duplicate_extension_is_rejected_at_decode():
    """V-09: a dict kept the last of two extensions with the same type."""
    config = PROFILES[PROFILE]
    hello = _hello(config)
    extensions = _encode_extensions(
        [
            (EXTENSION_SUPPORTED_VERSIONS, vec8(u16(TLS13_VERSION))),
            (EXTENSION_SUPPORTED_GROUPS, vec16(u16(X25519))),
            (EXTENSION_KEY_SHARE, vec16(hello.key_share.encode())),
            # The forgery: a second key_share, which RFC 8446 section 4.2 forbids.
            (EXTENSION_KEY_SHARE, vec16(hello.key_share.encode())),
        ]
    )
    body = (
        u16(0x0303)
        + hello.random
        + vec8(b"")
        + vec16(u16(config.cipher_suite_id))
        + vec8(b"\x00")
        + extensions
    )
    with pytest.raises(DecodeError) as excinfo:
        ClientHello.decode(body)
    assert "duplicate extension" in str(excinfo.value)


# --------------------------------------------------------------- the cipher-suite code point


def test_the_cipher_suite_code_point_matches_its_parameters():
    """V-10: 0x1301 names AES-128/SHA-256 and 0x1302 names AES-256/SHA-384, or nothing does."""
    assert HybridTLSConfig(aead="aes-128-gcm", hash_name="sha256").cipher_suite_id == 0x1301
    assert HybridTLSConfig(aead="aes-256-gcm", hash_name="sha384").cipher_suite_id == 0x1302


@pytest.mark.parametrize(
    ("aead", "hash_name"),
    [("aes-128-gcm", "sha384"), ("aes-256-gcm", "sha256")],
)
def test_a_combination_with_no_code_point_is_refused(aead, hash_name):
    """The parameter pair the audit used to expose the decoupling is refused outright."""
    with pytest.raises(ValueError) as excinfo:
        HybridTLSConfig(aead=aead, hash_name=hash_name).cipher_suite_id
    assert "no TLS 1.3 code point" in str(excinfo.value)


# --------------------------------------------------------------- the AEAD usage limit


def _layer() -> RecordLayer:
    return RecordLayer(get_aead_suite("aes-128-gcm"), bytes(range(16)), bytes(12))


def test_sealing_stops_at_the_aead_usage_limit():
    """V-17: RFC 8446 section 5.5 bounds AES-GCM at 2**24.5 records per key."""
    layer = _layer()
    layer._sequence = 2**25  # past the limit
    with pytest.raises(HandshakeError) as excinfo:
        layer.seal(CONTENT_TYPE_APPLICATION_DATA, b"one")
    assert excinfo.value.step == "record"
    assert "usage limit" in excinfo.value.reason


def test_opening_stops_at_the_aead_usage_limit():
    layer = _layer()
    layer._sequence = 2**25
    with pytest.raises(HandshakeError) as excinfo:
        layer.open(b"\x00" * 32, CONTENT_TYPE_APPLICATION_DATA)
    assert "usage limit" in excinfo.value.reason


def test_the_sequence_counter_overflow_is_no_longer_reachable():
    """The audit pushed the counter to 2**64-1 and got an OverflowError, not a rejection."""
    layer = _layer()
    layer._sequence = (1 << 64) - 1
    with pytest.raises(HandshakeError) as excinfo:
        layer.seal(CONTENT_TYPE_APPLICATION_DATA, b"one")
    assert "usage limit" in excinfo.value.reason


def test_ordinary_records_are_unaffected_by_the_limit():
    """Positive control: two directions with their own counters, as the handshake does."""
    sender, receiver = _layer(), _layer()
    record = sender.seal(CONTENT_TYPE_APPLICATION_DATA, b"payload")
    content_type, payload = receiver.open(record, CONTENT_TYPE_APPLICATION_DATA)
    assert (content_type, payload) == (CONTENT_TYPE_APPLICATION_DATA, b"payload")


# ------------------------------------------------------- one read budget per connection


def test_the_loopback_driver_builds_one_deadline_per_connection(monkeypatch):
    """V-19: the deadline used to be rebuilt for every frame, multiplying the budget."""
    config = PROFILE
    calls: list[float] = []
    original = tcp_module._frame_deadline

    def counting(timeout_seconds: float) -> float:
        calls.append(timeout_seconds)
        return original(timeout_seconds)

    monkeypatch.setattr(tcp_module, "_frame_deadline", counting)
    result = tcp_module.run_over_tcp(PROFILES[config], application_payload=b"ping")
    assert result.application_ok or result.server_error is None
    # One for the server's connection, one for the client's: not one per frame.
    assert len(calls) == 2, f"the driver built {len(calls)} deadlines for one connection"


def test_a_deadline_in_the_past_is_refused_without_reading():
    """The unit the budget rests on: an expired deadline raises instead of blocking."""
    import socket
    import time

    left, right = socket.socketpair()
    try:
        left.sendall((16).to_bytes(4, "big"))
        with pytest.raises(TimeoutError):
            tcp_module._recv_frame(right, deadline=time.monotonic() - 1.0)
    finally:
        left.close()
        right.close()


def test_the_protocol_document_no_longer_promises_a_record_header():
    """V-18: PROTOCOL.md described a 5-byte TLS record header this harness never produces."""
    text = (
        __import__("pathlib").Path(__file__).resolve().parents[1] / "docs" / "PROTOCOL.md"
    ).read_text(encoding="utf-8")
    section = text.split("## 8. Record layer", 1)[1].split("## 9.", 1)[0]
    assert "produces no TLS record header" in section
    assert "One real deviation from RFC 8446" in section
    # The old sentence must not survive as a bare promise; it appears only inside the
    # correction that quotes it.
    assert '**One deviation from RFC 8446 §5.2**: the outer record header carries' not in section


# --------------------------------------------- peer-controlled input is rejected by name


def test_a_31_byte_x25519_share_is_rejected_by_name():
    """B2/B3: the length check raised a bare ValueError, outside the documented contract."""
    with pytest.raises(HandshakeError) as excinfo:
        EcdheKeyPair.generate("x25519").exchange(bytes(31), step="server_hello")
    assert excinfo.value.step == "server_hello"
    assert "31 bytes" in excinfo.value.reason


def test_the_low_order_x25519_point_is_rejected_by_name():
    """D7: ``cryptography`` refuses it correctly, but the refusal used to escape as ValueError."""
    with pytest.raises(HandshakeError) as excinfo:
        EcdheKeyPair.generate("x25519").exchange(bytes(32), step="server_hello")
    assert "refused" in excinfo.value.reason


def test_a_truncated_kem_ciphertext_is_rejected_by_name():
    """B4/G2: the ciphertext is peer-controlled, so its length is checked before the backend."""
    config = PROFILES[PROFILE]
    client = _client(config)
    client.create_client_hello()
    short = _server_hello(config, pq_ciphertext=b"\x00" * 31)
    with pytest.raises(HandshakeError) as excinfo:
        client.receive_server_hello(short.to_message())
    assert "ciphertext" in excinfo.value.reason


def test_a_certificate_chain_check_refuses_a_foreign_issuer_key_type():
    """B10: ``_verify_signature`` used to hardcode ``ec.ECDSA`` for every issuer."""
    from cryptography.hazmat.primitives.asymmetric import ed25519

    from tls.pki import verify_chain

    issuer_key = ed25519.Ed25519PrivateKey.generate()
    root = _cert(
        subject="ed root",
        issuer_name="ed root",
        public_key=issuer_key.public_key(),
        signing_key=issuer_key,
        ca=True,
        path_length=1,
        server_auth=False,
    )
    # An Ed25519 issuer is verified rather than crashing: the leaf must come back.
    leaf = _cert(
        subject=SERVER_NAME,
        issuer_name="ed root",
        public_key=issuer_key.public_key(),
        signing_key=issuer_key,
        ca=False,
        san=SERVER_NAME,
    )
    assert verify_chain([_der(leaf)], root, SERVER_NAME) is not None


def test_a_leaf_without_the_optional_extensions_is_accepted():
    """B7/B8: RFC 5280 makes basicConstraints optional for an end entity and reads an absent
    EKU as "no restriction", so such a certificate is legal and must not raise."""
    from tls.pki import verify_chain

    root_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    root = _cert(
        subject="minimal root",
        issuer_name="minimal root",
        public_key=root_key.public_key(),
        signing_key=root_key,
        ca=True,
        path_length=1,
        server_auth=False,
    )
    leaf = _cert(
        subject=SERVER_NAME,
        issuer_name="minimal root",
        public_key=leaf_key.public_key(),
        signing_key=root_key,
        ca=False,
        san=SERVER_NAME,
        omit=("basic_constraints", "eku"),
    )
    assert verify_chain([_der(leaf)], root, SERVER_NAME) is not None


def test_a_leaf_without_a_subject_alternative_name_is_rejected_by_name():
    """B9: no SAN means no DNS name, so the name cannot match — a rejection, not an exception."""
    from tls.pki import verify_chain

    root_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    root = _cert(
        subject="nosan root",
        issuer_name="nosan root",
        public_key=root_key.public_key(),
        signing_key=root_key,
        ca=True,
        path_length=1,
        server_auth=False,
    )
    leaf = _cert(
        subject=SERVER_NAME,
        issuer_name="nosan root",
        public_key=leaf_key.public_key(),
        signing_key=root_key,
        ca=False,
        san=None,
        omit=("san",),
    )
    with pytest.raises(HandshakeError) as excinfo:
        verify_chain([_der(leaf)], root, SERVER_NAME)
    assert "no DNS name" in excinfo.value.reason


def _cert(
    *,
    subject: str,
    issuer_name: str,
    public_key,
    signing_key,
    ca: bool,
    path_length: int | None = None,
    san: str | None = None,
    server_auth: bool = True,
    omit: tuple[str, ...] = (),
):
    """A certificate with the extensions a test asks for, and only those."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
    )
    if "basic_constraints" not in omit:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=path_length), critical=True
        )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=not ca,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=ca,
            crl_sign=ca,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    if san is not None and "san" not in omit:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False
        )
    if "eku" not in omit:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH] if server_auth else [ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
    from cryptography.hazmat.primitives.asymmetric import ed448, ed25519

    # EdDSA signs the message itself; only the ECDSA/RSA families take a hash here.
    algorithm = (
        None
        if isinstance(signing_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey))
        else hashes.SHA256()
    )
    return builder.sign(signing_key, algorithm)


def _der(certificate) -> bytes:
    """The DER bytes a Certificate message would carry."""
    from cryptography.hazmat.primitives import serialization

    return certificate.public_bytes(serialization.Encoding.DER)
