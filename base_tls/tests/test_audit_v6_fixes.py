"""Regression tests for the fifth review (their `hybrid-tls13-v6-攻击包`).

That round accepted the client-side ClientHello checks as complete and then found the
gap on the other half of the negotiation: the two messages the **server** sends. One test
per finding, named after the auditor's case:

* **V6-01 (K1)** a legal chain whose leaf omits ``basicConstraints`` reached an unguarded
  extension lookup in ``_enforce_path_length`` and left path validation as an unhandled
  ``ExtensionNotFound``;
* **V6-02 (K2)** a ServerHello carrying an extension the client never offered;
* **V6-03 (K3)** an EncryptedExtensions carrying an extension at all;
* **V6-04 (K4)** two ``KeyShareEntry`` values in the ServerHello's ``key_share``;
* **V6-05 (K5)** trailing bytes inside the ``pq_ciphertext`` extension;
* **V6-06 (K6)** a non-empty ``certificate_request_context`` in the server's Certificate;
* **V6-07 (K7b)** a 255-byte ``legacy_session_id``, which the server echoed;
* **V6-08 (N1)** an exhausted XMSS key escaping the server flight as a bare ``ValueError``;
* **V6-09 (M3)** ``keygen_from_seed`` accepting one string as both the secret and the
  public seed, which publishes the secret seed inside the public key.

The K2–K5 cases build the message by hand from a real one rather than tampering with a
byte stream, so a failure names the rule that went missing. K1 uses its own certificates:
the project's ``build_test_chain`` only produces well-formed chains, and this case is a
well-formed chain in a shape the project does not generate.
"""

from __future__ import annotations

import datetime
from dataclasses import replace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from conftest import PROFILES
from tls.config import HybridTLSConfig
from tls.credentials import CertificateAuthority, ServerCredentials
from tls.errors import DecodeError, HandshakeError, HybridTLSError
from tls.handshake.client import HybridClient
from tls.handshake.messages import (
    ENCRYPTED_EXTENSIONS,
    EXTENSION_KEY_SHARE,
    EXTENSION_PQ_CIPHERTEXT,
    EXTENSION_SUPPORTED_VERSIONS,
    SERVER_HELLO,
    Certificate,
    ClientHello,
    ServerHello,
    X509Chain,
    _encode_extensions,
)
from tls.handshake.server import HybridServer
from tls.pki import verify_chain
from tls.pq.wots_xmss import XmssSignatureBackend
from tls.wire import handshake_message, split_handshake_message, u16, vec8, vec16

PROFILE = "ml-kem-768+ml-dsa-44"
SERVER_NAME = "server.example"
#: An unassigned extension type: nothing in this profile offers or expects it.
UNOFFERED_EXTENSION = 0xFE03


# --------------------------------------------------------------------------- helpers


def _server(config: HybridTLSConfig) -> HybridServer:
    authority = CertificateAuthority(config.classical())
    credentials = ServerCredentials(config, identity=SERVER_NAME.encode())
    return HybridServer(config, credentials, credentials.bind_to(authority))


def _client(config: HybridTLSConfig) -> HybridClient:
    return HybridClient(
        config, CertificateAuthority(config.classical()), trusted_name=SERVER_NAME
    )


def _hello(config: HybridTLSConfig, **overrides) -> ClientHello:
    """A real ClientHello for this profile, with fields the tests can break."""
    client = _client(config)
    return replace(ClientHello.decode(client.create_client_hello()[4:]), **overrides)


def _server_hello(config: HybridTLSConfig, **overrides) -> ServerHello:
    """A real ServerHello for this profile, built by running this profile's own server."""
    frame = _server(config).receive_client_hello(_hello(config).to_message())
    return replace(ServerHello.decode(frame[4:]), **overrides)


def _server_hello_body(
    hello: ServerHello,
    *,
    key_share_payload: bytes | None = None,
    pq_payload: bytes | None = None,
    extra: tuple[tuple[int, bytes], ...] = (),
) -> bytes:
    """Re-encode a ServerHello body with its extension block edited.

    ``key_share_payload`` and ``pq_payload`` replace the encoded extension bodies;
    ``extra`` appends extensions the profile never sends.
    """
    extensions = [
        (EXTENSION_SUPPORTED_VERSIONS, u16(hello.supported_versions[0])),
        (
            EXTENSION_KEY_SHARE,
            hello.key_share.encode() if key_share_payload is None else key_share_payload,
        ),
    ]
    if pq_payload is None and hello.pq_ciphertext is not None:
        pq_payload = vec16(hello.pq_ciphertext)
    if pq_payload is not None:
        extensions.append((EXTENSION_PQ_CIPHERTEXT, pq_payload))
    extensions.extend(extra)
    return (
        u16(hello.legacy_version)
        + hello.random
        + vec8(hello.legacy_session_id)
        + u16(hello.cipher_suite)
        + vec8(bytes(hello.legacy_compression_methods))
        + _encode_extensions(extensions)
    )


def _driver(config: HybridTLSConfig) -> tuple[HybridClient, bytes]:
    """A client that has sent its ClientHello, plus the frame it sent."""
    client = _client(config)
    return client, client.create_client_hello()


# ------------------------------------------------------------------ V6-01: path length


def _make_cert(
    *,
    subject: str,
    issuer_name: str,
    public_key,
    signing_key,
    ca: bool,
    path_length: int | None = None,
    basic_constraints: bool = True,
    san: str | None = None,
):
    """One hand-built certificate; ``basic_constraints=False`` omits the extension."""
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
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
    )
    if basic_constraints:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=path_length), critical=True
        )
    if san is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False
        )
    return builder.sign(signing_key, hashes.SHA256())


def _der(certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.DER)


def _k1_chain(*, leaf_has_basic_constraints: bool):
    """``[leaf, intermediate(path_length=1)]`` plus the root to trust, for K1 and its control."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    intermediate_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())

    root = _make_cert(
        subject="v6 root CA",
        issuer_name="v6 root CA",
        public_key=root_key.public_key(),
        signing_key=root_key,
        ca=True,
        path_length=2,
    )
    intermediate = _make_cert(
        subject="v6 intermediate CA",
        issuer_name="v6 root CA",
        public_key=intermediate_key.public_key(),
        signing_key=root_key,
        ca=True,
        path_length=1,
    )
    leaf = _make_cert(
        subject=SERVER_NAME,
        issuer_name="v6 intermediate CA",
        public_key=leaf_key.public_key(),
        signing_key=intermediate_key,
        ca=False,
        basic_constraints=leaf_has_basic_constraints,
        san=SERVER_NAME,
    )
    return [_der(leaf), _der(intermediate)], root


def test_a_leaf_without_basic_constraints_under_a_constrained_intermediate():
    """V6-01 (K1): the legal shape that used to raise ``ExtensionNotFound``.

    RFC 5280 section 4.2.1.9 makes ``basicConstraints`` optional in an end-entity
    certificate, and ``verify_chain`` already reads it that way everywhere else. The one
    unguarded lookup sat in the ``pathLenConstraint`` walk, so this exact chain — legal
    leaf, real intermediate carrying a constraint — crashed instead of verifying.
    """
    presented, root = _k1_chain(leaf_has_basic_constraints=False)
    assert verify_chain(presented, root, SERVER_NAME) is not None


def test_the_same_chain_with_the_extension_present_still_verifies():
    """The auditor's K1b control: the fix must not depend on the extension being absent."""
    presented, root = _k1_chain(leaf_has_basic_constraints=True)
    assert verify_chain(presented, root, SERVER_NAME) is not None


# ------------------------------------------------- V6-02 … V6-07: the server's messages


def test_a_server_hello_with_an_unoffered_extension_is_rejected():
    """V6-02 (K2): RFC 8446 section 4.1.3 — a response may only use offered extensions."""
    config = PROFILES[PROFILE]
    hello = _server_hello(config)
    frame = handshake_message(
        SERVER_HELLO,
        _server_hello_body(hello, extra=((UNOFFERED_EXTENSION, b""),)),
    )
    client, _hello_frame = _driver(config)
    with pytest.raises(HandshakeError) as excinfo:
        client.receive_server_hello(frame)
    assert excinfo.value.step == "server_hello"
    assert "never offered" in excinfo.value.reason
    assert f"{UNOFFERED_EXTENSION:#06x}" in excinfo.value.reason


def test_two_key_shares_in_the_server_hello_are_rejected():
    """V6-04 (K4): RFC 8446 section 4.2.8 — exactly one entry in a ServerHello."""
    config = PROFILES[PROFILE]
    hello = _server_hello(config)
    entry = hello.key_share.encode()
    frame = handshake_message(
        SERVER_HELLO, _server_hello_body(hello, key_share_payload=entry + entry)
    )
    client, _hello_frame = _driver(config)
    with pytest.raises(DecodeError) as excinfo:
        client.receive_server_hello(frame)
    assert "trailing" in str(excinfo.value)


def test_trailing_bytes_in_the_pq_ciphertext_extension_are_rejected():
    """V6-05 (K5): an extension body has to be consumed exactly.

    The garbage goes *after* the length-delimited ciphertext, not inside it: growing the
    vector is caught by the KEM's own length check (a different finding), while bytes the
    extension does not account for used to be dropped silently.
    """
    config = PROFILES[PROFILE]
    hello = _server_hello(config)
    frame = handshake_message(
        SERVER_HELLO,
        _server_hello_body(hello, pq_payload=vec16(hello.pq_ciphertext) + b"\x00\x00\x00\x00"),
    )
    client, _hello_frame = _driver(config)
    with pytest.raises(DecodeError) as excinfo:
        client.receive_server_hello(frame)
    assert "trailing" in str(excinfo.value)


def _run_to_the_server_flight(config: HybridTLSConfig, frame_filter):
    """Drive a real handshake up to the server's authenticated flight.

    Returns the client, positioned after the ServerHello, and the flight the server built
    with ``frame_filter`` applied to each plaintext frame before it was hashed and sealed.
    """
    client = _client(config)
    server = _server(config)
    server_hello = server.receive_client_hello(client.create_client_hello())
    client.receive_server_hello(server_hello)
    return client, server.send_authenticated_flight(frame_filter=frame_filter)


def test_an_encrypted_extensions_with_an_unknown_extension_is_rejected():
    """V6-03 (K3): RFC 8446 section 4.3.1 — the EE rule is the ServerHello rule."""
    config = PROFILES[PROFILE]

    def append_to_ee(name: str, frame: bytes) -> bytes:
        if name != "EncryptedExtensions":
            return frame
        return handshake_message(
            ENCRYPTED_EXTENSIONS,
            _encode_extensions([(UNOFFERED_EXTENSION, b"")]),
        )

    client, flight = _run_to_the_server_flight(config, append_to_ee)
    with pytest.raises(HandshakeError) as excinfo:
        client.receive_server_flight([record for _, record, _ in flight])
    assert excinfo.value.step == "server_flight"
    assert "EncryptedExtensions" in excinfo.value.reason


def test_a_non_empty_certificate_request_context_is_rejected():
    """V6-06 (K6): RFC 8446 section 4.4.2 — the server sent no CertificateRequest."""
    config = PROFILES[PROFILE]

    def add_context(name: str, frame: bytes) -> bytes:
        if name != "Certificate":
            return frame
        original = Certificate.decode(split_handshake_message(frame)[1])
        return Certificate(
            body=original.body,
            ca_signature=original.ca_signature,
            extensions=original.extensions,
            certificate_request_context=b"\x00\x00\x00\x01",
        ).to_message()

    client, flight = _run_to_the_server_flight(config, add_context)
    with pytest.raises(HybridTLSError) as excinfo:
        client.receive_server_flight([record for _, record, _ in flight])
    assert "certificate_request_context" in str(excinfo.value)


def test_the_x509_chain_message_applies_the_same_rule():
    """The other Certificate body has to reject it too, or the rule is profile-dependent."""
    with pytest.raises(DecodeError) as excinfo:
        X509Chain.decode(vec8(b"\x00\x00\x00\x01") + vec16(b""))
    assert "certificate_request_context" in str(excinfo.value)


def test_an_oversized_session_id_in_the_client_hello_is_rejected():
    """V6-07 (K7b): RFC 8446 section 4.1.2 caps the field at 32 bytes."""
    config = PROFILES[PROFILE]
    frame = _hello(config, legacy_session_id=b"x" * 255).to_message()
    with pytest.raises(HybridTLSError) as excinfo:
        _server(config).receive_client_hello(frame)
    assert "at most 32" in str(excinfo.value)


def test_an_oversized_session_id_in_the_server_hello_is_rejected():
    """The same field on the way back, so neither side relies on the echo check alone."""
    config = PROFILES[PROFILE]
    hello = _server_hello(config, legacy_session_id=b"x" * 255)
    client, _hello_frame = _driver(config)
    with pytest.raises(HybridTLSError) as excinfo:
        client.receive_server_hello(
            handshake_message(SERVER_HELLO, _server_hello_body(hello))
        )
    assert "at most 32" in str(excinfo.value)


def test_a_server_hello_that_breaks_no_rule_is_still_accepted():
    """Positive control for the whole block above."""
    config = PROFILES[PROFILE]
    client, hello_frame = _driver(config)
    server = _server(config)
    client.receive_server_hello(server.receive_client_hello(hello_frame))
    assert client.server_hello is not None


# ---------------------------------------------- V6-08: the server's own signing failure


def test_an_exhausted_xmss_key_is_a_named_refusal_not_a_bare_value_error():
    """V6-08 (N1): the primitive raises ``ValueError``; the handshake layer must not.

    A two-leaf tree is spent after two handshakes. The third signature used to raise a
    bare ``ValueError`` out of ``send_authenticated_flight``, which breaks the single
    error contract the rest of this package documents.
    """
    config = HybridTLSConfig(kem="ml-kem-768", pq_signer="xmss", xmss_height=1)
    client = _client(config)
    server = _server(config)
    server.receive_client_hello(client.create_client_hello())
    server.send_authenticated_flight()
    server.send_authenticated_flight()
    with pytest.raises(HandshakeError) as excinfo:
        server.send_authenticated_flight()
    assert excinfo.value.step == "server_flight"
    assert "refused to sign" in excinfo.value.reason
    assert "exhausted" in excinfo.value.reason


# -------------------------------------------------------------- V6-09: the U-03 invariant


def test_the_public_seed_may_not_share_material_with_the_secret_seed():
    """V6-09 (M3): the public seed travels in the public key, so overlap publishes secrets.

    The auditor reconstructed the secret seed from the public key's second half, rebuilt
    the tree and produced a signature that verified. Only the length was validated, so the
    misuse they exercised had nothing stopping it.
    """
    backend = XmssSignatureBackend(height=1)
    same = bytes(range(32))
    with pytest.raises(ValueError) as excinfo:
        backend.keygen_from_seed(same, public_seed=same)
    assert "independently" in str(excinfo.value)
    # A shortened copy leaks the same way; equality alone is not the rule.
    with pytest.raises(ValueError):
        backend.keygen_from_seed(bytes(range(32)), public_seed=bytes(range(16)))


def test_independent_seeds_still_build_a_key_pair():
    """Positive control: two unrelated seeds keep working."""
    backend = XmssSignatureBackend(height=1)
    secret, public_key = backend.keygen_from_seed(
        bytes(range(32)), public_seed=bytes(reversed(range(32)))
    )
    assert len(public_key) == 64
    assert secret.public_seed == bytes(reversed(range(32)))
