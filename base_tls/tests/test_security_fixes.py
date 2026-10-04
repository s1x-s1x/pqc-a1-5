"""Regression tests for the findings of the static security review.

Every test here corresponds to one finding, and each one is written to *fail* against
the code as it stood before the fix — that is the only thing that makes a regression
test worth keeping. Where the old behaviour is cheap to write down, the test asserts
that the old construction differs from the correct one, so a future edit that
reintroduces it cannot pass by accident.

The findings, in the order they are addressed below:

1. ``verify_chain`` accepted a forged trust anchor. The anchor check compared the
   top certificate's ``subject`` and ``serial_number`` against the trusted root and
   skipped the signature check when they matched — but both fields are public and
   attacker-chosen, so a fabricated root carrying the trusted root's name and serial
   number, with the attacker's own key, ended the chain. Fix: compare the DER.
2. The chain checks were incomplete: no ``keyCertSign`` requirement, no
   ``pathLenConstraint`` enforcement, and no refusal of unknown critical extensions.
3. The modelled certificate (the default profile) verified the CA signature and the
   classical scheme but never the identity, so a certificate the same CA had issued
   for another name was accepted.
4. ``RecordLayer.key_fingerprint`` returned the first ``length`` bytes of the traffic
   key, which for AES-128 left only four bytes unknown, while claiming not to print
   the key.
5. The TCP harness read a peer-announced frame length without bounding it.
6. ``ExporterMasterSecret`` was mixed with the current transcript hash and the raw
   context instead of the empty hash and the *hashed* context.
7. ``tools/sandbox_pyfix/sitecustomize.py`` widened directory permissions wherever it
   was imported, rather than only under the sandbox it exists for.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from conftest import PROFILES
from tls.credentials import CertificateAuthority, ServerCredentials
from tls.errors import HandshakeError
from tls.handshake.client import HybridClient
from tls.handshake.connection import HybridConnection
from tls.handshake.messages import HybridCertificateBody
from tls.handshake.server import HybridServer
from tls.pki import build_test_chain, verify_chain
from tls.record.aead import RecordLayer, get_aead_suite
from tls.transport.tcp import _MAX_FRAME_BYTES, _LENGTH_PREFIX_BYTES, _recv_frame

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SANDBOX_PYFIX = PROJECT_ROOT / "tools" / "sandbox_pyfix"
SERVER_NAME = "server.example"


# --------------------------------------------------------------------------- helpers


def _make_cert(
    *,
    subject: str,
    issuer_name: str,
    public_key,
    signing_key,
    ca: bool,
    key_cert_sign: bool = True,
    path_length: int | None = None,
    serial: int | None = None,
    san: str | None = None,
    server_auth: bool = True,
    extra_critical: ObjectIdentifier | None = None,
):
    """Build one certificate with every field the review's findings concern exposed.

    The project's own ``build_test_chain`` deliberately produces only well-formed
    chains, so a test that needs a *malformed* one has to assemble it here. Nothing in
    this helper is used by the code under test.
    """
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))
        .public_key(public_key)
        .serial_number(serial if serial is not None else x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=not ca,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=key_cert_sign,
                crl_sign=key_cert_sign,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if san is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False
        )
    if server_auth:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
    if extra_critical is not None:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(extra_critical, b"\x05\x00"), critical=True
        )
    return builder.sign(signing_key, hashes.SHA256())


def _der(certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.DER)


def _chain_under(intermediate_key_cert_sign: bool = True, intermediate_path_length: int = 0):
    """Return ``(chain_der, trusted_root, leaf_key)`` for a chain we control by hand.

    The leaf is signed by the intermediate, the intermediate by the root, and the root
    is what the client will be told to trust. ``intermediate_key_cert_sign`` and
    ``intermediate_path_length`` are the two knobs findings 2 concerns.
    """
    root_key = ec.generate_private_key(ec.SECP256R1())
    intermediate_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())

    root = _make_cert(
        subject="review root CA",
        issuer_name="review root CA",
        public_key=root_key.public_key(),
        signing_key=root_key,
        ca=True,
        path_length=2,
        server_auth=False,
    )
    intermediate = _make_cert(
        subject="review intermediate CA",
        issuer_name="review root CA",
        public_key=intermediate_key.public_key(),
        signing_key=root_key,
        ca=True,
        key_cert_sign=intermediate_key_cert_sign,
        path_length=intermediate_path_length,
        server_auth=False,
    )
    leaf = _make_cert(
        subject=SERVER_NAME,
        issuer_name="review intermediate CA",
        public_key=leaf_key.public_key(),
        signing_key=intermediate_key,
        ca=False,
        san=SERVER_NAME,
    )
    return [_der(leaf), _der(intermediate)], root, leaf_key


def _rfc_hkdf_expand_label(secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
    """HKDF-Expand-Label written from RFC 8446 section 7.1, not from the project.

    Reimplemented here on purpose: a regression test that calls the code under test to
    build its own expected value cannot catch a mistake in that code.
    """
    full_label = b"tls13 " + label
    info = (
        length.to_bytes(2, "big")
        + bytes([len(full_label)])
        + full_label
        + bytes([len(context)])
        + context
    )
    output = b""
    block = b""
    counter = 1
    while len(output) < length:
        block = hmac.new(secret, block + info + bytes([counter]), hashlib.sha256).digest()
        output += block
        counter += 1
    return output[:length]


def _rfc_exporter(exporter_master_secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
    """The RFC 8446 section 7.5 exporter, written out longhand.

    Section 7.5 defines the exported keying material as

        HKDF-Expand-Label(Derive-Secret(ExporterMasterSecret, label, ""),
                          "exporter", Hash(context_value), key_length)

    and ``Derive-Secret`` is itself ``HKDF-Expand-Label(secret, label, Hash(messages),
    Hash.length)`` with ``Hash(messages)`` empty here. Both of those details are what the
    pre-fix code got wrong, so this reference spells them out instead of sharing a helper
    with the implementation. The formula was cross-checked against an independent
    implementation's documentation of the same section
    (https://docs.rs/shin/0.7.2/shin/schedule/fn.export_keying_material.html); it is a
    reimplementation of the RFC's formula, not a check against published test vectors.
    """
    empty_hash = hashlib.sha256(b"").digest()
    derived = _rfc_hkdf_expand_label(exporter_master_secret, label, empty_hash, 32)
    return _rfc_hkdf_expand_label(derived, b"exporter", hashlib.sha256(context).digest(), length)


# ------------------------------------------------------- finding 1: the trust anchor


def test_forged_root_with_the_trusted_roots_name_and_serial_is_rejected():
    """The pre-fix anchor check compared two fields an attacker controls.

    The forgery below matches the trusted root on ``subject`` and ``serial_number`` and
    is signed by the attacker's own key, which is exactly the shape that walked through
    the old check. The test asserts the forgery really does match on those two fields
    first, so a rejection cannot be credited to some unrelated difference.
    """
    chain_der, trusted_root, _leaf_key = _chain_under()

    attacker_key = ec.generate_private_key(ec.SECP256R1())
    forged_root = _make_cert(
        subject=trusted_root.subject.rfc4514_string().split("=", 1)[1],
        issuer_name=trusted_root.subject.rfc4514_string().split("=", 1)[1],
        public_key=attacker_key.public_key(),
        signing_key=attacker_key,
        ca=True,
        path_length=2,
        serial=trusted_root.serial_number,
        server_auth=False,
    )

    # The forgery defeats the field-based check the code used to make.
    assert forged_root.subject == trusted_root.subject
    assert forged_root.serial_number == trusted_root.serial_number
    assert _der(forged_root) != _der(trusted_root)

    # An attacker leaf under the forged root, so nothing else in the path is wrong.
    attacker_leaf_key = ec.generate_private_key(ec.SECP256R1())
    attacker_leaf = _make_cert(
        subject=SERVER_NAME,
        issuer_name=trusted_root.subject.rfc4514_string().split("=", 1)[1],
        public_key=attacker_leaf_key.public_key(),
        signing_key=attacker_key,
        ca=False,
        san=SERVER_NAME,
    )

    presented = [_der(attacker_leaf), _der(forged_root)]
    with pytest.raises(HandshakeError) as excinfo:
        verify_chain(presented, trusted_root, SERVER_NAME)
    # The message comes from the signature check the DER comparison forces to run: the
    # forgery is only rejected because its encoding differs from the anchor's.
    assert "not signed by" in str(excinfo.value)


def test_honest_chain_still_verifies():
    """The positive control: the fix must not reject a correctly built chain."""
    chain_der, trusted_root, _leaf_key = _chain_under()
    leaf = verify_chain(chain_der, trusted_root, SERVER_NAME)
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert SERVER_NAME in san.get_values_for_type(x509.DNSName)


def test_chain_for_another_identity_is_rejected():
    """The X.509 path always checked the name; this pins that it still does."""
    chain_der, trusted_root, _leaf_key = _chain_under()
    with pytest.raises(HandshakeError) as excinfo:
        verify_chain(chain_der, trusted_root, "other.example")
    assert "other.example" in str(excinfo.value)


# ------------------------------------------- finding 2: the missing chain constraints


def test_intermediate_whose_key_usage_forbids_signing_certificates_is_rejected():
    """``basicConstraints: CA`` alone does not authorise issuing a certificate."""
    chain_der, trusted_root, _leaf_key = _chain_under(intermediate_key_cert_sign=False)
    with pytest.raises(HandshakeError) as excinfo:
        verify_chain(chain_der, trusted_root, SERVER_NAME)
    assert "key usage" in str(excinfo.value)


def test_intermediate_with_path_length_zero_cannot_issue_another_ca():
    """A fourth certificate below a ``pathLenConstraint=1`` intermediate must fail."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    intermediate_key = ec.generate_private_key(ec.SECP256R1())
    second_ca_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())

    root = _make_cert(
        subject="depth root CA",
        issuer_name="depth root CA",
        public_key=root_key.public_key(),
        signing_key=root_key,
        ca=True,
        path_length=1,
        server_auth=False,
    )
    intermediate = _make_cert(
        subject="depth intermediate CA",
        issuer_name="depth root CA",
        public_key=intermediate_key.public_key(),
        signing_key=root_key,
        ca=True,
        path_length=0,
        server_auth=False,
    )
    second_ca = _make_cert(
        subject="depth second CA",
        issuer_name="depth intermediate CA",
        public_key=second_ca_key.public_key(),
        signing_key=intermediate_key,
        ca=True,
        path_length=0,
        server_auth=False,
    )
    leaf = _make_cert(
        subject=SERVER_NAME,
        issuer_name="depth second CA",
        public_key=leaf_key.public_key(),
        signing_key=second_ca_key,
        ca=False,
        san=SERVER_NAME,
    )

    presented = [_der(leaf), _der(second_ca), _der(intermediate)]
    with pytest.raises(HandshakeError) as excinfo:
        verify_chain(presented, root, SERVER_NAME)
    assert "intermediate" in str(excinfo.value)


def test_unknown_critical_extension_is_rejected():
    """RFC 5280 section 4.2: a critical extension we do not understand ends the path."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    root = _make_cert(
        subject="crit root CA",
        issuer_name="crit root CA",
        public_key=root_key.public_key(),
        signing_key=root_key,
        ca=True,
        path_length=1,
        server_auth=False,
    )
    leaf = _make_cert(
        subject=SERVER_NAME,
        issuer_name="crit root CA",
        public_key=leaf_key.public_key(),
        signing_key=root_key,
        ca=False,
        san=SERVER_NAME,
        extra_critical=ObjectIdentifier("1.3.6.1.4.1.99999.77"),
    )
    with pytest.raises(HandshakeError) as excinfo:
        verify_chain([_der(leaf)], root, SERVER_NAME)
    assert "critical extension" in str(excinfo.value)


# --------------------------------------------- finding 3: the modelled certificate


def test_modelled_certificate_for_another_identity_is_rejected():
    """Drive a real handshake whose certificate names someone else.

    ``HybridConnection.run`` always asks for the identity the server presents, so this
    test wires the two halves together itself to make them disagree.
    """
    config = PROFILES["ml-kem-768+ml-dsa-44"]
    authority = CertificateAuthority(config.classical())
    credentials = ServerCredentials(config, identity=b"other.example")
    certificate = credentials.bind_to(authority)
    server = HybridServer(config, credentials, certificate)

    client = HybridClient(config, authority, trusted_name=SERVER_NAME)
    client_hello = client.create_client_hello()
    server_hello = server.receive_client_hello(client_hello)
    client.receive_server_hello(server_hello)
    flight = server.send_authenticated_flight()

    with pytest.raises(HandshakeError) as excinfo:
        client.receive_server_flight([record for _, record, _ in flight])
    assert "other.example" in str(excinfo.value)


def test_modelled_certificate_for_the_expected_identity_is_accepted():
    """The positive control for the check above, on the same code path."""
    config = PROFILES["ml-kem-768+ml-dsa-44"]
    result = HybridConnection.run(config, server_identity=SERVER_NAME.encode())
    assert result.certificate.body.server_identity == SERVER_NAME.encode()
    assert result.application_payload_ok


def test_modelled_body_identity_is_what_the_client_compares():
    """Keep the field the check reads tied to the identity the server means to assert."""
    config = PROFILES["ml-kem-768+ml-dsa-44"]
    body = ServerCredentials(config, identity=b"other.example").certificate_body()
    assert isinstance(body, HybridCertificateBody)
    assert body.server_identity == b"other.example"


# ---------------------------------------------------- finding 4: the key fingerprint


def test_traffic_key_fingerprint_is_a_hash_and_not_a_prefix_of_the_key():
    """The old implementation returned ``key[:length]`` and claimed not to leak the key."""
    key = bytes(range(16))
    layer = RecordLayer(get_aead_suite("aes-128-gcm"), key, bytes(12))
    fingerprint = layer.key_fingerprint()

    assert key[: len(fingerprint) // 2] != bytes.fromhex(fingerprint)
    assert key.hex()[: len(fingerprint)] != fingerprint
    expected = hashlib.sha256(b"hybrid-tls13 traffic key fingerprint|" + key).hexdigest()
    assert fingerprint == expected[: len(fingerprint)]

    other = RecordLayer(get_aead_suite("aes-128-gcm"), bytes([1]) + key[1:], bytes(12))
    assert other.key_fingerprint() != fingerprint


# --------------------------------------------------------- finding 5: the frame cap


def test_oversize_frame_is_refused_without_allocating_it():
    """A peer must not be able to make the reader allocate an announced length."""
    left, right = socket.socketpair()
    try:
        announced = _MAX_FRAME_BYTES + 1
        left.sendall(announced.to_bytes(_LENGTH_PREFIX_BYTES, "big"))
        with pytest.raises(ConnectionError) as excinfo:
            _recv_frame(right)
        assert str(announced) in str(excinfo.value)
    finally:
        left.close()
        right.close()


def test_frame_at_the_limit_still_arrives():
    """The cap must not truncate or refuse legitimate traffic."""
    payload = b"x" * 4096
    left, right = socket.socketpair()
    try:
        left.sendall(len(payload).to_bytes(_LENGTH_PREFIX_BYTES, "big") + payload)
        assert _recv_frame(right) == payload
    finally:
        left.close()
        right.close()


# ------------------------------------------------------------ finding 6: the exporter


def test_exporter_matches_the_rfc_expression():
    """Compare against the RFC written out longhand, not against the peer.

    Both endpoints shared the pre-fix mistake, so a client/server equality check passed
    while the value was wrong — which is why the comparison here is against an
    independent expression rather than against the other half of the handshake.
    """
    config = PROFILES["ml-kem-768+ml-dsa-44"]
    result = HybridConnection.run(config, server_identity=SERVER_NAME.encode())

    exporter_master_secret = result.client.schedule.exporter_master_secret
    assert exporter_master_secret is not None

    label = b"hybrid-tls13 test"
    context = b"exporter regression context"
    expected = _rfc_exporter(exporter_master_secret, label, context, 32)

    assert result.client.exporter_secret(label.decode(), context, 32) == expected
    assert result.server.exporter_secret(label.decode(), context, 32) == expected


def test_exporter_reference_differs_from_the_pre_fix_construction():
    """The negative control: the old construction must not equal the RFC's.

    Without this, a future edit that reinstated the old argument order could still pass
    the test above if the reference expression were also (mistakenly) relaxed.
    """
    config = PROFILES["ml-kem-768+ml-dsa-44"]
    result = HybridConnection.run(config, server_identity=SERVER_NAME.encode())
    exporter_master_secret = result.client.schedule.exporter_master_secret
    assert exporter_master_secret is not None

    label = b"hybrid-tls13 test"
    context = b"exporter regression context"
    correct = _rfc_exporter(exporter_master_secret, label, context, 32)

    # The pre-fix code: the *current* transcript hash where the RFC puts the empty hash,
    # and the raw context where the RFC puts its hash.
    empty_hash = hashlib.sha256(b"").digest()
    current_hash = result.client.transcript.hash()
    assert current_hash != empty_hash
    derived = _rfc_hkdf_expand_label(exporter_master_secret, label, current_hash, 32)
    pre_fix = _rfc_hkdf_expand_label(derived, b"exporter", context, 32)

    assert pre_fix != correct


def test_exporter_context_is_hashed_not_used_raw():
    """A second negative control aimed at the context half of the same finding."""
    config = PROFILES["ml-kem-768+ml-dsa-44"]
    result = HybridConnection.run(config, server_identity=SERVER_NAME.encode())
    exporter_master_secret = result.client.schedule.exporter_master_secret
    assert exporter_master_secret is not None

    label = b"hybrid-tls13 test"
    context = b"context that is longer than one hash block " * 4  # > 64 bytes, so raw != hashed
    assert len(context) > 64
    expected = _rfc_exporter(exporter_master_secret, label, context, 32)
    raw_context = _rfc_hkdf_expand_label(
        _rfc_hkdf_expand_label(
            exporter_master_secret, label, hashlib.sha256(b"").digest(), 32
        ),
        b"exporter",
        context,
        32,
    )
    assert raw_context != expected
    assert result.client.exporter_secret(label.decode(), context, 32) == expected


def test_local_hkdf_expand_label_matches_the_projects_encoding():
    """Tie the from-scratch helper to the project's encoding, so both stay honest.

    The helper above is what the exporter tests trust; if its HkdfLabel layout ever
    drifted from the project's, the exporter tests would be comparing two different
    encodings and could pass while both were wrong.
    """
    from tls.key_schedule.hkdf import hkdf_expand_label

    secret = bytes(range(32))
    assert _rfc_hkdf_expand_label(secret, b"test label", b"ctx", 32) == hkdf_expand_label(
        secret, "test label", b"ctx", 32
    )


# ---------------------------------------------------------- finding 7: the sandbox patch


def _run_with_sandbox_path(env_overrides: dict[str, str | None]) -> str:
    """Import the pyfix in a child interpreter and report whether it patched ``os.mkdir``."""
    environment = {name: value for name, value in os.environ.items() if not name.startswith("DSH_")}
    environment["PYTHONPATH"] = str(SANDBOX_PYFIX)
    for name, value in env_overrides.items():
        if value is None:
            environment.pop(name, None)
        else:
            environment[name] = value
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import os; print(getattr(os.mkdir, '__name__', 'builtin'))",
        ],
        capture_output=True,
        text=True,
        env=environment,
        check=True,
    )
    return completed.stdout.strip()


def test_sandbox_mkdir_patch_is_inert_without_the_sandbox_environment():
    """Importing the module on a normal machine must not widen directory permissions."""
    assert _run_with_sandbox_path({"DSH_SESSION_ID": None}) == "mkdir"


def test_sandbox_mkdir_patch_applies_under_the_sandbox_environment():
    """Windows DACL repair is active on Windows and inert on other platforms."""
    assert (
        _run_with_sandbox_path({"DSH_SESSION_ID": "regression-test"})
        == ("_mkdir_with_inheritable_dacl" if os.name == "nt" else "mkdir")
    )
