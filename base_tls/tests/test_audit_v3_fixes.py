"""Regression tests for the third review — the v3 static audit (F1–F10).

Each test corresponds to one finding of `hybrid-tls13-v3-安全审计报告.md` and is written to
fail against the code as audited. The audit's own boundary is honoured: it was a static
read, it executed nothing, and it claims no exploit. The tests below are the dynamic half
it could not run.

Covered here (Python):
* F2 — a leaf certificate whose KeyUsage forbids digital signatures was accepted.
* F3 — an intermediate CA's EKU restriction was not enforced down the chain.
* F4 — CertificateVerify's announced scheme identifiers were parsed and ignored.
* F5 — XMSS leaf allocation was a read-then-write race, and the seed leaked through `repr`.
* F6 — application traffic and exporter secrets were taken over the wrong transcript prefix.
* F7 — a frame read had a size cap but no total deadline.
* F10 — the sandbox directory patch was not limited to the platform it exists for.

F1 and F8 live in `rust-prototype/` and F9 is a dependency-pinning change; both are checked
by their own commands, recorded in `docs/AUDIT_V3_RESPONSE.md`.
"""

from __future__ import annotations

import datetime
import hashlib
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from conftest import PROFILES
from tls.credentials import CertificateAuthority, ServerCredentials
from tls.errors import HandshakeError
from tls.handshake.certificate_verify import HybridCertificateVerify
from tls.handshake.client import HybridClient
from tls.handshake.connection import HybridConnection
from tls.handshake.server import HybridServer
from tls.handshake.state import HandshakeState
from tls.handshake.transcript import Transcript
from tls.key_schedule.hkdf import derive_secret
from tls.pki import verify_chain
from tls.pq.wots_xmss import XmssSecretKey, XmssSignatureBackend
from tls.transport.tcp import _recv_frame

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SANDBOX_PYFIX = PROJECT_ROOT / "tools" / "sandbox_pyfix"
SERVER_NAME = "server.example"
PROFILE = "ml-kem-768+ml-dsa-44"


# --------------------------------------------------------------------------- helpers


def _cert(
    *,
    subject: str,
    issuer_name: str,
    public_key,
    signing_key,
    ca: bool,
    key_cert_sign: bool = True,
    digital_signature: bool = True,
    path_length: int | None = None,
    serial: int | None = None,
    san: str | None = None,
    server_auth: bool = True,
    eku: list[ObjectIdentifier] | None = None,
):
    """Build one certificate, exposing the two usage bits findings F2/F3 concern."""
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
                digital_signature=digital_signature,
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
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    elif server_auth:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
    return builder.sign(signing_key, hashes.SHA256())


def _der(certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.DER)


def _chain(*, leaf_digital_signature: bool = True, ca_eku: list[ObjectIdentifier] | None = None):
    """Return ``(chain_der, trusted_root)``: root -> intermediate -> leaf, all ours."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    intermediate_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())

    root = _cert(
        subject="audit root CA",
        issuer_name="audit root CA",
        public_key=root_key.public_key(),
        signing_key=root_key,
        ca=True,
        path_length=2,
        server_auth=False,
    )
    intermediate = _cert(
        subject="audit intermediate CA",
        issuer_name="audit root CA",
        public_key=intermediate_key.public_key(),
        signing_key=root_key,
        ca=True,
        path_length=0,
        server_auth=False,
        eku=ca_eku,
    )
    leaf = _cert(
        subject=SERVER_NAME,
        issuer_name="audit intermediate CA",
        public_key=leaf_key.public_key(),
        signing_key=intermediate_key,
        ca=False,
        digital_signature=leaf_digital_signature,
        san=SERVER_NAME,
    )
    return [_der(leaf), _der(intermediate)], root, intermediate_key


def _open_pair(config, *, frame_filter=None):
    """Drive ClientHello..server flight; return the halves plus the frames each side saw."""
    authority = CertificateAuthority(config.classical())
    credentials = ServerCredentials(config, identity=SERVER_NAME.encode())
    certificate = credentials.bind_to(authority)
    client = HybridClient(config, authority, trusted_name=SERVER_NAME)
    server = HybridServer(config, credentials, certificate)

    client_hello = client.create_client_hello()
    server_hello = server.receive_client_hello(client_hello)
    client.receive_server_hello(server_hello)
    flight = server.send_authenticated_flight(frame_filter)
    client.receive_server_flight([record for _, record, _ in flight])
    return authority, credentials, certificate, client, server, flight, client_hello, server_hello


# ------------------------------------- F2: leaf key usage must permit digital signatures


def test_leaf_whose_key_usage_forbids_digital_signatures_is_rejected():
    """F2: `digital_signature=False` on the leaf must end the handshake.

    The certificate is otherwise perfect — trusted CA, right name, right validity,
    serverAuth EKU — so before the fix nothing in the path looked at this bit.
    """
    chain_der, trusted_root, _key = _chain(leaf_digital_signature=False)
    with pytest.raises(HandshakeError) as excinfo:
        verify_chain(chain_der, trusted_root, SERVER_NAME)
    assert "digital signature" in str(excinfo.value).lower()


def test_leaf_with_digital_signature_still_verifies():
    """Positive control: the same chain with the bit set is accepted."""
    chain_der, trusted_root, _key = _chain()
    leaf = verify_chain(chain_der, trusted_root, SERVER_NAME)
    assert leaf.subject.rfc4514_string().endswith(SERVER_NAME)


# ------------------------------------------------ F3: an intermediate CA's EKU binds down


def test_intermediate_ca_restricted_to_client_auth_cannot_issue_a_server_certificate():
    """F3: an intermediate whose EKU excludes serverAuth must not validate a server.

    The leaf is a perfectly good serverAuth certificate; the restriction lives one level
    up, which is exactly what the chain loop never looked at.
    """
    chain_der, trusted_root, _key = _chain(ca_eku=[ExtendedKeyUsageOID.CLIENT_AUTH])
    with pytest.raises(HandshakeError) as excinfo:
        verify_chain(chain_der, trusted_root, SERVER_NAME)
    assert "serverAuth" in str(excinfo.value) or "purposes" in str(excinfo.value).lower()


def test_intermediate_ca_with_server_auth_or_no_eku_still_verifies():
    """Positive controls: an EKU that permits serverAuth, and no EKU at all."""
    for ca_eku in ([ExtendedKeyUsageOID.SERVER_AUTH], None):
        chain_der, trusted_root, _key = _chain(ca_eku=ca_eku)
        assert verify_chain(chain_der, trusted_root, SERVER_NAME) is not None


# ------------------------------------ F4: CertificateVerify's announced schemes are checked


def _relabel_scheme(name: str, frame: bytes, *, where: str) -> bytes:
    """Rewrite one scheme identifier in a CertificateVerify frame, keeping the signature."""
    if name != "CertificateVerify":
        return frame
    decoded = HybridCertificateVerify.decode(frame[4:])
    if where == "classic":
        decoded = HybridCertificateVerify(
            classic_scheme=0x0403 ^ 0x00FF,
            classic_signature=decoded.classic_signature,
            pq_scheme=decoded.pq_scheme,
            pq_signature=decoded.pq_signature,
        )
    else:
        decoded = HybridCertificateVerify(
            classic_scheme=decoded.classic_scheme,
            classic_signature=decoded.classic_signature,
            pq_scheme=(decoded.pq_scheme or 0) ^ 0x00FF,
            pq_signature=decoded.pq_signature,
        )
    return b"\x0f\x00" + len(decoded.encode()).to_bytes(2, "big") + decoded.encode()


@pytest.mark.parametrize("where", ["classic", "pq"])
def test_certificate_verify_with_a_wrong_scheme_identifier_is_rejected(where):
    """F4: the announced scheme must match the negotiated one, not just "verify anyway".

    The signature bytes are untouched and valid under the configured algorithm, so this
    isolates the identifier check from the signature check.
    """
    config = PROFILES[PROFILE]
    with pytest.raises(HandshakeError) as excinfo:
        _open_pair(config, frame_filter=lambda name, frame: _relabel_scheme(name, frame, where=where))
    assert "scheme" in str(excinfo.value)


def test_an_honest_certificate_verify_is_still_accepted():
    """Positive control for F4: the unmodified flight completes."""
    config = PROFILES[PROFILE]
    _authority, _credentials, _certificate, _client, server, _flight, _ch, _sh = _open_pair(config)
    assert server.certificate_verify_payload is not None


# --------------------------------------------------- F5: XMSS leaf allocation is atomic


def test_xmss_indices_are_unique_under_concurrent_signing():
    """F5: two threads signing at once must never be handed the same leaf.

    Before the fix the index was read at the top of `sign()` and written back at the
    bottom, with the whole WOTS+ derivation in between — a window wide enough that the
    threads in this test collide reliably.
    """
    backend = XmssSignatureBackend(height=6)
    secret, _public = backend.keygen()
    indices: list[int] = []
    errors: list[BaseException] = []
    barrier = threading.Barrier(4)

    def worker(n: int) -> None:
        try:
            barrier.wait(timeout=10)
            signature = backend.sign(secret, f"concurrent message {n}".encode())
            indices.append(int.from_bytes(signature[:4], "big"))
        except BaseException as exc:  # noqa: BLE001 - reported below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert not errors, errors
    assert len(indices) == 4
    assert len(set(indices)) == 4, f"a leaf was handed out twice: {sorted(indices)}"
    assert secret.next_index == 4


def test_xmss_secret_key_repr_does_not_contain_the_seed():
    """F5, second half: the dataclass repr printed the only secret material."""
    backend = XmssSignatureBackend(height=4)
    secret, _public = backend.keygen()
    printed = repr(secret)
    assert secret.seed.hex() not in printed
    assert repr(secret.seed) not in printed
    assert "XmssSecretKey" in printed and "next_index" in printed, (
        "the repr should still identify the object and its state"
    )


def test_xmss_seed_is_scrubbed_from_the_object_graph_it_prints():
    """A repr taken through a container must not leak the seed either."""
    secret, _public = XmssSignatureBackend(height=4).keygen()
    assert secret.seed.hex() not in repr({"key": secret})


def test_xmss_keygen_seed_field_is_actually_present():
    """Guard: the tests above are only meaningful while the field is called `seed`."""
    secret, _public = XmssSignatureBackend(height=4).keygen()
    assert isinstance(secret, XmssSecretKey)
    assert isinstance(secret.seed, bytes) and secret.seed


# ------------------------------- F6: secrets are taken over the right transcript prefix


def _drive_with_independent_transcript(config):
    """Run one handshake while a test-owned transcript follows the same frames.

    The point is that this transcript is built here, from the frames themselves, rather
    than read out of the implementation — so the assertion is against the byte string the
    standard talks about, not against the implementation's own bookkeeping.
    """
    authority = CertificateAuthority(config.classical())
    credentials = ServerCredentials(config, identity=SERVER_NAME.encode())
    certificate = credentials.bind_to(authority)
    client = HybridClient(config, authority, trusted_name=SERVER_NAME)
    server = HybridServer(config, credentials, certificate)

    transcript = Transcript(config.hash_name)
    client_hello = client.create_client_hello()
    transcript.add(client_hello)
    server_hello = server.receive_client_hello(client_hello)
    transcript.add(server_hello)
    client.receive_server_hello(server_hello)

    flight = server.send_authenticated_flight()
    for _name, _record, frame in flight:
        transcript.add(frame)
    client.receive_server_flight([record for _, record, _ in flight])
    hash_through_server_finished = transcript.hash()

    client_finished = client.send_client_finished()
    transcript.add(client.sent_client_finished)
    hash_through_client_finished = transcript.hash()
    server.receive_client_finished(client_finished)

    assert hash_through_server_finished != hash_through_client_finished, (
        "the client Finished must change the transcript, otherwise this test proves nothing"
    )
    return client, server, hash_through_server_finished, hash_through_client_finished


def test_application_and_exporter_secrets_use_the_server_finished_transcript():
    """F6: RFC 8446 section 7.1 takes these three over ClientHello...server Finished."""
    config = PROFILES[PROFILE]
    client, server, hash_sf, hash_full = _drive_with_independent_transcript(config)
    master = client.schedule.master_secret
    assert master is not None and server.schedule.master_secret == master

    assert client.schedule.client_application_traffic == derive_secret(master, "c ap traffic", hash_sf)
    assert client.schedule.server_application_traffic == derive_secret(master, "s ap traffic", hash_sf)
    assert client.schedule.exporter_master_secret == derive_secret(master, "exp master", hash_sf)

    # The negative control: the prefix the implementation used to pass produces something else.
    assert client.schedule.exporter_master_secret != derive_secret(master, "exp master", hash_full)


def test_resumption_secret_uses_the_client_finished_transcript():
    """F6, other half: `res master` is the one secret taken after the client Finished."""
    config = PROFILES[PROFILE]
    client, server, hash_sf, hash_full = _drive_with_independent_transcript(config)
    master = client.schedule.master_secret

    assert client.schedule.resumption_master_secret == derive_secret(master, "res master", hash_full)
    assert client.schedule.resumption_master_secret != derive_secret(master, "res master", hash_sf)
    assert server.schedule.resumption_master_secret == client.schedule.resumption_master_secret


def test_both_halves_still_agree_on_the_exporter_and_the_application_keys():
    """The property the old tests covered — kept, because the fix must not break it."""
    config = PROFILES[PROFILE]
    client, server, _hash_sf, _hash_full = _drive_with_independent_transcript(config)
    assert client.exporter_secret("audit", b"context") == server.exporter_secret("audit", b"context")
    assert client.schedule.client_application_traffic == server.schedule.client_application_traffic


def test_end_to_end_handshake_still_carries_application_data():
    """Whole-flow control, so the stage fix cannot have broken the connection."""
    result = HybridConnection.run(PROFILES[PROFILE], server_identity=SERVER_NAME.encode())
    assert result.application_payload_ok
    assert result.exporters_match


# ------------------------------------------------------- F7: a frame read has a deadline


def _silent_peer() -> tuple[socket.socket, socket.socket]:
    return socket.socketpair()


def test_a_slow_frame_read_gives_up_on_the_deadline():
    """F7: a peer that announces a length and then dribbles must not hold the reader.

    The announced length is inside the size cap, so only a total deadline can end this.
    """
    left, right = _silent_peer()
    try:
        left.sendall((4096).to_bytes(4, "big") + b"x" * 8)  # 8 of the 4096 bytes promised
        started = time.monotonic()
        with pytest.raises((TimeoutError, ConnectionError)) as excinfo:
            _recv_frame(right, deadline=started + 0.5)
        elapsed = time.monotonic() - started
        assert elapsed < 5.0, f"the deadline did not bound the wait (took {elapsed:.1f}s)"
        assert "deadline" in str(excinfo.value).lower() or "timed out" in str(excinfo.value).lower()
    finally:
        left.close()
        right.close()


def test_a_frame_that_arrives_in_time_is_still_read():
    """Positive control: a normal frame is unaffected by the deadline."""
    left, right = _silent_peer()
    try:
        payload = b"y" * 1024
        left.sendall(len(payload).to_bytes(4, "big") + payload)
        assert _recv_frame(right, deadline=time.monotonic() + 5.0) == payload
    finally:
        left.close()
        right.close()


def test_frame_read_without_a_deadline_keeps_working():
    """The default stays permissive, because callers other than the driver pass nothing."""
    left, right = _silent_peer()
    try:
        left.sendall((3).to_bytes(4, "big") + b"abc")
        assert _recv_frame(right) == b"abc"
    finally:
        left.close()
        right.close()


# ------------------------------------------- F10: the sandbox patch is platform limited


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
        [sys.executable, "-c", "import os; print(getattr(os.mkdir, '__name__', 'builtin'))"],
        capture_output=True,
        text=True,
        env=environment,
        check=True,
    )
    return completed.stdout.strip()


def test_sandbox_patch_is_off_without_any_marker():
    """F10: no marker, no patch — unchanged from the previous round."""
    assert _run_with_sandbox_path({"DSH_SESSION_ID": None}) == "mkdir"


def test_sandbox_patch_can_be_turned_off_explicitly():
    """F10: an explicit off switch must win over the sandbox marker."""
    assert (
        _run_with_sandbox_path({"DSH_SESSION_ID": "audit-test", "DSH_SANDBOX_PYFIX": "0"}) == "mkdir"
    )


def test_sandbox_patch_applies_under_the_sandbox_on_windows():
    """The positive control: under the sandbox, on the platform it exists for, it applies."""
    if os.name != "nt":
        pytest.skip("the patch exists for Windows directory DACLs")
    assert (
        _run_with_sandbox_path({"DSH_SESSION_ID": "audit-test"}) == "_mkdir_with_inheritable_dacl"
    )


def test_sandbox_patch_module_documents_the_platform_limit():
    """F10: the limit is readable in the source, not only in this test."""
    source = (SANDBOX_PYFIX / "sitecustomize.py").read_text(encoding="utf-8")
    assert "os.name" in source and "nt" in source
    assert "DSH_SANDBOX_PYFIX" in source
