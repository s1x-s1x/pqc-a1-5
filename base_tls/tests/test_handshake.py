"""End-to-end contract tests for the hybrid handshake.

The tests drive real handshakes through
:class:`~tls.handshake.connection.HybridConnection` and through the client/server
halves directly, and pin the properties the design claims:

* a complete handshake works for every post-quantum signature backend, and both
  sides derive the *same* traffic secrets (compared as secret bytes);
* the client accepts only when the classical *and* the post-quantum signature
  verify, and reports which one failed;
* tampering with any single authenticated field is rejected at a named step;
* the client Finished is bound to the transcript, so a re-sealed forgery with the
  right key and the right sequence number still fails on the verify_data;
* the XMSS backend spends exactly one leaf per handshake and reports the rest;
* ``ecdh-kem-placeholder`` completes but is never reported as post-quantum.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any

import pytest

# conftest is importable because pytest puts the test directory on sys.path; the profile
# catalogue lives there so every module agrees on which profiles this machine has.
from conftest import PROFILES

from tls.config import HybridTLSConfig
from tls.credentials import CertificateAuthority, IssuedCertificate, ServerCredentials
from tls.errors import HandshakeError, HybridTLSError
from tls.handshake.certificate_verify import (
    HybridCertificateVerify,
    HybridVerificationResult,
    build_certificate_verify_input,
)
from tls.handshake.client import HybridClient
from tls.handshake.connection import DEFAULT_APPLICATION_PAYLOAD, HybridConnection, measured_pq_deltas
from tls.handshake.messages import CERTIFICATE_VERIFY, Certificate, CertificateVerify, Finished
from tls.handshake.server import HybridServer
from tls.handshake.transcript import Transcript
from tls.record.aead import (
    CONTENT_TYPE_APPLICATION_DATA,
    CONTENT_TYPE_HANDSHAKE,
    RecordLayer,
    get_aead_suite,
)
from tls.wire import split_handshake_message

#: The profiles the end-to-end test must cover: a lattice signature, a
#: module-lattice signature, and a stateful hash-based signature. The Falcon entry is
#: conditional on its provider being installed, so the list is built from what the
#: fixtures actually carry rather than hard-coded; a test that needs only *a* signer
#: must not fail because an optional one is missing.
XMSS_PROFILE = "ml-kem-768+xmss-h6"

#: The profiles the parametrized end-to-end test covers. Built from the fixture catalogue at
#: import time, so a Falcon-free machine parametrizes over the profiles it actually has.
AVAILABLE_PROFILES = tuple(PROFILES)


def _profile_with(fast_profiles: dict, *required: str) -> tuple[str, object]:
    """Return the first (name, config) whose name contains every required fragment."""
    for name, config in fast_profiles.items():
        if all(fragment in name for fragment in required):
            return name, config
    raise AssertionError(f"no profile matching {required!r}; have {sorted(fast_profiles)}")


# ------------------------------------------------------------------- corruptions


def flip_first_byte(data: bytes) -> bytes:
    """Return ``data`` with its first byte flipped."""
    assert data, "nothing to corrupt"
    return bytes([data[0] ^ 0x01]) + data[1:]


def _corrupt_certificate_verify_signature(frame: bytes, which: str) -> bytes:
    """Flip one byte of the classical or post-quantum signature in a CertificateVerify frame."""
    message_type, body = split_handshake_message(frame)
    assert message_type == CERTIFICATE_VERIFY, "the filter only rewrites CertificateVerify"
    payload = HybridCertificateVerify.decode(CertificateVerify.decode(body).payload)
    field_name = "classic_signature" if which == "classic" else "pq_signature"
    broken_signature = flip_first_byte(getattr(payload, field_name))
    broken = HybridCertificateVerify(
        classic_scheme=payload.classic_scheme,
        classic_signature=broken_signature if which == "classic" else payload.classic_signature,
        pq_scheme=payload.pq_scheme,
        pq_signature=broken_signature if which != "classic" else payload.pq_signature,
    )
    return CertificateVerify(payload=broken.encode()).to_message()


def _corrupt_ca_signature(frame: bytes) -> bytes:
    """Flip one byte of the CA signature inside a Certificate frame."""
    _message_type, body = split_handshake_message(frame)
    certificate = Certificate.decode(body)
    return Certificate(
        body=certificate.body,
        ca_signature=flip_first_byte(certificate.ca_signature),
        extensions=certificate.extensions,
        certificate_request_context=certificate.certificate_request_context,
    ).to_message()


def _corrupt_server_hello_kem_ciphertext(frame: bytes) -> bytes:
    """Flip the last byte of ServerHello, which is the last byte of the KEM ciphertext."""
    return flip_first_byte(frame[::-1])[::-1]


def tamper_filter(tamper: str) -> Callable[[str, bytes], bytes] | None:
    """Return the ``frame_filter`` that corrupts one field, or ``None`` for an honest run."""
    if tamper == "pq-signature":
        return lambda name, frame: (
            _corrupt_certificate_verify_signature(frame, "pq")
            if name == "CertificateVerify"
            else frame
        )
    if tamper == "classic-signature":
        return lambda name, frame: (
            _corrupt_certificate_verify_signature(frame, "classic")
            if name == "CertificateVerify"
            else frame
        )
    if tamper == "certificate":
        return lambda name, frame: _corrupt_ca_signature(frame) if name == "Certificate" else frame
    # The KEM ciphertext is corrupted on the ServerHello wire path, not in a flight frame.
    assert tamper in ("none", "kem-ciphertext"), f"unknown tamper {tamper!r}"
    return None


TAMPER_CASES = (
    pytest.param("pq-signature", "certificate_verify", id="pq-signature"),
    pytest.param("classic-signature", "certificate_verify", id="classic-signature"),
    pytest.param("certificate", "certificate", id="ca-signature"),
    pytest.param("kem-ciphertext", "record", id="kem-ciphertext"),
)


# --------------------------------------------------------------- handshake driving


@dataclass
class Session:
    """One in-process handshake, with both halves and the credentials that signed it."""

    config: HybridTLSConfig
    authority: CertificateAuthority
    credentials: ServerCredentials
    certificate: IssuedCertificate
    client: HybridClient
    server: HybridServer
    flight: list[tuple[str, bytes, bytes]] = field(default_factory=list)


def open_session(
    config: HybridTLSConfig,
    *,
    credentials: ServerCredentials | None = None,
    certificate: IssuedCertificate | None = None,
    authority: CertificateAuthority | None = None,
    frame_filter: Callable[[str, bytes], bytes] | None = None,
    server_hello_filter: Callable[[bytes], bytes] | None = None,
) -> Session:
    """Run ClientHello..server authenticated flight; the client Finished is *not* sent.

    Passing an existing ``authority``/``credentials``/``certificate`` triple reuses
    one server key pair across handshakes, which is what the one-time-signature
    accounting test needs. ``frame_filter`` is handed to
    :meth:`HybridServer.send_authenticated_flight`, so it rewrites a frame *before*
    it is hashed into the transcript and sealed; ``server_hello_filter`` rewrites
    ServerHello on the wire.
    """
    authority = authority or CertificateAuthority(config.classical())
    credentials = credentials or ServerCredentials(config)
    certificate = certificate or credentials.bind_to(authority)
    client = HybridClient(config, authority)
    server = HybridServer(config, credentials, certificate)

    server_hello = server.receive_client_hello(client.create_client_hello())
    if server_hello_filter is not None:
        server_hello = server_hello_filter(server_hello)
    client.receive_server_hello(server_hello)

    flight = server.send_authenticated_flight(frame_filter)
    client.receive_server_flight([record for _, record, _ in flight])
    return Session(config, authority, credentials, certificate, client, server, flight)


def complete_session(session: Session) -> Session:
    """Send the client Finished and let the server verify it."""
    session.server.receive_client_finished(session.client.send_client_finished())
    return session


def run_session(config: HybridTLSConfig, **kwargs: Any) -> Session:
    """Drive one complete handshake and return both halves."""
    return complete_session(open_session(config, **kwargs))


# -------------------------------------------------------------------- end to end


@pytest.mark.parametrize("profile_name", AVAILABLE_PROFILES)
def test_end_to_end_handshake_completes_and_agrees_on_every_secret(profile_name, fast_profiles):
    """A full handshake succeeds and both halves derive identical traffic secrets."""
    config = fast_profiles[profile_name]
    result = HybridConnection.run(config, application_payload=DEFAULT_APPLICATION_PAYLOAD)

    assert result.application_payload_ok is True
    assert result.exporters_match is True
    assert result.profile["kem"] == config.kem and result.profile["pq_signer"] == config.pq_signer

    client_schedule, server_schedule = result.client.schedule, result.server.schedule
    # Secrets, not keys: the bytes every later derivation is expanded from.
    assert client_schedule.client_handshake_traffic == server_schedule.client_handshake_traffic
    assert client_schedule.server_handshake_traffic == server_schedule.server_handshake_traffic
    assert client_schedule.client_application_traffic == server_schedule.client_application_traffic
    assert client_schedule.server_application_traffic == server_schedule.server_application_traffic
    assert client_schedule.exporter_master_secret == server_schedule.exporter_master_secret
    assert client_schedule.handshake_secret == server_schedule.handshake_secret
    assert client_schedule.master_secret == server_schedule.master_secret

    for secret in (
        client_schedule.client_handshake_traffic,
        client_schedule.server_handshake_traffic,
        client_schedule.client_application_traffic,
        client_schedule.server_application_traffic,
    ):
        assert len(secret) == 32

    # Directions and stages are genuinely different secrets, not one value reused.
    assert client_schedule.client_handshake_traffic != client_schedule.server_handshake_traffic
    assert client_schedule.client_application_traffic != client_schedule.server_application_traffic
    assert client_schedule.client_handshake_traffic != client_schedule.client_application_traffic

    # Both halves agree on the hybrid secret and on both of its branches.
    assert result.client.hybrid_secret == result.server.hybrid_secret
    assert result.client.z_ecdh == result.server.z_ecdh
    assert result.client.ss_pq == result.server.ss_pq
    assert len(result.client.kem_public or b"") == result.kem.public_key_bytes
    assert len(result.server.kem_ciphertext or b"") == result.kem.ciphertext_bytes


def test_end_to_end_handshake_reports_its_cost_consistently(default_profile):
    """The byte accounting in ``HandshakeResult`` adds up and describes the same run."""
    result = HybridConnection.run(default_profile)

    assert result.handshake_bytes == sum(record.total_bytes for record in result.messages)
    assert result.plaintext_bytes + sum(r.protection_bytes for r in result.messages) == result.handshake_bytes
    assert result.client_bytes + result.server_bytes == result.handshake_bytes
    assert result.plaintext_bytes <= result.handshake_bytes

    deltas = result.pq_deltas()
    assert set(deltas) == {
        "client_hello.pq_key_share",
        "client_hello.pq_signature_algorithm",
        "server_hello.pq_ciphertext",
        "certificate.pq_public_key",
        "certificate_verify.pq_signature",
    }
    assert all(value > 0 for value in deltas.values())
    assert result.classical_only_estimate() == result.handshake_bytes - sum(deltas.values())

    # The decomposition is exact against a MEASURED baseline: the same profile run with
    # the post-quantum material removed, through the same code path. This is what makes
    # the baseline a measurement rather than an estimate.
    comparison = measured_pq_deltas(default_profile)
    baseline = comparison["baseline"]
    assert baseline.handshake_bytes < result.handshake_bytes
    assert baseline.application_payload_ok and baseline.exporters_match
    assert comparison["total"] == comparison["hybrid"].handshake_bytes - baseline.handshake_bytes
    assert comparison["client_hello"] == comparison["per_message"]["ClientHello"]
    assert comparison["server_hello"] == comparison["per_message"]["ServerHello"]
    assert comparison["certificate"] == comparison["per_message"]["Certificate"]
    assert comparison["certificate_verify"] == comparison["per_message"]["CertificateVerify"]
    # Every added field costs bytes, and the analytic estimate is close to the measured
    # total -- close, not equal: Falcon signatures vary in length per signature.
    assert all(value > 0 for value in comparison["per_message"].values() if value)
    assert comparison["per_message"]["ServerHello"] == result.kem.ciphertext_bytes + 6
    assert abs(int(comparison["analytic_estimate"]) - int(comparison["total"])) <= 4
    assert result.bytes_for("Finished") == baseline.bytes_for("Finished")

    report = result.report()
    assert all(
        text in report
        for text in ("handshake bytes", "post-quantum additions", "exporter secrets agree")
    )

    # Exactly one KEM operation and one signature operation per side per handshake.
    counts = result.metrics.counts
    assert counts["client_kem_keygen_calls"] == 1
    assert counts["client_kem_decaps_calls"] == 1
    assert counts["server_kem_encaps_calls"] == 1
    assert counts["client_verify_classical_calls"] == 1
    assert counts["client_verify_pq_calls"] == 1
    assert counts["server_sign_classical_calls"] == 1
    assert counts["server_sign_pq_calls"] == 1


def test_the_client_certificate_adopts_the_servers_public_keys(default_profile):
    """The keys the client verifies against are the server credentials' own public keys."""
    result = HybridConnection.run(default_profile)
    certificate = result.client.certificate
    assert certificate is not None
    body = certificate.body
    credentials = result.server.credentials

    assert body.classical_public_key == credentials.classical_public
    assert body.pq_public_key == credentials.pq_public
    assert body.server_identity == credentials.identity == b"server.example"
    assert body.classical_scheme == result.classical_signer.scheme_id
    assert body.pq_scheme == result.pq_signer.scheme_id
    assert certificate.ca_signature == result.certificate.signature
    # Checked through the authority rather than through a convenience method on the issued
    # certificate: that method existed only for this assertion, and
    # `tools/audit_live_checks.py` exists precisely to find validating code that nothing on
    # the handshake path calls. The assertion is the same one.
    assert (
        result.certificate.authority.verify(
            result.certificate.body, result.certificate.signature
        )
        is True
    )
    assert len(body.classical_public_key) == result.classical_signer.public_key_bytes
    assert len(body.pq_public_key) == result.pq_signer.public_key_bytes


def test_the_client_verifies_both_signatures_over_the_same_server_input(default_profile):
    """Both signatures in CertificateVerify validate over one identical input."""
    result = HybridConnection.run(default_profile)
    verification = result.client.verification

    assert isinstance(verification, HybridVerificationResult)
    assert verification.classic_ok is True
    assert verification.pq_ok is True
    assert verification.accepted is True

    payload = result.client.certificate_verify
    message = result.client.certificate_verify_input
    assert payload is not None and message is not None
    # The input is the TLS 1.3 server-role context string, not a bare transcript hash.
    assert message == build_certificate_verify_input(
        message[len(b"\x20" * 64) + len(b"TLS 1.3, server CertificateVerify\x00") :], role="server"
    )
    assert message.startswith(b"\x20" * 64 + b"TLS 1.3, server CertificateVerify\x00")

    # Re-verifying here proves the payload, the transmitted keys and the input agree.
    body = result.client.certificate.body
    assert result.classical_signer.verify(body.classical_public_key, message, payload.classic_signature)
    assert result.pq_signer.verify(body.pq_public_key, message, payload.pq_signature)
    assert payload.classic_scheme == result.classical_signer.scheme_id
    assert payload.pq_scheme == result.pq_signer.scheme_id
    assert payload.overhead_bytes() == 8


@pytest.mark.parametrize(("classic_ok", "pq_ok", "accepted"), [
    pytest.param(True, True, True, id="both-valid"),
    pytest.param(True, False, False, id="pq-forged"),
    pytest.param(False, True, False, id="classic-forged"),
    pytest.param(False, False, False, id="both-forged"),
])
def test_hybrid_verification_result_is_the_conjunction(classic_ok, pq_ok, accepted):
    """``accepted`` is true only when both signatures verify: neither half carries the other."""
    result = HybridVerificationResult(classic_ok=classic_ok, pq_ok=pq_ok)
    assert result.accepted is accepted
    assert result.accepted == (result.classic_ok and result.pq_ok)


# ------------------------------------------------------------------ tamper matrix


@pytest.mark.parametrize(("tamper", "expected_step"), TAMPER_CASES)
def test_tampered_handshake_is_rejected_at_the_expected_step(default_profile, tamper, expected_step):
    """One corrupted field, one named rejection -- and the handshake never completes."""
    with pytest.raises(HybridTLSError) as excinfo:
        run_session(
            default_profile,
            frame_filter=tamper_filter(tamper),
            server_hello_filter=(
                _corrupt_server_hello_kem_ciphertext if tamper == "kem-ciphertext" else None
            ),
        )
    assert isinstance(excinfo.value, HandshakeError)
    assert excinfo.value.step == expected_step


def test_an_honest_run_through_the_same_helper_completes(default_profile):
    """Control for the tamper matrix: the corruption, not the harness, causes the failure."""
    session = run_session(default_profile, frame_filter=tamper_filter("none"))
    assert session.client.verification is not None
    assert session.client.verification.accepted is True
    assert session.server.received_client_finished is not None
    assert [name for name, _, _ in session.flight] == [
        "EncryptedExtensions",
        "Certificate",
        "CertificateVerify",
        "Finished",
    ]


def test_a_corrupted_kem_ciphertext_is_only_caught_by_the_record_layer(default_profile):
    """ML-KEM decapsulation never fails, so the tamper surfaces as a key mismatch."""
    with pytest.raises(HandshakeError) as excinfo:
        run_session(default_profile, server_hello_filter=_corrupt_server_hello_kem_ciphertext)
    assert excinfo.value.step == "record"
    assert "failed authentication" in excinfo.value.reason


# -------------------------------------------------------------- transcript binding


def test_a_flipped_client_finished_record_is_rejected(default_profile):
    """The client Finished is AEAD protected: one flipped ciphertext byte fails the tag."""
    session = open_session(default_profile)
    record = session.client.send_client_finished()
    corrupted = flip_first_byte(record)

    with pytest.raises(HandshakeError) as excinfo:
        session.server.receive_client_finished(corrupted)
    assert excinfo.value.step == "record"
    assert session.server.received_client_finished is None


def test_a_re_sealed_client_finished_is_accepted_only_with_the_right_verify_data(default_profile):
    """Transcript binding: same key, same sequence, same framing -- only the MAC differs.

    The record is sealed with the client's real handshake key and with the sequence
    number the server is about to expect, so the AEAD tag check passes and the only
    thing left to reject the forgery is the verify_data HMAC over the transcript.
    Both cases go through the identical construction; only the verify_data is flipped.
    """
    accepted = []
    for flip in (False, True):
        session = open_session(default_profile)
        assert session.server.client_records is not None
        assert session.server.client_records.sequence == 0  # nothing opened yet

        schedule = session.client.schedule
        key, iv = schedule.traffic_keys(schedule.client_handshake_traffic)
        sealer = RecordLayer(default_profile.aead_suite(), key, iv)
        honest = session.client.finished_verify_data("client")
        verify_data = flip_first_byte(honest) if flip else honest
        record = sealer.seal(
            CONTENT_TYPE_HANDSHAKE, Finished(verify_data=verify_data).to_message()
        )

        if flip:
            with pytest.raises(HandshakeError) as excinfo:
                session.server.receive_client_finished(record)
            assert excinfo.value.step == "client_finished"
            assert "verify_data" in excinfo.value.reason
            assert session.server.received_client_finished is None
        else:
            session.server.receive_client_finished(record)
            assert session.server.received_client_finished == honest
        accepted.append(not flip)

    assert accepted == [True, False]  # both branches really ran


def test_the_client_finished_is_bound_to_the_whole_server_flight(default_profile):
    """Dropping CertificateVerify from the transcript changes the client's verify_data."""
    session = open_session(default_profile)
    honest = session.client.finished_verify_data("client")

    without_certificate_verify = Transcript(default_profile.hash_name)
    for name, _record, frame in session.flight:
        if name != "CertificateVerify":
            without_certificate_verify.add(frame)
    assert without_certificate_verify.byte_count < session.client.transcript.byte_count

    # Same Finished key, different transcript: the MAC must change.
    truncated = session.client.schedule.compute_finished(
        session.client.schedule.client_handshake_traffic, without_certificate_verify.hash()
    )
    assert truncated != honest


# ------------------------------------------------------ one-time signature leaves


def test_xmss_credentials_spend_one_leaf_per_handshake(fast_profiles):
    """Two handshakes on one key pair use leaves 0 and 1 and each spend one signature."""
    config = fast_profiles[XMSS_PROFILE]
    authority = CertificateAuthority(config.classical())
    credentials = ServerCredentials(config)
    certificate = credentials.bind_to(authority)

    backend = config.pq()
    assert backend.max_signatures == 2**config.xmss_height == 64
    assert credentials.pq_signatures_remaining() == backend.max_signatures

    indices = []
    for index in range(2):
        remaining_before = credentials.pq_signatures_remaining()
        session = run_session(
            config, authority=authority, credentials=credentials, certificate=certificate
        )
        payload = session.server.certificate_verify_payload
        assert payload is not None
        assert session.client.verification is not None and session.client.verification.accepted is True

        indices.append(int.from_bytes(payload.pq_signature[:4], "big"))
        assert credentials.pq_signatures_remaining() == remaining_before - 1
        assert credentials.pq_signatures_remaining() == backend.max_signatures - (index + 1)

    assert indices == [0, 1]
    assert credentials.pq_signatures_remaining() == backend.max_signatures - 2


def test_stateless_backends_report_no_signature_budget(default_profile):
    """``pq_signatures_remaining`` is ``None`` for stateless backends: unlimited, not zero."""
    credentials = ServerCredentials(default_profile)
    assert credentials.pq_signatures_remaining() is None
    assert not hasattr(credentials.pq_secret, "next_index")


# ----------------------------------------------------- placeholder KEM honesty


def test_the_placeholder_kem_completes_but_is_never_reported_post_quantum(fast_profiles):
    """The fallback branch keeps the protocol runnable and is labelled non-post-quantum."""
    _name, config = _profile_with(fast_profiles, "ecdh-kem-placeholder")
    result = HybridConnection.run(config)

    assert result.application_payload_ok is True
    assert result.exporters_match is True
    assert result.kem.name == "ecdh-kem-placeholder"
    assert result.kem.post_quantum is False
    assert config.kem_backend().post_quantum is False
    assert result.profile["kem"] == "ecdh-kem-placeholder"
    # It still contributes a real shared secret to the hybrid input.
    assert result.client.ss_pq == result.server.ss_pq
    assert len(result.client.ss_pq or b"") == 32
    assert result.client.hybrid_secret == result.server.hybrid_secret


def test_a_post_quantum_kem_is_reported_as_post_quantum(default_profile):
    """Control for the test above: a real KEM must report ``post_quantum`` true."""
    result = HybridConnection.run(default_profile)
    assert result.kem.post_quantum is True
    assert result.kem.shared_secret_bytes == 32


# ------------------------------------------------------------------- record layer


def test_record_layer_round_trips_and_separates_consecutive_records(default_profile):
    """Sealing advances the sequence number, so identical plaintexts give different records."""
    suite = get_aead_suite(default_profile.aead)
    sender = RecordLayer(suite, b"\x11" * suite.key_length, b"\x22" * suite.iv_length)
    receiver = RecordLayer(suite, b"\x11" * suite.key_length, b"\x22" * suite.iv_length)

    first = sender.seal(CONTENT_TYPE_HANDSHAKE, b"same payload")
    second = sender.seal(CONTENT_TYPE_HANDSHAKE, b"same payload")
    assert first != second
    assert len(first) == len(b"same payload") + 1 + suite.tag_length
    assert (sender.sequence, sender.records_sealed) == (2, 2)

    assert receiver.open(first, CONTENT_TYPE_HANDSHAKE) == (CONTENT_TYPE_HANDSHAKE, b"same payload")
    assert receiver.sequence == 1

    # The content type is authenticated: claiming another one breaks the tag.
    with pytest.raises(HandshakeError) as excinfo:
        receiver.open(second, CONTENT_TYPE_APPLICATION_DATA)
    assert excinfo.value.step == "record"
    assert receiver.sequence == 1  # a failed open consumes no sequence number

    assert receiver.open(second, CONTENT_TYPE_HANDSHAKE) == (CONTENT_TYPE_HANDSHAKE, b"same payload")
    assert receiver.sequence == 2


def test_application_keys_are_direction_specific_after_a_handshake(default_profile):
    """The two application directions use different keys, so cross-opening fails."""
    result = HybridConnection.run(default_profile)
    client_send = result.client.application_client_records
    client_recv = result.client.application_server_records
    server_recv = result.server.application_client_records
    assert client_send is not None and client_recv is not None and server_recv is not None

    assert client_send.key_fingerprint() != client_recv.key_fingerprint()
    record = client_send.seal(CONTENT_TYPE_APPLICATION_DATA, b"ping")
    with pytest.raises(HandshakeError):
        client_recv.open(record, CONTENT_TYPE_APPLICATION_DATA)
    assert server_recv.open(record, CONTENT_TYPE_APPLICATION_DATA) == (
        CONTENT_TYPE_APPLICATION_DATA,
        b"ping",
    )


def test_exported_keying_material_depends_on_the_label_and_the_context(default_profile):
    """Exporters are deterministic per (label, context) and differ across both."""
    result = HybridConnection.run(default_profile)
    client, server = result.client, result.server

    assert client.exporter_secret("label", b"ctx") == server.exporter_secret("label", b"ctx")
    assert client.exporter_secret("label", b"ctx") != client.exporter_secret("other", b"ctx")
    assert client.exporter_secret("label", b"ctx") != client.exporter_secret("label", b"other")
    assert len(client.exporter_secret("label", b"ctx")) == 32
    assert len(client.exporter_secret("label", b"ctx", length=17)) == 17


def test_handshake_bytes_are_recorded_with_their_protection_overhead(default_profile):
    """ClientHello and ServerHello are plaintext; everything after them carries a tag."""
    result = HybridConnection.run(default_profile)
    by_name = {record.name: record for record in result.messages}
    assert by_name["ClientHello"].protection_bytes == 0
    assert by_name["ServerHello"].protection_bytes == 0

    tag_overhead = default_profile.aead_suite().tag_length + 1  # actual inner type plus tag
    for name in ("EncryptedExtensions", "Certificate", "CertificateVerify", "Finished"):
        assert by_name[name].protection_bytes == tag_overhead

    assert by_name["Finished"].message_bytes == 4 + 32  # type, u24 length, 32-byte verify_data
    for name in ("ClientHello", "ServerHello"):
        assert result.bytes_for(name) == by_name[name].total_bytes


def test_the_negotiated_cipher_suite_is_the_configured_one(fast_profiles):
    """Every covered profile negotiates aes-128-gcm/sha256, whose code point is 0x1301."""
    for name, config in fast_profiles.items():
        session = run_session(config)
        assert session.client.server_hello is not None
        assert session.client.server_hello.cipher_suite == config.cipher_suite_id == 0x1301
        assert session.server.config.aead == "aes-128-gcm"
        assert len(session.client.schedule.client_application_traffic) == 32
