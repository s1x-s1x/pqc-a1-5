"""CA failure diagnostics and bounded receiver controls; no benchmark samples.

Certificate/signature operations are mocked here. Existing streaming tests retain
the actual long-DER, AEAD, transcript and Finished functional coverage.
"""
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tls import alt_chain
from tls.config import HybridTLSConfig
from tls.errors import HandshakeError
from tls.handshake.client import HybridClient, _EXPECTED_FLIGHT
from tls.record.aead import CONTENT_TYPE_HANDSHAKE, MAX_CONTENT_BYTES, RecordLayer, get_aead_suite
from tls.wire import handshake_message, split_handshake_message

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.signing_budget import SigningBudget


def mock_issuer(monkeypatch, failure):
    """Keep the real CA control flow while bypassing key/certificate operations."""
    primary = ValueError("primary " + failure)
    signer = SimpleNamespace(name="ml-dsa-44", signature_bytes=5,
                             sign=Mock(return_value=b"INERT"), verify=Mock(return_value=True))
    build_calls = []
    def build(**kwargs):
        build_calls.append(kwargs)
        if failure == "assembly" and len(build_calls) == 2:
            raise primary
        return SimpleNamespace(tbs_certificate_bytes=b"draft" if len(build_calls) == 1 else b"final")
    def pretbs(blob):
        return b"changed" if failure == "pretbs" and blob == b"final" else b"fixed input"
    monkeypatch.setattr(alt_chain, "_issue_fixed", build)
    monkeypatch.setattr(alt_chain, "pre_tbs", pretbs)
    if failure == "sign":
        signer.sign.side_effect = primary
    elif failure == "verify":
        signer.verify.side_effect = primary
    return signer, primary


@pytest.mark.parametrize("failure", ["sign", "verify", "assembly", "pretbs"])
@pytest.mark.parametrize("persist_first", [False, True])
def test_ca_double_failure_preserves_primary_and_never_refunds(tmp_path, monkeypatch, failure, persist_first):
    signer, primary = mock_issuer(monkeypatch, failure)
    ledger = SigningBudget(tmp_path / "ca.sqlite")
    finishes = []
    def finalize(receipt, signature):
        finishes.append((receipt, signature))
        if persist_first:
            ledger.finish(receipt, signature)
        raise RuntimeError("secondary ledger failure")
    with pytest.raises(ValueError) as caught:
        alt_chain.issue_alt_certificate(name=signer.name, signer=signer, secret_key=b"fixture",
            issuer_public_key=b"fixture", before_sign=ledger.reserve, after_sign=finalize)
    if failure != "pretbs":
        assert caught.value is primary
    else:
        assert "preTBS changed" in str(caught.value)
    assert caught.value.__notes__ == ["CA budget finalization also failed: secondary ledger failure"]
    assert len(finishes) == 1 and finishes[0][1] is None
    state = ledger.status()[0]
    assert state["used"] == 1 and state["count_reconciled"]
    assert state["states"] == {"failed" if persist_first else "reserved": 1}


def test_ca_success_finalizer_failure_still_stops_publication(tmp_path, monkeypatch):
    signer, _ = mock_issuer(monkeypatch, "success")
    ledger = SigningBudget(tmp_path / "ca.sqlite")
    finalizer = Mock(side_effect=RuntimeError("ledger unavailable"))
    with pytest.raises(RuntimeError, match="ledger unavailable") as caught:
        alt_chain.issue_alt_certificate(name=signer.name, signer=signer, secret_key=b"fixture",
            issuer_public_key=b"fixture", before_sign=ledger.reserve, after_sign=finalizer)
    assert not getattr(caught.value, "__notes__", None)
    assert finalizer.call_count == 1 and finalizer.call_args.args[1] == b"INERT"
    assert ledger.status()[0]["states"] == {"reserved": 1}
    assert ledger.status()[0]["used"] == 1


def test_ca_interrupt_preserved_when_finalizer_also_fails(monkeypatch):
    signer, _ = mock_issuer(monkeypatch, "sign")
    interrupted = KeyboardInterrupt("interrupted signer")
    signer.sign.side_effect = interrupted
    with pytest.raises(KeyboardInterrupt) as caught:
        alt_chain.issue_alt_certificate(name=signer.name, signer=signer, secret_key=b"fixture",
            issuer_public_key=b"fixture", before_sign=lambda *args: "receipt",
            after_sign=Mock(side_effect=RuntimeError("finalizer failed")))
    assert caught.value is interrupted and "finalizer failed" in caught.value.__notes__[0]


def mock_receiver(monkeypatch, **limits):
    config = HybridTLSConfig(pq_enabled=False, **limits)
    client = HybridClient(config, authority=None)
    opened, consumed, derived = [], [], []
    def open_record(record):
        opened.append(record)
        return record[:-17]  # Fixture shape, no actual AEAD operation.
    def consume(frame):
        message_type, _ = split_handshake_message(frame)
        expected = _EXPECTED_FLIGHT[client._server_flight_index][1]
        if message_type != expected:
            raise HandshakeError("server_flight", "wrong message type")
        consumed.append(frame)
    def derive():
        derived.append(True)
        client.application_client_records = object()
        client.application_server_records = object()
        client.schedule.exporter_master_secret = b"fixture exporter"
    monkeypatch.setattr(client, "open_handshake", open_record)
    monkeypatch.setattr(client, "_consume_server_handshake", consume)
    monkeypatch.setattr(client, "setup_application_keys", derive)
    return client, opened, consumed, derived


def fixture_record(payload):
    return payload + bytes(17)


def assert_terminal(client, monkeypatch):
    assert client._server_flight_failed and not client.server_flight_complete
    assert not client._handshake_buffer
    assert client.application_client_records is client.application_server_records is None
    assert client.schedule.exporter_master_secret is None
    monkeypatch.setattr(client, "open_handshake", Mock(side_effect=AssertionError("retried decryption")))
    for operation in (lambda: client.receive_server_record(fixture_record(b"x")),
                      client.finish_server_flight, client.send_client_finished):
        with pytest.raises(HandshakeError, match="already failed"):
            operation()


@pytest.mark.parametrize("field,limit,fragments,opened_count,reason", [
    ("server_flight_max_records", 2, [b"\x08", b"\0", b"\0"], 2, "record budget"),
    ("server_flight_max_audit_entries", 1, [b"\x08", b"\0"], 1, "audit entry budget"),
    ("server_flight_max_ciphertext_bytes", 18, [b"\x08", b"\0"], 1, "ciphertext budget"),
    ("server_flight_max_plaintext_bytes", 2, [b"\x08\0", b"\0"], 2, "plaintext budget"),
])
def test_flight_limits_bound_work_and_audit_before_growth(monkeypatch, field, limit, fragments, opened_count, reason):
    client, opened, consumed, derived = mock_receiver(monkeypatch, **{field: limit})
    with pytest.raises(HandshakeError, match=reason):
        for payload in fragments:
            client.receive_server_record(fixture_record(payload))
    assert len(opened) == opened_count and not consumed and not derived
    assert len(client.server_flight_fragments) <= 2
    assert_terminal(client, monkeypatch)


class ObservedBuffer(bytearray):
    def __init__(self):
        super().__init__()
        self.copied = []
    def extend(self, data):
        self.copied.append(len(data))
        super().extend(data)


@pytest.mark.parametrize("split_header", [False, True])
def test_oversized_announced_message_rejected_before_body_copy(monkeypatch, split_header):
    client, opened, _, _ = mock_receiver(monkeypatch)
    client._handshake_buffer = ObservedBuffer()
    header = bytes([8]) + (1 << 20).to_bytes(3, "big")  # body + header exceeds 1 MiB
    if split_header:
        client.receive_server_record(fixture_record(header[:2]))
        final = header[2:] + bytes(1000)
    else:
        final = header + bytes(1000)
    with pytest.raises(HandshakeError, match="message exceeds"):
        client.receive_server_record(fixture_record(final))
    assert sum(client._handshake_buffer.copied) == 4
    assert_terminal(client, monkeypatch)


def test_record_size_limit_checked_before_decryption(monkeypatch):
    client, opened, _, _ = mock_receiver(monkeypatch)
    with pytest.raises(HandshakeError, match="16640"):
        client.receive_server_record(bytes(16641))
    assert not opened and not client.server_flight_fragments
    assert_terminal(client, monkeypatch)


def flight_frames(certificate_body=b"certificate"):
    return [handshake_message(kind, certificate_body if name == "Certificate" else b"x")
            for name, kind in _EXPECTED_FLIGHT]


def test_exact_aggregate_budgets_accept_split_headers_and_coalesced_messages(monkeypatch):
    frames = flight_frames()
    stream = b"".join(frames)
    fragments = [stream[:2], stream[2:3], stream[3:]]
    ciphertext_bytes = len(stream) + 17 * len(fragments)
    client, opened, consumed, derived = mock_receiver(monkeypatch,
        server_flight_max_records=3, server_flight_max_audit_entries=3,
        server_flight_max_plaintext_bytes=len(stream),
        server_flight_max_ciphertext_bytes=ciphertext_bytes)
    for fragment in fragments:
        client.receive_server_record(fixture_record(fragment))
    client.finish_server_flight()
    assert consumed == frames and derived == [True] and client.server_flight_complete
    assert client._server_flight_records == len(opened) == 3
    assert client._server_flight_plaintext_bytes == len(stream)
    assert client._server_flight_ciphertext_bytes == ciphertext_bytes


def test_default_limits_allow_one_mib_message_and_max_record_fragments(monkeypatch):
    frames = flight_frames(bytes((1 << 20) - 4))  # exact 1 MiB Certificate frame
    stream = b"".join(frames)
    client, opened, consumed, derived = mock_receiver(monkeypatch)
    for start in range(0, len(stream), MAX_CONTENT_BYTES):
        client.receive_server_record(fixture_record(stream[start:start + MAX_CONTENT_BYTES]))
    client.finish_server_flight()
    assert consumed == frames and client.server_flight_complete and derived == [True]
    assert len(opened) == 65
    assert all(len(record) <= MAX_CONTENT_BYTES + 17 for record in opened)


def test_default_record_budget_bounds_tiny_fragment_audit(monkeypatch):
    client, opened, _, derived = mock_receiver(monkeypatch)
    header = bytes([8]) + ((1 << 20) - 4).to_bytes(3, "big")
    client.receive_server_record(fixture_record(header))
    for _ in range(client.config.server_flight_max_records - 1):
        client.receive_server_record(fixture_record(b"x"))
    with pytest.raises(HandshakeError, match="record budget"):
        client.receive_server_record(fixture_record(b"x"))
    assert len(opened) == len(client.server_flight_fragments) == 4096
    assert not derived
    assert_terminal(client, monkeypatch)


def test_plaintext_budget_covers_multiple_completed_messages(monkeypatch):
    frames = flight_frames()
    client, _, consumed, derived = mock_receiver(monkeypatch,
        server_flight_max_plaintext_bytes=len(frames[0]) + len(frames[1]) - 1)
    client.receive_server_record(fixture_record(frames[0]))
    with pytest.raises(HandshakeError, match="plaintext budget"):
        client.receive_server_record(fixture_record(frames[1]))
    assert consumed == [frames[0]] and not derived
    assert len(client.server_flight_fragments) == 1
    assert_terminal(client, monkeypatch)


def test_real_record_authentication_failure_terminates_attempt(monkeypatch):
    config = HybridTLSConfig(pq_enabled=False)
    client = HybridClient(config, authority=None)
    suite = get_aead_suite("aes-128-gcm")
    receiver = RecordLayer(suite, bytes(16), bytes(12))
    sender = RecordLayer(suite, bytes(16), bytes(12))
    client.server_records = receiver
    client.client_records = RecordLayer(suite, bytes(16), bytes(12))
    client.receive_server_record(sender.seal(CONTENT_TYPE_HANDSHAKE, b"\x08"))
    record = sender.seal(CONTENT_TYPE_HANDSHAKE, b"\0")
    corrupted = record[:-1] + bytes([record[-1] ^ 1])
    with pytest.raises(HandshakeError, match="authentication"):
        client.receive_server_record(corrupted)
    assert receiver.sequence == 1  # Failed AEAD did not advance its counter.
    assert len(client.server_flight_fragments) == 1
    assert_terminal(client, monkeypatch)


@pytest.mark.parametrize("failure", ["bad_type", "empty", "truncated", "trailing", "after_finished"])
def test_any_failed_flight_is_terminal_even_after_keys_were_derived(monkeypatch, failure):
    client, _, _, derived = mock_receiver(monkeypatch)
    stream = b"".join(flight_frames())
    with pytest.raises(HandshakeError):
        if failure == "bad_type":
            client.receive_server_record(fixture_record(handshake_message(99, b"x")))
        elif failure == "empty":
            client.receive_server_record(fixture_record(b""))
        elif failure == "truncated":
            client.receive_server_record(fixture_record(stream[:3]))
            client.finish_server_flight()
        elif failure == "trailing":
            client.receive_server_record(fixture_record(stream + b"x"))
        else:
            client.receive_server_record(fixture_record(stream))
            assert derived == [True]
            client.receive_server_record(fixture_record(b"x"))
    assert_terminal(client, monkeypatch)


@pytest.mark.parametrize("field", ["server_flight_max_records", "server_flight_max_plaintext_bytes",
                                  "server_flight_max_ciphertext_bytes", "server_flight_max_audit_entries"])
@pytest.mark.parametrize("value", [0, -1, True, 1.5])
def test_invalid_resource_policy_rejected_during_configuration(field, value):
    with pytest.raises((TypeError, ValueError)):
        HybridTLSConfig(pq_enabled=False, **{field: value})


def test_resource_policy_is_recorded_in_profile_description():
    config = HybridTLSConfig(pq_enabled=False, server_flight_max_records=100)
    description = config.describe()
    assert description["server_flight_max_records"] == "100"
    for field in ("server_flight_max_plaintext_bytes", "server_flight_max_ciphertext_bytes",
                  "server_flight_max_audit_entries"):
        assert description[field] == str(getattr(config, field))
