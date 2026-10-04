"""State both handshake roles share: transcript, key schedule, and record layers."""

from __future__ import annotations

from ..config import HybridTLSConfig
from ..key_schedule.hkdf import KeySchedule, derive_secret, hkdf_expand_label
from ..record.aead import CONTENT_TYPE_HANDSHAKE, RecordLayer
from ..metrics import Metrics
from .transcript import Transcript

__all__ = ["HandshakeState"]


class HandshakeState:
    """Common state for one side of one handshake.

    Each side keeps its own :class:`KeySchedule` and derives both directions of the
    record layer from the same transcript, so a mismatch anywhere in the exchanged
    bytes shows up as a failed Finished check rather than as silently divergent keys.
    """

    def __init__(self, config: HybridTLSConfig, role: str, metrics: Metrics | None = None) -> None:
        self.config = config
        self.role = role
        self.metrics = metrics or Metrics()
        self.transcript = Transcript(config.hash_name)
        self.schedule = KeySchedule(
            hash_name=config.hash_name,
            aead_key_length=config.aead_suite().key_length,
            aead_iv_length=config.aead_suite().iv_length,
        )
        self.client_records: RecordLayer | None = None
        self.server_records: RecordLayer | None = None
        self.application_client_records: RecordLayer | None = None
        self.application_server_records: RecordLayer | None = None
        self.hybrid_secret: bytes | None = None
        self.z_ecdh: bytes | None = None
        self.ss_pq: bytes | None = None

    # -- key schedule -------------------------------------------------------

    def setup_handshake_keys(self, z_hybrid: bytes) -> None:
        """Derive the handshake secret and both handshake-direction record layers."""
        suite = self.config.aead_suite()
        with self.metrics.time("kdf_handshake_secret"):
            self.schedule.derive_early_secret()
            self.schedule.derive_handshake_secret(z_hybrid)
        with self.metrics.time("kdf_handshake_traffic"):
            pair = self.schedule.derive_handshake_traffic(self.transcript.hash())
            client_key, client_iv = self.schedule.traffic_keys(pair.client)
            server_key, server_iv = self.schedule.traffic_keys(pair.server)
        self.client_records = RecordLayer(suite, client_key, client_iv)
        self.server_records = RecordLayer(suite, server_key, server_iv)

    def setup_application_keys(self) -> None:
        """Derive the application traffic secrets and both application record layers.

        **Call this while the transcript ends at the server's Finished.** RFC 8446
        section 7.1 derives ``c ap traffic``, ``s ap traffic`` and ``exp master`` over
        that prefix; the client's Finished extends the transcript and must be added only
        afterwards. Both roles used to call this after adding the client Finished, which
        made the harness self-consistent and non-conformant at the same time — an
        independent audit found it.
        """
        suite = self.config.aead_suite()
        with self.metrics.time("kdf_master_secret"):
            self.schedule.derive_master_secret()
        with self.metrics.time("kdf_application_traffic"):
            pair = self.schedule.derive_application_traffic(self.transcript.hash())
            client_key, client_iv = self.schedule.traffic_keys(pair.client)
            server_key, server_iv = self.schedule.traffic_keys(pair.server)
        self.application_client_records = RecordLayer(suite, client_key, client_iv)
        self.application_server_records = RecordLayer(suite, server_key, server_iv)

    def setup_resumption_secret(self) -> None:
        """Derive ``res master`` over the transcript that now includes the client Finished."""
        with self.metrics.time("kdf_resumption_secret"):
            self.schedule.derive_resumption_master_secret(self.transcript.hash())

    # -- record helpers -----------------------------------------------------

    def seal_handshake(self, payload: bytes) -> bytes:
        """Protect one handshake message with the sending direction's handshake keys."""
        if self.client_records is None or self.server_records is None:
            raise RuntimeError("handshake keys are not available yet")
        layer = self.client_records if self.role == "client" else self.server_records
        return layer.seal(CONTENT_TYPE_HANDSHAKE, payload)

    def open_handshake(self, record: bytes) -> bytes:
        """Unprotect one record received on the handshake keys."""
        if self.client_records is None or self.server_records is None:
            raise RuntimeError("handshake keys are not available yet")
        layer = self.server_records if self.role == "client" else self.client_records
        content_type, payload = layer.open(record, CONTENT_TYPE_HANDSHAKE)
        if content_type != CONTENT_TYPE_HANDSHAKE:
            raise ValueError(f"expected a handshake record, received content type {content_type}")
        return payload

    def finished_verify_data(self, direction: str) -> bytes:
        """Compute Finished ``verify_data`` for ``direction`` over the current transcript."""
        secret = (
            self.schedule.client_handshake_traffic
            if direction == "client"
            else self.schedule.server_handshake_traffic
        )
        if secret is None:
            raise RuntimeError("handshake traffic secrets are not available yet")
        return self.schedule.compute_finished(secret, self.transcript.hash())

    def exporter_secret(self, label: str, context: bytes, length: int = 32) -> bytes:
        """Export keying material from the exporter master secret (RFC 8446 section 7.5).

        The construction is

            Derive-Secret(ExporterMasterSecret, label, "")    -- empty transcript hash
            HKDF-Expand-Label(that, "exporter", Hash(context), length)

        and both details matter. An earlier version passed the *current transcript hash*
        where the RFC puts the empty hash, and the raw context where the RFC puts its hash.
        Both endpoints made the same mistake, so the handshake still agreed — which is
        exactly how an interoperability bug hides from an equality test. A static security
        review found it; `tests/test_security_fixes.py` now checks this against an
        independent implementation of the RFC expression rather than against the peer.
        """
        if self.schedule.exporter_master_secret is None:
            raise RuntimeError("exporter master secret is not available yet")
        empty_hash = self.schedule.hash_bytes(b"")
        derived = derive_secret(
            self.schedule.exporter_master_secret, label, empty_hash, self.config.hash_name
        )
        return hkdf_expand_label(
            derived,
            "exporter",
            self.schedule.hash_bytes(context),
            length,
            self.config.hash_name,
        )
