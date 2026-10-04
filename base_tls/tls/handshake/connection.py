"""Drive one complete hybrid handshake in process and account for what it cost.

The two halves run in the same process so the exchange can be measured without a
network in the loop; each handshake message is recorded with its plaintext size and
its record-protection overhead, which is what the size analysis in ``bench``
consumes.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, replace

from cryptography import x509

from ..classical.signature import ClassicalSigner
from ..config import HybridTLSConfig
from ..credentials import CertificateAuthority, IssuedCertificate, ServerCredentials
from ..metrics import TLS_RECORD_HEADER_BYTES, MessageRecord, Metrics
from ..pq.backends import KemBackend, PqSigner
from ..record.aead import CONTENT_TYPE_APPLICATION_DATA
from .client import HybridClient
from .server import HybridServer

__all__ = [
    "DEFAULT_APPLICATION_PAYLOAD",
    "HandshakeResult",
    "HybridConnection",
    "measured_pq_deltas",
]

DEFAULT_APPLICATION_PAYLOAD = b"GET / HTTP/1.1\r\nHost: server.example\r\n\r\n"
_APPLICATION_RESPONSE = b"HTTP/1.1 200 OK\r\n\r\n"


@dataclass
class HandshakeResult:
    """Everything one measured handshake produced."""

    profile: dict[str, str]
    messages: list[MessageRecord]
    metrics: Metrics
    client: HybridClient
    server: HybridServer
    certificate: IssuedCertificate | None
    application_payload_ok: bool
    exporters_match: bool
    kem: KemBackend = field(default=None, repr=False)  # type: ignore[assignment]
    classical_signer: ClassicalSigner = field(default=None, repr=False)  # type: ignore[assignment]
    pq_signer: PqSigner = field(default=None, repr=False)  # type: ignore[assignment]

    # -- byte accounting ----------------------------------------------------

    def bytes_for(self, name: str) -> int:
        """Total wire bytes contributed by every message called ``name``."""
        return sum(record.total_bytes for record in self.messages if record.name == name)

    @property
    def handshake_bytes(self) -> int:
        """Actual bare harness handshake bytes, including inner types and AEAD tags."""
        return sum(record.total_bytes for record in self.messages)

    @property
    def plaintext_bytes(self) -> int:
        """Handshake framing bytes only, excluding record protection."""
        return sum(record.message_bytes for record in self.messages)

    @property
    def server_bytes(self) -> int:
        """Handshake bytes sent by the server."""
        return sum(record.total_bytes for record in self.messages if record.sender == "server")

    @property
    def client_bytes(self) -> int:
        """Handshake bytes sent by the client."""
        return sum(record.total_bytes for record in self.messages if record.sender == "client")

    def pq_deltas(self) -> dict[str, int]:
        """Analytic decomposition of the post-quantum cost, from this run's own fields.

        Each entry is the encoded size of an added field plus its framing. This is an
        *estimate*: Falcon signatures vary in length, so a per-field formula cannot be
        exact to the byte. Prefer :func:`measured_pq_deltas`, which runs the same
        profile both ways and subtracts. All zero when this run is the baseline.
        """
        if self.classical_only:
            return {}
        if self.profile.get("x509") == "true":
            # In the X.509 profile the post-quantum key rides inside a DER extension, so
            # a per-field formula would miss the OID and the OCTET STRING wrapper.
            # measured_pq_deltas() is the number to use there.
            return {}
        payload = self.server.certificate_verify_payload
        pq_public = self.server.credentials.pq_public or b""
        return {
            # 4-byte extension header + KEM scheme id + the vec16 around the key.
            "client_hello.pq_key_share": 4 + 2 + 2 + len(self.client.kem_public or b""),
            # The hybrid ClientHello also advertises one more signature algorithm.
            "client_hello.pq_signature_algorithm": 2,
            "server_hello.pq_ciphertext": 4 + 2 + len(self.server.kem_ciphertext or b""),
            "certificate.pq_public_key": 2 + 2 + len(pq_public),
            "certificate_verify.pq_signature": 2
            + 2
            + len(payload.pq_signature if payload and payload.pq_signature else b""),
        }

    @property
    def classical_only(self) -> bool:
        """Whether this run is the classical-only baseline."""
        return self.profile.get("pq_enabled") == "false"

    def classical_only_estimate(self) -> int:
        """Handshake bytes this profile would have sent with the PQ fields removed."""
        return self.handshake_bytes - sum(self.pq_deltas().values())

    def flight_table(self) -> list[tuple[str, str, int, int]]:
        """``(message, sender, plaintext bytes, protection bytes)`` per message."""
        return [
            (record.name, record.sender, record.message_bytes, record.total_bytes - record.message_bytes)
            for record in self.messages
        ]

    def report(self) -> str:
        """Render a compact human-readable summary of the handshake."""
        lines = [
            "profile: " + ", ".join(f"{key}={value}" for key, value in self.profile.items()),
            f"handshake bytes (with record protection): {self.handshake_bytes}",
            f"handshake framing bytes (plaintext):       {self.plaintext_bytes}",
            f"  client -> server: {self.client_bytes}",
            f"  server -> client: {self.server_bytes}",
            "",
            f"{'message':<22}{'sender':<9}{'plain':>8}{'protect':>9}{'total':>8}",
        ]
        lines.extend(
            f"{name:<22}{sender:<9}{plain:>8}{protection:>9}{plain + protection:>8}"
            for name, sender, plain, protection in self.flight_table()
        )
        lines.extend(["", "post-quantum additions (bytes each):"])
        lines.extend(f"  {key:<34}{value:>7}" for key, value in self.pq_deltas().items())
        lines.extend(
            [
                f"  {'sum':<34}{sum(self.pq_deltas().values()):>7}",
                f"  classical-only estimate            {self.classical_only_estimate():>7}",
                "",
                f"application data round trip: {'ok' if self.application_payload_ok else 'FAILED'}",
                f"exporter secrets agree:      {'yes' if self.exporters_match else 'NO'}",
            ]
        )
        remaining = self.server.credentials.pq_signatures_remaining()
        if remaining is not None:
            lines.append(f"one-time signatures left:    {remaining}")
        return "\n".join(lines)


class HybridConnection:
    """Runs the client and server halves of one handshake against each other."""

    @staticmethod
    def run(
        config: HybridTLSConfig,
        *,
        server_identity: bytes = b"server.example",
        ca_signer: ClassicalSigner | None = None,
        metrics: Metrics | None = None,
        application_payload: bytes = DEFAULT_APPLICATION_PAYLOAD,
        authority: CertificateAuthority | None = None,
        credentials: ServerCredentials | None = None,
        certificate: IssuedCertificate | None = None,
        timings: dict[str, float] | None = None,
    ) -> HandshakeResult:
        """Execute a full handshake and the first application-data exchange.

        ``authority``/``credentials``/``certificate`` may be supplied by the caller: that is the
        driver's "hot" mode, used by ``bench/measure_xmss_lifecycle.py`` to separate the cost of
        generating an authentication key from the cost of the handshake itself. What is reused is
        the *authentication credential* only -- each call still builds its own ``HybridServer``,
        transcript, ECDHE and KEM ephemeral keys, traffic secrets and record sequences, so a hot
        handshake is a real handshake.

        ``timings``, when given, receives wall-clock marks (in seconds since an arbitrary epoch)
        for the phases the lifecycle benchmark reports: ``credentials_ready``,
        ``client_hello_ready``, ``server_hello_ready``, ``server_flight_ready``,
        ``client_finished_ready``, ``complete``.
        """
        metrics = metrics or Metrics()
        authority = authority or CertificateAuthority(ca_signer or config.classical())
        if credentials is None:
            credentials = ServerCredentials(config, identity=server_identity)
        if certificate is None:
            certificate = credentials.bind_to(authority)
        trusted_root = (
            x509.load_der_x509_certificate(credentials.chain.root_der)
            if config.x509 and credentials.chain is not None
            else None
        )

        def mark(name: str) -> None:
            if timings is not None:
                timings[name] = time.perf_counter()

        mark("credentials_ready")

        client = HybridClient(
            config,
            authority,
            metrics=metrics,
            trusted_root=trusted_root,
            trusted_name=server_identity.decode(),
        )
        server = HybridServer(config, credentials, certificate, metrics=metrics)
        messages: list[MessageRecord] = []

        with metrics.time("handshake_total"):
            # Flight 1: the client's two key shares, the server's answer plus ciphertext.
            client_hello = client.create_client_hello()
            mark("client_hello_ready")
            messages.append(MessageRecord("ClientHello", "client", len(client_hello)))
            server_hello = server.receive_client_hello(client_hello)
            mark("server_hello_ready")
            messages.append(MessageRecord("ServerHello", "server", len(server_hello)))
            client.receive_server_hello(server_hello)

            # Flight 2: authenticated server flight, then the client's Finished.
            flight = server.send_authenticated_flight()
            mark("server_flight_ready")
            for name, record, frame in flight:
                messages.append(MessageRecord(name, "server", len(frame), len(record) - len(frame)))
            client.receive_server_flight([record for _, record, _ in flight])

            client_finished = client.send_client_finished()
            mark("client_finished_ready")
            messages.append(
                MessageRecord("Finished", "client", len(client.sent_client_finished or b""),
                              len(client_finished) - len(client.sent_client_finished or b""))
            )
            server.receive_client_finished(client_finished)
        mark("complete")

        application_ok = _exchange_application_data(client, server, application_payload, metrics)
        exporters_match = False
        with metrics.time("exporter"):
            exporters_match = client.exporter_secret(
                "hybrid-tls13 test", b"context"
            ) == server.exporter_secret("hybrid-tls13 test", b"context")

        return HandshakeResult(
            profile=config.describe(),
            messages=messages,
            metrics=metrics,
            client=client,
            server=server,
            certificate=certificate,
            application_payload_ok=application_ok,
            exporters_match=exporters_match,
            kem=config.kem_backend() if config.pq_enabled else None,
            classical_signer=config.classical(),
            pq_signer=config.pq() if config.pq_enabled else None,
        )


def _exchange_application_data(
    client: HybridClient,
    server: HybridServer,
    payload: bytes,
    metrics: Metrics,
) -> bool:
    """Send one request and one response over the derived application keys."""
    with metrics.time("application_roundtrip"):
        outbound = client.application_client_records
        inbound = server.application_client_records
        if outbound is None or inbound is None:
            return False
        sealed = outbound.seal(CONTENT_TYPE_APPLICATION_DATA, payload)
        content_type, opened = inbound.open(sealed, CONTENT_TYPE_APPLICATION_DATA)
        if content_type != CONTENT_TYPE_APPLICATION_DATA or opened != payload:
            return False

        reply = server.application_server_records
        consume = client.application_server_records
        if reply is None or consume is None:
            return False
        sealed_reply = reply.seal(CONTENT_TYPE_APPLICATION_DATA, _APPLICATION_RESPONSE)
        content_type, opened_reply = consume.open(sealed_reply, CONTENT_TYPE_APPLICATION_DATA)
        return content_type == CONTENT_TYPE_APPLICATION_DATA and opened_reply == _APPLICATION_RESPONSE


def measured_pq_deltas(
    config: HybridTLSConfig,
    **run_options: object,
) -> dict[str, object]:
    """Run ``config`` with and without the post-quantum material, and subtract.

    This is the comparison a reader will ask for: the baseline is a handshake that
    actually ran through the same code, not a formula. Returns the per-message measured
    deltas, the totals, and both results so a caller can report either.
    """
    if not config.pq_enabled:
        raise ValueError("measured_pq_deltas needs a profile with pq_enabled=True")
    hybrid = HybridConnection.run(config, **run_options)  # type: ignore[arg-type]
    baseline = HybridConnection.run(replace(config, pq_enabled=False), **run_options)  # type: ignore[arg-type]

    per_message: dict[str, int] = {}
    for name, _sender, plain, protection in hybrid.flight_table():
        per_message[name] = per_message.get(name, 0) + plain + protection
    baseline_per_message: dict[str, int] = {}
    for name, _sender, plain, protection in baseline.flight_table():
        baseline_per_message[name] = baseline_per_message.get(name, 0) + plain + protection

    deltas = {
        name: per_message.get(name, 0) - baseline_per_message.get(name, 0)
        for name in sorted(set(per_message) | set(baseline_per_message))
    }
    return {
        "hybrid": hybrid,
        "baseline": baseline,
        "per_message": deltas,
        "client_hello": deltas.get("ClientHello", 0),
        "server_hello": deltas.get("ServerHello", 0),
        "certificate": deltas.get("Certificate", 0),
        "certificate_verify": deltas.get("CertificateVerify", 0),
        "total": hybrid.handshake_bytes - baseline.handshake_bytes,
        "baseline_bytes": baseline.handshake_bytes,
        "hybrid_bytes": hybrid.handshake_bytes,
        "analytic_estimate": sum(hybrid.pq_deltas().values()),
    }
