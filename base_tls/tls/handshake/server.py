"""Server side of the hybrid handshake.

The server contributes both branches: it generates the classical ephemeral share
and encapsulates to the client's KEM public key, then authenticates by signing the
same CertificateVerify input twice. Nothing in the message order differs from
TLS 1.3, so the post-quantum material costs bytes and computation rather than an
extra round trip.
"""

from __future__ import annotations

import hmac
import os
from collections.abc import Callable

from ..classical.ecdh import EcdheKeyPair
from ..config import HybridTLSConfig
from ..credentials import IssuedCertificate, ServerCredentials
from ..errors import HandshakeError, named_errors
from ..key_schedule.hkdf import encode_hybrid_secret
from ..metrics import Metrics
from ..wire import split_handshake_message
from .certificate_verify import HybridCertificateVerify, build_certificate_verify_input
from .messages import (
    CLIENT_HELLO,
    FINISHED,
    GROUPS,
    LEGACY_VERSION,
    TLS13_VERSION,
    Certificate,
    CertificateVerify,
    ClientHello,
    EncryptedExtensions,
    Finished,
    KeyShareEntry,
    ServerHello,
    X509Chain,
)
from .state import HandshakeState

__all__ = ["HybridServer"]


class HybridServer(HandshakeState):
    """Drives the server half of one handshake."""

    def __init__(
        self,
        config: HybridTLSConfig,
        credentials: ServerCredentials,
        certificate: IssuedCertificate,
        metrics: Metrics | None = None,
    ) -> None:
        super().__init__(config, role="server", metrics=metrics)
        self.credentials = credentials
        self.certificate = certificate
        self.ephemeral: EcdheKeyPair | None = None
        self.client_kem_public: bytes | None = None
        self.kem_ciphertext: bytes | None = None
        self.certificate_verify_payload: HybridCertificateVerify | None = None
        self.received_client_finished: bytes | None = None

    # -- flight 1: ClientHello -> ServerHello --------------------------------

    @named_errors("client_hello")
    def receive_client_hello(self, frame: bytes) -> bytes:
        """Consume ClientHello, complete both key-exchange branches, and answer with ServerHello."""
        message_type, body = split_handshake_message(frame)
        if message_type != CLIENT_HELLO:
            raise HandshakeError("client_hello", f"expected ClientHello, received type {message_type}")
        client_hello = ClientHello.decode(body)

        # What the client offered is checked before anything is derived from it. An
        # independent audit showed that none of these were checked: a client could omit
        # `supported_versions` (or offer only TLS 1.2), offer `signature_algorithms` that
        # exclude the schemes this server will sign with, put a key_share group outside its
        # own `supported_groups`, announce `[zlib]` compression, or omit the cipher suite the
        # server was about to select — and the handshake completed anyway.
        if TLS13_VERSION not in client_hello.supported_versions:
            listed = [f"{value:#06x}" for value in client_hello.supported_versions]
            found = ", ".join(listed) if listed else "no extension"
            raise HandshakeError(
                "client_hello",
                f"the client did not offer TLS 1.3 (supported_versions: {found})",
            )
        if client_hello.legacy_compression_methods != (0x00,):
            raise HandshakeError(
                "client_hello",
                f"legacy_compression_methods {client_hello.legacy_compression_methods} != (0,); "
                "RFC 8446 section 4.1.2 requires the null compression method alone",
            )

        expected_group = GROUPS[self.config.group]
        if client_hello.key_share.group != expected_group:
            raise HandshakeError(
                "client_hello",
                f"client offered group {client_hello.key_share.group:#06x}, this profile requires "
                f"{expected_group:#06x} ({self.config.group})",
            )
        if client_hello.key_share.group not in client_hello.supported_groups:
            raise HandshakeError(
                "client_hello",
                f"key_share names group {client_hello.key_share.group:#06x}, which is not in the "
                f"supported_groups this ClientHello offered",
            )
        if self.config.cipher_suite_id not in client_hello.cipher_suites:
            offered = ", ".join(f"{suite:#06x}" for suite in client_hello.cipher_suites)
            raise HandshakeError(
                "client_hello",
                f"the client did not offer cipher suite {self.config.cipher_suite_id:#06x} "
                f"(offered: {offered})",
            )

        required_schemes = {self.config.classical().scheme_id}
        if self.config.pq_enabled:
            required_schemes.add(self.config.pq().scheme_id)
        missing = required_schemes - set(client_hello.signature_algorithms)
        if missing:
            raise HandshakeError(
                "client_hello",
                "the client did not offer the signature scheme(s) this server must use: "
                + ", ".join(f"{scheme:#06x}" for scheme in sorted(missing)),
            )

        if self.config.pq_enabled:
            if client_hello.pq_key_share is None or client_hello.kem_scheme is None:
                raise HandshakeError(
                    "client_hello",
                    "hybrid profile requires the pq_key_share extension, which this ClientHello omits",
                )
            kem = self.config.kem_backend()
            if client_hello.kem_scheme != kem.scheme_id:
                raise HandshakeError(
                    "client_hello",
                    f"client offered KEM scheme {client_hello.kem_scheme:#06x}, this profile runs "
                    f"{kem.name} ({kem.scheme_id:#06x})",
                )
            if len(client_hello.pq_key_share) != kem.public_key_bytes:
                raise HandshakeError(
                    "client_hello",
                    f"KEM public key is {len(client_hello.pq_key_share)} bytes, "
                    f"{kem.name} requires {kem.public_key_bytes}",
                )
        elif client_hello.pq_key_share is not None:
            raise HandshakeError(
                "client_hello",
                "classical-only profile received a pq_key_share it does not implement",
            )

        # Only now does the message enter the transcript: a rejected ClientHello must
        # leave the server's state exactly as it found it.
        self.transcript.add(frame)

        if self.config.pq_enabled:
            self.client_kem_public = client_hello.pq_key_share

        with self.metrics.time("server_ecdhe_keygen"):
            self.ephemeral = EcdheKeyPair.generate(self.config.group)
        with self.metrics.time("server_ecdhe_exchange"):
            self.z_ecdh = self.ephemeral.exchange(
            client_hello.key_share.key_exchange, step="client_hello"
        )
        if self.config.pq_enabled:
            kem = self.config.kem_backend()
            with self.metrics.time("server_kem_encaps"):
                self.kem_ciphertext, self.ss_pq = kem.encapsulate(client_hello.pq_key_share)  # type: ignore[arg-type]
            self.metrics.count("server_kem_encaps_calls")
            self.hybrid_secret = encode_hybrid_secret(self.z_ecdh, self.ss_pq)
        else:
            # Plain TLS 1.3: the ECDHE secret is the key-schedule input, unencoded.
            self.hybrid_secret = self.z_ecdh
        server_hello = ServerHello(
            random=os.urandom(32),
            cipher_suite=self.config.cipher_suite_id,
            key_share=KeyShareEntry(expected_group, self.ephemeral.public_bytes()),
            pq_ciphertext=self.kem_ciphertext,
            legacy_session_id=client_hello.legacy_session_id,
        )
        frame_out = server_hello.to_message()
        self.transcript.add(frame_out)
        return frame_out

    # -- flight 2: EncryptedExtensions, Certificate, CertificateVerify, Finished

    @named_errors("server_flight")
    def send_authenticated_flight(
        self,
        frame_filter: "Callable[[str, bytes], bytes] | None" = None,
    ) -> list[tuple[str, bytes, bytes]]:
        """Build and protect the server's authenticated flight.

        Returns ``(name, record_bytes, plaintext_fragment)`` triples. Messages over
        16384 bytes produce multiple records; each transcript message is hashed
        once before fragmentation. The Finished message is built last
        because its MAC covers a transcript that now includes CertificateVerify.

        ``frame_filter`` rewrites each plaintext frame just before it is hashed into
        the transcript and sealed. It exists so tests can corrupt one field and
        observe which check rejects it, without leaving test logic in this class.
        """
        if self.hybrid_secret is None:
            raise HandshakeError("server_flight", "ServerHello has not been produced yet")
        self.setup_handshake_keys(self.hybrid_secret)

        flight: list[tuple[str, bytes, bytes]] = []

        def emit(name: str, frame: bytes) -> None:
            """Filter, hash, and seal one frame in that order."""
            if frame_filter is not None:
                frame = frame_filter(name, frame)
            self.transcript.add(frame)
            # Transcript hashes complete messages once; record sequence advances
            # once for each protected fragment, independently of message boundaries.
            from ..record.aead import MAX_CONTENT_BYTES
            for start in range(0, len(frame), MAX_CONTENT_BYTES):
                fragment = frame[start:start + MAX_CONTENT_BYTES]
                flight.append((name, self.seal_handshake(fragment), fragment))

        # EncryptedExtensions and Certificate must reach the transcript before the
        # CertificateVerify input is built, because that input covers them.
        emit("EncryptedExtensions", EncryptedExtensions().to_message())
        if self.config.x509:
            if self.credentials.chain is None:
                raise HandshakeError("server_flight", "the X.509 profile has no chain to send")
            certificate_frame = X509Chain(chain=self.credentials.chain.chain_der).to_message()
        else:
            certificate_frame = Certificate(
                body=self.certificate.body, ca_signature=self.certificate.signature
            ).to_message()
        emit("Certificate", certificate_frame)
        emit("CertificateVerify", self._build_certificate_verify())
        emit("Finished", Finished(verify_data=self.finished_verify_data("server")).to_message())
        # The application traffic keys and the exporter master secret cover the transcript
        # through this Finished — RFC 8446 section 7.1 — so they are derived here, before
        # the client's Finished arrives. An independent audit found the earlier version
        # deriving them after that Finished instead.
        self.setup_application_keys()
        return flight

    def _build_certificate_verify(self) -> bytes:
        """Sign the TLS 1.3 CertificateVerify input with both signature schemes.

        The classical-only profile signs once; the input is identical, so the baseline
        exercises the same context string and the same transcript position.
        """
        message = build_certificate_verify_input(self.transcript.hash(), role="server")
        classical = self.config.classical()
        with self.metrics.time("server_sign_classical"):
            classic_signature = classical.sign(self.credentials.classical_secret, message)
        self.metrics.count("server_sign_classical_calls")
        if self.config.pq_enabled:
            pq = self.config.pq()
            with self.metrics.time("server_sign_pq"):
                try:
                    pq_signature = pq.sign(self.credentials.pq_secret, message)
                except (ValueError, TypeError) as error:
                    # A stateful PQ signer refuses when its key is spent (XMSS spends one
                    # leaf per handshake). Named here rather than left to the decorator's
                    # backstop, so the caller sees *why*: the fifth review showed the raw
                    # `ValueError` escaping this method (their V6-08, probe N1).
                    raise HandshakeError(
                        "server_flight",
                        f"the post-quantum signer {type(pq).__name__} refused to sign: {error}",
                    ) from error
            self.metrics.count("server_sign_pq_calls")
            pq_scheme: int | None = pq.scheme_id
        else:
            pq_signature = None
            pq_scheme = None
        self.certificate_verify_payload = HybridCertificateVerify(
            classic_scheme=classical.scheme_id,
            classic_signature=classic_signature,
            pq_scheme=pq_scheme,
            pq_signature=pq_signature,
        )
        body = self.certificate_verify_payload.encode()
        return CertificateVerify(payload=body).to_message()

    # -- flight 3: client Finished and application keys ----------------------

    @named_errors("client_finished")
    def receive_client_finished(self, record: bytes) -> bytes:
        """Verify the client's Finished and finish the handshake."""
        inner = self.open_handshake(record)
        message_type, body = split_handshake_message(inner)
        if message_type != FINISHED:
            raise HandshakeError("client_finished", f"expected Finished, received type {message_type}")
        expected = self.finished_verify_data("client")
        received = Finished.decode(body).verify_data
        # `hmac.compare_digest`, for the same reason as the client side: this is an
        # authentication tag, and an early exit that depends on its content is what the
        # standard's advice about digest comparison is about (red-team finding W2).
        if len(received) != len(expected):
            raise HandshakeError(
                "client_finished",
                f"client verify_data is {len(received)} bytes, expected {len(expected)}",
            )
        if not hmac.compare_digest(received, expected):
            raise HandshakeError("client_finished", "client verify_data does not match")
        self.received_client_finished = received
        self.transcript.add(inner)
        # `res master` is the one secret RFC 8446 section 7.1 derives over the transcript
        # *including* the client Finished; the application keys were derived earlier.
        self.setup_resumption_secret()
        return inner
