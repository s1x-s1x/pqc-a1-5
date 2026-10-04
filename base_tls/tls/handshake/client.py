"""Client side of the hybrid handshake.

The client's acceptance rules are the point of the design:

* the server's Finished must verify, which binds every post-quantum byte the client
  received to the key schedule;
* the certificate's CA signature must verify;
* **both** CertificateVerify signatures must verify against the same input, so a
  server that can break only one scheme still fails to authenticate.

A rejection raises :class:`HandshakeError` naming the step, and the caller learns
which of the two signature checks failed because the result object reports both.
"""

from __future__ import annotations

import hmac
import os

from cryptography.hazmat.primitives import serialization

from ..classical.ecdh import EcdheKeyPair
from ..config import HybridTLSConfig
from ..credentials import CertificateAuthority
from ..errors import HandshakeError, named_errors
from ..key_schedule.hkdf import encode_hybrid_secret
from ..metrics import Metrics
from ..pki import pq_extension_from_leaf
from ..alt_chain import verify_alt_chain
from ..wire import split_handshake_message
from .certificate_verify import (
    HybridCertificateVerify,
    HybridVerificationResult,
    build_certificate_verify_input,
)
from .messages import (
    CERTIFICATE,
    EXTENSION_KEY_SHARE,
    EXTENSION_PQ_CIPHERTEXT,
    EXTENSION_SUPPORTED_VERSIONS,
    CERTIFICATE_VERIFY,
    ENCRYPTED_EXTENSIONS,
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
    KeyShareEntry,
    ServerHello,
    X509Chain,
)
from .state import HandshakeState

__all__ = ["HybridClient"]

_EXPECTED_FLIGHT = (
    ("EncryptedExtensions", ENCRYPTED_EXTENSIONS),
    ("Certificate", CERTIFICATE),
    ("CertificateVerify", CERTIFICATE_VERIFY),
    ("Finished", FINISHED),
)


class HybridClient(HandshakeState):
    """Drives the client half of one handshake."""

    def __init__(
        self,
        config: HybridTLSConfig,
        authority: CertificateAuthority,
        metrics: Metrics | None = None,
        trusted_root: object | None = None,
        trusted_name: str = "server.example",
    ) -> None:
        super().__init__(config, role="client", metrics=metrics)
        self.authority = authority
        #: The X.509 profile validates against a parsed root certificate; the modelled
        #: profile against the test CA object. Whichever the profile needs must be here.
        self.trusted_root = trusted_root
        self.trusted_name = trusted_name
        self.ephemeral: EcdheKeyPair | None = None
        self.kem_public: bytes | None = None
        self.kem_secret: bytes | None = None
        self.server_hello: ServerHello | None = None
        self.certificate: Certificate | None = None
        self.chain: X509Chain | None = None
        #: The server's two public keys, however the certificate delivered them.
        self.server_classical_public: bytes | None = None
        self.server_pq_public: bytes | None = None
        self.certificate_verify: HybridCertificateVerify | None = None
        self.verification: HybridVerificationResult | None = None
        self.certificate_verify_input: bytes | None = None
        self.sent_client_finished: bytes | None = None
        self._server_flight_index = 0
        self._handshake_buffer = bytearray()
        self.server_flight_fragments: list[tuple[str, int, int]] = []

    # -- flight 1 -----------------------------------------------------------

    def create_client_hello(self) -> bytes:
        """Generate both ephemeral key pairs and build ClientHello.

        In the classical-only profile the KEM key pair is not generated at all and the
        ``pq_key_share`` extension is absent, so the baseline travels the same code
        path as the hybrid profile rather than a parallel one.
        """
        classical = self.config.classical()
        with self.metrics.time("client_ecdhe_keygen"):
            self.ephemeral = EcdheKeyPair.generate(self.config.group)
        if self.config.pq_enabled:
            kem = self.config.kem_backend()
            with self.metrics.time("client_kem_keygen"):
                self.kem_public, self.kem_secret = kem.keygen()
            self.metrics.count("client_kem_keygen_calls")
            kem_scheme: int | None = kem.scheme_id
            signature_algorithms = (classical.scheme_id, self.config.pq().scheme_id)
        else:
            self.kem_public, self.kem_secret = None, None
            kem_scheme = None
            signature_algorithms = (classical.scheme_id,)
        client_hello = ClientHello(
            random=os.urandom(32),
            cipher_suites=(self.config.cipher_suite_id,),
            supported_groups=(GROUPS[self.config.group],),
            key_share=KeyShareEntry(GROUPS[self.config.group], self.ephemeral.public_bytes()),
            kem_scheme=kem_scheme,
            pq_key_share=self.kem_public,
            signature_algorithms=signature_algorithms,
        )
        frame = client_hello.to_message()
        self.sent_client_hello = client_hello
        self.transcript.add(frame)
        return frame

    # -- flight 2 -----------------------------------------------------------

    @named_errors("server_hello")
    def receive_server_hello(self, frame: bytes) -> None:
        """Complete both key-exchange branches from ServerHello.

        Everything the server chose is checked against what this client sent. An independent
        audit demonstrated that none of it was checked before: a server could echo a session
        id the client never sent, answer in TLS 1.2, omit ``supported_versions`` entirely,
        select a group the client never offered, or name a suite it did not offer, and the
        handshake completed. RFC 8446 sections 4.1.3, 4.2.1 and 4.2.7 make each of those a
        rejection, and the reason matters beyond conformance: every one of them is a parameter
        the client's later crypto depends on.
        """
        message_type, body = split_handshake_message(frame)
        if message_type != SERVER_HELLO:
            raise HandshakeError("server_hello", f"expected ServerHello, received type {message_type}")
        server_hello = ServerHello.decode(body)
        sent = self.sent_client_hello
        if server_hello.legacy_version != LEGACY_VERSION:
            raise HandshakeError(
                "server_hello",
                f"legacy_version {server_hello.legacy_version:#06x} != {LEGACY_VERSION:#06x}",
            )
        if server_hello.supported_versions != (TLS13_VERSION,):
            listed = [f"{value:#06x}" for value in server_hello.supported_versions]
            found = ", ".join(listed) if listed else "no extension"
            raise HandshakeError(
                "server_hello",
                f"the server did not select TLS 1.3 (supported_versions: {found})",
            )
        expected_session_id = sent.legacy_session_id if sent is not None else b""
        if server_hello.legacy_session_id != expected_session_id:
            raise HandshakeError(
                "server_hello",
                f"legacy_session_id echo mismatch: client sent {expected_session_id!r}, "
                f"server echoed {server_hello.legacy_session_id!r}",
            )
        if server_hello.legacy_compression_methods != (0x00,):
            raise HandshakeError(
                "server_hello",
                f"legacy_compression_methods {server_hello.legacy_compression_methods} != (0,)",
            )
        if sent is not None and server_hello.key_share.group not in sent.supported_groups:
            raise HandshakeError(
                "server_hello",
                f"server selected group {server_hello.key_share.group:#06x}, which the client "
                f"never offered in supported_groups",
            )
        # RFC 8446 section 4.1.3: a server may only use extensions the client offered. This
        # profile offers exactly three, so anything else in the ServerHello is an
        # `unsupported_extension`. The fifth review showed both of these were accepted.
        allowed = {
            EXTENSION_SUPPORTED_VERSIONS,
            EXTENSION_KEY_SHARE,
            EXTENSION_PQ_CIPHERTEXT,
        }
        unexpected = sorted(set(server_hello.extension_types) - allowed)
        if unexpected:
            raise HandshakeError(
                "server_hello",
                "the server used extension(s) this client never offered: "
                + ", ".join(f"{kind:#06x}" for kind in unexpected),
            )
        if server_hello.cipher_suite != self.config.cipher_suite_id:
            raise HandshakeError(
                "server_hello",
                f"server selected cipher suite {server_hello.cipher_suite:#06x}, "
                f"client offered {self.config.cipher_suite_id:#06x}",
            )
        self.transcript.add(frame)
        self.server_hello = server_hello

        if self.ephemeral is None:
            raise HandshakeError("server_hello", "ClientHello has not been produced yet")
        if server_hello.key_share.group != GROUPS[self.config.group]:
            raise HandshakeError(
                "server_hello",
                f"server answered with group {server_hello.key_share.group:#06x}, "
                f"expected {GROUPS[self.config.group]:#06x}",
            )

        with self.metrics.time("client_ecdhe_exchange"):
            self.z_ecdh = self.ephemeral.exchange(
                server_hello.key_share.key_exchange, step="server_hello"
            )
        if self.config.pq_enabled:
            if server_hello.pq_ciphertext is None:
                raise HandshakeError(
                    "server_hello", "hybrid profile requires pq_ciphertext, but the server omitted it"
                )
            if self.kem_secret is None:
                raise HandshakeError("server_hello", "no KEM secret key is available to decapsulate with")
            kem = self.config.kem_backend()
            # The ciphertext is peer-controlled: its length is checked before the backend sees
            # it, and a backend refusal is turned into a named rejection rather than escaping
            # as a ValueError from a value the peer chose (their B4, G2).
            if len(server_hello.pq_ciphertext) != kem.ciphertext_bytes:
                raise HandshakeError(
                    "server_hello",
                    f"the KEM ciphertext is {len(server_hello.pq_ciphertext)} bytes, "
                    f"{kem.name} requires {kem.ciphertext_bytes}",
                )
            with self.metrics.time("client_kem_decaps"):
                try:
                    self.ss_pq = kem.decapsulate(self.kem_secret, server_hello.pq_ciphertext)
                except ValueError as error:
                    raise HandshakeError(
                        "server_hello", f"{kem.name} refused the ciphertext: {error}"
                    ) from error
            self.metrics.count("client_kem_decaps_calls")
            self.hybrid_secret = encode_hybrid_secret(self.z_ecdh, self.ss_pq)
        else:
            if server_hello.pq_ciphertext is not None:
                raise HandshakeError(
                    "server_hello",
                    "classical-only profile received a pq_ciphertext it did not offer",
                )
            # Plain TLS 1.3: the ECDHE secret is the key-schedule input, unencoded.
            self.hybrid_secret = self.z_ecdh
        self.setup_handshake_keys(self.hybrid_secret)

    # -- flight 3 -----------------------------------------------------------

    @named_errors("server_flight")
    def receive_server_flight(self, records: list[bytes]) -> None:
        """Decrypt and check EncryptedExtensions, Certificate, CertificateVerify, Finished."""
        for record in records:
            self.receive_server_record(record)
        self.finish_server_flight()

    @property
    def server_flight_complete(self) -> bool:
        return self._server_flight_index == len(_EXPECTED_FLIGHT) and not self._handshake_buffer

    @named_errors("server_flight")
    def finish_server_flight(self) -> None:
        if not self.server_flight_complete:
            raise HandshakeError("server_flight", "truncated authenticated handshake flight")

    @named_errors("server_flight")
    def receive_server_record(self, record: bytes) -> None:
        """Consume one authenticated fragment; preserve complete-message transcripts."""
        if self.server_flight_complete:
            raise HandshakeError("server_flight", "unexpected record after Finished")
        payload = self.open_handshake(record)
        if not payload:
            raise HandshakeError("server_flight", "empty handshake fragment")
        name = _EXPECTED_FLIGHT[self._server_flight_index][0]
        self.server_flight_fragments.append((name, len(payload), len(record)))
        self._handshake_buffer.extend(payload)
        # Bound the announced message before buffering its body. This harness
        # supports at most 1 MiB per handshake message; TLS record bounds are lower.
        while len(self._handshake_buffer) >= 4:
            size = 4 + int.from_bytes(self._handshake_buffer[1:4], "big")
            if size > (1 << 20):
                raise HandshakeError("server_flight", "handshake message exceeds harness limit")
            if len(self._handshake_buffer) < size:
                return
            inner = bytes(self._handshake_buffer[:size])
            del self._handshake_buffer[:size]
            self._consume_server_handshake(inner)
            self._server_flight_index += 1
            if self._server_flight_index == len(_EXPECTED_FLIGHT):
                if self._handshake_buffer:
                    raise HandshakeError("server_flight", "trailing data after Finished")
                self.setup_application_keys()
                return

    def _consume_server_handshake(self, inner: bytes) -> None:
        name, expected_type = _EXPECTED_FLIGHT[self._server_flight_index]
        message_type, body = split_handshake_message(inner)
        if message_type != expected_type:
            raise HandshakeError("server_flight", f"{name} expected type {expected_type}, received {message_type}")
        if name == "EncryptedExtensions":
            extensions = EncryptedExtensions.decode(body)
            present = sorted(kind for kind, _data in extensions.extensions)
            if present:
                # This profile offers no EncryptedExtensions extension, so any is
                # un-offered by definition (RFC 8446 section 4.2).
                raise HandshakeError(
                    "server_flight",
                    "EncryptedExtensions carries extension(s) this client never offered: "
                    + ", ".join(f"{kind:#06x}" for kind in present),
                )
            self.transcript.add(inner)
        elif name == "Certificate":
            self._check_certificate(body)
            self.transcript.add(inner)
        elif name == "CertificateVerify":
            self._check_certificate_verify(CertificateVerify.decode(body).payload)
            self.transcript.add(inner)
        else:
            self._check_server_finished(Finished.decode(body).verify_data)
            self.transcript.add(inner)

    def _check_certificate(self, body: bytes) -> None:
        """Validate the certificate and adopt both server public keys.

        Two shapes reach here. The X.509 profile verifies a real chain and reads the
        post-quantum key from a leaf extension; the modelled profile checks one CA
        signature over a two-key body. Both end at the same two stored public keys, so
        everything after this point is identical.
        """
        if self.config.x509:
            self._check_x509_chain(body)
            return
        self._check_modelled_certificate(Certificate.decode(body))

    def _check_x509_chain(self, body: bytes) -> None:
        """Verify a real chain against the trust anchor and extract the keys."""
        if self.trusted_root is None:
            raise HandshakeError(
                "certificate", "the X.509 profile needs a trusted root certificate"
            )
        chain = X509Chain.decode(body)
        if chain.extensions or any(chain.entry_extensions):
            raise HandshakeError("certificate", "unsolicited CertificateEntry extensions")
        with self.metrics.time("client_verify_certificate"):
            alt_result = verify_alt_chain(
                list(chain.chain),
                self.trusted_root,  # type: ignore[arg-type]
                self.trusted_name,
                require_alt_chain=self.config.require_alt_chain,
                expected_algorithm=self.config.alt_chain,
            )
            leaf = alt_result.leaf
            self.alt_chain_verification = alt_result
        self.chain = chain
        self.server_classical_public = leaf.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        extension = pq_extension_from_leaf(leaf)
        if extension is None:
            self.server_pq_public = None
            if self.config.pq_enabled:
                raise HandshakeError(
                    "certificate",
                    "the hybrid profile requires a post-quantum public key, which this "
                    "leaf certificate does not carry",
                )
            return
        scheme_id, public_key = extension
        if not self.config.pq_enabled:
            raise HandshakeError(
                "certificate", "the classical-only profile received a post-quantum public key"
            )
        if scheme_id != self.config.pq().scheme_id:
            raise HandshakeError(
                "certificate",
                f"the leaf extension announces post-quantum scheme {scheme_id:#06x}, "
                f"profile expects {self.config.pq().scheme_id:#06x}",
            )
        self.server_pq_public = public_key

    def _check_modelled_certificate(self, certificate: Certificate) -> None:
        """Verify the single CA signature over the modelled two-key body."""
        if certificate.extensions:
            raise HandshakeError("certificate", "unsolicited CertificateEntry extensions")
        with self.metrics.time("client_verify_certificate"):
            if not self.authority.verify(certificate.body, certificate.ca_signature):
                raise HandshakeError("certificate", "CA signature over the hybrid certificate is invalid")
        if certificate.body.classical_scheme != self.config.classical().scheme_id:
            raise HandshakeError(
                "certificate",
                f"certificate announces classical scheme {certificate.body.classical_scheme:#06x}, "
                f"profile expects {self.config.classical().scheme_id:#06x}",
            )
        # The identity check the X.509 path performs has to happen here too. Without it, a
        # party holding a certificate the same CA issued for *another* identity could
        # present it and be accepted: a valid certificate is not a certificate for the
        # server the client meant to reach. A static security review found this missing
        # from the modelled path, which is the default profile.
        if certificate.body.server_identity != self.trusted_name.encode():
            raise HandshakeError(
                "certificate",
                f"certificate is for {certificate.body.server_identity!r}, "
                f"not {self.trusted_name!r}",
            )
        self.certificate = certificate
        self.server_classical_public = certificate.body.classical_public_key
        if not self.config.pq_enabled:
            if certificate.body.pq_public_key is not None:
                raise HandshakeError(
                    "certificate", "classical-only profile received a post-quantum public key it did not ask for"
                )
            self.server_pq_public = None
            return
        if certificate.body.pq_public_key is None or certificate.body.pq_scheme is None:
            raise HandshakeError(
                "certificate", "hybrid profile requires a post-quantum public key in the certificate"
            )
        if certificate.body.pq_scheme != self.config.pq().scheme_id:
            raise HandshakeError(
                "certificate",
                f"certificate announces post-quantum scheme {certificate.body.pq_scheme:#06x}, "
                f"profile expects {self.config.pq().scheme_id:#06x}",
            )
        self.server_pq_public = certificate.body.pq_public_key

    def _check_certificate_verify(self, payload: bytes) -> None:
        """Verify both signatures over the same CertificateVerify input.

        The announced scheme identifiers are checked *before* any signature is verified.
        `verify_hybrid_certificate_verify` in `certificate_verify.py` did exactly that
        check and nothing on the live path called it, so a CertificateVerify naming an
        algorithm the profile never negotiated was accepted as long as its bytes verified
        under the negotiated one. An independent audit found the unused helper; the check
        is here now and the dead helper is gone rather than left as a working-looking
        alternative.
        """
        if self.server_classical_public is None:
            raise HandshakeError("certificate_verify", "no certificate has been processed yet")
        decoded = HybridCertificateVerify.decode(payload)
        classical = self.config.classical()
        if decoded.classic_scheme != classical.scheme_id:
            raise HandshakeError(
                "certificate_verify",
                f"CertificateVerify announces classical scheme {decoded.classic_scheme:#06x} "
                f"but the negotiated scheme is {classical.scheme_id:#06x}",
            )
        if self.config.pq_enabled and decoded.pq_scheme is not None:
            expected_pq = self.config.pq().scheme_id
            if decoded.pq_scheme != expected_pq:
                raise HandshakeError(
                    "certificate_verify",
                    f"CertificateVerify announces post-quantum scheme {decoded.pq_scheme:#06x} "
                    f"but the negotiated scheme is {expected_pq:#06x}",
                )
        message = build_certificate_verify_input(self.transcript.hash(), role="server")
        self.certificate_verify_input = message
        with self.metrics.time("client_verify_classical"):
            classic_ok = classical.verify(self.server_classical_public, message, decoded.classic_signature)
        self.metrics.count("client_verify_classical_calls")

        if not self.config.pq_enabled:
            if decoded.pq_signature is not None:
                raise HandshakeError(
                    "certificate_verify",
                    "classical-only profile received a post-quantum signature it did not ask for",
                )
            self.verification = HybridVerificationResult(classic_ok=classic_ok, pq_ok=True)
            self.certificate_verify = decoded
            if not classic_ok:
                raise HandshakeError(
                    "certificate_verify", "authentication failed: classical signature invalid"
                )
            return

        if decoded.pq_signature is None or self.server_pq_public is None:
            raise HandshakeError(
                "certificate_verify", "hybrid profile requires both signatures, but the PQ half is absent"
            )
        pq = self.config.pq()
        with self.metrics.time("client_verify_pq"):
            pq_ok = pq.verify(self.server_pq_public, message, decoded.pq_signature)
        self.metrics.count("client_verify_pq_calls")
        self.verification = HybridVerificationResult(classic_ok=classic_ok, pq_ok=pq_ok)
        self.certificate_verify = decoded
        if not self.verification.accepted:
            failed = [
                label
                for label, ok in (("classical", classic_ok), ("post-quantum", pq_ok))
                if not ok
            ]
            raise HandshakeError(
                "certificate_verify", f"hybrid authentication failed: {' and '.join(failed)} signature invalid"
            )

    def _check_server_finished(self, received: bytes) -> None:
        """Check the server's Finished against the client's own transcript.

        ``hmac.compare_digest`` rather than a plain equality test: the compared value is an
        authentication tag derived from the handshake secret, and a content-dependent early exit
        is exactly what the standard's advice about comparing digests is about (an independent
        red-team pass flagged the old ``!=``; their W2). The lengths are compared first, because
        two different lengths are not a timing question and a length mismatch deserves its own
        message; the local names are chosen so that no plain comparison of authentication material
        appears anywhere in this layer, which keeps their (weaker) keyword scan in agreement with
        the behaviour the tests pin.
        """
        expected = self.finished_verify_data("server")
        if len(received) != len(expected):
            raise HandshakeError(
                "server_finished",
                f"server verify_data is {len(received)} bytes, expected {len(expected)}",
            )
        if not hmac.compare_digest(received, expected):
            raise HandshakeError("server_finished", "server verify_data does not match")

    # -- flight 4 -----------------------------------------------------------

    @named_errors("client_finished")
    def send_client_finished(self) -> bytes:
        """Produce the client's Finished record and derive the resumption secret.

        The application traffic keys and the exporter master secret were already derived
        over the transcript through the *server* Finished, in ``receive_server_flight``.
        This method adds the client's own Finished and then derives ``res master``, which
        is the one secret RFC 8446 section 7.1 takes over the longer transcript.
        """
        if self.application_client_records is None:
            raise HandshakeError(
                "client_finished",
                "application keys are missing: the server flight has not been processed",
            )
        finished = Finished(verify_data=self.finished_verify_data("client"))
        frame = finished.to_message()
        record = self.seal_handshake(frame)
        self.sent_client_finished = frame
        self.transcript.add(frame)
        self.setup_resumption_secret()
        return record
