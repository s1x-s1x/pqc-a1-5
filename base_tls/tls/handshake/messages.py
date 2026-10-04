"""Handshake message encodings, shaped like RFC 8446 so byte counts stay honest.

Extensions carry the post-quantum additions:

* ``pq_key_share`` (private-use type) in ClientHello: the KEM identifier and the
  client's ephemeral KEM public key.
* ``pq_ciphertext`` (private-use type) in ServerHello: the KEM ciphertext.

Certificate carries both authentication public keys, and CertificateVerify carries
both signatures over the same input. Chain validation against a real X.509 trust
anchor is modelled, not implemented: the CA signature field holds a signature by a
test CA over the hybrid certificate body, which is enough to show what the server
must publish and what the client must verify, without pretending the post-quantum
PKI migration is solved.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..errors import DecodeError
from ..wire import Reader, handshake_message, u16, vec8, vec16, vec24

__all__ = [
    "CERTIFICATE",
    "CERTIFICATE_VERIFY",
    "CLIENT_HELLO",
    "ENCRYPTED_EXTENSIONS",
    "EXTENSION_PQ_CIPHERTEXT",
    "EXTENSION_PQ_KEY_SHARE",
    "FINISHED",
    "GROUPS",
    "SERVER_HELLO",
    "Certificate",
    "CertificateVerify",
    "ClientHello",
    "EncryptedExtensions",
    "Finished",
    "HybridCertificateBody",
    "KeyShareEntry",
    "ServerHello",
    "X509Chain",
]

CLIENT_HELLO = 1
SERVER_HELLO = 2
ENCRYPTED_EXTENSIONS = 8
CERTIFICATE = 11
CERTIFICATE_VERIFY = 15
FINISHED = 20

EXTENSION_SUPPORTED_GROUPS = 10
EXTENSION_SIGNATURE_ALGORITHMS = 13
EXTENSION_SUPPORTED_VERSIONS = 43
EXTENSION_KEY_SHARE = 51
EXTENSION_PQ_KEY_SHARE = 0xFE01
EXTENSION_PQ_CIPHERTEXT = 0xFE02

LEGACY_VERSION = 0x0303
TLS13_VERSION = 0x0304

#: Named-group code points used by the classical branch.
GROUPS: dict[str, int] = {"secp256r1": 0x0017, "x25519": 0x001D}
GROUP_NAMES: dict[int, str] = {value: key for key, value in GROUPS.items()}


def _encode_extensions(extensions: list[tuple[int, bytes]]) -> bytes:
    body = b"".join(u16(kind) + vec16(data) for kind, data in extensions)
    return vec16(body)


def _decode_extensions(reader: Reader) -> dict[int, bytes]:
    """Collect a message's extensions, refusing a duplicate.

    A ``dict`` silently keeps the last of two extensions with the same type, which is how
    an attacker gets a peer to look at one copy while a middlebox or a different parser
    looks at the other. RFC 8446 section 4.2 requires the message to be rejected, and an
    independent audit demonstrated the old behaviour by injecting a second ``key_share``.
    """
    payload = Reader(reader.read_vec16())
    found: dict[int, bytes] = {}
    while not payload.at_end():
        kind = payload.read_u16()
        if kind in found:
            raise DecodeError(f"duplicate extension {kind:#06x}: RFC 8446 section 4.2 forbids it")
        found[kind] = payload.read_vec16()
    return found


def _decode_u16_list(
    extensions: dict[int, bytes], kind: int, *, prefix: int | None = 2
) -> tuple[int, ...]:
    """Decode a ``uint16`` list extension, or an empty tuple when it is absent.

    ``prefix`` is the width of the inner length prefix, and the three call sites genuinely
    differ: ``supported_groups`` and ``signature_algorithms`` are ``vec16`` of code points,
    a ClientHello's ``supported_versions`` is ``vec8`` of them (RFC 8446 section 4.2.1), and
    a ServerHello's ``supported_versions`` is one bare ``ProtocolVersion`` with no prefix at
    all. Treating them as one shape is what a first attempt at this did, and the wire tests
    caught it.
    """
    if kind not in extensions:
        return ()
    payload = extensions[kind]
    if prefix is None:
        body = payload
    else:
        vector = Reader(payload)
        body = vector.read_vec8() if prefix == 1 else vector.read_vec16()
        vector.expect_end()
    reader = Reader(body)
    values: list[int] = []
    while not reader.at_end():
        values.append(reader.read_u16())
    return tuple(values)


@dataclass(frozen=True)
class KeyShareEntry:
    """One ``KeyShareEntry``: a named group and the encoded share."""

    group: int
    key_exchange: bytes

    def encode(self) -> bytes:
        """Encode the entry."""
        return u16(self.group) + vec16(self.key_exchange)

    @classmethod
    def decode(cls, reader: Reader) -> "KeyShareEntry":
        """Decode one entry from ``reader``."""
        return cls(reader.read_u16(), reader.read_vec16())


@dataclass(frozen=True)
class ClientHello:
    """ClientHello with the classical key share and the added KEM public key.

    The negotiation fields are **kept**, not discarded: an independent audit showed that
    both roles used to read past them, so a peer could offer one thing and the implementation
    would act on another. They are decoded into fields with the values this profile sends as
    defaults, so ``encode()`` still produces exactly the bytes it did before.
    """

    random: bytes
    cipher_suites: tuple[int, ...]
    supported_groups: tuple[int, ...]
    key_share: KeyShareEntry
    #: ``None`` in the classical-only profile, which omits the extension entirely.
    kem_scheme: int | None
    pq_key_share: bytes | None
    signature_algorithms: tuple[int, ...] = ()
    legacy_session_id: bytes = b""
    supported_versions: tuple[int, ...] = (TLS13_VERSION,)
    legacy_compression_methods: tuple[int, ...] = (0x00,)
    legacy_version: int = LEGACY_VERSION

    def encode(self) -> bytes:
        """Encode the handshake body."""
        shares = vec16(self.key_share.encode())
        extensions = [
            (
                EXTENSION_SUPPORTED_VERSIONS,
                vec8(b"".join(u16(v) for v in self.supported_versions)),
            ),
            (EXTENSION_SUPPORTED_GROUPS, vec16(b"".join(u16(g) for g in self.supported_groups))),
            (EXTENSION_SIGNATURE_ALGORITHMS, vec16(b"".join(u16(s) for s in self.signature_algorithms))),
            (EXTENSION_KEY_SHARE, shares),
        ]
        if self.kem_scheme is not None and self.pq_key_share is not None:
            extensions.append(
                (EXTENSION_PQ_KEY_SHARE, u16(self.kem_scheme) + vec16(self.pq_key_share))
            )
        return (
            u16(self.legacy_version)
            + self.random
            + vec8(self.legacy_session_id)
            + vec16(b"".join(u16(s) for s in self.cipher_suites))
            + vec8(bytes(self.legacy_compression_methods))
            + _encode_extensions(extensions)
        )

    def to_message(self) -> bytes:
        """Frame the body as a handshake message."""
        return handshake_message(CLIENT_HELLO, self.encode())

    @classmethod
    def decode(cls, body: bytes) -> "ClientHello":
        """Decode a ClientHello body."""
        reader = Reader(body)
        version = reader.read_u16()
        if version != LEGACY_VERSION:
            # A constant of the protocol, so it is checked where it is parsed. The mirror of
            # this on the server side is a *policy* check (`server_hello` step), because the
            # client must reject a version it did not ask for rather than a malformed field.
            raise DecodeError(f"ClientHello legacy_version {version:#06x} != {LEGACY_VERSION:#06x}")
        random = reader.read_bytes(32)
        session_id = reader.read_vec8()
        # RFC 8446 section 4.1.2 caps `legacy_session_id` at 32 bytes; a `vec8` can carry
        # 255. The server used to echo whatever it was handed, so an oversized field was
        # accepted and reflected — the client's echo check hid the asymmetry, which is why
        # the fifth review found the length rule missing here (their V6-07).
        if len(session_id) > 32:
            raise DecodeError(
                f"ClientHello legacy_session_id is {len(session_id)} bytes, must be at most 32"
            )
        suites_reader = Reader(reader.read_vec16())
        suites = []
        while not suites_reader.at_end():
            suites.append(suites_reader.read_u16())
        compression = reader.read_vec8()
        extensions = _decode_extensions(reader)
        reader.expect_end()

        if EXTENSION_KEY_SHARE not in extensions:
            raise DecodeError("ClientHello is missing the key_share extension")
        # A ClientHello without pq_key_share decodes rather than raising, so the caller
        # can distinguish "this peer is classical-only" from "this message is broken"
        # and answer with the right rejection.
        share_payload = Reader(extensions[EXTENSION_KEY_SHARE])
        shares = Reader(share_payload.read_vec16())
        share_payload.expect_end()
        key_share = KeyShareEntry.decode(shares)
        if not shares.at_end():
            # RFC 8446 section 4.2.8 makes `key_share` a vector: a client may send one entry per
            # group it offers. This research profile accepts exactly one and implements no
            # HelloRetryRequest, so a legal multi-share ClientHello is refused **by profile**.
            # The message says that, instead of reporting "trailing bytes" -- which described a
            # framing problem where the real cause is a capability limit (red-team finding T5).
            # See docs/CAPABILITIES.md.
            raise DecodeError(
                "ClientHello carries more than one KeyShareEntry: this profile accepts exactly "
                "one classical share and implements no HelloRetryRequest (RFC 8446 section 4.2.8 "
                "allows several entries; see docs/CAPABILITIES.md)"
            )

        kem_scheme: int | None = None
        pq_key_share: bytes | None = None
        if EXTENSION_PQ_KEY_SHARE in extensions:
            pq = Reader(extensions[EXTENSION_PQ_KEY_SHARE])
            kem_scheme = pq.read_u16()
            pq_key_share = pq.read_vec16()
            pq.expect_end()

        # Both list extensions are vector-of-u16 on the wire, so the inner length
        # prefix has to be consumed before the code points.
        groups = _decode_u16_list(extensions, EXTENSION_SUPPORTED_GROUPS)
        algorithms = _decode_u16_list(extensions, EXTENSION_SIGNATURE_ALGORITHMS)

        return cls(
            random=random,
            cipher_suites=tuple(suites),
            supported_groups=groups,
            key_share=key_share,
            kem_scheme=kem_scheme,
            pq_key_share=pq_key_share,
            signature_algorithms=algorithms,
            legacy_session_id=session_id,
            supported_versions=_decode_u16_list(extensions, EXTENSION_SUPPORTED_VERSIONS, prefix=1),
            legacy_compression_methods=tuple(compression),
            legacy_version=version,
        )


@dataclass(frozen=True)
class ServerHello:
    """ServerHello with the classical share and the KEM ciphertext.

    Like :class:`ClientHello`, the negotiation fields are kept rather than read past, so the
    client can check that the server echoed what it sent and selected a version, a group and
    a suite the client actually offered.
    """

    random: bytes
    cipher_suite: int
    key_share: KeyShareEntry
    #: ``None`` in the classical-only profile, which omits the extension entirely.
    pq_ciphertext: bytes | None
    legacy_session_id: bytes = b""
    #: The extension types this ServerHello actually carried, so the client can refuse a
    #: response that offers an extension it never offered. RFC 8446 section 4.1.3 requires
    #: the client to abort with `unsupported_extension` in that case (audit finding K2).
    #: Decode-side metadata: ``encode()`` never reads it, so it is excluded from ``==``
    #: and a constructed message compares equal to its own round trip.
    extension_types: tuple[int, ...] = field(default=(), compare=False)
    supported_versions: tuple[int, ...] = (TLS13_VERSION,)
    legacy_compression_methods: tuple[int, ...] = (0x00,)
    legacy_version: int = LEGACY_VERSION

    def encode(self) -> bytes:
        """Encode the handshake body."""
        extensions = [
            (
                EXTENSION_SUPPORTED_VERSIONS,
                u16(self.supported_versions[0]) if self.supported_versions else b"",
            ),
            (EXTENSION_KEY_SHARE, self.key_share.encode()),
        ]
        if self.pq_ciphertext is not None:
            extensions.append((EXTENSION_PQ_CIPHERTEXT, vec16(self.pq_ciphertext)))
        return (
            u16(self.legacy_version)
            + self.random
            + vec8(self.legacy_session_id)
            + u16(self.cipher_suite)
            + vec8(bytes(self.legacy_compression_methods))
            + _encode_extensions(extensions)
        )

    def to_message(self) -> bytes:
        """Frame the body as a handshake message."""
        return handshake_message(SERVER_HELLO, self.encode())

    @classmethod
    def decode(cls, body: bytes) -> "ServerHello":
        """Decode a ServerHello body."""
        reader = Reader(body)
        version = reader.read_u16()
        random = reader.read_bytes(32)
        session_id = reader.read_vec8()
        # Same bound as ClientHello: RFC 8446 section 4.1.2's 32-byte limit is stated for
        # both messages, and a peer that echoes a longer field is malformed regardless of
        # whether the echo happens to match what this client sent.
        if len(session_id) > 32:
            raise DecodeError(
                f"ServerHello legacy_session_id is {len(session_id)} bytes, must be at most 32"
            )
        cipher_suite = reader.read_u16()
        compression = reader.read_vec8()
        extensions = _decode_extensions(reader)
        reader.expect_end()
        # A ServerHello without pq_ciphertext is a classical-only answer, not a broken
        # message; the caller decides whether it can accept one.
        if EXTENSION_PQ_CIPHERTEXT in extensions:
            # Trailing bytes inside the extension used to be dropped silently; a peer that
            # appends them is describing something this implementation does not implement.
            pq_reader = Reader(extensions[EXTENSION_PQ_CIPHERTEXT])
            pq_ciphertext = pq_reader.read_vec16()
            pq_reader.expect_end()
        else:
            pq_ciphertext = None
        if EXTENSION_KEY_SHARE not in extensions:
            # Used to be a bare `KeyError` from the dict lookup: a peer could crash the
            # caller instead of receiving a named rejection. An audit reported it (B1).
            raise DecodeError("ServerHello is missing the key_share extension")
        shares = Reader(extensions[EXTENSION_KEY_SHARE])
        entry = KeyShareEntry.decode(shares)
        # One entry only: a second `KeyShareEntry` used to be read past. RFC 8446 section
        # 4.2.8 has a ServerHello carry exactly the server's chosen share.
        shares.expect_end()
        chosen = _decode_u16_list(extensions, EXTENSION_SUPPORTED_VERSIONS, prefix=None)
        return cls(
            random=random,
            cipher_suite=cipher_suite,
            key_share=entry,
            pq_ciphertext=pq_ciphertext,
            extension_types=tuple(sorted(extensions)),
            legacy_session_id=session_id,
            supported_versions=chosen,
            legacy_compression_methods=tuple(compression),
            legacy_version=version,
        )


@dataclass(frozen=True)
class EncryptedExtensions:
    """EncryptedExtensions; empty in this profile, present to keep the flight faithful."""

    extensions: tuple[tuple[int, bytes], ...] = ()

    def encode(self) -> bytes:
        """Encode the handshake body."""
        return _encode_extensions(list(self.extensions))

    def to_message(self) -> bytes:
        """Frame the body as a handshake message."""
        return handshake_message(ENCRYPTED_EXTENSIONS, self.encode())

    @classmethod
    def decode(cls, body: bytes) -> "EncryptedExtensions":
        """Decode an EncryptedExtensions body."""
        reader = Reader(body)
        extensions = _decode_extensions(reader)
        reader.expect_end()
        return cls(tuple(extensions.items()))


@dataclass(frozen=True)
class HybridCertificateBody:
    """The certified part of a hybrid certificate: identity plus both public keys."""

    server_identity: bytes
    classical_scheme: int
    classical_public_key: bytes
    #: ``None`` for the classical-only baseline, whose certificate binds one key.
    pq_scheme: int | None
    pq_public_key: bytes | None

    def encode(self) -> bytes:
        """Encode the body that the test CA signs."""
        body = (
            vec16(self.server_identity)
            + u16(self.classical_scheme)
            + vec16(self.classical_public_key)
        )
        if self.pq_scheme is not None and self.pq_public_key is not None:
            body += u16(self.pq_scheme) + vec16(self.pq_public_key)
        return body

    @classmethod
    def decode(cls, body: bytes) -> "HybridCertificateBody":
        """Decode a certificate body, with or without the post-quantum key."""
        reader = Reader(body)
        server_identity = reader.read_vec16()
        classical_scheme = reader.read_u16()
        classical_public_key = reader.read_vec16()
        pq_scheme: int | None = None
        pq_public_key: bytes | None = None
        if not reader.at_end():
            pq_scheme = reader.read_u16()
            pq_public_key = reader.read_vec16()
        reader.expect_end()
        return cls(
            server_identity=server_identity,
            classical_scheme=classical_scheme,
            classical_public_key=classical_public_key,
            pq_scheme=pq_scheme,
            pq_public_key=pq_public_key,
        )


@dataclass(frozen=True)
class Certificate:
    """Certificate message carrying one hybrid certificate and its CA signature."""

    body: HybridCertificateBody
    ca_signature: bytes
    extensions: tuple[tuple[int, bytes], ...] = ()
    certificate_request_context: bytes = b""

    def encode(self) -> bytes:
        """Encode the handshake body.

        The certified body carries its own length prefix. Without it, a reader could
        not tell where an absent post-quantum key ends and the trailing CA signature
        begins: the optional fields sit in the middle of the structure, and a real
        certificate is a self-delimiting blob for exactly this reason.
        """
        certificate_data = vec16(self.body.encode()) + vec16(self.ca_signature)
        entry = vec24(certificate_data) + _encode_extensions(list(self.extensions))
        return vec8(self.certificate_request_context) + vec24(entry)

    def to_message(self) -> bytes:
        """Frame the body as a handshake message."""
        return handshake_message(CERTIFICATE, self.encode())

    @classmethod
    def decode(cls, body: bytes) -> "Certificate":
        """Decode a Certificate body holding exactly one certificate."""
        reader = Reader(body)
        context = reader.read_vec8()
        if context:
            # The server sent no CertificateRequest, so the context it echoes must be
            # empty (RFC 8446 section 4.4.2). The fifth review found this accepted (K6).
            raise DecodeError('Certificate carries a non-empty certificate_request_context')
        entries = Reader(reader.read_vec24())
        reader.expect_end()
        if entries.at_end():
            raise DecodeError("Certificate message carries no certificate")
        certificate_data = Reader(entries.read_vec24())
        entries_reader = Reader(entries.read_vec16())
        extensions: list[tuple[int, bytes]] = []
        while not entries_reader.at_end():
            kind = entries_reader.read_u16()
            extensions.append((kind, entries_reader.read_vec16()))
        if not entries.at_end():
            raise DecodeError("this implementation carries exactly one certificate per message")
        certified_body = HybridCertificateBody.decode(certificate_data.read_vec16())
        ca_signature = certificate_data.read_vec16()
        certificate_data.expect_end()
        return cls(
            body=certified_body,
            ca_signature=ca_signature,
            extensions=tuple(extensions),
            certificate_request_context=context,
        )


@dataclass(frozen=True)
class X509Chain:
    """Certificate message carrying a real X.509 chain (leaf first, then issuers).

    The same handshake message type as the modelled :class:`Certificate`, with a
    different body: the profile decides which one is in play, and a peer that sends the
    other shape fails at decode rather than being silently accepted.
    """

    chain: tuple[bytes, ...]
    # Legacy convenience field applies to the leaf only.
    extensions: tuple[tuple[int, bytes], ...] = ()
    certificate_request_context: bytes = b""
    entry_extensions: tuple[tuple[tuple[int, bytes], ...], ...] = ()

    def encode(self) -> bytes:
        """Encode the handshake body."""
        per_entry = self.entry_extensions or (self.extensions,) + ((),) * (len(self.chain) - 1)
        if len(per_entry) != len(self.chain):
            raise ValueError("entry_extensions must match the certificate count")
        if self.entry_extensions and self.extensions and self.extensions != per_entry[0]:
            raise ValueError("conflicting leaf extensions")
        entries = b"".join(
            vec24(blob) + _encode_extensions(list(ext))
            for blob, ext in zip(self.chain, per_entry)
        )
        return vec8(self.certificate_request_context) + vec24(entries)

    def to_message(self) -> bytes:
        """Frame the body as a handshake message."""
        return handshake_message(CERTIFICATE, self.encode())

    @classmethod
    def decode(cls, body: bytes) -> "X509Chain":
        """Decode a Certificate body carrying one or more opaque DER certificates."""
        reader = Reader(body)
        context = reader.read_vec8()
        if context:
            # Same rule as the modelled Certificate body above: no CertificateRequest is
            # sent in this profile, so a server echoing a context is describing a handshake
            # that did not happen (RFC 8446 section 4.4.2).
            raise DecodeError('X509Chain carries a non-empty certificate_request_context')
        entries = Reader(reader.read_vec24())
        reader.expect_end()
        chain: list[bytes] = []
        entry_extensions: list[tuple[tuple[int, bytes], ...]] = []
        while not entries.at_end():
            blob = entries.read_vec24()
            extensions = _decode_extensions(entries)
            entry_extensions.append(tuple(extensions.items()))
            chain.append(blob)
        if not chain:
            raise DecodeError("Certificate message carries no certificates")
        return cls(
            chain=tuple(chain),
            extensions=entry_extensions[0],
            entry_extensions=tuple(entry_extensions),
            certificate_request_context=context,
        )


@dataclass(frozen=True)
class CertificateVerify:
    """CertificateVerify carrying the dual-signature payload."""

    payload: bytes

    def encode(self) -> bytes:
        """Encode the handshake body."""
        return self.payload

    def to_message(self) -> bytes:
        """Frame the body as a handshake message."""
        return handshake_message(CERTIFICATE_VERIFY, self.encode())

    @classmethod
    def decode(cls, body: bytes) -> "CertificateVerify":
        """Decode a CertificateVerify body."""
        return cls(payload=body)


@dataclass(frozen=True)
class Finished:
    """Finished carrying ``verify_data`` of hash length."""

    verify_data: bytes

    def encode(self) -> bytes:
        """Encode the handshake body."""
        return self.verify_data

    def to_message(self) -> bytes:
        """Frame the body as a handshake message."""
        return handshake_message(FINISHED, self.encode())

    @classmethod
    def decode(cls, body: bytes) -> "Finished":
        """Decode a Finished body."""
        return cls(verify_data=body)
