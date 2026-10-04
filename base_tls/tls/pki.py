"""A real X.509 chain for the handshake, so absolute byte counts mean something.

The modelled certificate in :mod:`tls.credentials` binds a name and two public keys
with a single signature. That is enough to exercise the handshake, and it is what the
symbolic models describe, but its byte count is not comparable to a deployment: a real
handshake carries a leaf and at least one intermediate, with real encodings.

This module builds that: a root CA, an intermediate, and a leaf, with the post-quantum
public key carried in a private-extension OID on the leaf — the approach the design note
suggests and the one real deployments are converging on, since it needs no change to the
certificate's subject structure. Chain validation here is real: signatures up the chain,
validity windows, CA basic constraints, and the name, all checked by this module rather
than asserted.

Post-quantum *chain* migration is still out of scope: every signature in this chain is
ECDSA P-256. What becomes realistic is the size of what the server sends and the client
checks, which is what the benchmarks need.
"""

from __future__ import annotations

import datetime as _datetime
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from .errors import HandshakeError
from .wire import Reader, u16, vec16

__all__ = [
    "PQ_PUBLIC_KEY_OID",
    "CertificateChain",
    "build_test_chain",
    "pq_extension_from_leaf",
    "verify_chain",
]

#: Private-enterprise OID for the extension carrying `uint16 scheme_id ‖ vec16 key`.
#: A real deployment would need an assigned OID; this one is under the example arc.
PQ_PUBLIC_KEY_OID = ObjectIdentifier("1.3.6.1.4.1.99999.1")

_ROOT_NAME = "hybrid-tls13 test root CA"
_INTERMEDIATE_NAME = "hybrid-tls13 test intermediate CA"
_VALIDITY_DAYS = 365
_CLOCK_SKEW = _datetime.timedelta(days=1)


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _key_usage(*, ca: bool) -> x509.KeyUsage:
    if ca:
        return x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        )
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def _issue(
    *,
    subject: str,
    issuer_name: x509.Name,
    subject_public_key,
    signing_key,
    ca: bool,
    path_length: int | None,
    authority_key_identifier: x509.AuthorityKeyIdentifier | None,
    extra_extensions: list[x509.ExtensionType] | None = None,
    valid_from: _datetime.datetime | None = None,
    valid_to: _datetime.datetime | None = None,
) -> x509.Certificate:
    """Issue one certificate, signed by ``signing_key``."""
    now = _datetime.datetime.now(_datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(issuer_name)
        .public_key(subject_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from or (now - _CLOCK_SKEW))
        .not_valid_after(valid_to or (now + _datetime.timedelta(days=_VALIDITY_DAYS)))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
        .add_extension(_key_usage(ca=ca), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_public_key), critical=False)
    )
    if authority_key_identifier is not None:
        builder = builder.add_extension(authority_key_identifier, critical=False)
    for extension in extra_extensions or []:
        builder = builder.add_extension(extension, critical=False)
    return builder.sign(signing_key, hashes.SHA256())


@dataclass(frozen=True)
class CertificateChain:
    """A leaf plus its intermediates, and the root the client must already trust."""

    #: DER blobs as they travel in the Certificate message: leaf first, then intermediates.
    chain_der: tuple[bytes, ...]
    root_der: bytes
    root_public_key: object
    leaf_der: bytes

    @property
    def leaf(self) -> x509.Certificate:
        """The parsed leaf certificate."""
        return x509.load_der_x509_certificate(self.leaf_der)

    @property
    def total_bytes(self) -> int:
        """Bytes these certificates occupy before any message framing."""
        return sum(len(blob) for blob in self.chain_der)

    def pq_public_key(self) -> tuple[int, bytes] | None:
        """Return ``(scheme_id, public_key)`` from the leaf extension, or ``None``."""
        return pq_extension_from_leaf(self.leaf)


def build_test_chain(
    identity: str = "server.example",
    *,
    leaf_key=None,
    pq_scheme_id: int | None = None,
    pq_public_key: bytes | None = None,
    leaf_valid_from: _datetime.datetime | None = None,
    leaf_valid_to: _datetime.datetime | None = None,
) -> CertificateChain:
    """Build root -> intermediate -> leaf, with the PQ key in a leaf extension.

    ``leaf_key`` is the server's own signing key, so the leaf certifies the key the
    handshake will actually use; when omitted a fresh key is generated and only the size
    of the chain is meaningful. All three certificates use ECDSA P-256, which is what a
    real deployment would use for the classical half: the leaf carries ``serverAuth``,
    the CAs carry ``keyCertSign``, and the validity windows are a year.
    """
    root_key = ec.generate_private_key(ec.SECP256R1())
    intermediate_key = ec.generate_private_key(ec.SECP256R1())
    if leaf_key is None:
        leaf_key = ec.generate_private_key(ec.SECP256R1())

    root_name = _name(_ROOT_NAME)
    root = _issue(
        subject=_ROOT_NAME,
        issuer_name=root_name,
        subject_public_key=root_key.public_key(),
        signing_key=root_key,
        ca=True,
        path_length=1,
        authority_key_identifier=None,
    )
    intermediate = _issue(
        subject=_INTERMEDIATE_NAME,
        issuer_name=root.subject,
        subject_public_key=intermediate_key.public_key(),
        signing_key=root_key,
        ca=True,
        path_length=0,
        authority_key_identifier=x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
    )

    extra: list[x509.ExtensionType] = [
        x509.SubjectAlternativeName([x509.DNSName(identity)]),
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
    ]
    if pq_scheme_id is not None and pq_public_key is not None:
        extra.append(
            x509.UnrecognizedExtension(PQ_PUBLIC_KEY_OID, u16(pq_scheme_id) + vec16(pq_public_key))
        )
    leaf = _issue(
        subject=identity,
        issuer_name=intermediate.subject,
        subject_public_key=leaf_key.public_key(),
        signing_key=intermediate_key,
        ca=False,
        path_length=None,
        authority_key_identifier=x509.AuthorityKeyIdentifier.from_issuer_public_key(
            intermediate_key.public_key()
        ),
        extra_extensions=extra,
        valid_from=leaf_valid_from,
        valid_to=leaf_valid_to,
    )

    encode = lambda certificate: certificate.public_bytes(serialization.Encoding.DER)  # noqa: E731
    return CertificateChain(
        chain_der=(encode(leaf), encode(intermediate)),
        root_der=encode(root),
        root_public_key=root_key.public_key(),
        leaf_der=encode(leaf),
    )


def pq_extension_from_leaf(leaf: x509.Certificate) -> tuple[int, bytes] | None:
    """Read the post-quantum public key extension, or return ``None`` when absent."""
    try:
        extension = leaf.extensions.get_extension_for_oid(PQ_PUBLIC_KEY_OID)
    except x509.ExtensionNotFound:
        return None
    value = extension.value
    if not isinstance(value, x509.UnrecognizedExtension):
        return None
    reader = Reader(value.value)
    scheme_id = reader.read_u16()
    public_key = reader.read_vec16()
    reader.expect_end()
    return scheme_id, public_key


def _check_window(certificate: x509.Certificate, label: str) -> None:
    now = _datetime.datetime.now(_datetime.UTC)
    if now < certificate.not_valid_before_utc or now > certificate.not_valid_after_utc:
        raise HandshakeError("certificate", f"{label} is outside its validity window")


def _require_key_cert_sign(certificate: x509.Certificate, position: int) -> None:
    """Require ``keyCertSign`` on a certificate that issued another.

    A static security review noted that this chain check was missing: a certificate with
    ``basicConstraints: CA`` but a key usage that forbids signing certificates could
    otherwise issue one here.
    """
    try:
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        raise HandshakeError(
            "certificate", f"chain[{position}] is a CA but carries no key usage extension"
        ) from None
    if not usage.key_cert_sign:
        raise HandshakeError(
            "certificate", f"chain[{position}] is a CA but its key usage forbids signing certificates"
        )


def _require_digital_signature(certificate: x509.Certificate) -> None:
    """Require the leaf's key usage to permit signing, when it states one.

    TLS 1.3 authenticates the server with a signature made by the leaf's key, so a
    certificate whose ``keyUsage`` switches ``digitalSignature`` off cannot legitimately
    be used for this handshake. An earlier version checked the *issuer's* ``keyCertSign``
    and never looked at the leaf's own usage, so a certificate that forbids signing was
    accepted as long as its signature over CertificateVerify verified — which it does,
    since the private key signs regardless of what the certificate says. An independent
    audit found this. An absent extension means "no stated restriction" and is allowed.
    """
    try:
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return
    if not usage.digital_signature:
        raise HandshakeError(
            "certificate", "the leaf certificate's key usage forbids digital signatures"
        )


def _require_usable_for_server_auth(certificate: x509.Certificate, position: int) -> None:
    """Require an intermediate CA's EKU to permit server authentication.

    RFC 5280's extended key usage states the purposes a certified key may be used for.
    When an intermediate CA carries one, every certificate below it inherits that
    restriction, so an intermediate restricted to ``clientAuth`` must not be able to
    validate a server — which is what happened while only the *leaf's* EKU was checked.
    ``anyExtendedKeyUsage`` permits all purposes, per RFC 5280 section 4.2.1.12.
    """
    try:
        purposes = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return
    allowed = set(purposes)
    if ExtendedKeyUsageOID.SERVER_AUTH in allowed:
        return
    if getattr(ExtendedKeyUsageOID, "ANY_EXTENDED_KEY_USAGE", None) in allowed:
        return
    raise HandshakeError(
        "certificate",
        f"chain[{position}] is restricted to purposes {sorted(oid.dotted_string for oid in allowed)} "
        "and may not be used for server authentication",
    )


def _enforce_path_length(
    issuer: x509.Certificate, position: int, chain: list[x509.Certificate]
) -> None:
    """Enforce ``pathLenConstraint`` for the subtree below ``issuer``.

    The constraint bounds how many *non-self-issued intermediate* certificates may follow
    it in a valid path. Without this check, an intermediate marked ``path_length=0`` could
    still be used to issue another CA, which is the constraint's whole purpose.
    """
    constraint = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
    if constraint.path_length is None:
        return
    # Count only the *CA* certificates below, not the end-entity leaf: RFC 5280's
    # pathLenConstraint bounds intermediate CAs, and counting the leaf would reject every
    # chain whose intermediate carries path_length=0.
    intermediates = 0
    for certificate in chain[:position]:
        # An absent `basicConstraints` means "not a CA" (RFC 5280 section 4.2.1.9), not an
        # error: a leaf that legally omits it used to reach this lookup and raise
        # `x509.ExtensionNotFound` out of a path validation. Every other lookup in this file
        # was given that default in round 6; this one was missed, and the fifth review found
        # it (their V6-01) by reading the file for exactly that asymmetry.
        try:
            below = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound:
            below = x509.BasicConstraints(ca=False, path_length=None)
        if below.ca and certificate.subject != certificate.issuer:
            intermediates += 1
    if intermediates > constraint.path_length:
        raise HandshakeError(
            "certificate",
            f"chain[{position}] allows {constraint.path_length} intermediate(s) below it, "
            f"but the chain has {intermediates}",
        )


#: Extensions this verifier understands. Anything else marked critical is refused, as
#: RFC 5280 section 4.2 requires: a critical extension asserts that the path must not be
#: accepted unless the semantics are understood.
_UNDERSTOOD_EXTENSIONS: tuple[ObjectIdentifier, ...] = (
    x509.oid.ExtensionOID.BASIC_CONSTRAINTS,
    x509.oid.ExtensionOID.KEY_USAGE,
    x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER,
    x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
    x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
    x509.oid.ExtensionOID.EXTENDED_KEY_USAGE,
    PQ_PUBLIC_KEY_OID,
)


def _reject_unknown_critical_extensions(certificate: x509.Certificate, position: int) -> None:
    """Refuse a certificate carrying a critical extension whose semantics are unknown."""
    for extension in certificate.extensions:
        if extension.critical and extension.oid not in _UNDERSTOOD_EXTENSIONS:
            raise HandshakeError(
                "certificate",
                f"chain[{position}] carries an unrecognised critical extension "
                f"{extension.oid.dotted_string}",
            )


def _verify_signature(child: x509.Certificate, issuer: x509.Certificate) -> None:
    """Check ``child`` was signed by ``issuer``'s key."""
    public_key = issuer.public_key()
    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(child.signature_hash_algorithm),
            )
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            # An EdDSA issuer is legitimate PKI; the earlier code hardcoded `ec.ECDSA` and
            # raised TypeError for every other key type, which is not a rejection a caller can
            # act on. An independent audit reported it (their B10).
            public_key.verify(child.signature, child.tbs_certificate_bytes)
        else:
            raise HandshakeError(
                "certificate",
                f"this verifier does not support {type(public_key).__name__} issuers; "
                "only ECDSA and EdDSA are implemented",
            )
    except (InvalidSignature, ValueError) as error:
        raise HandshakeError(
            "certificate",
            f"{child.subject.rfc4514_string()} is not signed by {issuer.subject.rfc4514_string()}",
        ) from error


def verify_chain(
    chain_der: list[bytes] | tuple[bytes, ...],
    trusted_root: x509.Certificate,
    expected_name: str,
) -> x509.Certificate:
    """Validate a chain against a trust anchor and return the leaf.

    Checks, in order: the chain is non-empty, every certificate is inside its validity
    window, each certificate is signed by the next one, the top of the chain is the
    trusted root, every issuer has ``basicConstraints`` with ``ca`` set and a key usage
    that permits signing certificates, ``pathLenConstraint`` is respected, no unknown
    critical extension appears, and the leaf carries ``expected_name`` in its subject
    alternative names.

    An earlier version also took an ``issuer_public_key`` argument, documented as "how a
    caller holding only the anchor's public key would use this" — and then discarded it,
    because the anchor check needs the certificate to compare against. Nothing called it
    with that argument, so the parameter was a promise the code did not keep. It is gone
    rather than implemented: a second verification path shipped without tests would be a
    worse answer to a security review than one honest path. A trust-anchor-by-key mode
    would be a real feature, and it would need its own tests.
    """
    if not chain_der:
        raise HandshakeError("certificate", "Certificate message carried no certificates")

    parsed = [x509.load_der_x509_certificate(blob) for blob in chain_der]
    leaf = parsed[0]
    for index, certificate in enumerate(parsed):
        _check_window(certificate, "leaf" if index == 0 else f"chain[{index}]")

    # Leaf must be an end-entity certificate, and every issuer a CA. An absent
    # `basicConstraints` is *allowed* for an end entity (RFC 5280 section 4.2.1.9), so it
    # means "not a CA" rather than an error: the earlier code let the lookup raise
    # `x509.ExtensionNotFound` out of a certificate a peer chose, which is not a rejection.
    try:
        constraints = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        constraints = x509.BasicConstraints(ca=False, path_length=None)
    if constraints.ca:
        raise HandshakeError("certificate", "the leaf certificate is a CA certificate")
    _require_digital_signature(leaf)

    for index in range(len(parsed) - 1):
        issuer = parsed[index + 1]
        try:
            issuer_constraints = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound:
            issuer_constraints = x509.BasicConstraints(ca=False, path_length=None)
        if not issuer_constraints.ca:
            raise HandshakeError(
                "certificate", f"chain[{index + 1}] issued a certificate but is not a CA"
            )
        _require_key_cert_sign(issuer, index + 1)
        _require_usable_for_server_auth(issuer, index + 1)
        _enforce_path_length(issuer, index + 1, parsed)
        _verify_signature(parsed[index], issuer)

    for index, certificate in enumerate(parsed):
        _reject_unknown_critical_extensions(certificate, index)

    top = parsed[-1]
    # The anchor check compares the FULL certificate, and only skips the signature check
    # when the top of the chain IS the trusted anchor byte for byte.
    #
    # An earlier version compared `subject` and `serial_number` instead, and skipped the
    # check when they matched. Both fields are public and attacker-chosen: a forged root
    # carrying the trusted root's subject and serial number, with the attacker's own key,
    # would pass this test and the chain would be accepted. A static security review found
    # it, and the fix is to compare the encoding, which the attacker cannot forge.
    if chain_der[-1] != trusted_root.public_bytes(serialization.Encoding.DER):
        _verify_signature(top, trusted_root)

    # EKU absent means "no stated restriction" (RFC 5280 section 4.2.1.12), which is a
    # legitimate server certificate, so absence is not an error.
    try:
        purposes = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        purposes = None
    if purposes is not None and ExtendedKeyUsageOID.SERVER_AUTH not in purposes:
        raise HandshakeError("certificate", "the leaf certificate is not valid for server authentication")

    # A leaf with no SAN carries no DNS name at all, so it cannot match the name the client
    # means to reach — a rejection, not a `x509.ExtensionNotFound` escaping to the caller.
    try:
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        present = sorted(names.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        present = []
    if expected_name not in present:
        raise HandshakeError(
            "certificate",
            f"the leaf certificate is for {present if present else 'no DNS name'}, "
            f"not {expected_name}",
        )
    return leaf