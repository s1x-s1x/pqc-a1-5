"""X.509 alternative public keys/signatures, with classical validation first.

The extension OIDs follow X.509 (2019); the SLH algorithm OIDs are private
experimental identifiers. This is an application profile in the TLS harness.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, ObjectIdentifier

from .der import (DerError, algorithm_identifier, algorithm_oid, bit_string,
                  bit_string_bytes, elements, pre_tbs, single, tlv)
from .errors import HandshakeError
from .pki import CertificateChain, PQ_PUBLIC_KEY_OID, _key_usage, _name, verify_chain
from .wire import u16, vec16

SUBJECT_ALT_PUBLIC_KEY_INFO = ObjectIdentifier("2.5.29.72")
ALT_SIGNATURE_ALGORITHM = ObjectIdentifier("2.5.29.73")
ALT_SIGNATURE_VALUE = ObjectIdentifier("2.5.29.74")
ALGORITHM_OIDS = {
    "slh-dsa-sm3-128s": "1.3.6.1.4.1.99999.2.1",
    "slh-dsa-sm3-128f": "1.3.6.1.4.1.99999.2.2",
    "slh-dsa-sm3-128-24": "1.3.6.1.4.1.99999.2.3",
    "ml-dsa-44": "2.16.840.1.101.3.4.3.17",
}
OID_ALGORITHMS = {value: key for key, value in ALGORITHM_OIDS.items()}


def get_alt_signer(name: str, *, force_python=False, require_native=False, threads=1, library=None):
    if name not in ALGORITHM_OIDS:
        raise ValueError(f"unsupported alternative-signature algorithm {name!r}")
    if name.startswith("slh-dsa-sm3-"):
        from .pq.slhdsa_sm3 import SlhDsaSm3
        return SlhDsaSm3(name, threads=threads, library=library, force_python=force_python,
                        require_native=require_native)
    from .pq.signature import get_pq_signer
    return get_pq_signer(name)


def public_key_info(name: str, public_key: bytes) -> bytes:
    return tlv(0x30, algorithm_identifier(ALGORITHM_OIDS[name]) + bit_string(public_key))


def parse_public_key_info(encoded: bytes) -> tuple[str, bytes]:
    fields = elements(single(encoded, 0x30).value)
    if len(fields) != 2:
        raise DerError("alternative SPKI requires algorithm and key")
    identifier = algorithm_oid(fields[0].encoded)
    if identifier not in OID_ALGORITHMS:
        raise DerError("unknown alternative public-key algorithm")
    key = bit_string_bytes(fields[1].encoded)
    signer = get_alt_signer(OID_ALGORITHMS[identifier])
    if len(key) != signer.public_key_bytes:
        raise DerError("alternative public-key length mismatch")
    return OID_ALGORITHMS[identifier], key


def _extension(certificate: x509.Certificate, identifier: ObjectIdentifier) -> bytes | None:
    try:
        extension = certificate.extensions.get_extension_for_oid(identifier)
    except x509.ExtensionNotFound:
        return None
    if extension.critical or not isinstance(extension.value, x509.UnrecognizedExtension):
        raise DerError("alternative extensions must be noncritical opaque DER")
    return extension.value.value


@dataclass(frozen=True)
class AltVerification:
    leaf: x509.Certificate
    checked_edges: int
    legacy_edges: int
    algorithms: tuple[str, ...]
    verifiers: tuple[dict, ...] = ()

    @property
    def complete(self) -> bool:
        return self.checked_edges > 0 and self.legacy_edges == 0


def verify_alt_chain(chain_der, trusted_root: x509.Certificate, expected_name: str,
                     *, require_alt_chain=False, expected_algorithm=None,
                     force_python=False, require_native=False, library=None) -> AltVerification:
    """Validate all ordinary constraints first, then every advertised alt edge.

    No public key supplied by the peer replaces the local root's alt key. A peer
    may include the root, but only byte-identical trusted-root DER is skipped.
    In compatibility mode a legacy edge has neither 73 nor 74 nor child72;
    partial extensions, mismatches and failed advertised signatures are errors.
    """
    leaf = verify_chain(chain_der, trusted_root, expected_name)
    parsed = [x509.load_der_x509_certificate(x) for x in chain_der]
    root_der = trusted_root.public_bytes(serialization.Encoding.DER)
    if chain_der[-1] == root_der:
        parsed.pop()
    checked, legacy, algorithms, verifiers = 0, 0, [], []
    try:
        # Check the local anchor's encoding even on a legacy path. Its alternative
        # key is provisioned out of band together with this exact certificate.
        root_alt = _extension(trusted_root, SUBJECT_ALT_PUBLIC_KEY_INFO)
        if root_alt is not None:
            root_name, _ = parse_public_key_info(root_alt)
            if expected_algorithm is not None and root_name != expected_algorithm:
                raise DerError("configured algorithm differs from the local trust anchor")
        elif require_alt_chain:
            raise DerError("the local trust anchor has no alternative public key")
        for index, child in enumerate(parsed):
            issuer = parsed[index + 1] if index + 1 < len(parsed) else trusted_root
            if child.issuer != issuer.subject:
                raise DerError("certificate issuer name differs from issuer subject")
            own_key = _extension(child, SUBJECT_ALT_PUBLIC_KEY_INFO)
            alg = _extension(child, ALT_SIGNATURE_ALGORITHM)
            sig = _extension(child, ALT_SIGNATURE_VALUE)
            if alg is None and sig is None and own_key is None:
                if require_alt_chain:
                    raise DerError("required alternative signature extensions are absent")
                legacy += 1
                continue
            if alg is None or sig is None:
                raise DerError("incomplete alternative signature extension pair")
            issuer_key = _extension(issuer, SUBJECT_ALT_PUBLIC_KEY_INFO)
            if issuer_key is None:
                raise DerError("advertised alternative signature has no issuer alternative key")
            name, key = parse_public_key_info(issuer_key)
            identifier = algorithm_oid(alg)
            if identifier != ALGORITHM_OIDS[name]:
                raise DerError("alternative signature algorithm differs from issuer SPKI")
            if expected_algorithm is not None and name != expected_algorithm:
                raise DerError("alternative signature algorithm differs from configured profile")
            if own_key is not None:
                # Child CA keys are classical-signed and alt-signed. Merely parsing
                # or finding a supplied 72 does not make it a trusted anchor.
                parse_public_key_info(own_key)
            signature = bit_string_bytes(sig)
            signer = get_alt_signer(name, force_python=force_python, require_native=require_native,
                                    library=library)
            if len(signature) != signer.signature_bytes:
                raise DerError("alternative signature length mismatch")
            if not signer.verify(key, pre_tbs(child.tbs_certificate_bytes), signature):
                raise DerError("alternative signature verification failed")
            import hashlib
            evidence = dict(getattr(signer, "last_verification", None) or {"mode": "provider", "algorithm": name})
            evidence.update({"edge": index, "public_key_sha256": hashlib.sha256(key).hexdigest(),
                "message_sha256": hashlib.sha256(pre_tbs(child.tbs_certificate_bytes)).hexdigest(),
                "signature_sha256": hashlib.sha256(signature).hexdigest(), "passed": True})
            verifiers.append(evidence)
            checked += 1
            algorithms.append(name)
        return AltVerification(leaf, checked, legacy, tuple(algorithms), tuple(verifiers))
    except (DerError, ValueError, TypeError, KeyError) as error:
        raise HandshakeError("certificate_alt", str(error)) from error


def _issue_fixed(*, subject, issuer, subject_key, issuer_key, ca, path_length,
                 serial, valid_from, valid_to, extra=()):
    builder = (x509.CertificateBuilder().subject_name(_name(subject))
               .issuer_name(issuer).public_key(subject_key).serial_number(serial)
               .not_valid_before(valid_from).not_valid_after(valid_to)
               .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
               .add_extension(_key_usage(ca=ca), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False))
    for extension in extra:
        builder = builder.add_extension(extension, critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def issue_alt_certificate(*, name: str, signer, secret_key, issuer_public_key: bytes,
                          extra=(), before_sign: Callable | None = None,
                          after_sign: Callable | None = None, **issue):
    """Two fixed-serial classical builds around one PQ signature of preTBS.

    before_sign(name, issuer_public_key, preTBS) is called before each CA signing
    attempt; a budget ledger can reserve/consume its count transactionally.
    """
    if signer.name != name:
        raise ValueError("alternative signer does not match requested algorithm")
    if before_sign is not None and after_sign is None:
        raise ValueError("a CA reservation callback requires an after_sign finalizer")
    reserved = {SUBJECT_ALT_PUBLIC_KEY_INFO, ALT_SIGNATURE_ALGORITHM, ALT_SIGNATURE_VALUE}
    if any(getattr(x, "oid", None) in reserved - {SUBJECT_ALT_PUBLIC_KEY_INFO} for x in extra):
        raise ValueError("caller supplied reserved alternative signature extension")
    extensions = [*extra, x509.UnrecognizedExtension(ALT_SIGNATURE_ALGORITHM,
                                                   algorithm_identifier(ALGORITHM_OIDS[name]))]
    draft = _issue_fixed(extra=extensions, **issue)
    to_sign = pre_tbs(draft.tbs_certificate_bytes)
    receipt = before_sign(name, bytes(issuer_public_key), to_sign) if before_sign else None
    try:
        signature = signer.sign(secret_key, to_sign)
        if len(signature) != signer.signature_bytes or not signer.verify(issuer_public_key, to_sign, signature):
            raise ValueError("generated alternative signature failed its independent wrapper check")
        final = _issue_fixed(extra=[*extensions, x509.UnrecognizedExtension(ALT_SIGNATURE_VALUE,
                                                                         bit_string(signature))], **issue)
        if pre_tbs(final.tbs_certificate_bytes) != to_sign:
            raise ValueError("preTBS changed during final certificate assembly")
    except BaseException as original:
        if receipt is not None:
            try:
                after_sign(receipt, None)
            except Exception as finalization:
                # The reservation remains charged even when its finalizer fails.
                # Preserve the signing/assembly error for callers and traceback.
                original.add_note("CA budget finalization also failed: " + str(finalization))
        raise
    if receipt is not None:
        after_sign(receipt, signature)
    return final


@dataclass
class TestChainMaterial:
    chain: CertificateChain
    root_key: object
    intermediate_key: object
    leaf_key: object
    baseline_chain: CertificateChain
    classical_chain: CertificateChain
    signing_records: list[dict]


def build_alt_test_chain(name: str, *, identity="server.example", leaf_key=None,
                         pq_scheme_id=None, pq_public_key=None, threads=1,
                         library=None, before_sign=None, after_sign=None, now=None, root_key=None,
                         intermediate_key=None) -> TestChainMaterial:
    """Offline fixture generator. Runtime handshakes load its public chain.

    Key material returned here is explicitly for generated test fixtures. Root
    self-signature remains ECDSA; its alternative key belongs to the local store.
    """
    now = now or dt.datetime.now(dt.UTC).replace(microsecond=0)
    valid_from, valid_to = now - dt.timedelta(days=1), now + dt.timedelta(days=365)
    root_key = root_key or ec.generate_private_key(ec.SECP256R1())
    intermediate_key = intermediate_key or ec.generate_private_key(ec.SECP256R1())
    leaf_key = leaf_key or ec.generate_private_key(ec.SECP256R1())
    signer = get_alt_signer(name, threads=threads, library=library)
    root_secret, root_public = signer.keygen()
    intermediate_secret, intermediate_public = signer.keygen()
    root_name, intermediate_name = "A1-5 test root", "A1-5 test intermediate"
    shared = dict(valid_from=valid_from, valid_to=valid_to)
    root_args = dict(subject=root_name, issuer=_name(root_name), subject_key=root_key.public_key(),
                     issuer_key=root_key, ca=True, path_length=1, serial=1, **shared)
    intermediate_args = dict(subject=intermediate_name, issuer=_name(root_name),
                             subject_key=intermediate_key.public_key(), issuer_key=root_key,
                             ca=True, path_length=0, serial=2, **shared)
    leaf_args = dict(subject=identity, issuer=_name(intermediate_name), subject_key=leaf_key.public_key(),
                     issuer_key=intermediate_key, ca=False, path_length=None, serial=3, **shared)
    leaf_ext = [x509.SubjectAlternativeName([x509.DNSName(identity)]),
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])]
    if pq_scheme_id is not None and pq_public_key is not None:
        leaf_ext.append(x509.UnrecognizedExtension(PQ_PUBLIC_KEY_OID, u16(pq_scheme_id) + vec16(pq_public_key)))
    root = _issue_fixed(extra=[x509.UnrecognizedExtension(SUBJECT_ALT_PUBLIC_KEY_INFO,
                                                        public_key_info(name, root_public))], **root_args)
    signing_records = []
    def reserve(algorithm, public, message):
        import hashlib
        receipt = None
        if before_sign is not None:
            receipt = before_sign(algorithm, public, message)
        signing_records.append({"algorithm": algorithm, "issuer_public_key_sha256": hashlib.sha256(public).hexdigest(),
                                "pre_tbs_sha256": hashlib.sha256(message).hexdigest(), "message_bytes": len(message),
                                "budget_receipt": str(receipt) if receipt is not None else None})
        return receipt
    def finish(receipt, signature=None):
        if after_sign is None:
            raise ValueError("CA budget finalizer is required")
        after_sign(receipt, signature)
        import hashlib
        for row in signing_records:
            if row["budget_receipt"] == str(receipt):
                row["budget_status"] = "committed" if signature is not None else "failed"
                row["signature_sha256"] = hashlib.sha256(signature).hexdigest() if signature is not None else None
    intermediate = issue_alt_certificate(name=name, signer=signer, secret_key=root_secret,
        issuer_public_key=root_public, extra=[x509.UnrecognizedExtension(SUBJECT_ALT_PUBLIC_KEY_INFO,
        public_key_info(name, intermediate_public))], before_sign=reserve, after_sign=finish, **intermediate_args)
    leaf = issue_alt_certificate(name=name, signer=signer, secret_key=intermediate_secret,
                                issuer_public_key=intermediate_public, extra=leaf_ext, before_sign=reserve,
                                after_sign=finish, **leaf_args)
    encode = lambda c: c.public_bytes(serialization.Encoding.DER)
    def bundle(r, i, l):
        return CertificateChain((encode(l), encode(i)), encode(r), root_key.public_key(), encode(l))
    baseline_root = _issue_fixed(**root_args)
    baseline_intermediate = _issue_fixed(**intermediate_args)
    baseline_leaf = _issue_fixed(extra=leaf_ext, **leaf_args)
    classical_leaf = _issue_fixed(extra=leaf_ext[:2], **leaf_args)
    result = bundle(root, intermediate, leaf)
    verify_alt_chain(result.chain_der, root, identity, require_alt_chain=True, expected_algorithm=name,
                     require_native=name.startswith("slh-dsa-sm3-"), library=library)
    if hasattr(signer, "close"):
        signer.close()
    return TestChainMaterial(result, root_key, intermediate_key, leaf_key,
                             bundle(baseline_root, baseline_intermediate, baseline_leaf),
                             bundle(baseline_root, baseline_intermediate, classical_leaf), signing_records)
