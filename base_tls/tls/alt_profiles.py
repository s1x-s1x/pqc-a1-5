"""P0-P4 handshake profiles over one set of preissued fixture credentials."""
from __future__ import annotations

import hashlib
from pathlib import Path

from cryptography import x509

from .config import HybridTLSConfig
from .der import extension_fields, tbs_extensions
from .handshake.connection import HybridConnection


def profiles(fixtures, *, handshake_signer="falcon-512", require_alt=True):
    fixtures = Path(fixtures)
    baseline = str(fixtures / "slh-dsa-sm3-128-24")
    common = dict(x509=True, pq_signer=handshake_signer, kem="ml-kem-768")
    result = {
        "P0": HybridTLSConfig(**common, pq_enabled=False, alt_fixture=baseline),
        "P1": HybridTLSConfig(**common, alt_fixture=baseline),
    }
    for code, name in (("P2", "slh-dsa-sm3-128-24"), ("P3", "slh-dsa-sm3-128s"), ("P4", "ml-dsa-44")):
        result[code] = HybridTLSConfig(**common, alt_chain=name, require_alt_chain=require_alt,
                                      alt_fixture=str(fixtures / name))
    return result


def e1_record(profile, config):
    """Execute a real authenticated handshake and export exact message/DER bytes.

    The server-flight figure is TLS-harness wire bytes; external TCP framing,
    segmentation and initcwnd belong to the root runner's network evidence.
    """
    result = HybridConnection.run(config)
    chain = result.server.credentials.chain
    extensions = []
    for position, blob in enumerate(chain.chain_der):
        certificate = x509.load_der_x509_certificate(blob)
        for ext in tbs_extensions(certificate.tbs_certificate_bytes):
            identifier, critical, value = extension_fields(ext.encoded)
            extensions.append({"certificate": "leaf" if position == 0 else "intermediate",
                               "oid": identifier, "critical": critical,
                               "encoded_extension_bytes": len(ext.encoded), "value_bytes": len(value)})
    return {"schema": "a15-E1-v1", "profile": profile, "configuration": config.describe(),
            "passed": result.application_payload_ok and result.exporters_match,
            "handshake_bytes": result.handshake_bytes, "server_flight_bytes": result.server_bytes,
            "per_message": [{"name": x.name, "sender": x.sender, "plaintext_bytes": x.message_bytes,
                             "protection_bytes": x.protection_bytes, "wire_bytes": x.total_bytes} for x in result.messages],
            "chain_der_bytes": [len(x) for x in chain.chain_der], "chain_der_sha256": [hashlib.sha256(x).hexdigest() for x in chain.chain_der],
            "root_der_sha256": hashlib.sha256(chain.root_der).hexdigest(),
            "extensions": extensions,
            "alt_extension_bytes": sum(x["encoded_extension_bytes"] for x in extensions if x["oid"] in {"2.5.29.72", "2.5.29.73", "2.5.29.74"}),
            "scope": "real DER certificates and authenticated in-process TLS harness; no inferred TCP/initcwnd claim"}
