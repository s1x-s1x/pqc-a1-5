"""Load immutable test certificates and leaf keys; runtime never signs 128-24 CAs."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .alt_chain import verify_alt_chain
from .errors import BackendUnavailableError
from .pki import CertificateChain, pq_extension_from_leaf, verify_chain


def load_fixture(directory, *, chain_kind="alt", identity="server.example",
                 pq_signer=None, expected_algorithm=None):
    directory = Path(directory).resolve()
    metadata_path = directory / "fixture.json"
    if not metadata_path.is_file():
        raise BackendUnavailableError(f"offline CA fixture is missing: {metadata_path}")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if metadata.get("schema") != "a15-alt-fixture-v1" or metadata.get("test_only") is not True:
        raise ValueError("unrecognised test fixture schema")
    def read(name):
        if name not in metadata["files_sha256"]:
            raise ValueError("fixture file lacks manifest hash")
        path = (directory / name).resolve()
        if not path.is_relative_to(directory):
            raise ValueError("fixture path leaves bundle directory")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != metadata["files_sha256"][name]:
            raise ValueError("fixture file hash differs from manifest")
        return data
    profile = metadata["chains"][chain_kind]
    root_der, leaf_der, intermediate_der = (read(profile[x]) for x in ("root", "leaf", "intermediate"))
    root = x509.load_der_x509_certificate(root_der)
    chain = CertificateChain((leaf_der, intermediate_der), root_der, root.public_key(), leaf_der)
    if chain_kind == "alt":
        verify_alt_chain(chain.chain_der, root, identity, require_alt_chain=True,
                         expected_algorithm=expected_algorithm or metadata["alt_algorithm"])
    else:
        verify_chain(chain.chain_der, root, identity)
    classical_secret = serialization.load_pem_private_key(read("leaf-test-key.pem"), password=None)
    spki = lambda key: key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if spki(classical_secret.public_key()) != spki(chain.leaf.public_key()):
        raise ValueError("test leaf private key differs from certificate SPKI")
    if pq_signer is None:
        if pq_extension_from_leaf(chain.leaf) is not None:
            raise ValueError("classical fixture carries an unsolicited PQ handshake key")
        return chain, classical_secret, None, None
    key_metadata = json.loads(read("handshake-test-key.json"))
    secret = bytes.fromhex(key_metadata["secret_key"])
    public = bytes.fromhex(key_metadata["public_key"])
    if key_metadata["algorithm"] != pq_signer.name or pq_extension_from_leaf(chain.leaf) != (pq_signer.scheme_id, public):
        raise ValueError("fixture PQ handshake key or algorithm differs from configuration")
    return chain, classical_secret, secret, public
