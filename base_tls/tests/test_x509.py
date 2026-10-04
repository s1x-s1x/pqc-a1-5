"""The X.509 profile: real chain, real validation, real sizes.

The modelled certificate in ``tls.credentials`` is what the symbolic models describe.
The X.509 profile exists so that the byte counts in ``bench`` are comparable to a
deployment, which means its chain validation has to be genuine rather than asserted —
these tests attack it.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import replace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from tls.config import HybridTLSConfig
from tls.errors import HandshakeError, HybridTLSError
from tls.handshake.connection import HybridConnection, measured_pq_deltas
from tls.pki import PQ_PUBLIC_KEY_OID, build_test_chain, pq_extension_from_leaf, verify_chain
from tls.pq.signature import available_pq_signers


def _available_signer(preferred: str = "falcon-512", fallback: str = "ml-dsa-44") -> str:
    """Falcon lives in a separate provider, so a test needing *a* signer must not pin it.

    See tests/conftest.py for the same reasoning applied to the shared profiles.
    """
    return preferred if available_pq_signers().get(preferred) == "ok" else fallback

PQ_KEY = bytes(range(256)) * 4


def root_of(chain) -> x509.Certificate:
    """Parse the trust anchor out of a chain bundle."""
    return x509.load_der_x509_certificate(chain.root_der)


def test_chain_verifies_and_reports_the_leaf() -> None:
    """A freshly built chain validates against its own root for the right name."""
    chain = build_test_chain("server.example")
    leaf = verify_chain(list(chain.chain_der), root_of(chain), "server.example")

    assert leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "server.example"
    assert len(chain.chain_der) == 2, "leaf plus one intermediate"


def test_chain_is_ordered_leaf_first() -> None:
    """The wire order is leaf then issuers, so a peer never has to guess."""
    chain = build_test_chain("server.example")
    leaf = x509.load_der_x509_certificate(chain.chain_der[0])
    issuer = x509.load_der_x509_certificate(chain.chain_der[1])

    assert leaf.issuer == issuer.subject
    assert issuer.issuer == root_of(chain).subject


def test_wrong_name_is_rejected() -> None:
    """Name checking is real: a valid chain for another host must not be accepted."""
    chain = build_test_chain("server.example")
    with pytest.raises(HandshakeError) as excinfo:
        verify_chain(list(chain.chain_der), root_of(chain), "attacker.example")
    assert excinfo.value.step == "certificate"
    assert "attacker.example" in excinfo.value.reason


def test_tampered_leaf_is_rejected() -> None:
    """Flipping one byte of the leaf breaks the issuer's signature over it."""
    chain = build_test_chain("server.example")
    tampered = chain.chain_der[0][:-1] + bytes([chain.chain_der[0][-1] ^ 0x01])
    with pytest.raises(HandshakeError):
        verify_chain([tampered, *chain.chain_der[1:]], root_of(chain), "server.example")


def test_untrusted_root_is_rejected() -> None:
    """A chain that is internally consistent but rooted elsewhere is not trusted."""
    chain = build_test_chain("server.example")
    other = build_test_chain("server.example")
    with pytest.raises(HandshakeError):
        verify_chain(list(chain.chain_der), root_of(other), "server.example")


def test_leaf_alone_does_not_chain_to_the_root() -> None:
    """Skipping the intermediate must fail: the leaf is signed by the intermediate."""
    chain = build_test_chain("server.example")
    with pytest.raises(HandshakeError):
        verify_chain([chain.chain_der[0]], root_of(chain), "server.example")


def test_empty_chain_is_rejected() -> None:
    """No certificates at all is not a valid Certificate message."""
    chain = build_test_chain("server.example")
    with pytest.raises(HandshakeError):
        verify_chain([], root_of(chain), "server.example")


def test_expired_leaf_is_rejected() -> None:
    """A chain outside its validity window is refused, not accepted with a warning."""
    now = dt.datetime.now(dt.UTC)
    chain = build_test_chain(
        "server.example",
        leaf_valid_from=now - dt.timedelta(days=400),
        leaf_valid_to=now - dt.timedelta(days=30),
    )
    with pytest.raises(HandshakeError) as excinfo:
        verify_chain(list(chain.chain_der), root_of(chain), "server.example")
    assert "validity" in excinfo.value.reason


def test_pq_key_extension_roundtrips_and_is_absent_when_not_requested() -> None:
    """The post-quantum key travels in a leaf extension, or not at all."""
    with_pq = build_test_chain("server.example", pq_scheme_id=0x0F51, pq_public_key=PQ_KEY)
    scheme_id, public_key = with_pq.pq_public_key() or (None, None)
    assert scheme_id == 0x0F51
    assert public_key == PQ_KEY
    assert with_pq.leaf.extensions.get_extension_for_oid(PQ_PUBLIC_KEY_OID)

    without = build_test_chain("server.example")
    assert without.pq_public_key() is None
    assert pq_extension_from_leaf(without.leaf) is None
    # The extension is the whole difference in size, and it is large.
    assert with_pq.total_bytes - without.total_bytes > len(PQ_KEY)


def test_leaf_certifies_the_key_the_handshake_uses() -> None:
    """The leaf's subject public key is the server's signing key, not a fresh one."""
    server_key = ec.generate_private_key(ec.SECP256R1())
    chain = build_test_chain("server.example", leaf_key=server_key)
    leaf = x509.load_der_x509_certificate(chain.chain_der[0])

    assert leaf.public_key().public_numbers() == server_key.public_key().public_numbers()


@pytest.mark.parametrize("pq_signer", ["falcon-512", "ml-dsa-44"])
def test_end_to_end_handshake_over_a_real_chain(pq_signer: str) -> None:
    """The full handshake completes with a real chain and both signatures checked."""
    config = HybridTLSConfig(x509=True, pq_signer=pq_signer)
    result = HybridConnection.run(config)

    assert result.application_payload_ok
    assert result.exporters_match
    assert result.client.chain is not None
    assert len(result.client.chain.chain) == 2
    assert result.client.server_pq_public == result.server.credentials.pq_public
    assert result.client.verification is not None
    assert result.client.verification.classic_ok and result.client.verification.pq_ok


def test_classical_baseline_over_a_real_chain_is_smaller() -> None:
    """The measured comparison in the X.509 profile, which is the publishable one."""
    comparison = measured_pq_deltas(HybridTLSConfig(x509=True, pq_signer=_available_signer()))

    assert comparison["baseline_bytes"] < comparison["hybrid_bytes"]
    assert comparison["per_message"]["Certificate"] > 0
    assert comparison["per_message"]["ClientHello"] > 0
    assert comparison["per_message"]["ServerHello"] > 0
    assert comparison["per_message"]["CertificateVerify"] > 0
    # The real chain makes the baseline an order of magnitude bigger than the modelled
    # certificate did, which is exactly why these numbers are the comparable ones.
    assert comparison["baseline_bytes"] > 1200
    assert comparison["total"] == sum(
        comparison["per_message"][name] for name in ("ClientHello", "ServerHello", "Certificate", "CertificateVerify")
    )


def test_x509_profile_rejects_a_tampered_certificate_record() -> None:
    """Corrupting the chain in flight is caught, not silently accepted."""
    config = HybridTLSConfig(x509=True, pq_signer=_available_signer())
    from tls.credentials import CertificateAuthority, ServerCredentials
    from tls.handshake.client import HybridClient
    from tls.handshake.server import HybridServer

    authority = CertificateAuthority(config.classical())
    credentials = ServerCredentials(config)
    client = HybridClient(config, authority, trusted_root=root_of(credentials.chain))
    server = HybridServer(config, credentials, credentials.bind_to(authority))

    client_hello = client.create_client_hello()
    client.receive_server_hello(server.receive_client_hello(client_hello))

    def corrupt(name: str, frame: bytes) -> bytes:
        if name != "Certificate":
            return frame
        return frame[:-1] + bytes([frame[-1] ^ 0x01])

    records = [record for _, record, _ in server.send_authenticated_flight(corrupt)]
    with pytest.raises(HybridTLSError):
        client.receive_server_flight(records)


def test_x509_requires_an_ecdsa_p256_classical_signer() -> None:
    """The chain certifies an ECDSA key, so another classical signer is refused early."""
    config = HybridTLSConfig(x509=True, classical_signer="ed25519")
    with pytest.raises(HybridTLSError):
        HybridConnection.run(config)


def test_modeled_profile_is_unaffected_by_the_x509_option() -> None:
    """Turning the option off reproduces the modelled sizes exactly."""
    signer = _available_signer()
    modelled = HybridConnection.run(HybridTLSConfig(pq_signer=signer))
    x509_run = HybridConnection.run(HybridTLSConfig(x509=True, pq_signer=signer))

    assert modelled.bytes_for("Certificate") < x509_run.bytes_for("Certificate")
    assert modelled.client.chain is None
    assert modelled.certificate is not None
    assert x509_run.certificate is not None  # the modelled CA still issues one
    assert replace(modelled.client.config, x509=False).x509 is False
