"""Negative chains are re-signed classically so they reach the alt verifier."""
import datetime as dt
import hashlib
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from tls import alt_chain
from tls.alt_chain import (ALT_SIGNATURE_ALGORITHM, ALT_SIGNATURE_VALUE,
    SUBJECT_ALT_PUBLIC_KEY_INFO, build_alt_test_chain, public_key_info, verify_alt_chain)
from tls.config import HybridTLSConfig
from tls.der import (algorithm_identifier, bit_string, bit_string_bytes, elements,
                     extension_fields, oid, pre_tbs, single, tlv)
from tls.errors import HandshakeError
from tls.pki import verify_chain
from tls.pq.signature import get_pq_signer


@pytest.fixture(scope="module")
def material():
    return build_alt_test_chain("ml-dsa-44")


def anchor(material):
    return x509.load_der_x509_certificate(material.chain.root_der)


def modify_certificate(blob, issuer_key, changes, *, resign=True):
    """Schema-guided test mutation; unrelated DER fields retain their raw bytes."""
    outer = elements(single(blob, 0x30).value)
    fields = elements(single(outer[0].encoded, 0x30).value)
    new_fields = []
    for field in fields:
        if field.tag != 0xA3:
            new_fields.append(field.encoded)
            continue
        extensions = []
        for ext in elements(single(field.value, 0x30).value):
            identifier, critical, value = extension_fields(ext.encoded)
            if identifier not in changes:
                extensions.append(ext.encoded)
                continue
            replacement = changes[identifier]
            if replacement is None:
                continue
            value = replacement(value) if callable(replacement) else replacement
            extensions.append(tlv(0x30, oid(identifier)+(tlv(1, b"\xff") if critical else b"")+tlv(4, value)))
        if extensions:
            new_fields.append(tlv(0xA3, tlv(0x30, b"".join(extensions))))
    tbs = tlv(0x30, b"".join(new_fields))
    signature = bit_string(issuer_key.sign(tbs, ec.ECDSA(hashes.SHA256()))) if resign else outer[2].encoded
    return tlv(0x30, tbs+outer[1].encoded+signature)


@pytest.mark.parametrize("strict", [False, True])
def test_valid_alt_chain_and_exact_peer_anchor(material, strict):
    for chain in [material.chain.chain_der, (*material.chain.chain_der, material.chain.root_der)]:
        result = verify_alt_chain(chain, anchor(material), "server.example",
                                  require_alt_chain=strict, expected_algorithm="ml-dsa-44")
        assert result.complete and result.checked_edges == 2
        assert result.algorithms == ("ml-dsa-44", "ml-dsa-44")


def test_wholly_absent_alt_material_is_compatibility_only(material):
    bundle = material.classical_chain
    root = x509.load_der_x509_certificate(bundle.root_der)
    result = verify_alt_chain(bundle.chain_der, root, "server.example")
    assert (result.checked_edges, result.legacy_edges, result.complete) == (0, 2, False)
    with pytest.raises(HandshakeError, match="trust anchor"):
        verify_alt_chain(bundle.chain_der, root, "server.example", require_alt_chain=True)


@pytest.mark.parametrize("changes", [
    {"2.5.29.74": None}, {"2.5.29.73": None},
    {"2.5.29.74": lambda value: bit_string(bytes([bit_string_bytes(value)[0]^1])+bit_string_bytes(value)[1:])},
    {"2.5.29.74": lambda value: bit_string(bit_string_bytes(value)[:-1])},
    {"2.5.29.73": algorithm_identifier("1.3.6.1.4.1.99999.2.3")},
    {"2.5.29.73": algorithm_identifier("1.2.3.4")},
    {"2.5.29.74": tlv(3, b"\x01\x00")},
], ids=["strip-value", "strip-algorithm", "corrupt-signature", "short-signature", "swap-oid", "unknown-oid", "unused-bits"])
@pytest.mark.parametrize("strict", [False, True])
def test_advertised_partial_or_bad_alt_material_rejected_after_classical_pass(material, changes, strict):
    leaf = modify_certificate(material.chain.leaf_der, material.intermediate_key, changes)
    chain = (leaf, material.chain.chain_der[1])
    verify_chain(chain, anchor(material), "server.example")
    with pytest.raises(HandshakeError) as error:
        verify_alt_chain(chain, anchor(material), "server.example", require_alt_chain=strict)
    assert error.value.step == "certificate_alt"


def test_own_key_only_on_peer_ca_is_partial_material(material):
    intermediate = modify_certificate(material.chain.chain_der[1], material.root_key,
                                      {"2.5.29.73": None, "2.5.29.74": None})
    chain = (material.chain.leaf_der, intermediate)
    verify_chain(chain, anchor(material), "server.example")
    with pytest.raises(HandshakeError, match="incomplete"):
        verify_alt_chain(chain, anchor(material), "server.example")


def test_entire_leaf_alt_pair_stripped_is_strict_rejection(material):
    leaf = modify_certificate(material.chain.leaf_der, material.intermediate_key,
                              {"2.5.29.73": None, "2.5.29.74": None})
    chain = (leaf, material.chain.chain_der[1])
    result = verify_alt_chain(chain, anchor(material), "server.example")
    assert (result.checked_edges, result.legacy_edges) == (1, 1)
    with pytest.raises(HandshakeError, match="absent"):
        verify_alt_chain(chain, anchor(material), "server.example", require_alt_chain=True)


def test_classical_validation_precedes_alt_parsing_and_backend(material, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("alternative signer reached before classical validation")
    leaf = modify_certificate(material.chain.leaf_der, material.intermediate_key,
                              {"2.5.29.73": algorithm_identifier("1.2.3")}, resign=False)
    monkeypatch.setattr(alt_chain, "get_alt_signer", forbidden)
    with pytest.raises(HandshakeError) as error:
        verify_alt_chain((leaf, material.chain.chain_der[1]), anchor(material), "server.example")
    assert error.value.step == "certificate"


def test_exact_local_root_alt_key_binding(material):
    """Same classical key/name/serial with a changed local PQ key fails the old path."""
    signer = get_pq_signer("ml-dsa-44")
    _, attacker_public = signer.keygen()
    replaced = modify_certificate(material.chain.root_der, material.root_key,
                                   {"2.5.29.72": public_key_info("ml-dsa-44", attacker_public)})
    local_replaced = x509.load_der_x509_certificate(replaced)
    verify_chain(material.chain.chain_der, local_replaced, "server.example")
    with pytest.raises(HandshakeError, match="verification failed"):
        verify_alt_chain(material.chain.chain_der, local_replaced, "server.example", require_alt_chain=True)
    # A peer sends a root with the same classical fields and new PQ key. It does
    # not replace the separately supplied anchor, even though ECDSA still passes.
    with pytest.raises(HandshakeError):
        verify_alt_chain((*material.chain.chain_der, replaced), anchor(material), "server.example", require_alt_chain=True)


def test_profile_algorithm_and_spki_parameters_fail_closed(material):
    with pytest.raises(HandshakeError, match="configured algorithm"):
        verify_alt_chain(material.chain.chain_der, anchor(material), "server.example",
                          expected_algorithm="slh-dsa-sm3-128-24")
    bad_key = tlv(0x30, tlv(0x30, oid(alt_chain.ALGORITHM_OIDS["ml-dsa-44"])+tlv(5, b""))+bit_string(b"key"))
    intermediate = modify_certificate(material.chain.chain_der[1], material.root_key, {"2.5.29.72": bad_key})
    with pytest.raises(HandshakeError, match="parameters"):
        verify_alt_chain((material.chain.leaf_der, intermediate), anchor(material), "server.example")


def test_budget_callback_runs_before_sign_and_failure_stops_signing(monkeypatch):
    signer = get_pq_signer("ml-dsa-44")
    secret, public = signer.keygen()
    classical = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    order = []
    def reserve(name, key, message):
        order.append("reserve")
        assert name == "ml-dsa-44" and key == public and message
        raise RuntimeError("budget exhausted")
    monkeypatch.setattr(signer, "sign", lambda *args: order.append("sign"))
    with pytest.raises(RuntimeError, match="budget exhausted"):
        alt_chain.issue_alt_certificate(name="ml-dsa-44", signer=signer, secret_key=secret,
            issuer_public_key=public, before_sign=reserve, after_sign=lambda *args: None, subject="test",
            issuer=alt_chain._name("test"), subject_key=classical.public_key(), issuer_key=classical,
            ca=True, path_length=0, serial=10, valid_from=now-dt.timedelta(days=1), valid_to=now+dt.timedelta(days=1))
    assert order == ["reserve"]


def test_fixed_serial_two_pass_pre_tbs_identity_and_records(material):
    for index, label in [(0, "leaf"), (1, "intermediate")]:
        cert = x509.load_der_x509_certificate(material.chain.chain_der[index])
        stripped = modify_certificate(material.chain.chain_der[index],
            material.intermediate_key if index == 0 else material.root_key, {"2.5.29.74": None})
        assert pre_tbs(cert.tbs_certificate_bytes) == pre_tbs(x509.load_der_x509_certificate(stripped).tbs_certificate_bytes)
        assert cert.serial_number == (3 if label == "leaf" else 2)
    assert len(material.signing_records) == 2


@pytest.fixture(scope="module")
def fixture_bundle(tmp_path_factory):
    """Cheap ML-DSA fixture exercises the real loader and the handshake path."""
    directory = tmp_path_factory.mktemp("alt-chain")
    handshake = get_pq_signer("ml-dsa-44")
    secret, public = handshake.keygen()
    material = build_alt_test_chain("ml-dsa-44", pq_scheme_id=handshake.scheme_id, pq_public_key=public)
    files, chains = {}, {}
    for kind, chain, prefix in [("alt", material.chain, ""), ("hybrid", material.baseline_chain, "hybrid-"),
                                ("classical", material.classical_chain, "classical-")]:
        chains[kind] = {}
        for label, data in [("root", chain.root_der), ("leaf", chain.leaf_der), ("intermediate", chain.chain_der[1])]:
            filename = prefix+label+".der"
            files[filename], chains[kind][label] = data, filename
    files["leaf-test-key.pem"] = material.leaf_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    files["handshake-test-key.json"] = json.dumps({"test_only": True, "algorithm": handshake.name,
        "secret_key": secret.hex(), "public_key": public.hex()}).encode()
    for name, data in files.items():
        (directory/name).write_bytes(data)
    metadata = {"schema": "a15-alt-fixture-v1", "test_only": True, "alt_algorithm": "ml-dsa-44",
        "handshake_signer": handshake.name, "chains": chains,
        "files_sha256": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
    (directory/"fixture.json").write_text(json.dumps(metadata))
    return directory


@pytest.mark.parametrize("kind", ["classical", "hybrid", "alt"])
def test_real_fixture_handshake_and_e1(fixture_bundle, kind):
    from tls.alt_profiles import e1_record
    config = HybridTLSConfig(x509=True, pq_enabled=kind != "classical", pq_signer="ml-dsa-44",
        alt_fixture=str(fixture_bundle), alt_chain="ml-dsa-44" if kind == "alt" else None,
        require_alt_chain=kind == "alt")
    record = e1_record("test-"+kind, config)
    assert record["passed"] and record["server_flight_bytes"] > 0
    assert record["handshake_bytes"] == sum(x["wire_bytes"] for x in record["per_message"])
    assert (record["alt_extension_bytes"] > 0) == (kind == "alt")


def test_fixture_hash_and_key_binding_reject_tampering(fixture_bundle, tmp_path):
    import shutil
    from tls.alt_fixtures import load_fixture
    clone = tmp_path/"bundle"
    shutil.copytree(fixture_bundle, clone)
    blob = (clone/"leaf.der").read_bytes()
    (clone/"leaf.der").write_bytes(blob[:-1]+bytes([blob[-1]^1]))
    with pytest.raises(ValueError, match="hash differs"):
        load_fixture(clone, pq_signer=get_pq_signer("ml-dsa-44"))
