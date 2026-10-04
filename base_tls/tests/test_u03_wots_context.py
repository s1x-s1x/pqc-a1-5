"""U-03 regressions: RFC chain oracle, public context isolation and migration.

The oracle below uses only hashlib/struct, not production address, PRF, chain,
or checksum helpers. It implements RFC 8391 sections 2.5, 3.1.2 and 5.1 for
SHA-256/n=32. These are local reference checks, not official XMSS test vectors.
"""

import hashlib
import json
import struct
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from tls.config import HybridTLSConfig
from tls.handshake.connection import HybridConnection
from tls.pq.signature import Xmss
from tls.pq.wots_xmss import WotsPlus, XmssSecretKey, XmssSignatureBackend


SEED_A = bytes(range(32))
SEED_B = bytes(reversed(range(32)))


def reference_material(seed, leaf, chain, step):
    values = []
    for role in (0, 1):
        address = struct.pack(">8I", 0, 0, 0, 0, leaf, chain, step, role)
        values.append(hashlib.sha256(bytes(31) + b"\x03" + seed + address).digest())
    return tuple(values)


def reference_chain(value, seed, leaf, chain, start, steps):
    for step in range(start, start + steps):
        key, mask = reference_material(seed, leaf, chain, step)
        value = hashlib.sha256(bytes(32) + key + bytes(x ^ y for x, y in zip(value, mask))).digest()
    return value


@pytest.mark.parametrize("leaf,chain,start,steps", [
    (0, 0, 0, 15), (1, 0, 0, 15), (0xFFFFFFFF, 66, 7, 8),
    (0x12345678, 17, 3, 9), (2, 66, 14, 1), (4, 11, 15, 0),
])
@pytest.mark.parametrize("public_seed", [SEED_A, SEED_B])
def test_rfc_chain_matches_independent_reference(leaf, chain, start, steps, public_seed):
    wots = WotsPlus()
    value = hashlib.sha256(b"independent input").digest()
    expected = reference_chain(value, public_seed, leaf, chain, start, steps)
    assert wots._chain(value, chain, start, steps, public_seed=public_seed, address=leaf) == expected


def test_step_keys_and_masks_separate_tree_leaf_chain_step_and_role():
    wots = WotsPlus()
    contexts = [(SEED_A, 0, 0, 0), (SEED_B, 0, 0, 0), (SEED_A, 1, 0, 0),
                (SEED_A, 0, 1, 0), (SEED_A, 0, 0, 1)]
    outputs = []
    for context in contexts:
        material = wots._step_material(*context)
        assert material == reference_material(*context)
        outputs.extend(material)
    assert len(set(outputs)) == 10
    assert wots._step_material(*contexts[0]) == WotsPlus()._step_material(*contexts[0])


def test_full_wots_sign_and_verify_against_reference():
    # Independent chain secrets, with no call to production key generation.
    secrets = [hashlib.sha256(b"reference-secret" + bytes([i])).digest() for i in range(67)]
    digest = hashlib.sha256(b"reference message").digest()
    digits = [v for byte in digest for v in (byte >> 4, byte & 15)]
    checksum = sum(15 - d for d in digits)
    digits += [(checksum >> shift) & 15 for shift in (8, 4, 0)]
    leaf = 13
    expected_pk = b"".join(reference_chain(s, SEED_A, leaf, i, 0, 15) for i, s in enumerate(secrets))
    expected_sig = b"".join(reference_chain(s, SEED_A, leaf, i, 0, d)
                            for i, (s, d) in enumerate(zip(secrets, digits)))
    wots = WotsPlus()
    actual = wots.sign(b"".join(secrets), digest, public_seed=SEED_A, address=leaf)
    assert actual == expected_sig
    assert WotsPlus().verify(expected_pk, digest, expected_sig, public_seed=SEED_A, address=leaf)
    assert not wots.verify(expected_pk, digest, expected_sig, public_seed=SEED_B, address=leaf)
    assert not wots.verify(expected_pk, digest, expected_sig, public_seed=SEED_A, address=leaf + 1)


def test_keygen_uses_independent_random_draws(monkeypatch):
    draws = iter([b"s" * 32, SEED_A, b"t" * 32, SEED_B])
    sizes = []

    def random_bytes(n):
        sizes.append(n)
        return next(draws)

    monkeypatch.setattr("tls.pq.wots_xmss.os.urandom", random_bytes)
    backend = XmssSignatureBackend(height=1)
    sk_a, pk_a = backend.keygen()
    sk_b, pk_b = backend.keygen()
    assert sizes == [32, 32, 32, 32]
    assert (sk_a.seed, sk_a.public_seed, pk_a[32:]) == (b"s" * 32, SEED_A, SEED_A)
    assert (sk_b.seed, sk_b.public_seed, pk_b[32:]) == (b"t" * 32, SEED_B, SEED_B)
    assert pk_a[:32] != pk_b[:32]


def test_public_seed_changes_root_and_signature_even_with_same_secret():
    backend = XmssSignatureBackend(height=2)
    sk_a, pk_a = backend.keygen_from_seed(b"same secret", public_seed=SEED_A)
    sk_b, pk_b = backend.keygen_from_seed(b"same secret", public_seed=SEED_B)
    sig_a = backend.sign(sk_a, b"message")
    sig_b = backend.sign(sk_b, b"message")
    assert pk_a[:32] != pk_b[:32] and sig_a != sig_b
    verifier = XmssSignatureBackend(height=2)
    assert verifier.verify(pk_a, b"message", sig_a)
    assert not verifier.verify(pk_b, b"message", sig_a)
    assert not verifier.verify(pk_a[:32] + SEED_B, b"message", sig_a)
    assert not verifier.verify((1).to_bytes(32, "big") + pk_a[32:], b"message", sig_a)
    assert not verifier.verify(pk_a, b"message", (1).to_bytes(4, "big") + sig_a[4:])


def test_verification_in_fresh_process_needs_only_public_data():
    backend = XmssSignatureBackend(height=2)
    sk, pk = backend.keygen()
    signature = backend.sign(sk, b"fresh process")
    payload = json.dumps({"pk": pk.hex(), "signature": signature.hex()})
    code = """import json, sys
from tls.pq.wots_xmss import XmssSignatureBackend
d = json.load(sys.stdin)
assert XmssSignatureBackend(height=2).verify(bytes.fromhex(d['pk']), b'fresh process', bytes.fromhex(d['signature']))
"""
    result = subprocess.run([sys.executable, "-c", code], input=payload, text=True,
                            cwd=Path(__file__).resolve().parents[1], capture_output=True)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("public_seed,address", [
    (b"", 0), (bytes(31), 0), (bytes(33), 0), (None, 0), ("str", 0),
    (SEED_A, -1), (SEED_A, 2**32), (SEED_A, True), (SEED_A, "0"),
])
def test_malformed_context_is_rejected(public_seed, address):
    wots = WotsPlus()
    with pytest.raises((ValueError, TypeError)):
        wots.keygen(b"secret", address, public_seed=public_seed)
    with pytest.raises((ValueError, TypeError)):
        wots.sign(bytes(wots.signature_bytes), bytes(32), public_seed=public_seed, address=address)
    assert not wots.verify(bytes(wots.signature_bytes), bytes(32), bytes(wots.signature_bytes),
                           public_seed=public_seed, address=address)


def test_missing_public_seed_cannot_fall_back_to_legacy_context():
    with pytest.raises(TypeError):
        WotsPlus().keygen(b"secret", 0)
    with pytest.raises(TypeError):
        XmssSignatureBackend(height=1).keygen_from_seed(b"secret")
    with pytest.raises(TypeError):
        XmssSecretKey(seed=b"secret", height=1, n=32, w=16, hash_name="sha256")


def test_legacy_v1_keys_and_signatures_fail_closed():
    fixture = json.loads((Path(__file__).parent / "vectors/u03_legacy_v1.json").read_text())
    pk, message, signature = [bytes.fromhex(fixture[k]) for k in ("public_key", "message", "signature")]
    backend = XmssSignatureBackend(height=2)
    assert not backend.verify(pk, message, signature)
    assert not backend.verify(pk + SEED_A, message, signature)
    assert Xmss(height=2).scheme_id == 0xFE02
    assert Xmss(height=2).scheme_id != 0x0E02
    assert len(signature) == backend.signature_bytes == 4356
    assert backend.public_key_bytes == 64


def test_shared_backend_concurrent_keys_keep_their_contexts():
    backend = XmssSignatureBackend(height=2)
    pairs = [backend.keygen_from_seed(bytes([i]), public_seed=bytes([i + 1]) * 32) for i in range(4)]
    work = [(sk, pk, bytes([i, j])) for i, (sk, pk) in enumerate(pairs) for j in range(4)]

    def sign_and_verify(item):
        sk, pk, message = item
        signature = backend.sign(sk, message)
        assert backend.verify(pk, message, signature)
        return pk, int.from_bytes(signature[:4], "big")

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(sign_and_verify, work))
    for _, pk in pairs:
        assert sorted(index for key, index in results if key == pk) == [0, 1, 2, 3]


@pytest.mark.parametrize("x509", [False, True])
def test_hybrid_handshake_authenticates_seed_bearing_public_key(x509):
    config = HybridTLSConfig(pq_signer="xmss", xmss_height=2, x509=x509)
    result = HybridConnection.run(config)
    assert result.application_payload_ok and result.exporters_match
    assert result.client.verification.classic_ok and result.client.verification.pq_ok
    assert result.client.server_pq_public == result.server.credentials.pq_public
    assert len(result.client.server_pq_public) == 64
    assert result.client.server_pq_public[32:] == result.server.credentials.pq_secret.public_seed
