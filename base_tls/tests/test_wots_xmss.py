"""Tests for :mod:`tls.pq.wots_xmss`.

The file runs both under pytest::

    python -m pytest tests/test_wots_xmss.py -q

and as a plain script, which is the fallback used when pytest is not installed::

    python tests/test_wots_xmss.py

Only the standard library is required either way; there are no fixtures or
plugins, so the plain-script runner at the bottom simply calls every
module-level ``test_*`` function.

Coverage maps onto the module's stated contracts: WOTS+ size formulas and digest
conversion, WOTS+ keygen determinism, WOTS+ per-step chaining keys (as opposed to
naive iterated hashing), rejection of every single-byte signature flip, XMSS wire
layout and independent re-derivation of the Merkle fold, index monotonicity and
exhaustion, key determinism, cross-key rejection, and the height-10 time budget.
"""

from __future__ import annotations

import hashlib
import os
import sys
import time
import traceback

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_HERE)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from tls.pq.wots_xmss import (  # noqa: E402  (import after the sys.path fix-up)
    WotsPlus,
    XmssSecretKey,
    XmssSignatureBackend,
)

# Timings recorded by the performance test, printed by the plain-script runner.
MEASUREMENTS: dict[str, float] = {}

_DEFAULT_BACKEND: XmssSignatureBackend | None = None
_DEFAULT_KEYPAIR: tuple[XmssSecretKey, bytes] | None = None

PUBLIC_SEED = bytes(range(32))  # deterministic test context, never a production default

TLS_MESSAGE = b"TLS 1.3, server CertificateVerify" + b"\x00" * 64


# --------------------------------------------------------------------- helpers


def default_backend() -> XmssSignatureBackend:
    """Return the shared default-parameter backend (height 10, SHA-256, w = 16)."""
    global _DEFAULT_BACKEND
    if _DEFAULT_BACKEND is None:
        _DEFAULT_BACKEND = XmssSignatureBackend()
    return _DEFAULT_BACKEND


def default_keypair() -> tuple[XmssSecretKey, bytes]:
    """Return a shared default-parameter key pair.

    Tests may spend leaves of it, but none of them assert on absolute indices.
    """
    global _DEFAULT_KEYPAIR
    if _DEFAULT_KEYPAIR is None:
        _DEFAULT_KEYPAIR = default_backend().keygen()
    return _DEFAULT_KEYPAIR


def split_signature(
    backend: XmssSignatureBackend, signature: bytes
) -> tuple[int, bytes, bytes, bytes]:
    """Split *signature* into ``(index, wots_signature, wots_pk, auth_path)``."""
    wots_bytes = backend.wots.signature_bytes
    index = int.from_bytes(signature[:4], "big")
    wots_signature = signature[4 : 4 + wots_bytes]
    wots_pk = signature[4 + wots_bytes : 4 + 2 * wots_bytes]
    auth_path = signature[4 + 2 * wots_bytes :]
    return index, wots_signature, wots_pk, auth_path


def flip(signature: bytes, offset: int) -> bytes:
    """Return *signature* with the single byte at *offset* flipped."""
    tampered = bytearray(signature)
    tampered[offset] ^= 0x01
    return bytes(tampered)


# ----------------------------------------------------------- WOTS+ parameters


def test_wots_size_formulas() -> None:
    """len1/len2/length/signature_bytes follow the RFC 8391 formulas."""
    expected = {
        # (n, w): (len1, len2, length)
        (32, 16): (64, 3, 67),
        (32, 4): (128, 5, 133),
        (32, 256): (32, 2, 34),
        (32, 2): (256, 9, 265),
        (16, 4): (64, 4, 68),
        (24, 256): (24, 2, 26),
    }
    for (n, w), (len1, len2, length) in expected.items():
        wots = WotsPlus(n=n, w=w)
        assert wots.n == n and wots.w == w
        assert (wots.len1, wots.len2) == (len1, len2), (n, w)
        assert wots.length == length == len1 + len2, (n, w)
        assert wots.signature_bytes == length * n, (n, w)


def test_wots_constructor_rejects_invalid_parameters() -> None:
    """Out-of-range or non-power-of-two parameters raise ValueError, not assert."""
    for kwargs in (
        {"n": 0},
        {"n": -1},
        {"n": 33},  # SHA-256 cannot produce more than 32 bytes
        {"n": True},
        {"w": 1},
        {"w": 3},
        {"w": 0},
        {"hash_name": "definitely-not-a-hash"},
        {"hash_name": 7},
    ):
        try:
            WotsPlus(**kwargs)  # type: ignore[arg-type]
        except ValueError:
            continue
        raise AssertionError(f"WotsPlus{kwargs!r} should have raised ValueError")


def test_xmss_constructor_and_metadata() -> None:
    """The backend advertises the documented parameter set and wire sizes."""
    backend = default_backend()
    assert backend.name == "XMSS-SHA256-h10-w16"
    assert backend.height == 10
    assert backend.public_key_bytes == 64
    assert backend.max_signatures == 1024
    assert backend.signature_bytes == 4 + 2 * 2144 + 10 * 32 == 4612

    small = XmssSignatureBackend(height=2, n=16, w=4)
    assert small.name == "XMSS-SHA256-h2-w4"
    assert small.public_key_bytes == 32
    assert small.max_signatures == 4
    assert small.signature_bytes == 4 + 2 * (68 * 16) + 2 * 16 == 2212

    for kwargs in ({"height": 0}, {"height": -3}, {"height": 33}, {"height": True}, {"n": 33}):
        try:
            XmssSignatureBackend(**kwargs)  # type: ignore[arg-type]
        except ValueError:
            continue
        raise AssertionError(f"XmssSignatureBackend{kwargs!r} should have raised ValueError")


# ------------------------------------------------------------------- WOTS+ use


def test_wots_keygen_is_deterministic_and_separated() -> None:
    """Same (seed, address) reproduces the pair; seed and address both separate."""
    wots = WotsPlus()
    sk_a, pk_a = wots.keygen(b"seed-a", 0, public_seed=PUBLIC_SEED[:wots.n])
    sk_b, pk_b = wots.keygen(b"seed-a", 0, public_seed=PUBLIC_SEED[:wots.n])
    assert (sk_a, pk_a) == (sk_b, pk_b)
    assert len(sk_a) == len(pk_a) == wots.signature_bytes

    _, pk_other_seed = wots.keygen(b"seed-b", 0, public_seed=PUBLIC_SEED[:wots.n])
    assert pk_other_seed != pk_a
    _, pk_other_address = wots.keygen(b"seed-a", 1, public_seed=PUBLIC_SEED[:wots.n])
    assert pk_other_address != pk_a
    # A WOTS+ chain never ends where it started.
    assert pk_a != sk_a

    for kwargs in ({"seed": b""}, {"seed": "not-bytes"}, {"seed": b"s", "address": -1}, {"seed": b"s", "address": 2**32}):
        try:
            wots.keygen(**kwargs, public_seed=PUBLIC_SEED[:wots.n])  # type: ignore[arg-type]
        except (ValueError, TypeError):
            continue
        raise AssertionError(f"keygen{kwargs!r} should have raised")


def test_wots_sign_verify_roundtrip() -> None:
    """Every digest signs and verifies, including checksum extremes."""
    digests = [
        bytes(32),
        b"\xff" * 32,
        b"\x00" * 31 + b"\x01",
        bytes(range(32)),
        hashlib.sha256(b"message").digest(),
    ]
    for n, w in ((32, 16), (16, 4), (24, 256), (32, 2)):
        wots = WotsPlus(n=n, w=w)
        sk, pk = wots.keygen(b"roundtrip-seed", 7, public_seed=PUBLIC_SEED[:wots.n])
        for digest in digests:
            message_digest = digest[:n].ljust(n, b"\xa5")
            signature = wots.sign(sk, message_digest, public_seed=PUBLIC_SEED[:wots.n], address=7)
            assert len(signature) == wots.signature_bytes, (n, w)
            assert wots.verify(pk, message_digest, signature, public_seed=PUBLIC_SEED[:wots.n], address=7), (n, w, message_digest.hex())
            # A different digest must not verify under the same one-time key.
            other = bytes((message_digest[0] ^ 0x01,)) + message_digest[1:]
            assert not wots.verify(pk, other, signature, public_seed=PUBLIC_SEED[:wots.n], address=7)


def test_wots_chaining_uses_per_step_keys() -> None:
    """The chains follow the documented keyed construction, not naive iteration.

    This recomputes chain 0 of a public key from its secret with raw hashlib and
    checks both that the WOTS+ construction reproduces it and that plain
    iterated hashing (naive WOTS) does not.
    """
    wots = WotsPlus()
    sk, pk = wots.keygen(b"chaining-seed", 3, public_seed=PUBLIC_SEED[:wots.n])
    n = wots.n

    value = sk[:n]
    naive = value
    for step in range(wots.w - 1):
        # Direct RFC 8391 Algorithm 2, independent of production helpers.
        adrs = bytes(16) + (3).to_bytes(4, "big") + bytes(4) + step.to_bytes(4, "big")
        prefix = (3).to_bytes(32, "big") + PUBLIC_SEED + adrs
        step_key = hashlib.sha256(prefix + bytes(4)).digest()
        mask = hashlib.sha256(prefix + (1).to_bytes(4, "big")).digest()
        masked = bytes(a ^ b for a, b in zip(value, mask))
        value = hashlib.sha256(bytes(32) + step_key + masked).digest()
        naive = hashlib.sha256(naive).digest()
    assert value == pk[:n]
    assert naive != pk[:n]


def test_wots_rejects_flipped_signature_bytes() -> None:
    """A flipped byte anywhere in a WOTS+ signature invalidates it."""
    wots = WotsPlus()
    sk, pk = wots.keygen(b"flip-seed", 0, public_seed=PUBLIC_SEED[:wots.n])
    message_digest = hashlib.sha256(b"flip me").digest()
    signature = wots.sign(sk, message_digest, public_seed=PUBLIC_SEED[:wots.n], address=0)
    assert wots.verify(pk, message_digest, signature, public_seed=PUBLIC_SEED[:wots.n], address=0)

    offsets = set(range(0, wots.signature_bytes, 37))
    offsets.update({0, wots.signature_bytes - 1, wots.n - 1, wots.n, wots.signature_bytes // 2})
    for offset in sorted(offsets):
        assert not wots.verify(pk, message_digest, flip(signature, offset), public_seed=PUBLIC_SEED[:wots.n], address=0), offset


def test_wots_rejects_wrong_digest_and_wrong_public_key() -> None:
    """The same signature is rejected under another digest or another public key."""
    wots = WotsPlus()
    sk, pk = wots.keygen(b"wrong-seed", 0, public_seed=PUBLIC_SEED[:wots.n])
    digest = hashlib.sha256(b"right").digest()
    signature = wots.sign(sk, digest, public_seed=PUBLIC_SEED[:wots.n], address=0)

    assert wots.verify(pk, hashlib.sha256(b"wrong").digest(), signature, public_seed=PUBLIC_SEED[:wots.n], address=0) is False
    assert wots.verify(pk, flip(digest, 5), signature, public_seed=PUBLIC_SEED[:wots.n], address=0) is False
    _, other_pk = wots.keygen(b"wrong-seed", 1, public_seed=PUBLIC_SEED[:wots.n])
    assert wots.verify(other_pk, digest, signature, public_seed=PUBLIC_SEED[:wots.n], address=0) is False
    assert wots.verify(flip(pk, 0), digest, signature, public_seed=PUBLIC_SEED[:wots.n], address=0) is False


def test_wots_verify_rejects_wrong_lengths_without_raising() -> None:
    """Malformed inputs are rejected by returning False, never by an exception."""
    wots = WotsPlus()
    sk, pk = wots.keygen(b"length-seed", 0, public_seed=PUBLIC_SEED[:wots.n])
    digest = hashlib.sha256(b"lengths").digest()
    signature = wots.sign(sk, digest, public_seed=PUBLIC_SEED[:wots.n], address=0)
    assert wots.verify(pk, digest, signature, public_seed=PUBLIC_SEED[:wots.n], address=0)

    for bad_signature in (
        b"",
        signature[:-1],
        signature + b"\x00",
        signature[: wots.signature_bytes // 2],
    ):
        assert wots.verify(pk, digest, bad_signature, public_seed=PUBLIC_SEED[:wots.n], address=0) is False
    for bad_digest in (b"", digest[:-1], digest + b"\x00", bytes(33)):
        assert wots.verify(pk, bad_digest, signature, public_seed=PUBLIC_SEED[:wots.n], address=0) is False
    for bad_pk in (b"", pk[:-1], pk + b"\x00", bytes(wots.signature_bytes + 1)):
        assert wots.verify(bad_pk, digest, signature, public_seed=PUBLIC_SEED[:wots.n], address=0) is False
    for bad_input in ("str", 17, None, [1, 2, 3]):
        assert wots.verify(bad_input, digest, signature, public_seed=PUBLIC_SEED[:wots.n], address=0) is False  # type: ignore[arg-type]
        assert wots.verify(pk, bad_input, signature, public_seed=PUBLIC_SEED[:wots.n], address=0) is False  # type: ignore[arg-type]
        assert wots.verify(pk, digest, bad_input, public_seed=PUBLIC_SEED[:wots.n], address=0) is False  # type: ignore[arg-type]


def test_wots_sign_rejects_wrong_input() -> None:
    """sign() raises for a wrong-length digest/key rather than indexing past the end."""
    wots = WotsPlus()
    sk, _ = wots.keygen(b"sign-seed", 0, public_seed=PUBLIC_SEED[:wots.n])
    digest = hashlib.sha256(b"sign").digest()
    assert len(wots.sign(sk, digest, public_seed=PUBLIC_SEED[:wots.n], address=0)) == wots.signature_bytes

    for bad_digest in (b"", digest[:-1], digest + b"\x00", bytes(16)):
        try:
            wots.sign(sk, bad_digest, public_seed=PUBLIC_SEED[:wots.n], address=0)
        except ValueError:
            continue
        raise AssertionError(f"sign with a {len(bad_digest)}-byte digest should have raised")
    for bad_sk in (b"", sk[:-1], sk + b"\x00", bytes(wots.n)):
        try:
            wots.sign(bad_sk, digest, public_seed=PUBLIC_SEED[:wots.n], address=0)
        except ValueError:
            continue
        raise AssertionError(f"sign with a {len(bad_sk)}-byte sk should have raised")
    try:
        wots.sign("not-bytes", digest, public_seed=PUBLIC_SEED[:wots.n], address=0)  # type: ignore[arg-type]
    except TypeError:
        pass
    else:
        raise AssertionError("sign with a str sk should have raised TypeError")


# --------------------------------------------------------------------- XMSS


def test_xmss_roundtrip_for_several_parameter_sets() -> None:
    """Sign/verify works for every configured parameter set and message length."""
    messages = [b"", b"\x00", b"x" * 1024, TLS_MESSAGE]
    for height, n, w in ((2, 16, 4), (2, 24, 256), (3, 32, 2), (4, 32, 4), (5, 32, 16)):
        backend = XmssSignatureBackend(height=height, n=n, w=w)
        sk, root = backend.keygen()
        assert len(root) == backend.public_key_bytes == 2 * n
        for message in messages:
            signature = backend.sign(sk, message)
            assert len(signature) == backend.signature_bytes
            assert backend.verify(root, message, signature), (height, n, w, message[:8])
            assert not backend.verify(root, message + b"!", signature)
            assert not backend.verify(root, b"!" + message, signature)
        assert sk.next_index == len(messages)


def test_xmss_signature_layout_and_index_advance() -> None:
    """Two consecutive signatures carry indices i and i + 1 in the u32 field."""
    backend = XmssSignatureBackend(height=4)
    sk, root = backend.keygen()
    assert sk.next_index == 0

    first = backend.sign(sk, b"first")
    second = backend.sign(sk, b"second")
    index_a, wots_sig_a, wots_pk_a, auth_a = split_signature(backend, first)
    index_b, _, _, auth_b = split_signature(backend, second)

    assert (index_a, index_b) == (0, 1)
    assert sk.next_index == 2
    assert first[:4] == index_a.to_bytes(4, "big") == b"\x00\x00\x00\x00"
    assert second[:4] == index_b.to_bytes(4, "big") == b"\x00\x00\x00\x01"
    assert len(wots_sig_a) == len(wots_pk_a) == backend.wots.signature_bytes
    assert len(auth_a) == len(auth_b) == backend.height * backend.n
    assert wots_sig_a != wots_pk_a
    assert backend.verify(root, b"first", first)
    assert backend.verify(root, b"second", second)
    # Signatures are bound to their message and to their index.
    assert not backend.verify(root, b"second", first)
    assert first != second


def test_xmss_keygen_determinism() -> None:
    """The same seed reproduces the root and the signatures; other seeds do not."""
    backend = XmssSignatureBackend(height=4)
    sk_a, root_a = backend.keygen_from_seed(b"fixed-seed", public_seed=PUBLIC_SEED[:backend.n])
    sk_b, root_b = backend.keygen_from_seed(b"fixed-seed", public_seed=PUBLIC_SEED[:backend.n])
    assert (sk_a.seed, root_a) == (sk_b.seed, root_b)
    assert backend.sign(sk_a, b"determinism") == backend.sign(sk_b, b"determinism")

    _, root_c = backend.keygen_from_seed(b"fixed-see", public_seed=PUBLIC_SEED[:backend.n])
    _, root_d = backend.keygen_from_seed(b"fixed-seed\x00", public_seed=PUBLIC_SEED[:backend.n])
    assert root_c != root_a and root_d != root_a

    sk_random, root_random = backend.keygen()
    assert len(sk_random.seed) == backend.n and len(root_random) == 2 * backend.n
    assert root_random != root_a


def test_xmss_all_leaves_verify() -> None:
    """Every leaf index is reachable, verifiable and used exactly once."""
    backend = XmssSignatureBackend(height=4, n=16, w=4)
    sk, root = backend.keygen()
    messages = [f"leaf-{i}".encode() for i in range(backend.max_signatures)]

    signatures = [backend.sign(sk, message) for message in messages]
    indices = [int.from_bytes(signature[:4], "big") for signature in signatures]
    assert indices == list(range(backend.max_signatures))

    for index, (message, signature) in enumerate(zip(messages, signatures)):
        assert backend.verify(root, message, signature), index
        assert not backend.verify(root, b"leaf-other", signature), index
    assert sk.next_index == backend.max_signatures


def test_xmss_rejects_every_single_byte_flip() -> None:
    """Flipping any single byte of a default-parameter signature invalidates it."""
    backend = default_backend()
    sk, root = default_keypair()
    signature = backend.sign(sk, TLS_MESSAGE)
    assert backend.verify(root, TLS_MESSAGE, signature)

    for offset in range(len(signature)):
        tampered = flip(signature, offset)
        assert not backend.verify(root, TLS_MESSAGE, tampered), f"accepted flip at {offset}"


def test_xmss_rejects_altered_index_field() -> None:
    """Rewriting the index field breaks verification, including out-of-range values."""
    backend = default_backend()
    sk, root = default_keypair()
    message = b"index tampering"
    signature = backend.sign(sk, message)
    index, _, _, _ = split_signature(backend, signature)
    assert backend.verify(root, message, signature)

    for other in (0, 1, 2, 511, 1023, index ^ 1, (index + 1) % backend.max_signatures):
        if other == index:
            continue
        assert not backend.verify(root, message, other.to_bytes(4, "big") + signature[4:]), other
    for out_of_range in (backend.max_signatures, backend.max_signatures + 1, 0xFFFFFFFF):
        assert not backend.verify(
            root, message, out_of_range.to_bytes(4, "big") + signature[4:]
        ), out_of_range


def test_xmss_rejects_changed_message_and_other_key() -> None:
    """A signature verifies only under its own message and its own root."""
    backend = default_backend()
    sk, root = default_keypair()
    signature = backend.sign(sk, TLS_MESSAGE)

    assert backend.verify(root, TLS_MESSAGE, signature)
    assert not backend.verify(root, TLS_MESSAGE[:-1], signature)
    assert not backend.verify(root, TLS_MESSAGE + b"\x00", signature)
    assert not backend.verify(root, flip(TLS_MESSAGE, len(TLS_MESSAGE) - 1), signature)
    assert not backend.verify(root, b"", signature)

    _, other_root = backend.keygen()
    assert other_root != root
    assert not backend.verify(other_root, TLS_MESSAGE, signature)
    assert not backend.verify(flip(root, 0), TLS_MESSAGE, signature)
    assert not backend.verify(root[:-1], TLS_MESSAGE, signature)
    assert not backend.verify(root + b"\x00", TLS_MESSAGE, signature)


def test_xmss_rejects_wrong_length_signature_and_types() -> None:
    """Malformed signatures and non-bytes inputs are rejected, never raised on."""
    backend = default_backend()
    sk, root = default_keypair()
    signature = backend.sign(sk, TLS_MESSAGE)
    assert backend.verify(root, TLS_MESSAGE, signature)

    for bad_signature in (
        b"",
        signature[:-1],
        signature + b"\x00",
        signature[:4],
        signature[: 4 + backend.wots.signature_bytes],
    ):
        assert backend.verify(root, TLS_MESSAGE, bad_signature) is False, len(bad_signature)
    for bad_input in ("str", 17, None, object()):
        assert backend.verify(bad_input, TLS_MESSAGE, signature) is False  # type: ignore[arg-type]
        assert backend.verify(root, bad_input, signature) is False  # type: ignore[arg-type]
        assert backend.verify(root, TLS_MESSAGE, bad_input) is False  # type: ignore[arg-type]


def test_xmss_layout_matches_independent_merkle_fold() -> None:
    """The wire format folds to the root exactly as documented, recomputed here."""
    backend = default_backend()
    sk, root = default_keypair()
    message = b"independent fold check"
    signature = backend.sign(sk, message)
    n = backend.n
    index, wots_signature, wots_pk, auth_path = split_signature(backend, signature)
    assert len(auth_path) == backend.height * n

    # WOTS+ digest of the raw message, then the WOTS+ check against the carried key.
    digest = hashlib.sha256(b"\x05" + message).digest()
    assert backend.wots.verify(wots_pk, digest, wots_signature, public_seed=root[n:], address=index)

    node = hashlib.sha256(b"\x00" + wots_pk).digest()
    for level in range(backend.height):
        sibling = auth_path[level * n : (level + 1) * n]
        left, right = (sibling, node) if (index >> level) & 1 else (node, sibling)
        node = hashlib.sha256(b"\x01" + left + right).digest()
    assert node == root[:n]

    # Domain separation is load-bearing: dropping the 0x00 leaf tag and folding
    # with 0x00 instead of 0x01 for internal nodes must not reproduce the root.
    wrong = hashlib.sha256(wots_pk).digest()
    for level in range(backend.height):
        sibling = auth_path[level * n : (level + 1) * n]
        left, right = (sibling, wrong) if (index >> level) & 1 else (wrong, sibling)
        wrong = hashlib.sha256(b"\x00" + left + right).digest()
    assert wrong != root[:n]


def test_xmss_sign_exhaustion_and_no_index_reuse() -> None:
    """A key signs exactly max_signatures times and then raises ValueError."""
    backend = XmssSignatureBackend(height=2, n=16, w=4)
    sk, root = backend.keygen()
    assert backend.max_signatures == 4

    signatures = []
    for expected_index in range(backend.max_signatures):
        signature = backend.sign(sk, f"m{expected_index}".encode())
        assert int.from_bytes(signature[:4], "big") == expected_index
        assert sk.next_index == expected_index + 1
        assert backend.verify(root, f"m{expected_index}".encode(), signature)
        signatures.append(signature)
    assert len({signature[:4] for signature in signatures}) == 4

    for _ in range(2):
        try:
            backend.sign(sk, b"one too many")
        except ValueError:
            pass
        else:
            raise AssertionError("signing past max_signatures should have raised ValueError")
    assert sk.next_index == backend.max_signatures  # a refused signature spends nothing


def test_xmss_sign_without_cached_tree() -> None:
    """Both persisted seeds suffice without the cache, preserving signature bytes."""
    backend = XmssSignatureBackend(height=4)
    sk, root = backend.keygen_from_seed(b"cache-free-seed", public_seed=PUBLIC_SEED[:backend.n])
    signature_cached = backend.sign(sk, b"no cache")

    bare = XmssSecretKey(
        seed=b"cache-free-seed", public_seed=PUBLIC_SEED, height=4, n=32, w=16, hash_name="sha256", next_index=0
    )
    assert bare._levels is None
    signature_bare = backend.sign(bare, b"no cache")

    assert signature_cached == signature_bare
    assert backend.verify(root, b"no cache", signature_bare)
    assert (sk.next_index, bare.next_index) == (1, 1)


def test_xmss_sign_rejects_mismatched_key_and_bad_input() -> None:
    """A key of another parameter set, or a non-bytes message, is refused."""
    backend = XmssSignatureBackend(height=4)
    small = XmssSignatureBackend(height=2, n=16, w=4)
    other_sk, _ = small.keygen()

    try:
        backend.sign(other_sk, b"wrong key")
    except ValueError:
        pass
    else:
        raise AssertionError("signing with a mismatched secret key should have raised")

    try:
        backend.sign("not a key", b"x")  # type: ignore[arg-type]
    except TypeError:
        pass
    else:
        raise AssertionError("signing with a non-key should have raised TypeError")

    sk, _ = backend.keygen()
    for bad_message in ("str", 3.5, None):
        try:
            backend.sign(sk, bad_message)  # type: ignore[arg-type]
        except TypeError:
            continue
        raise AssertionError("signing a non-bytes message should have raised TypeError")
    assert sk.next_index == 0  # refused calls never spend a leaf

    try:
        XmssSecretKey(seed=b"", public_seed=PUBLIC_SEED, height=4, n=32, w=16, hash_name="sha256")
    except ValueError:
        pass
    else:
        raise AssertionError("an empty seed should have raised ValueError")
    try:
        XmssSecretKey(seed=b"s", public_seed=PUBLIC_SEED, height=4, n=32, w=16, hash_name="sha256", next_index=-1)
    except ValueError:
        pass
    else:
        raise AssertionError("a negative next_index should have raised ValueError")


def test_xmss_verify_accepts_bytes_like_inputs() -> None:
    """bytearray and memoryview inputs are accepted, matching the bytes result."""
    backend = XmssSignatureBackend(height=3)
    sk, root = backend.keygen()
    message = b"bytes-like"
    signature = backend.sign(sk, message)
    assert backend.verify(bytearray(root), bytearray(message), bytearray(signature))
    assert backend.verify(memoryview(root), memoryview(message), memoryview(signature))


def test_default_height_performance_budget() -> None:
    """Keygen + sign + verify at the default height stay far inside the 30 s budget."""
    backend = XmssSignatureBackend(height=10)
    started = time.perf_counter()
    sk, root = backend.keygen()
    after_keygen = time.perf_counter()
    signature = backend.sign(sk, TLS_MESSAGE)
    after_sign = time.perf_counter()
    assert backend.verify(root, TLS_MESSAGE, signature)
    after_verify = time.perf_counter()

    MEASUREMENTS["keygen_ms"] = round((after_keygen - started) * 1000, 2)
    MEASUREMENTS["sign_ms"] = round((after_sign - after_keygen) * 1000, 2)
    MEASUREMENTS["verify_ms"] = round((after_verify - after_sign) * 1000, 2)
    MEASUREMENTS["total_ms"] = round((after_verify - started) * 1000, 2)
    MEASUREMENTS["pk_bytes"] = float(len(root))
    MEASUREMENTS["signature_bytes"] = float(len(signature))

    assert len(root) == 64 and len(signature) == 4612
    assert after_verify - started < 30.0


# ------------------------------------------------------- plain-script runner


def _main() -> int:
    """Run every module-level ``test_*`` function; the fallback for no pytest."""
    tests = [
        (name, obj)
        for name, obj in sorted(globals().items())
        if name.startswith("test_") and callable(obj)
    ]
    width = max(len(name) for name, _ in tests)
    failures: list[tuple[str, str]] = []
    print(f"wots_xmss: running {len(tests)} tests (plain-script runner, no pytest)")
    for name, test in tests:
        started = time.perf_counter()
        try:
            test()
        except Exception:  # noqa: BLE001  (report every failure, keep going)
            failures.append((name, traceback.format_exc()))
            print(f"FAIL  {name:<{width}}  {round((time.perf_counter() - started) * 1000, 1):>9.1f} ms")
        else:
            print(f"ok    {name:<{width}}  {round((time.perf_counter() - started) * 1000, 1):>9.1f} ms")

    if MEASUREMENTS:
        print(
            "measured default height=10: "
            + ", ".join(f"{key}={value}" for key, value in MEASUREMENTS.items())
        )
    for name, report in failures:
        print(f"\n=== {name} ===\n{report}")
    passed = len(tests) - len(failures)
    print(f"\n{passed}/{len(tests)} tests passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_main())
