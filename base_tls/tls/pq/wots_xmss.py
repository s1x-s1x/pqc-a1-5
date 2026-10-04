"""WOTS+ one-time signatures and a stateful XMSS (Merkle-tree) signature backend.

This module is the post-quantum signature backend of the hybrid TLS 1.3
handshake implemented in this repository: the classical signature over the
TLS 1.3 ``CertificateVerify`` input is kept, and a post-quantum signature over
the *same* input is added next to it.

A WOTS+ key pair can sign at most one digest, so many WOTS+ public keys are
organised as the leaves of a Merkle tree.  The certificate binds only the tree
root and a fresh public seed. Every handshake spends exactly one leaf, so the
wire signature has to be self-contained::

    index:u32 || wots_signature || wots_public_key || auth_path

``index`` selects the spent leaf, ``auth_path`` holds one sibling per level
ordered from the leaf level upwards, and ``wots_public_key`` is carried so that
a verifier never needs per-leaf state.

The prototype's Merkle and secret/message hashes use these domains::

    0x00  Merkle leaf         H(0x00 || wots_pk)
    0x01  Merkle tree node    H(0x01 || left || right)
    0x03  WOTS+ chain secret  H(0x03 || key_seed || address || chain_index)
    0x05  message digest      H(0x05 || message)

WOTS+ chaining uses RFC 8391 sections 2.5, 3.1.2 and 5.1: a 32-byte
single-tree OTS address binds the leaf, chain, absolute step and key/mask role.
For the default SHA-256/n=32 configuration::

    KEY = SHA256(toByte(3, 32) || public_seed || ADRS[keyAndMask=0])
    BM  = SHA256(toByte(3, 32) || public_seed || ADRS[keyAndMask=1])
    F   = SHA256(toByte(0, 32) || KEY || (value XOR BM))

The seed is public, independently sampled at key generation, and authenticated
as part of the public key ``root || public_seed``. It is never a source-code
constant or the secret chain seed. All WOTS+ operations require this context
explicitly; no per-instance context cache is shared between keys or leaves.

Simplifications relative to RFC 8391 ("XMSS: eXtended Merkle Signature
Scheme").  This is a research prototype: the byte strings produced here are
**not** interoperable with RFC 8391.

* **SHA-256 only.**  ``hash_name`` accepts any :mod:`hashlib` digest, and ``n``
  may be any length up to that digest's output size, but the intended and
  tested configuration is SHA-256 with ``n = 32``.  The RFC 8391 variants
  ``SHA2-256/192`` (``n = 24``) and the SHAKE-based parameter sets are not
  implemented.
* **Partial ADRS coverage.**  WOTS+ chain keys and bitmasks use the RFC address;
  secret generation and the prototype Merkle hashes retain their own domains.
* **No OID.**  The XMSS public key is ``root || public_seed`` (``2*n`` bytes);
  RFC 8391 additionally prepends a parameter-set OID. Parameters
  (``height``, ``n``, ``w``, ``hash_name``) must therefore be agreed out of band
  by both peers.
* **No randomized tree hashing.**  RFC 8391 keys its leaf and
  internal-node hashes with the public SEED; here they are deterministic,
  unkeyed hashes distinguished only by the ``0x00``/``0x01`` prefixes.
* **WOTS+ public key on the wire.**  RFC 8391 derives the WOTS+ public key from
  the signature and never transmits it; this layout carries it (``length * n``
  extra bytes) because the surrounding TLS integration requires a
  self-contained signature.  :meth:`XmssSignatureBackend.verify` still
  recomputes it from the chains and compares, so the transmitted copy is
  authenticated rather than trusted.
* **State handling.**  As in RFC 8391, signing is stateful: the caller owns
  :class:`XmssSecretKey` and must persist ``next_index`` atomically.  This
  module never stores state globally, and it does *not* protect against
  restoring a stale key state; reusing a leaf index destroys the security of the
  one-time scheme.
* **No hypertree.**  This is single-tree XMSS (``XMSS``), not ``XMSS^MT``, and
  there is no BDS-style tree traversal: the Merkle tree is built once in
  :meth:`XmssSignatureBackend.keygen` and held in the secret key as a cache.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Final

__all__ = ["WotsPlus", "XmssSecretKey", "XmssSignatureBackend"]

#: Guards the read-reserve-write of ``XmssSecretKey.next_index``.
#:
#: A WOTS+ leaf may sign exactly one message, so two signers handed the same index break
#: the scheme's only assumption. ``sign()`` used to read ``next_index`` at the top and
#: write it back at the bottom, with the whole WOTS+ derivation in between — a window a
#: second thread can walk straight into. An independent audit found it. The lock is held
#: only for the allocation, never for the hashing, so concurrent signing still runs in
#: parallel; a global lock is enough because allocating an index is O(1) and this is a
#: research prototype, not a signing service.
_INDEX_LOCK = threading.Lock()

_DOM_LEAF: Final[bytes] = b"\x00"
_DOM_NODE: Final[bytes] = b"\x01"
_DOM_CHAIN_SECRET: Final[bytes] = b"\x03"
_DOM_MESSAGE: Final[bytes] = b"\x05"

_INDEX_BYTES: Final[int] = 4
_MAX_U32: Final[int] = 0xFFFF_FFFF


def _coerce_bytes(value: object, name: str) -> bytes:
    """Return *value* as :class:`bytes`, or raise :class:`TypeError`.

    Byte-oriented inputs accept ``bytes``, ``bytearray`` and ``memoryview`` so
    that callers may pass a slice of a larger TLS buffer without copying first.
    """
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    raise TypeError(f"{name} must be bytes-like, got {type(value).__name__}")


def _check_uint(value: object, name: str, maximum: int) -> int:
    """Return *value* as an int in ``0..maximum``, or raise :class:`ValueError`."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer, got {type(value).__name__}")
    if not 0 <= value <= maximum:
        raise ValueError(f"{name} must be in 0..{maximum}, got {value}")
    return value


def _resolve_hash(hash_name: str) -> tuple[Callable[[bytes], Any], int]:
    """Return ``(constructor, digest_size)`` for *hash_name*, or raise ValueError.

    The constructor is looked up as a concrete :mod:`hashlib` attribute when
    possible: the WOTS+ chaining function performs millions of single-block
    hashes and ``hashlib.new`` would add avoidable lookup overhead per call.
    """
    if not isinstance(hash_name, str):
        raise ValueError(f"hash_name must be a string, got {type(hash_name).__name__}")
    try:
        digest_size = hashlib.new(hash_name).digest_size
    except (ValueError, TypeError) as exc:
        raise ValueError(f"unsupported hash_name {hash_name!r}") from exc
    ctor = getattr(hashlib, hash_name.replace("-", "_"), None)
    if not callable(ctor):
        ctor = lambda data=b"": hashlib.new(hash_name, data)  # noqa: E731
    return ctor, digest_size


class WotsPlus:
    """WOTS+ one-time signature over ``n``-byte hash outputs with Winternitz parameter ``w``.

    Contract:

    * ``w`` is a power of two, ``w >= 2``; ``1 <= n <= digest_size`` of
      ``hash_name``.  Anything else raises :class:`ValueError` from the
      constructor.
    * ``length == len1 + len2`` chains of ``n`` bytes, ``len1 = ceil(8n / lg w)``
      message digits and ``len2`` checksum digits (RFC 8391 formulas).
    * :meth:`keygen`, :meth:`sign` always return exactly ``signature_bytes``
      bytes; :meth:`verify` accepts only that length.
    * :meth:`sign` and :meth:`verify` take an ``n``-byte *digest*.  Callers
      holding a raw message must hash it first (:class:`XmssSignatureBackend`
      does).
    * All operations require an ``n``-byte ``public_seed``; signing and
      verification also require the same leaf ``address`` used for keygen.
    * One key pair signs at most one digest.  This class does not enforce that;
      the XMSS layer does, through its leaf index.
    * :meth:`verify` signals rejection by returning ``False``; it never raises
      for malformed input.
    """

    def __init__(self, n: int = 32, w: int = 16, hash_name: str = "sha256") -> None:
        ctor, digest_size = _resolve_hash(hash_name)
        if isinstance(n, bool) or not isinstance(n, int) or n < 1:
            raise ValueError(f"n must be a positive integer, got {n!r}")
        if n > digest_size:
            raise ValueError(
                f"n={n} exceeds the {digest_size}-byte output of {hash_name!r}; "
                "use a longer hash or a smaller n"
            )
        if isinstance(w, bool) or not isinstance(w, int) or w < 2 or (w & (w - 1)):
            raise ValueError(f"w must be a power of two >= 2, got {w!r}")

        self.n: int = n
        self.w: int = w
        self.hash_name: str = hash_name

        self._ctor = ctor
        self._digest_size = digest_size
        self._lg_w: int = w.bit_length() - 1
        # len1 = ceil(8n / lg w); lg w divides 8, hence 8n, so this is exact.
        self._len1: int = -(-8 * n // self._lg_w)
        # len2 = floor(log2(len1 * (w - 1)) / lg w) + 1, in exact integer math.
        self._len2: int = ((self._len1 * (w - 1)).bit_length() - 1) // self._lg_w + 1
        self._length: int = self._len1 + self._len2
        self._prf_domain = (3).to_bytes(n, "big")
        self._f_domain = bytes(n)

    # ------------------------------------------------------------------ sizes

    @property
    def length(self) -> int:
        """Number of WOTS+ chains, ``len1 + len2``."""
        return self._length

    @property
    def signature_bytes(self) -> int:
        """Size of a WOTS+ signature or public key in bytes, ``length * n``."""
        return self._length * self.n

    @property
    def len1(self) -> int:
        """Number of base-``w`` digits taken from the message digest."""
        return self._len1

    @property
    def len2(self) -> int:
        """Number of base-``w`` digits taken from the checksum."""
        return self._len2

    # -------------------------------------------------------------- internals

    def _check_context(self, public_seed: bytes, address: int) -> bytes:
        """Validate public verification context; never substitute a fixed seed."""
        public_seed = _coerce_bytes(public_seed, "public_seed")
        if len(public_seed) != self.n:
            raise ValueError(f"public_seed must be {self.n} bytes")
        _check_uint(address, "address", _MAX_U32)
        return public_seed

    def _step_material(
        self, public_seed: bytes, address: int, chain_index: int, step: int
    ) -> tuple[bytes, bytes]:
        """RFC 8391 KEY and BM for an already validated single-tree context."""
        # layer:u32=0, tree:u64=0, type:u32=0, OTS, chain, hash, keyAndMask.
        adrs = (
            bytes(16) + address.to_bytes(4, "big")
            + chain_index.to_bytes(4, "big") + step.to_bytes(4, "big")
        )
        prefix = self._prf_domain + public_seed + adrs
        key = self._ctor(prefix + bytes(4)).digest()[:self.n]
        mask = self._ctor(prefix + b"\x00\x00\x00\x01").digest()[:self.n]
        return key, mask

    def _chain(
        self, value: bytes, chain_index: int, start: int, steps: int,
        *, public_seed: bytes, address: int,
    ) -> bytes:
        """RFC 8391 chain, with a different key AND bitmask at each address."""
        if start < 0 or steps < 0 or start + steps > self.w - 1:
            raise ValueError("chain range exceeds w - 1")
        ctor = self._ctor
        n = self.n
        for step in range(start, start + steps):
            key, mask = self._step_material(public_seed, address, chain_index, step)
            masked = (int.from_bytes(value, "big") ^ int.from_bytes(mask, "big")).to_bytes(n, "big")
            value = ctor(self._f_domain + key + masked).digest()[:n]
        return value

    def _base_w(self, data: bytes, out_len: int) -> list[int]:
        """Convert *data* to *out_len* base-``w`` digits, most significant first.

        Requires ``out_len * lg w <= 8 * len(data)``, which both call sites
        satisfy by construction.
        """
        lg_w = self._lg_w
        mask = self.w - 1
        digits: list[int] = []
        total = 0
        bits = 0
        index = 0
        for _ in range(out_len):
            if bits == 0:
                total = data[index]
                index += 1
                bits = 8
            bits -= lg_w
            digits.append((total >> bits) & mask)
        return digits

    def _digits(self, message_digest: bytes) -> list[int]:
        """Return the ``length`` base-``w`` digits of *message_digest*.

        Layout is ``len1`` message digits followed by ``len2`` checksum digits,
        where the checksum is ``sum(w - 1 - digit)`` over the message digits,
        left-shifted so that it occupies exactly ``len2`` digits (RFC 8391).
        """
        digits = self._base_w(message_digest, self._len1)
        checksum = 0
        for digit in digits:
            checksum += self.w - 1 - digit
        shift = (8 - ((self._len2 * self._lg_w) % 8)) % 8
        checksum_bytes = (checksum << shift).to_bytes(-(-(self._len2 * self._lg_w) // 8), "big")
        digits.extend(self._base_w(checksum_bytes, self._len2))
        return digits

    # ------------------------------------------------------------- public API

    def keygen(self, seed: bytes, address: int, *, public_seed: bytes) -> tuple[bytes, bytes]:
        """Derive the WOTS+ key pair of leaf *address* deterministically from *seed*.

        Returns ``(sk_seed_material, pk)``, both exactly :attr:`signature_bytes`
        bytes: the former is the concatenation of the ``length`` chain secrets,
        the latter the concatenation of the ``length`` chain endpoints.

        * ``seed`` must be non-empty bytes-like; ``address`` an integer in
          ``0..2**32 - 1`` (the XMSS leaf index, used for domain separation).
        * ``public_seed`` must be an independently generated ``n``-byte public
          seed, shared with the verifier. The full context determines the pair.
        """
        seed = _coerce_bytes(seed, "seed")
        if not seed:
            raise ValueError("seed must be non-empty")
        public_seed = self._check_context(public_seed, address)

        address_bytes = address.to_bytes(4, "big")
        ctor = self._ctor
        n = self.n
        sk = bytearray()
        pk = bytearray()
        for chain_index in range(self._length):
            chain_secret = ctor(
                _DOM_CHAIN_SECRET + seed + address_bytes + chain_index.to_bytes(4, "big")
            ).digest()[:n]
            sk += chain_secret
            pk += self._chain(
                chain_secret, chain_index, 0, self.w - 1,
                public_seed=public_seed, address=address,
            )
        return bytes(sk), bytes(pk)

    def sign(self, sk: bytes, message_digest: bytes, *, public_seed: bytes, address: int) -> bytes:
        """Sign an ``n``-byte *message_digest* with the chain secrets *sk*.

        Returns exactly :attr:`signature_bytes` bytes.  Raises
        :class:`ValueError` if ``sk`` is not :attr:`signature_bytes` bytes or
        ``message_digest`` is not ``n`` bytes, and :class:`TypeError` for
        non-bytes-like input.
        """
        sk = _coerce_bytes(sk, "sk")
        public_seed = self._check_context(public_seed, address)
        message_digest = _coerce_bytes(message_digest, "message_digest")
        if len(sk) != self.signature_bytes:
            raise ValueError(
                f"sk must be {self.signature_bytes} bytes, got {len(sk)}"
            )
        if len(message_digest) != self.n:
            raise ValueError(
                f"message_digest must be {self.n} bytes, got {len(message_digest)}"
            )

        digits = self._digits(message_digest)
        n = self.n
        signature = bytearray()
        for chain_index, digit in enumerate(digits):
            secret = sk[chain_index * n : (chain_index + 1) * n]
            signature += self._chain(
                secret, chain_index, 0, digit, public_seed=public_seed, address=address,
            )
        return bytes(signature)

    def verify(
        self, pk: bytes, message_digest: bytes, signature: bytes,
        *, public_seed: bytes, address: int,
    ) -> bool:
        """Return whether *signature* is a valid WOTS+ signature of *message_digest* under *pk*.

        Returns ``False`` -- never raises -- for a signature or public key that
        is not :attr:`signature_bytes` bytes, a digest that is not ``n`` bytes,
        or non-bytes-like input.  All chains are recomputed before the result is
        returned, so the check does not short-circuit on the first mismatch.
        """
        try:
            public_seed = self._check_context(public_seed, address)
            pk = _coerce_bytes(pk, "pk")
            signature = _coerce_bytes(signature, "signature")
            message_digest = _coerce_bytes(message_digest, "message_digest")
        except (TypeError, ValueError):
            return False
        if len(pk) != self.signature_bytes or len(signature) != self.signature_bytes:
            return False
        if len(message_digest) != self.n:
            return False

        digits = self._digits(message_digest)
        n = self.n
        valid = True
        for chain_index, digit in enumerate(digits):
            candidate = self._chain(
                signature[chain_index * n : (chain_index + 1) * n],
                chain_index,
                digit,
                self.w - 1 - digit,
                public_seed=public_seed,
                address=address,
            )
            offset = chain_index * n
            valid &= hmac.compare_digest(candidate, pk[offset : offset + n])
        return bool(valid)


@dataclass
class XmssSecretKey:
    """XMSS signing state: a master seed plus the next unspent leaf index.

    * ``seed`` is the only secret material.  Every WOTS+ chain secret of every
      leaf is derived from it together with the leaf address, so the key can be
      stored with the independent public seed and a counter.
    * ``public_seed`` is authenticated in the public key and must be persisted
      with the secret seed. It is not secret and must not be replaced on reload.
    * ``next_index`` is advanced by every :meth:`XmssSignatureBackend.sign`
      call; a leaf index is never handed out twice, and signing raises
      :class:`ValueError` once ``next_index == 2 ** height``.  The caller must
      persist it atomically.
    * ``_levels`` is a private memo of the Merkle tree filled in by
      :meth:`XmssSignatureBackend.keygen`.  It is a pure cache: signing
      recomputes the tree from both seeds when it is absent, and it is excluded
      from equality and from ``repr``.  It must never be written by hand.
    """

    seed: bytes = field(repr=False)
    public_seed: bytes
    height: int
    n: int
    w: int
    hash_name: str
    next_index: int = 0
    _levels: list[list[bytes]] | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.seed, (bytes, bytearray, memoryview)):
            raise ValueError("seed must be bytes-like")
        self.seed = bytes(self.seed)
        if not self.seed:
            raise ValueError("seed must be non-empty")
        self.public_seed = _coerce_bytes(self.public_seed, "public_seed")
        if len(self.public_seed) != self.n:
            raise ValueError(f"public_seed must be {self.n} bytes")
        if self.height < 1:
            raise ValueError(f"height must be >= 1, got {self.height}")
        if self.next_index < 0:
            raise ValueError(f"next_index must be >= 0, got {self.next_index}")


class XmssSignatureBackend:
    """PQ signature backend: XMSS (WOTS+ leaves under a Merkle tree), stateful.

    Wire signature layout, big-endian::

        index:u32 || wots_signature || wots_public_key || auth_path

    with ``len(wots_signature) == len(wots_public_key) == wots.signature_bytes``
    and ``len(auth_path) == height * n``; the authentication path holds one
    sibling per level, ordered from the leaf level upward.

    Verification recomputes ``leaf = H(0x00 || wots_public_key)`` (domain
    separated from internal nodes), folds ``node = H(0x01 || left || right)`` up
    the tree with the bits of ``index`` deciding the sibling order, and compares
    the resulting root against ``pk[:n]`` in constant time. ``pk[n:]`` supplies
    the public seed for every chain calculation.

    Contracts:

    * The backend is stateless; all signing state lives in the
      :class:`XmssSecretKey` handed to :meth:`sign`, so one instance serves many
      keys.  A key with parameters other than the backend's is rejected with
      :class:`ValueError`.
    * :meth:`sign` accepts a raw message of any length (including empty) and
      hashes it internally; :meth:`verify` does the same.
    * :meth:`verify` signals rejection by returning ``False`` and never raises
      for malformed input.
    * ``keygen`` builds the whole tree once (``2 ** height`` WOTS+ key
      generations) and memoizes it in the returned secret key.  Cost grows
      linearly in ``2 ** height``; ``height=10`` is the intended default.
    """

    name: str
    """Human-readable parameter-set label, e.g. ``"XMSS-SHA256-h10-w16"``."""

    public_key_bytes: int
    """Size of ``root || public_seed``, ``2*n`` bytes."""

    height: int
    """Merkle tree height; the tree has ``2 ** height`` leaves."""

    def __init__(
        self, height: int = 10, n: int = 32, w: int = 16, hash_name: str = "sha256"
    ) -> None:
        if isinstance(height, bool) or not isinstance(height, int) or height < 1:
            raise ValueError(f"height must be an integer >= 1, got {height!r}")
        if height > 32:
            raise ValueError("height must be <= 32 so a leaf index fits the u32 field")

        self.wots = WotsPlus(n=n, w=w, hash_name=hash_name)
        self.height = height
        self.n = n
        self.w = w
        self.hash_name = hash_name
        self.public_key_bytes = 2 * n
        self.name = f"XMSS-{hash_name.upper()}-h{height}-w{w}"
        self._ctor, _ = _resolve_hash(hash_name)

    # ------------------------------------------------------------------ sizes

    @property
    def max_signatures(self) -> int:
        """Number of leaves, ``2 ** height``; the key refuses to sign beyond it."""
        return 1 << self.height

    @property
    def signature_bytes(self) -> int:
        """Size of a signature in bytes: ``4 + 2 * wots.signature_bytes + height * n``."""
        return _INDEX_BYTES + 2 * self.wots.signature_bytes + self.height * self.n

    # -------------------------------------------------------------- internals

    def _h(self, *parts: bytes) -> bytes:
        """Hash the concatenation of *parts*, truncated to ``n`` bytes."""
        return self._ctor(b"".join(parts)).digest()[: self.n]

    def _hash_leaf(self, wots_pk: bytes) -> bytes:
        """``H(0x00 || wots_pk)`` -- the Merkle leaf of a WOTS+ public key."""
        return self._h(_DOM_LEAF, wots_pk)

    def _hash_node(self, left: bytes, right: bytes) -> bytes:
        """``H(0x01 || left || right)`` -- an internal Merkle node."""
        return self._h(_DOM_NODE, left, right)

    def _hash_message(self, message: bytes) -> bytes:
        """``H(0x05 || message)`` -- the ``n``-byte WOTS+ digest of a raw message."""
        return self._h(_DOM_MESSAGE, message)

    def _leaf(self, seed: bytes, public_seed: bytes, index: int) -> bytes:
        """Merkle leaf *index* of the tree derived from both seeds."""
        _, wots_pk = self.wots.keygen(seed, index, public_seed=public_seed)
        return self._hash_leaf(wots_pk)

    def _build_tree(self, seed: bytes, public_seed: bytes) -> list[list[bytes]]:
        """Return the Merkle tree of both seeds as ``height + 1`` levels.

        ``levels[0]`` holds the ``2 ** height`` leaves and ``levels[height]`` the
        single root; ``levels[j][i]`` is the node covering leaves
        ``[i * 2**j, (i + 1) * 2**j)``.
        """
        levels: list[list[bytes]] = [
            [self._leaf(seed, public_seed, index) for index in range(self.max_signatures)]
        ]
        while len(levels[-1]) > 1:
            below = levels[-1]
            levels.append(
                [self._hash_node(below[2 * i], below[2 * i + 1]) for i in range(len(below) // 2)]
            )
        return levels

    def _check_secret_key(self, sk: XmssSecretKey) -> None:
        """Raise unless *sk* is a secret key of exactly this parameter set."""
        if not isinstance(sk, XmssSecretKey):
            raise TypeError(f"sk must be an XmssSecretKey, got {type(sk).__name__}")
        actual = (sk.height, sk.n, sk.w, sk.hash_name)
        expected = (self.height, self.n, self.w, self.hash_name)
        if actual != expected:
            raise ValueError(
                f"secret key parameters (height, n, w, hash_name)={actual} do not match "
                f"this backend's {expected}"
            )
        if sk.next_index < 0:
            raise ValueError(f"next_index must be >= 0, got {sk.next_index}")
        self.wots._check_context(sk.public_seed, 0)

    def _auth_path(self, sk: XmssSecretKey, index: int) -> list[bytes]:
        """Authentication path of leaf *index*: siblings from the leaf level upward.

        Uses the secret key's memoized tree when present; otherwise rebuilds the
        tree from both seeds, so correctness never depends on the cache. Entry
        ``j`` is the sibling of the node that contains the leaf at level ``j``.
        """
        levels = sk._levels
        if (
            levels is None
            or len(levels) != self.height + 1
            or len(levels[0]) != self.max_signatures
        ):
            levels = self._build_tree(sk.seed, sk.public_seed)
        return [levels[level][(index >> level) ^ 1] for level in range(self.height)]

    # ------------------------------------------------------------- public API

    def keygen(self) -> tuple[XmssSecretKey, bytes]:
        """Generate independently random secret and public ``n``-byte seeds.

        Returns ``(sk, root || public_seed)``; only the chain seed is secret.
        """
        return self.keygen_from_seed(os.urandom(self.n), public_seed=os.urandom(self.n))

    def keygen_from_seed(self, seed: bytes, *, public_seed: bytes) -> tuple[XmssSecretKey, bytes]:
        """Rebuild a key from BOTH persisted seeds, or create deterministic tests.

        *seed* must be non-empty bytes-like.  Provided so that a key can be
        recreated from persisted material and so that determinism is testable.
        ``public_seed`` is mandatory and must be independent of the secret seed:
        containment of either seed in the other at any offset is refused, because the
        public seed is published as part of the public key.
        On restoration the caller MUST also restore the latest ``next_index``
        before signing; this helper initializes it to zero and cannot prevent rollback.
        """
        seed = _coerce_bytes(seed, "seed")
        if not seed:
            raise ValueError("seed must be non-empty")
        public_seed = self.wots._check_context(public_seed, 0)
        # Length validation is not enough: ``public_seed`` travels inside the public key
        # (``root || public_seed``), so a caller that passes the same string for both
        # publishes its own secret seed. The fifth review built the whole chain from that
        # mistake — read the seed out of the public key, rebuild the tree, sign — against a
        # version that checked lengths only (their V6-09). Refuse full containment in either direction. This misuse guard cannot
        # prove independence or detect every possible correlation between seeds.
        if seed in public_seed or public_seed in seed:
            raise ValueError(
                "public_seed and seed must be generated independently: "
                "neither may be a substring of the other (the public seed appears in the "
                "public key, so containment publishes secret material)"
            )
        levels = self._build_tree(seed, public_seed)
        sk = XmssSecretKey(
            seed=seed,
            public_seed=public_seed,
            height=self.height,
            n=self.n,
            w=self.w,
            hash_name=self.hash_name,
            next_index=0,
            _levels=levels,
        )
        return sk, levels[self.height][0] + public_seed

    def sign(self, sk: XmssSecretKey, message: bytes) -> bytes:
        """Spend the next leaf on *message* and return a signature.

        The index is **reserved under a lock before any hashing happens**, so two threads
        signing different messages can never be handed the same leaf — the failure mode
        that breaks WOTS+ outright. Advancing the counter first also means a crash part-way
        through burns a leaf instead of reusing one, which fails in the safe direction:
        leaves are free, a reused leaf is a forged signature.

        Raises :class:`ValueError` once ``max_signatures`` leaves are spent or when ``sk``
        belongs to a different parameter set, and :class:`TypeError`/:class:`ValueError` for
        a non-bytes-like message.
        """
        self._check_secret_key(sk)
        message = _coerce_bytes(message, "message")
        with _INDEX_LOCK:
            index = sk.next_index
            if index >= self.max_signatures:
                raise ValueError(
                    f"XMSS key exhausted: all {self.max_signatures} leaves are spent; "
                    "generate a new key pair"
                )
            sk.next_index = index + 1

        wots_sk, wots_pk = self.wots.keygen(sk.seed, index, public_seed=sk.public_seed)
        wots_signature = self.wots.sign(
            wots_sk, self._hash_message(message), public_seed=sk.public_seed, address=index,
        )
        auth_path = self._auth_path(sk, index)

        return (
            index.to_bytes(_INDEX_BYTES, "big")
            + wots_signature
            + wots_pk
            + b"".join(auth_path)
        )

    def verify(self, pk: bytes, message: bytes, signature: bytes) -> bool:
        """Return whether *signature* is a valid XMSS signature of *message* under *pk*.

        *pk* is ``root || public_seed`` (``2*n`` bytes). Returns ``False`` -- never raises --
        for a signature of the wrong length, a leaf index outside the tree, a
        wrong-size public key, a message that does not match, a WOTS+ signature
        that does not match the transmitted WOTS+ public key, or an
        authentication path that does not fold to *pk*.
        """
        try:
            pk = _coerce_bytes(pk, "pk")
            message = _coerce_bytes(message, "message")
            signature = _coerce_bytes(signature, "signature")
        except TypeError:
            return False
        if len(pk) != self.public_key_bytes or len(signature) != self.signature_bytes:
            return False

        index = int.from_bytes(signature[:_INDEX_BYTES], "big")
        if index >= self.max_signatures:
            return False

        offset = _INDEX_BYTES
        wots_bytes = self.wots.signature_bytes
        wots_signature = signature[offset : offset + wots_bytes]
        offset += wots_bytes
        wots_pk = signature[offset : offset + wots_bytes]
        offset += wots_bytes
        auth_path = signature[offset:]

        if not self.wots.verify(
            wots_pk, self._hash_message(message), wots_signature,
            public_seed=pk[self.n:], address=index,
        ):
            return False

        node = self._hash_leaf(wots_pk)
        n = self.n
        for level in range(self.height):
            sibling = auth_path[level * n : (level + 1) * n]
            if (index >> level) & 1:
                node = self._hash_node(sibling, node)
            else:
                node = self._hash_node(node, sibling)
        return hmac.compare_digest(node, pk[:self.n])
