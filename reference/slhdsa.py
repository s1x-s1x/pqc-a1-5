"""SM3/SHA-256 adaptation of py-acvp-pqc's FIPS 205 reference.

The upstream algorithms remain inherited and independently supply the
sequential reference. Treehash splits aligned subtrees into indexed jobs.
No project C implementation is imported or used by this model.
"""

from concurrent.futures import ProcessPoolExecutor
import hashlib
import hmac
import importlib.util
import os
from pathlib import Path
import sys

from .sm3 import Sm3


UPSTREAM_COMMIT = "1c859956c0217b04fa5ae76e338e5570aba622c5"
_UPSTREAM = Path(__file__).resolve().parents[1] / "third_party" / "py-acvp-pqc"
sys.path.insert(0, str(_UPSTREAM))
_spec = importlib.util.spec_from_file_location("a15_upstream_fips205", _UPSTREAM / "fips205.py")
_upstream = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_upstream)
ADRS = _upstream.ADRS

# (hash, n, h, d, h/d, a, k, log2(w), m), independently checked from SPEC.
PARAMETERS = {
    1: ("SM3", 16, 63, 7, 9, 12, 14, 4, 30),
    2: ("SM3", 16, 66, 22, 3, 6, 33, 4, 34),
    3: ("SM3", 16, 22, 1, 22, 24, 6, 2, 21),
    101: ("SHA2", 16, 63, 7, 9, 12, 14, 4, 30),
    102: ("SHA2", 16, 66, 22, 3, 6, 33, 4, 34),
    103: ("SHA2", 16, 22, 1, 22, 24, 6, 2, 21),
    201: ("SM3", 16, 10, 1, 10, 10, 6, 2, 10),
}
_NAMES = {
    "SLH-DSA-SM3-128s": 1, "SLH-DSA-SM3-128f": 2,
    "SLH-DSA-SM3-128-24": 3, "SLH-DSA-SHA2-128s": 101,
    "SLH-DSA-SHA2-128f": 102, "SLH-DSA-SHA2-128-24": 103,
    "SLH-DSA-SM3-TOY": 201,
}
_WORKER_MODEL = None


def encode_message(message, context=b""):
    """FIPS 205 pure-mode M' (Algorithm 22)."""
    if len(context) > 255:
        raise ValueError("context must contain at most 255 bytes")
    return b"\x00" + bytes([len(context)]) + bytes(context) + bytes(message)


def _worker_init(pid, force_python_sm3):
    global _WORKER_MODEL
    _WORKER_MODEL = ReferenceSlhDsa(pid, force_python_sm3=force_python_sm3)


def _worker_subtree(arguments):
    return _WORKER_MODEL._treehash(*arguments)


class ReferenceSlhDsa(_upstream.SLH_DSA):
    """Reference API; methods with slh_ prefixes retain upstream signatures.

    keygen_internal(seed, prf, public_seed) -> (pk, sk)
    sign_internal(encoded_message, sk, addrnd=None) -> signature
    verify_internal(encoded_message, signature, pk) -> bool
    sign(message, sk, context=b'', addrnd=None) -> signature
    verify(message, signature, pk, context=b'') -> bool
    subtree(kind, sk_seed, pk_seed, adrs, leaf_start, z, target=None)
        -> (root, bottom-up authentication_path)
    """

    def __init__(self, pid=3, workers=1, task_height=14, parallel_min_height=12,
                 force_python_sm3=False):
        if isinstance(pid, str):
            pid = _NAMES[pid]
        if pid not in PARAMETERS:
            raise ValueError("unsupported parameter identifier")
        if workers < 1 or task_height < 0 or parallel_min_height < 0:
            raise ValueError("invalid parallel settings")
        self.pid = pid
        self.workers = workers
        self.task_height = task_height
        self.parallel_min_height = parallel_min_height
        self.force_python_sm3 = force_python_sm3
        self._pool = None
        self._prefix_seed = None
        self._prefix_hash = None
        super().__init__(PARAMETERS[pid])
        self._hash_name = "sm3" if self.hashname == "SM3" else "sha256"
        self.h_msg = self._h_msg
        self.prf = self._prf
        self.prf_msg = self._prf_msg
        self.h_f = self._thash
        self.h_h = self._thash
        self.h_t = self._thash
        self.rbg = os.urandom
        expected_m = ((self.k * self.a + 7) // 8 +
                      (self.h - self.hp + 7) // 8 + (self.hp + 7) // 8)
        if self.h != self.d * self.hp or self.m != expected_m:
            raise ValueError("inconsistent parameter dimensions")
        self.hash_backend = self._new_hash().name
        if isinstance(self._new_hash(), Sm3):
            self.hash_backend = "python-sm3"

    def close(self):
        if self._pool is not None:
            self._pool.shutdown(wait=True)
            self._pool = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _new_hash(self, data=b""):
        if self._hash_name == "sm3" and self.force_python_sm3:
            return Sm3(data)
        try:
            return hashlib.new(self._hash_name, data)
        except ValueError:
            if self._hash_name == "sm3":
                return Sm3(data)
            raise

    def _digest(self, data):
        return self._new_hash(data).digest()

    def _prefix(self, pk_seed):
        # hashlib.copy preserves the absorbed 64-byte prefix and total length.
        if self._prefix_seed != pk_seed:
            self._prefix_seed = bytes(pk_seed)
            self._prefix_hash = self._new_hash(pk_seed + bytes(64 - self.n))
        return self._prefix_hash.copy()

    def _thash(self, pk_seed, adrs, value):
        state = self._prefix(pk_seed)
        state.update(adrs.adrsc())
        state.update(value)
        return state.digest()[:self.n]

    def _prf(self, pk_seed, sk_seed, adrs):
        return self._thash(pk_seed, adrs, sk_seed)

    def _prf_msg(self, sk_prf, opt_rand, message):
        return hmac.new(sk_prf, opt_rand + message, self._new_hash).digest()[:self.n]

    def _h_msg(self, randomizer, pk_seed, pk_root, message):
        seed = randomizer + pk_seed + self._digest(randomizer + pk_seed + pk_root + message)
        return b"".join(self._digest(seed + i.to_bytes(4, "big"))
                        for i in range((self.m + 31) // 32))[:self.m]

    def _ensure_pool(self):
        if self._pool is None:
            self._pool = ProcessPoolExecutor(
                max_workers=self.workers, initializer=_worker_init,
                initargs=(self.pid, self.force_python_sm3))
        return self._pool

    def _tree_address(self, kind, base_adrs):
        address = ADRS(base_adrs)
        key_pair = address.get_key_pair_address()
        address.set_type_and_clear(ADRS.TREE if kind == "wots" else ADRS.FORS_TREE)
        if kind == "fors":
            address.set_key_pair_address(key_pair)
        return address

    def _treehash(self, kind, sk_seed, pk_seed, base_adrs, leaf_start, z, target):
        """Iterative, constant-space equivalent of Algorithms 9 and 15."""
        stack = []
        auth = [None] * z if target is not None else []
        leaf_address = ADRS(base_adrs)
        tree_address = self._tree_address(kind, base_adrs)
        key_pair = ADRS(base_adrs).get_key_pair_address()
        for leaf in range(leaf_start, leaf_start + (1 << z)):
            if kind == "wots":
                leaf_address.set_type_and_clear(ADRS.WOTS_HASH)
                leaf_address.set_key_pair_address(leaf)
                node = self.wots_pkgen(sk_seed, pk_seed, leaf_address)
            else:
                leaf_address.set_type_and_clear(ADRS.FORS_TREE)
                leaf_address.set_key_pair_address(key_pair)
                secret = self.fors_sk_gen(sk_seed, pk_seed, leaf_address, leaf)
                leaf_address.set_tree_height(0)
                leaf_address.set_tree_index(leaf)
                node = self.h_f(pk_seed, leaf_address, secret)
            height, index = 0, leaf
            if target is not None and z and index == (target ^ 1):
                auth[0] = node
            while stack and stack[-1][1] == height:
                left, _, _ = stack.pop()
                height += 1
                index >>= 1
                tree_address.set_tree_height(height)
                tree_address.set_tree_index(index)
                node = self.h_h(pk_seed, tree_address, left + node)
                if target is not None and height < z and index == ((target >> height) ^ 1):
                    auth[height] = node
            stack.append((node, height, index))
        if len(stack) != 1 or any(value is None for value in auth):
            raise AssertionError("treehash stack/authentication invariant")
        return stack[0][0], b"".join(auth)

    def subtree(self, kind, sk_seed, pk_seed, adrs, leaf_start, z, target=None):
        if kind not in ("wots", "fors"):
            raise ValueError("kind must be 'wots' or 'fors'")
        maximum_height = self.hp if kind == "wots" else self.a
        maximum_leaves = 1 << self.hp if kind == "wots" else self.k << self.a
        if (not 0 <= z <= maximum_height or leaf_start < 0 or
                leaf_start % (1 << z) or leaf_start + (1 << z) > maximum_leaves):
            raise ValueError("subtree must be aligned and within parameter bounds")
        if target is not None and not leaf_start <= target < leaf_start + (1 << z):
            raise ValueError("target must lie within the requested subtree")
        if len(sk_seed) != self.n or len(pk_seed) != self.n:
            raise ValueError("incorrect seed length")
        address = bytes(adrs.adrs() if isinstance(adrs, ADRS) else adrs)
        if len(address) != 32:
            raise ValueError("ADRS must contain 32 bytes")
        arguments = (kind, sk_seed, pk_seed, address, leaf_start, z, target)
        if self.workers == 1 or z < self.parallel_min_height:
            return self._treehash(*arguments)
        # Give every worker multiple equal subtrees; map preserves task order.
        split_bits = min(z, (self.workers * 4 - 1).bit_length())
        child_height = min(self.task_height, z - split_bits)
        child_size = 1 << child_height
        jobs = []
        for start in range(leaf_start, leaf_start + (1 << z), child_size):
            local_target = target if target is not None and start <= target < start + child_size else None
            jobs.append((kind, sk_seed, pk_seed, address, start, child_height, local_target))
        results = self._ensure_pool().map(_worker_subtree, jobs, chunksize=1)
        stack = []
        auth = [None] * z if target is not None else []
        tree_address = self._tree_address(kind, address)
        for ordinal, (node, local_auth) in enumerate(results):
            start = leaf_start + ordinal * child_size
            if local_auth:
                for height in range(child_height):
                    auth[height] = local_auth[height * self.n:(height + 1) * self.n]
            height, index = child_height, start >> child_height
            if target is not None and height < z and index == ((target >> height) ^ 1):
                auth[height] = node
            while stack and stack[-1][1] == height:
                left, _, _ = stack.pop()
                height += 1
                index >>= 1
                tree_address.set_tree_height(height)
                tree_address.set_tree_index(index)
                node = self.h_h(pk_seed, tree_address, left + node)
                if target is not None and height < z and index == ((target >> height) ^ 1):
                    auth[height] = node
            stack.append((node, height, index))
        if len(stack) != 1 or any(value is None for value in auth):
            raise AssertionError("parallel treehash stack/authentication invariant")
        return stack[0][0], b"".join(auth)

    def xmss_node(self, sk_seed, i, z, pk_seed, adrs):
        if self.workers == 1 or z < self.parallel_min_height:
            return super().xmss_node(sk_seed, i, z, pk_seed, adrs)
        return self.subtree("wots", sk_seed, pk_seed, adrs, i << z, z)[0]

    def fors_node(self, sk_seed, i, z, pk_seed, adrs):
        if self.workers == 1 or z < self.parallel_min_height:
            return super().fors_node(sk_seed, i, z, pk_seed, adrs)
        return self.subtree("fors", sk_seed, pk_seed, adrs, i << z, z)[0]

    def slh_keygen_internal(self, sk_seed, sk_prf, pk_seed, param=None):
        if param is not None and _NAMES.get(param, param) != self.pid:
            raise ValueError("parameter override must match this model")
        if any(len(seed) != self.n for seed in (sk_seed, sk_prf, pk_seed)):
            raise ValueError("incorrect seed length")
        return super().slh_keygen_internal(sk_seed, sk_prf, pk_seed)

    def slh_sign_internal(self, m, sk, addrnd=None, param=None):
        if param is not None and _NAMES.get(param, param) != self.pid:
            raise ValueError("parameter override must match this model")
        if len(sk) != self.sk_sz or (addrnd is not None and len(addrnd) != self.n):
            raise ValueError("incorrect secret key or randomizer length")
        return super().slh_sign_internal(bytes(m), bytes(sk), addrnd)

    def slh_verify_internal(self, m, sig, pk, param=None):
        if param is not None and _NAMES.get(param, param) != self.pid:
            return False
        return super().slh_verify_internal(bytes(m), bytes(sig), bytes(pk))

    keygen_internal = slh_keygen_internal
    sign_internal = slh_sign_internal
    verify_internal = slh_verify_internal

    def keygen(self):
        return self.slh_keygen_internal(*(os.urandom(self.n) for _ in range(3)))

    def sign(self, message, sk, context=b"", addrnd=None):
        return self.slh_sign_internal(encode_message(message, context), sk, addrnd)

    def verify(self, message, signature, pk, context=b""):
        if len(context) > 255:
            return False
        return self.slh_verify_internal(encode_message(message, context), signature, pk)
