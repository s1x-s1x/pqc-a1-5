"""Small, length-checked ctypes adapter for the public C ABI."""

import ctypes as ct
import os
import operator
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NAMES = {
    "SLH-DSA-SM3-128s": 1, "SLH-DSA-SM3-128f": 2,
    "SLH-DSA-SM3-128-24": 3, "SLH-DSA-SHA2-128s": 101,
    "SLH-DSA-SHA2-128f": 102, "SLH-DSA-SHA2-128-24": 103,
    "SLH-DSA-SM3-TOY": 201,
}
PREHASH = {"sha256": 1, "sha512": 2, "shake128": 3, "shake256": 4, "sm3": 5}
ABI_VERSION = 0x00010001
PARAM_SHAPES = {1: (9, 12, 14, 7856), 2: (3, 6, 33, 17088),
                3: (22, 24, 6, 3856), 101: (9, 12, 14, 7856),
                102: (3, 6, 33, 17088), 103: (22, 24, 6, 3856),
                201: (10, 10, 6, 2320)}
U8P = ct.POINTER(ct.c_uint8)
VOID = ct.c_void_p


def _buffer(data, length=None, label="input"):
    data = _bytes(data, label)
    if length is not None and len(data) != length:
        raise ValueError(f"{label} must contain {length} bytes")
    return (ct.c_uint8 * max(1, len(data))).from_buffer_copy(data or b"\0")


def _bytes(data, label="input"):
    """Buffer protocol only: reject bytes(integer) and implicit iterable casts."""
    if isinstance(data, bytes):
        return data
    try:
        return memoryview(data).tobytes()
    except TypeError as error:
        raise TypeError(f"{label} must support the buffer protocol") from error


def _integer(value, low, high, label):
    if isinstance(value, bool):
        raise TypeError(f"{label} must be an integer, not bool")
    try:
        value = operator.index(value)
    except TypeError as error:
        raise TypeError(f"{label} must be an integer") from error
    if not low <= value <= high:
        raise ValueError(f"{label} must be in [{low}, {high}]")
    return value


def _erase(buffer):
    if buffer is not None:
        ct.memset(buffer, 0, ct.sizeof(buffer))


class NativeError(RuntimeError):
    def __init__(self, operation, code):
        self.operation, self.code = operation, code
        super().__init__(f"{operation} returned {code}")


class NativeSlhDsa:
    """Own one context; independent contexts may be used by separate workers.

    flags: low byte is backend (0 auto, 1 reference, 2 AVX2), 0x100 verify-after-sign.
    Cache and key data stay owned by the C context. close() erases that context.
    """

    def __init__(self, pid=3, threads=1, flags=0, library=None):
        self.pid = NAMES[pid] if isinstance(pid, str) else pid
        self.pid = _integer(self.pid, 1, 0x7fffffff, "pid")
        if self.pid not in PARAM_SHAPES:
            raise ValueError("unsupported parameter id")
        threads = _integer(threads, 0, 1024, "threads")
        flags = _integer(flags, 0, 0xffffffff, "flags")
        if flags & ~0x1ff or flags & 0xff not in (0, 1, 2, 5):
            raise ValueError("unsupported backend or flags")
        path = library or os.environ.get("A15_NATIVE_LIBRARY")
        path = path or ROOT / "build" / ("slhdsa_sm3.dll" if os.name == "nt" else "libslhdsa_sm3.so")
        self.library_path = str(Path(path).resolve())
        self.lib = ct.CDLL(self.library_path)
        version = getattr(self.lib, "slh_abi_version", None)
        if version is None:
            raise RuntimeError("native ABI version query missing; rebuild library for ABI 1.1")
        version.argtypes, version.restype = [], ct.c_uint32
        self.abi_version = version()
        if self.abi_version != ABI_VERSION:
            raise RuntimeError(f"native ABI mismatch: expected {ABI_VERSION:#x}, got {self.abi_version:#x}")
        self._configure()
        expected = (32, 64, PARAM_SHAPES[self.pid][3])
        actual = (self.lib.slh_pk_bytes(self.pid), self.lib.slh_sk_bytes(self.pid),
                  self.lib.slh_sig_bytes(self.pid))
        if actual != expected:
            raise RuntimeError(f"native ABI size mismatch: expected {expected}, got {actual}")
        self.ctx = VOID()
        self._check("slh_ctx_new", self.lib.slh_ctx_new(ct.byref(self.ctx), self.pid, flags))
        try:
            self._check("slh_ctx_set_threads", self.lib.slh_ctx_set_threads(self.ctx, threads))
            self.pk_bytes, self.sk_bytes, self.sig_bytes = actual
            self.n = self.pk_bytes // 2
        except Exception:
            self.close()
            raise

    def _configure(self):
        signatures = {
            "slh_ctx_new": ([ct.POINTER(VOID), ct.c_int, ct.c_uint], ct.c_int),
            "slh_ctx_set_threads": ([VOID, ct.c_int], ct.c_int),
            "slh_ctx_set_cache_level": ([VOID, ct.c_uint], ct.c_int),
            "slh_ctx_free": ([VOID], None),
            "slh_pk_bytes": ([ct.c_int], ct.c_size_t),
            "slh_sk_bytes": ([ct.c_int], ct.c_size_t),
            "slh_sig_bytes": ([ct.c_int], ct.c_size_t),
            "slh_keygen_internal": ([VOID, U8P, U8P, U8P, U8P, U8P], ct.c_int),
            "slh_keygen": ([VOID, U8P, U8P], ct.c_int),
            "slh_sign_internal": ([VOID, U8P, U8P, ct.c_size_t, U8P, U8P], ct.c_int),
            "slh_sign_internal_checked": ([VOID, U8P, ct.c_size_t, U8P, ct.c_size_t, U8P, U8P], ct.c_int),
            "slh_verify_internal": ([VOID, U8P, ct.c_size_t, U8P, ct.c_size_t, U8P], ct.c_int),
            "slh_sign": ([VOID, U8P, ct.POINTER(ct.c_size_t), U8P, ct.c_size_t,
                           U8P, ct.c_size_t, U8P, U8P], ct.c_int),
            "slh_sign_checked": ([VOID, U8P, ct.c_size_t, ct.POINTER(ct.c_size_t), U8P, ct.c_size_t,
                                   U8P, ct.c_size_t, U8P, U8P], ct.c_int),
            "slh_verify": ([VOID, U8P, ct.c_size_t, U8P, ct.c_size_t, U8P,
                            ct.c_size_t, U8P], ct.c_int),
            "slh_ctx_bind_key": ([VOID, U8P], ct.c_int),
            "slh_subtree": ([VOID, ct.c_int, U8P, ct.c_uint32, ct.c_uint,
                              ct.c_uint32, U8P, U8P], ct.c_int),
            "slh_subtree_checked": ([VOID, ct.c_int, U8P, ct.c_uint32, ct.c_uint,
                                      ct.c_uint32, U8P, ct.c_size_t, U8P, ct.c_size_t], ct.c_int),
            "slh_cache_build": ([VOID, U8P, ct.c_uint], ct.c_int),
            "slh_cache_save": ([VOID, ct.c_char_p], ct.c_int),
            "slh_cache_load": ([VOID, ct.c_char_p, U8P], ct.c_int),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.lib, name)
            function.argtypes, function.restype = arguments, result
        optional = {
            "slh_prehash_bytes": ([ct.c_int], ct.c_size_t),
            "slh_backend_available": ([ct.c_int], ct.c_int),
            "slh_ctx_backend": ([VOID], ct.c_int),
        }
        for ending in ("prehash", "digest"):
            signatures["slh_sign_" + ending + "_checked"] = ([VOID, U8P, ct.c_size_t,
                ct.POINTER(ct.c_size_t), ct.c_int, U8P, ct.c_size_t, U8P, ct.c_size_t, U8P, U8P], ct.c_int)
            optional["slh_sign_" + ending] = ([VOID, U8P, ct.POINTER(ct.c_size_t), ct.c_int,
                U8P, ct.c_size_t, U8P, ct.c_size_t, U8P, U8P], ct.c_int)
            optional["slh_verify_" + ending] = ([VOID, U8P, ct.c_size_t, ct.c_int,
                U8P, ct.c_size_t, U8P, ct.c_size_t, U8P], ct.c_int)
        for name, (arguments, result) in optional.items():
            function = getattr(self.lib, name, None)
            if function is not None:
                function.argtypes, function.restype = arguments, result
        for ending in ("prehash", "digest"):
            name = "slh_sign_" + ending + "_checked"
            function = getattr(self.lib, name)
            function.argtypes, function.restype = signatures[name]

    @staticmethod
    def _check(operation, code):
        if code:
            raise NativeError(operation, code)

    def _live(self):
        if not self.ctx:
            raise RuntimeError("native context is closed")

    def close(self):
        if getattr(self, "ctx", None):
            self.lib.slh_ctx_free(self.ctx)
            self.ctx = VOID()

    def __enter__(self):
        self._live()
        return self

    def __exit__(self, *_):
        self.close()

    def __del__(self):
        self.close()

    def set_threads(self, threads):
        self._live()
        threads = _integer(threads, 0, 1024, "threads")
        self._check("slh_ctx_set_threads", self.lib.slh_ctx_set_threads(self.ctx, threads))

    def set_cache_level(self, level):
        self._live()
        level = _integer(level, 0, PARAM_SHAPES[self.pid][0], "cache level")
        self._check("slh_ctx_set_cache_level", self.lib.slh_ctx_set_cache_level(self.ctx, level))

    def keygen_internal(self, sk_seed, sk_prf, pk_seed):
        self._live()
        pk, sk = (ct.c_uint8 * self.pk_bytes)(), (ct.c_uint8 * self.sk_bytes)()
        seed = prf = None
        try:
            seed = _buffer(sk_seed, self.n, "sk_seed")
            prf = _buffer(sk_prf, self.n, "sk_prf")
            self._check("slh_keygen_internal", self.lib.slh_keygen_internal(
                self.ctx, pk, sk, seed, prf, _buffer(pk_seed, self.n, "pk_seed")))
            return bytes(pk), bytes(sk)
        finally:
            _erase(seed); _erase(prf); _erase(sk)

    def keygen(self):
        self._live()
        pk, sk = (ct.c_uint8 * self.pk_bytes)(), (ct.c_uint8 * self.sk_bytes)()
        try:
            self._check("slh_keygen", self.lib.slh_keygen(self.ctx, pk, sk))
            return bytes(pk), bytes(sk)
        finally:
            _erase(sk)

    def sign_internal(self, mp, sk, addrnd=None):
        self._live()
        mp = _bytes(mp, "message")
        sig = (ct.c_uint8 * self.sig_bytes)()
        secret = rnd = None
        try:
            secret = _buffer(sk, self.sk_bytes, "sk")
            rnd = None if addrnd is None else _buffer(addrnd, self.n, "addrnd")
            self._check("slh_sign_internal_checked", self.lib.slh_sign_internal_checked(
                self.ctx, sig, self.sig_bytes, _buffer(mp), len(mp), secret, rnd))
            return bytes(sig)
        finally:
            _erase(secret); _erase(rnd); _erase(sig)

    def verify_internal(self, mp, sig, pk):
        self._live()
        mp, sig = _bytes(mp, "message"), _bytes(sig, "signature")
        result = self.lib.slh_verify_internal(self.ctx, _buffer(sig), len(sig),
            _buffer(mp), len(mp), _buffer(pk, self.pk_bytes, "pk"))
        if result not in (0, -3):
            self._check("slh_verify_internal", result)
        return result == 0

    def sign(self, message, sk, context=b"", addrnd=None):
        self._live()
        message, context = _bytes(message, "message"), _bytes(context, "context")
        if len(context) > 255:
            raise ValueError("context must contain at most 255 bytes")
        sig, length = (ct.c_uint8 * self.sig_bytes)(), ct.c_size_t()
        secret = rnd = None
        try:
            secret = _buffer(sk, self.sk_bytes, "sk")
            rnd = None if addrnd is None else _buffer(addrnd, self.n, "addrnd")
            self._check("slh_sign_checked", self.lib.slh_sign_checked(self.ctx, sig, self.sig_bytes, ct.byref(length),
                _buffer(message), len(message), _buffer(context), len(context), secret, rnd))
            if length.value != self.sig_bytes:
                raise RuntimeError("native signature length mismatch")
            return bytes(sig[:length.value])
        finally:
            _erase(secret); _erase(rnd); _erase(sig)

    def verify(self, message, sig, pk, context=b""):
        self._live()
        message, sig, context = _bytes(message, "message"), _bytes(sig, "signature"), _bytes(context, "context")
        if len(context) > 255:
            raise ValueError("context must contain at most 255 bytes")
        result = self.lib.slh_verify(self.ctx, _buffer(sig), len(sig),
            _buffer(message), len(message), _buffer(context), len(context),
            _buffer(pk, self.pk_bytes, "pk"))
        if result not in (0, -3):
            self._check("slh_verify", result)
        return result == 0

    def _prehash_operation(self, ending, data, hash_alg, sk=None, sig=None, pk=None,
                           context=b"", addrnd=None):
        self._live()
        algorithm = PREHASH[hash_alg] if isinstance(hash_alg, str) else hash_alg
        algorithm = _integer(algorithm, 1, 5, "prehash algorithm")
        data, context = _bytes(data, "message/digest"), _bytes(context, "context")
        if len(context) > 255:
            raise ValueError("context must contain at most 255 bytes")
        if ending == "digest" and len(data) != (64 if algorithm == 2 else 32):
            raise ValueError("digest length does not match prehash algorithm")
        signing = sk is not None
        name = "slh_" + ("sign_" if signing else "verify_") + ending + ("_checked" if signing else "")
        function = getattr(self.lib, name, None)
        if function is None:
            raise RuntimeError("this library predates the native prehash ABI")
        if signing:
            output, length = (ct.c_uint8 * self.sig_bytes)(), ct.c_size_t()
            secret = rnd = None
            try:
                secret = _buffer(sk, self.sk_bytes, "sk")
                rnd = None if addrnd is None else _buffer(addrnd, self.n, "addrnd")
                self._check(name, function(self.ctx, output, self.sig_bytes, ct.byref(length), algorithm,
                    _buffer(data), len(data), _buffer(context), len(context), secret, rnd))
                if length.value != self.sig_bytes:
                    raise RuntimeError("native signature length mismatch")
                return bytes(output[:length.value])
            finally:
                _erase(secret); _erase(rnd); _erase(output)
        sig = _bytes(sig, "signature")
        result = function(self.ctx, _buffer(sig), len(sig), algorithm, _buffer(data), len(data),
                          _buffer(context), len(context), _buffer(pk, self.pk_bytes, "pk"))
        if result not in (0, -3):
            self._check(name, result)
        return result == 0

    def sign_prehash(self, message, sk, hash_alg="sm3", context=b"", addrnd=None):
        return self._prehash_operation("prehash", message, hash_alg, sk=sk, context=context, addrnd=addrnd)

    def verify_prehash(self, message, sig, pk, hash_alg="sm3", context=b""):
        return self._prehash_operation("prehash", message, hash_alg, sig=sig, pk=pk, context=context)

    def sign_digest(self, digest, sk, hash_alg="sm3", context=b"", addrnd=None):
        return self._prehash_operation("digest", digest, hash_alg, sk=sk, context=context, addrnd=addrnd)

    def verify_digest(self, digest, sig, pk, hash_alg="sm3", context=b""):
        return self._prehash_operation("digest", digest, hash_alg, sig=sig, pk=pk, context=context)

    @property
    def backend(self):
        self._live()
        function = getattr(self.lib, "slh_ctx_backend", None)
        return function(self.ctx) if function is not None else 1

    def bind_key(self, sk):
        self._live()
        secret = _buffer(sk, self.sk_bytes, "sk")
        try:
            self._check("slh_ctx_bind_key", self.lib.slh_ctx_bind_key(self.ctx, secret))
        finally:
            _erase(secret)

    def subtree(self, kind, adrs, leaf_start, z, target=None):
        self._live()
        kind = {"wots": 0, "fors": 1}.get(kind, kind)
        kind = _integer(kind, 0, 1, "leaf kind")
        hp, height, trees, _ = PARAM_SHAPES[self.pid]
        maximum = hp if kind == 0 else height
        z = _integer(z, 0, maximum, "subtree height")
        leaf_start = _integer(leaf_start, 0, 0xffffffff, "leaf_start")
        target = 0xffffffff if target is None else target
        target = _integer(target, 0, 0xffffffff, "target")
        end = leaf_start + (1 << z)
        if leaf_start & ((1 << z) - 1) or end > (1 << hp if kind == 0 else trees << height):
            raise ValueError("subtree start is unaligned or range is invalid")
        if kind == 1 and leaf_start >> height != (end - 1) >> height:
            raise ValueError("subtree crosses FORS tree boundary")
        if target != 0xffffffff and not leaf_start <= target < end:
            raise ValueError("target is outside subtree")
        address = _buffer(adrs, 32, "adrs")
        path = z * self.n if target != 0xffffffff else 0
        root, auth = (ct.c_uint8 * self.n)(), (ct.c_uint8 * max(1, path))()
        self._check("slh_subtree_checked", self.lib.slh_subtree_checked(self.ctx, kind,
            address, leaf_start, z, target, root, self.n, auth, path))
        return bytes(root), bytes(auth[:z*self.n]) if target != 0xffffffff else b""

    def cache_build(self, sk, level):
        self._live()
        level = _integer(level, 0, PARAM_SHAPES[self.pid][0], "cache level")
        secret = _buffer(sk, self.sk_bytes, "sk")
        try:
            self._check("slh_cache_build", self.lib.slh_cache_build(self.ctx, secret, level))
        finally:
            _erase(secret)

    def cache_save(self, path):
        self._live()
        self._check("slh_cache_save", self.lib.slh_cache_save(self.ctx, os.fsencode(path)))

    def cache_load(self, path, pk):
        self._live()
        self._check("slh_cache_load", self.lib.slh_cache_load(self.ctx, os.fsencode(path), _buffer(pk, self.pk_bytes, "pk")))
