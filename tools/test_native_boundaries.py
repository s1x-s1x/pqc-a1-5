"""Untimed native adapter tests. Mock callbacks never load a shared library."""
import ctypes as ct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

try:
    from tools import native
except ImportError:
    import native


class AdapterBoundaries(unittest.TestCase):
    def setUp(self):
        self.records = []
        self.callbacks = []
        self.lib = SimpleNamespace()
        self.adapter = native.NativeSlhDsa.__new__(native.NativeSlhDsa)
        self.adapter.lib, self.adapter.ctx = self.lib, native.VOID(1)
        self.adapter.pid = 201
        self.adapter.n, self.adapter.pk_bytes, self.adapter.sk_bytes, self.adapter.sig_bytes = 16, 32, 64, 2320
        self.attach("slh_sign_checked", [native.VOID, native.U8P, ct.c_size_t,
            ct.POINTER(ct.c_size_t), native.U8P, ct.c_size_t, native.U8P,
            ct.c_size_t, native.U8P, native.U8P], self.sign)
        self.attach("slh_sign_internal_checked", [native.VOID, native.U8P,
            ct.c_size_t, native.U8P, ct.c_size_t, native.U8P, native.U8P], self.sign_internal)
        for ending in ("prehash", "digest"):
            self.attach("slh_sign_" + ending + "_checked", [native.VOID, native.U8P,
                ct.c_size_t, ct.POINTER(ct.c_size_t), ct.c_int, native.U8P,
                ct.c_size_t, native.U8P, ct.c_size_t, native.U8P, native.U8P], self.prehash)
            self.attach("slh_verify_" + ending, [native.VOID, native.U8P, ct.c_size_t,
                ct.c_int, native.U8P, ct.c_size_t, native.U8P, ct.c_size_t,
                native.U8P], self.verify_prehash)
        self.attach("slh_ctx_set_threads", [native.VOID, ct.c_int], lambda _, n: self.record("threads", n))
        self.attach("slh_ctx_set_cache_level", [native.VOID, ct.c_uint], lambda _, n: self.record("level", n))
        self.attach("slh_subtree_checked", [native.VOID, ct.c_int, native.U8P,
            ct.c_uint32, ct.c_uint, ct.c_uint32, native.U8P, ct.c_size_t,
            native.U8P, ct.c_size_t], self.subtree)

    def tearDown(self):
        self.adapter.ctx = native.VOID()

    def attach(self, name, args, callback):
        fn = ct.CFUNCTYPE(ct.c_int, *args)(callback)
        self.callbacks.append(fn)
        setattr(self.lib, name, fn)

    def record(self, *items):
        self.records.append(items)
        return 0

    def sign(self, ctx, sig, capacity, length, msg, mlen, context, clen, sk, rnd):
        self.record("sign", ct.string_at(msg, mlen), ct.string_at(context, clen), capacity)
        ct.memset(sig, 0x42, capacity)
        length[0] = capacity
        return 0

    def sign_internal(self, ctx, sig, capacity, msg, mlen, sk, rnd):
        self.record("internal", ct.string_at(msg, mlen), capacity)
        ct.memset(sig, 0x42, capacity)
        return 0

    def prehash(self, ctx, sig, capacity, length, alg, msg, mlen, context, clen, sk, rnd):
        self.record("prehash", alg, ct.string_at(msg, mlen), ct.string_at(context, clen))
        ct.memset(sig, 0x42, capacity)
        length[0] = capacity
        return 0

    def verify_prehash(self, ctx, sig, slen, alg, msg, mlen, context, clen, pk):
        self.record("verify_prehash", alg, ct.string_at(msg, mlen), ct.string_at(context, clen))
        return 0

    def test_all_five_digest_algorithms_and_lengths_before_sign_verify_abi(self):
        # Explicit C ABI contract, independent of the adapter's lookup table.
        sizes = {"sha256": 32, "sha512": 64, "shake128": 32, "shake256": 64, "sm3": 32}
        for name, expected in sizes.items():
            for selector in (name, native.PREHASH[name]):
                for signing in (True, False):
                    with self.subTest(algorithm=selector, signing=signing):
                        for size in (expected - 1, expected + 1):
                            before = len(self.records)
                            with self.assertRaises(ValueError):
                                if signing:
                                    self.adapter.sign_digest(bytes(size), bytes(64), selector)
                                else:
                                    self.adapter.verify_digest(bytes(size), bytes(2320), bytes(32), selector)
                            self.assertEqual(len(self.records), before)
                        digest = memoryview(bytes(range(expected))).cast("I")
                        if signing:
                            self.assertEqual(self.adapter.sign_digest(digest, bytes(64), selector), bytes([0x42]) * 2320)
                        else:
                            self.assertTrue(self.adapter.verify_digest(digest, bytes(2320), bytes(32), selector))
                        self.assertEqual(self.records[-1][1:3], (native.PREHASH[name], bytes(range(expected))))
        # SHAKE256's old 32-byte allowance is outside the required +/-1 cases.
        for selector in ("shake256", 4):
            with self.assertRaises(ValueError):
                self.adapter.sign_digest(bytes(32), bytes(64), selector)
            with self.assertRaises(ValueError):
                self.adapter.verify_digest(bytes(32), bytes(2320), bytes(32), selector)

    def test_digest_optional_c_length_query_must_match_all_five_algorithms(self):
        # No query is supported by the explicit fallback contract in the matrix.
        self.lib.slh_prehash_bytes = lambda alg: {1: 32, 2: 64, 3: 32, 4: 64, 5: 32}[alg]
        for alg, size in {1: 32, 2: 64, 3: 32, 4: 64, 5: 32}.items():
            self.adapter.sign_digest(bytes(size), bytes(64), alg)
            self.assertTrue(self.adapter.verify_digest(bytes(size), bytes(2320), bytes(32), alg))
        for reported in (0, 32, 65):
            self.lib.slh_prehash_bytes = lambda alg: reported
            before = len(self.records)
            with self.assertRaisesRegex(RuntimeError, "contract mismatch"):
                self.adapter.sign_digest(bytes(64), bytes(64), "shake256")
            with self.assertRaisesRegex(RuntimeError, "contract mismatch"):
                self.adapter.verify_digest(bytes(64), bytes(2320), bytes(32), 4)
            self.assertEqual(len(self.records), before)

    def test_message_prehash_is_distinct_from_digest_length_guard(self):
        for selector in ("shake256", 4):
            self.adapter.sign_prehash(b"message", bytes(64), selector)
            self.assertTrue(self.adapter.verify_prehash(b"message", bytes(2320), bytes(32), selector))
            self.assertEqual(self.records[-1][1:3], (4, b"message"))

    def subtree(self, ctx, kind, adrs, start, z, target, root, rcap, auth, acap):
        self.record("subtree", kind, start, z, target, rcap, acap)
        return 0

    def test_typed_memoryview_is_full_bytes_in_all_sign_modes(self):
        source = bytes.fromhex("0102030405060708")
        view = memoryview(source).cast("I")
        self.assertEqual(self.adapter.sign(view, bytes(64), context=view), bytes([0x42]) * 2320)
        self.assertEqual(self.records[-1], ("sign", source, source, 2320))
        self.adapter.sign_internal(view, bytes(64))
        self.assertEqual(self.records[-1], ("internal", source, 2320))
        self.adapter.sign_prehash(view, bytes(64), context=view)
        self.assertEqual(self.records[-1], ("prehash", 5, source, source))
        digest = memoryview(bytes(range(32))).cast("I")
        self.adapter.sign_digest(digest, bytes(64), context=view)
        self.assertEqual(self.records[-1][2:], (bytes(range(32)), source))

    def test_integer_wrapping_is_rejected_before_abi(self):
        for value in (2**32, -(2**32), 2**32 + 1, -1, 1025, True, 1.5):
            with self.assertRaises((TypeError, ValueError)):
                self.adapter.set_threads(value)
        for value in (2**32, -1, 11, True):
            with self.assertRaises((TypeError, ValueError)):
                self.adapter.set_cache_level(value)
        self.assertFalse(self.records)
        self.adapter.set_threads(0)
        self.adapter.set_threads(1024)
        self.adapter.set_cache_level(10)
        self.assertEqual(self.records, [("threads", 0), ("threads", 1024), ("level", 10)])

    def test_invalid_subtree_never_allocates_or_calls_abi(self):
        invalid = [(2**32, 0, None), (0, 2**32, None), (0, 11, None),
                   (1, 2, None), (0, 2, 4), (0, 2, 2**32), (6144, 0, None)]
        with patch.object(native, "_buffer", side_effect=AssertionError("allocated")):
            for start, z, target in invalid:
                with self.assertRaises((ValueError, TypeError)):
                    self.adapter.subtree("fors", bytes(32), start, z, target)
        self.assertFalse(self.records)
        self.adapter.subtree("fors", bytes(32), 1024, 4, 1029)
        self.assertEqual(self.records[-1], ("subtree", 1, 1024, 4, 1029, 16, 64))

    def test_invalid_buffers_and_context_rejected(self):
        for value in (8, [1, 2], "text"):
            with self.assertRaises(TypeError):
                self.adapter.sign(value, bytes(64))
        with self.assertRaises(ValueError):
            self.adapter.sign(b"m", bytes(64), context=bytes(256))
        with self.assertRaises(ValueError):
            self.adapter.sign_digest(bytes(31), bytes(64))
        self.assertFalse(self.records)

    def test_native_secret_buffers_wiped_on_success_and_failure(self):
        held = []
        original = native._buffer
        def capture(data, length=None, label="input"):
            buf = original(data, length, label)
            if label in ("sk", "addrnd"):
                held.append(buf)
            return buf
        with patch.object(native, "_buffer", side_effect=capture):
            self.adapter.sign(b"m", bytes([9]) * 64, addrnd=bytes([7]) * 16)
        self.assertTrue(all(not any(buf) for buf in held))
        held.clear()
        self.attach("slh_sign_checked", [native.VOID, native.U8P, ct.c_size_t,
            ct.POINTER(ct.c_size_t), native.U8P, ct.c_size_t, native.U8P,
            ct.c_size_t, native.U8P, native.U8P], lambda *args: -5)
        with patch.object(native, "_buffer", side_effect=capture):
            with self.assertRaises(native.NativeError):
                self.adapter.sign(b"m", bytes([9]) * 64, addrnd=bytes([7]) * 16)
        self.assertTrue(all(not any(buf) for buf in held))

    def test_bad_abi_rejected_before_configure_or_context(self):
        def library(version):
            fn = SimpleNamespace()
            class Query:
                def __call__(self):
                    return version
            fn.slh_abi_version = Query()
            return fn
        for version in (0x00010000, 0x00020000):
            with patch.object(native.ct, "CDLL", return_value=library(version)):
                with self.assertRaisesRegex(RuntimeError, "ABI mismatch"):
                    native.NativeSlhDsa(library="mock")
        with patch.object(native.ct, "CDLL", return_value=SimpleNamespace()):
            with self.assertRaisesRegex(RuntimeError, "version query missing"):
                native.NativeSlhDsa(library="mock")

    def test_partial_keygen_input_allocation_is_wiped(self):
        held = []
        original = native._buffer
        def capture(data, length=None, label="input"):
            buffer = original(data, length, label)
            if label == "sk_seed":
                held.append(buffer)
            return buffer
        with patch.object(native, "_buffer", side_effect=capture):
            with self.assertRaises(ValueError):
                self.adapter.keygen_internal(bytes([9]) * 16, bytes(15), bytes(16))
        self.assertEqual(len(held), 1)
        self.assertFalse(any(held[0]))


if __name__ == "__main__":
    unittest.main()
