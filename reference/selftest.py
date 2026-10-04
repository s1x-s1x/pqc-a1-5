"""Bounded model checks; full 128-24 signing is deliberately outside these tests."""

import hashlib
import random
import unittest

from .slhdsa import ADRS, PARAMETERS, ReferenceSlhDsa, _upstream, encode_message
from .sm3 import Sm3


class ModelTests(unittest.TestCase):
    def test_sm3_standard_and_copy(self):
        examples = [
            (b"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
            (b"abcd" * 16, "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"),
        ]
        for message, expected in examples:
            self.assertEqual(Sm3(message).hexdigest(), expected)
        for length in (0, 1, 55, 56, 63, 64, 65, 119, 120, 128, 1024):
            message = bytes(i % 256 for i in range(length))
            left = Sm3(message[:length // 2])
            right = left.copy()
            right.update(message[length // 2:])
            self.assertEqual(right.digest(), hashlib.new("sm3", message).digest())
            self.assertEqual(left.digest(), hashlib.new("sm3", message[:length // 2]).digest())

    def test_parameters(self):
        expected = {1: (35, 7856), 2: (35, 17088), 3: (68, 3856),
                    101: (35, 7856), 102: (35, 17088), 103: (68, 3856),
                    201: (68, 2320)}
        for pid, dimensions in expected.items():
            model = ReferenceSlhDsa(pid)
            self.assertEqual((model.len, model.sig_sz), dimensions)
            self.assertEqual((model.pk_sz, model.sk_sz), (32, 64))
        self.assertEqual(PARAMETERS[3][1:], PARAMETERS[103][1:])
        model = ReferenceSlhDsa(3)
        self.assertEqual(model.split_digest(bytes(range(21))),
                         (bytes(range(18)), 0, int.from_bytes(bytes([18, 19, 20]), "big") & ((1 << 22) - 1)))
        self.assertEqual(model.base_2b(bytes.fromhex("ffffff123456000001"), 24, 3),
                         [0xFFFFFF, 0x123456, 1])

    def test_compressed_address(self):
        address = ADRS(bytes(range(32)))
        self.assertEqual(bytes(address.adrsc()), bytes([3]) + bytes(range(8, 16)) +
                         bytes([19]) + bytes(range(20, 32)))

    def test_midstate_matches_full_prefix(self):
        seed = bytes(range(16))
        address = ADRS(bytes(range(32)))
        for pid in (3, 103):
            model = ReferenceSlhDsa(pid)
            for length in (16, 32, 96, 1088):
                payload = bytes(i % 256 for i in range(length))
                expected = model._digest(seed + bytes(48) + address.adrsc() + payload)[:16]
                self.assertEqual(model._thash(seed, address, payload), expected)
        self.assertEqual(encode_message(b"message", b"ctx"), b"\x00\x03ctxmessage")
        with self.assertRaises(ValueError):
            encode_message(b"", bytes(256))

    def test_treehash_matches_recursive(self):
        rng = random.Random(426)
        model = ReferenceSlhDsa(201)
        for kind in ("wots", "fors"):
            for height, start in ((0, 4), (1, 6), (3, 16), (4, 32)):
                address = ADRS()
                address.set_layer_address(0)
                address.set_tree_address(17)
                address.set_type_and_clear(ADRS.FORS_TREE)
                address.set_key_pair_address(29)
                seed = rng.randbytes(16)
                public_seed = rng.randbytes(16)
                target = start + rng.randrange(1 << height)
                root, auth = model.subtree(kind, seed, public_seed, address, start, height, target)
                node = model.xmss_node if kind == "wots" else model.fors_node
                expected = node(seed, start >> height, height, public_seed, address.copy())
                self.assertEqual(root, expected)
                for level in range(height):
                    sibling = node(seed, (target >> level) ^ 1, level, public_seed, address.copy())
                    self.assertEqual(auth[level * 16:(level + 1) * 16], sibling)

    def test_parallel_indexed_merge(self):
        sequential = ReferenceSlhDsa(201)
        with ReferenceSlhDsa(201, workers=2, task_height=3,
                             parallel_min_height=4) as parallel:
            for kind in ("wots", "fors"):
                address = ADRS()
                address.set_tree_address(987)
                address.set_type_and_clear(ADRS.FORS_TREE)
                address.set_key_pair_address(1019)
                for target in (None, 64, 71, 123, 127):
                    args = (kind, bytes(range(16)), bytes(range(16, 32)), address, 64, 6, target)
                    self.assertEqual(sequential.subtree(*args), parallel.subtree(*args))
            seeds = (bytes(range(16)), bytes(range(16, 32)), bytes(range(32, 48)))
            pk, sk = sequential.keygen_internal(*seeds)
            self.assertEqual(parallel.keygen_internal(*seeds), (pk, sk))
            for randomizer in (None, bytes(range(48, 64))):
                signature = sequential.sign(b"parallel-toy", sk, b"context", randomizer)
                self.assertEqual(parallel.sign(b"parallel-toy", sk, b"context", randomizer), signature)
                self.assertTrue(parallel.verify(b"parallel-toy", signature, pk, b"context"))
                self.assertFalse(parallel.verify(b"parallel-toy!", signature, pk, b"context"))
                self.assertFalse(parallel.verify(b"parallel-toy", signature[:-1], pk, b"context"))

    def test_original_sha256_anchor(self):
        seeds = (bytes(range(16)), bytes(range(16, 32)), bytes(range(32, 48)))
        for pid, name in ((101, "SLH-DSA-SHA2-128s"), (102, "SLH-DSA-SHA2-128f")):
            model = ReferenceSlhDsa(pid)
            upstream = _upstream.SLH_DSA(name)
            pk, sk = model.keygen_internal(*seeds)
            self.assertEqual(upstream.slh_keygen_internal(*seeds), (pk, sk))
            encoded = encode_message(b"upstream-anchor", b"model")
            randomizer = bytes(range(48, 64))
            signature = model.sign_internal(encoded, sk, randomizer)
            self.assertEqual(signature, upstream.slh_sign_internal(encoded, sk, randomizer))
            self.assertTrue(upstream.slh_verify_internal(encoded, signature, pk))
            self.assertTrue(model.verify_internal(encoded, signature, pk))

    def test_python_sm3_fallback(self):
        native = ReferenceSlhDsa(201)
        fallback = ReferenceSlhDsa(201, force_python_sm3=True)
        address = ADRS()
        seeds = (bytes(range(16)), bytes(range(16, 32)))
        for kind in ("wots", "fors"):
            self.assertEqual(native.subtree(kind, *seeds, address, 0, 1, 1),
                             fallback.subtree(kind, *seeds, address, 0, 1, 1))
        self.assertEqual(native._prf_msg(*seeds, b"test"), fallback._prf_msg(*seeds, b"test"))
        self.assertEqual(native._h_msg(seeds[0], seeds[1], bytes(16), b"test"),
                         fallback._h_msg(seeds[0], seeds[1], bytes(16), b"test"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
