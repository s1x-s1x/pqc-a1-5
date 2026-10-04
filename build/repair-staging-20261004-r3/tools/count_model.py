"""Exact *implemented-path* counters for the stage-1 scalar engine.

This model predicts the seven public counters, not elapsed time or a mean
WOTS cost.  It uses integer tree formulas and the actual WOTS message/checksum
digits recovered from a supplied signature.  Recovering those messages walks
only verification paths; it never builds a FORS or XMSS tree.
"""

import argparse
from dataclasses import asdict, dataclass
import hashlib
import importlib.util
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
FIELDS = ("prf", "prf_msg", "h_msg", "f", "h", "t", "compress")


@dataclass(frozen=True)
class Parameter:
    pid: int
    sm3: int
    h: int
    d: int
    hp: int
    a: int
    k: int
    lgw: int
    length: int
    m: int
    n: int = 16

    @property
    def maximum_digit(self):
        return (1 << self.lgw) - 1

    @property
    def chain_capacity(self):
        return self.length * self.maximum_digit

    @property
    def signature_bytes(self):
        return self.n * (1 + self.k * (1 + self.a) + self.h + self.d * self.length)


def parameters(source=ROOT / "c/src/engine.c"):
    """Read the implemented parameter table, without executing the C library."""
    text = Path(source).read_text(encoding="utf-8")
    match = re.search(r"static const param parameters\[\]\s*=\s*\{(.*?)\};", text, re.S)
    if not match:
        raise ValueError("engine parameter table was not found")
    result = {}
    for row in re.findall(r"\{\s*((?:\d+\s*,\s*){9}\d+)\s*\}", match.group(1)):
        p = Parameter(*map(int, row.split(",")))
        if p.h != p.d * p.hp or 8 * p.n % p.lgw:
            raise ValueError("model supports the implemented integral WOTS digit widths")
        result[p.pid] = p
    if not result:
        raise ValueError("engine parameter table is empty")
    return result


def hash_compressions(length):
    """Number of 64-byte MD blocks including 0x80 and the 8-byte length."""
    if length < 0:
        raise ValueError("negative hash input length")
    return (length + 72) // 64


def empty_counts():
    return dict.fromkeys(FIELDS, 0)


def add_counts(*vectors):
    return {field: sum(vector[field] for vector in vectors) for field in FIELDS}


def component(p, name, *, prf=0, f=0, h=0, t_wots=0, t_fors=0,
              prf_msg=0, h_msg=0, midstate=0, message_length=0, **details):
    # PK.seed || zero[48] is already compressed once by init_work.  A copied
    # midstate is free, so thash only charges blocks of ADRSc || input.
    compression = {
        "midstate": midstate,
        "prf": prf * hash_compressions(22 + p.n),
        "f": f * hash_compressions(22 + p.n),
        "h": h * hash_compressions(22 + 2 * p.n),
        "t_wots": t_wots * hash_compressions(22 + p.length * p.n),
        "t_fors": t_fors * hash_compressions(22 + p.k * p.n),
        "prf_msg": prf_msg * (hash_compressions(64 + p.n + message_length)
                               + hash_compressions(64 + 32)),
        "h_msg": h_msg * (hash_compressions(3 * p.n + message_length)
                           + ((p.m + 31) // 32) * hash_compressions(2 * p.n + 32 + 4)),
    }
    counters = dict(prf=prf, prf_msg=prf_msg, h_msg=h_msg, f=f, h=h,
                    t=t_wots + t_fors, compress=sum(compression.values()))
    return {"name": name, "counts": counters, "compression": compression, **details}


def tree_component(p, kind, height, name="tree"):
    leaves = 1 << height
    if kind == "wots":
        return component(p, name, prf=leaves * p.length,
                         f=leaves * p.chain_capacity, h=leaves - 1,
                         t_wots=leaves, height=height, leaves=leaves)
    if kind == "fors":
        return component(p, name, prf=leaves, f=leaves, h=leaves - 1,
                         height=height, leaves=leaves)
    raise ValueError("tree kind must be wots or fors")


def prediction(p, operation, components, **metadata):
    return {"model": "stage1-implemented-path-v1", "pid": p.pid,
            "operation": operation, "parameters": asdict(p),
            "counts": add_counts(*(item["counts"] for item in components)),
            "components": components, "metadata": metadata}


def treehash_schedule(height, threads):
    """Native scheduling rule. Splitting changes work placement, not totals."""
    if threads < 1:
        raise ValueError("supply the resolved positive thread allocation")
    split = 0
    while split < height and split < 10 and (1 << split) < threads * 4:
        split += 1
    if threads <= 1 or height < 5:
        split = 0
    chunks = 1 << split
    sub = height - split
    return {"requested_threads": threads, "split_bits": split, "chunks": chunks,
            "chunk_height": sub, "hashes_inside_chunks": chunks * ((1 << sub) - 1),
            "hashes_combining_chunks": chunks - 1,
            "total_internal_hashes": (1 << height) - 1}


def keygen_model(p, threads=1, cache_t=None, operation="keygen"):
    return prediction(p, operation, [component(p, "init_work", midstate=1),
                      tree_component(p, "wots", p.hp, "top_xmss_full_tree")],
                      threads=threads, cache_t=cache_t,
                      schedule=treehash_schedule(p.hp, threads),
                      cache_level_changes_storage_only=True)


def subtree_model(p, kind, height, threads=1):
    if not 0 <= height <= (p.hp if kind == "wots" else p.a):
        raise ValueError("height exceeds the implemented parameter")
    return prediction(p, "subtree", [component(p, "init_work", midstate=1),
                      tree_component(p, kind, height)],
                      kind=kind, height=height,
                      schedule=treehash_schedule(height, threads),
                      authentication_target_does_not_change_counts=True)


def cache_model(p, operation, cache_t, threads=1):
    if not 0 <= cache_t <= p.hp:
        raise ValueError("cache level is outside the parameter")
    payload = (1 << (p.hp - cache_t)) * p.n
    memory = ((1 << (p.hp - cache_t + 1)) - 1) * p.n
    if operation == "cache_build":
        result = keygen_model(p, threads, cache_t, operation)
    elif operation == "cache_save":
        result = prediction(p, operation, [])
    elif operation == "cache_load":
        result = prediction(p, operation, [component(p, "init_work", midstate=1),
                            component(p, "rebuild_upper_public_nodes",
                                      h=(1 << (p.hp - cache_t)) - 1)])
    else:
        raise ValueError("unknown cache operation")
    result["metadata"].update({"cache_t": cache_t, "payload_bytes": payload,
                              "file_bytes": 96 + payload, "node_ram_bytes": memory,
                              "cache_checksum_compressions_uninstrumented":
                              hash_compressions(64 + payload) if operation != "cache_build" else 0,
                              "checksum_in_public_compress_counter": False})
    return result


def verify_model(p, message_length, chain_sums):
    _check_chain_sums(p, chain_sums)
    parts = [component(p, "init_work", midstate=1),
             component(p, "message_digest", h_msg=1, message_length=message_length),
             component(p, "fors_from_signature", f=p.k, h=p.k * p.a, t_fors=1)]
    for layer, steps in enumerate(chain_sums):
        parts.append(component(p, "xmss_from_signature", f=p.chain_capacity - steps,
                               h=p.hp, t_wots=1, layer=layer,
                               actual_sign_chain_steps=steps,
                               actual_verify_chain_steps=p.chain_capacity - steps))
    return prediction(p, "verify", parts, message_length=message_length,
                      actual_chain_sums=list(chain_sums), root_reconstruction_layers=p.d)


def _check_chain_sums(p, chain_sums):
    if len(chain_sums) != p.d or any(not 0 <= value <= p.chain_capacity for value in chain_sums):
        raise ValueError("one actual WOTS chain-step sum is required for every layer")


def sign_model(p, message_length, chain_sums, cache_t=None, threads=1,
               verify_after_sign=False):
    """cache_t=None means no eligible cache; only the top XMSS is cached."""
    _check_chain_sums(p, chain_sums)
    if cache_t is not None and not 0 <= cache_t <= p.hp:
        raise ValueError("cache level is outside the parameter")
    parts = [component(p, "init_work", midstate=1),
             component(p, "message_primitives", prf_msg=1, h_msg=1,
                       message_length=message_length),
             component(p, "fors_full_trees_and_selected_secrets",
                       prf=p.k * ((1 << p.a) + 1), f=p.k * (1 << p.a),
                       h=p.k * ((1 << p.a) - 1), t_fors=1,
                       root_reuse=True, selected_secret_prf=p.k)]
    for layer, steps in enumerate(chain_sums):
        limit = cache_t if cache_t is not None and layer == p.d - 1 else p.hp
        leaves = (1 << limit) - 1
        parts.append(component(p, "xmss_authentication_sibling_subtrees",
                               prf=leaves * p.length, f=leaves * p.chain_capacity,
                               h=leaves - limit, t_wots=leaves, layer=layer,
                               uncached_heights=list(range(limit)),
                               leaves=leaves,
                               schedules=[treehash_schedule(j, threads) for j in range(limit)]))
        parts.append(component(p, "wots_signature", prf=p.length, f=steps, layer=layer,
                               actual_sign_chain_steps=steps))
        if layer + 1 < p.d:
            parts.append(component(p, "xmss_root_for_next_layer",
                                   f=p.chain_capacity - steps, h=p.hp, t_wots=1,
                                   layer=layer,
                                   actual_verify_chain_steps=p.chain_capacity - steps))
    if verify_after_sign:
        parts.extend({**item, "name": "post_sign_verify/" + item["name"]}
                     for item in verify_model(p, message_length, chain_sums)["components"])
    return prediction(p, "sign", parts, message_length=message_length,
                      actual_chain_sums=list(chain_sums), eligible_top_cache_t=cache_t,
                      threads=threads, verify_after_sign=verify_after_sign,
                      fors_root_reuse=True, xmss_root_reconstruction_layers=p.d - 1,
                      fors_schedule=(treehash_schedule(p.a, threads) if p.a >= 16 else
                                     {"trees_parallel": p.k, "within_tree_threads": 1}))


def digits(data, width, length):
    if length * width > 8 * len(data):
        raise ValueError("insufficient digit input")
    value = int.from_bytes(data, "big")
    total = 8 * len(data)
    mask = (1 << width) - 1
    return [(value >> (total - (j + 1) * width)) & mask for j in range(length)]


def wots_digits(p, message):
    if len(message) != p.n:
        raise ValueError("WOTS message must be n bytes")
    l1 = 8 * p.n // p.lgw
    l2 = p.length - l1
    result = digits(message, p.lgw, l1)
    checksum = sum(p.maximum_digit - value for value in result)
    shift = (8 - (l2 * p.lgw) % 8) % 8
    encoded = (checksum << shift).to_bytes((l2 * p.lgw + 7) // 8, "big")
    return result + digits(encoded, p.lgw, l2)


_SM3_FALLBACK = None


def hash_digest(p, data):
    if not p.sm3:
        return hashlib.sha256(data).digest()
    if "sm3" in hashlib.algorithms_available:
        return hashlib.new("sm3", data).digest()
    global _SM3_FALLBACK
    if _SM3_FALLBACK is None:
        spec = importlib.util.spec_from_file_location("a15_count_sm3", ROOT / "reference/sm3.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _SM3_FALLBACK = module.Sm3
    return _SM3_FALLBACK(data).digest()


def _put32(address, offset, value):
    address[offset:offset + 4] = value.to_bytes(4, "big")


def _set_type(address, kind, preserve_keypair=False):
    _put32(address, 16, kind)
    start = 24 if preserve_keypair else 20
    address[start:32] = bytes(32 - start)


def _set_tree(address, tree):
    address[8:16] = tree.to_bytes(8, "big")


def _thash(p, pkseed, address, data):
    compressed = address[3:4] + address[8:16] + address[19:32]
    return hash_digest(p, pkseed + bytes(64 - p.n) + compressed + data)[:p.n]


def signature_trace(p, encoded_message, signature, public_key):
    """Recover exact layer messages/digits using independent full-hash paths.

    This is not independent evidence of an entire signing implementation: it
    is an independently hashed, signature-dependent input for a count model.
    The recorded root comparison also detects an incorrect address trace.
    """
    if len(signature) != p.signature_bytes or len(public_key) != 2 * p.n:
        raise ValueError("signature/public key length does not match parameter")
    pkseed, pkroot = public_key[:p.n], public_key[p.n:]
    r = signature[:p.n]
    inner = hash_digest(p, r + public_key + encoded_message)
    seed = r + pkseed + inner
    digest = b"".join(hash_digest(p, seed + j.to_bytes(4, "big"))
                      for j in range((p.m + 31) // 32))[:p.m]
    choices = digits(digest, p.a, p.k)
    md = (p.k * p.a + 7) // 8
    tree_bits = p.h - p.hp
    tb = (tree_bits + 7) // 8
    tree = int.from_bytes(digest[md:md + tb], "big") & ((1 << tree_bits) - 1)
    leaf = int.from_bytes(digest[md + tb:md + tb + (p.hp + 7) // 8], "big") & ((1 << p.hp) - 1)
    address = bytearray(32)
    _set_tree(address, tree)
    _set_type(address, 3, True)
    _put32(address, 20, leaf)
    roots = []
    offset = p.n
    for i, choice in enumerate(choices):
        index = (i << p.a) + choice
        _put32(address, 24, 0)
        _put32(address, 28, index)
        node = _thash(p, pkseed, address, signature[offset:offset + p.n])
        offset += p.n
        for height in range(p.a):
            sibling = signature[offset:offset + p.n]
            offset += p.n
            _put32(address, 24, height + 1)
            _put32(address, 28, index >> (height + 1))
            pair = sibling + node if (choice >> height) & 1 else node + sibling
            node = _thash(p, pkseed, address, pair)
        roots.append(node)
    _set_type(address, 4, True)
    node = _thash(p, pkseed, address, b"".join(roots))
    address = bytearray(32)
    _set_tree(address, tree)
    layers = []
    for layer in range(p.d):
        _put32(address, 0, layer)
        values = wots_digits(p, node)
        layers.append({"layer": layer, "tree_index": tree, "leaf_index": leaf,
                       "message_hex": node.hex(), "digits": values,
                       "sign_chain_steps": sum(values),
                       "verify_chain_steps": p.chain_capacity - sum(values)})
        _set_type(address, 0, True)
        _put32(address, 20, leaf)
        public_chains = []
        for j, value in enumerate(values):
            _put32(address, 24, j)
            end = signature[offset:offset + p.n]
            offset += p.n
            for step in range(value, p.maximum_digit):
                _put32(address, 28, step)
                end = _thash(p, pkseed, address, end)
            public_chains.append(end)
        _set_type(address, 1, True)
        node = _thash(p, pkseed, address, b"".join(public_chains))
        _set_type(address, 2)
        for height in range(p.hp):
            sibling = signature[offset:offset + p.n]
            offset += p.n
            _put32(address, 24, height + 1)
            _put32(address, 28, leaf >> (height + 1))
            pair = sibling + node if (leaf >> height) & 1 else node + sibling
            node = _thash(p, pkseed, address, pair)
        leaf = tree & ((1 << p.hp) - 1)
        tree >>= p.hp
        _set_tree(address, tree)
    if offset != len(signature):
        raise AssertionError("signature trace consumed an unexpected byte count")
    return {"encoded_message_length": len(encoded_message), "h_msg_hex": digest.hex(),
            "fors_choices": choices, "layers": layers,
            "chain_sums": [layer["sign_chain_steps"] for layer in layers],
            "reconstructed_root_hex": node.hex(), "public_root_matches": node == pkroot}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, default=201)
    parser.add_argument("--operation", choices=("keygen", "subtree", "cache_build", "cache_save", "cache_load", "sign", "verify"), default="keygen")
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument("--cache-t", type=int)
    parser.add_argument("--kind", choices=("wots", "fors"), default="wots")
    parser.add_argument("--height", type=int, default=0)
    parser.add_argument("--message-hex", default="")
    parser.add_argument("--public-key-hex")
    parser.add_argument("--signature", type=Path)
    parser.add_argument("--verify-after-sign", action="store_true")
    args = parser.parse_args()
    p = parameters()[args.pid]
    if args.operation == "keygen":
        result = keygen_model(p, args.threads, args.cache_t)
    elif args.operation == "subtree":
        result = subtree_model(p, args.kind, args.height, args.threads)
    elif args.operation.startswith("cache_"):
        if args.cache_t is None:
            parser.error("cache operations require --cache-t")
        result = cache_model(p, args.operation, args.cache_t, args.threads)
    else:
        if args.signature is None or args.public_key_hex is None:
            parser.error("sign/verify predictions require --signature and --public-key-hex")
        mp = bytes.fromhex(args.message_hex)
        trace = signature_trace(p, mp, args.signature.read_bytes(), bytes.fromhex(args.public_key_hex))
        result = (sign_model(p, len(mp), trace["chain_sums"], args.cache_t,
                             args.threads, args.verify_after_sign) if args.operation == "sign" else
                  verify_model(p, len(mp), trace["chain_sums"]))
        result["actual_signature_trace"] = trace
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
