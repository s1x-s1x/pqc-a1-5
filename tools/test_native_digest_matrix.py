"""Real adapter/ABI digest matrix with toy parameters; correctness only."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from native import NativeSlhDsa, PREHASH, PREHASH_BYTES


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    message = b"A1-5 digest interface independent matrix"
    context = b"review"
    rows = []
    with NativeSlhDsa(pid=201, threads=1, flags=1, library=args.library) as native:
        pk, sk = native.keygen_internal(bytes(range(16)), bytes(range(16, 32)), bytes(range(32, 48)))
        for name, identifier in PREHASH.items():
            h = hashlib.new(name, message)
            digest = h.digest(PREHASH_BYTES[identifier]) if name.startswith("shake") else h.digest()
            for selector in (name, identifier):
                signature = native.sign_digest(digest, sk, hash_alg=selector, context=context, addrnd=bytes(16))
                assert native.verify_digest(digest, signature, pk, hash_alg=selector, context=context)
                changed = bytes([digest[0] ^ 1]) + digest[1:]
                assert not native.verify_digest(changed, signature, pk, hash_alg=selector, context=context)
                assert not native.verify_digest(digest, signature, pk, hash_alg=selector, context=b"changed")
                assert native.verify_prehash(message, signature, pk, hash_alg=selector, context=context)
                assert signature == native.sign_prehash(message, sk, hash_alg=selector, context=context, addrnd=bytes(16))
                for length in (len(digest) - 1, len(digest) + 1):
                    for op in ("sign", "verify"):
                        try:
                            if op == "sign":
                                native.sign_digest(bytes(length), sk, hash_alg=selector)
                            else:
                                native.verify_digest(bytes(length), signature, pk, hash_alg=selector)
                        except ValueError:
                            pass
                        else:
                            raise AssertionError("wrong digest length accepted")
                rows.append(dict(algorithm=name, selector=selector, digest_bytes=len(digest), passed=True))
    record = dict(schema="a15-native-digest-matrix-v1", passed=True, rows=rows, pid=201, backend="REF",
                  library_sha256=hashlib.sha256(args.library.read_bytes()).hexdigest(),
                  adapter_sha256=hashlib.sha256((Path(__file__).parent / "native.py").read_bytes()).hexdigest(),
                  created_utc=datetime.now(timezone.utc).isoformat(), formal_performance_started=False, real_timing_samples=0)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": True, "algorithm_selector_paths": len(rows), "real_timing_samples": 0}))


if __name__ == "__main__":
    main()
