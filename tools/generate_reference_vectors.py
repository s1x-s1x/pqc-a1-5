"""Generate reproducible Python-only keygen/sign/verify JSONL evidence."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from reference import ADRS, ReferenceSlhDsa, encode_message
from reference.slhdsa import UPSTREAM_COMMIT


def _seed(pid, index, field):
    label = "A1-5/reference/v1/{}/{}/{}".format(pid, index, field)
    return hashlib.sha256(label.encode("ascii")).digest()[:16]


def _fingerprints():
    paths = ["reference/slhdsa.py", "reference/sm3.py",
             "third_party/py-acvp-pqc/fips205.py", "tools/generate_reference_vectors.py"]
    return {relative: hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
            for relative in paths}


def smoke(args):
    with ReferenceSlhDsa(args.pid, workers=args.workers,
                         task_height=args.task_height) as model:
        address = ADRS()
        address.set_type_and_clear(ADRS.FORS_TREE if args.kind == "fors" else ADRS.WOTS_HASH)
        address.set_key_pair_address(37)
        seed, public_seed = _seed(args.pid, 0, "sk_seed"), _seed(args.pid, 0, "pk_seed")
        started = time.perf_counter()
        root, auth = model.subtree(args.kind, seed, public_seed, address,
                                  0, args.height, 13 if args.height >= 4 else 0)
        elapsed = time.perf_counter() - started
        print(json.dumps({"type": "subtree_timing", "pid": args.pid,
                          "kind": args.kind, "height": args.height,
                          "leaves": 1 << args.height, "workers": args.workers,
                          "hash_backend": model.hash_backend, "seconds": elapsed,
                          "aggregate_leaves_per_second": (1 << args.height) / elapsed,
                          "root": root.hex(), "auth": auth.hex(),
                          "note": "diagnostic timing, includes process startup"}), flush=True)


def vectors(args):
    destination = args.output.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and not args.append:
        raise SystemExit("output exists; select another path or use --append with --start-index")
    sources = _fingerprints()
    with ReferenceSlhDsa(args.pid, workers=args.workers,
                         task_height=args.task_height) as model, destination.open("a", encoding="utf-8") as stream:
        for index in range(args.start_index, args.start_index + args.count):
            seeds = {field: _seed(args.pid, index, field)
                     for field in ("sk_seed", "sk_prf", "pk_seed")}
            message = ("A1-5 complete seeded reference case {}:{}".format(args.pid, index)).encode("ascii")
            message += bytes(range(64)) * (index + 1)
            context = b"A1-5 stage1"
            encoded = encode_message(message, context)
            randomizer = _seed(args.pid, index, "addrnd") if index % 2 else None
            print(json.dumps({"type": "progress", "pid": args.pid,
                              "index": index, "phase": "keygen"}), flush=True)
            started = time.perf_counter()
            pk, sk = model.keygen_internal(seeds["sk_seed"], seeds["sk_prf"], seeds["pk_seed"])
            keygen_seconds = time.perf_counter() - started
            print(json.dumps({"type": "progress", "pid": args.pid,
                              "index": index, "phase": "sign", "keygen_seconds": keygen_seconds}), flush=True)
            started = time.perf_counter()
            signature = model.sign_internal(encoded, sk, randomizer)
            sign_seconds = time.perf_counter() - started
            started = time.perf_counter()
            if not model.verify_internal(encoded, signature, pk):
                raise AssertionError("generated signature did not verify")
            if model.verify_internal(encoded + b"!", signature, pk):
                raise AssertionError("modified message unexpectedly verified")
            verify_seconds = time.perf_counter() - started
            payload = {"message": message, "context": context, "mp": encoded,
                       "opt_rand": randomizer if randomizer is not None else seeds["pk_seed"],
                       "pk": pk, "sk": sk, "sig": signature, **seeds}
            record = {
                "schema": "a15-reference-v1", "case_id": "python-{}-{}".format(args.pid, index),
                "pid": args.pid, "index": index, "mode": "pure",
                "randomization": "explicit" if randomizer is not None else "deterministic",
                "upstream_commit": UPSTREAM_COMMIT, "sources_sha256": sources,
                "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                "python": platform.python_version(), "hash_backend": model.hash_backend,
                "workers": args.workers, "task_height": args.task_height,
                "timings_seconds": {"keygen": keygen_seconds, "sign": sign_seconds,
                                    "verify_and_negative_message": verify_seconds},
                "content_sha256": {key: hashlib.sha256(value).hexdigest() for key, value in payload.items()},
                **{key: value.hex() for key, value in payload.items()},
            }
            canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
            record["record_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            stream.write(json.dumps(record, sort_keys=True) + "\n")
            stream.flush()
            print(json.dumps({"type": "completed", "case_id": record["case_id"],
                              "signature_bytes": len(signature), "record_sha256": record["record_sha256"],
                              "timings_seconds": record["timings_seconds"]}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, default=3)
    parser.add_argument("--workers", type=int, default=48)
    parser.add_argument("--task-height", type=int, default=14)
    subparsers = parser.add_subparsers(dest="command", required=True)
    measure = subparsers.add_parser("smoke")
    measure.add_argument("--kind", choices=("wots", "fors"), default="fors")
    measure.add_argument("--height", type=int, default=14)
    generate = subparsers.add_parser("vectors")
    generate.add_argument("--count", type=int, default=3)
    generate.add_argument("--start-index", type=int, default=0)
    generate.add_argument("--output", type=Path, default=ROOT / "vectors" / "python-sm3-128-24.jsonl")
    generate.add_argument("--append", action="store_true")
    args = parser.parse_args()
    if args.command == "smoke":
        smoke(args)
    else:
        vectors(args)


if __name__ == "__main__":
    main()
