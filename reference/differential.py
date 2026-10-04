"""C ABI versus independent Python correctness evidence, with explicit scope."""

import argparse
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import random
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from reference import ADRS, ReferenceSlhDsa, encode_message
from reference.slhdsa import UPSTREAM_COMMIT
from tools.native import NativeSlhDsa
BACKENDS = {"auto": 0, "ref": 1, "avx2": 2}


def fingerprint(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def deterministic_rng(suite, index):
    label = "A1-5/differential/v1/{}/{}".format(suite, index)
    seed = hashlib.sha256(label.encode("ascii")).digest()
    return random.Random(int.from_bytes(seed, "big")), seed.hex()


def payload_hashes(payload):
    return {key: hashlib.sha256(value).hexdigest() for key, value in payload.items()}


def toy_case(job):
    index, library, threads, backend = job
    rng, random_seed = deterministic_rng("toy-complete", index)
    seeds = {field: rng.randbytes(16) for field in ("sk_seed", "sk_prf", "pk_seed")}
    context = rng.randbytes((0, 1, 15, 255)[index % 4])
    message = rng.randbytes((0, 1, 16, 31, 64, 257, 1024)[index % 7])
    opt_rand = None if index % 2 == 0 else rng.randbytes(16)
    encoded = encode_message(message, context)
    started = time.perf_counter()
    python = ReferenceSlhDsa(201)
    with NativeSlhDsa(201, threads=threads, flags=BACKENDS[backend], library=library) as native:
        selected_backend = native.backend
        pk, sk = python.keygen_internal(seeds["sk_seed"], seeds["sk_prf"], seeds["pk_seed"])
        native_pk, native_sk = native.keygen_internal(seeds["sk_seed"], seeds["sk_prf"], seeds["pk_seed"])
        signature = python.sign_internal(encoded, sk, opt_rand)
        native_signature = native.sign_internal(encoded, native_sk, opt_rand)
        checks = {"keygen_pk_equal": pk == native_pk, "keygen_sk_equal": sk == native_sk,
                  "signature_equal": signature == native_signature,
                  "python_valid": python.verify_internal(encoded, signature, pk),
                  "native_valid": native.verify_internal(encoded, signature, pk),
                  "native_pure_valid": native.verify(message, signature, pk, context)}
        changed = bytearray(signature)
        mutation_index = index % len(signature)
        changed[mutation_index] ^= 1 << (index % 8)
        for name, mp, sig in (("modified_message", encoded + b"!", signature),
                              ("modified_signature", encoded, bytes(changed)),
                              ("truncated_signature", encoded, signature[:-1]),
                              ("extended_signature", encoded, signature + b"\x00")):
            py_result = python.verify_internal(mp, sig, pk)
            c_result = native.verify_internal(mp, sig, pk)
            checks[name + "_rejected_both"] = py_result is False and c_result is False
        changed_context = bytes([context[0] ^ 1]) + context[1:] if context else b"!"
        checks["modified_context_rejected_both"] = (
            python.verify(message, signature, pk, changed_context) is False and
            native.verify(message, signature, pk, changed_context) is False)
        payload = {**seeds, "message": message, "context": context, "mp": encoded,
                   "opt_rand": opt_rand if opt_rand is not None else seeds["pk_seed"],
                   "pk": pk, "sk": sk, "sig": signature}
    return {"suite": "toy-complete", "case_id": "toy-complete-{}".format(index),
            "index": index, "pid": 201, "random_seed": random_seed,
            "randomization": "deterministic" if opt_rand is None else "explicit",
            "native_threads": threads, "backend_requested": backend, "backend_selected": selected_backend,
            "seconds": time.perf_counter() - started,
            "checks": checks, "passed": all(checks.values()),
            "mutation_index": mutation_index, "content_sha256": payload_hashes(payload),
            **{key: value.hex() for key, value in payload.items()}}


def subtree_case(job):
    index, library, _, backend = job
    rng, random_seed = deterministic_rng("subtree", index)
    pid = (201, 1, 2, 3, 101, 102, 103)[index % 7]
    python = ReferenceSlhDsa(pid)
    kind = "fors" if (index // 7) % 2 else "wots"
    maximum = python.a if kind == "fors" else python.hp
    height = min((index // 14) % 7, maximum)
    base_count = (python.k << python.a) if kind == "fors" else (1 << python.hp)
    leaf_start = rng.randrange(base_count >> height) << height
    target = None if index % 3 == 0 else leaf_start + rng.randrange(1 << height)
    seeds = {field: rng.randbytes(16) for field in ("sk_seed", "sk_prf", "pk_seed")}
    address = ADRS()
    address.set_layer_address(rng.randrange(python.d))
    tree_width = python.h - python.hp
    address.set_tree_address(rng.getrandbits(tree_width) if tree_width else 0)
    address.set_type_and_clear(ADRS.FORS_TREE if kind == "fors" else ADRS.WOTS_HASH)
    address.set_key_pair_address(rng.randrange(1 << python.hp))
    encoded_address = bytes(address.adrs())
    # Binding does not need a valid root: subtree only uses the three seed fields.
    secret_key = seeds["sk_seed"] + seeds["sk_prf"] + seeds["pk_seed"] + bytes(16)
    started = time.perf_counter()
    expected = python.subtree(kind, seeds["sk_seed"], seeds["pk_seed"],
                              address, leaf_start, height, target)
    with NativeSlhDsa(pid, threads=1, flags=BACKENDS[backend], library=library) as native:
        selected_backend = native.backend
        native.bind_key(secret_key)
        actual = native.subtree(kind, encoded_address, leaf_start, height, target)
        native.set_threads(4)
        threaded = native.subtree(kind, encoded_address, leaf_start, height, target)
    checks = {"root_equal": expected[0] == actual[0], "auth_equal": expected[1] == actual[1],
              "native_thread_count_equal": actual == threaded}
    payload = {**seeds, "adrs": encoded_address, "root": expected[0], "auth": expected[1]}
    return {"suite": "subtree", "case_id": "subtree-{}".format(index),
            "index": index, "pid": pid, "kind": kind, "height": height,
            "leaf_start": leaf_start, "target": target,
            "native_thread_counts": [1, 4], "backend_requested": backend,
            "backend_selected": selected_backend, "random_seed": random_seed,
            "seconds": time.perf_counter() - started, "checks": checks,
            "passed": all(checks.values()), "content_sha256": payload_hashes(payload),
            **{key: value.hex() for key, value in payload.items()}}


def complete_records(args, emit):
    source_hash = fingerprint(args.input)
    records = [json.loads(line) for line in args.input.read_text(encoding="utf-8").splitlines() if line]
    for record in records:
        original = dict(record)
        record_hash = original.pop("record_sha256")
        canonical = json.dumps(original, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if hashlib.sha256(canonical).hexdigest() != record_hash:
            raise ValueError("source reference record hash mismatch")
        pid = record["pid"]
        decode = lambda field: bytes.fromhex(record[field])
        python = ReferenceSlhDsa(pid)
        checks = {"python_verify": python.verify_internal(decode("mp"), decode("sig"), decode("pk"))}
        print(json.dumps({"phase": "native_keygen", "case_id": record["case_id"], "threads": args.threads}), flush=True)
        with NativeSlhDsa(pid, threads=args.threads, flags=BACKENDS[args.backend], library=args.library) as native:
            selected_backend = native.backend
            started = time.perf_counter()
            pk, sk = native.keygen_internal(decode("sk_seed"), decode("sk_prf"), decode("pk_seed"))
            keygen_seconds = time.perf_counter() - started
            checks.update({"keygen_pk_equal": pk == decode("pk"), "keygen_sk_equal": sk == decode("sk")})
            print(json.dumps({"phase": "native_sign", "case_id": record["case_id"], "keygen_seconds": keygen_seconds}), flush=True)
            started = time.perf_counter()
            randomizer = None if record["randomization"] == "deterministic" else decode("opt_rand")
            signature = native.sign_internal(decode("mp"), sk, randomizer)
            sign_seconds = time.perf_counter() - started
            checks.update({"signature_equal": signature == decode("sig"),
                           "native_verify": native.verify_internal(decode("mp"), signature, pk),
                           "native_pure_verify": native.verify(decode("message"), signature, pk, decode("context")),
                           "native_modified_message_rejected": native.verify_internal(decode("mp") + b"!", signature, pk) is False})
        emit({"suite": "sm3-128-24-complete", "case_id": record["case_id"] + "-differential",
              "pid": pid, "input_reference_record_sha256": record_hash,
              "input_reference_file_sha256": source_hash, "native_threads": args.threads,
              "backend_requested": args.backend, "backend_selected": selected_backend,
              "randomization": record["randomization"], "checks": checks,
              "passed": all(checks.values()), "signature_bytes": len(signature),
              "pk_sha256": hashlib.sha256(pk).hexdigest(),
              "sk_sha256": hashlib.sha256(sk).hexdigest(),
              "signature_sha256": hashlib.sha256(signature).hexdigest(),
              "timings_seconds": {"native_keygen": keygen_seconds, "native_sign": sign_seconds},
              "timing_scope": "diagnostic correctness run; not final performance evidence"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, default=ROOT / "build" / "libslhdsa_sm3.so")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=32)
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument("--backend", choices=BACKENDS, default="ref")
    subparsers = parser.add_subparsers(dest="suite", required=True)
    for name in ("toy", "subtree"):
        sub = subparsers.add_parser(name)
        sub.add_argument("--count", type=int, default=1000)
        sub.add_argument("--start-index", type=int, default=0)
    complete = subparsers.add_parser("complete")
    complete.add_argument("--input", type=Path, default=ROOT / "vectors" / "python-sm3-128-24.jsonl")
    args = parser.parse_args()
    args.library = args.library.resolve()
    if args.output.exists():
        raise SystemExit("output already exists; preserve evidence and select another path")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    library_hash = fingerprint(args.library)
    sources = {relative: fingerprint(ROOT / relative)
               for relative in ("reference/slhdsa.py", "reference/sm3.py", "reference/differential.py", "tools/native.py")}
    summary = {"schema": "a15-differential-summary-v1", "suite": args.suite,
               "upstream_python_commit": UPSTREAM_COMMIT, "sources_sha256": sources,
               "native_library_sha256": library_hash, "workers": args.workers,
               "backend_requested": args.backend, "selected_backend_counts": {},
               "native_threads": args.threads, "started_at_utc": datetime.now(timezone.utc).isoformat(),
               "total": 0, "passed": 0, "failed": 0,
               "scope": "independent implementation agreement; not a security proof or final benchmark"}
    started = time.perf_counter()
    with args.output.open("w", encoding="utf-8") as stream:
        def emit(record):
            record.update({"schema": "a15-differential-case-v1", "native_library_sha256": library_hash,
                           "sources_sha256": sources, "generated_at_utc": datetime.now(timezone.utc).isoformat()})
            record["record_sha256"] = hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            stream.write(json.dumps(record, sort_keys=True) + "\n")
            stream.flush()
            summary["total"] += 1
            selected = str(record["backend_selected"])
            summary["selected_backend_counts"][selected] = summary["selected_backend_counts"].get(selected, 0) + 1
            summary["passed" if record["passed"] else "failed"] += 1
            if not record["passed"] or summary["total"] % 32 == 0 or args.suite == "complete":
                print(json.dumps({"suite": args.suite, "completed": summary["total"],
                                  "failed": summary["failed"], "elapsed_seconds": time.perf_counter() - started}), flush=True)
        if args.suite == "complete":
            complete_records(args, emit)
        else:
            function = toy_case if args.suite == "toy" else subtree_case
            jobs = ((index, str(args.library), args.threads, args.backend)
                    for index in range(args.start_index, args.start_index + args.count))
            with ProcessPoolExecutor(max_workers=args.workers) as pool:
                for record in pool.map(function, jobs, chunksize=1):
                    emit(record)
    summary.update({"elapsed_seconds": time.perf_counter() - started,
                    "native_library_unchanged": library_hash == fingerprint(args.library),
                    "cases_jsonl_sha256": fingerprint(args.output)})
    summary_path = args.output.with_suffix(".summary.json")
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary), flush=True)
    return 0 if summary["failed"] == 0 and summary["native_library_unchanged"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
