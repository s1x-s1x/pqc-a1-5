"""Replay the preserved A/B/C inputs against one explicitly selected library."""
import argparse
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import time

from external_vectors import encoded_message
from native import NativeSlhDsa

ROOT = Path(__file__).resolve().parents[1]
BACKENDS = {"auto": 0, "ref": 1, "avx2": 2}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def check(job):
    case, library, threads, backend = job
    begin = time.monotonic()
    row = {key: case[key] for key in ("case_id", "vector_set", "suite", "pid", "operation")}
    row.update({"schema": "a15-external-recheck-v1", "threads": threads, "backend_requested": backend,
                "input_source": case["input_source"], "input_line": case["input_line"]})
    test, group = case["test"], case["group"]
    decode = lambda key: bytes.fromhex(test[key])
    try:
        with NativeSlhDsa(case["pid"], threads=threads, flags=BACKENDS[backend], library=library) as native:
            row["backend_selected"] = native.backend
            if case["operation"] == "keyGen":
                pk, sk = native.keygen_internal(decode("skSeed"), decode("skPrf"), decode("pkSeed"))
                checks = {"pk_equal": pk == decode("pk"), "sk_equal": sk == decode("sk")}
            elif case["operation"] == "sigGen":
                rnd = None if group["deterministic"] else decode("additionalRandomness")
                sig = native.sign_internal(encoded_message(group, test), decode("sk"), rnd)
                checks = {"signature_equal": sig == decode("signature")}
                row.update({"expected_signature_sha256": sha_bytes(decode("signature")),
                            "actual_signature_sha256": sha_bytes(sig)})
            else:
                actual = native.verify_internal(encoded_message(group, test), decode("signature"), decode("pk"))
                checks = {"verification_matches_expected": actual == test["testPassed"]}
                row.update({"expected": test["testPassed"], "actual": actual})
            row.update({"checks": checks, "passed": all(checks.values())})
    except Exception as error:
        row.update({"passed": False, "error": f"{type(error).__name__}: {error}"})
    row.update({"executed_at_utc": datetime.now(timezone.utc).isoformat(),
                "diagnostic_seconds": time.monotonic() - begin})
    return row


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=24)
    parser.add_argument("--large-threads", type=int, default=32)
    parser.add_argument("--backend", choices=BACKENDS, default="ref")
    args = parser.parse_args()
    if args.workers < 1 or args.large_threads < 1:
        parser.error("workers and large-threads must be positive")
    args.library = args.library.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    evidence = json.loads((ROOT / "validation/external-EVIDENCE.json").read_text(encoding="utf8"))
    cases, input_hashes = [], {}
    for suite in evidence["vector_sets"]:
        relative = suite["inputs_path"]
        path = ROOT / relative
        digest = sha(path)
        if digest != suite["inputs_sha256"]:
            raise ValueError(f"preserved input hash mismatch: {relative}")
        input_hashes[relative] = digest
        for relative_source, expected in suite["raw_sources_sha256"].items():
            if sha(ROOT / relative_source) != expected:
                raise ValueError(f"upstream source hash mismatch: {relative_source}")
        for number, line in enumerate(path.read_text(encoding="utf8").splitlines(), 1):
            case = json.loads(line)
            case.update({"input_source": relative, "input_line": number})
            cases.append(case)
    if len(cases) != evidence["total"] or len({c["case_id"] for c in cases}) != len(cases):
        raise ValueError("preserved case count or case identifiers differ")
    library_hash = sha(args.library)
    rows = []
    with args.output.open("x", encoding="utf8") as stream:
        def emit(row):
            row["library_sha256"] = library_hash
            row["record_sha256"] = sha_bytes(json.dumps(row, sort_keys=True, separators=(",", ":")).encode())
            stream.write(json.dumps(row, sort_keys=True) + "\n")
            stream.flush()
            rows.append(row)
        small = [c for c in cases if c["pid"] != 103]
        with ProcessPoolExecutor(max_workers=args.workers) as pool:
            for row in pool.map(check, ((c, str(args.library), 1, args.backend) for c in small)):
                emit(row)
        for case in (c for c in cases if c["pid"] == 103):
            print(json.dumps({"phase": "large_external", "case_id": case["case_id"]}), flush=True)
            emit(check((case, str(args.library), args.large_threads, args.backend)))
    counts = {}
    for row in rows:
        label = f"{row['vector_set']}/{row['pid']}/{row['operation']}"
        count = counts.setdefault(label, {"total": 0, "passed": 0})
        count["total"] += 1
        count["passed"] += int(row["passed"])
    summary = {"schema": "a15-external-recheck-summary-v1", "total": len(rows),
               "backend_requested": args.backend,
               "selected_backend_counts": {str(backend): sum(r.get("backend_selected") == backend for r in rows)
                                           for backend in (1, 2)},
               "passed": sum(r["passed"] for r in rows), "failed": sum(not r["passed"] for r in rows),
               "counts": counts, "library_sha256": library_hash,
               "library_unchanged": sha(args.library) == library_hash,
               "inputs_sha256": input_hashes, "results_sha256": sha(args.output),
               "sources_sha256": {p: sha(ROOT / p) for p in ("tools/recheck_external.py", "tools/native.py", "tools/external_vectors.py")},
               "affinity": sorted(os.sched_getaffinity(0)),
               "scope": "Same preserved 351 operation checks; a rerun adds no distinct vectors. Internal ABI with independently encoded pure/prehash inputs; timings are diagnostic."}
    args.output.with_suffix(".summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf8")
    print(json.dumps(summary), flush=True)
    return int(summary["failed"] != 0 or not summary["library_unchanged"])


if __name__ == "__main__":
    raise SystemExit(main())
