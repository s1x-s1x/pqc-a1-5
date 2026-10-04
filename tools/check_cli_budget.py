"""Execute file CLI round trips and concurrent crash-safe signing reservations."""
import argparse
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from signing_budget import BudgetError, SigningBudget

ROOT = Path(__file__).resolve().parents[1]


def reserve_worker(job):
    path, index = job
    ledger = SigningBudget(path)
    try:
        receipt = ledger.reserve("SLH-DSA-SM3-128-24", b"fixture public key", str(index).encode(), limit=17)
        # Some reservations deliberately simulate a crash and remain reserved.
        if index % 3:
            ledger.finish(receipt, b"signature" + str(index).encode())
        return {"index": index, "reserved": True}
    except BudgetError:
        return {"index": index, "reserved": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path)
    parser.add_argument("--budget-only", action="store_true", help="run the independent durable ledger check")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.budget_only and args.library is None:
        parser.error("--library is required for CLI checks")
    if args.output.exists():
        parser.error("output already exists; choose a fresh evidence filename")
    rows = []
    with tempfile.TemporaryDirectory(prefix="a15-cli-") as folder:
        work = Path(folder)
        budget = work / "concurrent.sqlite"
        SigningBudget(budget)
        with ProcessPoolExecutor(max_workers=8) as pool:
            reservations = list(pool.map(reserve_worker, ((str(budget), i) for i in range(40))))
        status = SigningBudget(budget).status()[0]
        rows.append({"case_id": "concurrent-budget", "attempts": 40,
                     "reserved": sum(r["reserved"] for r in reservations), "status": status,
                     "passed": sum(r["reserved"] for r in reservations) == 17 and status["used"] == 17
                               and status["remaining"] == 0 and status["count_reconciled"]})
        if args.budget_only:
            return write_summary(args, rows)
        common = [sys.executable, str(ROOT / "tools/cli.py"), "--pid", "201", "--library", str(args.library.resolve())]
        def run(case, command, expected=0):
            result = subprocess.run(common + command, text=True, capture_output=True)
            row = {"case_id": case, "command": command, "returncode": result.returncode,
                   "expected_returncode": expected, "stdout": result.stdout, "stderr": result.stderr,
                   "passed": result.returncode == expected}
            rows.append(row)
            if not row["passed"]:
                raise RuntimeError(row)
        prefix, cache, message = work / "key", work / "key.cache", work / "message.bin"
        message.write_bytes(b"\0binary CLI fixture\xff")
        run("keygen", ["keygen", str(prefix), "--seed-hex", bytes(range(48)).hex(), "--save-cache", str(cache), "--cache-level", "5"])
        run("keygen-overwrite", ["keygen", str(prefix)], 1)
        run("cache-load", ["cache-load", str(cache), str(prefix) + ".pk"])
        for alg in (None, "sm3", "sha256", "sha512", "shake128", "shake256"):
            signature = work / (f"signature-{alg}.bin")
            options = ["--prehash", alg] if alg else []
            run(f"sign-{alg}", ["sign", str(message), str(prefix) + ".sk", str(signature), "--context-hex", "aabb",
                "--load-cache", str(cache), "--budget-db", str(work / "sign.sqlite"), *options])
            run(f"verify-{alg}", ["verify", str(message), str(prefix) + ".pk", str(signature), "--context-hex", "aabb", *options])
            run(f"wrong-context-{alg}", ["verify", str(message), str(prefix) + ".pk", str(signature), "--context-hex", "aabc", *options], 2)
        status = SigningBudget(work / "sign.sqlite").status()[0]
        rows.append({"case_id": "CLI-budget-committed", "status": status,
                     "passed": status["used"] == 6 and status["states"] == {"committed": 6}})
    return write_summary(args, rows)


def write_summary(args, rows):
    summary = {"schema": "a15-cli-budget-v1", "timestamp_utc": datetime.now(timezone.utc).isoformat(),
               "total": len(rows), "passed": sum(r["passed"] for r in rows),
               "failed": sum(not r["passed"] for r in rows), "results": rows,
               "library_sha256": hashlib.sha256(args.library.read_bytes()).hexdigest() if args.library else None,
               "sources_sha256": {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest()
                                  for p in ("tools/cli.py", "tools/signing_budget.py", "tools/native.py", "tools/check_cli_budget.py")}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf8") as stream:
        stream.write(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k not in ("results", "sources_sha256")}))
    return int(summary["failed"] != 0)


if __name__ == "__main__":
    raise SystemExit(main())
