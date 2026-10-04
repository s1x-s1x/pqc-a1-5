"""Synthetic SQLite VM instruction evidence, zero native or elapsed samples."""
from itertools import count
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
import signing_budget
from test_friend_budget_scalability import (SigningBudget, ALGORITHM, PUBLIC, MESSAGE,
                                    STAMP, seed_identity_v2, count_vm)


class SyntheticClock:
    @staticmethod
    def now(_timezone):
        return SimpleNamespace(isoformat=lambda: STAMP)


def measure(budget, operation):
    with count_vm(budget) as (vm, sql):
        value = operation()
    return value, {"vm_opcodes": vm["opcodes"],
                   "count_queries": sum("COUNT(" in s.upper() for s in sql),
                   "history_scan_queries": sum("FROM RESERVATIONS" in s.upper() and "WHERE" not in s.upper() for s in sql)}


def main():
    serial = count(1)
    rows = []
    with tempfile.TemporaryDirectory(prefix="a15-b03-vm-") as temp, \
            patch.object(signing_budget, "datetime", SyntheticClock), \
            patch.object(signing_budget.uuid, "uuid4", side_effect=lambda: SimpleNamespace(hex=f"{next(serial):032x}")), \
            patch("time.perf_counter_ns", side_effect=AssertionError("performance timer forbidden")):
        for history in (1, 10, 100, 1000, 10000):
            path = Path(temp) / f"synthetic-{history}.sqlite"
            limit = max(history + 2, 3)
            seed_identity_v2(path, history, limit=limit)
            budget = SigningBudget(path)
            receipt, reserve = measure(budget, lambda: budget.reserve(ALGORITHM, PUBLIC, MESSAGE, limit=limit))
            _, validate = measure(budget, lambda: budget.validate_receipt(receipt, statuses=("reserved",)))
            _, finish = measure(budget, lambda: budget.finish(receipt, b"synthetic signature"))
            batches = {}
            for length in sorted({1, min(10, history), min(100, history), min(1000, history)}):
                requests = [{"receipt": f"synthetic-{i}", "statuses": ("reserved",)} for i in range(1, length + 1)]
                _, evidence = measure(budget, lambda: budget.validate_receipts(requests))
                batches[str(length)] = evidence
            audit_result, audit = measure(budget, budget.audit)
            rows.append({"history_before": history, "reserve": reserve, "validate": validate,
                         "finish": finish, "batches": batches, "explicit_full_audit": audit,
                         "audit": audit_result})
    result = {"schema": "a15-b03-guarded-counters-v1", "sqlite": sqlite3.sqlite_version,
              "clock": STAMP, "inputs": "synthetic public/message/signature and legacy identity-v2 history",
              "native_calls": 0, "formal_performance_started": False, "elapsed_samples": 0,
              "measurement": "SQLite progress_handler callback per VM instruction; no stopwatch",
              "source_sha256": {str(path.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(path.read_bytes()).hexdigest()
                                for path in (ROOT / "tools/signing_budget.py", ROOT / "tools/test_friend_budget_scalability.py", Path(__file__))},
              "rows": rows}
    output = Path(__file__).with_name("b03-repair-vm-results.json")
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
