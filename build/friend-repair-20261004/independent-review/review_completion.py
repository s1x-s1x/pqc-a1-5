"""Read-only, synthetic preserved-evidence review; no native calls or timers."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from test_budget_repair import BudgetRepair
import bench_cpu as cpu
import bench_cuda as cuda

checks = []
for mode in ("pending", "failed"):
    test = BudgetRepair()
    test.setUp()
    try:
        budget, case, records = test.evidence()
        complete = records.pop()
        start = records[2].copy()
        receipt = budget.reserve(cpu.ALGORITHMS[case["pid"]], test.public, test.message)
        start.update(operation_id="3"*32, receipt=receipt,
                     budget_evidence=budget.validate_receipt(receipt, statuses=("reserved",)))
        records.append(start)
        if mode == "failed":
            budget.finish(receipt)
            records.append({**start, "kind": "sample", "passed": False, "duration_ns": None,
                            "error": "synthetic operation failure", "budget_evidence": budget.validate_receipt(receipt, statuses=("failed",))})
        records.append(complete)
        result = {"mode": mode}
        for backend, checker in (("cpu", cpu.validate_completed), ("cuda", cuda.validate_completed)):
            try:
                result[backend+"_completion_accepted"] = checker(records, case, test.folder, budget)
            except ValueError as error:
                result[backend+"_completion_accepted"] = False
                result[backend+"_error"] = str(error)
        checks.append(result)
    finally:
        test.doCleanups()
output = {"schema": "a15-independent-completion-review-v1", "native_calls": 0,
          "real_timing_samples": 0, "checks": checks}
print(json.dumps(output, indent=2))
Path(__file__).with_name("completion-review.json").write_text(json.dumps(output, indent=2)+"\n", encoding="utf-8")
