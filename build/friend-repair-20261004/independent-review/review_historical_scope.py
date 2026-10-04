"""Compare preserved matrix identity with current sources; no execution/timers."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[3]
STAGE = ROOT / "build/repair-staging-20261004-r3/validation"
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

rows = []
for backend, name, planned, records in (
        ("cpu", "cpu-full-repair-r3", 3471, 4433),
        ("cuda", "cuda-full-repair-r3", 1789, 2541)):
    folder = STAGE / name
    summary = json.loads((folder / "summary.json").read_text(encoding="utf-8-sig"))
    assert summary["passed"] and summary["planned_cases"] == summary["passed_planned"] == planned
    assert summary["records"] == records and not summary["formal_performance_started"] and not summary["measured_durations"]
    sources = summary["source_hashes"]
    current = {name: sha(ROOT / name) for name in sources}
    changed = {name: {"historical_sha256": sources[name], "current_sha256": current[name]}
               for name in sources if sources[name] != current[name]}
    core_names = [name for name in sources if name.startswith(("c/", "third_party/"))]
    changed_core = {name: value for name, value in changed.items() if name in core_names}
    artifacts = {str(path.relative_to(ROOT)).replace("\\", "/"): sha(path)
                 for path in (folder / "summary.json", folder / "cases.jsonl", folder / "manifest.json") if path.exists()}
    if (folder / "cases.jsonl").exists():
        assert sha(folder / "cases.jsonl") == summary["cases_jsonl_sha256"]
    rows.append({"backend": backend, "historical_planned_cases": planned,
        "historical_records": records, "original_project_commit": "808d34c938725cf9b1edb7b2452d550afa396455",
        "historical_artifacts_sha256": artifacts, "recorded_libraries": summary["libraries"],
        "changed_sources": changed, "native_sources_compared": len(core_names),
        "changed_native_sources": changed_core, "native_core_hash_match": not changed_core,
        "full_matrix_rerun": False,
        "scope": "Historical native core may be inherited only when its exact recorded source/build/library identity matches; changed Python/TLS/runner require separate new evidence. No current full-source matrix claim."})
output = {"schema": "a15-historical-matrix-scope-review-v1", "native_calls": 0,
          "real_timing_samples": 0, "rows": rows}
target = Path(__file__).with_name("historical-scope-review.json")
target.write_text(json.dumps(output, indent=2)+"\n", encoding="utf-8")
print(json.dumps({"output": str(target), "native_calls": 0, "real_timing_samples": 0,
                  "rows": [{"backend": row["backend"], "native_core_hash_match": row["native_core_hash_match"],
                            "changed_sources": list(row["changed_sources"])} for row in rows]}, indent=2))
