"""Bind current correctness/analysis evidence without generating performance data."""
from __future__ import annotations
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpu-run", type=Path, required=True)
    parser.add_argument("--cuda-run", type=Path, required=True)
    parser.add_argument("--functional-run", type=Path, required=True)
    parser.add_argument("--analysis", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    evidence, rows, count_rows, summaries = {}, [], [], {}
    for kind, directory in (("cpu", args.cpu_run), ("cuda", args.cuda_run)):
        summary_path = directory / "summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        expected_cases = 3471 if kind == "cpu" else 1789
        if (not summary.get("passed") or summary.get("final") is not True
                or summary.get("completed_requested_scope") is not True
                or summary.get("suite") != "full" or summary.get("deferred_scope")
                or summary.get("planned_cases") != expected_cases
                or summary.get("passed_planned") != expected_cases
                or summary.get("formal_performance_started") is not False
                or summary.get("measured_durations") is not False
                or (kind == "cpu" and summary.get("full_sha2") is not True)):
            raise ValueError("Expected complete, passing, untimed correctness matrix")
        if summary.get("failed_case_ids") or summary.get("pending_case_ids") or summary.get("unavailable_case_ids"):
            raise ValueError("Correctness matrix has uncovered cases")
        for name, digest in summary["source_hashes"].items():
            if sha(ROOT / name) != digest:
                raise ValueError("Current source differs from matrix: " + name)
        cases = directory / "cases.jsonl"
        if sha(cases) != summary["cases_jsonl_sha256"]:
            raise ValueError("Correctness cases differ from summary")
        evidence[str(summary_path.resolve())] = sha(summary_path)
        evidence[str(cases.resolve())] = sha(cases)
        summaries[kind] = {key: summary.get(key) for key in ("schema", "planned_cases", "passed_planned", "records", "coverage", "source_hashes", "libraries")}
        for line_number, line in enumerate(cases.read_text(encoding="utf-8").splitlines(), 1):
            row = json.loads(line)
            checksum = row.pop("record_sha256")
            if hashlib.sha256(canonical(row)).hexdigest() != checksum:
                raise ValueError("Correctness row digest differs")
            case = row.get("case", {})
            rows.append(dict(matrix=kind, case_id=row["case_id"], pid=case.get("pid"), backend=case.get("backend"),
                threads=case.get("threads"), operation=case.get("operation"), cache_t=case.get("cache_t"),
                status=row.get("status"), passed=row.get("passed"), evidence_file=str(cases.resolve()),
                evidence_line=line_number, record_sha256=checksum))
            if row.get("observed"):
                observed = row["observed"]
                predicted = row.get("prediction") or {}
                predicted = predicted.get("counts", predicted)
                for field, value in observed.items():
                    count_rows.append(dict(matrix=kind, case_id=row["case_id"], pid=case.get("pid"), operation=case.get("operation"),
                        field=field, observed=value, predicted=predicted.get(field), has_prediction=field in predicted,
                        match=predicted[field] == value if field in predicted else None,
                        evidence_line=line_number, record_sha256=checksum))
    functional_path = args.functional_run / "manifest.json"
    functional = json.loads(functional_path.read_text(encoding="utf-8"))
    if (not functional.get("passed") or functional.get("real_timing_samples") != 0
            or functional.get("formal_performance_started") is not False
            or not functional.get("source_unchanged") or not functional.get("library_unchanged")
            or any(step["returncode"] != 0 for step in functional["steps"])):
        raise ValueError("Functional gate is incomplete")
    for name, digest in functional["source_sha256"].items():
        if sha(ROOT / name) != digest:
            raise ValueError("Functional source differs: " + name)
    for name, digest in functional["evidence_sha256"].items():
        if sha(args.functional_run / name) != digest:
            raise ValueError("Functional evidence differs: " + name)
    evidence[str(functional_path.resolve())] = sha(functional_path)
    analysis_path = args.analysis / "analysis-checks.summary.json"
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    if not analysis.get("passed") or not analysis.get("no_native_execution"):
        raise ValueError("Analytical checks are incomplete")
    for name, digest in analysis["source_hashes"].items():
        if sha(ROOT / name) != digest:
            raise ValueError("Analytical source differs: " + name)
    for name, digest in analysis["package_files"].items():
        if sha(args.analysis / name) != digest:
            raise ValueError("Analytical data differs: " + name)
    evidence[str(analysis_path.resolve())] = sha(analysis_path)
    for name, data in (("R1-current-case-index.csv", rows), ("R2-current-exact-counts.csv", count_rows)):
        with (output / name).open("x", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(data[0]) if data else ["empty"])
            writer.writeheader()
            writer.writerows(data)
    manifest = dict(schema="a15-final-correctness-analysis-binding-v1", final=True,
        created_utc=datetime.now(timezone.utc).isoformat(), passed=True,
        matrices=summaries, evidence_sha256=evidence,
        analysis_checks=analysis["checks"], functional_steps=len(functional["steps"]),
        formal_performance_started=False, real_timing_samples=0,
        performance_results=None, network_performance_results=None,
        scope="Current-source correctness and numerical/structural analysis. Final binding does not supply pending performance/energy/network distributions.",
        files_sha256={p.name: sha(p) for p in output.iterdir() if p.is_file()},
        tool_sha256=sha(__file__))
    (output / "package.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": True, "records": len(rows), "count_fields": len(count_rows), "real_timing_samples": 0}))


if __name__ == "__main__":
    main()
