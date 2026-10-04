"""Validate archived evidence and emit separately scoped R1 rows."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inspect_case_records(path, expected):
    cases = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    if len(cases) != expected or len({case["case_id"] for case in cases}) != expected:
        raise ValueError("record count/uniqueness mismatch: " + str(path))
    for case in cases:
        original = dict(case)
        checksum = original.pop("record_sha256")
        canonical = json.dumps(original, sort_keys=True, separators=(",", ":")).encode()
        if hashlib.sha256(canonical).hexdigest() != checksum:
            raise ValueError("record checksum mismatch: " + case["case_id"])
        if not case["passed"] or not all(case["checks"].values()):
            raise ValueError("failed checks: " + case["case_id"])
        for field, checksum in case.get("content_sha256", {}).items():
            if hashlib.sha256(bytes.fromhex(case[field])).hexdigest() != checksum:
                raise ValueError("payload checksum mismatch: " + case["case_id"] + ":" + field)
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path, default=ROOT / "reference" / "evidence")
    parser.add_argument("--acvp", type=Path, default=ROOT / "reference" / "acvp-server-results.json")
    parser.add_argument("--output", type=Path, default=ROOT / "reference" / "evidence" / "R1-python.jsonl")
    args = parser.parse_args()
    rows = []
    acvp = json.loads(args.acvp.read_text())
    if acvp["total"] != 208 or acvp["passed"] != 208 or acvp["failed"]:
        raise ValueError("ACVP evidence does not report 208 passing cases")
    rows.append({"id": "A-python", "parameter_sets": [101, 102],
                 "source_kind": "external pinned NIST ACVP snapshot from py-acvp-pqc",
                 "source_commit": acvp["upstream_commit"], "test_unit": "one external ACVP case",
                 "total": 208, "passed": 208, "failed": 0,
                 "operation_counts": acvp["counts"],
                 "evidence": str(args.acvp.relative_to(ROOT)).replace("\\", "/"),
                 "evidence_sha256": sha256(args.acvp),
                 "scope": "Python model; keyGen/sign/verify with 128s/128f. Prehash inputs use upstream encoder plus internal API.",
                 "counting_note": "The same 208 case IDs run against C are the same source cases, not 416 distinct vectors."})
    for stem, count, row_id, scope in (
        ("sm3-128-24-differential", 3, "D-complete", "Complete seeded C/Python keygen plus signing and verification, 3856-byte signatures; two deterministic and one explicit randomized case."),
        ("toy-differential", 1000, "D-toy-complete", "1000 distinct seeded toy keys/messages; complete keygen/sign agreement, valid and five malformed/changed-input verification checks per case."),
        ("subtree-differential-balanced", 1000, "D-subtrees", "Auxiliary subtree coverage across all seven pids, WOTS and FORS, heights 0-6 within each parameter bound; native 1-versus-4-thread equivalence."),
    ):
        path = args.evidence_root / (stem + ".jsonl")
        summary_path = args.evidence_root / (stem + ".summary.json")
        summary = json.loads(summary_path.read_text())
        cases = inspect_case_records(path, count)
        if (summary["total"] != count or summary["passed"] != count or summary["failed"] or
                summary["cases_jsonl_sha256"] != sha256(path) or not summary["native_library_unchanged"]):
            raise ValueError("summary mismatch: " + str(path))
        rows.append({"id": row_id, "parameter_sets": sorted({case["pid"] for case in cases}),
                     "source_kind": "C versus Python derived from different upstream language implementations",
                     "source_commit": summary["upstream_python_commit"],
                     "test_unit": "one input case; assertions are not counted as separate vectors",
                     "total": count, "passed": count, "failed": 0,
                     "evidence": str(path.relative_to(ROOT)).replace("\\", "/"),
                     "evidence_sha256": sha256(path),
                     "summary_sha256": sha256(summary_path),
                     "native_library_sha256": summary["native_library_sha256"],
                     "sources_sha256": summary["sources_sha256"], "scope": scope,
                     "excluded": "32-case diagnostic and earlier unbalanced subtree diagnostic are not counted."})
    timestamp = datetime.now(timezone.utc).isoformat()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as stream:
        for row in rows:
            row.update({"schema": "a15-R1-row-v1", "assembled_at_utc": timestamp,
                        "boundary": "Implementation correctness evidence only; no formal implementation proof, zero-defect guarantee, FIPS certification or final performance claim."})
            stream.write(json.dumps(row, sort_keys=True) + "\n")
    print(json.dumps({"rows": len(rows), "distinct_case_count": sum(row["total"] for row in rows),
                      "cases_without_auxiliary_subtrees": 1211, "output_sha256": sha256(args.output)}))


if __name__ == "__main__":
    main()
