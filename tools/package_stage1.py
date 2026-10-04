"""Export a reviewable DP1 scalar snapshot with checked source-line references."""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_csv(path, rows):
    fields = list(dict.fromkeys(k for row in rows for k in row))
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args()
    run = args.run_dir.resolve()
    if not run.is_relative_to(ROOT / "validation"):
        parser.error("run-dir must be inside validation")
    manifest_path = run / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf8"))
    if not manifest["passed"] or not manifest["source_unchanged"]:
        raise ValueError("stage1 run has not passed its complete source-matched suite")
    for relative, expected in manifest["evidence_sha256"].items():
        if sha(ROOT / relative) != expected:
            raise ValueError(f"execution evidence hash mismatch: {relative}")
    for relative, expected in manifest["source_sha256"].items():
        if sha(ROOT / relative) != expected:
            raise ValueError(f"execution source hash mismatch: {relative}")
    out = ROOT / "report-data" / ("DP1-" + run.name)
    out.mkdir(parents=True, exist_ok=False)
    library = next(digest for name, digest in manifest["build_sha256"].items()
                   if name.endswith("/ref/libslhdsa_sm3.so"))
    summary_rows, cases = [], []
    families = [("external", "A/B/C", "external operation check", "8.2;8.5;8.7"),
                ("complete-128-24", "D-complete", "complete SM3-128-24 seeded case", "8.5;8.7"),
                ("toy", "D-toy", "complete toy seeded case", "8.5;8.7"),
                ("subtree", "D-subtree", "auxiliary subtree case", "6.6;8.5;8.7")]
    summaries = {}
    for name, label, unit, sections in families:
        summary_file = run / (name + ".summary.json")
        summary = json.loads(summary_file.read_text(encoding="utf8"))
        summaries[name] = summary
        bound_library = summary.get("library_sha256", summary.get("native_library_sha256"))
        if bound_library != library or summary["failed"] or summary["passed"] != summary["total"]:
            raise ValueError(f"suite status/library mismatch: {name}")
        source = run / (name + ".jsonl")
        source_hash = sha(source)
        lines = source.read_text(encoding="utf8").splitlines()
        if len(lines) != summary["total"]:
            raise ValueError(f"case count mismatch: {name}")
        summary_rows.append({"suite": label, "unit": unit, "total": summary["total"],
            "passed": summary["passed"], "failed": summary["failed"], "library_sha256": library,
            "source": summary_file.relative_to(ROOT).as_posix(), "source_sha256": sha(summary_file),
            "report_sections": sections, "stage": "scalar-review", "final_performance": False})
        seen = set()
        for number, line in enumerate(lines, 1):
            row = json.loads(line)
            case_id = row["case_id"]
            if case_id in seen or not row["passed"]:
                raise ValueError(f"duplicate/failed case: {name}:{case_id}")
            seen.add(case_id)
            checksum = row.pop("record_sha256")
            actual = hashlib.sha256(json.dumps(row, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            if checksum != actual:
                raise ValueError(f"canonical record hash mismatch: {name}:{case_id}")
            cases.append({"suite": label, "case_id": case_id, "pid": row.get("pid"),
                "operation": row.get("operation", unit), "passed": True,
                "source": source.relative_to(ROOT).as_posix(), "source_line": number,
                "source_sha256": source_hash, "record_sha256": checksum, "library_sha256": library})
    write_csv(out / "R1-summary.csv", summary_rows)
    write_csv(out / "R1-case-index.csv", cases)
    counts_file = run / "exact-counts.summary.json"
    counts_summary = json.loads(counts_file.read_text(encoding="utf8"))
    if counts_summary["passed"] is not True or not counts_summary["records"] or counts_summary["error"]:
        raise ValueError("counter suite reports failures")
    for name in ("exact-counts.jsonl", "exact-counts.summary.json"):
        shutil.copy2(run / name, out / name)
    count_rows = []
    count_source = run / "exact-counts.jsonl"
    count_source_hash = sha(count_source)
    for number, line in enumerate(count_source.read_text(encoding="utf8").splitlines(), 1):
        record = json.loads(line)
        if not record["passed"]:
            raise ValueError("failed exact-count record")
        for field, predicted in record["predicted"].items():
            count_rows.append({"case_id": record["case_id"], "pid": record["pid"],
                "operation": record["operation"], "threads": record["native_threads"],
                "message_encoding": record["message_encoding"], "cache_t": record["cache_t"],
                "field": field, "predicted": predicted, "observed": record["observed"][field],
                "matches": record["field_matches"][field], "source": count_source.relative_to(ROOT).as_posix(),
                "source_line": number, "source_sha256": count_source_hash,
                "input_sha256": record["input_sha256"], "counter_build_sha256": record["counter_build_sha256"]})
    write_csv(out / "R2-exact-counts.csv", count_rows)
    steps = [{**step, "stage": "scalar-review", "final_performance": False} for step in manifest["steps"]]
    write_csv(out / "execution-index.csv", steps)
    vector_rows = []
    for relative in summaries["external"]["inputs_sha256"]:
        vector_rows.append({"source": relative, "sha256": sha(ROOT / relative),
                            "records": len((ROOT / relative).read_text(encoding="utf8").splitlines()),
                            "kind": "preserved external operation inputs"})
    relative = "reference/evidence/python-sm3-128-24.jsonl"
    vector_rows.append({"source": relative, "sha256": sha(ROOT / relative),
                        "records": len((ROOT / relative).read_text(encoding="utf8").splitlines()),
                        "kind": "complete Python reference inputs"})
    write_csv(out / "vector-manifest.csv", vector_rows)
    availability = [
        {"family": "R1", "status": "verified scalar snapshot", "report": "第8章，附录D/E", "source": "R1-summary.csv;R1-case-index.csv"},
        {"family": "R2", "status": "executed exact-count coverage listed in summary; large signing costs remain separate", "report": "5.3;9.4", "source": "exact-counts.jsonl;exact-counts.summary.json"},
        {"family": "R3-R5", "status": "pending formal performance/SIMD/cache/scaling experiments", "report": "第9章", "source": ""},
        {"family": "R6", "status": "pending new SLH chain/TCP experiments", "report": "第10章", "source": ""},
        {"family": "R7-R8", "status": "pending numerical security-term/grid analysis; SPEC defines claim boundaries", "report": "第5、7章", "source": "SPEC.md"},
    ]
    write_csv(out / "report-availability.csv", availability)
    data = {"schema": "a15-stage1-report-package-v1", "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "run_manifest": manifest_path.relative_to(ROOT).as_posix(), "run_manifest_sha256": sha(manifest_path),
            "library_sha256": library, "stage1_suite_passed": True, "complete_DP1": False,
            "final_performance": False, "plan_manifest_sha256": sha(ROOT / "docs/plans/manifest.json"),
            "exporter_sha256": sha(Path(__file__)),
            "files": {p.name: sha(p) for p in out.iterdir() if p.is_file()}}
    note = f"""# 第一轮审核包：标量正确性

审核日期：2026-10-04。服务器工作目录：`/home/guest-experiment/pqc-a1-5`。
本轮验收通过，源码与运行结果由 `{data['run_manifest']}` 绑定。
共享库 SHA256：`{library}`。

| 证据 | 通过/执行 | 计数单位 |
|---|---:|---|
| ACVP/xous/gmsm | {summaries['external']['passed']}/{summaries['external']['total']} | 操作或验签检查；208+3+140 |
| 完整 SM3-128-24 C/Python | {summaries['complete-128-24']['passed']}/{summaries['complete-128-24']['total']} | 完整种子用例，含3,856字节签名 |
| 完整玩具参数 C/Python | {summaries['toy']['passed']}/{summaries['toy']['total']} | 完整种子用例 |
| 辅助 subtree C/Python | {summaries['subtree']['passed']}/{summaries['subtree']['total']} | 子树用例，单列辅助覆盖 |

本轮重新执行已有输入，重复执行不增加独立向量数量。
原生/扩展缓存与线程测试、计算故障注入矩阵、ASan/UBSan、精确计数的命令、退出码和日志位于 `execution-index.csv`。
故障测试使用专用编译宏，普通共享库不开放运行时注入接口；故障点和覆盖以原始fault日志为准。

`R1-summary.csv` 可用于表8-5；`R1-case-index.csv` 给出逐例来源文件、行号和哈希，支持表8-1、8-3。
`exact-counts.jsonl` 按实际消息和WOTS校验和比较理论预测与原生计数，覆盖参数/操作以摘要为准，供R2与表5-3/5-4使用。
参数尺寸与cache载荷/文件/节点内存来自 `DP1-preliminary/parameters.csv` 与 `cache-storage.csv`，属于按参数计算。
`report-availability.csv` 明确标识后续章节尚待实测的项目。

当前是标量正确性审核点，完整DP1还需参数网格与FORS攻击项等分析产物。报告中的正式性能数值、SIMD/CUDA、证书链/TCP和形式化模型结果留待后续实验。
全部耗时来自正确性运行，标为诊断耗时；旧TLS底座393项测试另列既有工作。
FORS攻击概率项、SM3适配假设与整个签名方案的安全结论分开写。该测试包提供功能一致性证据。

推荐审核入口：本文件 → `R1-summary.csv` → `execution-index.csv` → `package.json`。
"""
    (out / "REVIEW.md").write_text(note, encoding="utf8")
    data["files"]["REVIEW.md"] = sha(out / "REVIEW.md")
    (out / "package.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf8")
    print(json.dumps({"package": str(out.relative_to(ROOT)), "R1_cases": len(cases), "stage1_suite_passed": True}, ensure_ascii=False))


if __name__ == "__main__":
    main()
