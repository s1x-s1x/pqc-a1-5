"""Export report assets from preserved plans and source-backed evidence.

All exports remain preliminary until a final gate and matching code manifest exist.
No diagnostic duration is promoted into a final benchmark table.
"""
import csv
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "docs" / "plans" / "A1-5_设计报告框架_150页.md"
OUT = ROOT / "report-data" / "DP1-preliminary"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_csv(name, records):
    if not records:
        return
    with (OUT / name).open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                         text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        commit = None
    report_lines = REPORT.read_text(encoding="utf-8").splitlines()
    assets = []
    for line_number, line in enumerate(report_lines, 1):
        if not line.startswith("|"):
            continue
        fields = [field.strip() for field in line.strip("|").split("|")]
        if len(fields) < 5 or not re.fullmatch(r"(?:图|表)[0-9A-F]+-\d+|算法框 \d+-\d+", fields[0]):
            continue
        assets.append({"id": fields[0], "title": fields[1], "report_section": fields[2],
                       "planned_source": fields[3], "plan_line": line_number,
                       "status": "pending", "final": False})
    contracts = {
        "R1": {"meaning": "correctness and boundary checks", "required": ["case_id", "input_source", "implementation_hashes", "result", "coverage_scope"]},
        "R2": {"meaning": "exact native primitive/compression counters", "required": ["pid", "operation", "message_encoding", "cache_t", "input_hash", "predicted", "observed", "counter_build_hash"]},
        "R3": {"meaning": "single-thread performance and same-engine SHA2/SM3", "required": ["pid", "backend", "cache_t", "commit", "build_flags", "affinity", "clock_policy", "samples", "dispersion"]},
        "R4": {"meaning": "cache tradeoffs", "required": ["cache_t", "payload_bytes", "file_bytes", "ram_bytes", "build_seconds", "load_seconds", "sign_seconds", "amortization", "R3_metadata"]},
        "R5": {"meaning": "parallel scaling and optimization ablations", "required": ["threads", "numa", "affinity", "backend", "cache_t", "samples", "dispersion", "R3_metadata"]},
        "R6": {"meaning": "real DER chains and TCP experiments E1-E5", "required": ["profile", "chain_der_bytes", "first_flight_bytes", "MSS", "initcwnd", "rtt", "pcap_source", "validation_policy", "negative_cases"]},
        "R7": {"meaning": "parameter assumptions and security boundaries", "required": ["standard_status", "parameter_source", "max_signatures", "attack_term_label", "assumptions"]},
        "R8": {"meaning": "FORS probability term as use-count varies", "required": ["q", "h", "a", "k", "negative_log2_probability", "numerical_method", "tail_bound", "not_full_EUF_CMA"]},
    }
    contract = {"schema_version": 1, "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "report_plan": str(REPORT.relative_to(ROOT)), "report_plan_sha256": sha(REPORT),
                "source_commit": commit, "final": False,
                "publication_rule": "DP3 numeric claims require raw source line, source hash, script hash, and matching gate3 code. Analytical outputs must be labeled separately.",
                "families": contracts, "assets": assets}
    (OUT / "evidence-contract.json").write_text(json.dumps(contract, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_csv("asset-catalog.csv", assets)
    engine = ROOT / "c" / "src" / "engine.c"
    parameter_records = []
    for line_number, line in enumerate(engine.read_text(encoding="utf-8").splitlines(), 1):
        for match in re.finditer(r"\{(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\}", line):
            pid, sm3, h, d, hp, a, k, lgw, length, m = map(int, match.groups())
            parameter_records.append({"pid": pid, "hash": "SM3" if sm3 else "SHA256",
                "n": 16, "h": h, "d": d, "hp": hp, "a": a, "k": k, "lgw": lgw,
                "wots_len": length, "digest_bytes": m,
                "pk_bytes": 32, "sk_bytes": 64,
                "signature_bytes": 16 * (1 + k * (a + 1) + d * length + h),
                "basis": "calculated from implemented parameters; not performance measurement",
                "source": str(engine.relative_to(ROOT)), "source_line": line_number,
                "source_sha256": sha(engine), "final": False})
    write_csv("parameters.csv", parameter_records)
    cache_records = [{"pid": 3, "t": t, "hp": 22,
                      "payload_bytes": 16 * 2 ** (22 - t),
                      "header_bytes": 96, "file_bytes": 96 + 16 * 2 ** (22 - t),
                      "node_ram_bytes": 16 * (2 ** (23 - t) - 1),
                      "basis": "calculated node storage; allocator/context overhead excluded",
                      "source": "c/src/DESIGN.md", "source_sha256": sha(ROOT / "c/src/DESIGN.md"),
                      "final": False} for t in range(23)]
    write_csv("cache-storage.csv", cache_records)
    environment = ROOT / "validation" / "environment.json"
    if environment.exists():
        env = json.loads(environment.read_text(encoding="utf-8"))
        public_env = {key: env.get(key) for key in ["platform", "python", "gcc", "boost", "governor", "selected_physical_cpus", "selected_numa_node", "hashlib_sm3"]}
        public_env["cpu"] = {row["field"].rstrip(":"): row["data"] for row in env["lscpu"]["lscpu"] if row["field"].rstrip(":") in {"Model name", "CPU(s)", "Core(s) per socket", "Socket(s)", "Thread(s) per core"}}
        public_env["gpu_models"] = [entry.split(",")[1].strip() for entry in env.get("gpu", [])]
        public_env.update({"basis": "observed server environment; hardware inventory does not imply resources used by each experiment",
                           "source": str(environment.relative_to(ROOT)), "source_sha256": sha(environment), "final": False})
        (OUT / "platform-public.json").write_text(json.dumps(public_env, indent=2) + "\n", encoding="utf-8")
    note = """# DP1 预备数据包

本包由 `tools/make_tables.py` 生成，供报告搭建表头、核对参数和索引证据。
当前为第一阶段预备数据，所有文件 `final=false`；时间与加速比待正式基准输出。

- `evidence-contract.json`：R1–R8 字段约束，以及报告逐图、逐表、算法框的来源清单。
- `asset-catalog.csv`：报告框架的全部资产和原文行号；pending 表示尚未交付该资产。
- `parameters.csv`：与 C 参数表绑定的尺寸计算，可用于表5-1、表A-1。
- `cache-storage.csv`：磁盘有效载荷、完整文件与节点内存分别列出，可用于表5-6、表9-3。
- `platform-public.json`：脱去主机名、用户名的环境信息，可用于表3-5、表9-1。

当前默认 t=12：有效载荷 16,384 B，完整文件 16,480 B，节点内存 32,752 B。
理论成本、诊断耗时、正式基准三个来源须分别标注。R8 只描述 FORS 攻击概率项。
每个最终数值需保留原始文件、行号、哈希和生成脚本；DP3 必须与门3代码一致。
"""
    (OUT / "README.md").write_text(note, encoding="utf-8")
    print(json.dumps({"directory": str(OUT), "assets": len(assets),
                      "parameters": len(parameter_records), "final": False}, ensure_ascii=False))


if __name__ == "__main__":
    main()
