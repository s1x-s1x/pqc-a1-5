"""Synthetic metadata regression for the repaired read-only project audit."""
from contextlib import redirect_stdout
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ops"))
spec = importlib.util.spec_from_file_location("repaired_project_audit", ROOT / "ops/audit_project_repair.py")
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
canonical = lambda row: hashlib.sha256(json.dumps(row, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class DeliveryFixture:
    def __init__(self, *args, **kwargs):
        self.protected = set()
    def run(self):
        return {"passed": True, "native_calls": 0, "real_timing_samples": 0,
                "checks": [{} for _ in range(19)], "errors": []}


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def fixture_file(path, text="synthetic metadata fixture bytes\n"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return sha(path)


def invoke(root):
    tool.ROOT = root
    tool.Audit = DeliveryFixture
    previous = sys.argv
    try:
        sys.argv = [tool.__file__]
        output = io.StringIO()
        with redirect_stdout(output):
            tool.main()
        return json.loads(output.getvalue())
    finally:
        sys.argv = previous


checks = []
with tempfile.TemporaryDirectory(prefix="a15-repaired-audit-") as folder:
    root = Path(folder)
    stage = root / tool.STAGE_NAME
    validation = stage / "validation"
    write(validation / "repair-final-readiness-r3.json", {"synthetic": True})
    write(root / "validation/repair-external-evidence-r3-manifest.json", {"synthetic": True})
    required_sources = tool.BASE_SOURCES | {"tools/native.py", "tools/alt_chain_fixtures.py", "tools/signing_budget.py", "tools/bind_project_results.py",
        "tools/reproduce_project.py", "base_tls/tls/alt_chain.py", "base_tls/tls/handshake/client.py", "base_tls/tests/test_merged_tls_fixes.py"}
    source = {name: fixture_file(root / name, "fixture source: " + name) for name in required_sources}
    for name in ("ops/audit_project_repair.py", "ops/audit_optimization_delivery.py"):
        path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes((ROOT / name).read_bytes())
    def steps(names, directory):
        return [{"name": name, "returncode": 0, "log_sha256": fixture_file(directory / (name + ".log"))} for name in names]
    for kind, names, variants in (("cpu", tool.CPU_STEPS, ("avx2", "counters", "portable")),
                                   ("cuda", tool.CUDA_STEPS, ("release", "counters", "disabled"))):
        name = "native-repair-r3" if kind == "cpu" else "cuda-native-repair-r3"
        directory = validation / name
        data = {"schema": "a15-native-stage2-v1" if kind == "cpu" else "a15-cuda-native-v1",
                "passed": True, "source_unchanged": True, "steps": steps(names, directory),
                "source_sha256" if kind == "cpu" else "source_hashes": source,
                "evidence_sha256": {tool.REMOTE + "/validation/" + name + "/" + step + ".log": sha(directory / (step + ".log")) for step in names},
                "build_sha256": {tool.REMOTE + "/build/" + name + "/" + variant + "/libslhdsa_sm3.so":
                    fixture_file(stage / "build" / name / variant / "libslhdsa_sm3.so") for variant in variants}}
        if kind == "cpu":
            data.update(inputs_unchanged=True, inputs_sha256={"vectors/fixture.txt": fixture_file(root / "vectors/fixture.txt")})
        else:
            data.update(formal_performance_started=False, real_timing_samples=0, measured_durations=False)
        write(directory / "manifest.json", data)
    resource_dir = validation / "cuda-native-repair-r3"
    build = stage / "build/cuda-native-repair-r3/release/cuda-resources"
    fixture_file(build / "ptxas.log")
    write(resource_dir / "device-code-resource-sass.json", {"schema": "a15-cuda-device-code-review-v1", "passed": True,
        "native_calls": 0, "real_timing_samples": 0, "kernels": ["fors_leaf_kernel", "fors_reduce_kernel", "sm3_kernel"],
        "object_sha256": fixture_file(build / "sm3_cuda.o"),
        "sass_resource_sha256": fixture_file(resource_dir / "device-code-resource-sass.log")})
    for kind, count in (("cpu", 3471), ("cuda", 1789)):
        directory = validation / (kind + "-full-repair-r3")
        directory.mkdir(parents=True)
        schema = "a15-optimization-correctness-v1" if kind == "cpu" else "a15-cuda-correctness-v1"
        row = {"case_id": "fixture", "case": {"case_id": "fixture"}, "schema": schema, "status": "passed", "passed": True,
               "formal_performance": False, "source_hashes": source, "checks": {"fixture": True}, "field_matches": {}}
        row["record_sha256"] = canonical(row)
        (directory / "cases.jsonl").write_text((json.dumps(row) + "\n") * count, encoding="utf-8")
        write(directory / "summary.json", {"schema": schema, "passed": True, "final": True, "completed_requested_scope": True,
            "suite": "full", "deferred_scope": [], "planned_cases": count, "passed_planned": count, "records": count,
            "formal_performance_started": False, "measured_durations": False, "full_sha2": True,
            "failed_case_ids": [], "pending_case_ids": [], "unavailable_case_ids": [], "source_hashes": source,
            "cases_jsonl_sha256": sha(directory / "cases.jsonl")})
    functional = validation / "project-functional-repair-r3-final3"
    functional_steps = steps(tool.FUNCTIONAL_STEPS, functional)
    for name in ("bench_cpu-mock.json", "bench_cuda-mock.json", "freeze_cuda-mock.json", "ca-verification.json", "p0-p4-size-functional.jsonl"):
        fixture_file(functional / name)
    write(functional / "manifest.json", {"schema": "a15-project-functional-v1", "passed": True, "source_unchanged": True,
        "library_unchanged": True, "formal_performance_started": False, "real_timing_samples": 0,
        "source_sha256": source, "steps": functional_steps,
        "evidence_sha256": {p.name: sha(p) for p in functional.iterdir() if p.is_file()}})
    fixture_root = validation / "real-alt-fixtures-repair-r3-parallel2"
    ledger_path = validation / "functional-parallel/ca-budget.sqlite"
    ledger_path.parent.mkdir(parents=True)
    connection = sqlite3.connect(ledger_path)
    connection.executescript("""CREATE TABLE ledger_metadata(name TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE keys(key_id TEXT PRIMARY KEY,algorithm TEXT NOT NULL,public_key BLOB NOT NULL,used_text TEXT NOT NULL,limit_text TEXT NOT NULL);
        CREATE TABLE reservations(receipt TEXT PRIMARY KEY,key_id TEXT NOT NULL,ordinal_text TEXT NOT NULL,status TEXT NOT NULL,
                                  message_sha256 TEXT NOT NULL,signature_sha256 TEXT NOT NULL);""")
    fixture_uuid = "0123456789abcdef0123456789abcdef"
    connection.executemany("INSERT INTO ledger_metadata VALUES (?,?)", [("ledger_uuid", fixture_uuid), ("identity_schema", "2")])
    fixture_entries, verified_edges = [], []
    for algorithm, identity in tool.FIXTURE_ALGORITHMS.items():
        directory = fixture_root / algorithm
        files = {name: fixture_file(directory / name, "fixture public test-only file " + algorithm + "/" + name) for name in tool.FIXTURE_FILES}
        signing = []
        for index, name in enumerate(("intermediate-pre-tbs.der", "leaf-pre-tbs.der")):
            public = (algorithm + "-public-" + str(index)).encode()
            key_id = hashlib.sha256(identity.encode("ascii") + b"\0" + public).hexdigest()
            receipt = algorithm + "-receipt-" + str(index)
            signature = hashlib.sha256((algorithm + "-signature-" + str(index)).encode()).hexdigest()
            row = {"algorithm": algorithm, "budget_status": "committed", "ledger_uuid": fixture_uuid,
                   "budget_receipt": receipt, "pre_tbs_sha256": files[name], "message_bytes": (directory / name).stat().st_size,
                   "signature_sha256": signature, "issuer_public_key_sha256": hashlib.sha256(public).hexdigest()}
            signing.append(row)
            connection.execute("INSERT INTO keys VALUES (?,?,?,?,?)", (key_id, algorithm, public, "1", "16"))
            connection.execute("INSERT INTO reservations VALUES (?,?,?,?,?,?)", (receipt, key_id, "1", "committed", files[name], signature))
            verified_edges.append({"algorithm": algorithm, "public_key_sha256": row["issuer_public_key_sha256"],
                "message_sha256": files[name], "signature_sha256": signature, "passed": True})
        metadata = {"schema": "a15-alt-fixture-v1", "test_only": True, "alt_algorithm": algorithm,
                    "budget_ledger_uuid": fixture_uuid, "library_sha256": sha(stage / "build/native-repair-r3/avx2/libslhdsa_sm3.so"),
                    "sources_sha256": source, "files_sha256": files, "signing_records": signing}
        write(directory / "fixture.json", metadata)
        fixture_entries.append({"algorithm": algorithm, "fixture_path": tool.REMOTE + "/validation/real-alt-fixtures-repair-r3-parallel2/" + algorithm,
                                "fixture_sha256": sha(directory / "fixture.json")})
    connection.commit(); connection.close()
    write(fixture_root / "MANIFEST.json", {"schema": "a15-alt-fixtures-v1", "test_only": True,
        "source_unchanged": True, "library_unchanged": True, "sources_sha256": source, "fixtures": fixture_entries,
        "budget_ledger_uuid": fixture_uuid, "library_sha256": sha(stage / "build/native-repair-r3/avx2/libslhdsa_sm3.so")})
    write(functional / "ca-verification.json", {"schema": "a15-alt-fixture-verification-v1", "passed": True,
        "rows": [{"passed": True, "verifiers": verified_edges}]})
    functional_manifest = json.loads((functional / "manifest.json").read_text())
    functional_manifest["evidence_sha256"]["ca-verification.json"] = sha(functional / "ca-verification.json")
    write(functional / "manifest.json", functional_manifest)
    clean = validation / "clean-reproduction-repair-r3-final2"
    write(clean / "manifest.json", {"schema": "a15-clean-reproduction-v1", "passed": True, "source_unchanged": True,
        "formal_performance_started": False, "real_timing_samples": 0, "source_sha256": source,
        "steps": steps(tool.CLEAN_STEPS, clean), "external_provider_sha256": {"base_tls/.deps-falcon/fixture": "0" * 64}})
    config = validation / "build-config-repair-r3"
    write(config / "manifest.json", {"schema": "a15-build-config-regression-v1", "passed": True,
        "checks": {name: True for name in tool.CONFIG_CHECKS}, "steps": steps(tool.CONFIG_STEPS, config),
        "makefile_sha256": source["c/Makefile"], "native_calls": 0, "real_timing_samples": 0, "formal_performance_started": False})
    demo = validation / "project-demo-repair-r3"
    artifacts = {name: fixture_file(demo / name) for name in ("evidence-demo.mp4", "captions.srt", "evidence.json",
        "slide-01.png", "slide-02.png", "slide-03.png", "slide-04.png")}
    write(demo / "manifest.json", {"schema": "a15-demo-artifacts-v1", "video_status": "generated", "performance_samples": 0,
        "contains_private_keys": False, "contains_elapsed_times": False, "artifacts_sha256": artifacts})
    write(root / "validation/ca-models-v2-summary-20261004.json", {"security_validation_complete": False,
        "runs": [], "invocations": [], "full_model_completed_verdicts": 0, "full_model_timeouts": 0})
    analysis = stage / "report-data/DP1-analysis-repair-20261004"
    write(analysis / "analysis-checks.summary.json", {"passed": True, "no_native_execution": True, "checks": 121,
        "source_hashes": source, "package_files": {"fixture.csv": fixture_file(analysis / "fixture.csv")}})
    binding = stage / "report-data/DP1-final-repair-r3"
    inputs = [validation / (kind + "-full-repair-r3") / name for kind in ("cpu", "cuda") for name in ("summary.json", "cases.jsonl")]
    inputs += [functional / "manifest.json", analysis / "analysis-checks.summary.json"]
    write(binding / "package.json", {"schema": "a15-final-correctness-analysis-binding-v1", "passed": True, "final": True,
        "real_timing_samples": 0, "formal_performance_started": False, "tool_sha256": source["tools/bind_project_results.py"],
        "files_sha256": {name: fixture_file(binding / name) for name in ("R1-current-case-index.csv", "R2-current-exact-counts.csv")},
        "evidence_sha256": {tool.REMOTE + "/" + p.relative_to(stage).as_posix(): sha(p) for p in inputs}, "analysis_checks": 121})
    baseline = invoke(root)
    checks.append({"name": "complete-synthetic-baseline", "passed": baseline["passed"], "errors": baseline["errors"]})
    assert baseline["passed"], baseline["errors"]
    checks.append({"name": "verified-file-closure-nonempty", "passed": len(baseline["evidence_sha256"]) > 50
        and "ops/audit_project_repair.py" in baseline["evidence_sha256"]})
    def json_failure(name, path, target, mutate):
        original = path.read_bytes()
        data = json.loads(original)
        mutate(data)
        write(path, data)
        try:
            result = invoke(root)
            selected = next(row for row in result["checks"] if row["name"] == target)
            checks.append({"name": name, "passed": selected["passed"] is False})
        finally:
            path.write_bytes(original)
    def missing_file(name, path, target):
        original = path.read_bytes()
        path.unlink()
        try:
            result = invoke(root)
            checks.append({"name": name, "passed": next(row for row in result["checks"] if row["name"] == target)["passed"] is False})
        finally:
            path.write_bytes(original)
    native = validation / "native-repair-r3/manifest.json"
    for field in ("source_sha256", "evidence_sha256", "build_sha256", "inputs_sha256"):
        json_failure("native-empty-" + field, native, "cpu-native", lambda d, key=field: d.update({key: {}}))
    json_failure("native-wrong-step-name", native, "cpu-native", lambda d: d["steps"][0].update(name="wrong"))
    json_failure("native-wrong-log-hash", native, "cpu-native", lambda d: d["steps"][0].update(log_sha256="0" * 64))
    missing_file("native-required-log-missing", native.parent / "avx2-build-and-tests.log", "cpu-native")
    for field in ("source_sha256", "evidence_sha256"):
        json_failure("functional-empty-" + field, functional / "manifest.json", "functional", lambda d, key=field: d.update({key: {}}))
    json_failure("functional-required-evidence-map-entry-missing", functional / "manifest.json", "functional", lambda d: d["evidence_sha256"].pop("ca-verification.json"))
    json_failure("functional-source-windows-path", functional / "manifest.json", "functional", lambda d: d["source_sha256"].update({"C:/outside.txt": "0" * 64}))
    for key in ("full_sha2",):
        json_failure("cpu-missing-" + key, validation / "cpu-full-repair-r3/summary.json", "cpu-full", lambda d, key=key: d.update({key: False}))
    for key in ("failed_case_ids", "pending_case_ids", "unavailable_case_ids"):
        json_failure("cpu-nonempty-" + key, validation / "cpu-full-repair-r3/summary.json", "cpu-full", lambda d, key=key: d.update({key: ["bad"]}))
    json_failure("cpu-real-record-count-mismatch", validation / "cpu-full-repair-r3/summary.json", "cpu-full", lambda d: d.update(records=0))
    json_failure("cpu-case-file-hash-mismatch", validation / "cpu-full-repair-r3/summary.json", "cpu-full", lambda d: d.update(cases_jsonl_sha256="0" * 64))
    def row_failure(name, mutate, valid_digest=True):
        directory = validation / "cpu-full-repair-r3"
        cases, summary = directory / "cases.jsonl", directory / "summary.json"
        original_cases, original_summary = cases.read_bytes(), summary.read_bytes()
        lines = cases.read_text(encoding="utf-8").splitlines()
        row = json.loads(lines[0])
        row.pop("record_sha256")
        mutate(row)
        row["record_sha256"] = canonical(row) if valid_digest else "0" * 64
        lines[0] = json.dumps(row)
        cases.write_text("\n".join(lines) + "\n", encoding="utf-8")
        data = json.loads(original_summary); data["cases_jsonl_sha256"] = sha(cases); write(summary, data)
        try:
            result = invoke(root)
            checks.append({"name": name, "passed": next(x for x in result["checks"] if x["name"] == "cpu-full")["passed"] is False})
        finally:
            cases.write_bytes(original_cases); summary.write_bytes(original_summary)
    row_failure("cpu-row-checksum-mismatch", lambda d: None, valid_digest=False)
    row_failure("cpu-row-failure-status", lambda d: d.update(status="failed", passed=False))
    row_failure("cpu-row-check-false", lambda d: d.update(checks={"fixture": False}))
    row_failure("cpu-row-source-binding-differs", lambda d: d.update(source_hashes={}))
    row_failure("cpu-row-case-identity-differs", lambda d: d.update(case={"case_id": "wrong"}))
    json_failure("config-empty-checks", config / "manifest.json", "same-output-build-identity", lambda d: d.update(checks={}))
    json_failure("config-empty-steps", config / "manifest.json", "same-output-build-identity", lambda d: d.update(steps=[]))
    json_failure("config-failed-returncode", config / "manifest.json", "same-output-build-identity", lambda d: d["steps"][0].update(returncode=1))
    json_failure("clean-empty-source-map", clean / "manifest.json", "clean-reproduction", lambda d: d.update(source_sha256={}))
    json_failure("clean-formal-timing-state", clean / "manifest.json", "clean-reproduction", lambda d: d.update(formal_performance_started=True))
    json_failure("clean-empty-provider-inventory", clean / "manifest.json", "clean-reproduction", lambda d: d.update(external_provider_sha256={}))
    for name in ("device-code-resource-sass.log",):
        missing_file("resource-required-" + name, resource_dir / name, "cuda-device-resources")
    for name in ("sm3_cuda.o", "ptxas.log"):
        missing_file("resource-required-" + name, build / name, "cuda-device-resources")
    json_failure("demo-empty-artifacts", demo / "manifest.json", "demo-media", lambda d: d.update(artifacts_sha256={}))
    missing_file("demo-required-video", demo / "evidence-demo.mp4", "demo-media")
    json_failure("binding-empty-inputs", binding / "package.json", "correctness-analysis-binding", lambda d: d.update(evidence_sha256={}))
    json_failure("binding-empty-csv-map", binding / "package.json", "correctness-analysis-binding", lambda d: d.update(files_sha256={}))
    json_failure("fixture-bundle-test-only-required", fixture_root / "MANIFEST.json", "test-fixtures-and-ca-ledger", lambda d: d.update(test_only=False))
    json_failure("fixture-set-required", fixture_root / "MANIFEST.json", "test-fixtures-and-ca-ledger", lambda d: d.update(fixtures=[]))
    missing_file("fixture-authorized-test-key-required", fixture_root / "slh-dsa-sm3-128s/handshake-test-key.json", "test-fixtures-and-ca-ledger")
    def ledger_failure(name, sql):
        original = ledger_path.read_bytes()
        connection = sqlite3.connect(ledger_path)
        connection.execute(sql); connection.commit(); connection.close()
        try:
            result = invoke(root)
            checks.append({"name": name, "passed": next(x for x in result["checks"] if x["name"] == "test-fixtures-and-ca-ledger")["passed"] is False})
        finally:
            ledger_path.write_bytes(original)
    ledger_failure("fixture-ledger-UUID-differs", "UPDATE ledger_metadata SET value='wrong' WHERE name='ledger_uuid'")
    ledger_failure("fixture-receipt-missing", "DELETE FROM reservations WHERE receipt=(SELECT receipt FROM reservations LIMIT 1)")
    ledger_failure("fixture-receipt-status-differs", "UPDATE reservations SET status='reserved'")
    ledger_failure("fixture-receipt-message-digest-differs", "UPDATE reservations SET message_sha256='wrong'")
    ledger_failure("fixture-receipt-signature-digest-differs", "UPDATE reservations SET signature_sha256='wrong'")
    ledger_failure("fixture-charge-reconciliation-differs", "UPDATE keys SET used_text='0'")

result = {"schema": "a15-project-audit-repair-synthetic-regression-v1", "passed": all(row["passed"] for row in checks),
          "checks": checks, "check_count": len(checks), "passed_checks": sum(row["passed"] for row in checks),
          "tool_sha256": sha(ROOT / "ops/audit_project_repair.py"), "native_calls": 0, "real_timing_samples": 0,
          "formal_performance_started": False, "scope": "Synthetic metadata fixtures and stub delivery; not actual matrix or runtime acceptance."}
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, default=ROOT / "build/repair-delivery-tools/project-audit-regression.json")
output = parser.parse_args().output
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(json.dumps({key: result[key] for key in ("passed", "check_count", "passed_checks", "tool_sha256", "native_calls", "real_timing_samples")}))
raise SystemExit(int(not result["passed"]))
