"""Synthetic regressions for the read-only parallel CPU evidence auditor.

The fixture is deliberately tiny and uses no project execution modules, native
libraries, remote environment, or elapsed-time measurements.  Library files are
plain bytes.  Every negative fixture is derived from a complete positive one.
"""
from __future__ import annotations

import argparse
from contextlib import closing
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
STAGE_NAME = "build/repair-staging-20261004-r3"
REMOTE = "/home/guest-experiment/pqc-a1-5/" + STAGE_NAME
SCHEMA = "a15-optimization-correctness-v1"
PARALLEL = "a15-parallel-correctness-provenance-v1"
FIELDS = ("prf", "prf_msg", "h_msg", "f", "h", "t", "compress")
UUID = "0123456789abcdef0123456789abcdef"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    return digest(Path(path).read_bytes())


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json.dumps(value, sort_keys=True, indent=2).encode("utf-8") + b"\n")


def put(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def case_id(case):
    return "/".join(str(case[key]) for key in
                    ("library", "pid", "backend", "threads", "operation", "variant"))


def raw_rows(rows):
    output = []
    for row in rows:
        row = deepcopy(row)
        row.pop("record_sha256", None)
        row["record_sha256"] = digest(canonical(row))
        output.append(json.dumps(row, sort_keys=True).encode("utf-8") + b"\n")
    return b"".join(output)


def import_auditor():
    spec = importlib.util.spec_from_file_location(
        "a15_parallel_read_only_audit", ROOT / "ops/audit_parallel_correctness.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Fixture:
    """Three planned cases, one independent worker, and two settled charges."""

    def __init__(self, root):
        self.root = Path(root)
        self.stage = self.root / STAGE_NAME
        self.cpu = self.stage / "validation/cpu-full-repair-r3"
        self.history = self.stage / "validation/cpu-full-repair-r3-serial-history"
        self.work = self.stage / "validation/parallel-correctness-r3"
        self.worker = self.work / "worker-00"
        self.live = self.stage / "validation/repair-pipeline/correctness-budget.sqlite"
        self.vectors = self.stage / "report-data/DP1-analysis/count-replay-inputs.jsonl"
        self.library = self.stage / "build/native-repair-r3/counters/libslhdsa_sm3.so"
        self.controller = self.work / "controller.py"
        self.helper = self.root / "ops/parallel_correctness.py"
        self.copied_cache_inputs = []
        for name in ("ops/parallel_correctness.py", "ops/audit_parallel_correctness.py"):
            put(self.root / name, (ROOT / name).read_bytes())
        put(self.stage / "ops/parallel_correctness.py", self.helper.read_bytes())
        for path in (self.root / "ops/test_parallel_correctness.py", self.stage / "ops/test_parallel_correctness.py"):
            put(path, (ROOT / "ops/test_parallel_correctness.py").read_bytes())
        acceptance_dir = self.stage / "build/repair-delivery-tools/parallel-regression"
        write(acceptance_dir / "selftest.json", {"schema": "a15-parallel-correctness-selftest-v1", "passed": True,
            "mock_checks": 55, "failures": 0, "errors": 0, "native_calls": 0, "real_timing_samples": 0,
            "formal_performance_started": False, "actual_matrix_acceptance": False,
            "tool_sha256": sha(self.helper), "test_tool_sha256": sha(self.root / "ops/test_parallel_correctness.py")})
        put(acceptance_dir / "selftest.log", b"synthetic 55/55 helper acceptance; no native calls\n")
        put(self.root / "build/run_parallel_repair.py", b"# synthetic controller\n")
        put(self.controller, b"# synthetic controller\n")
        put(self.library, b"synthetic library bytes; never loaded\n")
        put(self.root / "c/src/engine.c", b"/* synthetic source; never compiled */\n")
        self.sources = {"c/src/engine.c": sha(self.root / "c/src/engine.c")}
        self.label = "lib0-" + sha(self.library)[:12]
        self.libraries = {self.label: {"path": self.remote(self.library), "sha256": sha(self.library)}}
        self.vector = {"case_id": "synthetic-vector-201", "pid": 201,
            "sk_seed": "00" * 16, "sk_prf": "11" * 16, "pk_seed": "22" * 16,
            "pk": "22" * 16 + "33" * 16, "sk": "00" * 16 + "11" * 16 + "22" * 16 + "33" * 16,
            "mp": "736e617073686f742d66697874757265", "sig": "44" * 32,
            "opt_rand": "55" * 16, "source": "synthetic fixed vector",
            "source_hashes": self.sources}
        self.vector["record_sha256"] = digest(canonical(self.vector))
        put(self.vectors, json.dumps(self.vector, sort_keys=True).encode() + b"\n")
        self.fingerprint = {"case_id": self.vector["case_id"], "pid": 201,
            "vector_file": self.remote(self.vectors), "vector_line": 1,
            "vector_file_sha256": sha(self.vectors), "original_source": self.vector["source"],
            "original_source_hashes": self.sources,
            **{target: digest(bytes.fromhex(self.vector[source])) for source, target in (
                ("pk", "public_key_sha256"), ("sk", "secret_key_sha256"),
                ("mp", "encoded_message_sha256"), ("opt_rand", "opt_rand_sha256"),
                ("sig", "signature_sha256"))}}
        self.plan = [self.case("counter_probe", "enabled"),
                     self.case("backend_rejection", "explicit-SHA2-AVX2"),
                     self.case("sign", "native-t0")]
        self.serial_rows = [self.row(self.plan[0]), self.row(self.plan[1])]
        self.worker_rows = [self.row(self.plan[0]), self.row(self.plan[2]),
                            self.row(self.case("verify_generated", "native-t0"))]
        self.identity = {"schema": SCHEMA, "sources_sha256": self.sources,
            "libraries": self.libraries, "vector_sha256": sha(self.vectors),
            "budget_database_path": self.remote(self.live),
            "configuration": {"run_dir": self.remote(self.cpu), "budget_db": self.remote(self.live),
                "vectors": self.remote(self.vectors), "library": [self.remote(self.library)],
                "suite": "full", "full_sha2": True, "full_small": True,
                "backends": ["REF", "AVX2"], "threads": [1, 2, 4, 8, 16, 32, 64]}}
        self.original_manifest = {"identity": self.identity, "plan": self.plan}
        self.worker_manifest = deepcopy(self.original_manifest)
        self.worker_manifest["identity"]["configuration"]["run_dir"] = self.remote(self.worker)
        self.binding = {"ledger_uuid": UUID, "receipt": "receipt-sign-001",
            "key_id": digest(b"a15:slh:pid:201\0" + bytes.fromhex(self.vector["pk"])),
            "algorithm": "slh-dsa-sm3-toy", "public_key_sha256": self.fingerprint["public_key_sha256"],
            "message_sha256": self.fingerprint["encoded_message_sha256"],
            "status": "committed", "signature_sha256": self.fingerprint["signature_sha256"]}
        self.key_status = {"key_id": self.binding["key_id"], "algorithm": self.binding["algorithm"],
            "limit": 16, "used": 2, "remaining": 14, "states": {"committed": 1, "failed": 1},
            "count_reconciled": True}
        self.create_ledger()
        self.publish()

    def remote(self, path):
        return REMOTE + "/" + Path(path).relative_to(self.stage).as_posix()

    def case(self, operation, variant):
        result = {"library": self.label, "pid": 201, "backend": "REF", "threads": 1,
                  "operation": operation, "variant": variant, "cache_t": None}
        result["case_id"] = case_id(result)
        return result

    def row(self, case):
        checks = {"counter_probe": {"counters_enabled": True},
                  "backend_rejection": {"explicit_SHA2_AVX2_rejected": True},
                  "sign": {"signature_equals_existing_complete_vector": True},
                  "derive_cache": {"all_levels_exported": True, "top_root_matches": True},
                  "cache_load_setup": {},
                  "verify_generated": {"new_signature_valid": True}}[case["operation"]]
        prediction = None if case["operation"] in {"backend_rejection", "derive_cache"} else {
            "model": "stage1-implemented-path-v1", "pid": 201,
            "operation": case["operation"], "counts": dict.fromkeys(FIELDS, 1)}
        result = {"signature_sha256": self.fingerprint["signature_sha256"]} if case["operation"] in {
            "sign", "verify_generated"} else {"fixture": True}
        value = {"schema": SCHEMA, "case_id": case["case_id"], "case": deepcopy(case),
            "status": "passed", "passed": True, "checks": checks, "prediction": prediction,
            "observed": prediction["counts"] if prediction else None,
            "field_matches": dict.fromkeys(FIELDS, True) if prediction else {},
            "input": deepcopy(self.fingerprint),
            "input_sha256": digest(canonical({"case": case, "input": self.fingerprint})),
            "result": result, "result_sha256": digest(canonical(result)),
            "source_hashes": self.sources, "library": self.libraries[self.label],
            "formal_performance": False, "recorded_utc": "2026-10-04T00:00:00+00:00"}
        if case["operation"] == "sign":
            value.update(budget_receipt="receipt-sign-001", budget_status="committed")
        return value

    def create_ledger(self):
        path = self.cpu / "settled-budget.sqlite"
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(path)) as db:
            db.executescript("""CREATE TABLE ledger_metadata(name TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE keys(key_id TEXT PRIMARY KEY,algorithm TEXT NOT NULL,public_key BLOB NOT NULL,
                                  limit_text TEXT NOT NULL,used_text TEXT NOT NULL);
                CREATE TABLE reservations(receipt TEXT PRIMARY KEY,key_id TEXT NOT NULL,ordinal_text TEXT NOT NULL,
                                  message_sha256 TEXT NOT NULL,status TEXT NOT NULL,signature_sha256 TEXT);""")
            db.executemany("INSERT INTO ledger_metadata VALUES (?,?)", [("identity_schema", "2"), ("ledger_uuid", UUID)])
            db.execute("INSERT INTO keys VALUES (?,?,?,?,?)", (self.binding["key_id"], self.binding["algorithm"],
                       bytes.fromhex(self.vector["pk"]), "16", "2"))
            db.executemany("INSERT INTO reservations VALUES (?,?,?,?,?,?)", [
                ("receipt-sign-001", self.binding["key_id"], "1", self.binding["message_sha256"], "committed", self.binding["signature_sha256"]),
                ("receipt-interrupted-002", self.binding["key_id"], "2", self.binding["message_sha256"], "failed", None)])
            db.commit()

    def ledger_change(self, sql, parameters=()):
        with closing(sqlite3.connect(self.cpu / "settled-budget.sqlite")) as db:
            db.execute(sql, parameters)
            db.commit()

    def summary(self, rows, path, *, aggregate=False):
        seen = {row["case_id"] for row in rows}
        plan_ids = {case["case_id"] for case in self.plan}
        pending = sorted(plan_ids - seen)
        value = {"schema": SCHEMA, "completed_requested_scope": not pending, "passed": not pending,
            "planned_cases": len(self.plan), "passed_planned": len(plan_ids & seen),
            "pending_case_ids": pending, "failed_case_ids": [], "unavailable_case_ids": [],
            "failed_auxiliary_case_ids": [], "records": len(rows), "error": "KeyboardInterrupt" if path == self.history else None,
            "suite": "full", "full_sha2": True, "full_small": True, "deferred_scope": [], "final": True,
            "source_hashes": self.sources, "libraries": self.libraries, "cases_jsonl_sha256": sha(path / "cases.jsonl"),
            "global_atomic_measurements_serialized": not aggregate,
            "budget_database": self.remote(self.cpu / "settled-budget.sqlite") if aggregate else self.remote(self.live),
            "budget_status": [self.key_status], "formal_performance_started": False,
            "real_timing_samples": 0, "measured_durations": False}
        if aggregate:
            value.update(counter_measurements_serialized_per_process=True, budget_ledger_uuid=UUID,
                         budget_snapshot_sha256=sha(self.cpu / "settled-budget.sqlite"))
        return value

    def publish(self):
        put(self.history / "cases.jsonl", raw_rows(self.serial_rows))
        put(self.worker / "cases.jsonl", raw_rows(self.worker_rows))
        write(self.history / "manifest.json", self.original_manifest)
        write(self.worker / "manifest.json", self.worker_manifest)
        write(self.history / "summary.json", self.summary(self.serial_rows, self.history))
        write(self.worker / "summary.json", self.summary(self.worker_rows, self.worker))
        selected = self.work / "worker-00.cases.json"
        write(selected, [self.plan[2]["case_id"]])
        write(self.worker / "worker-provenance.json", {"schema": PARALLEL, "kind": "worker",
            "original_manifest_path": self.remote(self.history / "manifest.json"),
            "original_manifest_sha256": sha(self.history / "manifest.json"),
            "requested_case_ids": [self.plan[2]["case_id"]],
            "executed_case_ids": [self.plan[0]["case_id"], self.plan[2]["case_id"]],
            "requested_scope_complete": True, "error": None, "copied_caches": [], "receipt_bindings": [self.binding],
            "global_atomic_measurements_serialized": True, "formal_performance_started": False, "real_timing_samples": 0,
            "input_files_sha256": {self.remote(path): sha(path) for path in
                (self.history / "manifest.json", self.library, self.vectors, selected)},
            "cases_jsonl_sha256": sha(self.worker / "cases.jsonl"),
            "worker_summary_sha256": sha(self.worker / "summary.json"), "helper_sha256": sha(self.helper)})
        put(self.work / "worker-00.log", b'{"synthetic_worker_finished":true}\n')
        write(self.work / "handoff.json", {"pids": {"101": "python tools/check_optimization.py"},
            "cpu_signal": "SIGINT", "waiting_signal": "SIGSTOP", "core_budget": 2, "physical_cpus": [0, 1],
            "formal_performance_started": False, "real_timing_samples": 0, "controller_sha256": sha(self.controller)})
        write(self.work / "assignments.json", {"assignments": [{"name": "worker-00", "directory": self.remote(self.worker),
            "cases_file": self.remote(selected), "threads": 1, "pid": 201, "backend": "REF", "case_ids": [self.plan[2]["case_id"]]}],
            "pending_cases": 1,
            "completed_serial": len({case["case_id"] for case in self.plan} & {row["case_id"] for row in self.serial_rows}),
            "full_plan": len(self.plan)})
        write(self.work / "execution.json", {"events": [
            {"worker": "worker-00", "pid": 102, "cores": [0], "threads": 1, "event": "started"},
            {"worker": "worker-00", "pid": 102, "event": "finished", "returncode": 0}],
            "all_workers_exited": True, "all_returncodes_zero": True, "core_budget": 2,
            "formal_performance_started": False, "real_timing_samples": 0})
        put(self.stage / "validation/repair-pipeline/speed-controller.log",
            b'{"started":"worker-00","pid":102,"threads":1,"cores":[0]}\n'
            b'{"finished":"worker-00","returncode":0}\n')
        write(self.cpu / "settlement.json", {"schema": "a15-cpu-correctness-budget-settlement-v1", "ledger_uuid": UUID,
            "live_database_path": self.remote(self.live), "snapshot_database_path": self.remote(self.cpu / "settled-budget.sqlite"),
            "snapshot_sha256": sha(self.cpu / "settled-budget.sqlite"), "all_fees_preserved": True, "ordinals_reconciled": True,
            "reserved_attempts": 0, "charged_attempts": 2, "keys": [self.key_status], "receipts": [
                {"receipt": "receipt-interrupted-002", "key_id": self.binding["key_id"], "ordinal": 2,
                 "message_sha256": self.binding["message_sha256"], "status": "failed", "signature_sha256": None},
                {"receipt": "receipt-sign-001", "key_id": self.binding["key_id"], "ordinal": 1,
                 "message_sha256": self.binding["message_sha256"], "status": "committed", "signature_sha256": self.binding["signature_sha256"]}],
            "record_receipts_verified": 1, "charged_attempts_without_matrix_rows": 1,
            "native_calls": 0, "real_timing_samples": 0})
        self.rebind()

    def rebind(self):
        """Refresh hash bindings after a mutation, retaining semantic content."""
        settlement = read(self.cpu / "settlement.json")
        settlement["snapshot_sha256"] = sha(self.cpu / "settled-budget.sqlite")
        write(self.cpu / "settlement.json", settlement)
        input_runs = []
        input_files = {self.remote(self.library): sha(self.library), self.remote(self.vectors): sha(self.vectors)}
        for index, directory in enumerate((self.history, self.worker)):
            summary = read(directory / "summary.json")
            summary["cases_jsonl_sha256"] = sha(directory / "cases.jsonl")
            write(directory / "summary.json", summary)
            files = ["manifest.json", "summary.json", "cases.jsonl"]
            entry = {"directory": self.remote(directory), "manifest_sha256": sha(directory / "manifest.json"),
                "summary_sha256": sha(directory / "summary.json"), "cases_jsonl_sha256": sha(directory / "cases.jsonl"),
                "records": len((directory / "cases.jsonl").read_bytes().splitlines())}
            if index:
                proof = read(directory / "worker-provenance.json")
                proof["cases_jsonl_sha256"] = entry["cases_jsonl_sha256"]
                proof["worker_summary_sha256"] = entry["summary_sha256"]
                write(directory / "worker-provenance.json", proof)
                entry["worker_provenance_sha256"] = sha(directory / "worker-provenance.json")
                files.append("worker-provenance.json")
                if (directory / "cache-source-records.jsonl").exists():
                    files.append("cache-source-records.jsonl")
            for name in files:
                path = directory / name
                put(self.cpu / f"provenance/input-{index}" / name, path.read_bytes())
                input_files[self.remote(path)] = sha(path)
            input_runs.append(entry)
        put(self.cpu / "cases.jsonl", (self.history / "cases.jsonl").read_bytes() + (self.worker / "cases.jsonl").read_bytes())
        summary = self.summary([*self.serial_rows, *self.worker_rows], self.cpu, aggregate=True)
        write(self.cpu / "summary.json", summary)
        parallel = {"schema": PARALLEL, "input_runs": input_runs,
            "original_manifest_path": self.remote(self.history / "manifest.json"), "original_manifest_sha256": sha(self.history / "manifest.json"),
            "helper_path": self.remote(self.stage / "ops/parallel_correctness.py"), "helper_sha256": sha(self.helper),
            "receipts_verified": 1, "ledger_uuid": UUID,
            "settled_budget_path": self.remote(self.cpu / "settled-budget.sqlite"), "settled_budget_sha256": sha(self.cpu / "settled-budget.sqlite"),
            "settlement_path": self.remote(self.cpu / "settlement.json"), "settlement_sha256": sha(self.cpu / "settlement.json"),
            "copied_cache_inputs": self.copied_cache_inputs, "process_local_measurements_serialized": True,
            "real_timing_samples": 0, "formal_performance_started": False}
        write(self.cpu / "manifest.json", {**deepcopy(self.original_manifest), "parallel_provenance": parallel})
        write(self.cpu / "provenance.json", {"schema": PARALLEL, "kind": "aggregate", "native_calls": 0,
            "real_timing_samples": 0, "formal_performance_started": False, "original_identity_preserved": True,
            "input_files_sha256": input_files, "input_runs": input_runs, "receipt_bindings": [self.binding],
            "ledger_uuid": UUID, "helper_sha256": sha(self.helper), "output_files_sha256": {
                name: sha(self.cpu / name) for name in ("manifest.json", "cases.jsonl", "summary.json", "settled-budget.sqlite", "settlement.json")}})
        write(self.work / "published.json", {"passed": True, "canonical_path": self.remote(self.cpu),
            "summary_sha256": sha(self.cpu / "summary.json"), "formal_performance_started": False, "real_timing_samples": 0})

    def change_json(self, path, action, *, rebind=True):
        value = read(path)
        action(value)
        write(path, value)
        if rebind:
            self.rebind()

    def audit(self):
        return import_auditor().audit_parallel(self.root, self.stage, REMOTE, self.cpu, expected_plan_count=len(self.plan))

    def add_cache_provenance(self):
        """Bind a copied level-one cache to an exact preserved serial prefix."""
        cache_bytes = b"synthetic level-one cache bytes; never parsed or loaded\n"
        cache_sha = digest(cache_bytes)
        sign = self.case("sign", "native-t1")
        sign["cache_t"] = 1
        self.plan[2] = sign
        derived = self.case("derive_cache", "all-levels")
        self.plan.append(derived)
        derived_row = self.row(derived)
        derived_row["result"] = {"family": [{"level": 1, "file_sha256": cache_sha}]}
        derived_row["result_sha256"] = digest(canonical(derived_row["result"]))
        self.serial_rows.append(derived_row)
        loaded = {**sign, "operation": "cache_load_setup", "variant": sign["variant"] + "/load"}
        loaded["case_id"] = case_id(loaded)
        loaded_row = self.row(loaded)
        loaded_row["result"] = {"cache_file_sha256": cache_sha}
        loaded_row["result_sha256"] = digest(canonical(loaded_row["result"]))
        verified = {**sign, "operation": "verify_generated"}
        verified["case_id"] = case_id(verified)
        self.worker_rows = [self.row(self.plan[0]), loaded_row, self.row(sign), self.row(verified)]
        self.worker_manifest["plan"] = deepcopy(self.plan)
        self.publish()
        source = self.history / "cache" / self.label / "pid201/pid201-t1.cache"
        destination = self.worker / "cache" / self.label / "pid201/pid201-t1.cache"
        preserved = self.cpu / "provenance/cache-input-0.bin"
        for path in (source, destination, preserved):
            put(path, cache_bytes)
        records = self.worker / "cache-source-records.jsonl"
        put(records, (self.history / "cases.jsonl").read_bytes())
        proof = read(self.worker / "worker-provenance.json")
        proof["copied_caches"] = [{"source_path": self.remote(source), "destination_path": self.remote(destination),
            "sha256": cache_sha, "source_records_path": self.remote(self.history / "cases.jsonl"),
            "source_records_snapshot_path": self.remote(records), "source_records_snapshot_sha256": sha(records)}]
        proof["input_files_sha256"].update({self.remote(source): cache_sha,
            self.remote(destination): cache_sha, self.remote(records): sha(records)})
        write(self.worker / "worker-provenance.json", proof)
        self.copied_cache_inputs = [{"input_run": self.remote(self.worker), "source_path": self.remote(source),
            "worker_path": self.remote(destination), "sha256": cache_sha,
            "preserved_path": "provenance/cache-input-0.bin"}]
        self.rebind()
        return preserved, records

    def terminated_handoff(self):
        """Preserve raw non-final history and checkpoint an exact byte copy."""
        summary = read(self.history / "summary.json")
        summary.update(final=False, error=None)
        write(self.history / "summary.json", summary)
        generated = self.work / "serial-snapshot"
        for name in ("manifest.json", "summary.json", "cases.jsonl"):
            put(generated / name, (self.history / name).read_bytes())
        manifest = read(generated / "manifest.json")
        manifest["identity"]["configuration"]["run_dir"] = self.remote(generated)
        write(generated / "manifest.json", manifest)
        summary.update(final=True, error="External SIGTERM handoff: controller-generated snapshot; original unfinished raw summary retained separately")
        write(generated / "summary.json", summary)
        handoff = read(self.work / "handoff.json")
        handoff["cpu_signal"] = "SIGTERM after stable SIGSTOP snapshot"
        write(self.work / "handoff.json", handoff)
        write(self.work / "termination.json", {"original_summary_final": False,
            "original_files_sha256": {name: sha(self.history / name) for name in ("manifest.json", "summary.json", "cases.jsonl")},
            "charged_aborted_receipts": ["receipt-interrupted-002"], "generated_snapshot": self.remote(generated),
            "original_raw_evidence_preserved": True, "native_calls": 0, "real_timing_samples": 0})
        final_manifest = read(self.cpu / "manifest.json")
        entry = final_manifest["parallel_provenance"]["input_runs"][0]
        entry.update(directory=self.remote(generated), manifest_sha256=sha(generated / "manifest.json"),
                     summary_sha256=sha(generated / "summary.json"))
        write(self.cpu / "manifest.json", final_manifest)
        proof = read(self.cpu / "provenance.json")
        proof["input_runs"][0] = entry
        for name in ("manifest.json", "summary.json", "cases.jsonl"):
            put(self.cpu / "provenance/input-0" / name, (generated / name).read_bytes())
            proof["input_files_sha256"].pop(self.remote(self.history / name), None)
            proof["input_files_sha256"][self.remote(generated / name)] = sha(generated / name)
        proof["input_files_sha256"][self.remote(self.history / "manifest.json")] = sha(self.history / "manifest.json")
        proof["output_files_sha256"]["manifest.json"] = sha(self.cpu / "manifest.json")
        write(self.cpu / "provenance.json", proof)

    def adjust_affinity(self):
        raw = (self.work / "handoff.json").read_bytes()
        put(self.work / "handoff.before-affinity.json", raw)
        put(self.work / "affinity-controller.py", b"# synthetic affinity controller\n")
        adjustment = {"schema": "a15-correctness-affinity-adjustment-v1", "status": "applied",
            "changes": [{"worker": "worker-00", "pid": 102, "threads": 1,
                "assigned_initial_cores": [0], "new_cores": [1], "tasks": [{"tid": 102, "before": [0], "after": [1]}],
                "command": "python ops/parallel_correctness.py worker --run-dir " + self.remote(self.worker)
                    + " --cases " + self.remote(self.work / "worker-00.cases.json")
                    + " --manifest " + self.remote(self.history / "manifest.json") + " "}],
            "observed_idle_percent": {"0": 10.0, "1": 99.0}, "original_handoff_sha256": digest(raw),
            "controller_sha256": sha(self.work / "affinity-controller.py"), "all_groups_launched": True,
            "core_budget": 2, "native_calls": 0, "real_timing_samples": 0, "formal_performance_started": False}
        write(self.work / "affinity-adjustment.json", adjustment)
        self.rebind_affinity()

    def rebind_affinity(self):
        handoff = read(self.work / "handoff.json")
        handoff["external_affinity_adjustment"] = {"path": self.remote(self.work / "affinity-adjustment.json"),
            "sha256": sha(self.work / "affinity-adjustment.json"), "original_handoff_sha256": sha(self.work / "handoff.before-affinity.json")}
        write(self.work / "handoff.json", handoff)


class ParallelAuditTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="a15-parallel-audit-")
        self.addCleanup(self.folder.cleanup)
        self.fixture = Fixture(Path(self.folder.name))

    def reject(self):
        with self.assertRaises(ValueError):
            self.fixture.audit()

    def test_terminated_handoff_preserves_original_and_charged_aborted_attempt(self):
        self.fixture.terminated_handoff()
        self.assertEqual(self.fixture.audit()["details"]["charged_attempts"], 2)

    def test_terminated_handoff_original_bytes_hash(self):
        self.fixture.terminated_handoff()
        put(self.fixture.history / "summary.json", b"{}\n")
        self.reject()

    def test_terminated_handoff_snapshot_raw_bytes(self):
        self.fixture.terminated_handoff()
        f = self.fixture
        put(f.work / "serial-snapshot/cases.jsonl", (f.work / "serial-snapshot/cases.jsonl").read_bytes() + b"\n")
        self.reject()

    def test_terminated_handoff_aborted_receipt_must_be_failed_charge(self):
        self.fixture.terminated_handoff()
        f = self.fixture
        value = read(f.work / "termination.json")
        value["charged_aborted_receipts"] = ["receipt-sign-001"]
        write(f.work / "termination.json", value)
        self.reject()

    def test_terminated_handoff_requires_disclosure(self):
        self.fixture.terminated_handoff()
        (self.fixture.work / "termination.json").unlink()
        self.reject()

    def test_missing_helper_launch_acceptance(self):
        (self.fixture.stage / "build/repair-delivery-tools/parallel-regression/selftest.json").unlink()
        self.reject()

    def test_helper_launch_acceptance_hash(self):
        f = self.fixture
        f.change_json(f.stage / "build/repair-delivery-tools/parallel-regression/selftest.json",
                      lambda value: value.update(tool_sha256="0" * 64), rebind=False)
        self.reject()

    def test_helper_launch_test_source_hash(self):
        put(self.fixture.stage / "ops/test_parallel_correctness.py", b"changed fixture test source")
        self.reject()

    def test_helper_launch_mock_acceptance_disclosed_as_actual(self):
        f = self.fixture
        f.change_json(f.stage / "build/repair-delivery-tools/parallel-regression/selftest.json",
                      lambda value: value.update(actual_matrix_acceptance=True), rebind=False)
        self.reject()

    def test_remote_stage_parent_traversal_rejected(self):
        f = self.fixture
        f.change_json(f.cpu / "manifest.json", lambda value: value["identity"]["configuration"].update(
            run_dir=REMOTE + "/validation/../validation/cpu-full-repair-r3"), rebind=False)
        self.reject()

    def test_original_relative_stage_configuration(self):
        f = self.fixture
        config = f.original_manifest["identity"]["configuration"]
        config.update(run_dir="validation/cpu-full-repair-r3", budget_db="validation/repair-pipeline/correctness-budget.sqlite",
                      library=[f.library.relative_to(f.stage).as_posix()])
        f.worker_manifest["identity"] = deepcopy(f.original_manifest["identity"])
        f.worker_manifest["identity"]["configuration"]["run_dir"] = f.remote(f.worker)
        f.publish()
        self.assertTrue(f.audit()["details"]["assignment_coverage_complete"])

    def test_positive_external_affinity_adjustment(self):
        self.fixture.adjust_affinity()
        self.assertTrue(self.fixture.audit()["details"]["all_worker_exit_codes_zero"])

    def test_affinity_original_handoff_fields_preserved(self):
        f = self.fixture
        f.adjust_affinity()
        f.change_json(f.work / "handoff.json", lambda value: value.update(explanation="changed original disclosure"), rebind=False)
        self.reject()

    def test_affinity_target_must_be_in_inventory(self):
        f = self.fixture
        f.adjust_affinity()
        f.change_json(f.work / "affinity-adjustment.json", lambda value: value["changes"][0].update(new_cores=[7]), rebind=False)
        f.rebind_affinity()
        self.reject()

    def test_affinity_idle_core_evidence(self):
        f = self.fixture
        f.adjust_affinity()
        f.change_json(f.work / "affinity-adjustment.json", lambda value: value["observed_idle_percent"].update({"1": 89}), rebind=False)
        f.rebind_affinity()
        self.reject()

    def test_affinity_task_actual_after_binding(self):
        f = self.fixture
        f.adjust_affinity()
        f.change_json(f.work / "affinity-adjustment.json", lambda value: value["changes"][0]["tasks"][0].update(after=[0]), rebind=False)
        f.rebind_affinity()
        self.reject()

    def test_affinity_worker_thread_scope(self):
        f = self.fixture
        f.adjust_affinity()
        f.change_json(f.work / "affinity-adjustment.json", lambda value: value["changes"][0].update(threads=2), rebind=False)
        f.rebind_affinity()
        self.reject()

    def test_affinity_controller_hash(self):
        self.fixture.adjust_affinity()
        put(self.fixture.work / "affinity-controller.py", b"changed controller")
        self.reject()

    def test_controller_log_exit_binding(self):
        put(self.fixture.stage / "validation/repair-pipeline/speed-controller.log",
            b'{"started":"worker-00","pid":102,"threads":1,"cores":[0]}\n'
            b'{"finished":"worker-00","returncode":1}\n')
        self.reject()

    def test_complete_positive_preserves_read_only_flags_and_closure(self):
        result = self.fixture.audit()
        self.assertEqual(result["native_calls"], 0)
        self.assertEqual(result["real_timing_samples"], 0)
        self.assertIs(result["formal_performance_started"], False)
        evidence = result["evidence_sha256"]
        self.assertTrue(evidence)
        for path in (self.fixture.cpu / "settled-budget.sqlite", self.fixture.cpu / "settlement.json",
                     self.fixture.history / "cases.jsonl", self.fixture.worker / "worker-provenance.json",
                     self.fixture.work / "execution.json", self.fixture.work / "worker-00.log"):
            self.assertEqual(evidence[path.relative_to(self.fixture.root).as_posix()], sha(path))

    def test_aggregate_raw_bytes_must_be_original_concatenation(self):
        f = self.fixture
        put(f.cpu / "cases.jsonl", (f.cpu / "cases.jsonl").read_bytes().replace(b'"checks": {', b'"checks" : {', 1))
        summary = read(f.cpu / "summary.json")
        summary["cases_jsonl_sha256"] = sha(f.cpu / "cases.jsonl")
        write(f.cpu / "summary.json", summary)
        proof = read(f.cpu / "provenance.json")
        proof["output_files_sha256"]["cases.jsonl"] = sha(f.cpu / "cases.jsonl")
        proof["output_files_sha256"]["summary.json"] = sha(f.cpu / "summary.json")
        write(f.cpu / "provenance.json", proof)
        publication = read(f.work / "published.json")
        publication["summary_sha256"] = sha(f.cpu / "summary.json")
        write(f.work / "published.json", publication)
        self.reject()

    def test_positive_cache_provenance_includes_preserved_bytes_and_source_records(self):
        f = self.fixture
        preserved, records = f.add_cache_provenance()
        evidence = f.audit()["evidence_sha256"]
        for path in (preserved, records, f.cpu / "provenance/input-1/cache-source-records.jsonl"):
            self.assertEqual(evidence[path.relative_to(f.root).as_posix()], sha(path))

    def test_altered_preserved_cache_bytes(self):
        preserved, _ = self.fixture.add_cache_provenance()
        put(preserved, b"changed preserved cache bytes\n")
        self.reject()

    def test_missing_preserved_cache_bytes(self):
        preserved, _ = self.fixture.add_cache_provenance()
        preserved.unlink()
        self.reject()

    def test_cache_raw_source_binding_must_match_bytes(self):
        f = self.fixture
        _, records = f.add_cache_provenance()
        row = f.serial_rows[-1]
        row["result"]["family"][0]["file_sha256"] = "0" * 64
        row["result_sha256"] = digest(canonical(row["result"]))
        put(f.history / "cases.jsonl", raw_rows(f.serial_rows))
        put(records, (f.history / "cases.jsonl").read_bytes())
        proof = read(f.worker / "worker-provenance.json")
        proof["copied_caches"][0]["source_records_snapshot_sha256"] = sha(records)
        proof["input_files_sha256"][f.remote(records)] = sha(records)
        write(f.worker / "worker-provenance.json", proof)
        f.rebind()
        with self.assertRaisesRegex(ValueError, "raw derivation/load binding"):
            f.audit()

    def test_missing_preserved_cache_source_record_copy(self):
        f = self.fixture
        f.add_cache_provenance()
        (f.cpu / "provenance/input-1/cache-source-records.jsonl").unlink()
        self.reject()

    def test_altered_preserved_cache_source_record_copy(self):
        f = self.fixture
        f.add_cache_provenance()
        put(f.cpu / "provenance/input-1/cache-source-records.jsonl", b"{}\n")
        self.reject()

    def test_preserved_input_bytes_must_equal_original(self):
        f = self.fixture
        put(f.cpu / "provenance/input-0/cases.jsonl", b"{}\n")
        self.reject()

    def test_input_source_identity_must_match(self):
        f = self.fixture
        f.change_json(f.worker / "manifest.json", lambda v: v["identity"]["sources_sha256"].update({"c/src/engine.c": "0" * 64}))
        self.reject()

    def test_input_library_identity_must_match(self):
        f = self.fixture
        f.change_json(f.worker / "manifest.json", lambda v: v["identity"]["libraries"][f.label].update(sha256="0" * 64))
        self.reject()

    def test_input_full_plan_must_match(self):
        f = self.fixture
        f.change_json(f.worker / "manifest.json", lambda v: v["plan"].pop())
        self.reject()

    def test_missing_aggregate_sidecar(self):
        (self.fixture.cpu / "provenance.json").unlink()
        self.reject()

    def test_missing_worker_provenance(self):
        (self.fixture.worker / "worker-provenance.json").unlink()
        self.reject()

    def test_missing_assignment_file(self):
        (self.fixture.work / "worker-00.cases.json").unlink()
        self.reject()

    def test_assignment_overlap_with_completed_serial(self):
        f = self.fixture
        f.change_json(f.work / "assignments.json", lambda v: v["assignments"][0]["case_ids"].append(f.plan[1]["case_id"]))
        self.reject()

    def test_assignment_incomplete(self):
        f = self.fixture
        f.change_json(f.work / "assignments.json", lambda v: v["assignments"][0].update(case_ids=[]))
        self.reject()

    def test_generated_signature_auxiliary_required(self):
        f = self.fixture
        f.worker_rows.pop()
        f.publish()
        self.reject()

    def test_failed_worker_exit(self):
        f = self.fixture
        f.change_json(f.work / "execution.json", lambda v: v["events"][1].update(returncode=7))
        self.reject()

    def test_helper_hash_binding(self):
        f = self.fixture
        f.change_json(f.worker / "worker-provenance.json", lambda v: v.update(helper_sha256="0" * 64))
        self.reject()

    def test_controller_hash_binding(self):
        f = self.fixture
        f.change_json(f.work / "handoff.json", lambda v: v.update(controller_sha256="0" * 64))
        self.reject()

    def test_vector_raw_bytes_and_fingerprints_bound(self):
        f = self.fixture
        f.worker_rows[1]["input"]["public_key_sha256"] = "0" * 64
        f.worker_rows[1]["input_sha256"] = digest(canonical({"case": f.worker_rows[1]["case"], "input": f.worker_rows[1]["input"]}))
        f.publish()
        self.reject()

    def test_seven_field_observed_counts_must_match(self):
        f = self.fixture
        f.worker_rows[1]["observed"] = {**f.worker_rows[1]["observed"], "f": 2}
        f.publish()
        self.reject()

    def test_stale_settled_ledger_uuid(self):
        f = self.fixture
        f.ledger_change("UPDATE ledger_metadata SET value=? WHERE name='ledger_uuid'", ("f" * 32,))
        f.rebind()
        self.reject()

    def test_orphan_settled_reservation(self):
        f = self.fixture
        f.ledger_change("INSERT INTO reservations VALUES (?,?,?,?,?,?)", ("orphan", "missing-key", "1", "0" * 64, "failed", None))
        f.rebind()
        self.reject()

    def test_settled_ordinal_gap(self):
        f = self.fixture
        f.ledger_change("UPDATE reservations SET ordinal_text='3' WHERE receipt='receipt-interrupted-002'")
        f.rebind()
        self.reject()

    def test_settled_sidefile_is_active_evidence(self):
        put(self.fixture.cpu / "settled-budget.sqlite-wal", b"pending bytes")
        self.reject()

    def test_reserved_attempt_prevents_settlement_acceptance(self):
        f = self.fixture
        f.ledger_change("UPDATE reservations SET status='reserved' WHERE receipt='receipt-interrupted-002'")
        f.rebind()
        self.reject()

    def test_receipt_binding_signature_digest(self):
        f = self.fixture
        f.binding["signature_sha256"] = "0" * 64
        f.rebind()
        self.reject()

    def test_distinct_signing_cases_must_not_reuse_receipt(self):
        f = self.fixture
        second = f.case("sign", "native-t0-second")
        f.plan.append(second)
        f.worker_rows.extend((f.row(second), f.row(f.case("verify_generated", "native-t0-second"))))
        f.publish()
        # Keep the ordinary complete bindings coherent.  The only intentionally
        # invalid property is that both signing cases name receipt-sign-001.
        selected = [f.plan[2]["case_id"], second["case_id"]]
        write(f.work / "worker-00.cases.json", selected)
        assignments = read(f.work / "assignments.json")
        assignments.update(full_plan=4, pending_cases=2)
        assignments["assignments"][0]["case_ids"] = selected
        write(f.work / "assignments.json", assignments)
        proof = read(f.worker / "worker-provenance.json")
        proof.update(requested_case_ids=selected, executed_case_ids=[f.plan[0]["case_id"], *selected])
        proof["input_files_sha256"][f.remote(f.work / "worker-00.cases.json")] = sha(f.work / "worker-00.cases.json")
        write(f.worker / "worker-provenance.json", proof)
        f.rebind()
        with self.assertRaisesRegex(ValueError, "receipt reused"):
            import_auditor().audit_parallel(f.root, f.stage, REMOTE, f.cpu, expected_plan_count=4)

    def test_direct_budget_key_count_must_match_reservations(self):
        f = self.fixture
        f.ledger_change("UPDATE keys SET used_text='1'")
        f.rebind()
        self.reject()

    def test_canonical_budget_key_identity(self):
        f = self.fixture
        f.ledger_change("UPDATE keys SET algorithm='ml-dsa-44'")
        f.rebind()
        self.reject()

    def test_settlement_preserves_interrupted_attempt(self):
        f = self.fixture
        f.change_json(f.cpu / "settlement.json", lambda v: v["receipts"].pop(0))
        self.reject()

    def test_summary_claims_parallel_after_sidecars_removed(self):
        f = self.fixture
        for name in ("manifest.json", "provenance.json", "settlement.json", "settled-budget.sqlite"):
            (f.cpu / name).unlink()
        self.assertTrue(import_auditor().parallel_declared(f.cpu))
        self.reject()

    def test_timing_flags(self):
        f = self.fixture
        f.change_json(f.work / "execution.json", lambda v: v.update(real_timing_samples=1))
        self.reject()

    def test_modeled_case_requires_count_prediction(self):
        f = self.fixture
        f.worker_rows[1].update(prediction=None, observed=None, field_matches={})
        f.publish()
        self.reject()

    def test_duplicate_json_key(self):
        f = self.fixture
        raw = (f.work / "handoff.json").read_bytes()
        put(f.work / "handoff.json", raw.replace(b'{', b'{"cpu_signal": "SIGTERM",', 1))
        self.reject()

    def test_truncated_raw_final_line(self):
        f = self.fixture
        put(f.worker / "cases.jsonl", (f.worker / "cases.jsonl").read_bytes().rstrip(b"\n"))
        f.rebind()
        self.reject()

    def test_worker_extra_planned_case_execution(self):
        f = self.fixture
        f.worker_rows.insert(1, f.row(f.plan[1]))
        f.publish()
        self.reject()

    def test_duplicate_physical_core_inventory(self):
        f = self.fixture
        f.change_json(f.work / "handoff.json", lambda v: v.update(physical_cpus=[0, 0]))
        self.reject()

    def test_original_records_are_not_modified_by_audit(self):
        f = self.fixture
        paths = [path for path in f.root.rglob("*") if path.is_file()]
        before = {path: sha(path) for path in paths}
        f.audit()
        self.assertEqual(before, {path: sha(path) for path in paths})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ParallelAuditTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {"schema": "a15-parallel-correctness-audit-selftest-v1", "passed": result.wasSuccessful(),
        "tests": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
        "native_calls": 0, "real_timing_samples": 0, "formal_performance_started": False,
        "test_sha256": sha(Path(__file__)), "audit_sha256": sha(ROOT / "ops/audit_parallel_correctness.py")}
    if args.output:
        write(args.output, report)
    print(json.dumps(report, sort_keys=True))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
