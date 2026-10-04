"""Synthetic parallel-correctness regression; no native loading or performance work."""
from __future__ import annotations

from contextlib import ExitStack, closing, redirect_stdout
import copy
import ctypes
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import parallel_correctness as pc

PROJECT = Path(__file__).resolve().parents[1]
OUTPUT = PROJECT / "build/repair-delivery-tools/parallel-regression"
COUNTER_FIELDS = tuple(pc.opt.FIELDS)
BASE_RUNNER = pc.opt.Runner
REAL_BUDGET = pc.opt.SigningBudget
REAL_SETTLE = pc.settle_budget


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    return sha(Path(path).read_bytes())


def hashed(row):
    row = copy.deepcopy(row)
    row.pop("record_sha256", None)
    row["record_sha256"] = sha(pc.opt.canonical(row))
    return row


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def write_rows(path, rows):
    Path(path).write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def read_rows(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines()]


class SyntheticFixture:
    """Non-executable files plus ordinary row hashes and a strict fake receipt ledger."""

    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(exist_ok=True)
        self.source = self.root / "synthetic-source.py"
        self.source.write_bytes(b"# Synthetic source identity only\n")
        self.library = self.root / "lib-counter.so"
        self.library.write_bytes(b"NOT AN EXECUTABLE: SYNTHETIC COUNTER LIBRARY")
        self.vector_path = self.root / "vectors.jsonl"
        self.vector_path.write_bytes(b'{"synthetic":true,"contains_real_keys":false}\n')
        self.budget = self.root / "budget.sqlite"
        self.budget.write_bytes(b"SYNTHETIC LEDGER STUB; NOT A SQLITE DATABASE")
        self.canonical_run = self.root / "canonical-final"
        self.sources = {"synthetic-source.py": file_sha(self.source)}
        self.label = "lib0-" + file_sha(self.library)[:12]
        self.libraries = {self.label: {"path": str(self.library.resolve()), "sha256": file_sha(self.library)}}
        self.counts = {field: 1 for field in COUNTER_FIELDS}
        self.vector = dict(case_id="synthetic-vector-pid201", pid=201,
            vector_file=str(self.vector_path.resolve()), vector_line=1, vector_sha256=file_sha(self.vector_path),
            source="synthetic-test", pk_bytes=b"SYNTHETIC-PUBLIC-BYTES", sk_bytes=b"SYNTHETIC-NOT-A-REAL-SECRET",
            mp_bytes=b"SYNTHETIC-MESSAGE", sig_bytes=b"SYNTHETIC-SIGNATURE", opt_rand_bytes=b"",
            randomization="deterministic", trace={"chain_sums": [0], "public_root_matches": True})
        self.vectors = {201: self.vector}
        self.config = dict(library=[str(self.library.resolve())], run_dir=str(self.canonical_run.resolve()),
            budget_db=str(self.budget.resolve()), vectors=str(self.vector_path.resolve()), suite="full", full_small=False,
            full_sha2=True, threads=[1, 2, 4, 8, 16, 32, 64], backends=["REF", "AVX2"],
            cache_source_backend="REF", subtree_heights=[0, 1], fail_fast=True)
        self.plan = [self.case("counter_probe", "enabled"),
                     self.case("subtree", "fors-z1-first", kind="fors", height=1, start=0, target=0),
                     self.case("sign", "uncached", cache_t=None),
                     self.case("sign_fault", "changed-root-self-check")]
        self.identity = dict(schema=pc.opt.SCHEMA, sources_sha256=self.sources, libraries=self.libraries,
            vector_sha256=file_sha(self.vector_path), configuration=self.config,
            budget_database_path=str(self.budget.resolve()))
        self.manifest = dict(identity=self.identity, plan=self.plan, created_utc="2026-10-04T00:00:00+00:00",
            boundary="synthetic optimization correctness; formal performance has not started")
        self.manifest_path = self.root / "original-manifest.json"
        write_json(self.manifest_path, self.manifest)
        self.receipts = {
            "synthetic-committed": self.receipt("committed", sha(self.vector["sig_bytes"])),
            "synthetic-failed": self.receipt("failed", None)}
        self.receipt_calls = []
        self.execution_order = []
        self.worker_failure = None
        self.reconciled = True
        self.instances = []

    def case(self, operation, variant, **extra):
        case = dict(library=self.label, pid=201, backend="REF", threads=1,
                    operation=operation, variant=variant, **extra)
        case["case_id"] = pc.opt.case_id(case)
        return case

    def receipt(self, status, signature):
        return dict(algorithm=pc.opt.ALGORITHMS[201].lower(), public_key=self.vector["pk_bytes"],
            message_sha256=sha(self.vector["mp_bytes"]), signature_sha256=signature,
            status=status, ledger_uuid="0" * 32, key_id="1" * 64)

    def row(self, case, *, checks=None, result=None, predicted=True, receipt=None, status="passed"):
        fingerprint = pc.opt.vector_fingerprint(self.vector)
        result = result if result is not None else {"synthetic": True}
        row = dict(schema=pc.opt.SCHEMA, case_id=case["case_id"], case=copy.deepcopy(case), status=status,
            passed=status == "passed", checks=checks if checks is not None else {"synthetic_check": True},
            prediction={"counts": self.counts.copy()} if predicted else None,
            observed=self.counts.copy(), field_matches={field: True for field in COUNTER_FIELDS} if predicted else {},
            input=fingerprint, input_sha256=sha(pc.opt.canonical({"case": case, "input": fingerprint})),
            result=result, result_sha256=sha(pc.opt.canonical(result)), source_hashes=self.sources.copy(),
            library=self.libraries[self.label].copy(), formal_performance=False,
            recorded_utc="2026-10-04T00:00:00+00:00")
        if receipt:
            row.update(budget_receipt=receipt, budget_status=self.receipts[receipt]["status"])
        return hashed(row)

    def rows_for_case(self, case):
        operation = case["operation"]
        if operation == "subtree":
            result = dict(root_hex="aa" * 16, auth_hex="bb" * 16, adrs_hex="00" * 32)
            ref = {**case, "backend": "REF", "threads": 1, "operation": "subtree_reference"}
            ref["case_id"] = pc.opt.case_id(ref)
            return [self.row(ref, result=result), self.row(case, result=result,
                checks={"root_equals_scalar_REF": True, "auth_equals_scalar_REF": True})]
        if operation == "sign":
            result = dict(signature_sha256=sha(self.vector["sig_bytes"]), actual_chain_sums=[0])
            verify = {**case, "operation": "verify_generated"}
            verify["case_id"] = pc.opt.case_id(verify)
            return [self.row(case, result=result, receipt="synthetic-committed",
                checks={"signature_equals_existing_complete_vector": True}),
                self.row(verify, result={"signature_sha256": result["signature_sha256"]},
                         checks={"new_signature_valid": True})]
        if operation == "sign_fault":
            return [self.row(case, result={"error_code": -5}, predicted=False, receipt="synthetic-failed",
                checks={"self_check_error_returned": True, "failed_attempt_budget_consumed": True})]
        return [self.row(case, checks={"counters_enabled": True})]

    def all_rows(self):
        return [row for case in self.plan for row in self.rows_for_case(case)]

    def input_run(self, name, rows, manifest=None):
        directory = self.root / name
        directory.mkdir()
        write_json(directory / "manifest.json", self.manifest if manifest is None else manifest)
        write_rows(directory / "cases.jsonl", rows)
        self.write_summary(directory, rows)
        return directory

    def write_summary(self, directory, rows):
        summary_runner = SimpleNamespace(args=SimpleNamespace(**self.config),
            sources=self.sources, libraries=self.libraries, plan=self.plan, records=rows,
            latest={row["case_id"]: row for row in rows}, ledger=self.ledger_class()(self.budget),
            output=directory / "cases.jsonl", summary_path=directory / "summary.json",
            deferred_scope=lambda: [])
        BASE_RUNNER.checkpoint(summary_runner, final=True)

    def input_pair(self):
        return [self.input_run("shard-a", self.rows_for_case(self.plan[0]) + self.rows_for_case(self.plan[1])),
                self.input_run("shard-b", self.rows_for_case(self.plan[2]) + self.rows_for_case(self.plan[3]))]

    def add_cache_proof(self, directory):
        cache = directory / "cache" / "public.cache"
        cache.parent.mkdir()
        cache.write_bytes(b"SYNTHETIC PUBLIC CACHE BYTE PROVENANCE")
        records = directory / "cache-source-records.jsonl"
        records.write_bytes((directory / "cases.jsonl").read_bytes())
        proof = dict(schema=pc.PROVENANCE_SCHEMA, kind="worker", requested_scope_complete=True,
            error=None, cases_jsonl_sha256=file_sha(directory / "cases.jsonl"),
            worker_summary_sha256=file_sha(directory / "summary.json"), helper_sha256=file_sha(PROJECT / "ops/parallel_correctness.py"),
            copied_caches=[dict(destination_path=str(cache), source_path=str(self.root / "preserved-serial-cache"),
                sha256=file_sha(cache), source_records_snapshot_path=str(records),
                source_records_snapshot_sha256=file_sha(records))])
        write_json(directory / "worker-provenance.json", proof)
        return cache, records

    def selection(self, values):
        path = self.root / "selected.json"
        write_json(path, values)
        return path

    def ledger_class(self):
        fixture = self
        class Ledger:
            def __init__(self, database):
                self.path = Path(database).resolve()
                if self.path != fixture.budget.resolve():
                    raise ValueError("synthetic ledger identity differs")
                self.ledger_uuid = "0" * 32
            def status(self):
                return [dict(key_id="1" * 64, algorithm=pc.opt.ALGORITHMS[201], limit=100, used=2,
                    remaining=98, states={"committed": 1, "failed": 1}, count_reconciled=fixture.reconciled)]
            def validate_receipt(self, receipt, *, algorithm=None, public_key=None, message=None,
                                 message_sha256=None, signature=None, signature_sha256=None,
                                 statuses=("committed",)):
                fixture.receipt_calls.append(dict(receipt=receipt, algorithm=algorithm, statuses=list(statuses)))
                if receipt not in fixture.receipts:
                    raise ValueError("synthetic receipt missing")
                row = fixture.receipts[receipt]
                if row["status"] not in statuses:
                    raise ValueError("synthetic receipt status differs")
                if algorithm is not None and algorithm.lower() != row["algorithm"]:
                    raise ValueError("synthetic receipt algorithm differs")
                if public_key is not None and bytes(public_key) != row["public_key"]:
                    raise ValueError("synthetic receipt public key differs")
                expected_message = sha(bytes(message)) if message is not None else message_sha256
                expected_signature = sha(bytes(signature)) if signature is not None else signature_sha256
                if expected_message is not None and expected_message != row["message_sha256"]:
                    raise ValueError("synthetic receipt message differs")
                if expected_signature is not None and expected_signature != row["signature_sha256"]:
                    raise ValueError("synthetic receipt signature differs")
                return dict(ledger_uuid=self.ledger_uuid, receipt=receipt, key_id=row["key_id"],
                    algorithm=row["algorithm"], public_key_sha256=sha(row["public_key"]),
                    message_sha256=row["message_sha256"], signature_sha256=row["signature_sha256"], status=row["status"])
        return Ledger

    def runner_class(self, ledger_type):
        fixture = self
        class Runner:
            checkpoint = BASE_RUNNER.checkpoint
            deferred_scope = BASE_RUNNER.deferred_scope
            def __init__(self, args):
                self.args = args
                self.run_dir = Path(args.run_dir).resolve()
                self.run_dir.mkdir(parents=True, exist_ok=True)
                self.output = self.run_dir / "cases.jsonl"
                self.summary_path = self.run_dir / "summary.json"
                self.sources = copy.deepcopy(fixture.sources)
                self.libraries = copy.deepcopy(fixture.libraries)
                self.vectors = fixture.vectors
                self.ps = pc.opt.parameters()
                self.plan = copy.deepcopy(fixture.plan)
                self.records, self.latest = [], {}
                self.ledger = ledger_type(args.budget_db)
                config = {name: value for name, value in vars(args).items() if name != "resume"}
                config = json.loads(json.dumps(config, default=str))
                self.identity = dict(schema=pc.opt.SCHEMA, sources_sha256=self.sources,
                    libraries=self.libraries, vector_sha256=file_sha(fixture.vector_path),
                    configuration=config, budget_database_path=str(self.ledger.path))
                if getattr(args, "resume", False) and self.output.exists():
                    for row in read_rows(self.output):
                        self.records.append(row)
                        self.latest[row["case_id"]] = row
                if not (self.run_dir / "manifest.json").exists():
                    write_json(self.run_dir / "manifest.json", dict(identity=self.identity, plan=self.plan))
                self.stream = self.output.open("a", encoding="utf-8")
                fixture.instances.append(self)
            def run_case(self, case):
                fixture.execution_order.append(case["case_id"])
                for row in fixture.rows_for_case(case):
                    if case["case_id"] == fixture.worker_failure:
                        row = copy.deepcopy(row)
                        row.update(status="failed", passed=False, checks={"synthetic_check": False})
                        row = hashed(row)
                    self.stream.write(json.dumps(row, sort_keys=True) + "\n")
                    self.stream.flush()
                    self.records.append(row)
                    self.latest[row["case_id"]] = row
                return row
            def close(self):
                self.stream.close()
        return Runner


class ParallelChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="a15-par-test-")
        self.addCleanup(self.temp.cleanup)
        self.fixture = SyntheticFixture(Path(self.temp.name))
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        blocked = AssertionError("parallel helper tests prohibit native code, subprocesses and timing")
        self.stack.enter_context(patch("ctypes.CDLL", side_effect=blocked))
        self.stack.enter_context(patch.object(pc.opt, "NativeSlhDsa", side_effect=blocked))
        self.stack.enter_context(patch.object(subprocess, "Popen", side_effect=blocked))
        self.stack.enter_context(patch.object(time, "perf_counter", side_effect=blocked))
        self.stack.enter_context(patch.object(time, "perf_counter_ns", side_effect=blocked))
        ledger = self.fixture.ledger_class()
        self.stack.enter_context(patch.object(pc.opt, "SigningBudget", ledger))
        if hasattr(pc, "SigningBudget"):
            self.stack.enter_context(patch.object(pc, "SigningBudget", ledger))
        self.stack.enter_context(patch.object(pc.opt, "Runner", self.fixture.runner_class(ledger)))
        self.stack.enter_context(patch.object(pc, "settle_budget", self.synthetic_settlement))
        self.stack.enter_context(patch.object(pc.opt, "build_plan", lambda args, libraries: copy.deepcopy(self.fixture.plan)))
        self.stack.enter_context(patch.object(pc.opt, "load_vectors", lambda path: self.fixture.vectors))
        self.stack.enter_context(patch.object(pc.opt, "source_hashes",
            lambda: {"synthetic-source.py": file_sha(self.fixture.source)}))
        for name in ("subtree_model", "verify_model", "keygen_model", "cache_model", "sign_model"):
            self.stack.enter_context(patch.object(pc.opt, name,
                lambda *args, **kwargs: {"counts": self.fixture.counts.copy()}))
        self.stack.enter_context(patch.object(pc.opt, "ROOT", self.fixture.root))
        if hasattr(pc, "ROOT"):
            self.stack.enter_context(patch.object(pc, "ROOT", self.fixture.root))

    def synthetic_settlement(self, database, destination, ledger_uuid, statuses):
        destination = Path(destination)
        with destination.open("xb") as stream:
            stream.write(b"SYNTHETIC SETTLED LEDGER OUTPUT; NO NATIVE")
        return dict(schema="a15-cpu-correctness-budget-settlement-v1", ledger_uuid=ledger_uuid,
            live_database_path=str(Path(database).resolve()), snapshot_database_path=str(destination.resolve()),
            snapshot_sha256=file_sha(destination), all_fees_preserved=True, ordinals_reconciled=True,
            reserved_attempts=0, charged_attempts=2, keys=statuses,
            receipts=[dict(receipt=name, status=entry["status"], key_id=entry["key_id"],
                message_sha256=entry["message_sha256"], signature_sha256=entry["signature_sha256"])
                for name, entry in self.fixture.receipts.items()],
            native_calls=0, real_timing_samples=0)

    def merge(self, inputs):
        with redirect_stdout(io.StringIO()):
            return pc.merge(self.fixture.manifest_path, inputs, self.fixture.canonical_run, self.fixture.budget)

    def worker(self, ids):
        selection = self.fixture.selection(ids)
        destination = self.fixture.root / "worker-output"
        with redirect_stdout(io.StringIO()):
            result = pc.worker(self.fixture.manifest_path, selection, destination, self.fixture.budget)
        return destination, result

    def test_worker_non_probe_selection_preserves_requested_order(self):
        ids = [self.fixture.plan[2]["case_id"], self.fixture.plan[1]["case_id"]]
        self.worker(ids)
        self.assertEqual(self.fixture.execution_order, [self.fixture.plan[0]["case_id"], *ids])

    def rejection(self, inputs, message=None):
        with self.assertRaises(Exception) as failure:
            self.merge(inputs)
        if message is not None:
            self.assertIn(message, str(failure.exception))
        self.assertFalse(self.fixture.canonical_run.exists(), "Failed merge retained its new aggregate output")

    def mutate_row(self, run, index, change, recompute=True):
        rows = read_rows(run / "cases.jsonl")
        change(rows[index])
        if recompute:
            rows[index] = hashed(rows[index])
        write_rows(run / "cases.jsonl", rows)
        self.fixture.write_summary(run, rows)

    def test_worker_whitelist_and_plan_execution_order(self):
        selected = [self.fixture.plan[1]["case_id"], self.fixture.plan[0]["case_id"]]
        directory, _ = self.worker(selected)
        self.assertEqual(self.fixture.execution_order, [self.fixture.plan[0]["case_id"], self.fixture.plan[1]["case_id"]])
        summary = json.loads((directory / "summary.json").read_text())
        self.assertEqual(summary["planned_cases"], len(self.fixture.plan))
        self.assertEqual(summary["passed_planned"], 2)
        self.assertFalse(summary["passed"])
        self.assertFalse(summary["completed_requested_scope"])
        self.assertEqual(set(summary["pending_case_ids"]), {x["case_id"] for x in self.fixture.plan[2:]})
        self.assertFalse(summary["formal_performance_started"])
        self.assertFalse(summary["measured_durations"])

    def test_worker_unknown_id_rejected_without_execution(self):
        with self.assertRaises(Exception):
            self.worker(["missing-case-id"])
        self.assertEqual(self.fixture.execution_order, [])

    def test_worker_duplicate_ids_rejected_without_execution(self):
        with self.assertRaises(Exception):
            self.worker([self.fixture.plan[0]["case_id"]] * 2)
        self.assertEqual(self.fixture.execution_order, [])

    def test_worker_non_array_selection_rejected(self):
        with self.assertRaises(Exception):
            self.worker({"case_ids": [self.fixture.plan[0]["case_id"]]})
        self.assertEqual(self.fixture.execution_order, [])

    def test_worker_non_string_case_id_rejected(self):
        with self.assertRaises(Exception):
            self.worker([True])
        self.assertEqual(self.fixture.execution_order, [])

    def test_worker_empty_selection_rejected(self):
        with self.assertRaises(Exception):
            self.worker([])
        self.assertEqual(self.fixture.execution_order, [])

    def test_worker_occupied_output_rejected(self):
        directory = self.fixture.root / "worker-output"
        directory.mkdir()
        sentinel = directory / "preserve.txt"
        sentinel.write_bytes(b"PRESERVE PRIOR OUTPUT")
        with self.assertRaises(Exception):
            self.worker([self.fixture.plan[0]["case_id"]])
        self.assertEqual(sentinel.read_bytes(), b"PRESERVE PRIOR OUTPUT")
        self.assertEqual(self.fixture.execution_order, [])

    def test_worker_failed_case_never_reports_final_acceptance(self):
        self.fixture.worker_failure = self.fixture.plan[0]["case_id"]
        try:
            directory, _ = self.worker([x["case_id"] for x in self.fixture.plan])
        except Exception:
            directory = self.fixture.root / "worker-output"
        summary = json.loads((directory / "summary.json").read_text())
        self.assertFalse(summary["passed"])
        self.assertIn(self.fixture.worker_failure, summary["failed_case_ids"])

    def test_merge_valid_shards_preserves_input_and_original_manifest(self):
        inputs = self.fixture.input_pair()
        before = {(str(d), name): (d / name).read_bytes() for d in inputs for name in ("manifest.json", "cases.jsonl")}
        original = self.fixture.manifest_path.read_bytes()
        self.merge(inputs)
        output = self.fixture.canonical_run
        manifest = json.loads((output / "manifest.json").read_text())
        self.assertEqual(manifest["identity"], self.fixture.identity)
        self.assertEqual(manifest["plan"], self.fixture.plan)
        self.assertEqual(self.fixture.manifest_path.read_bytes(), original)
        for (directory, name), content in before.items():
            self.assertEqual((Path(directory) / name).read_bytes(), content)
        self.assertTrue((output / "provenance.json").is_file())
        preserved = [p.read_bytes() for p in (output / "provenance").rglob("*") if p.is_file()]
        for content in before.values():
            self.assertIn(content, preserved)
        summary = json.loads((output / "summary.json").read_text())
        self.assertTrue(summary["passed"])
        self.assertTrue(summary["completed_requested_scope"])
        self.assertTrue(summary["final"])
        self.assertEqual(summary["planned_cases"], len(self.fixture.plan))
        self.assertEqual(summary["passed_planned"], len(self.fixture.plan))
        self.assertEqual(summary["cases_jsonl_sha256"], file_sha(output / "cases.jsonl"))
        self.assertEqual(summary["records"], len(read_rows(output / "cases.jsonl")))
        self.assertFalse(summary["formal_performance_started"])
        self.assertFalse(summary["measured_durations"])
        self.assertFalse(summary["global_atomic_measurements_serialized"])
        self.assertTrue(summary["counter_measurements_serialized_per_process"])
        self.assertEqual(summary["budget_database"], str(output / "settled-budget.sqlite"))
        self.assertEqual(summary["budget_snapshot_sha256"], file_sha(output / "settled-budget.sqlite"))
        settlement = json.loads((output / "settlement.json").read_text())
        self.assertEqual(settlement["record_receipts_verified"], 2)
        self.assertTrue(settlement["all_fees_preserved"])
        self.assertEqual({x["receipt"] for x in self.fixture.receipt_calls}, set(self.fixture.receipts))

    def test_merge_preserves_copied_cache_and_record_snapshot_bytes(self):
        inputs = self.fixture.input_pair()
        cache, records = self.fixture.add_cache_proof(inputs[0])
        cache_bytes, record_bytes = cache.read_bytes(), records.read_bytes()
        self.merge(inputs)
        output = self.fixture.canonical_run
        self.assertEqual((output / "provenance/cache-input-0.bin").read_bytes(), cache_bytes)
        self.assertEqual((output / "provenance/input-0/cache-source-records.jsonl").read_bytes(), record_bytes)
        manifest = json.loads((output / "manifest.json").read_text())
        copied = manifest["parallel_provenance"]["copied_cache_inputs"]
        self.assertEqual(copied[0]["sha256"], sha(cache_bytes))
        self.assertEqual(copied[0]["preserved_path"], "provenance/cache-input-0.bin")
        self.assertEqual(cache.read_bytes(), cache_bytes)
        self.assertEqual(records.read_bytes(), record_bytes)

    def test_merge_copied_cache_changed_after_proof_rejected(self):
        inputs = self.fixture.input_pair()
        cache, _ = self.fixture.add_cache_proof(inputs[0])
        cache.write_bytes(b"CHANGED SYNTHETIC CACHE")
        self.rejection(inputs, "Worker copied cache bytes changed")

    def test_merge_cache_record_snapshot_changed_rejected(self):
        inputs = self.fixture.input_pair()
        _, records = self.fixture.add_cache_proof(inputs[0])
        records.write_bytes(b"CHANGED CACHE RECORD SNAPSHOT")
        self.rejection(inputs, "Worker cache record snapshot differs")

    def test_merge_settlement_failure_cleans_new_aggregate(self):
        inputs = self.fixture.input_pair()
        with patch.object(pc, "settle_budget", side_effect=ValueError("synthetic settlement failure")):
            self.rejection(inputs, "synthetic settlement failure")

    def test_merge_charged_receipt_reused_across_distinct_sign_cases_rejected(self):
        extra = self.fixture.case("sign", "another-synthetic-sign", cache_t=None)
        self.fixture.plan.append(extra)
        self.fixture.manifest["plan"] = self.fixture.plan
        write_json(self.fixture.manifest_path, self.fixture.manifest)
        inputs = [self.fixture.input_run("all-with-reused-receipt", self.fixture.all_rows())]
        self.rejection(inputs, "One charged receipt was reused across distinct signing cases")

    def test_merge_occupied_output_rejected_and_original_bytes_preserved(self):
        inputs = self.fixture.input_pair()
        self.fixture.canonical_run.mkdir()
        sentinel = self.fixture.canonical_run / "manifest.json"
        sentinel.write_bytes(b"PRESERVED EARLIER MANIFEST")
        with self.assertRaises(Exception):
            self.merge(inputs)
        self.assertEqual(sentinel.read_bytes(), b"PRESERVED EARLIER MANIFEST")

    def test_merge_input_manifest_identity_mismatch_rejected(self):
        inputs = self.fixture.input_pair()
        manifest = copy.deepcopy(self.fixture.manifest)
        manifest["identity"]["vector_sha256"] = "f" * 64
        write_json(inputs[0] / "manifest.json", manifest)
        self.rejection(inputs)

    def test_merge_original_manifest_plan_change_rejected(self):
        inputs = self.fixture.input_pair()
        manifest = copy.deepcopy(self.fixture.manifest)
        manifest["plan"] = manifest["plan"][:-1]
        write_json(self.fixture.manifest_path, manifest)
        self.rejection(inputs)

    def test_merge_input_manifest_plan_change_rejected(self):
        inputs = self.fixture.input_pair()
        manifest = copy.deepcopy(self.fixture.manifest)
        manifest["plan"] = manifest["plan"][:-1]
        write_json(inputs[0] / "manifest.json", manifest)
        self.rejection(inputs)

    def test_merge_original_source_identity_stale_rejected(self):
        inputs = self.fixture.input_pair()
        self.fixture.source.write_bytes(b"CHANGED SYNTHETIC SOURCE")
        self.rejection(inputs)

    def test_merge_library_bytes_changed_rejected(self):
        inputs = self.fixture.input_pair()
        self.fixture.library.write_bytes(b"CHANGED SYNTHETIC NONEXECUTABLE LIBRARY")
        self.rejection(inputs)

    def test_merge_vector_file_changed_rejected(self):
        inputs = self.fixture.input_pair()
        self.fixture.vector_path.write_bytes(b"CHANGED SYNTHETIC VECTORS")
        self.rejection(inputs)

    def test_merge_record_checksum_mismatch_rejected(self):
        inputs = self.fixture.input_pair()
        self.mutate_row(inputs[0], 0, lambda row: row.update(recorded_utc="changed"), recompute=False)
        self.rejection(inputs, "Case record checksum differs")

    def test_merge_input_hash_mismatch_rejected(self):
        inputs = self.fixture.input_pair()
        self.mutate_row(inputs[0], 0, lambda row: row.update(input_sha256="f" * 64))
        self.rejection(inputs, "Record vector fingerprint differs")

    def test_merge_result_hash_mismatch_rejected(self):
        inputs = self.fixture.input_pair()
        self.mutate_row(inputs[0], 0, lambda row: row.update(result_sha256="f" * 64))
        self.rejection(inputs, "Record result digest differs")

    def test_merge_input_fingerprint_not_matching_vector_rejected(self):
        inputs = self.fixture.input_pair()
        def mutate(row):
            row["input"]["encoded_message_sha256"] = "f" * 64
            row["input_sha256"] = sha(pc.opt.canonical({"case": row["case"], "input": row["input"]}))
        self.mutate_row(inputs[0], 0, mutate)
        self.rejection(inputs, "Record vector fingerprint differs")

    def test_merge_unknown_auxiliary_shape_rejected(self):
        inputs = self.fixture.input_pair()
        rows = read_rows(inputs[0] / "cases.jsonl")
        case = self.fixture.case("unknown_auxiliary", "synthetic-extra")
        rows.append(self.fixture.row(case))
        write_rows(inputs[0] / "cases.jsonl", rows)
        self.fixture.write_summary(inputs[0], rows)
        self.rejection(inputs, "Record case differs")

    def test_merge_case_payload_mismatch_rejected(self):
        inputs = self.fixture.input_pair()
        def mutate(row):
            row["case"]["threads"] = 2
            row["input_sha256"] = sha(pc.opt.canonical({"case": row["case"], "input": row["input"]}))
        self.mutate_row(inputs[0], 0, mutate)
        self.rejection(inputs, "Record case differs")

    def test_merge_seven_field_count_mismatch_rejected(self):
        inputs = self.fixture.input_pair()
        def mutate(row):
            row["observed"][COUNTER_FIELDS[0]] += 1
        self.mutate_row(inputs[0], 0, mutate)
        self.rejection(inputs, "Seven-field direct counts differ")

    def test_merge_missing_counter_field_rejected(self):
        inputs = self.fixture.input_pair()
        def mutate(row):
            for field in ("observed", "field_matches"):
                row[field].pop(COUNTER_FIELDS[0])
            row["prediction"]["counts"].pop(COUNTER_FIELDS[0])
        self.mutate_row(inputs[0], 0, mutate)
        self.rejection(inputs, "Independent count prediction differs")

    def test_merge_false_check_with_passed_status_rejected(self):
        inputs = self.fixture.input_pair()
        self.mutate_row(inputs[0], 0, lambda row: row.update(checks={"synthetic_check": False}))
        self.rejection(inputs, "Required correctness checks")

    def test_merge_missing_required_check_name_rejected(self):
        inputs = self.fixture.input_pair()
        self.mutate_row(inputs[0], 0, lambda row: row.update(checks={"unrelated_true_check": True}))
        self.rejection(inputs, "Required correctness checks")

    def test_merge_row_source_identity_mismatch_rejected(self):
        inputs = self.fixture.input_pair()
        self.mutate_row(inputs[0], 0, lambda row: row.update(source_hashes={"synthetic-source.py": "f" * 64}))
        self.rejection(inputs, "Record source/library/schema identity differs")

    def test_merge_row_library_identity_mismatch_rejected(self):
        inputs = self.fixture.input_pair()
        self.mutate_row(inputs[0], 0, lambda row: row.update(library={"path": str(self.fixture.library), "sha256": "f" * 64}))
        self.rejection(inputs, "Record source/library/schema identity differs")

    def test_merge_subtree_reference_result_conflict_rejected(self):
        inputs = self.fixture.input_pair()
        def mutate(row):
            row["result"]["root_hex"] = "cc" * 16
            row["result_sha256"] = sha(pc.opt.canonical(row["result"]))
        self.mutate_row(inputs[0], 1, mutate)
        self.rejection(inputs, "Direct subtree differs from preserved scalar reference")

    def test_merge_missing_planned_case_rejected(self):
        inputs = self.fixture.input_pair()
        rows = read_rows(inputs[0] / "cases.jsonl")
        write_rows(inputs[0] / "cases.jsonl", rows[1:])
        self.fixture.write_summary(inputs[0], rows[1:])
        self.rejection(inputs, "Aggregate planned case missing")

    def test_merge_missing_generated_verification_rejected(self):
        inputs = self.fixture.input_pair()
        rows = [row for row in read_rows(inputs[1] / "cases.jsonl") if row["case"]["operation"] != "verify_generated"]
        write_rows(inputs[1] / "cases.jsonl", rows)
        self.fixture.write_summary(inputs[1], rows)
        self.rejection(inputs, "Aggregate direct auxiliary evidence missing")

    def test_merge_missing_scalar_subtree_reference_rejected(self):
        inputs = self.fixture.input_pair()
        rows = [row for row in read_rows(inputs[0] / "cases.jsonl") if row["case"]["operation"] != "subtree_reference"]
        write_rows(inputs[0] / "cases.jsonl", rows)
        self.fixture.write_summary(inputs[0], rows)
        self.rejection(inputs, "Aggregate direct auxiliary evidence missing")

    def test_merge_missing_receipt_rejected(self):
        inputs = self.fixture.input_pair()
        self.fixture.receipts.pop("synthetic-committed")
        self.rejection(inputs, "synthetic receipt missing")

    def test_merge_sign_row_without_receipt_rejected(self):
        inputs = self.fixture.input_pair()
        def mutate(row):
            row.pop("budget_receipt")
            row.pop("budget_status")
        self.mutate_row(inputs[1], 0, mutate)
        self.rejection(inputs, "Signing receipt or status missing")

    def test_merge_receipt_wrong_public_key_rejected(self):
        inputs = self.fixture.input_pair()
        self.fixture.receipts["synthetic-committed"]["public_key"] = b"OTHER SYNTHETIC PUBLIC KEY"
        self.rejection(inputs, "synthetic receipt public key differs")

    def test_merge_receipt_wrong_message_rejected(self):
        inputs = self.fixture.input_pair()
        self.fixture.receipts["synthetic-committed"]["message_sha256"] = "f" * 64
        self.rejection(inputs, "synthetic receipt message differs")

    def test_merge_receipt_wrong_signature_rejected(self):
        inputs = self.fixture.input_pair()
        self.fixture.receipts["synthetic-committed"]["signature_sha256"] = "f" * 64
        self.rejection(inputs, "synthetic receipt signature differs")

    def test_merge_receipt_wrong_status_rejected(self):
        inputs = self.fixture.input_pair()
        self.fixture.receipts["synthetic-failed"]["status"] = "committed"
        self.rejection(inputs, "synthetic receipt status differs")

    def test_merge_budget_count_unreconciled_rejected(self):
        inputs = self.fixture.input_pair()
        self.fixture.reconciled = False
        self.rejection(inputs, "Live budget reconciliation failed")

    def test_merge_formal_performance_row_rejected(self):
        inputs = self.fixture.input_pair()
        self.mutate_row(inputs[0], 0, lambda row: row.update(formal_performance=True))
        self.rejection(inputs, "Record source/library/schema identity differs")

    def test_merge_row_schema_mismatch_rejected(self):
        inputs = self.fixture.input_pair()
        self.mutate_row(inputs[0], 0, lambda row: row.update(schema="other-schema"))
        self.rejection(inputs, "Record source/library/schema identity differs")

    def test_merge_empty_input_list_rejected(self):
        self.rejection([])

    def test_merge_duplicate_input_directories_rejected(self):
        inputs = self.fixture.input_pair()
        self.rejection([inputs[0], inputs[0]], "Input runs empty or duplicated")

    def test_merge_missing_input_manifest_rejected(self):
        inputs = self.fixture.input_pair()
        (inputs[0] / "manifest.json").unlink()
        self.rejection(inputs)

    def test_merge_missing_input_cases_rejected(self):
        inputs = self.fixture.input_pair()
        (inputs[0] / "cases.jsonl").unlink()
        self.rejection(inputs)

    def real_ledger(self, unfinished=False):
        database = self.fixture.root / "real-budget.sqlite"
        ledger = REAL_BUDGET(database)
        first = ledger.reserve(pc.opt.ALGORITHMS[201], b"SYNTHETIC-PUBLIC-NOT-A-REAL-KEY", b"SYNTHETIC-MESSAGE")
        if not unfinished:
            ledger.finish(first, b"SYNTHETIC-SIGNATURE")
            second = ledger.reserve(pc.opt.ALGORITHMS[201], b"SYNTHETIC-PUBLIC-NOT-A-REAL-KEY", b"SYNTHETIC-FAILED-MESSAGE")
            ledger.finish(second)
        return database, ledger

    def test_real_sqlite_settlement_preserves_all_charges_and_immutable_uuid(self):
        database, ledger = self.real_ledger()
        statuses = ledger.status()
        destination = self.fixture.root / "real-settled.sqlite"
        with patch.object(pc, "SigningBudget", REAL_BUDGET):
            result = REAL_SETTLE(database, destination, ledger.ledger_uuid, statuses)
        self.assertEqual(result["charged_attempts"], 2)
        self.assertEqual({row["status"] for row in result["receipts"]}, {"committed", "failed"})
        self.assertEqual(result["keys"], statuses)
        self.assertEqual(result["ledger_uuid"], ledger.ledger_uuid)
        self.assertEqual(result["snapshot_sha256"], file_sha(destination))
        self.assertEqual(ledger.status(), statuses)
        self.assertEqual(result["native_calls"], 0)
        self.assertEqual(result["real_timing_samples"], 0)
        for suffix in ("-wal", "-shm", "-journal"):
            self.assertFalse(Path(str(destination) + suffix).exists())
        with closing(sqlite3.connect(destination.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchall(), [("ok",)])

    def test_real_sqlite_settlement_rejects_unfinished_reserved_attempt(self):
        database, ledger = self.real_ledger(unfinished=True)
        destination = self.fixture.root / "unfinished-settled.sqlite"
        with patch.object(pc, "SigningBudget", REAL_BUDGET):
            with self.assertRaisesRegex(ValueError, "reserved attempts"):
                REAL_SETTLE(database, destination, ledger.ledger_uuid, ledger.status())
        self.assertFalse(destination.exists())

    def test_real_sqlite_settlement_rejects_wrong_uuid(self):
        database, ledger = self.real_ledger()
        with patch.object(pc, "SigningBudget", REAL_BUDGET):
            with self.assertRaisesRegex(ValueError, "UUID/schema differs"):
                REAL_SETTLE(database, self.fixture.root / "wrong-uuid.sqlite", "f" * 32, ledger.status())

    def test_real_sqlite_settlement_rejects_nonconsecutive_charge_ordinal(self):
        database, ledger = self.real_ledger()
        statuses = ledger.status()
        with closing(sqlite3.connect(database)) as db:
            # The managed ledger now rejects direct writes. Remove and restore
            # the guards only to model corruption in an external DB editor;
            # the settlement must still reject the corrupted full history.
            triggers = db.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name='reservations'").fetchall()
            for name, _ in triggers:
                db.execute(f"DROP TRIGGER {name}")
            db.execute("UPDATE reservations SET ordinal_text='4' WHERE ordinal_text='1'")
            for _, definition in triggers:
                db.execute(definition)
            db.commit()
        with patch.object(pc, "SigningBudget", REAL_BUDGET):
            with self.assertRaisesRegex((ValueError, RuntimeError), "ordinal reconciliation failed"):
                REAL_SETTLE(database, self.fixture.root / "wrong-ordinal.sqlite", ledger.ledger_uuid, statuses)


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    log = io.StringIO()
    result = unittest.TextTestRunner(stream=log, verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ParallelChecks))
    record = dict(schema="a15-parallel-correctness-selftest-v1", passed=result.wasSuccessful(),
        mock_checks=result.testsRun, failures=len(result.failures), errors=len(result.errors),
        native_calls=0, real_timing_samples=0, formal_performance_started=False,
        actual_matrix_acceptance=False, tool_sha256=file_sha(PROJECT / "ops/parallel_correctness.py"),
        test_tool_sha256=file_sha(__file__),
        scope="Temporary synthetic source/library/vector files, strict stub Runner/ledger, row hashes and original-byte provenance; no native or performance calls")
    (OUTPUT / "selftest.log").write_text(log.getvalue(), encoding="utf-8")
    write_json(OUTPUT / "selftest.json", record)
    print(log.getvalue())
    print(json.dumps(record))
    return int(not result.wasSuccessful())


if __name__ == "__main__":
    raise SystemExit(main())
