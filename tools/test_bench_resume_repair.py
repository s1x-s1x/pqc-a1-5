"""B01/B02 regressions: real temporary SQLite, fake ABI and fixed clocks only.

No native library, GPU, cryptographic operation, subprocess or real timing is
permitted. Production CUDA sample minimums remain intact in these fake runs.
"""
from contextlib import ExitStack
import copy
import ctypes
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bench_cpu as cpu
import bench_cuda as cuda
from signing_budget import SigningBudget


class SyntheticCrash(BaseException):
    pass


class Harness:
    def __init__(self, folder, mode="cpu", *, warmups=1, samples=2, two_cases=False, fixture_signature=False, cache="none"):
        self.folder, self.mode = folder, mode
        folder.mkdir()
        self.inputs = {"pk": b"P"*32, "sk": b"S"*32+b"P"*32,
                       "message": b"fixed synthetic message", "context": b"audit",
                       "sk_seed": b"S"*16, "sk_prf": b"R"*16, "pk_seed": b"P"*16}
        self.result = b"Y"*cpu.SIG_BYTES[2]
        if mode == "cuda":
            plan = cuda.make_plan([2], [1])
            cases = [copy.deepcopy(plan["cases"][0])]
            if two_cases:
                cases.append({**cases[0], "threads": 2, "case_id": "CUDA-B1-p2-sign-cnone-p2"})
            plan["cases"] = cases
        else:
            cases = [cpu.case_record(2, "sign", backend=b, family="B01B02", samples=samples)
                     for b in (("REF", "AVX2") if two_cases else ("REF",))]
            plan = {"schema": "a15-cpu-plan-v1", "cases": cases, "diagnostic_sample_override": True}
        for case in cases:
            case["warmups"] = warmups
            if cache != "none":
                case.update(cache=str(cache), cache_t=int(cache))
        self.plan, self.case = plan, cases[0]
        self.args = SimpleNamespace(plan=folder/"plan.json", worker_case=self.case["case_id"],
            output=folder/"evidence.jsonl", fixtures=folder/"fixtures", library=folder/"fake-library.bin",
            budget_db=folder/"budget.sqlite", build_record=folder/"fake-build.json" if mode == "cuda" else None,
            freeze=folder/"freeze.json" if mode == "cuda" else None, cpus=None,
            timeout_seconds=1, case=None)
        self.args.plan.write_text(json.dumps(plan), encoding="utf8")
        self.args.fixtures.mkdir()
        self.fixture_path = self.args.fixtures/"p2-fixture.json"
        self.fixture_path.write_text(json.dumps({k: v.hex() for k, v in self.inputs.items()}), encoding="utf8")
        self.files = {str(self.fixture_path.resolve()): cpu.file_sha(self.fixture_path)}
        self.budget = SigningBudget(self.args.budget_db)
        if fixture_signature:
            self.inputs["sig"] = self.result
            token = self.budget.reserve(cpu.ALGORITHMS[2], self.inputs["pk"], self.encoded())
            self.budget.finish(token, self.result)
            path = self.args.fixtures/"p2-signature.json"
            path.write_text(json.dumps({"fixture_sha256": cpu.file_sha(self.fixture_path),
                "sig": self.result.hex(), "receipt": token, "ledger_uuid": self.budget.ledger_uuid}), encoding="utf8")
            self.files[str(path.resolve())] = cpu.file_sha(path)
            self.fixture_receipt = token
        self.calls, self.contexts, self.ticks = [], [], 0
        self.fail_calls, self.crash_match, self.crash_after_write = set(), None, True
        self.stats_enabled = False
        self.affinity = {"cpus": [0], "verified_physical": True}
        self.env = {"host": "synthetic", "cpu": "synthetic", "affinity": self.affinity,
                    "lscpu": {}, "turbo": {}, "governor": {}}
        self.gpu = {"identity": {"gpu": "GPU-FAKE", "power_policy": "fixed"}, "observations": {}}
        self.prov = {"final": mode == "cuda", "classification": "formal" if mode == "cuda" else "diagnostic",
            "source_sha256": {"fixture": "fixed"}, "library_sha256": "FAKE-NO-LIBRARY",
            "freeze_sha256": None, "build_record_sha256": None, "build_record": None,
            "git": {}, "timing_scope": "synthetic fixed clock, never measured"}
        if mode == "cuda":
            self.prov.update(formal_gate_passed=True, plan_sha256=cpu.file_sha(self.args.plan),
                             device_identity={"name": "GPU-FAKE"})
        self.write = cpu.append if mode == "cpu" else cuda.append
        self.module = cpu if mode == "cpu" else cuda
        self.worker = self.module.worker
        self.stack = ExitStack()

    def encoded(self):
        return b"\0"+bytes([len(self.inputs["context"])])+self.inputs["context"]+self.inputs["message"]

    def clock(self):
        self.ticks += 100
        return self.ticks

    def append(self, path, row):
        crash = self.crash_match is not None and self.crash_match(row)
        if crash and not self.crash_after_write:
            raise SyntheticCrash("synthetic process loss before durable result")
        self.write(path, row)
        if crash:
            raise SyntheticCrash("synthetic process loss after durable record")

    def operation(self):
        self.calls.append({"context_generation": len(self.contexts), "events": self.stats_enabled})
        return -2 if len(self.calls) in self.fail_calls else 0

    def __enter__(self):
        probe = self
        class FakeNative:
            def __init__(self, pid, threads, backend, library):
                self.backend, self.pk_bytes, self.sk_bytes, self.sig_bytes = backend, 32, 64, cpu.SIG_BYTES[pid]
                self.lib = object()
                probe.contexts.append({"pid": pid, "threads": threads, "backend": backend})
            def __enter__(self): return self
            def __exit__(self, *unused): pass
            def bind_key(self, key): pass
            def cache_build(self, *unused): pass
            def cache_load(self, *unused): pass
            def cache_save(self, path): Path(path).write_bytes(b"fixed fake cache; never loaded by native")
            def verify(self, *unused): return True
            def _check(self, op, code):
                if code: raise ValueError("fake ABI returned -2")
        class FakeStatistics:
            def __init__(self, lib): pass
            def reset(self, enabled=False): probe.stats_enabled = enabled
            def info(self): return {"name": "GPU-FAKE"}
            def get(self):
                return {"kernel_launches": 1, "h2d_bytes": 1, "d2h_bytes": 1,
                        "device_hashes": 1, "kernel_ns": 40, "timing_enabled": int(probe.stats_enabled)}
        replacements = [(cpu, "bind", self.affinity), (cpu, "environment", self.env),
            (cpu, "verify_library_runtime", {"fake": True}), (cpu, "sample_environment", {}),
            (cpu, "counters_enabled", False), (cpu, "theoretical", {"hash_calls": 0, "compressions": 0}),
            (cpu, "fixture", (self.inputs, self.files)),
            (cpu, "topology", ([{"cpu": 0, "core": 0, "socket": 0, "node": 0}], {"fake": True}))]
        for owner, name, value in replacements:
            self.stack.enter_context(patch.object(owner, name, return_value=value))
        self.stack.enter_context(patch.object(self.module, "provenance", return_value=self.prov))
        self.stack.enter_context(patch.object(self.module, "NativeSlhDsa", side_effect=FakeNative))
        self.stack.enter_context(patch.object(self.module, "append", side_effect=self.append))
        self.stack.enter_context(patch.object(self.module, "raw_operation", return_value=(self.operation, lambda: self.result)))
        self.stack.enter_context(patch.dict(os.environ, cpu.openmp_environment(1, [0])))
        if self.mode == "cpu":
            self.stack.enter_context(patch.object(cpu.time, "perf_counter_ns", side_effect=self.clock))
        else:
            self.stack.enter_context(patch.object(cuda, "gpu_environment", return_value=self.gpu))
            self.stack.enter_context(patch.object(cuda, "validate_freeze", return_value=self.prov))
            self.stack.enter_context(patch.object(cuda, "Statistics", side_effect=FakeStatistics))
            sample = cuda.sample_once
            self.stack.enter_context(patch.object(cuda, "sample_once", side_effect=lambda operation, stats, permit:
                sample(operation, stats, permit=permit, clock=self.clock)))
        return self

    def __exit__(self, *unused): self.stack.close()
    def rows(self): return cpu.rows(self.args.output)
    def used(self): return sum(row["used"] for row in self.budget.status())
    def rewrite(self, records):
        self.args.output.write_text("".join(cpu.canonical({k: v for k, v in row.items() if k != "_line"})+"\n"
                                           for row in records), encoding="utf8")
    def audit(self, records):
        return cpu.audit_campaign_evidence(records, self.plan, self.budget, self.args.fixtures,
            self.module.SCHEMA, self.prov, cpu.file_sha(self.args.plan),
            cuda.resume_samples if self.mode == "cuda" else None,
            cuda.validate_completed if self.mode == "cuda" else None)


class ResumeRepair(unittest.TestCase):
    mode = "cpu"
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="a15-bench-repair-")
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.guards = ExitStack()
        self.addCleanup(self.guards.close)
        self.guards.enter_context(patch.object(ctypes, "CDLL", side_effect=AssertionError("native loading forbidden")))
        self.guards.enter_context(patch.object(cpu.time, "perf_counter_ns", side_effect=AssertionError("real timing forbidden")))
        self.guards.enter_context(patch.object(cpu, "command", side_effect=AssertionError("external command forbidden")))
        self.guards.enter_context(patch.object(cpu.subprocess, "run", side_effect=AssertionError("subprocess forbidden")))

    def harness(self, **kwargs):
        return Harness(self.folder/"campaign", self.mode, **kwargs)

    def reject_without_native(self, p, records=None):
        if records is not None: p.rewrite(records)
        before = p.args.output.read_bytes(), p.used(), len(p.contexts), len(p.calls)
        with self.assertRaises(ValueError): p.worker(p.args)
        self.assertEqual((p.args.output.read_bytes(), p.used(), len(p.contexts), len(p.calls)), before)

    def test_partial_resume_rewarms_every_new_segment(self):
        with self.harness(warmups=2) as p:
            p.crash_match = lambda r: r["kind"] == "sample" and r.get("sample_index") == 0
            with self.assertRaises(SyntheticCrash): p.worker(p.args)
            first = p.rows(); calls = len(p.calls)
            p.crash_match = None; p.worker(p.args)
            records = p.rows(); p.audit(records)
            self.assertEqual(sum(r["kind"] == "warmup" for r in records), 4)
            self.assertEqual(len(p.calls)-calls, 2+p.case["samples"]-1)
            segments = {r["segment_id"] for r in records if r["kind"] == "case_start"}
            self.assertEqual(len(segments), 2)
            self.assertEqual(p.used(), p.case["samples"]+4)
            self.assertEqual([r for r in records if r["kind"] == "sample" and r["sample_index"] == 0],
                             [r for r in first if r["kind"] == "sample"])
            if self.mode == "cuda":
                self.assertEqual(sum(not c["events"] for c in p.calls), 4)
                self.assertEqual(sum(c["events"] for c in p.calls), p.case["samples"])

    def test_zero_warmup_resume_has_no_added_warmups(self):
        with self.harness(warmups=0) as p:
            p.crash_match = lambda r: r["kind"] == "sample" and r.get("sample_index") == 0
            with self.assertRaises(SyntheticCrash): p.worker(p.args)
            p.crash_match = None; p.worker(p.args); p.audit(p.rows())
            self.assertEqual(sum(r["kind"] == "warmup" for r in p.rows()), 0)
            self.assertEqual(p.used(), p.case["samples"])

    def test_failed_warmup_stays_charged_and_full_warmup_restarts(self):
        with self.harness(warmups=2) as p:
            p.fail_calls = {2}
            with self.assertRaises(ValueError): p.worker(p.args)
            first = p.rows(); p.audit(first)
            self.assertFalse(next(r for r in first if r["kind"] == "warmup" and r["index"] == 1)["passed"])
            p.worker(p.args); p.audit(p.rows())
            self.assertEqual(p.used(), p.case["samples"]+4)
            self.assertEqual(p.budget.status()[0]["states"]["failed"], 1)

    def test_failed_sample_stays_charged_and_missing_index_retries(self):
        with self.harness() as p:
            p.fail_calls = {3}
            with self.assertRaises(ValueError): p.worker(p.args)
            first = p.rows(); p.audit(first)
            self.assertEqual(sum(r["kind"] == "sample" and r.get("passed") for r in first), 1)
            p.worker(p.args); p.audit(p.rows())
            self.assertEqual(p.used(), p.case["samples"]+3)
            self.assertEqual(p.budget.status()[0]["states"]["failed"], 1)

    def test_crash_after_reservation_retains_reserved_charge(self):
        with self.harness() as p:
            p.crash_match = lambda r: r["kind"] == "operation_start" and r["operation_kind"] == "sample"
            with self.assertRaises(SyntheticCrash): p.worker(p.args)
            p.audit(p.rows()); self.assertEqual(p.used(), 2)
            p.crash_match = None; p.worker(p.args); p.audit(p.rows())
            self.assertEqual(p.used(), p.case["samples"]+3)
            self.assertEqual(p.budget.status()[0]["states"]["reserved"], 1)

    def test_crash_after_finish_before_result_retains_committed_charge(self):
        with self.harness() as p:
            p.crash_match = lambda r: r["kind"] == "sample" and r.get("sample_index") == 0
            p.crash_after_write = False
            with self.assertRaises(SyntheticCrash): p.worker(p.args)
            p.audit(p.rows()); self.assertEqual(p.used(), 2)
            self.assertEqual(sum(r["kind"] == "sample" for r in p.rows()), 0)
            p.crash_match = None; p.worker(p.args); p.audit(p.rows())
            self.assertEqual(p.used(), p.case["samples"]+3)
            self.assertEqual(p.budget.status()[0]["states"].get("reserved", 0), 0)

    def test_all_samples_present_only_summary_added_without_operations(self):
        with self.harness() as p:
            p.crash_match = lambda r: r["kind"] == "case_complete"
            p.crash_after_write = False
            with self.assertRaises(SyntheticCrash): p.worker(p.args)
            calls, used = len(p.calls), p.used()
            p.crash_match = None; p.worker(p.args); p.audit(p.rows())
            self.assertEqual((len(p.calls), p.used()), (calls, used))
            self.assertEqual(sum(r["kind"] == "warmup" for r in p.rows()), 1)

    def test_complete_skip_revalidates_without_operations(self):
        with self.harness() as p:
            p.worker(p.args); calls, used, ctx = len(p.calls), p.used(), len(p.contexts)
            p.worker(p.args)
            self.assertEqual((len(p.calls), p.used()), (calls, used))
            self.assertEqual(len(p.contexts)-ctx, 1 if self.mode == "cuda" else 0)

    def test_metadata_mutation_each_bound_kind_rejected_before_native(self):
        with self.harness() as p:
            p.worker(p.args); baseline = p.rows()
            mutations = {"case_id": "WRONG", "pid": 103, "op": "verify", "backend": "WRONG", "actual_backend": 999,
                "threads": 64, "cores": 64, "cache_t": 1, "requested_cache_t": "1", "keygen_mode": "rng",
                "family": "OTHER", "final": not p.prov["final"], "classification": "OTHER", "ledger_uuid": "0"*32,
                "case_key": "0"*64, "segment_id": "broken"}
            for kind in ("case_start", "inputs_ready", "operation_start", "warmup", "sample", "case_complete"):
                for field, value in mutations.items():
                    with self.subTest(kind=kind, field=field):
                        records = copy.deepcopy(baseline)
                        next(r for r in records if r["kind"] == kind)[field] = value
                        self.reject_without_native(p, records)
                for field, value in (("plan_sha256", "changed"), ("environment_identity", {"changed": True}),
                                     ("provenance", {**baseline[0]["execution_binding"]["provenance"], "library_sha256": "changed"})):
                    with self.subTest(kind=kind, binding=field):
                        records = copy.deepcopy(baseline)
                        next(r for r in records if r["kind"] == kind)["execution_binding"][field] = value
                        self.reject_without_native(p, records)

    def test_completion_and_sample_data_tampering_rejected(self):
        with self.harness() as p:
            p.worker(p.args); baseline = p.rows()
            mutations = [("sample", "duration_ns", 0), ("sample", "duration_ns", True),
                ("operation_start", "timed", True), ("warmup", "timed", True),
                ("operation_start", "budget_evidence", {}),
                ("sample", "sample_index", 999), ("sample", "input_hashes", {}),
                ("sample", "result_sha256", "0"*64), ("sample", "operation_id", "0"*32),
                ("case_complete", "median", 999), ("case_complete", "samples", []),
                ("case_complete", "sample_lines", []), ("case_complete", "input_hashes", {}),
                ("case_complete", "input_files_after", {}), ("case_complete", "source_sha256_before", {}),
                ("case_complete", "library_sha256_after", "changed"), ("case_complete", "build_record_sha256", "changed"),
                ("case_complete", "freeze_sha256", "changed"), ("case_complete", "environment_identity", {})]
            if self.mode == "cuda":
                mutations += [("sample", "kernel_ns", 101), ("sample", "end_to_end_ns", 200),
                    ("sample", "scopes", {}), ("case_complete", "kernel_samples", []),
                    ("case_complete", "kernel_summary", {}), ("case_complete", "scopes", {})]
            for kind, field, value in mutations:
                with self.subTest(kind=kind, field=field):
                    records = copy.deepcopy(baseline); next(r for r in records if r["kind"] == kind)[field] = value
                    self.reject_without_native(p, records)

    def test_partial_bad_sample_rejected_before_native(self):
        with self.harness() as p:
            p.crash_match = lambda r: r["kind"] == "sample" and r.get("sample_index") == 0
            with self.assertRaises(SyntheticCrash): p.worker(p.args)
            records = p.rows(); next(r for r in records if r["kind"] == "sample")["duration_ns"] = 0
            p.crash_match = None; self.reject_without_native(p, records)

    def test_unselected_case_bad_evidence_is_audited(self):
        with self.harness(two_cases=True) as p:
            p.worker(p.args); records = p.rows()
            next(r for r in records if r["kind"] == "case_complete")["final"] = not p.prov["final"]
            p.args.worker_case = p.plan["cases"][1]["case_id"]
            self.reject_without_native(p, records)

    def test_fixture_receipt_shared_as_input_is_valid_not_as_operation(self):
        with self.harness(two_cases=True, fixture_signature=True) as p:
            p.worker(p.args)
            p.args.worker_case = p.plan["cases"][1]["case_id"]
            with patch.dict(os.environ, cpu.openmp_environment(p.plan["cases"][1]["threads"], [0])):
                p.worker(p.args)
            baseline = p.rows(); p.audit(baseline)
            self.assertEqual(p.used(), 1+2*(p.case["samples"]+1))
            records = copy.deepcopy(baseline)
            operation = next(r for r in records if r["kind"] == "sample")["operation_id"]
            for row in records:
                if row.get("operation_id") == operation:
                    row["receipt"] = p.fixture_receipt
            self.reject_without_native(p, records)

    def test_cross_case_receipt_reuse_rejected_even_with_consistent_local_binding(self):
        with self.harness(two_cases=True, warmups=0) as p:
            p.worker(p.args); source = p.rows(); target = copy.deepcopy(source)
            case = p.plan["cases"][1]
            for row in target:
                binding = copy.deepcopy(row["execution_binding"]); binding["case"] = case
                row.update(cpu.binding_fields(binding), case_key=cpu.sha(cpu.canonical(binding).encode()))
                if row["kind"] == "case_start": row["case"] = case
                if row["kind"] == "case_complete": row["sample_lines"] = [n+len(source) for n in row["sample_lines"]]
            # Only IDs are new: each local case still has matching start/result.
            remap = {}
            for row in target:
                if row.get("operation_id"):
                    row["operation_id"] = remap.setdefault(row["operation_id"], cpu.uuid.uuid4().hex)
            p.args.worker_case = case["case_id"]
            self.reject_without_native(p, source+target)

    def test_operation_structure_corruption_rejected(self):
        with self.harness() as p:
            p.worker(p.args); baseline = p.rows()
            samples = [r for r in baseline if r["kind"] == "sample"]
            operations = [r for r in baseline if r["kind"] == "operation_start"]
            altered = []
            altered.append([r for r in baseline if r is not operations[0]])
            records = copy.deepcopy(baseline); next(r for r in records if r["kind"] == "sample")["operation_id"] = "0"*32
            altered.append(records)
            altered.append(baseline+[copy.deepcopy(samples[0])])
            records = copy.deepcopy(baseline); next(r for r in records if r["kind"] == "operation_start")["index"] = 999
            altered.append(records)
            for number, records in enumerate(altered):
                with self.subTest(mutation=number): self.reject_without_native(p, records)

    def test_completion_cannot_close_pending_failed_or_unready_segment(self):
        with self.harness(warmups=0) as p:
            p.worker(p.args); baseline = p.rows()
            for failure in (False, True):
                with self.subTest(failed=failure):
                    records = copy.deepcopy(baseline); complete = records.pop()
                    start = copy.deepcopy(next(r for r in records if r["kind"] == "operation_start"))
                    receipt = p.budget.reserve(cpu.ALGORITHMS[2], p.inputs["pk"], p.encoded())
                    start.update(operation_id=cpu.uuid.uuid4().hex, receipt=receipt,
                        budget_evidence=p.budget.validate_receipt(receipt, statuses=("reserved",)))
                    records.append(start)
                    if failure:
                        p.budget.finish(receipt)
                        records.append({**start, "kind": "sample", "passed": False, "duration_ns": None,
                            "error": "synthetic failed operation", "budget_evidence": p.budget.validate_receipt(receipt, statuses=("failed",))})
                    records.append(complete); self.reject_without_native(p, records)
            records = copy.deepcopy(baseline); complete = records.pop()
            segment = cpu.uuid.uuid4().hex
            start = copy.deepcopy(records[0]); start["segment_id"] = segment
            complete["segment_id"] = segment
            self.reject_without_native(p, records+[start, complete])

    def test_keyboard_interrupt_records_nonempty_failure_and_can_resume(self):
        with self.harness() as p:
            calls = p.operation
            def interrupt():
                if len(p.calls) == 0:
                    p.calls.append({"events": False})
                    raise KeyboardInterrupt()
                return calls()
            with patch.object(p.module, "raw_operation", return_value=(interrupt, lambda: p.result)):
                with self.assertRaises(KeyboardInterrupt): p.worker(p.args)
            failed = next(r for r in p.rows() if r["kind"] == "warmup")
            self.assertEqual(failed["error"], "KeyboardInterrupt: ")
            p.audit(p.rows()); p.worker(p.args); p.audit(p.rows())
            self.assertEqual(p.used(), p.case["samples"]+2)

    def test_legacy_v1_preserved_unchanged_and_not_migrated(self):
        with self.harness() as p:
            p.worker(p.args); records = p.rows()
            for row in records: row["schema"] = p.module.SCHEMA.replace("v2", "v1")
            p.rewrite(records); before = p.args.output.read_bytes(), p.used()
            with self.assertRaisesRegex(ValueError, "legacy/foreign.*no implicit migration"): p.worker(p.args)
            self.assertEqual((p.args.output.read_bytes(), p.used()), before)

    def test_campaign_metadata_tamper_parent_and_worker(self):
        with self.harness() as p:
            topo, _ = cpu.topology()
            host = cpu.environment_identity(cpu.environment({"cpus": [], "verified_physical": True, "physical_cores": topo}))
            if self.mode == "cpu":
                key = cpu.sha(cpu.canonical({"plan": cpu.file_sha(p.args.plan), "library": p.prov["library_sha256"],
                    "sources": p.prov["source_sha256"], "freeze": p.prov["freeze_sha256"],
                    "host_environment": host, "explicit_cpus": None, "ledger_uuid": p.budget.ledger_uuid}).encode())
                campaign = {"kind": "campaign_start", "campaign_key": key, "plan_sha256": cpu.file_sha(p.args.plan),
                    "provenance": p.prov, "host_environment": host, "ledger_uuid": p.budget.ledger_uuid}
            else:
                key = cpu.sha(cpu.canonical({"provenance": {k: p.prov[k] for k in
                    ("source_sha256", "library_sha256", "plan_sha256", "build_record_sha256", "freeze_sha256")},
                    "host": host, "gpu": p.gpu["identity"], "explicit_cpus": None, "ledger_uuid": p.budget.ledger_uuid}).encode())
                campaign = {"kind": "campaign_start", "campaign_key": key, "provenance": p.prov,
                    "host_environment": host, "gpu_environment": p.gpu, "ledger_uuid": p.budget.ledger_uuid}
            p.write(p.args.output, campaign); p.worker(p.args); baseline = p.rows(); p.audit(baseline)
            changes = [("ledger_uuid", "0"*32), ("provenance", {}), ("host_environment", {})]
            changes += [("plan_sha256", "wrong")] if self.mode == "cpu" else [("gpu_environment", {"identity": {}})]
            for field, value in changes:
                with self.subTest(field=field):
                    records = copy.deepcopy(baseline); records[0][field] = value
                    self.reject_without_native(p, records)
                    with self.assertRaises(ValueError): p.module.run_cases(p.args)

    def test_fixture_setup_row_binding_rejected_on_tamper(self):
        with self.harness(fixture_signature=True) as p:
            saved = cpu.read_json(p.args.fixtures/"p2-signature.json")
            setup = {"kind": "setup_signature", "case_id": p.case["case_id"], "receipt": p.fixture_receipt,
                "ledger_uuid": p.budget.ledger_uuid, "budget_evidence": p.budget.validate_receipt(p.fixture_receipt), "timed": False}
            p.write(p.args.output, setup); p.worker(p.args); baseline = p.rows(); p.audit(baseline)
            for field, value in (("receipt", "missing"), ("ledger_uuid", "0"*32), ("budget_evidence", {}),
                                 ("case_id", "other"), ("timed", True)):
                with self.subTest(field=field):
                    records = copy.deepcopy(baseline); records[0][field] = value
                    self.reject_without_native(p, records)

    def test_setup_cache_hash_bound_to_existing_file(self):
        if self.mode == "cuda": self.skipTest("CUDA reuses CPU cache preparation without a setup_cache row")
        with self.harness(cache="1") as p:
            p.worker(p.args); baseline = p.rows(); p.audit(baseline)
            self.assertEqual(sum(r["kind"] == "setup_cache" for r in baseline), 1)
            records = copy.deepcopy(baseline)
            next(r for r in records if r["kind"] == "setup_cache")["cache_file_sha256"] = "0"*64
            self.reject_without_native(p, records)


class CudaResumeRepair(ResumeRepair):
    mode = "cuda"


def main():
    output = None
    if "--output" in sys.argv:
        output = Path(sys.argv[sys.argv.index("--output")+1])
    sources = ["tools/bench_cpu.py", "tools/bench_cuda.py", "tools/signing_budget.py", "tools/test_bench_resume_repair.py"]
    before = cpu.hashes(sources)
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(cls)
                               for cls in (ResumeRepair, CudaResumeRepair))
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    print(stream.getvalue())
    after = cpu.hashes(sources)
    report = {"schema": "a15-bench-resume-repair-tests-v1", "passed": result.wasSuccessful() and before == after,
        "checks": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
        "skipped": len(result.skipped), "sources_unchanged_during_run": before == after,
        "scope": "real temporary SQLite; fake ABI, fake CUDA stats, fixed clock; subtest metadata matrices",
        "native_loads": 0, "cryptographic_operations": 0, "formal_performance_samples": 0,
        "source_sha256": after}
    if output:
        cpu.atomic_json(output, report)
        output.with_suffix(".log").write_text(stream.getvalue(), encoding="utf8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
