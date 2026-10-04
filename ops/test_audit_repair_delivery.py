"""Synthetic byte-level delivery fixtures; never execute project/native code."""
from contextlib import closing
import copy
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import tarfile
import unittest

import audit_optimization_delivery as mod


class DeliveryFixture:
    def __init__(self, root, repair=True):
        self.root, self.repair = root, repair
        self.stage = "build/repair-staging-test"
        self.remote = mod.REMOTE_ROOT+"/"+self.stage
        self.readiness = "validation/repair-readiness.json" if repair else mod.READINESS
        self.sources = {}
        for name in ("c/Makefile", "c/src/secure_zero.h", "tools/bench_cpu.py", "tools/bench_cuda.py"):
            self.put(name, ("mock source "+name).encode())
            self.sources[name] = mod.file_sha(root/name)
        original = "/usr/bin/mock-compiler"
        external_path = "validation/optimization-external-evidence/"+original.lstrip("/")
        self.put(external_path, b"external mock")
        external_hash = mod.file_sha(root/external_path)
        self.write(mod.EXTERNAL_MANIFEST, {"schema": "a15-external-evidence-mirror-v1",
            "remote_project_root": mod.REMOTE_ROOT,
            "files": {original: {"local_path": external_path, "sha256": external_hash, "size_bytes": 13}}})
        self.packages = {}
        self.gate = {"schema": "a15-optimization-final-readiness-v1", "passed": True,
            "cpu_gate_passed": True, "cuda_gate_passed": True, "formal_performance_started": False,
            "real_native_calls": 0, "real_timing_samples": 0,
            "active_benchmark_processes": [], "performance_jsonl_files": [], "packages": {}}
        for kind in ("cpu", "cuda"):
            folder = self.stage+"/validation/optimization-"+kind+"-repair" if repair else "validation/optimization-"+kind+"-final"
            remote_folder = mod.REMOTE_ROOT+"/"+folder
            build = self.stage+"/build/release-"+kind if repair else "build/cuda-staging-20261004/build/bench-"+kind+"-prep-20261004"
            library = build+"/libslhdsa_sm3.so"
            self.put(library, b"mock not executable library")
            record_name = build+"/build-record.json"
            self.write(record_name, {"schema": "a15-"+kind+"-build-v1", "library": mod.REMOTE_ROOT+"/"+library,
                "library_sha256": mod.file_sha(root/library), "counters": False, "test_injection": False,
                "sanitizer": False, "compile_output_checked": True,
                "source_sha256": {n: self.sources[n] for n in ("c/Makefile", "c/src/secure_zero.h")}})
            count = (28 if kind == "cpu" else 25) if repair else (26 if kind == "cpu" else 23)
            version = "v6" if kind == "cpu" else "v7"
            mock_name = self.stage+"/preparation/"+kind+"-mock.json" if repair else "build/cuda-staging-20261004/preparation/bench_"+kind+"-mock-final-"+version+".json"
            tool = "tools/bench_"+kind+".py"
            self.write(mock_name, {"schema": "a15-bench-selftest-v1" if kind == "cpu" else "a15-cuda-selftest-v1",
                "passed": True, "mock_checks": count, "native_calls": 0, "real_timing_samples": 0,
                "tool_sha256": self.sources[tool], "source_sha256": {tool: self.sources[tool]}})
            evidence = {mod.REMOTE_ROOT+"/"+record_name: mod.file_sha(root/record_name),
                        mod.REMOTE_ROOT+"/"+mock_name: mod.file_sha(root/mock_name), original: external_hash}
            plans = {}
            for suite, cases in ({"r3":54, "r4":207, "r5":252} if kind == "cpu" else {"cuda_b1":64}).items():
                plan_name = (self.stage+"/" if repair else "")+"docs/"+suite+".json"
                self.write(plan_name, {"schema": "a15-"+kind+"-plan-v1", "suite": suite,
                    "cases": [{"case_id": suite+"-"+str(i)} for i in range(cases)]})
                digest = mod.file_sha(root/plan_name)
                plans[suite] = {"path": mod.REMOTE_ROOT+"/"+plan_name, "sha256": digest, "cases": cases}
                evidence[mod.REMOTE_ROOT+"/"+plan_name] = digest
            freeze = {"schema": "a15-"+kind+"-freeze-v1", "final": True, "correctness_passed": True,
                "formal_performance_started": False, "real_timing_samples": 0,
                "source_sha256": self.sources.copy(), "build_record_sha256": mod.file_sha(root/record_name),
                "library_sha256": mod.file_sha(root/library), "plans": plans, "budget_snapshots": []}
            if kind == "cuda":
                snapshot_name = folder+"/budget-evidence/budget.sqlite"
                (root/snapshot_name).parent.mkdir(parents=True, exist_ok=True)
                with closing(sqlite3.connect(root/snapshot_name)) as db:
                    db.execute("CREATE TABLE mock(value INTEGER)"); db.commit()
                original_snapshot = mod.REMOTE_ROOT+"/"+snapshot_name
                snapshot_hash = mod.file_sha(root/snapshot_name)
                freeze["budget_snapshots"] = [{"live_database": self.remote+"/live.sqlite",
                    "snapshot_database": original_snapshot, "files_sha256": {original_snapshot: snapshot_hash}}]
                evidence[original_snapshot] = snapshot_hash
                release_name = (self.stage+"/" if repair else "")+"preparation/cuda-release.json"
                release = {"passed": True, "library_sha256": freeze["library_sha256"],
                    "build_record_sha256": freeze["build_record_sha256"], "device_identity": {"name":"mock GPU"},
                    "formal_performance_started": False, "measured_durations": False, "real_timing_samples": 0,
                    "sources_and_tools_sha256": self.sources.copy(), "rows": [{"passed":True} for _ in range(14)]}
                self.write(release_name, release)
                evidence[mod.REMOTE_ROOT+"/"+release_name] = mod.file_sha(root/release_name)
                freeze["device_identity"] = release["device_identity"]
                freeze["evidence"] = {"correctness": {"path": mod.REMOTE_ROOT+"/"+release_name, "sha256": mod.file_sha(root/release_name)},
                                      "mock": {"path": mod.REMOTE_ROOT+"/"+mock_name, "sha256": mod.file_sha(root/mock_name)}}
            field = "correctness_evidence" if kind == "cpu" else "correctness_evidence_sha256"
            freeze[field] = evidence
            self.write(folder+"/source-manifest.json", self.sources)
            self.put(folder+"/REVIEW.md", b"synthetic mock test fixture only")
            archive_path = root/folder/"source.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                for name in self.sources:
                    raw = (root/name).read_bytes()
                    info = tarfile.TarInfo(name); info.size = len(raw)
                    archive.addfile(info, io.BytesIO(raw))
            self.packages[kind] = {"folder": folder, "remote_folder": remote_folder,
                                   "freeze": freeze, "field": field, "mock": mock_name, "count": count}
            self.publish(kind)
        self.write(self.readiness, self.gate)

    def put(self, name, raw):
        path = self.root/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)

    def write(self, name, value): self.put(name, (json.dumps(value)+"\n").encode())

    def publish(self, kind):
        data = self.packages[kind]; folder = data["folder"]
        self.write(folder+"/freeze.json", data["freeze"])
        hashes = {name: mod.file_sha(self.root/folder/name) for name in mod.ARTIFACTS}
        self.write(folder+"/package.json", {"passed": True, "formal_performance_started": False,
            "real_timing_samples": 0, "files_sha256": hashes})
        self.gate["packages"][kind] = {"passed": True, "source_files": len(self.sources),
            "evidence_files": len(data["freeze"][data["field"]]), "files_sha256": hashes,
            "freeze_sha256": hashes["freeze.json"], "package_sha256": mod.file_sha(self.root/folder/"package.json"),
            "directory": data["remote_folder"], "mock_checks": data["count"]}
        self.write(self.readiness, self.gate)

    def audit(self):
        return mod.Audit(self.root, readiness=self.readiness,
            staging_root=self.stage if self.repair else None,
            remote_staging_root=self.remote if self.repair else None)


class Checks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="a15-delivery-repair-mock-")
        self.addCleanup(self.temp.cleanup); self.root=Path(self.temp.name)

    def test_historical_default_19_checks_preserved(self):
        data = DeliveryFixture(self.root, repair=False)
        result = data.audit().run()
        self.assertTrue(result["passed"], result["errors"])
        self.assertEqual(len(result["checks"]), 19)
        self.assertEqual((result["packages"]["cpu"]["final_mock"]["checks"], result["packages"]["cuda"]["final_mock"]["checks"]), (26,23))

    def test_repair_19_checks_explicit_mapping_and_new_mocks(self):
        data = DeliveryFixture(self.root)
        result=data.audit().run()
        self.assertTrue(result["passed"], result["errors"])
        self.assertEqual(len(result["checks"]), 19)
        self.assertEqual((result["packages"]["cpu"]["final_mock"]["checks"], result["packages"]["cuda"]["final_mock"]["checks"]), (28,25))
        self.assertEqual(result["real_timing_samples"], 0)

    def test_mapping_is_explicit_and_confined(self):
        for values in ({"readiness":"validation/repair.json"}, {"staging_root":"build/r", "remote_staging_root":mod.REMOTE_ROOT+"/build/r"},
                       {"readiness":"validation/r.json", "staging_root":"../r", "remote_staging_root":mod.REMOTE_ROOT+"/build/r"},
                       {"readiness":"validation/r.json", "staging_root":"build/r", "remote_staging_root":"/tmp/r"}):
            with self.assertRaises(mod.AuditError): mod.Audit(self.root, **values)

    def test_current_source_hash_changes_are_rejected(self):
        data=DeliveryFixture(self.root); self.root.joinpath("c/src/secure_zero.h").write_bytes(b"changed")
        result=data.audit().run()
        self.assertFalse(result["passed"])
        self.assertTrue(any(r["check"]=="cpu.current_frozen_source_hashes" for r in result["errors"]))

    def test_new_header_must_be_in_freeze_and_build(self):
        data=DeliveryFixture(self.root)
        data.packages["cpu"]["freeze"]["source_sha256"].pop("c/src/secure_zero.h")
        data.publish("cpu")
        result=data.audit().run()
        self.assertTrue(any("omits secure-zero" in r["error"] for r in result["errors"]))
        data.packages["cpu"]["freeze"]["source_sha256"]=data.sources.copy()
        freeze=data.packages["cpu"]["freeze"]
        field=data.packages["cpu"]["field"]
        original=next(name for name, digest in freeze[field].items() if digest==freeze["build_record_sha256"])
        path=data.audit().mapped(original)
        record=mod.read_json(path); record["source_sha256"].pop("c/src/secure_zero.h")
        data.put(path.relative_to(data.root).as_posix(),json.dumps(record).encode())
        freeze["build_record_sha256"]=mod.file_sha(path)
        freeze[field][original]=mod.file_sha(path); data.publish("cpu")
        result=data.audit().run()
        self.assertTrue(any("compiled sources omit secure-zero" in r["error"] for r in result["errors"]))

    def test_mock_content_hash_is_rechecked(self):
        data=DeliveryFixture(self.root)
        path=self.root/data.packages["cpu"]["mock"]
        path.write_bytes(path.read_bytes()+b" ")
        result=data.audit().run()
        self.assertFalse(result["passed"])
        self.assertTrue(any(r["check"]=="cpu.final_mock" and "SHA256 differs" in r["error"] for r in result["errors"]))

    def test_mock_count_state_and_native_zero_checked(self):
        data=DeliveryFixture(self.root)
        audit=data.audit(); package=audit.published_package("cpu", data.gate)
        mock=mod.read_json(self.root/data.packages["cpu"]["mock"])
        for field, value in (("native_calls",1), ("real_timing_samples",1), ("mock_checks",26), ("passed",False)):
            changed={**mock,field:value}; path=data.packages["cpu"]["mock"]
            data.write(path,changed)
            package["evidence"][mod.REMOTE_ROOT+"/"+path]=mod.file_sha(self.root/path)
            with self.assertRaises(mod.AuditError): audit.mocks("cpu", package)

    def test_mock_must_be_unique_exact_tool_evidence(self):
        data=DeliveryFixture(self.root); audit=data.audit(); package=audit.published_package("cpu", data.gate)
        path=data.packages["cpu"]["mock"]; original=mod.REMOTE_ROOT+"/"+path
        digest=package["evidence"].pop(original)
        with self.assertRaisesRegex(mod.AuditError,"one mock"): audit.mocks("cpu", package)
        package["evidence"][original]=digest
        duplicate=data.stage+"/preparation/duplicate-mock.json"
        data.put(duplicate,(self.root/path).read_bytes())
        package["evidence"][mod.REMOTE_ROOT+"/"+duplicate]=digest
        with self.assertRaisesRegex(mod.AuditError,"one mock"): audit.mocks("cpu", package)

    def test_archive_member_hash_and_set_stay_exact(self):
        data=DeliveryFixture(self.root); package=data.audit().published_package("cpu", data.gate)
        package["sources"]={**package["sources"],"invented.h":"0"*64}
        with self.assertRaisesRegex(mod.AuditError,"member set"): data.audit().archive(package)

    def test_readiness_and_any_project_timing_fail_closed(self):
        data=DeliveryFixture(self.root)
        data.gate["real_timing_samples"]=1; data.write(data.readiness,data.gate)
        self.assertFalse(data.audit().run()["passed"])
        data.gate["real_timing_samples"]=0; data.write(data.readiness,data.gate)
        data.put("unexpected/hidden.jsonl", b'{"schema":"a15-cpu-bench-v1","kind":"sample"}\n')
        result=data.audit().run()
        self.assertFalse(result["passed"])
        self.assertTrue(any(r["check"]=="local_performance_campaign_not_started" for r in result["errors"]))

    def test_budget_snapshot_remains_read_only_and_independent(self):
        data=DeliveryFixture(self.root); audit=data.audit(); package=audit.published_package("cuda", data.gate)
        self.assertEqual(audit.budgets("cuda",package)[0]["sqlite_integrity"],"ok")
        snapshot=package["freeze"]["budget_snapshots"][0]
        path=audit.mapped(snapshot["snapshot_database"])
        Path(str(path)+"-wal").write_bytes(b"unexpected WAL")
        with self.assertRaisesRegex(mod.AuditError,"sidecars"): audit.budgets("cuda",package)


if __name__=="__main__": unittest.main(verbosity=2)
