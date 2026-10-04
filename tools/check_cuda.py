"""CUDA backend-5 correctness evidence and logical counters; no timing.

The frozen CPU checker is imported only for immutable format/count helpers.
No GPU work silently falls back to another backend. Large REF work is reused
only from a complete, hash-checked CPU correctness run supplied explicitly.
"""

import argparse
import ctypes as ct
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import struct
import sys
import subprocess
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import check_optimization as cpu
from tools.count_model import (FIELDS, cache_model, keygen_model, parameters,
                              sign_model, subtree_model, verify_model)
from tools.native import NativeError, NativeSlhDsa, U8P, VOID, _buffer
from tools.signing_budget import SigningBudget

BACKENDS = {"REF": 1, "CUDA": 5}
SCHEMA = "a15-cuda-correctness-v1"
sha, canonical, file_sha = cpu.sha, cpu.canonical, cpu.file_sha


class CudaInfo(ct.Structure):
    _fields_=[(name,ct.c_int) for name in ("device","runtime_version","driver_version","compute_major","compute_minor")]+[
              ("total_memory",ct.c_uint64),("name",ct.c_char*96)]


class CudaStats(ct.Structure):
    _fields_=[(name,ct.c_uint64) for name in ("kernel_launches","h2d_bytes","d2h_bytes","device_hashes","kernel_ns","timing_enabled")]


def environment():
    """Capture compiler/driver/device identity; never run a benchmark probe."""
    commands=[("nvcc",["nvcc","--version"]),("c_compiler",["gcc","--version"]),
              ("devices",["nvidia-smi","--query-gpu=index,uuid,name,driver_version,memory.total,compute_cap","--format=csv,noheader"])]
    result=dict(CUDA_VISIBLE_DEVICES=os.environ.get("CUDA_VISIBLE_DEVICES"),CUDA_DEVICE_ORDER=os.environ.get("CUDA_DEVICE_ORDER"),commands={})
    for name,argv in commands:
        try:
            command=subprocess.run(argv,capture_output=True,text=True,timeout=20)
            result["commands"][name]=dict(argv=argv,returncode=command.returncode,stdout=command.stdout,stderr=command.stderr)
        except (OSError,subprocess.TimeoutExpired) as exc:
            result["commands"][name]=dict(argv=argv,error=f"{type(exc).__name__}: {exc}")
    candidates=[Path("/usr/include/cuda.h"),Path("/usr/include/cuda_runtime_api.h"),
                Path("/usr/local/cuda/include/cuda_runtime_api.h")]
    if os.environ.get("CUDA_PATH"): candidates.append(Path(os.environ["CUDA_PATH"])/"include/cuda_runtime_api.h")
    result["header_sha256"]={str(p):file_sha(p) for p in candidates if p.is_file()}
    return result


def source_hashes():
    hashes = cpu.source_hashes()
    paths = {"tools/check_cuda.py", "c/src/cuda.h", "c/src/cuda.cu"}
    paths.update(str(p.relative_to(ROOT)).replace("\\", "/")
                 for p in (ROOT / "c").rglob("*cuda*") if p.is_file())
    paths.update(("third_party/slhdsa-c/sha3_api.h", "third_party/slhdsa-c/plat_local.h"))
    hashes.update({p: file_sha(ROOT / p) for p in paths if (ROOT / p).is_file()})
    return hashes


def add_case(plan, library, pid, backend, threads, operation, variant, **extra):
    case = dict(library=library, pid=pid, backend=backend, threads=threads,
                operation=operation, variant=variant, **extra)
    case["case_id"] = cpu.case_id(case)
    plan.append(case)


def build_plan(args, libraries):
    ps, plan = parameters(), []
    for label, library in libraries.items():
        if args.require_cuda_absent and library["role"]=="cuda":
            for pid in (201,1,2,3):
                add_case(plan,label,pid,"CUDA",1,"missing_backend","required-runtime-absence")
            continue
        if library["role"] in ("disabled","missing"):
            for pid in (201, 1, 2, 3):
                add_case(plan, label, pid, "CUDA", 1, "disabled_backend" if library["role"]=="disabled" else "missing_backend", "explicit-rejection")
            continue
        add_case(plan, label, 201, "CUDA", 1, "device", "explicit-runtime")
        add_case(plan, label, 201, "CUDA", 1, "sm3_kernel", "independent-native-suite")
        for pid, p in ps.items():
            backends = ("REF", "CUDA") if p.sm3 else ("REF",)
            if not p.sm3:
                add_case(plan, label, pid, "CUDA", 1, "sha2_backend", "explicit-rejection")
            for backend in backends:
                for threads in args.threads:
                    add_case(plan, label, pid, backend, threads, "verify", "existing-vector")
                    if p.sm3:
                        for kind, maximum in (("wots", p.hp), ("fors", p.a)):
                            for z in sorted({min(z, maximum) for z in args.subtree_heights}):
                                end = (1 << p.hp) if kind == "wots" else p.k << p.a
                                for start in sorted({0, end - (1 << z)}):
                                    for target in dict.fromkeys((None, start, start + (1 << z) // 2,
                                                                start + (1 << z) - 1)):
                                        tag = "root" if target is None else "i" + str(target - start)
                                        add_case(plan, label, pid, backend, threads, "subtree",
                                                 f"{kind}-z{z}-s{start}-{tag}", kind=kind,
                                                 height=z, start=start, target=target)
                if p.sm3:
                    add_case(plan, label, pid, backend, 1, "subtree_guards", "invalid-and-unaligned")
        for pid in (201, 1, 2):
            p = ps[pid]
            for backend in ("REF", "CUDA"):
                for threads in args.threads:
                    add_case(plan, label, pid, backend, threads, "keygen", "small-t0", cache_t=0)
                    for level in (None, min(12, p.hp)):
                        add_case(plan, label, pid, backend, threads, "sign",
                                 "uncached" if level is None else f"matrix-t{level}", cache_t=level)
                    if pid == 201:
                        add_case(plan, label, pid, backend, threads, "sign_guards", "fault-wipe-budget")
        cache_pids = (201, 3) if args.suite == "full" else (201,)
        for pid in cache_pids:
            p = ps[pid]
            add_case(plan, label, pid, "CUDA", max(args.threads), "cache_source", "keygen-t0", cache_t=0)
            add_case(plan, label, pid, "CUDA", max(args.threads), "derive_cache", "independent-all-levels")
            for backend in ("REF", "CUDA"):
                for level in range(p.hp + 1):
                    add_case(plan, label, pid, backend, max(args.threads), "cache_roundtrip", f"t{level}", cache_t=level)
                    add_case(plan, label, pid, backend, max(args.threads), "cache_root_binding", f"t{level}", cache_t=level)
            for level in sorted({0, min(12, p.hp), p.hp} if pid == 201 else {12}):
                add_case(plan, label, pid, "CUDA", max(args.threads), "cache_build", f"native-t{level}", cache_t=level)
        if args.suite == "full":
            levels = range(23) if args.large_sign_all_levels else (0, 12, 22)
            for level in (None, *levels):
                add_case(plan, label, 3, "CUDA", max(args.threads), "sign",
                         "large-uncached" if level is None else f"large-t{level}", cache_t=level)
    return plan


def read_cpu_reference(directory, vectors):
    """Validate preserved rows before reusing expensive pid3 REF evidence."""
    directory = Path(directory).resolve()
    summary = json.loads((directory / "summary.json").read_text(encoding="utf8"))
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf8"))
    if not (summary["passed"] and summary["completed_requested_scope"] and summary["final"]
            and summary["suite"] == "full" and not summary["formal_performance_started"]
            and not summary["measured_durations"]):
        raise ValueError("CPU reference must be a completed full correctness run")
    identity = manifest["identity"]
    if identity["vector_sha256"] != vectors[3]["vector_sha256"]:
        raise ValueError("CPU reference vector file differs")
    if summary["source_hashes"] != identity["sources_sha256"] or summary["libraries"] != identity["libraries"]:
        raise ValueError("CPU reference manifest/summary identity differs")
    output = directory / "cases.jsonl"
    if file_sha(output) != summary["cases_jsonl_sha256"]:
        raise ValueError("CPU reference records file checksum differs")
    latest, rows = {}, 0
    for line in output.read_text(encoding="utf8").splitlines():
        row = json.loads(line)
        stored = row.pop("record_sha256")
        if sha(canonical(row)) != stored or row["schema"] != cpu.SCHEMA:
            raise ValueError("CPU reference individual record checksum/schema differs")
        if (row["source_hashes"] != summary["source_hashes"] or row["formal_performance"]
                or row["library"] != identity["libraries"][row["case"]["library"]]):
            raise ValueError("CPU reference record identity differs")
        if row["passed"] and (not all(row["checks"].values()) or not all(row["field_matches"].values())):
            raise ValueError("CPU reference passed row contains failed checks")
        if row["passed"] and row["prediction"] is not None and row["observed"] != row["prediction"]["counts"]:
            raise ValueError("CPU reference seven-field counts differ")
        row["record_sha256"] = stored
        latest[row["case_id"]] = row
        rows += 1
    if rows != summary["records"] or any(not r["passed"] for r in latest.values()):
        raise ValueError("CPU reference includes failed latest records")
    for case in manifest["plan"]:
        if case["case_id"] not in latest or latest[case["case_id"]]["case"] != case:
            raise ValueError("CPU reference planned row missing or altered")
    expected=cpu.build_plan(SimpleNamespace(**identity["configuration"]),identity["libraries"])
    if expected!=manifest["plan"] or len(expected)!=summary["planned_cases"]:
        raise ValueError("CPU reference plan differs from frozen CPU implementation")
    references = {}
    for row in latest.values():
        c = row["case"]
        if c["pid"] == 3 and c["backend"] == "REF" and c["operation"] == "sign":
            if row["input"]["signature_sha256"] != sha(vectors[3]["sig_bytes"]):
                raise ValueError("CPU reference signature fixture differs")
            if row["result"]["signature_sha256"] != sha(vectors[3]["sig_bytes"]):
                raise ValueError("CPU reference generated signature differs")
            references.setdefault(c["cache_t"], row)
    if None not in references or any(t not in references for t in range(23)):
        raise ValueError("CPU reference must include REF uncached and every pid3 cache level")
    evidence = {str(directory / name): file_sha(directory / name)
                for name in ("manifest.json", "summary.json", "cases.jsonl")}
    return references, evidence


class Runner(cpu.Runner):
    """Reuse only serialized measurement, ledger and cache path helpers."""

    def __init__(self, args):
        self.args, self.ps = args, parameters()
        self.run_dir = args.run_dir.resolve()
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.output, self.summary_path = self.run_dir / "cases.jsonl", self.run_dir / "summary.json"
        self.vectors, self.sources = cpu.load_vectors(args.vectors), source_hashes()
        self.libraries = {}
        for role, paths in (("cuda", args.library), ("disabled", args.disabled_library),("missing",args.missing_library)):
            for path in paths:
                path = path.resolve()
                digest = file_sha(path)
                label = f"{role}-{len(self.libraries)}-{digest[:12]}"
                self.libraries[label] = dict(path=str(path), sha256=digest, role=role)
        self.ledger = SigningBudget(args.budget_db)
        self.records, self.latest, self.reference_subtrees, self.available = [], {}, {}, {}
        self.measurement_metadata={}
        self.library_missing_checks=set()
        self.gpu_environment=environment()
        self.cpu_references, self.cpu_evidence = ({}, {}) if args.cpu_run is None else read_cpu_reference(args.cpu_run, self.vectors)
        self.kernel_evidence={} if args.kernel_record is None else {str(args.kernel_record.resolve()):file_sha(args.kernel_record)}
        self.plan = build_plan(args, self.libraries)
        config = json.loads(json.dumps({k:v for k,v in vars(args).items() if k != "resume"}, default=str))
        self.identity = dict(schema=SCHEMA, sources_sha256=self.sources, libraries=self.libraries,
                             vector_sha256=file_sha(args.vectors), configuration=config,
                             cpu_evidence_sha256=self.cpu_evidence,kernel_evidence_sha256=self.kernel_evidence,
                             budget_database_path=str(self.ledger.path))
        manifest = self.run_dir / "manifest.json"
        if args.resume:
            if json.loads(manifest.read_text(encoding="utf8"))["identity"] != self.identity:
                raise ValueError("resume hashes/configuration differ; preserve this run and use a new directory")
            if self.output.exists():
                for line in self.output.read_text(encoding="utf8").splitlines():
                    row = json.loads(line)
                    saved = row.pop("record_sha256")
                    if sha(canonical(row)) != saved:
                        raise ValueError("preserved CUDA case checksum differs")
                    row["record_sha256"] = saved
                    self.records.append(row); self.latest[row["case_id"]] = row
        else:
            if manifest.exists() or self.output.exists():
                raise ValueError("run directory already contains evidence")
            cpu.atomic_json(manifest, dict(identity=self.identity, plan=self.plan,
                                          created_utc=datetime.now(timezone.utc).isoformat(),
                                          boundary="CUDA correctness; formal performance has not started"))
        self.stream = self.output.open("a", encoding="utf8", newline="\n")

    def native(self, case, flags=None, backend=None):
        native = NativeSlhDsa(case["pid"], case["threads"],
                             BACKENDS[backend or case["backend"]] if flags is None else flags,
                             self.libraries[case["library"]]["path"])
        native.lib.slh_counters_reset.argtypes, native.lib.slh_counters_reset.restype = [], None
        native.lib.slh_counters_get.argtypes, native.lib.slh_counters_get.restype = [ct.POINTER(cpu.Counters)], None
        for name,signature in (("slh_cuda_get_info",([ct.POINTER(CudaInfo)],ct.c_int)),
                               ("slh_cuda_stats_reset",([ct.c_int],ct.c_int)),
                               ("slh_cuda_stats_get",([ct.POINTER(CudaStats)],ct.c_int))):
            function=getattr(native.lib,name,None)
            if function is not None: function.argtypes,function.restype=signature
        return native

    def measure(self,native,function):
        reset,get=getattr(native.lib,"slh_cuda_stats_reset",None),getattr(native.lib,"slh_cuda_stats_get",None)
        if native.backend==5 and (reset is None or get is None):
            raise ValueError("CUDA correctness stats ABI is missing")
        if reset is not None:
            code=reset(0)
            if native.backend==5 and code!=0: raise NativeError("slh_cuda_stats_reset",code)
        counts=None
        try:
            result,counts=super().measure(native,function)
        except BaseException as exc:
            counts=getattr(exc,"optimization_counts",None)
            if counts is not None: self.capture_stats(native,counts)
            raise
        self.capture_stats(native,counts)
        return result,counts

    def capture_stats(self,native,counts):
        stats=CudaStats()
        get=getattr(native.lib,"slh_cuda_stats_get",None)
        if get is not None:
            code=get(ct.byref(stats))
            if native.backend==5 and code!=0: raise NativeError("slh_cuda_stats_get",code)
        self.measurement_metadata[id(counts)]=dict(actual_selected_backend=native.backend,
                              gpu_stats={name:getattr(stats,name) for name,_ in CudaStats._fields_})

    def record(self, case, status, *, checks=None, predicted=None, observed=None, result=None, stop_on_failure=True, **details):
        checks = checks or {}
        matches = ({f: predicted["counts"][f] == observed[f] for f in FIELDS}
                   if predicted is not None and observed is not None else {})
        metadata=self.measurement_metadata.pop(id(observed),{}) if observed is not None else {}
        stats=metadata.get("gpu_stats")
        if stats is not None:
            checks["cuda_timing_disabled"]=stats["kernel_ns"]==0 and stats["timing_enabled"]==0
            if case["backend"]=="CUDA" and (case["operation"] in ("sign","sign_guards") or
                  case["operation"]=="subtree_guards" or
                  (case["operation"]=="subtree" and case.get("kind")=="fors")):
                checks["direct_gpu_kernel_execution"]=stats["kernel_launches"]>0 and stats["device_hashes"]>0
            if case["backend"]=="CUDA" and (case["operation"] in ("keygen","cache_source","cache_build","cache_prepare","cache_save","cache_load_setup","verify","verify_generated") or
                  (case["operation"]=="subtree" and case.get("kind")=="wots")):
                checks["B1_CPU_component_has_no_gpu_work"]=stats["kernel_launches"]==0 and stats["device_hashes"]==0
        if status=="passed" and (not all(checks.values()) or not all(matches.values())): status="failed"
        fingerprint = cpu.vector_fingerprint(self.vectors[case["pid"]])
        row = dict(schema=SCHEMA, case_id=case["case_id"], case=case, status=status,
                   passed=status == "passed", checks=checks, prediction=predicted,
                   observed=observed, field_matches=matches, input=fingerprint,
                   input_sha256=sha(canonical(dict(case=case,input=fingerprint))),
                   result=result, result_sha256=sha(canonical(result)), source_hashes=self.sources,
                   library=self.libraries[case["library"]], formal_performance=False,
                   recorded_utc=datetime.now(timezone.utc).isoformat(), **metadata, **details)
        row["record_sha256"] = sha(canonical(row))
        self.stream.write(json.dumps(row, sort_keys=True) + "\n"); self.stream.flush()
        self.records.append(row); self.latest[row["case_id"]] = row
        print(json.dumps(dict(case_id=row["case_id"],status=status)),flush=True)
        if status == "failed" and self.args.fail_fast and stop_on_failure:
            raise cpu.CorrectnessFailure("persisted CUDA failed check: " + row["case_id"])
        return row

    def measured_load(self,native,case,path,level):
        vector=self.vectors[case["pid"]]
        _,counts=self.measure(native,lambda:cpu.native_file_call(native.cache_load,path,vector["pk_bytes"]))
        auxiliary={**case,"operation":"cache_load_setup","variant":case["variant"]+"/load"}
        auxiliary["case_id"]=cpu.case_id(auxiliary)
        return self.record(auxiliary,"passed",predicted=cache_model(self.ps[case["pid"]],"cache_load",level),observed=counts,
                           result=dict(cache_file_sha256=file_sha(path),level=level))

    def ensure_small_cache(self,case,level):
        path=self.cache_path(case,level)
        p,vector=self.ps[case["pid"]],self.vectors[case["pid"]]
        if path.exists(): cpu.cache_payload(path,p,vector["pk_bytes"],level); return
        if p.pid==3: raise ValueError("pid3 explicit independent all-level preparation is missing")
        with self.native(case) as native:
            _,counts=self.measure(native,lambda:native.cache_build(vector["sk_bytes"],level))
            auxiliary={**case,"operation":"cache_prepare","variant":f"native-t{level}","cache_t":level}
            auxiliary["case_id"]=cpu.case_id(auxiliary)
            self.record(auxiliary,"passed",predicted=cache_model(p,"cache_build",level,case["threads"]),observed=counts)
            self.save(native,case,path,level,"prepare-save")

    def sign_attempt(self,native,vector,sk):
        receipt=self.ledger.reserve(cpu.ALGORITHMS[native.pid],vector["pk_bytes"],vector["mp_bytes"])
        try:
            signature,counts=self.measure(native,lambda:native.sign_internal(vector["mp_bytes"],sk,
                              None if vector["randomization"]=="deterministic" else vector["opt_rand_bytes"]))
        except BaseException as exc:
            self.ledger.finish(receipt); setattr(exc,"budget_receipt",receipt); raise
        self.ledger.finish(receipt,signature)
        return signature,counts,receipt

    def supported(self, case):
        key = case["library"], case["backend"]
        if key not in self.available:
            try:
                with self.native(case) as native:
                    self.available[key] = native.backend == BACKENDS[case["backend"]]
            except NativeError as exc:
                if exc.code != -2: raise
                self.available[key] = False
        if not self.available[key] and key not in self.library_missing_checks:
            rejected={**case,"operation":"missing_backend","variant":"runtime-missing-explicit-rejection"}
            rejected["case_id"]=cpu.case_id(rejected)
            self.reject_backend(rejected)
            self.library_missing_checks.add(key)
        return self.available[key]

    def reject_backend(self, case):
        library = ct.CDLL(self.libraries[case["library"]]["path"])
        library.slh_ctx_new.argtypes, library.slh_ctx_new.restype = [ct.POINTER(VOID),ct.c_int,ct.c_uint],ct.c_int
        library.slh_ctx_free.argtypes, library.slh_ctx_free.restype = [VOID],None
        library.slh_backend_available.argtypes, library.slh_backend_available.restype = [ct.c_int],ct.c_int
        context = VOID()
        code = library.slh_ctx_new(ct.byref(context),case["pid"],5)
        was_null = not context
        if context: library.slh_ctx_free(context)
        return self.record(case,"passed",checks=dict(explicit_cuda_rejected=code == -2,failed_context_is_null=was_null,
                           disabled_reports_unavailable=(library.slh_backend_available(5)==0 if case["operation"] in ("disabled_backend","missing_backend") else True)),
                           result=dict(returned_code=code))

    def device_case(self,native,case):
        function=getattr(native.lib,"slh_cuda_get_info",None)
        if function is None: raise ValueError("CUDA runtime info ABI is missing")
        info=CudaInfo(); code=function(ct.byref(info))
        data={name:(bytes(info.name).decode("utf8",errors="replace") if name=="name" else getattr(info,name))
              for name,_ in CudaInfo._fields_}
        checks=dict(device_query_success=code==0,actual_context_backend_is_cuda=native.backend==5,
                    runtime_recorded=info.runtime_version>0,driver_recorded=info.driver_version>0,
                    device_identity_recorded=bool(data["name"]) and bool(self.gpu_environment["commands"]["devices"].get("stdout")))
        if self.args.suite=="full":
            checks["CUDA_compiler_recorded"]=self.gpu_environment["commands"]["nvcc"].get("returncode")==0
            checks["C_compiler_recorded"]=self.gpu_environment["commands"]["c_compiler"].get("returncode")==0
            checks["CUDA_header_recorded"]=bool(self.gpu_environment["header_sha256"])
            checks["device_UUID_recorded"]="GPU-" in self.gpu_environment["commands"]["devices"].get("stdout","")
        return self.record(case,"passed",checks=checks,
                           result=dict(cuda_info=data,environment=self.gpu_environment,actual_selected_backend=native.backend))

    def sm3_case(self,native,case):
        if self.args.kernel_record is None:
            return self.record(case,"unavailable",reason="independent test_cuda kernel record has not been supplied")
        record=json.loads(self.args.kernel_record.read_text(encoding="utf8"))
        checks=dict(independent_kernel_suite_passed=record.get("passed") is True,
                    no_kernel_timing=record.get("formal_performance_started") is False and record.get("measured_durations") is False,
                    actual_cuda_kernel_execution=record.get("actual_selected_backend")==5 and record.get("gpu_stats",{}).get("kernel_launches",0)>0)
        sources=record.get("source_hashes",{})
        checks["kernel_source_identity_matches"]=bool(sources) and all(self.sources.get(p)==h for p,h in sources.items())
        return self.record(case,"passed",checks=checks,result=dict(kernel_record_path=str(self.args.kernel_record.resolve()),
                           kernel_record_sha256=file_sha(self.args.kernel_record),record=record))

    def subtree_guards(self,native,case):
        """Raw unaligned buffers expose overwrites hidden by the adapter."""
        p,vector=self.ps[case["pid"]],self.vectors[case["pid"]]
        native.bind_key(vector["sk_bytes"])
        address=_buffer(bytes(32)); original=bytes(address)
        root=(ct.c_uint8*18)(*([0xa5]*18)); auth=(ct.c_uint8*50)(*([0xa5]*50))
        rootp=ct.cast(ct.byref(root,1),U8P); authp=ct.cast(ct.byref(auth,1),U8P)
        first=(p.k<<p.a)-8; expected=native.subtree("fors",bytes(32),first,3,first+7)
        code,counts=self.measure(native,lambda:native.lib.slh_subtree(native.ctx,1,address,first,3,first+7,rootp,authp))
        checks=dict(valid_unaligned_succeeds=code==0,root_bytes_match=bytes(root)[1:17]==expected[0],
                    auth_bytes_match=bytes(auth)[1:49]==expected[1],root_guards=root[0]==root[17]==0xa5,
                    auth_guards=auth[0]==auth[49]==0xa5,address_unchanged=bytes(address)==original)
        invalid=[("unaligned_start",1,first+1,3,first+1,authp),
                 ("target_before",1,first,3,first-1,authp),("target_after",1,first,3,first+8,authp),
                 ("cross_fors_tree",1,(1<<p.a)-4,3,(1<<p.a)-4,authp),
                 ("missing_auth",1,first,3,first,None),
                 ("unknown_kind",2,0,0,0,None),
                 ("excess_height",1,0,p.a+1,0,authp)]
        rejected=[]
        for tag,kind,start,z,target,authptr in invalid:
            r=(ct.c_uint8*18)(*([0xa5]*18)); a=(ct.c_uint8*50)(*([0xa5]*50))
            output=ct.cast(ct.byref(r,1),U8P)
            pointer=None if authptr is None else ct.cast(ct.byref(a,1),U8P)
            returned,badcounts=self.measure(native,lambda:native.lib.slh_subtree(native.ctx,kind,address,start,z,target,output,pointer))
            badcase={**case,"operation":"subtree_rejection","variant":tag}; badcase["case_id"]=cpu.case_id(badcase)
            self.record(badcase,"passed",observed=badcounts,checks=dict(parameter_error=returned==-1,
                        output_preserved=all(v==0xa5 for v in r) and all(v==0xa5 for v in a),
                        zero_logic_counts=all(v==0 for v in badcounts.values()),address_unchanged=bytes(address)==original),
                        result=dict(returned_code=returned))
            rejected.append(tag)
        return self.record(case,"passed",predicted=subtree_model(p,"fors",3,case["threads"]),observed=counts,
                           checks=checks,result=dict(invalid_cases=rejected,root_hex=expected[0].hex(),auth_hex=expected[1].hex()))

    def sign_guards(self,native,case):
        p,vector=self.ps[case["pid"]],self.vectors[case["pid"]]
        altered=bytearray(vector["sk_bytes"]); altered[-1]^=1
        receipt=self.ledger.reserve(cpu.ALGORITHMS[p.pid],vector["pk_bytes"],vector["mp_bytes"])
        checked_case={**case}
        with self.native(checked_case,flags=BACKENDS[case["backend"]]|0x100) as checked:
            signature=(ct.c_uint8*(checked.sig_bytes+2))(*([0xa5]*(checked.sig_bytes+2)))
            pointer=ct.cast(ct.byref(signature,1),U8P)
            randomizer=None if vector["randomization"]=="deterministic" else _buffer(vector["opt_rand_bytes"])
            try:
                code,counts=self.measure(checked,lambda:checked.lib.slh_sign_internal(checked.ctx,pointer,_buffer(vector["mp_bytes"]),
                                  len(vector["mp_bytes"]),_buffer(altered),randomizer))
            finally: self.ledger.finish(receipt)
        return self.record(case,"passed",observed=counts,checks=dict(fault_error=code==-5,
                           full_output_erased=not any(bytes(signature)[1:-1]),outer_guards_preserved=signature[0]==signature[-1]==0xa5,
                           failed_budget_consumed=bool(receipt)),result=dict(returned_code=code),budget_receipt=receipt,budget_status="failed",
                           count_model_scope="corrupted SK.root: normal successful-sign formula does not apply")

    def run_case(self, case):
        p, vector, operation = self.ps[case["pid"]], self.vectors[case["pid"]], case["operation"]
        if operation in ("disabled_backend","missing_backend","sha2_backend"):
            return self.reject_backend(case)
        if not self.supported(case):
            return self.record(case,"unavailable",reason="explicit requested CUDA backend missing; no fallback")
        if operation == "derive_cache":
            family = cpu.derive_cache_family(p,vector["pk_bytes"],self.cache_directory(case)/"native-source-t0.cache",self.cache_directory(case))
            return self.record(case,"passed",checks=dict(all_levels=len(family)==p.hp+1,
                                independent_top_root=cpu.cache_payload(self.cache_path(case,p.hp),p,vector["pk_bytes"],p.hp)[1]==vector["pk_bytes"][p.n:]),
                                result=dict(family=family))
        with self.native(case) as native:
            if native.backend != BACKENDS[case["backend"]]: raise ValueError("actual backend differs")
            if operation == "device": return self.device_case(native,case)
            if operation == "sm3_kernel": return self.sm3_case(native,case)
            if operation == "subtree_guards": return self.subtree_guards(native,case)
            if operation == "sign_guards": return self.sign_guards(native,case)
            if operation == "verify":
                valid,counts=self.measure(native,lambda:native.verify_internal(vector["mp_bytes"],vector["sig_bytes"],vector["pk_bytes"]))
                return self.record(case,"passed",predicted=verify_model(p,len(vector["mp_bytes"]),vector["trace"]["chain_sums"]),
                                   observed=counts,checks=dict(existing_signature_valid=valid))
            if operation == "subtree": return self.subtree_case(native,case)
            if operation in ("keygen","cache_source"):
                native.set_cache_level(case["cache_t"])
                actual,counts=self.measure(native,lambda:native.keygen_internal(vector["sk_seed_bytes"],vector["sk_prf_bytes"],vector["pk_seed_bytes"]))
                row=self.record(case,"passed",predicted=keygen_model(p,case["threads"],case["cache_t"]),observed=counts,
                                checks=dict(public_key_matches=actual[0]==vector["pk_bytes"],secret_key_matches=actual[1]==vector["sk_bytes"]),
                                result=dict(public_key_hex=actual[0].hex(),secret_key_sha256=sha(actual[1])))
                if operation=="cache_source": self.save(native,case,self.cache_directory(case)/"native-source-t0.cache",0,"source-save")
                return row
            if operation == "cache_build":
                _,counts=self.measure(native,lambda:native.cache_build(vector["sk_bytes"],case["cache_t"]))
                built=self.cache_directory(case)/f"build-{case['backend']}-t{case['cache_t']}.cache"
                self.save(native,case,built,case["cache_t"],"real-build-save")
                expected=self.cache_path(case,case["cache_t"])
                return self.record(case,"passed",predicted=cache_model(p,"cache_build",case["cache_t"],case["threads"]),observed=counts,
                                   checks=dict(native_bytes_equal_independent_layer=file_sha(built)==file_sha(expected)),
                                   result=dict(file_sha256=file_sha(built)))
            if operation in ("cache_roundtrip","cache_root_binding"): return self.cache_case(native,case)
            if operation == "sign": return self.sign_case(native,case)
        raise ValueError("unknown CUDA correctness operation: " + operation)

    def save(self,native,case,path,level,variant):
        path.parent.mkdir(parents=True,exist_ok=True)
        _,counts=self.measure(native,lambda:cpu.native_file_call(native.cache_save,path))
        auxiliary={**case,"operation":"cache_save","variant":variant,"cache_t":level}; auxiliary["case_id"]=cpu.case_id(auxiliary)
        return self.record(auxiliary,"passed",predicted=cache_model(self.ps[case["pid"]],"cache_save",level),observed=counts,
                           result=dict(file_sha256=file_sha(path)))

    def subtree_case(self,native,case):
        p,vector=self.ps[case["pid"]],self.vectors[case["pid"]]
        native.bind_key(vector["sk_bytes"])
        address=bytearray(32); struct.pack_into(">I",address,0,p.d-1)
        address[8:16]=(((1<<(p.h-p.hp))-1) if p.h>p.hp else 0).to_bytes(8,"big")
        struct.pack_into(">I",address,16,3 if case["kind"]=="fors" else 0)
        struct.pack_into(">I",address,20,(1<<p.hp)-1)
        actual,counts=self.measure(native,lambda:native.subtree(case["kind"],address,case["start"],case["height"],case["target"]))
        key=case["library"],p.pid,case["kind"],bytes(address),case["start"],case["height"],case["target"]
        if key not in self.reference_subtrees:
            refcase={**case,"backend":"REF","threads":1,"operation":"subtree_reference"}; refcase["case_id"]=cpu.case_id(refcase)
            with self.native(refcase) as reference:
                reference.bind_key(vector["sk_bytes"])
                expected,refcounts=self.measure(reference,lambda:reference.subtree(case["kind"],address,case["start"],case["height"],case["target"]))
            self.reference_subtrees[key]=expected
            self.record(refcase,"passed",predicted=subtree_model(p,case["kind"],case["height"],1),observed=refcounts,
                        result=dict(root_hex=expected[0].hex(),auth_hex=expected[1].hex(),adrs_hex=address.hex()))
        expected=self.reference_subtrees[key]
        return self.record(case,"passed",predicted=subtree_model(p,case["kind"],case["height"],case["threads"]),observed=counts,
                           checks=dict(root_equals_REF=actual[0]==expected[0],path_equals_REF=actual[1]==expected[1]),
                           result=dict(root_hex=actual[0].hex(),auth_hex=actual[1].hex(),adrs_hex=address.hex()))

    def cache_case(self,native,case):
        p,vector,level=self.ps[case["pid"]],self.vectors[case["pid"]],case["cache_t"]
        path=self.cache_path(case,level); cpu.cache_payload(path,p,vector["pk_bytes"],level)
        self.measured_load(native,case,path,level)
        if case["operation"]=="cache_roundtrip":
            saved=self.cache_directory(case)/f"roundtrip-{case['backend']}-t{level}.cache"
            self.save(native,case,saved,level,"roundtrip-save")
            return self.record(case,"passed",checks=dict(load_save_bytes_identical=file_sha(saved)==file_sha(path)),result=dict(file_sha256=file_sha(saved)))
        bad=bytearray(path.read_bytes()); bad[48]^=1; wrong_pk=bytes(bad[32:64])
        digest=cpu.new_hash(True,bad[:64]); digest.update(bad[96:]); bad[64:96]=digest.digest()
        badpath=self.cache_directory(case)/f"bad-root-t{level}.cache"; badpath.write_bytes(bad)
        code=None
        try: _,counts=self.measure(native,lambda:cpu.native_file_call(native.cache_load,badpath,wrong_pk))
        except NativeError as exc: code,counts=exc.code,exc.optimization_counts
        preserved=self.cache_directory(case)/f"preserved-{case['backend']}-t{level}.cache"
        self.save(native,case,preserved,level,"preserved-save")
        return self.record(case,"passed",predicted=cache_model(p,"cache_load",level),observed=counts,
                           checks=dict(recomputed_checksum_root_rejected=code==-4,good_cache_preserved=file_sha(preserved)==file_sha(path)),result=dict(returned_code=code))

    def sign_case(self,native,case):
        p,vector,level=self.ps[case["pid"]],self.vectors[case["pid"]],case["cache_t"]
        if level is not None:
            if p.pid!=3: self.ensure_small_cache(case,level)
            self.measured_load(native,case,self.cache_path(case,level),level)
        signature,counts,receipt=self.sign_attempt(native,vector,vector["sk_bytes"])
        checks=dict(signature_equals_existing_vector=signature==vector["sig_bytes"])
        reference=None
        if p.pid==3:
            reference=self.cpu_references.get(level)
            checks["complete_REF_evidence_matches"]=reference is not None and reference["result"]["signature_sha256"]==sha(signature)
            checks["seven_counts_equal_preserved_REF"]=reference is not None and reference["observed"]==counts
        row=self.record(case,"passed",predicted=sign_model(p,len(vector["mp_bytes"]),vector["trace"]["chain_sums"],level,case["threads"]),
                        observed=counts,checks=checks,result=dict(signature_sha256=sha(signature)),budget_receipt=receipt,
                        budget_status="committed",reference_record_sha256=None if reference is None else reference["record_sha256"])
        for backend in ("REF","CUDA"):
            verifycase={**case,"backend":backend,"operation":"verify_generated"}; verifycase["case_id"]=cpu.case_id(verifycase)
            with self.native(verifycase) as verifier:
                valid,vcounts=self.measure(verifier,lambda:verifier.verify_internal(vector["mp_bytes"],signature,vector["pk_bytes"]))
            self.record(verifycase,"passed",predicted=verify_model(p,len(vector["mp_bytes"]),vector["trace"]["chain_sums"]),observed=vcounts,
                        checks=dict(generated_signature_valid=valid),result=dict(signature_sha256=sha(signature)))
        return row

    def checkpoint(self,error=None,final=False):
        planned={c["case_id"] for c in self.plan}
        passed={cid for cid,r in self.latest.items() if r["passed"]}
        failed=sorted(cid for cid,r in self.latest.items() if r["status"]=="failed")
        unavailable=sorted(cid for cid,r in self.latest.items() if r["status"]=="unavailable")
        pending=sorted(planned-passed-set(failed)-set(unavailable))
        good=[r for r in self.latest.values() if r["passed"]]
        budget=self.ledger.status()
        reconciled=all(r["count_reconciled"] for r in budget)
        result=dict(schema=SCHEMA,passed=not(failed or unavailable or pending or error) and reconciled,
                    completed_requested_scope=not(failed or unavailable or pending or error) and reconciled,final=final,
                    planned_cases=len(self.plan),passed_planned=len(planned&passed),records=len(self.records),
                    failed_case_ids=failed,unavailable_case_ids=unavailable,pending_case_ids=pending,error=error,
                    source_hashes=self.sources,libraries=self.libraries,identity=self.identity,gpu_environment=self.gpu_environment,
                    cases_jsonl_sha256=file_sha(self.output),budget_status=budget,budget_reconciled=reconciled,
                    formal_performance_started=False,measured_durations=False,global_atomic_measurements_serialized=True,
                    coverage=dict(verify_existing_pids=sorted({r["case"]["pid"] for r in good if r["case"]["operation"]=="verify"}),
                                  CUDA_complete_sign_pids=sorted({r["case"]["pid"] for r in good if r["case"]["operation"]=="sign" and r["case"]["backend"]=="CUDA"}),
                                  CUDA_large_sign_levels=sorted({r["case"]["cache_t"] for r in good if r["case"]["operation"]=="sign" and r["case"]["pid"]==3 and r["case"]["cache_t"] is not None}),
                                  cache_load_levels={str(pid):sorted({r["case"]["cache_t"] for r in good if r["case"]["pid"]==pid and r["case"]["operation"]=="cache_roundtrip"}) for pid in (201,3)},
                                  direct_gpu_operations=sorted({r["case"]["operation"] for r in good if r.get("gpu_stats",{}).get("kernel_launches",0)>0}),
                                  actual_selected_backends=sorted({r["actual_selected_backend"] for r in good if "actual_selected_backend" in r}),
                                  GPU_WOTS="B1 mixed backend: WOTS/message/upper/cache hashing remains CPU; GPU FORS PRF/F/H subtrees"),
                    deferred_scope=(["pid3 full hybrid tree/keygen/cache/sign requires --suite full"] if self.args.suite!="full" else [])+
                      ([] if self.args.large_sign_all_levels else ["pid3 full signatures at cache t1..11/t13..21 not directly repeated; --large-sign-all-levels enables them"]))
        result["suite"]=self.args.suite
        result["large_sign_all_levels"]=self.args.large_sign_all_levels
        result["validation_kind"]="backend-absence" if self.args.require_cuda_absent else "hybrid-CUDA-B1"
        result["direct_gpu_operation_counts"]={operation:sum(1 for r in good if r["case"]["operation"]==operation and r.get("gpu_stats",{}).get("kernel_launches",0)>0)
                          for operation in sorted({r["case"]["operation"] for r in good})}
        result["all_gpu_measurements_without_timing"]=all(r.get("gpu_stats",{}).get("kernel_ns",0)==0 and r.get("gpu_stats",{}).get("timing_enabled",0)==0 for r in self.records)
        if self.args.require_cuda_absent: result["deferred_scope"]=[]
        cpu.atomic_json(self.summary_path,result); return result

    def execute(self):
        error=None
        try:
            for case in self.plan:
                if self.latest.get(case["case_id"],{}).get("passed"): continue
                try: self.run_case(case)
                except cpu.CorrectnessFailure as exc: error=str(exc); break
                except Exception as exc:
                    self.record(case,"failed",observed=getattr(exc,"optimization_counts",None),
                                error=f"{type(exc).__name__}: {exc}",budget_receipt=getattr(exc,"budget_receipt",None),stop_on_failure=False)
                    if self.args.fail_fast or case["operation"] in ("cache_source","derive_cache"): error=f"{type(exc).__name__}: {exc}"; break
                self.checkpoint()
            if (source_hashes()!=self.sources or file_sha(self.args.vectors)!=self.identity["vector_sha256"]
                or any(file_sha(r["path"])!=r["sha256"] for r in self.libraries.values())
                or any(file_sha(p)!=h for p,h in {**self.cpu_evidence,**self.kernel_evidence}.items())):
                error="source/library/vector/preserved CPU reference changed during CUDA correctness run"
        except BaseException as exc: error=f"{type(exc).__name__}: {exc}"
        finally:
            summary=self.checkpoint(error,final=True); self.close()
        return summary


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library",type=Path,action="append",required=True,help="COUNTERS=1 CUDA-enabled library")
    parser.add_argument("--disabled-library",type=Path,action="append",default=[],help="CUDA=0 COUNTERS=1 library; required for full")
    parser.add_argument("--missing-library",type=Path,action="append",default=[],help="older/portable library without CUDA support; explicit-rejection checks")
    parser.add_argument("--run-dir",type=Path,required=True)
    parser.add_argument("--budget-db",type=Path,required=True)
    parser.add_argument("--vectors",type=Path,default=ROOT/"report-data/DP1-analysis/count-replay-inputs.jsonl")
    parser.add_argument("--cpu-run",type=Path,help="completed CPU full reference, reused for expensive pid3 REF signatures")
    parser.add_argument("--kernel-record",type=Path,help="independent native test_cuda kernel JSON evidence")
    parser.add_argument("--suite",choices=("light","full"),default="light")
    parser.add_argument("--threads",type=int,nargs="+",default=[1,4])
    parser.add_argument("--subtree-heights",type=int,nargs="+",default=[0,1,3,5,8])
    parser.add_argument("--large-sign-all-levels",action="store_true")
    parser.add_argument("--require-cuda-absent",action="store_true",help="fresh process with hidden GPU: require explicit backend5 rejection")
    parser.add_argument("--resume",action="store_true")
    parser.add_argument("--fail-fast",action="store_true")
    args=parser.parse_args()
    if args.suite=="full" and not args.require_cuda_absent and (args.cpu_run is None or not args.disabled_library or args.kernel_record is None):
        parser.error("full requires --cpu-run, --disabled-library and --kernel-record")
    if any(not 1<=n<=1024 for n in args.threads): parser.error("threads must be1..1024")
    if any(not 0<=z<=12 for z in args.subtree_heights): parser.error("bounded subtree heights must be0..12")
    args.threads=list(dict.fromkeys(args.threads)); args.subtree_heights=list(dict.fromkeys(args.subtree_heights))
    try: result=Runner(args).execute()
    except Exception as exc:
        print(json.dumps(dict(passed=False,initialization_error=f"{type(exc).__name__}: {exc}"))); return 1
    print(json.dumps(dict(summary=str(args.run_dir/"summary.json"),passed=result["passed"],formal_performance_started=False)))
    return 0 if result["passed"] else 1


if __name__=="__main__": raise SystemExit(main())
