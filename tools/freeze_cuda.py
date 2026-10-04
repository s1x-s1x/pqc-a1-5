"""Independently accept CUDA B1 evidence and freeze a preparation package.

This program loads no native library and collects no performance sample.
All validation uses preserved outputs, exact hashes and checked build records.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import sqlite3
import tempfile
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
import bench_cpu
import bench_cuda
import check_cuda
import check_optimization
import run_cuda_native
from signing_budget import canonical_algorithm


def require(condition,message):
    if not condition: raise ValueError(message)


def same_budget_algorithm(observed,expected):
    """Compare allowlisted identities for old caller labels and new ledgers."""
    try:
        return canonical_algorithm(observed)==canonical_algorithm(expected)
    except ValueError:
        return False


class InputSnapshot:
    """Parse the same bytes that supply the first digest; reject later changes."""
    def __init__(self):
        self.sha256={}
        self.budget_databases={}

    def read_bytes(self,path):
        path=Path(path).resolve(); data=path.read_bytes(); value=hashlib.sha256(data).hexdigest()
        require(self.sha256.setdefault(str(path),value)==value,"input changed after first snapshot: "+str(path))
        return data

    def digest(self,path): return hashlib.sha256(self.read_bytes(path)).hexdigest()
    def read_json(self,path): return json.loads(self.read_bytes(path).decode("utf8"))
    def lines(self,path): return self.read_bytes(path).decode("utf8").splitlines()
    def archive(self,path): return tarfile.open(fileobj=io.BytesIO(self.read_bytes(path)),mode="r:*")

    def verify(self):
        for path,expected in self.sha256.items():
            require(bench_cpu.file_sha(Path(path))==expected,"input changed during validation/packaging: "+path)


INPUTS=InputSnapshot()
def read(path): return INPUTS.read_json(path)
def digest(path): return INPUTS.digest(path)
def resolved(path):
    path=Path(path)
    return path.resolve() if path.is_absolute() else (ROOT/path).resolve()


def hash_map(mapping,label,*,current=True):
    require(bool(mapping),label+" hash map is empty")
    for name,expected in mapping.items():
        path=resolved(name)
        require(path.is_file(),label+" artifact is missing: "+name)
        if current: require(digest(path)==expected,label+" hash differs: "+name)


def row_hash(row,label,*,release=False):
    body=dict(row); expected=body.pop("record_sha256")
    encoded=bench_cpu.canonical(body).encode() if release else check_cuda.canonical(body)
    require(hashlib.sha256(encoded).hexdigest()==expected,label+" row hash differs")


def no_timing(record,label):
    require(record.get("formal_performance_started") is False and record.get("measured_durations") is False,
            label+" must explicitly precede timing")
    if "real_timing_samples" in record:
        require(type(record["real_timing_samples"]) is int and record["real_timing_samples"]==0,label+" contains timing samples")


def gpu_stats(stats,label,*,work=False):
    require(isinstance(stats,dict) and set(stats)=={name for name,_ in check_cuda.CudaStats._fields_} and
            all(type(value) is int and value>=0 for value in stats.values()),label+" requires complete six-field GPU statistics")
    require(stats["kernel_ns"]==stats["timing_enabled"]==0,label+" contains GPU timing")
    if work: require(stats["kernel_launches"]>0 and stats["device_hashes"]>0,label+" contains no device work")


def load_vectors(path):
    vectors={}; ps=check_cuda.parameters(); vector_digest=digest(path)
    for line_no,line in enumerate(INPUTS.lines(path),1):
        if not line: continue
        row=json.loads(line); row_hash(row,"independent input")
        p=ps[row["pid"]]
        for name in ("sk_seed","sk_prf","pk_seed","pk","sk","mp","sig","opt_rand"):
            row[name+"_bytes"]=bytes.fromhex(row[name])
        trace=check_optimization.signature_trace(p,row["mp_bytes"],row["sig_bytes"],row["pk_bytes"])
        require(trace["public_root_matches"],"independent input root trace differs")
        row.update(trace=trace,vector_file=str(Path(path).resolve()),vector_line=line_no,vector_sha256=vector_digest)
        vectors[p.pid]=row
    require(set(vectors)==set(ps),"independent input must supply all seven parameters")
    return vectors


def archived_sources(archive_path,expected,label):
    """Inspect only regular named source members from the hashed archive bytes."""
    with INPUTS.archive(archive_path) as archive:
        for name,value in expected.items():
            path=Path(name)
            require(not path.is_absolute() and ".." not in path.parts and "\\" not in name,
                    label+" source member path differs")
            members=[m for m in archive.getmembers() if m.name==name]
            require(len(members)==1 and members[0].isfile(),label+" source member missing/duplicate/nonregular: "+name)
            require(hashlib.sha256(archive.extractfile(members[0]).read()).hexdigest()==value,
                    label+" source member digest differs: "+name)


def read_cpu_reference(directory,vectors,baseline_directory):
    """Bind old full coverage to its own archived sources and accepted library."""
    directory=directory.resolve(); summary=read(directory/"summary.json"); manifest=read(directory/"manifest.json")
    require(summary.get("passed") is True and summary.get("completed_requested_scope") is True and
            summary.get("final") is True and summary.get("suite")=="full" and summary.get("full_sha2") is True and
            not summary.get("deferred_scope"),"CPU historical full correctness incomplete")
    no_timing(summary,"CPU historical matrix")
    identity=manifest["identity"]
    require(identity["sources_sha256"]==summary["source_hashes"] and identity["libraries"]==summary["libraries"] and
            identity["vector_sha256"]==vectors[3]["vector_sha256"],"CPU historical identity differs")
    config=identity["configuration"]
    require(config["threads"]==[1,2,4,8,16,32,64] and config["backends"]==["REF","AVX2"] and
            config["suite"]=="full" and config["full_sha2"] is True,"CPU historical full scope differs")
    expected=check_optimization.build_plan(SimpleNamespace(**config),identity["libraries"])
    require(expected==manifest["plan"] and len(expected)==summary["planned_cases"]==3471,"CPU historical explicit3471 plan differs")
    archive_record=read(directory/"tested-source.json"); archive_path=directory/"tested-source.tar.gz"
    require(archive_record["archive_sha256"]==digest(archive_path) and
            all(archive_record["sources_sha256"].get(n)==v for n,v in summary["source_hashes"].items()),
            "CPU historical tested source archive identity differs")
    archived_sources(archive_path,archive_record["sources_sha256"],"CPU historical matrix")
    baseline_directory=baseline_directory.resolve(); baseline_path=baseline_directory/"manifest.json"; baseline=read(baseline_path)
    baseline_steps=["avx2-build-and-tests","counter-build-and-tests","portable-build-and-tests","sanitizer-tests",
                    "external-avx2","external-portable","complete-128-24","toy-differential","subtree-differential",
                    "exact-counts","cli-and-budget"]
    require(baseline.get("passed") is True and baseline.get("source_unchanged") is True and baseline.get("inputs_unchanged") is True
            and [s["name"] for s in baseline["steps"]]==baseline_steps and all(s["returncode"]==0 for s in baseline["steps"]),
            "CPU historical native baseline incomplete")
    baseline_record=read(baseline_directory/"source-archive.json"); baseline_archive=baseline_directory/"source.tar.gz"
    require(baseline_record["manifest_sha256"]==digest(baseline_path) and
            baseline_record["source_archive_sha256"]==digest(baseline_archive),"CPU historical native archive identity differs")
    archived_sources(baseline_archive,baseline["source_sha256"],"CPU historical native")
    overlap=set(summary["source_hashes"])&set(baseline["source_sha256"])
    require(bool(overlap) and all(summary["source_hashes"][n]==baseline["source_sha256"][n] for n in overlap),
            "CPU historical matrix/native sources differ")
    for group in ("inputs_sha256","evidence_sha256","build_sha256"):
        hash_map(baseline[group],"CPU historical native "+group)
    accepted={h for n,h in baseline["build_sha256"].items() if n.endswith("/counters/libslhdsa_sm3.so")}
    require(bool(accepted),"CPU historical accepted counter library missing")
    for library in identity["libraries"].values():
        require(library["sha256"] in accepted and digest(library["path"])==library["sha256"],"CPU historical counter library differs")
    cases_path=directory/"cases.jsonl"; require(digest(cases_path)==summary["cases_jsonl_sha256"],"CPU historical cases hash differs")
    latest={}; count=0
    for line in INPUTS.lines(cases_path):
        row=json.loads(line); row_hash(row,"CPU historical")
        require(row["schema"]==check_optimization.SCHEMA and row["source_hashes"]==summary["source_hashes"] and
                row["formal_performance"] is False and row["library"]==identity["libraries"][row["case"]["library"]] and
                row["passed"]==(row["status"]=="passed") and row["case_id"]==check_optimization.case_id(row["case"]),
                "CPU historical row identity/status differs")
        if row["passed"]:
            require(all(row["checks"].values()) and all(row["field_matches"].values()),"CPU historical passed row contains failed checks")
            if row["prediction"] is not None:
                require(row["observed"]==row["prediction"]["counts"],"CPU historical seven-field counts differ")
        latest[row["case_id"]]=row; count+=1
    # Preparation, cache I/O and generated verification have distinct,
    # preserved auxiliary IDs; all must pass, while every planned ID must exist.
    require(count==summary["records"] and {c["case_id"] for c in expected}.issubset(latest) and
            all(r["passed"] for r in latest.values()),"CPU historical latest records incomplete")
    for case in expected: require(latest[case["case_id"]]["case"]==case,"CPU historical plan row differs")
    references={}
    for row in latest.values():
        case=row["case"]
        if case["pid"]==3 and case["backend"]=="REF" and case["operation"]=="sign":
            require(row["input"]["signature_sha256"]==row["result"]["signature_sha256"]==check_cuda.sha(vectors[3]["sig_bytes"]),
                    "CPU historical signature differs from fixture")
            references.setdefault(case["cache_t"],row)
    require(set(references)=={None,*range(23)},"CPU historical REF full cache levels missing")
    require(bool(summary["budget_status"]) and all(r["count_reconciled"] is True for r in summary["budget_status"]),
            "CPU historical full budget reconciliation differs")
    evidence={str(directory/name):digest(directory/name) for name in ("summary.json","manifest.json","cases.jsonl")}
    return references,evidence


def receipt_rows(database,receipts):
    database=database.resolve(); require(database.is_file(),"persistent CUDA budget database missing")
    database_bytes=INPUTS.read_bytes(database)
    wal=Path(str(database)+"-wal")
    wal_bytes=INPUTS.read_bytes(wal) if wal.is_file() else None
    require(INPUTS.budget_databases.setdefault(str(database),wal_bytes is not None)==(wal_bytes is not None),
            "CUDA persistent budget WAL presence changed after first snapshot")
    # SQLite reads the preserved bytes, including a preserved WAL when present.
    # The original database is read-only evidence; temporary shm writes stay here.
    with tempfile.TemporaryDirectory(prefix="a15-cuda-budget-") as temporary:
        clone=Path(temporary)/"budget.sqlite"; clone.write_bytes(database_bytes)
        if wal_bytes is not None: Path(str(clone)+"-wal").write_bytes(wal_bytes)
        db=sqlite3.connect("file:"+clone.as_posix()+"?mode=ro",uri=True)
        try:
            db.execute("BEGIN")
            result={}
            for receipt in receipts:
                matches=db.execute("SELECT r.status,r.message_sha256,r.signature_sha256,k.algorithm,k.public_key "
                        "FROM reservations r JOIN keys k ON r.key_id=k.key_id WHERE receipt=?",(receipt,)).fetchall()
                require(len(matches)<=1,"CUDA persistent receipt has multiple SQL matches")
                result[receipt]=matches[0] if matches else None
        finally: db.close()
    digest(database)
    require(wal.is_file()==(wal_bytes is not None),"CUDA persistent budget WAL changed during validation")
    if wal_bytes is not None: digest(wal)
    return result


def preserve_budget_evidence(out,evidence):
    """Keep immutable SQL evidence when future campaigns extend the live ledger."""
    snapshots=[]
    if not INPUTS.budget_databases: return snapshots
    directory=out/"budget-evidence"; directory.mkdir()
    for index,(database,has_wal) in enumerate(sorted(INPUTS.budget_databases.items())):
        clone=directory/f"budget-{index}.sqlite"
        files={database:clone}
        if has_wal: files[database+"-wal"]=Path(str(clone)+"-wal")
        hashes={}
        for source,target in files.items():
            data=INPUTS.read_bytes(source)
            with target.open("xb") as stream: stream.write(data)
            expected=hashlib.sha256(data).hexdigest()
            require(digest(target)==expected,"CUDA preserved budget snapshot differs")
            evidence.pop(source,None)
            evidence[str(target.resolve())]=expected
            hashes[str(target.resolve())]=expected
        snapshots.append(dict(live_database=database,snapshot_database=str(clone.resolve()),
                              files_sha256=hashes,classification="immutable acceptance evidence; live ledger may grow after publication"))
    return snapshots


def predicted_counts(case,vector):
    p=check_cuda.parameters()[case["pid"]]; op=case["operation"]
    if op in ("verify","verify_generated"):
        return check_cuda.verify_model(p,len(vector["mp_bytes"]),vector["trace"]["chain_sums"])["counts"]
    if op in ("subtree","subtree_reference","subtree_guards"):
        return check_cuda.subtree_model(p,"fors" if op=="subtree_guards" else case["kind"],
                                       3 if op=="subtree_guards" else case["height"],case["threads"])["counts"]
    if op in ("keygen","cache_source"):
        return check_cuda.keygen_model(p,case["threads"],case["cache_t"])["counts"]
    if op=="sign":
        return check_cuda.sign_model(p,len(vector["mp_bytes"]),vector["trace"]["chain_sums"],case["cache_t"],case["threads"])["counts"]
    if op in ("cache_prepare","cache_build","cache_save","cache_load_setup","cache_root_binding"):
        name="cache_build" if op in ("cache_prepare","cache_build") else "cache_save" if op=="cache_save" else "cache_load"
        return check_cuda.cache_model(p,name,case["cache_t"],case["threads"])["counts"]
    return None


def verify_budget_receipts(database,rows,vectors):
    rows=[row for row in rows if row.get("budget_receipt") is not None]
    receipts=[row["budget_receipt"] for row in rows]
    require(len(set(receipts))==len(receipts),"CUDA matrix budget receipt reused")
    found_rows=receipt_rows(database,receipts)
    for row in rows:
        receipt=row.get("budget_receipt"); found=found_rows[receipt]
        require(found is not None,"CUDA signature reservation absent from persistent database")
        require(found[0]==row["budget_status"],"CUDA receipt status differs")
        pid=row["case"]["pid"]; vector=vectors[pid]
        require(found[1]==check_cuda.sha(vector["mp_bytes"]) and same_budget_algorithm(found[3],check_optimization.ALGORITHMS[pid]) and
                found[4]==vector["pk_bytes"],"CUDA receipt input/key identity differs")
        if found[0]=="committed": require(found[2]==row["result"]["signature_sha256"],"CUDA receipt signature digest differs")
        else: require(found[2] is None,"CUDA failed reservation contains signature digest")


def validate_matrix(directory,*,expected_kernel,cpu_baseline):
    directory=directory.resolve(); summary=read(directory/"summary.json"); manifest=read(directory/"manifest.json")
    require(summary.get("schema")==check_cuda.SCHEMA and summary.get("final") is True and
            summary.get("passed") is True and summary.get("completed_requested_scope") is True,
            "CUDA full correctness acceptance incomplete")
    require(summary.get("validation_kind")=="hybrid-CUDA-B1" and summary.get("suite")=="full" and
            summary.get("large_sign_all_levels") is True and not summary.get("deferred_scope"),"CUDA full all-level scope required")
    no_timing(summary,"CUDA matrix")
    require(summary.get("all_gpu_measurements_without_timing") is True and summary.get("budget_reconciled") is True,
            "CUDA matrix timing/budget flags differ")
    require(not any(summary.get(k) for k in ("failed_case_ids","unavailable_case_ids","pending_case_ids","error")),
            "CUDA matrix includes incomplete cases")
    identity=manifest["identity"]
    require(identity==summary["identity"] and identity["schema"]==check_cuda.SCHEMA,
            "CUDA manifest/summary identity differs")
    require(identity["sources_sha256"]==summary["source_hashes"]==check_cuda.source_hashes(),"CUDA checker source hash differs")
    require(identity["libraries"]==summary["libraries"],"CUDA library identities differ")
    config=identity["configuration"]
    require(config["suite"]=="full" and config["large_sign_all_levels"] is True and
            config["threads"]==[1,4,64] and not config["require_cuda_absent"],"CUDA acceptance must use threads1/4/64 and all levels")
    require(config["subtree_heights"]==[0,1,3,5,8],"CUDA bounded-subtree plan differs")
    vectors=load_vectors(resolved(config["vectors"]))
    require(vectors[3]["vector_sha256"]==identity["vector_sha256"],"CUDA vector file changed")
    require(str(resolved(config["kernel_record"]))==str(expected_kernel.resolve()),"CUDA matrix kernel record path differs")
    require(identity["kernel_evidence_sha256"]=={str(expected_kernel.resolve()):digest(expected_kernel)},"CUDA kernel reference hash differs")
    cpu_refs,cpu_evidence=read_cpu_reference(resolved(config["cpu_run"]),vectors,cpu_baseline)
    require(cpu_evidence==identity["cpu_evidence_sha256"],"preserved CPU full reference identity differs")
    require(identity["budget_database_path"]==str(resolved(config["budget_db"])),"CUDA budget path differs")
    hash_map(summary["source_hashes"],"CUDA source")
    roles={library["role"] for library in summary["libraries"].values()}
    require("cuda" in roles and "disabled" in roles,"CUDA enabled and build-disabled libraries both required")
    for library in summary["libraries"].values():
        require(digest(library["path"])==library["sha256"],"CUDA tested library changed")
    expected=check_cuda.build_plan(SimpleNamespace(**config),summary["libraries"])
    require(expected==manifest["plan"] and len(expected)==summary["planned_cases"],"CUDA explicit plan differs")
    path=directory/"cases.jsonl"; require(digest(path)==summary["cases_jsonl_sha256"],"CUDA cases file hash differs")
    latest={}; count=0
    predicted_operations={"verify","verify_generated","subtree","subtree_reference","subtree_guards",
                          "keygen","cache_source","cache_prepare","cache_build","cache_save","cache_load_setup","cache_root_binding","sign"}
    for line in INPUTS.lines(path):
        row=json.loads(line); row_hash(row,"CUDA")
        case=row["case"]; pid=case["pid"]
        require(row["schema"]==check_cuda.SCHEMA and row["source_hashes"]==summary["source_hashes"] and
                row["library"]==summary["libraries"][case["library"]] and row["formal_performance"] is False,
                "CUDA case source/library/schema/timing identity differs")
        require(row["case_id"]==check_optimization.case_id(case),"CUDA case identifier differs from fields")
        fingerprint=check_optimization.vector_fingerprint(vectors[pid])
        require(row["input"]==fingerprint and row["input_sha256"]==check_cuda.sha(check_cuda.canonical(dict(case=case,input=fingerprint))),
                "CUDA case input fingerprint differs")
        require(row["result_sha256"]==check_cuda.sha(check_cuda.canonical(row["result"])),"CUDA result fingerprint differs")
        require(row["passed"]==(row["status"]=="passed"),"CUDA case pass/status differs")
        if row["passed"]:
            require(all(row["checks"].values()) and all(row["field_matches"].values()),"CUDA passed row contains failed check")
            if case["operation"] in predicted_operations:
                require(row["prediction"] is not None and row["observed"] is not None and
                        set(row["field_matches"])==set(check_cuda.FIELDS) and row["prediction"]["counts"]==row["observed"],
                        "CUDA normal operation lacks complete seven-field prediction")
                require(row["observed"]==predicted_counts(case,vectors[pid]),"independent seven-field recomputation differs")
            stats=row.get("gpu_stats")
            if stats is not None:
                gpu_stats(stats,"CUDA matrix operation")
                require(row["actual_selected_backend"]==check_cuda.BACKENDS[case["backend"]],"CUDA actual context backend differs")
                GPU_required=case["backend"]=="CUDA" and (case["operation"] in ("sign","sign_guards","subtree_guards") or
                                        case["operation"]=="subtree" and case.get("kind")=="fors")
                if GPU_required: require(stats["kernel_launches"]>0 and stats["device_hashes"]>0,"CUDA claimed operation contains no GPU work")
            elif case["operation"] in predicted_operations or case["operation"]=="sign_guards":
                raise ValueError("CUDA measured operation lacks GPU statistics")
            if case["operation"]=="sign":
                require(row.get("budget_receipt") and row.get("budget_status")=="committed" and
                        row["result"]["signature_sha256"]==check_cuda.sha(vectors[pid]["sig_bytes"]),"CUDA full signature/budget differs")
                if pid==3:
                    reference=cpu_refs[case["cache_t"]]
                    require(row["reference_record_sha256"]==reference["record_sha256"] and row["observed"]==reference["observed"],
                            "CUDA pid3 preserved REF comparison differs")
            if case["operation"]=="sign_guards":
                require(row.get("budget_receipt") and row.get("budget_status")=="failed" and
                        row["checks"].get("full_output_erased") is True,"CUDA failed sign guard/budget differs")
        latest[row["case_id"]]=row; count+=1
    require(count==summary["records"] and all(r["passed"] for r in latest.values()),"CUDA latest rows include failure")
    require({c["case_id"] for c in expected}.issubset(latest) and len(expected)==1789,"CUDA exact1789-case scope differs")
    for case in expected:
        require(case["case_id"] in latest and latest[case["case_id"]]["case"]==case and latest[case["case_id"]]["passed"],
                "CUDA planned case missing or identity altered: "+case["case_id"])
    coverage=summary["coverage"]
    require(coverage["verify_existing_pids"]==[1,2,3,101,102,103,201] and coverage["CUDA_complete_sign_pids"]==[1,2,3,201],"CUDA parameter coverage differs")
    require(coverage["CUDA_large_sign_levels"]==list(range(23)) and coverage["cache_load_levels"]["3"]==list(range(23)),"CUDA pid3 all-level coverage differs")
    require(coverage["actual_selected_backends"]==[1,5] and summary["direct_gpu_operation_counts"].get("sign",0)>0 and
            summary["direct_gpu_operation_counts"].get("subtree",0)>0,"CUDA actual backend/GPU coverage differs")
    require(all(r["count_reconciled"] for r in summary["budget_status"]),"CUDA budget reconciliation differs")
    verify_budget_receipts(resolved(identity["budget_database_path"]),latest.values(),vectors)
    gpu_env=summary["gpu_environment"]
    require(gpu_env["CUDA_VISIBLE_DEVICES"]=="0" and bool(gpu_env["header_sha256"]) and
            all(gpu_env["commands"][name].get("returncode")==0 for name in ("nvcc","c_compiler","devices")) and
            "GPU-" in gpu_env["commands"]["devices"]["stdout"],"CUDA compiler/header/driver/device UUID environment incomplete")
    hash_map(gpu_env["header_sha256"],"CUDA compiler headers")
    return summary,manifest,{str(directory/name):digest(directory/name) for name in ("summary.json","manifest.json","cases.jsonl")},cpu_evidence


def validate_native(directory,matrix):
    directory=directory.resolve(); manifest=read(directory/"manifest.json")
    require(manifest.get("schema")=="a15-cuda-native-v1" and manifest.get("passed") is True and
            manifest.get("source_unchanged") is True and not manifest.get("error"),"CUDA native acceptance incomplete")
    no_timing(manifest,"CUDA native acceptance")
    current_sources=run_cuda_native.sources()
    require(all(current_sources.get(name)==value for name,value in manifest["source_hashes"].items()),"CUDA native source changed")
    # The main checkout also carries upstream test fixtures omitted from the
    # isolated acceptance checkout. They are outside the accepted Makefile inputs.
    added_sources=set(current_sources)-set(manifest["source_hashes"])
    require(all(name.startswith("third_party/slhdsa-c/test/") and name not in bench_cuda.BUILD_FILES
                for name in added_sources),"CUDA native acceptance omits active source inputs")
    require(all(manifest["source_hashes"].get(p)==h for p,h in matrix["source_hashes"].items() if p.startswith(("c/","third_party/"))),
            "CUDA matrix/native source versions differ")
    names=["release-kernels-faults-guards","counter-kernels","disabled-build-dispatch","hidden-device-dispatch","release-library-dependencies"]
    require([s["name"] for s in manifest["steps"]]==names and all(s["returncode"]==0 for s in manifest["steps"]),
            "CUDA native five steps incomplete")
    hash_map(manifest["source_hashes"],"CUDA native source")
    hash_map(manifest["build_sha256"],"CUDA native build")
    hash_map(manifest["evidence_sha256"],"CUDA native evidence")
    steps={s["name"]:s for s in manifest["steps"]}
    for step in manifest["steps"]:
        require(digest(step["log"])==step["log_sha256"],"CUDA native log differs")
    log="\n".join(INPUTS.lines(steps[names[0]]["log"]))
    require("native guard compiler checks PASS" in log,"CUDA release guard acceptance missing")
    for point in range(6):
        command_lines=[line for line in log.splitlines() if " -DSLH_TEST_BUILD " in line and f"-DSLH_TEST_FAULT_POINT={point} " in line]
        require(any("-DSLH_TEST_BACKEND=5" in line for line in command_lines),"CUDA host fault compile flags missing")
        require(any("sm3_cuda.cu" in line and "-DSLH_RELEASE_BUILD" not in line for line in command_lines),"CUDA device fault compile flags missing")
        for threads in (1,4):
            for level in (5,10):
                for enabled in (0,1):
                    line=f"fault point={point} backend=5 threads={threads} cache_t={level} self_verify={enabled} pure/internal/prehash/digest PASS"
                    require(line in log,"CUDA fault executable combination missing: "+line)
        require(any(name.endswith(f"/test_cuda_fault_{point}") for name in manifest["build_sha256"]),"CUDA fault executable fingerprint missing")
    counter_lines=[json.loads(line) for line in INPUTS.lines(steps["counter-kernels"]["log"]) if line.startswith('{"')]
    require(len(counter_lines)==4 and all(r.get("passed") is True and r.get("timed") is False for r in counter_lines),"CUDA native counter test rows incomplete")
    disabled="\n".join(INPUTS.lines(steps["disabled-build-dispatch"]["log"]))
    absence=[json.loads(line) for line in disabled.splitlines() if line.startswith('{"')]
    require(bool(absence) and absence[-1].get("cuda_available") is False and absence[-1].get("passed") is True,
            "CUDA=0 dispatch rejection missing")
    hidden=read(steps["hidden-device-dispatch"]["log"])
    require(steps["hidden-device-dispatch"]["hidden_device"] is True and hidden.get("cuda_available") is False and
            hidden.get("passed") is True and hidden.get("timed") is False,"runtime hidden-device dispatch rejection missing")
    deps="\n".join(INPUTS.lines(steps["release-library-dependencies"]["log"]))
    require("not found" not in deps and "lib" in deps,"CUDA release dependencies missing")
    enabled={h for name,h in manifest["build_sha256"].items() if name.endswith("/counters/libslhdsa_sm3.so")}
    disabled_hashes={h for name,h in manifest["build_sha256"].items() if name.endswith("/disabled/libslhdsa_sm3.so")}
    for library in matrix["libraries"].values():
        if library["role"]=="cuda": require(library["sha256"] in enabled,"matrix does not use native accepted CUDA counter library")
        if library["role"]=="disabled": require(library["sha256"] in disabled_hashes,"matrix does not use native accepted disabled library")
    return manifest,steps,counter_lines


def validate_kernel(path,matrix,native,steps,raw):
    record=read(path); no_timing(record,"CUDA kernel wrapper")
    require(record.get("passed") is True and record.get("actual_selected_backend")==5,"CUDA kernel wrapper did not execute GPU backend5")
    stats=record.get("gpu_stats",{})
    require(isinstance(stats,dict) and set(stats)=={"kernel_launches","device_hashes","kernel_ns","timing_enabled"} and
            all(type(value) is int and value>=0 for value in stats.values()),"CUDA kernel wrapper requires its four reported statistics")
    require(stats["kernel_ns"]==stats["timing_enabled"]==0 and stats["kernel_launches"]>0 and
            stats["device_hashes"]>0,"CUDA kernel wrapper contains timing or no device work")
    sources=record.get("source_hashes",{})
    require(bool(sources) and all(matrix["source_hashes"].get(p)==h for p,h in sources.items()),"CUDA kernel wrapper source identity differs")
    results=record.get("results",record.get("cases",[]))
    require(results==raw and all(r.get("passed") is True for r in results),"CUDA raw kernel comparisons differ from native log")
    require(record["log_sha256"]==steps["counter-kernels"]["log_sha256"],"CUDA kernel wrapper log binding differs")
    require(record["library_sha256"] in {h for n,h in native["build_sha256"].items() if n.endswith("/counters/libslhdsa_sm3.so")} and
            record["executable_sha256"] in {h for n,h in native["build_sha256"].items() if n.endswith("/counters/test_cuda")},"CUDA kernel executable/library binding differs")
    tags={r.get("case"):r for r in results}
    require(tags.get("gpu-sm3",{}).get("comparisons",0)>0 and
            tags.get("gpu-fors-subtrees-and-hybrid-wots",{}).get("comparisons",0)>0 and
            tags.get("gpu-full-signatures-cache-randomized-inputs-and-guards",{}).get("comparisons",0)>0,
            "CUDA independent SM3/FORS/signature raw cases missing")
    actual=results[-1]
    require(actual.get("cuda_available") is True and actual.get("actual_backend")==5 and actual.get("device")==0 and
            actual["kernel_launches"]==stats["kernel_launches"] and actual["device_hashes"]==stats["device_hashes"],
            "CUDA kernel wrapper aggregate differs from raw GPU output")
    return record


def release_vectors(path):
    vectors=[json.loads(line) for line in INPUTS.lines(path) if line]
    require(len(vectors)==3 and all(v["pid"]==3 for v in vectors) and
            len({v["case_id"] for v in vectors})==len({v["pk"] for v in vectors})==len({v["sk_seed"] for v in vectors})==3 and
            {v["randomization"] for v in vectors}=={"deterministic","explicit"},"CUDA release independent three-vector scope differs")
    for vector in vectors: row_hash(vector,"CUDA release independent input")
    return vectors


def expected_signature_input(pid,api,message,context,pk,*,raw_message=None,hash_alg=None,randomization="deterministic",opt_rand=None):
    return dict(pid=pid,api=api,hash_alg=hash_alg,randomization=randomization,
                api_input_sha256=check_cuda.sha(message),message_sha256=check_cuda.sha(message if raw_message is None else raw_message),
                context_sha256=check_cuda.sha(context),opt_rand_sha256=None if opt_rand is None else check_cuda.sha(opt_rand),
                public_key_hex=pk.hex(),public_key_sha256=check_cuda.sha(pk),budget_algorithm=check_optimization.ALGORITHMS[pid],
                budget_message_sha256=check_cuda.sha(message))


def validate_release_rows(record,vectors,database):
    expected={v["case_id"]+suffix for v in vectors for suffix in ("/keygen","/sign","/release-counts")}
    expected.update("toy/prehash-"+str(i) for i in range(1,6))
    rows=record["rows"]; require(len(rows)==14 and {r["case_id"] for r in rows}==expected,"CUDA exact14 release cases differ")
    by_id={r["case_id"]:r for r in rows}; signatures=[]
    for row in rows:
        row_hash(row,"CUDA release",release=True)
        require(row["passed"] is True and bool(row["checks"]) and all(type(v) is bool and v for v in row["checks"].values()),
                "CUDA release check failed")
    for vector in vectors:
        decode=lambda key:bytes.fromhex(vector[key]); case_id=vector["case_id"]
        for suffix in ("/keygen","/sign","/release-counts"):
            require(by_id[case_id+suffix]["input_reference_record_sha256"]==vector["record_sha256"],"CUDA release input reference differs")
        keygen=by_id[case_id+"/keygen"]; counts=by_id[case_id+"/release-counts"]; signed=by_id[case_id+"/sign"]
        require(set(keygen["checks"])=={"actual_backend","pk_equals_Python","sk_equals_Python"} and
                keygen["actual_selected_backend"]==5 and keygen["public_key_sha256"]==check_cuda.sha(decode("pk")),
                "CUDA release keygen scope/public key differs")
        require(counts["checks"]=={"counters_disabled":True} and keygen.get("gpu_stats") is None and counts.get("gpu_stats") is None,
                "CUDA release counter-off scope differs")
        require(set(signed["checks"])=={"signature_equals_Python","verify_internal","pure_verify","changed_message_rejected","REF_verify",
                                          "events_disabled","actual_GPU_work"},"CUDA release Python signature checks differ")
        randomizer=None if vector["randomization"]=="deterministic" else decode("opt_rand")
        expected_input=expected_signature_input(3,"sign_internal",decode("mp"),decode("context"),decode("pk"),
                        raw_message=decode("message"),randomization=vector["randomization"],opt_rand=randomizer)
        require(signed["input"]==expected_input and signed["signature_sha256"]==check_cuda.sha(decode("sig")),
                "CUDA release signature input/public key/signature digest differs")
        signatures.append(signed)
    require(record["prehash_seed_sha256"]==check_cuda.sha(bytes(range(48))),"CUDA prehash seed identity differs")
    pk=bytes.fromhex(record["prehash_public_key_hex"])
    require(len(pk)==32 and pk[:16]==bytes(range(32,48)),"CUDA prehash public key seed/length differs")
    for hash_alg in range(1,6):
        row=by_id["toy/prehash-"+str(hash_alg)]
        require(set(row["checks"])=={"CUDA_verify","REF_verify","wrong_context_rejected","events_disabled","actual_GPU_work"},
                "CUDA release prehash checks differ")
        expected_input=expected_signature_input(201,"sign_prehash",b"\0CUDA release prehash\xff",b"CUDA",pk,hash_alg=hash_alg)
        require(row["input"]==expected_input,"CUDA release prehash API/message/context/public key differs")
        signatures.append(row)
    require(len(signatures)==8,"CUDA release requires eight complete signatures")
    receipts=[r.get("budget_receipt") for r in signatures]
    require(all(type(r) is str and bool(r) for r in receipts) and len(set(receipts))==8,"CUDA release receipt missing/duplicated")
    found_rows=receipt_rows(database,receipts)
    for row in signatures:
        gpu_stats(row.get("gpu_stats"),"CUDA release signature",work=True)
        require(row["actual_selected_backend"]==5 and row["budget_status"]=="committed","CUDA release backend/budget status differs")
        signature=row["signature_sha256"]
        require(type(signature) is str and len(signature)==64 and all(c in "0123456789abcdef" for c in signature),
                "CUDA release signature digest malformed")
        fingerprint=row["input"]
        found=found_rows[row["budget_receipt"]]
        require(found is not None and found[:3]==("committed",fingerprint["budget_message_sha256"],signature) and
                same_budget_algorithm(found[3],fingerprint["budget_algorithm"]) and
                found[4]==bytes.fromhex(fingerprint["public_key_hex"]),
                "CUDA release persistent receipt message/public key/signature/status differs")


def validate_release(path,build,*,budget_database):
    record=read(path); no_timing(record,"CUDA exact release acceptance")
    require(record.get("schema")=="a15-cuda-release-correctness-v1" and record.get("passed") is True and
            record.get("real_timing_samples")==0 and record.get("actual_selected_backend")==5 and not record.get("error"),"CUDA exact release acceptance incomplete")
    require(record["source_sha256"]==build["source_sha256"] and record["library_sha256"]==build["library_sha256"] and
            record["build_record_sha256"]==digest(build["_record_path"]) and record["device_identity"]==build["release_probe"]["device"],"CUDA release build/device identity differs")
    hash_map(record["sources_and_tools_sha256"],"CUDA release source/tool")
    require(record["sources_and_tools_sha256"]==bench_cpu.hashes(bench_cuda.BUILD_FILES+bench_cuda.TOOL_FILES+["tools/check_cuda_release.py"]),
            "CUDA release source/tool scope differs")
    hash_map(record["input_sha256"],"CUDA release input")
    require(set(record["input_sha256"].values())=={digest(ROOT/"reference/evidence/python-sm3-128-24.jsonl")},
            "CUDA release independent Python input differs from project acceptance")
    require(set(record["input_sha256"])=={str((ROOT/"reference/evidence/python-sm3-128-24.jsonl").resolve())},
            "CUDA release independent Python input path differs")
    require(record["budget_database_path"]==str(budget_database.resolve()),"CUDA release and matrix persistent budget database differs")
    validate_release_rows(record,release_vectors(ROOT/"reference/evidence/python-sm3-128-24.jsonl"),budget_database)
    require(bool(record["budget_status"]) and all(r["count_reconciled"] is True for r in record["budget_status"]),"CUDA release budget reconciliation failed")
    return record


def bind_build(record):
    hash_map(record["source_sha256"],"CUDA exact build source")
    require(digest(record["library"])==record["library_sha256"],"CUDA exact build library changed")
    for compiler in record["compilers"].values():
        require(digest(compiler["path"])==compiler["sha256"],"CUDA exact build compiler changed")
    hash_map(record["dependencies"]["sha256"],"CUDA exact build runtime")
    bench_cuda.checked_build(record,record["library"])


def publish_freeze(out,freeze,snapshot,compatibility):
    """Complete package first, recheck all original inputs, publish canonical last."""
    require(freeze.get("formal_performance_started") is False and type(freeze.get("real_timing_samples")) is int and
            freeze["real_timing_samples"]==0,"CUDA freeze lifecycle contains formal timing")
    candidate=out/"freeze.candidate.json"
    bench_cpu.atomic_json(candidate,freeze)
    encoded=candidate.read_bytes(); candidate_hash=hashlib.sha256(encoded).hexdigest()
    permit=compatibility(candidate)
    require(permit.get("content_gate_passed") is True and permit.get("formal_gate_passed") is False and
            permit.get("real_timing_samples")==0,"CUDA candidate content gate failed or granted formal timing")
    result={name:bench_cpu.file_sha(out/name) for name in ("source.tar.gz","source-manifest.json","REVIEW.md")}
    result["freeze.json"]=candidate_hash
    package=dict(schema="a15-cuda-freeze-package-v1",passed=True,files_sha256=result,
                 formal_performance_started=False,real_timing_samples=0)
    bench_cpu.atomic_json(out/"package.json",package)
    package_hash=bench_cpu.file_sha(out/"package.json")
    for name,expected in result.items():
        path=candidate if name=="freeze.json" else out/name
        require(bench_cpu.file_sha(path)==expected,"CUDA package artifact changed before publication: "+name)
    require(bench_cpu.file_sha(out/"package.json")==package_hash,"CUDA package manifest changed before publication")
    snapshot.verify()
    require(not (out/"freeze.json").exists(),"CUDA canonical freeze already published")
    candidate.replace(out/"freeze.json")
    return result


def self_test(output=None):
    """Pure fixtures exercise acceptance failures with native calls/clocks blocked."""
    import copy
    import tempfile
    import unittest
    from unittest.mock import patch

    class Checks(unittest.TestCase):
        def fixture(self):
            temporary=tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
            out=Path(temporary.name); snapshot=InputSnapshot()
            replacement=patch.dict(globals(),INPUTS=snapshot); replacement.start(); self.addCleanup(replacement.stop)
            vectors=[]
            for i in range(3):
                vector=dict(case_id="python-3-"+str(i),pid=3,pk=bytes([i+1]*32).hex(),sig=bytes([i+5]*32).hex(),
                            message=bytes([i]).hex(),mp=bytes([0,1,2,i]).hex(),context="0203",sk_seed=bytes([i]*16).hex(),
                            opt_rand=bytes([i+8]*16).hex(),randomization="explicit" if i==1 else "deterministic")
                vector["record_sha256"]=check_cuda.sha(check_cuda.canonical(vector)); vectors.append(vector)
            rows=[]
            def add(case_id,checks,**details):
                row=dict(case_id=case_id,checks=checks,passed=True,gpu_stats=None,**details)
                row["record_sha256"]=check_cuda.sha(bench_cpu.canonical(row).encode()); rows.append(row); return row
            stats=dict(kernel_launches=1,h2d_bytes=0,d2h_bytes=64,device_hashes=100,kernel_ns=0,timing_enabled=0)
            for vector in vectors:
                decode=lambda name:bytes.fromhex(vector[name]); prefix=vector["case_id"]; saved=vector["record_sha256"]
                add(prefix+"/keygen",dict(actual_backend=True,pk_equals_Python=True,sk_equals_Python=True),
                    actual_selected_backend=5,input_reference_record_sha256=saved,public_key_sha256=check_cuda.sha(decode("pk")))
                row=add(prefix+"/sign",{k:True for k in ("signature_equals_Python","verify_internal","pure_verify",
                        "changed_message_rejected","REF_verify","events_disabled","actual_GPU_work")},
                        actual_selected_backend=5,budget_status="committed",budget_receipt=prefix,
                        input_reference_record_sha256=saved,signature_sha256=check_cuda.sha(decode("sig")),
                        input=expected_signature_input(3,"sign_internal",decode("mp"),decode("context"),decode("pk"),
                              raw_message=decode("message"),randomization=vector["randomization"],
                              opt_rand=decode("opt_rand") if vector["randomization"]=="explicit" else None))
                row["gpu_stats"]=dict(stats); self.rehash(row)
                add(prefix+"/release-counts",dict(counters_disabled=True),input_reference_record_sha256=saved)
            pk=bytes(range(32,48))+bytes(range(16))
            for hash_alg in range(1,6):
                row=add("toy/prehash-"+str(hash_alg),{k:True for k in ("CUDA_verify","REF_verify","wrong_context_rejected",
                                  "events_disabled","actual_GPU_work")},actual_selected_backend=5,budget_status="committed",
                        budget_receipt="prehash"+str(hash_alg),signature_sha256=check_cuda.sha(bytes([hash_alg+20])),
                        input=expected_signature_input(201,"sign_prehash",b"\0CUDA release prehash\xff",b"CUDA",pk,hash_alg=hash_alg))
                row["gpu_stats"]=dict(stats); self.rehash(row)
            record=dict(rows=rows,prehash_public_key_hex=pk.hex(),prehash_seed_sha256=check_cuda.sha(bytes(range(48))))
            database=out/"budget.sqlite"
            with sqlite3.connect(database) as db:
                db.execute("CREATE TABLE keys(key_id TEXT,algorithm TEXT,public_key BLOB)")
                db.execute("CREATE TABLE reservations(receipt TEXT,key_id TEXT,status TEXT,message_sha256 TEXT,signature_sha256 TEXT)")
                for row in rows:
                    if row.get("budget_receipt"):
                        key=row["budget_receipt"]; fingerprint=row["input"]
                        db.execute("INSERT INTO keys VALUES(?,?,?)",(key,fingerprint["budget_algorithm"],bytes.fromhex(fingerprint["public_key_hex"])))
                        db.execute("INSERT INTO reservations VALUES(?,?,?,?,?)",(key,key,"committed",fingerprint["budget_message_sha256"],row["signature_sha256"]))
            return out,snapshot,vectors,record,database

        def rehash(self,row):
            row.pop("record_sha256",None); row["record_sha256"]=check_cuda.sha(bench_cpu.canonical(row).encode())

        def signature(self,record): return next(row for row in record["rows"] if row["case_id"].endswith("/sign"))

        def test_valid_exact14_eight_receipts_without_h2d(self):
            _,snapshot,vectors,record,database=self.fixture()
            validate_release_rows(record,vectors,database); snapshot.verify()

        def current_ledger_fixture(self):
            from signing_budget import SigningBudget
            out,snapshot,vectors,record,_=self.fixture()
            database=out/"current-budget.sqlite"; ledger=SigningBudget(database)
            by_id={v["case_id"]:v for v in vectors}
            for row in record["rows"]:
                if not row.get("budget_receipt"): continue
                fingerprint=row["input"]; public=bytes.fromhex(fingerprint["public_key_hex"])
                if row["case_id"].endswith("/sign"):
                    vector=by_id[row["case_id"].removesuffix("/sign")]
                    message=bytes.fromhex(vector["mp"]); signature=bytes.fromhex(vector["sig"])
                else:
                    message=b"\0CUDA release prehash\xff"
                    signature=bytes([fingerprint["hash_alg"]+20])
                receipt=ledger.reserve(fingerprint["budget_algorithm"],public,message)
                ledger.finish(receipt,signature); row["budget_receipt"]=receipt; self.rehash(row)
            return snapshot,vectors,record,database,ledger

        def test_actual_current_ledger_exact14_lowercase_algorithms(self):
            snapshot,vectors,record,database,ledger=self.current_ledger_fixture()
            status=ledger.status()
            self.assertEqual(sum(r["used"] for r in status),8)
            self.assertTrue(all(r["algorithm"]==r["algorithm"].lower() and r["count_reconciled"] for r in status))
            validate_release_rows(record,vectors,database); snapshot.verify()

        def test_actual_current_ledger_matrix_committed_and_failed(self):
            from signing_budget import SigningBudget
            out,snapshot,_,_,_=self.fixture(); database=out/"matrix-budget.sqlite"
            ledger=SigningBudget(database); public=b"p"*32; message=b"matrix input"; signature=b"matrix signature"
            committed=ledger.reserve(check_optimization.ALGORITHMS[3],public,message)
            ledger.finish(committed,signature)
            failed=ledger.reserve(check_optimization.ALGORITHMS[3].lower(),public,message); ledger.finish(failed)
            vectors={3:dict(mp_bytes=message,pk_bytes=public)}
            rows=[dict(case=dict(pid=3),budget_receipt=committed,budget_status="committed",
                       result=dict(signature_sha256=check_cuda.sha(signature))),
                  dict(case=dict(pid=3),budget_receipt=failed,budget_status="failed",result={})]
            verify_budget_receipts(database,rows,vectors); snapshot.verify()
            self.assertEqual(ledger.status()[0]["used"],2)

        def test_algorithm_normalization_retains_allowlist(self):
            self.assertTrue(same_budget_algorithm("slh-dsa-sm3-128-24","SLH-DSA-SM3-128-24"))
            self.assertTrue(same_budget_algorithm("SLH-DSA-SM3-128-24","slh-dsa-sm3-128-24"))
            self.assertFalse(same_budget_algorithm("slh-dsa-sm3-128s","SLH-DSA-SM3-128-24"))
            self.assertFalse(same_budget_algorithm("unknown","UNKNOWN"))
            self.assertFalse(same_budget_algorithm(None,"SLH-DSA-SM3-128-24"))

        def test_actual_current_ledger_wrong_algorithm_rejected(self):
            _,vectors,record,database,_=self.current_ledger_fixture()
            for algorithm in ("slh-dsa-sm3-128s","unknown"):
                with self.subTest(algorithm=algorithm):
                    with sqlite3.connect(database) as db:
                        with self.assertRaises(sqlite3.DatabaseError):
                            db.execute("UPDATE keys SET algorithm=?",(algorithm,))
                        # Deliberately bypass the write guards only in this
                        # corruption fixture, then restore their exact schema.
                        triggers=db.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name='keys'").fetchall()
                        for name,_ in triggers: db.execute('DROP TRIGGER "'+name.replace('"','""')+'"')
                        db.execute("UPDATE keys SET algorithm=?",(algorithm,))
                        for _,sql in triggers: db.execute(sql)
                    with patch.dict(globals(),INPUTS=InputSnapshot()):
                        with self.assertRaisesRegex(ValueError,"persistent receipt"):
                            validate_release_rows(record,vectors,database)

        def test_preserved_budget_survives_future_live_reservations(self):
            out,snapshot,vectors,record,database=self.fixture()
            validate_release_rows(record,vectors,database)
            evidence=dict(snapshot.sha256)
            archived=preserve_budget_evidence(out,evidence)
            self.assertEqual(len(archived),1)
            clone=Path(archived[0]["snapshot_database"])
            self.assertNotIn(str(database.resolve()),evidence)
            self.assertEqual(evidence[str(clone.resolve())],bench_cpu.file_sha(clone))
            snapshot.verify()
            # A later campaign extends the shared live budget, while accepted
            # evidence continues to describe the original eight receipts.
            with sqlite3.connect(database) as db:
                db.execute("INSERT INTO reservations VALUES(?,?,?,?,?)",("future","future","committed","future","future"))
            with sqlite3.connect("file:"+clone.as_posix()+"?mode=ro",uri=True) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM reservations").fetchone()[0],8)
            self.assertEqual(evidence[str(clone.resolve())],bench_cpu.file_sha(clone))

        def test_missing_case(self):
            _,_,vectors,record,database=self.fixture(); record["rows"].pop()
            with self.assertRaisesRegex(ValueError,"exact14"): validate_release_rows(record,vectors,database)

        def test_duplicate_case(self):
            _,_,vectors,record,database=self.fixture(); record["rows"][-1]=copy.deepcopy(record["rows"][-2])
            with self.assertRaisesRegex(ValueError,"exact14"): validate_release_rows(record,vectors,database)

        def test_renamed_case(self):
            _,_,vectors,record,database=self.fixture(); record["rows"][-1]["case_id"]="toy/prehash-6"
            with self.assertRaisesRegex(ValueError,"exact14"): validate_release_rows(record,vectors,database)

        def test_missing_stats(self):
            _,_,vectors,record,database=self.fixture(); row=self.signature(record); row["gpu_stats"]=None; self.rehash(row)
            with self.assertRaisesRegex(ValueError,"six-field"): validate_release_rows(record,vectors,database)

        def test_missing_stats_field(self):
            _,_,vectors,record,database=self.fixture(); row=self.signature(record); row["gpu_stats"].pop("h2d_bytes"); self.rehash(row)
            with self.assertRaisesRegex(ValueError,"six-field"): validate_release_rows(record,vectors,database)

        def test_noninteger_stats(self):
            for value in (True,-1,"1"):
                with self.subTest(value=value):
                    _,_,vectors,record,database=self.fixture(); row=self.signature(record); row["gpu_stats"]["d2h_bytes"]=value; self.rehash(row)
                    with self.assertRaisesRegex(ValueError,"six-field"): validate_release_rows(record,vectors,database)

        def test_gpu_timing(self):
            _,_,vectors,record,database=self.fixture(); row=self.signature(record); row["gpu_stats"]["kernel_ns"]=1; self.rehash(row)
            with self.assertRaisesRegex(ValueError,"GPU timing"): validate_release_rows(record,vectors,database)

        def test_no_device_work(self):
            _,_,vectors,record,database=self.fixture(); row=self.signature(record); row["gpu_stats"]["device_hashes"]=0; self.rehash(row)
            with self.assertRaisesRegex(ValueError,"no device work"): validate_release_rows(record,vectors,database)

        def test_wrong_api_context_randomizer_pk(self):
            for field in ("api_input_sha256","context_sha256","opt_rand_sha256","public_key_sha256"):
                with self.subTest(field=field):
                    _,_,vectors,record,database=self.fixture(); row=self.signature(record); row["input"][field]="0"*64; self.rehash(row)
                    with self.assertRaisesRegex(ValueError,"input/public key/signature"): validate_release_rows(record,vectors,database)

        def test_wrong_fixture_signature(self):
            _,_,vectors,record,database=self.fixture(); row=self.signature(record); row["signature_sha256"]="0"*64; self.rehash(row)
            with self.assertRaisesRegex(ValueError,"input/public key/signature"): validate_release_rows(record,vectors,database)

        def test_duplicate_receipt(self):
            _,_,vectors,record,database=self.fixture(); signs=[r for r in record["rows"] if r.get("budget_receipt")]
            signs[-1]["budget_receipt"]=signs[0]["budget_receipt"]; self.rehash(signs[-1])
            with self.assertRaisesRegex(ValueError,"receipt missing/duplicated"): validate_release_rows(record,vectors,database)

        def test_sql_wrong_message_pk_signature_status(self):
            for table,field,value in (("reservations","message_sha256","wrong"),("reservations","signature_sha256","wrong"),
                                    ("reservations","status","pending"),("keys","public_key",b"wrong"),("keys","algorithm","wrong")):
                with self.subTest(field=field):
                    _,_,vectors,record,database=self.fixture()
                    with sqlite3.connect(database) as db: db.execute("UPDATE "+table+" SET "+field+"=?",(value,))
                    with self.assertRaisesRegex(ValueError,"persistent receipt"): validate_release_rows(record,vectors,database)

        def test_sql_missing_receipt(self):
            _,_,vectors,record,database=self.fixture()
            with sqlite3.connect(database) as db: db.execute("DELETE FROM reservations")
            with self.assertRaisesRegex(ValueError,"persistent receipt"): validate_release_rows(record,vectors,database)

        def test_sql_wal_bytes_are_preserved(self):
            _,snapshot,vectors,record,database=self.fixture()
            writer=sqlite3.connect(database)
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute("UPDATE reservations SET status='committed'"); writer.commit()
                self.assertTrue(Path(str(database)+"-wal").is_file())
                validate_release_rows(record,vectors,database)
                self.assertIn(str(database.resolve())+"-wal",snapshot.sha256)
                snapshot.verify()
            finally: writer.close()

        def test_same_bytes_json_jsonl_and_final_mutation(self):
            out,snapshot,_,_,_=self.fixture(); path=out/"evidence.jsonl"; initial=b'{"passed":true}\n'
            path.write_bytes(initial); self.assertEqual(snapshot.read_json(path),{"passed":True})
            self.assertEqual(snapshot.lines(path),['{"passed":true}']); self.assertEqual(snapshot.digest(path),check_cuda.sha(initial))
            path.write_bytes(b'{"passed":false}\n')
            with self.assertRaisesRegex(ValueError,"first snapshot"): snapshot.lines(path)
            with self.assertRaisesRegex(ValueError,"validation/packaging"): snapshot.verify()

        def test_historical_archive_member_and_alteration(self):
            out,snapshot,_,_,_=self.fixture(); path=out/"source.tar.gz"
            with tarfile.open(path,"w:gz") as archive:
                member=tarfile.TarInfo("c/source.c"); member.size=6; archive.addfile(member,io.BytesIO(b"source"))
            archived_sources(path,{"c/source.c":check_cuda.sha(b"source")},"historical")
            with self.assertRaisesRegex(ValueError,"member digest"): archived_sources(path,{"c/source.c":"0"*64},"historical")
            path.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError,"first snapshot"): snapshot.archive(path)

        def test_historical_archive_duplicate_member(self):
            out,_,_,_,_=self.fixture(); path=out/"source.tar.gz"
            with tarfile.open(path,"w:gz") as archive:
                for _ in range(2):
                    member=tarfile.TarInfo("c/source.c"); member.size=6; archive.addfile(member,io.BytesIO(b"source"))
            with self.assertRaisesRegex(ValueError,"missing/duplicate"): archived_sources(path,{"c/source.c":check_cuda.sha(b"source")},"historical")

        def test_historical_library_final_mutation(self):
            out,snapshot,_,_,_=self.fixture(); path=out/"old.so"; path.write_bytes(b"old accepted library"); digest(path)
            path.write_bytes(b"changed library")
            with self.assertRaisesRegex(ValueError,"validation/packaging"): snapshot.verify()

        def package_fixture(self):
            out,snapshot,_,_,_=self.fixture()
            for name in ("source.tar.gz","source-manifest.json","REVIEW.md"): (out/name).write_bytes(name.encode())
            freeze=dict(schema="a15-cuda-freeze-v1",source_sha256={},final=True,correctness_passed=True,
                        formal_performance_started=False,real_timing_samples=0)
            return out,snapshot,freeze

        def content(self,candidate):
            self.assertFalse((candidate.parent/"freeze.json").exists())
            return dict(content_gate_passed=True,formal_gate_passed=False,real_timing_samples=0)

        def test_publish_canonical_last(self):
            out,snapshot,freeze=self.package_fixture(); original=Path.replace
            def inspected(path,target):
                self.assertEqual(path.name,"freeze.candidate.json")
                self.assertTrue(all((out/name).is_file() for name in ("package.json","source.tar.gz","source-manifest.json","REVIEW.md")))
                self.assertFalse((out/"freeze.json").exists())
                return original(path,target)
            with patch.object(Path,"replace",inspected): hashes=publish_freeze(out,freeze,snapshot,self.content)
            self.assertEqual(bench_cpu.file_sha(out/"freeze.json"),hashes["freeze.json"])
            self.assertFalse((out/"freeze.candidate.json").exists())

        def test_candidate_never_formal_gate(self):
            out,_,freeze=self.package_fixture(); candidate=out/"freeze.candidate.json"; bench_cpu.atomic_json(candidate,freeze)
            with self.assertRaisesRegex(ValueError,"canonical"): bench_cuda.validate_freeze(SimpleNamespace(freeze=candidate))

        def test_missing_package_never_formal_gate(self):
            out,_,freeze=self.package_fixture(); canonical=out/"freeze.json"; bench_cpu.atomic_json(canonical,freeze)
            with self.assertRaisesRegex(ValueError,"package"): bench_cuda.validate_freeze(SimpleNamespace(freeze=canonical))

        def test_package_write_failure_no_canonical(self):
            out,snapshot,freeze=self.package_fixture(); original=bench_cpu.atomic_json
            def fail(path,value,*args,**kwargs):
                if Path(path).name=="package.json": raise OSError("fixture package write failure")
                return original(path,value,*args,**kwargs)
            with patch.object(bench_cpu,"atomic_json",fail):
                with self.assertRaises(OSError): publish_freeze(out,freeze,snapshot,self.content)
            self.assertFalse((out/"freeze.json").exists())

        def test_mutation_during_content_gate_no_canonical(self):
            out,snapshot,freeze=self.package_fixture(); source=out/"bound-source"; source.write_bytes(b"original"); snapshot.digest(source)
            def changed(candidate): source.write_bytes(b"changed"); return self.content(candidate)
            with self.assertRaisesRegex(ValueError,"validation/packaging"): publish_freeze(out,freeze,snapshot,changed)
            self.assertFalse((out/"freeze.json").exists())

        def test_candidate_formal_flag_rejected(self):
            out,snapshot,freeze=self.package_fixture()
            with self.assertRaisesRegex(ValueError,"granted formal timing"):
                publish_freeze(out,freeze,snapshot,lambda _:dict(content_gate_passed=True,formal_gate_passed=True,real_timing_samples=0))
            self.assertFalse((out/"freeze.json").exists())

        def test_lifecycle_timing_rejected_before_candidate(self):
            for field,value in (("formal_performance_started",True),("real_timing_samples",1),("real_timing_samples",False)):
                with self.subTest(field=field,value=value):
                    out,snapshot,freeze=self.package_fixture(); freeze[field]=value
                    with self.assertRaisesRegex(ValueError,"lifecycle"):
                        publish_freeze(out,freeze,snapshot,self.content)
                    self.assertFalse((out/"freeze.json").exists()); self.assertFalse((out/"freeze.candidate.json").exists())

    def blocked(*args,**kwargs): raise AssertionError("native process or real clock reached by pure fixture")
    names=unittest.defaultTestLoader.getTestCaseNames(Checks)
    with patch("ctypes.CDLL",side_effect=blocked), patch.object(bench_cuda,"NativeSlhDsa",side_effect=blocked), \
         patch("subprocess.run",side_effect=blocked), patch.object(bench_cpu,"command",side_effect=blocked), \
         patch("time.perf_counter",side_effect=blocked), patch("time.perf_counter_ns",side_effect=blocked):
        for name in names:
            case=Checks(name)
            try: getattr(case,name)()
            finally: case.doCleanups()
    record=dict(schema="a15-cuda-freeze-selftest-v1",passed=True,mock_checks=len(names),native_calls=0,
                real_timing_samples=0,formal_performance_started=False,tool_sha256=bench_cpu.file_sha(Path(__file__)),
                release_tool_sha256=bench_cpu.file_sha(ROOT/"tools/check_cuda_release.py"),
                scope="exact14/eight signatures; six-field stats; persistent SQL; current canonical ledger and matrix receipts; historical archive/library; first-byte binding; canonical publication last")
    if output is not None: bench_cpu.atomic_json(output,record)
    return record


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    names=("cuda-run","native-run","cpu-baseline-run","kernel-record","release-correctness","cli-correctness",
           "build-record","mock-record","plan","output-dir")
    for name in names: parser.add_argument("--"+name,type=Path)
    parser.add_argument("--self-test",action="store_true")
    parser.add_argument("--self-test-output",type=Path)
    args=parser.parse_args()
    if args.self_test:
        print(json.dumps(self_test(args.self_test_output))); return
    for name in names:
        if getattr(args,name.replace("-","_")) is None: parser.error("required: --"+name)
    summary,manifest,evidence,cpu_evidence=validate_matrix(args.cuda_run,expected_kernel=args.kernel_record,cpu_baseline=args.cpu_baseline_run)
    native,steps,raw=validate_native(args.native_run,summary)
    require(args.kernel_record.resolve()==args.native_run.resolve()/"kernel.json","CUDA kernel wrapper must belong to native accepted run")
    kernel=validate_kernel(args.kernel_record,summary,native,steps,raw)
    build=read(args.build_record)
    bind_build(build)
    require(build.get("real_timing_samples")==0 and build.get("compile_output_checked") is True,"CUDA clean build record missing")
    require(build["arch"]=="sm_86","CUDA11.5/RTX4090 preparation requires compute86 PTX build")
    build["_record_path"]=str(args.build_record.resolve())
    release=validate_release(args.release_correctness,build,budget_database=resolved(summary["identity"]["budget_database_path"]))
    cli=read(args.cli_correctness)
    require(cli.get("schema")=="a15-native-rng-v1" and cli.get("passed") is True
            and cli.get("backend_requested")=="cuda" and cli.get("library_sha256")==build["library_sha256"]
            and cli.get("formal_performance_started") is False and cli.get("duration_measured") is False
            and len(cli["results"])==6 and all(r["passed"] for r in cli["results"]),
            "CUDA file CLI/RNG acceptance incomplete")
    require(all(r["result"].get("backend_selected")==5 for r in cli["results"] if "result" in r),
            "CUDA file CLI selected another backend")
    hash_map(cli["sources_sha256"],"CUDA CLI source")
    mock=read(args.mock_record)
    require(mock.get("schema")=="a15-cuda-selftest-v1" and mock.get("passed") is True and mock.get("native_calls")==0 and
            mock.get("real_timing_samples")==0 and mock["source_sha256"]==bench_cpu.hashes(bench_cuda.TOOL_FILES),"CUDA mock evidence differs")
    plan=read(args.plan); bench_cuda.check_plan(plan)
    expected=bench_cuda.make_plan()
    require(len(plan["cases"])==64 and plan["cases"]==expected["cases"] and plan["scopes"]==expected["scopes"] and
            plan["hybrid_boundary"]==expected["hybrid_boundary"],"normative64-case CUDA plan required")
    device=build["release_probe"]["device"]
    # Device equality with the matrix is extracted from its preserved device row.
    matrix_devices=[]
    for line in INPUTS.lines(args.cuda_run/"cases.jsonl"):
        row=json.loads(line)
        if row["case"]["operation"]=="device" and row["passed"]: matrix_devices.append(row["result"]["cuda_info"])
    require(bool(matrix_devices) and all(d==device for d in matrix_devices),"CUDA exact release and counter matrix selected different devices")
    out=args.output_dir.resolve(); out.mkdir(parents=True,exist_ok=False)
    current=bench_cpu.hashes(bench_cuda.BUILD_FILES+bench_cuda.TOOL_FILES)
    evidence.update(cpu_evidence)
    evidence.update({str(resolved(name)):h for name,h in native["evidence_sha256"].items()})
    for path in (args.native_run/"manifest.json",args.kernel_record,args.release_correctness,args.cli_correctness,args.build_record,args.mock_record,args.plan):
        evidence[str(path.resolve())]=digest(path)
    evidence.update(INPUTS.sha256)
    budget_snapshots=preserve_budget_evidence(out,evidence)
    package_sources=dict(summary["source_hashes"]); package_sources.update(current)
    package_sources.update(native["source_hashes"])
    package_sources.update(cli["sources_sha256"])
    for name in ("tools/freeze_cuda.py","tools/check_cuda_release.py","docs/CUDA_VALIDATION.md"):
        package_sources[name]=digest(ROOT/name)
    archive=out/"source.tar.gz"
    with tarfile.open(archive,"x:gz") as bundle:
        for name in sorted(package_sources): bundle.add(ROOT/name,arcname=name)
    with tarfile.open(archive) as bundle:
        for name,expected_hash in package_sources.items():
            require(hashlib.sha256(bundle.extractfile(name).read()).hexdigest()==expected_hash,"CUDA source archive member changed: "+name)
    hash_map(package_sources,"CUDA source package")
    hash_map(evidence,"CUDA frozen evidence")
    bind_build(build)
    freeze=dict(schema="a15-cuda-freeze-v1",final=True,correctness_passed=True,
                created_utc=datetime.now(timezone.utc).isoformat(),formal_performance_started=False,real_timing_samples=0,
                source_sha256=current,library_sha256=build["library_sha256"],build_record_sha256=digest(args.build_record),
                device_identity=device,plans={plan["suite"]:dict(path=str(args.plan.resolve()),sha256=digest(args.plan),cases=64)},
                evidence={"correctness":dict(path=str(args.release_correctness.resolve()),sha256=digest(args.release_correctness)),
                          "mock":dict(path=str(args.mock_record.resolve()),sha256=digest(args.mock_record))},
                correctness_evidence_sha256=evidence,budget_snapshots=budget_snapshots,counter_matrix_cases=summary["planned_cases"],
                classification="CUDA B1 correctness accepted; exact release and normative plans prepared; performance samples=0")
    bench_cpu.atomic_json(out/"source-manifest.json",package_sources)
    text=("# CUDA B1 验收完成，停于性能测试准备\n\n"
          f"CUDA 矩阵 {summary['passed_planned']}/{summary['planned_cases']}，{summary['records']} 条追加记录通过。\n\n"
          "GPU FORS PRF/F/H 子树、认证路径与偏移有直接 GPU kernel 证据；WOTS/消息/缓存/上层继续走 CPU。\n\n"
          "pid3 全部 t0..22 载入、根绑定、完整签名与既有 REF 证据及七逻辑计数一致；"
          "测试构建故障0..5、独立原始 SM3 和精确无计数器 release 校验通过。\n\n"
          "compute86 PTX 的独立 release、GPU 身份、mock 和规范64项计划已准备。正式性能样本数为0。\n")
    (out/"REVIEW.md").write_text(text,encoding="utf8")
    hash_map(package_sources,"CUDA final source package")
    hash_map(evidence,"CUDA final evidence")
    bind_build(build)
    publish_freeze(out,freeze,INPUTS,lambda candidate:bench_cuda.validate_freeze_content(
        SimpleNamespace(build_record=args.build_record,library=Path(build["library"]),plan=args.plan,freeze=candidate),device=device))
    permit=bench_cuda.validate_freeze(SimpleNamespace(build_record=args.build_record,library=Path(build["library"]),
                                    plan=args.plan,freeze=out/"freeze.json"),device=device)
    require(permit["formal_gate_passed"] and permit["real_timing_samples"]==0,"CUDA published formal gate failed")
    print(json.dumps(dict(passed=True,output=str(out),matrix_cases=summary["planned_cases"],formal_performance_started=False)))


if __name__=="__main__": main()
