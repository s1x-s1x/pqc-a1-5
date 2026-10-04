#!/usr/bin/env python3
"""CUDA B1 preparation: checked build, plans, untimed probe and mock timing API.

Native correctness checks use stats_reset(0); only an explicit frozen run/worker
enables device events. One sample yields separate kernel and end-to-end scopes.
"""
from __future__ import annotations

import argparse
import ctypes as ct
import csv
import io
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import bench_cpu as cpu
from native import NativeSlhDsa
from signing_budget import SigningBudget

CUDA_FILES = ["c/src/sm3_cuda.h", "c/src/sm3_cuda.cu", "c/src/sm3_cuda_device.cuh"]
BUILD_FILES = list(dict.fromkeys([p for p in cpu.BUILD_FILES if p != "c/src/sm3_cuda_stub.c"] + CUDA_FILES))
TOOL_FILES = list(dict.fromkeys(["tools/bench_cuda.py"] + cpu.TOOL_FILES))
FORS_HEIGHT = {1: 12, 2: 6, 3: 24}
SCOPES = {
    "end_to_end_ns": "perf_counter_ns around one preallocated synchronous ABI call; includes libffi, CPU B1 work, device allocations, copies and synchronization; excludes reset/read events, Python setup, budget and validation",
    "kernel_ns": "sum of CUDA event intervals for device kernels only; excludes explicit copies, allocation, ABI and CPU work; event creation/record/synchronization overhead is included in end-to-end time",
    "transfer_bytes": "explicit cudaMemcpy payload bytes only; excludes kernel parameters, CUDA runtime metadata and memory initialization/wiping",
}
SCHEMA = "a15-cuda-bench-v1"


class CudaInfo(ct.Structure):
    _fields_ = [(p, ct.c_int) for p in ("device", "runtime_version", "driver_version", "compute_major", "compute_minor")] + [
        ("total_memory", ct.c_uint64), ("name", ct.c_char * 96)]


class CudaStats(ct.Structure):
    _fields_ = [(p, ct.c_uint64) for p in ("kernel_launches", "h2d_bytes", "d2h_bytes", "device_hashes", "kernel_ns", "timing_enabled")]


class Statistics:
    """Caller serializes reset, operation and read in one independent worker."""
    def __init__(self, lib):
        self.lib = lib
        for name, args in {"slh_cuda_get_info": [ct.POINTER(CudaInfo)],
                           "slh_cuda_stats_reset": [ct.c_int],
                           "slh_cuda_stats_get": [ct.POINTER(CudaStats)]}.items():
            function = getattr(lib, name)
            function.argtypes, function.restype = args, ct.c_int

    @staticmethod
    def check(code):
        if code != 0:
            raise ValueError("CUDA statistics/device ABI returned " + str(code))

    def info(self):
        result = CudaInfo()
        self.check(self.lib.slh_cuda_get_info(ct.byref(result)))
        value = {k: getattr(result, k) for k, _ in result._fields_ if k != "name"}
        value["name"] = bytes(result.name).decode("utf8", errors="replace")
        return value

    def reset(self, enabled=False):
        self.check(self.lib.slh_cuda_stats_reset(int(enabled)))

    def get(self):
        result = CudaStats()
        self.check(self.lib.slh_cuda_stats_get(ct.byref(result)))
        return {k: getattr(result, k) for k, _ in result._fields_}


def sample_once(operation, statistics, *, permit, clock=None):
    """Future worker primitive; operation owns preallocated inputs/outputs.

    Budget reservation, input hashes and context setup precede this function;
    independent REF validation and receipt finalization follow it. The permit
    comes from validate_freeze and is rechecked against hashes by that worker.
    """
    if not isinstance(permit, dict) or permit.get("formal_gate_passed") is not True:
        raise ValueError("CUDA timing requires a checked formal freeze permit")
    if clock is None:
        clock = time.perf_counter_ns
    statistics.reset(True)
    try:
        start = clock()
        result = operation()
        end = clock()
        if isinstance(result, int) and result != 0:
            raise ValueError("CUDA operation returned " + str(result))
        stats = statistics.get()
        if (stats.get("timing_enabled") != 1 or stats.get("kernel_launches", 0) < 1
                or stats.get("device_hashes", 0) < 1 or stats.get("kernel_ns", 0) < 1
                or end <= start or stats["kernel_ns"] > end - start):
            raise ValueError("CUDA sample lacks valid timed device work")
        sample = {"backend": 5, "backend_name": "CUDA B1 hybrid", "end_to_end_ns": end-start,
                  "kernel_ns": stats["kernel_ns"], "cuda_stats": stats,
                  "scopes": SCOPES, "core_cycles": None}
    except BaseException as original:
        try:
            statistics.reset(False)
        except Exception as reset_error:
            original.add_note("secondary CUDA event-disable failure: " + str(reset_error))
        raise
    else:
        statistics.reset(False)
        return sample


def make_plan(pids=(1, 2, 3), threads=(1, 2, 4, 8, 16, 32, 64)):
    if (not pids or not threads or len(set(pids)) != len(pids) or len(set(threads)) != len(threads)
            or any(p not in FORS_HEIGHT for p in pids) or any(not 1 <= t <= 64 for t in threads)):
        raise ValueError("CUDA plan requires unique SM3 pid1/2/3 and physical threads1..64")
    cases = []
    for pid in pids:
        for threads_count in threads:
            for cache in ("none", "12"):
                case = cpu.case_record(pid, "sign", cache=cache, threads=threads_count, family="CUDA-B1")
                case.update(backend="CUDA", backend_id=5,
                            case_id=f"CUDA-B1-p{pid}-sign-c{cache}-p{threads_count}")
                cases.append(case)
        for height in sorted({0, min(3, FORS_HEIGHT[pid]), min(6, FORS_HEIGHT[pid]), FORS_HEIGHT[pid]}):
            for auth in (False, True):
                cases.append({"pid": pid, "op": "fors_subtree", "backend": "CUDA", "backend_id": 5,
                    "threads": 1, "cache": "none", "cache_t": None, "height": height,
                    "leaf_start": 0, "target": (1 << height)-1 if auth else 4294967295,
                    "samples": 5, "warmups": 1,
                    "case_id": f"CUDA-B1-p{pid}-fors-z{height}-" + ("auth" if auth else "root")})
    return {"schema": "a15-cuda-plan-v1", "created_utc": cpu.utc(), "suite": "cuda_b1",
        "cases": cases, "diagnostic": False, "case_order": "independent sequential workers; serialize process-wide CUDA statistics",
        "scopes": SCOPES, "cpu_baselines": ["REF", "AVX2"],
        "comparison_policy": "identical pid/input/threads/cache/operation; compare CUDA end_to_end_ns to CPU ABI time; kernel_ns is a separate device-only metric",
        "hybrid_boundary": "GPU FORS leaves and reductions; CPU WOTS/message/cache/upper XMSS. keygen/cache/verify have no B1 GPU acceleration claim",
        "requires_before_formal_run": ["final CUDA freeze", "independent correctness", "Linux physical-core affinity", "recorded GPU identity and environment"]}


def check_plan(plan):
    if plan.get("schema") != "a15-cuda-plan-v1" or plan.get("suite") != "cuda_b1" or plan.get("diagnostic") is not False:
        raise ValueError("unexpected or diagnostic CUDA plan")
    cases = plan.get("cases", [])
    if not cases or len({c["case_id"] for c in cases}) != len(cases):
        raise ValueError("CUDA cases must be nonempty and unique")
    for case in cases:
        if case.get("pid") not in FORS_HEIGHT or case.get("backend") != "CUDA" or case.get("backend_id") != 5:
            raise ValueError("CUDA plan requires actual backend5 SM3")
        if not 1 <= case.get("threads", 0) <= 64 or case.get("warmups", -1) < 0:
            raise ValueError("invalid CUDA physical threads or warmups")
        if case.get("op") == "sign":
            cpu_case = {**case, "backend": "AVX2"}
            cpu.validate_case(cpu_case)
            if case["samples"] < cpu.minimum_samples(cpu_case):
                raise ValueError("insufficient CUDA sign samples")
        elif case.get("op") == "fors_subtree":
            height = case.get("height", -1)
            start, target = case.get("leaf_start", -1), case.get("target", -1)
            if (not 0 <= height <= FORS_HEIGHT[case["pid"]] or start < 0 or start % (1 << height)
                    or start+(1 << height) > (1 << FORS_HEIGHT[case["pid"]])
                    or target != 4294967295 and not start <= target < start+(1 << height)
                    or case.get("samples", 0) < 5):
                raise ValueError("invalid CUDA FORS subtree")
        else:
            raise ValueError("CUDA B1 performance case must execute FORS device work")


def compiler_info(name):
    executable = shutil.which(name)
    if executable is None:
        raise ValueError("compiler executable missing: " + name)
    executable = str(Path(executable).resolve())
    version = cpu.command([executable, "--version"])
    if version.get("returncode") != 0:
        raise ValueError("compiler version check failed: " + name)
    return {"path": executable, "sha256": cpu.file_sha(executable), "version": version}


def build_commands(output, cc, nvcc, host_cxx, arch):
    if not re.fullmatch(r"sm_[0-9]{2,3}", arch):
        raise ValueError("CUDA architecture must be sm_ followed by compute digits")
    virtual = "compute_" + arch.removeprefix("sm_")
    includes = ["-Ic/include", "-Ic/src", "-Ithird_party/slhdsa-c"]
    commands, objects = [], []
    for index, name in enumerate(p for p in BUILD_FILES if p.endswith(".c")):
        obj = str(output / (f"host-{index}.o"))
        objects.append(obj)
        commands.append([cc, "-std=c11", "-O3", "-Wall", "-Wextra", "-Wno-misleading-indentation", "-fPIC", "-fopenmp", "-DSLH_RELEASE_BUILD", *includes, "-c", name, "-o", obj])
    device = str(output / "sm3_cuda.o")
    commands.append([nvcc, "-std=c++14", "-O3", "--compiler-bindir", host_cxx,
        "-gencode", f"arch={virtual},code=[{arch},{virtual}]", "-Xcompiler=-fPIC,-fvisibility=hidden,-pthread", "-DSLH_RELEASE_BUILD",
        *includes, "-c", "c/src/sm3_cuda.cu", "-o", device])
    commands.append([nvcc, "--compiler-bindir", host_cxx, "-shared", "-Xcompiler=-fopenmp,-pthread",
        *objects, device, "-o", str(output / "libslhdsa_sm3.so")])
    return commands


def dependencies(library):
    result = cpu.command(["ldd", str(library)])
    if result.get("returncode") != 0 or "not found" in result.get("stdout", ""):
        raise ValueError("CUDA library dependencies are unresolved")
    paths = set()
    for line in result["stdout"].splitlines():
        match = re.search(r"(?:=>\s*)?(/\S+)\s+\(", line)
        if match:
            path = Path(match[1]).resolve()
            if not path.is_file():
                raise ValueError("ldd dependency is missing")
            paths.add(str(path))
    if not paths:
        raise ValueError("CUDA ldd output lacks resolved dependencies")
    return {"result": result, "sha256": {p: cpu.file_sha(p) for p in sorted(paths)}}


def untimed_probe(library):
    release = cpu.verify_library_runtime(library)
    with NativeSlhDsa(201, 1, 5, library) as gpu, NativeSlhDsa(201, 1, 1, library) as ref:
        if gpu.backend != 5:
            raise ValueError("CUDA request did not select backend5")
        gpu.bind_key(bytes(64)); ref.bind_key(bytes(64))
        statistics = Statistics(gpu.lib)
        statistics.reset(False)
        root = gpu.subtree("fors", bytes(32), 0, 0)
        expected = ref.subtree("fors", bytes(32), 0, 0)
        stats = statistics.get()
        if root != expected or stats["timing_enabled"] != 0 or stats["kernel_ns"] != 0 or stats["kernel_launches"] < 1:
            raise ValueError("untimed CUDA release correctness/stats probe failed")
        info = statistics.info()
        statistics.reset(False)
    return {"passed": True, "native_calls": 3, "native_calls_scope": "constant-work subtree invocations (one release counter probe plus CUDA/REF comparison); excludes context/info/stats ABI calls",
        "real_timing_samples": 0, "counter_probe": release, "device": info, "untimed_stats": stats,
        "gpu_fors_matches_ref": True, "kernel_timing_enabled": False}


def build(args):
    if sys.platform != "linux":
        raise ValueError("checked CUDA benchmark build requires Linux CUDA toolchain")
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=False)
    compilers = {k: compiler_info(getattr(args, k)) for k in ("cc", "nvcc", "host_cxx")}
    commands = build_commands(output, *(compilers[k]["path"] for k in ("cc", "nvcc", "host_cxx")), args.arch)
    before = cpu.hashes(BUILD_FILES)
    build_env = {k: v for k, v in os.environ.items() if k not in {"CC", "CXX", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "NVCC_PREPEND_FLAGS", "NVCC_APPEND_FLAGS", "LD_PRELOAD"}}
    results = []
    for argv in commands:
        result = cpu.command(argv, timeout=600, env=build_env)
        results.append(result)
        if result.get("returncode") != 0:
            cpu.atomic_json(output / "build-failure.json", {"source_sha256": before, "commands": results})
            raise ValueError("CUDA checked build command failed")
    after = cpu.hashes(BUILD_FILES)
    if before != after:
        raise ValueError("CUDA build sources changed during compilation")
    library = output / "libslhdsa_sm3.so"
    # Only correctness calls: events are explicitly disabled throughout.
    probe = untimed_probe(library)
    record = {"schema": "a15-cuda-build-v1", "created_utc": cpu.utc(), "final": False,
        "source_sha256": after, "library": str(library), "library_sha256": cpu.file_sha(library),
        "compilers": compilers, "arch": args.arch, "build_output": str(output), "compile_commands": commands,
        "results": results, "compile_output_checked": True, "dependencies": dependencies(library),
        "counters": False, "test_injection": False, "sanitizer": False, "release_probe": probe,
        "passed": True, "native_calls": probe["native_calls"], "real_timing_samples": 0,
        "tool_sha256": cpu.file_sha(__file__)}
    cpu.atomic_json(output / "build-record.json", record)
    print(output / "build-record.json")


def checked_build(record, library, *, check_dependencies=True):
    if record.get("schema") != "a15-cuda-build-v1" or record.get("passed") is not True:
        raise ValueError("missing passed checked CUDA build")
    if record.get("source_sha256") != cpu.hashes(BUILD_FILES) or record.get("library_sha256") != cpu.file_sha(library):
        raise ValueError("CUDA build differs from current source/library")
    if any(record.get(k) is not False for k in ("counters", "test_injection", "sanitizer")):
        raise ValueError("CUDA timing excludes instrumented builds")
    compilers = record["compilers"]
    if any(cpu.file_sha(compilers[k]["path"]) != compilers[k]["sha256"] for k in ("cc", "nvcc", "host_cxx")):
        raise ValueError("CUDA compiler executable changed")
    commands = build_commands(Path(record["build_output"]), *(compilers[k]["path"] for k in ("cc", "nvcc", "host_cxx")), record["arch"])
    if (record.get("compile_output_checked") is not True or record.get("compile_commands") != commands
            or len(record.get("results", [])) != len(commands)
            or any(result.get("argv") != argv or result.get("returncode") != 0 for argv, result in zip(commands, record["results"]))):
        raise ValueError("CUDA actual compile/link commands differ from checked release templates")
    probe = record.get("release_probe", {})
    if (probe.get("passed") is not True or probe.get("real_timing_samples") != 0 or probe.get("gpu_fors_matches_ref") is not True
            or probe.get("kernel_timing_enabled") is not False or not probe.get("device")):
        raise ValueError("CUDA untimed release probe is incomplete")
    if check_dependencies:
        recorded = record.get("dependencies", {}).get("sha256", {})
        if not recorded or any(cpu.file_sha(p) != digest for p, digest in recorded.items()):
            raise ValueError("CUDA runtime dependencies changed")
        if dependencies(library)["sha256"] != recorded:
            raise ValueError("CUDA runtime dependency resolution changed")


def validate_freeze_content(args, *, device=None):
    """Check candidate content only; result never grants a timing permit."""
    record = cpu.read_json(args.build_record)
    checked_build(record, args.library)
    plan = cpu.read_json(args.plan)
    check_plan(plan)
    freeze = cpu.read_json(args.freeze)
    if (freeze.get("schema") != "a15-cuda-freeze-v1" or freeze.get("final") is not True
            or freeze.get("correctness_passed") is not True):
        raise ValueError("CUDA timing requires final independently accepted freeze")
    if (freeze.get("formal_performance_started") is not False
            or type(freeze.get("real_timing_samples")) is not int or freeze["real_timing_samples"] != 0):
        raise ValueError("CUDA freeze lifecycle must explicitly precede formal timing with integer zero samples")
    if (freeze.get("build_record_sha256") != cpu.file_sha(args.build_record)
            or freeze.get("library_sha256") != cpu.file_sha(args.library)
            or freeze.get("source_sha256") != cpu.hashes(BUILD_FILES + TOOL_FILES)):
        raise ValueError("CUDA final freeze build/library/source hash differs")
    entry = freeze.get("plans", {}).get(plan["suite"], {})
    if entry.get("sha256") != cpu.file_sha(args.plan):
        raise ValueError("CUDA runtime plan suite/digest is absent from freeze")
    expected_device = freeze.get("device_identity")
    if not expected_device or expected_device != record["release_probe"]["device"] or device is not None and device != expected_device:
        raise ValueError("CUDA device identity differs from freeze")
    evidence = freeze.get("evidence", {})
    for kind in ("correctness", "mock"):
        item = evidence.get(kind, {})
        if not item.get("path") or item.get("sha256") != cpu.file_sha(item["path"]):
            raise ValueError("CUDA freeze evidence hash differs: " + kind)
        value = cpu.read_json(item["path"])
        if value.get("passed") is not True or value.get("real_timing_samples") != 0:
            raise ValueError("CUDA preparation evidence is incomplete or contains timing")
        if kind == "mock" and (value.get("native_calls") != 0 or value.get("source_sha256") != cpu.hashes(TOOL_FILES)):
            raise ValueError("CUDA mock evidence differs from current tools")
        if kind == "correctness" and (value.get("source_sha256") != record.get("source_sha256")
                or value.get("library_sha256") != record.get("library_sha256")
                or value.get("build_record_sha256") != cpu.file_sha(args.build_record)
                or value.get("device_identity") != expected_device):
            raise ValueError("CUDA correctness evidence differs from accepted source/library/device")
    return {"formal_gate_passed": False, "content_gate_passed": True, "freeze_sha256": cpu.file_sha(args.freeze),
        "build_record_sha256": cpu.file_sha(args.build_record), "plan_sha256": cpu.file_sha(args.plan),
        "device_identity": expected_device, "real_timing_samples": 0,
        "note": "permit validates provenance only; campaign worker must additionally enforce budget, inputs, affinity, environment, resume and independent result verification"}


def validate_freeze(args, *, device=None):
    """No native load/sample. Only final canonical publication grants a permit."""
    freeze = cpu.read_json(args.freeze)
    cpu.validate_published_freeze(args.freeze, freeze)
    result = validate_freeze_content(args, device=device)
    return {**result, "formal_gate_passed": True}


def append(path, value):
    cpu.append(path, {"schema": SCHEMA, **value})


def gpu_environment():
    stable_fields = ["index", "uuid", "pci.bus_id", "name", "driver_version", "compute_mode", "power.limit"]
    dynamic_fields = ["pstate", "temperature.gpu", "utilization.gpu", "clocks.current.graphics", "clocks.current.memory", "power.draw"]
    def query(fields):
        result = cpu.command(["nvidia-smi", "--query-gpu="+",".join(fields), "--format=csv,noheader,nounits"])
        if result.get("returncode") != 0:
            raise ValueError("formal CUDA worker requires nvidia-smi GPU identity/environment")
        values = list(csv.reader(io.StringIO(result["stdout"])))
        if not values or any(len(row) != len(fields) for row in values):
            raise ValueError("unexpected GPU environment query")
        return {"rows": [dict(zip(fields, (x.strip() for x in row))) for row in values], "command": result}
    # Restrict to a reproducible default CUDA device selection. The engine
    # selects CUDA ordinal 0; PCI_BUS_ID makes that mapping stable.
    visible = os.environ.get("CUDA_VISIBLE_DEVICES")
    order = os.environ.get("CUDA_DEVICE_ORDER")
    if visible not in (None, "") or order not in (None, "PCI_BUS_ID"):
        raise ValueError("CUDA worker requires default visible devices and PCI_BUS_ID ordering")
    stable, dynamic = query(stable_fields), query(dynamic_fields)
    return {"identity": {"gpus": stable["rows"], "CUDA_VISIBLE_DEVICES": visible, "CUDA_DEVICE_ORDER": order},
        "identity_query": stable["command"], "observations": dynamic}


def provenance(args):
    permit = validate_freeze(args)
    record = cpu.read_json(args.build_record)
    return {**permit, "source_sha256": cpu.hashes(BUILD_FILES + TOOL_FILES),
        "library_sha256": cpu.file_sha(args.library), "library": str(args.library.resolve()),
        "build_record": record, "final": True, "classification": "formal", "scopes": SCOPES}


def resume_samples(existing, case, input_hashes):
    good = cpu.resume_samples(existing, case, input_hashes)
    for row in good.values():
        stats = row.get("cuda_stats", {})
        if (row.get("actual_backend") != 5 or row.get("end_to_end_ns") != row["duration_ns"]
                or not isinstance(row.get("kernel_ns"), int) or isinstance(row["kernel_ns"], bool)
                or not 0 < row["kernel_ns"] <= row["duration_ns"]
                or stats.get("kernel_ns") != row["kernel_ns"] or stats.get("timing_enabled") != 1
                or stats.get("kernel_launches", 0) < 1 or stats.get("device_hashes", 0) < 1):
            raise ValueError("preserved CUDA sample lacks valid device timing/scopes")
    return good


def validate_completed(existing, case, fixtures, budget=None):
    if not cpu.validate_completed(existing, case, fixtures, budget):
        return False
    ready = next(r for r in existing if r.get("kind") == "inputs_ready")
    good = resume_samples(existing, case, ready["input_hashes"])
    complete = next(r for r in existing if r.get("kind") == "case_complete")
    values = [good[index]["kernel_ns"] for index in range(case["samples"])]
    if complete.get("kernel_samples") != values or complete.get("kernel_summary") != cpu.summary(values):
        raise ValueError("CUDA kernel completion statistics differ from raw samples")
    return True


def raw_operation(c, case, inputs):
    if case["op"] == "sign":
        return cpu.raw_operation(c, case, inputs, None)
    # Buffers live in the returned closures and are allocated outside timing.
    address = (ct.c_uint8 * 32)()
    root = (ct.c_uint8 * 16)()
    height, start, target = case["height"], case["leaf_start"], case["target"]
    auth = (ct.c_uint8 * max(1, height*16))()
    call = lambda: c.lib.slh_subtree(c.ctx, 1, address, start, height, target, root, auth)
    extract = lambda: (bytes(root), bytes(auth[:height*16]) if target != 4294967295 else b"")
    return call, extract


def result_check(verifier, case, inputs, result, expected):
    if case["op"] == "sign":
        if len(result) != cpu.SIG_BYTES[case["pid"]] or not verifier.verify(inputs["message"], result, inputs["pk"], inputs["context"]):
            raise ValueError("CUDA signature length/independent REF verification failed")
        return {"passed": True, "method": "separate REF signature verification", "timed": False}
    if result != expected:
        raise ValueError("CUDA root/auth differs from independent REF subtree")
    return {"passed": True, "method": "independent REF root/auth equality", "timed": False}


def worker(args):
    cpu.protected_paths(args)
    plan = cpu.read_json(args.plan); check_plan(plan)
    case = next(c for c in plan["cases"] if c["case_id"] == args.worker_case)
    before = provenance(args)  # Gate plan/build/source before affinity or native.
    affinity = cpu.bind(case, True, args.cpus)
    if any(os.environ.get(k) != v for k, v in cpu.openmp_environment(case["threads"], affinity["cpus"]).items()):
        raise ValueError("CUDA OpenMP placement must be set before worker/native startup")
    initial = cpu.environment(affinity)
    initial_gpu = gpu_environment()
    identity = {"cpu": cpu.environment_identity(initial), "gpu": initial_gpu["identity"]}
    budget = SigningBudget(args.budget_db)
    case_key = cpu.sha(cpu.canonical({"case": case, "provenance": {k: before[k] for k in
        ("source_sha256", "library_sha256", "plan_sha256", "build_record_sha256", "freeze_sha256")}, "environment": identity, "ledger_uuid": budget.ledger_uuid}).encode())
    evidence = cpu.rows(args.output)
    if any(r.get("schema") != SCHEMA for r in evidence):
        raise ValueError("preserved CUDA JSONL contains foreign records")
    if any(r.get("kind") == "case_start" and r.get("case", {}).get("case_id") == case["case_id"] and r.get("case_key") != case_key for r in evidence):
        raise ValueError("CUDA resume source/build/plan/CPU/GPU conditions changed")
    existing = [r for r in evidence if r.get("case_key") == case_key]
    if validate_completed(existing, case, args.fixtures, budget):
        cpu.validate_fixture_receipts(args.fixtures, case["pid"], budget)
        # Even skipped cases recheck native device identity with events off.
        with NativeSlhDsa(case["pid"], case["threads"], 5, args.library) as c:
            stats = Statistics(c.lib); stats.reset(False)
            validate_freeze(args, device=stats.info())
        return
    append(args.output, {"kind": "case_start", "case_key": case_key, "case": case,
        "provenance": before, "environment": initial, "gpu_environment": initial_gpu,
        "environment_identity": identity, "ledger_uuid": budget.ledger_uuid, "pid_process": os.getpid()})
    runtime = cpu.verify_library_runtime(args.library)
    # Fixture creation uses a REF backend outside timing; CPU and CUDA campaigns
    # can share immutable fixtures. pid3 imports the independent Python vectors.
    inputs, input_files = cpu.fixture(args, {**case, "backend": "REF"}, args.output, emit=append)
    with NativeSlhDsa(case["pid"], case["threads"], 5, args.library) as c, \
            NativeSlhDsa(case["pid"], 1, 1, args.library) as verifier:
        c.bind_key(inputs["sk"]); verifier.bind_key(inputs["sk"])
        if c.backend != 5 or (c.pk_bytes, c.sk_bytes, c.sig_bytes) != (32, 64, cpu.SIG_BYTES[case["pid"]]):
            raise ValueError("CUDA actual backend/ABI differs from planned variant")
        stats = Statistics(c.lib); stats.reset(False)
        validate_freeze(args, device=stats.info())
        if case["op"] == "sign" and case["cache_t"] is not None:
            cache_path = args.fixtures.resolve()/f"p{case['pid']}-{cpu.sha(inputs['pk'])[:16]}-t{case['cache_t']}.cache"
            if not cache_path.exists():
                with NativeSlhDsa(case["pid"], case["threads"], 1, args.library) as prepare:
                    prepare.cache_build(inputs["sk"], case["cache_t"]); prepare.cache_save(cache_path)
            c.cache_load(cache_path, inputs["pk"])
            input_files[str(cache_path)] = cpu.file_sha(cache_path)
        expected = None
        if case["op"] == "fors_subtree":
            expected = verifier.subtree("fors", bytes(32), case["leaf_start"], case["height"], case["target"])
        if inputs.get("sig") and not verifier.verify(inputs["message"], inputs["sig"], inputs["pk"], inputs["context"]):
            raise ValueError("stored fixture signature rejected before CUDA timing")
        input_hashes = {k: cpu.sha(v) for k, v in inputs.items()}
        for old in (r for r in existing if r.get("kind") == "inputs_ready"):
            if old.get("input_hashes") != input_hashes or old.get("input_files") != input_files:
                raise ValueError("CUDA fixture changed during partial resume")
            if old.get("budget_binding") != cpu.budget_binding(budget, case, inputs):
                raise ValueError("CUDA partial-case budget binding differs from immutable fixture")
        append(args.output, {"kind": "inputs_ready", "case_key": case_key, "input_hashes": input_hashes,
            "ledger_uuid": budget.ledger_uuid, "budget_binding": cpu.budget_binding(budget, case, inputs),
            "input_files": input_files, "runtime_checks": runtime, "actual_backend": 5,
            "validation": "separate REF after timing", "kernel_events": "disabled during setup/warmup/validation"})
        call, extract = raw_operation(c, case, inputs)
        encoded = b"\x00" + bytes([len(inputs["context"])]) + inputs["context"] + inputs["message"]
        good = resume_samples(existing, case, input_hashes)
        cpu.validate_preserved_budget(existing, case, budget)
        if not good:
            for warmup in range(case["warmups"]):
                receipt = budget.reserve(cpu.ALGORITHMS[case["pid"]], inputs["pk"], encoded) if case["op"] == "sign" else None
                finished = False
                try:
                    stats.reset(False); c._check(case["op"], call()); result = extract()
                    validation = result_check(verifier, case, inputs, result, expected)
                    if receipt:
                        finished = True; budget.finish(receipt, result)
                except BaseException as exc:
                    if receipt and not finished: cpu.finish_failure(budget, receipt, exc)
                    raise
                append(args.output, {"kind": "warmup", "case_key": case_key, "index": warmup,
                    "receipt": receipt, "budget_evidence": cpu.receipt_evidence(budget, receipt), "validation": validation, "timed": False})
        prediction = None
        for index in range(case["samples"]):
            if index in good: continue
            observation = {"cpu": cpu.sample_environment(affinity["cpus"]), "gpu": gpu_environment()}
            if observation["gpu"]["identity"] != identity["gpu"]:
                raise ValueError("GPU identity/power policy changed before CUDA sample")
            receipt = budget.reserve(cpu.ALGORITHMS[case["pid"]], inputs["pk"], encoded) if case["op"] == "sign" else None
            finished, sample = False, None
            try:
                sample = sample_once(call, stats, permit=before)
                result = extract(); validation = result_check(verifier, case, inputs, result, expected)
                if receipt:
                    finished = True; budget.finish(receipt, result)
                if prediction is None and case["op"] == "sign":
                    prediction = cpu.theoretical(case, inputs, result)
                observation_after = {"cpu": cpu.sample_environment(affinity["cpus"]), "gpu": gpu_environment()}
                if observation_after["gpu"]["identity"] != identity["gpu"]:
                    raise ValueError("GPU identity/power policy changed during CUDA sample")
            except BaseException as exc:
                if receipt and not finished: cpu.finish_failure(budget, receipt, exc)
                append(args.output, {"kind": "sample", "case_key": case_key, "sample_index": index,
                    "passed": False, "duration_ns": sample["end_to_end_ns"] if sample else None,
                    "error": str(exc), "receipt": receipt, "budget_evidence": cpu.failure_receipt_evidence(budget, receipt, exc)})
                raise
            row = {"kind": "sample", "case_key": case_key, "case_id": case["case_id"], "sample_index": index,
                "passed": True, "duration_ns": sample["end_to_end_ns"], **sample, "actual_backend": 5,
                "receipt": receipt, "budget_evidence": cpu.receipt_evidence(budget, receipt), "input_hashes": input_hashes,
                "result_sha256": cpu.sha(result if isinstance(result, bytes) else b"".join(result)),
                "environment_before": observation,
                "environment_after": observation_after,
                "validation": validation, "classification": "formal"}
            append(args.output, row); good[index] = row
        after = provenance(args)
        if any(after[k] != before[k] for k in ("source_sha256", "library_sha256", "plan_sha256", "build_record_sha256", "freeze_sha256")):
            raise ValueError("CUDA source/library/plan/build/freeze changed during case")
        if any(cpu.file_sha(p) != digest for p, digest in input_files.items()):
            raise ValueError("CUDA input file changed during case")
        end_cpu, end_gpu = cpu.environment(affinity), gpu_environment()
        if {"cpu": cpu.environment_identity(end_cpu), "gpu": end_gpu["identity"]} != identity:
            raise ValueError("stable CPU/GPU environment changed during CUDA case")
        validate_freeze(args, device=stats.info())
        if prediction is None:
            if case["op"] == "sign": prediction = cpu.theoretical(case, inputs, inputs.get("sig"))
            else:
                leaves = 1 << case["height"]
                prediction = {"hash_calls": 3*leaves-1, "compressions": 3*leaves-1,
                    "primitive_counts": {"prf": leaves, "f": leaves, "h": leaves-1},
                    "count_basis": "logical scalar FORS PRF/F/H equivalents; excludes seed initialization, transport and GPU lane padding"}
        values = [good[index]["duration_ns"] for index in range(case["samples"])]
        kernel_values = [good[index]["kernel_ns"] for index in range(case["samples"])]
        latest = cpu.rows(args.output)
        append(args.output, {"kind": "case_complete", "case_key": case_key, "case_id": case["case_id"],
            "ledger_uuid": budget.ledger_uuid,
            **cpu.summary(values), "samples": values, "kernel_samples": kernel_values,
            "kernel_summary": cpu.summary(kernel_values), "scopes": SCOPES, **prediction,
            "sample_lines": [r["_line"] for r in latest if r.get("case_key") == case_key and r.get("kind") == "sample" and r.get("passed")],
            "pid": case["pid"], "op": case["op"], "actual_backend": 5, "threads": case["threads"], "cache_t": case["cache_t"],
            "input_hashes": input_hashes, "input_files_before": input_files, "input_files_after": input_files,
            "environment_identity": identity, "environment_end": end_cpu, "gpu_environment_end": end_gpu,
            "source_sha256_before": before["source_sha256"], "source_sha256_after": after["source_sha256"],
            "library_sha256_before": before["library_sha256"], "library_sha256_after": after["library_sha256"],
            "build_record_sha256": before["build_record_sha256"], "freeze_sha256": before["freeze_sha256"],
            "device_identity": before["device_identity"], "final": True, "classification": "formal", "core_cycles": None})


def run_cases(args):
    cpu.protected_paths(args)
    if not math.isfinite(args.timeout_seconds) or args.timeout_seconds <= 0:
        raise ValueError("CUDA worker timeout must be finite and positive")
    plan = cpu.read_json(args.plan); check_plan(plan)
    before = provenance(args)  # Gate before topology, child execution or native.
    topo, topo_result = cpu.topology()
    if not topo: raise ValueError("formal CUDA campaign requires Linux physical CPU topology")
    host = cpu.environment_identity(cpu.environment({"cpus": [], "verified_physical": True, "physical_cores": topo}))
    gpu = gpu_environment()
    budget = SigningBudget(args.budget_db)
    campaign_key = cpu.sha(cpu.canonical({"provenance": {k: before[k] for k in
        ("source_sha256", "library_sha256", "plan_sha256", "build_record_sha256", "freeze_sha256")},
        "host": host, "gpu": gpu["identity"], "explicit_cpus": args.cpus, "ledger_uuid": budget.ledger_uuid}).encode())
    old = cpu.rows(args.output)
    if any(r.get("schema") != SCHEMA for r in old): raise ValueError("foreign CUDA JSONL records")
    starts = [r for r in old if r.get("kind") == "campaign_start"]
    if old and not starts or len(starts) > 1 or starts and starts[0].get("campaign_key") != campaign_key:
        raise ValueError("CUDA campaign resume source/plan/CPU/GPU conditions changed")
    ids = [c["case_id"] for c in plan["cases"]]
    selected = set(args.case or ids)
    if not selected.issubset(ids): raise ValueError("--case name absent from CUDA plan")
    if not starts: append(args.output, {"kind": "campaign_start", "campaign_key": campaign_key,
        "ledger_uuid": budget.ledger_uuid,
        "provenance": before, "host_environment": host, "gpu_environment": gpu, "topology_probe": topo_result})
    for case in plan["cases"]:
        if case["case_id"] not in selected: continue
        current = provenance(args)
        if any(current[k] != before[k] for k in ("source_sha256", "library_sha256", "plan_sha256", "build_record_sha256", "freeze_sha256")):
            raise ValueError("CUDA sources/build/plan changed between sequential cases")
        if gpu_environment()["identity"] != gpu["identity"]:
            raise ValueError("GPU identity/power policy changed between sequential CUDA cases")
        try:
            cpus = [r["cpu"] for r in cpu.physical_cpus(topo, case["threads"], args.cpus)]
        except ValueError as exc:
            append(args.output, {"kind": "case_unavailable", "case_id": case["case_id"], "passed": False, "reason": str(exc)})
            continue
        child_env = {k: v for k, v in os.environ.items() if not k.startswith(("OMP_", "GOMP_", "KMP_"))}
        child_env.pop("CUDA_VISIBLE_DEVICES", None)
        child_env["CUDA_DEVICE_ORDER"] = "PCI_BUS_ID"
        argv = [sys.executable, str(Path(__file__).resolve()), "worker", "--worker-case", case["case_id"],
            "--parent-pid", str(os.getpid()), "--cpus", ",".join(map(str, cpus))]
        for name in ("plan", "library", "build_record", "freeze", "output", "fixtures", "budget_db"):
            argv += ["--"+name.replace("_", "-"), str(getattr(args, name).resolve())]
        try:
            child = subprocess.run(argv, cwd=ROOT, env={**child_env, **cpu.openmp_environment(case["threads"], cpus)}, timeout=args.timeout_seconds)
        except subprocess.TimeoutExpired:
            append(args.output, {"kind": "case_process_timeout", "case_id": case["case_id"], "passed": False,
                "timeout_seconds": args.timeout_seconds, "budget_policy": "reservations remain consumed"})
            raise RuntimeError("CUDA worker exceeded timeout: " + case["case_id"]) from None
        if child.returncode:
            append(args.output, {"kind": "case_process_failed", "case_id": case["case_id"], "returncode": child.returncode})
            raise RuntimeError("CUDA worker failed: " + case["case_id"])
    print(cpu.canonical({"output": str(args.output), "classification": "formal",
        "complete_cases": sum(r.get("kind") == "case_complete" for r in cpu.rows(args.output))}))


def self_test(output=None):
    import tempfile
    import unittest
    from contextlib import ExitStack
    from types import SimpleNamespace
    from unittest.mock import patch
    module = sys.modules[__name__]
    class FakeStats:
        def __init__(self, row=None):
            self.resets = []
            self.row = row or {"kernel_launches": 3, "h2d_bytes": 16, "d2h_bytes": 32,
                "device_hashes": 8, "kernel_ns": 40, "timing_enabled": 1}
        def reset(self, enabled=False): self.resets.append(enabled)
        def get(self): return self.row
    class Checks(unittest.TestCase):
        def setUp(self):
            self.temp = tempfile.TemporaryDirectory(prefix="a15-cuda-mock-")
            self.folder = Path(self.temp.name)
            self.addCleanup(self.temp.cleanup)
        def worker_harness(self, fail_call=None, model_error=False, real_fixture=False):
            plan = make_plan([2], [1]); case = plan["cases"][0]
            case["warmups"] = 1
            args = SimpleNamespace(plan=self.folder/"plan.json", library=self.folder/"library.so",
                build_record=self.folder/"build.json", freeze=self.folder/"freeze.json",
                output=self.folder/"raw.jsonl", fixtures=self.folder/"inputs", budget_db=self.folder/"budget.db",
                cpus=[0], worker_case=case["case_id"], timeout_seconds=10, case=[case["case_id"]])
            args.plan.write_text(json.dumps(plan)); args.library.write_bytes(b"mock-not-a-library")
            args.fixtures.mkdir(); input_path = args.fixtures/"fixture.json"; input_path.write_bytes(b"immutable inputs")
            inputs = {"pk": b"p"*32, "sk": b"s"*32+b"p"*32, "sk_seed": b"s"*16,
                "sk_prf": b"r"*16, "pk_seed": b"p"*16, "message": b"mock message", "context": b"mock"}
            if not real_fixture:
                cpu.atomic_json(args.fixtures/"p2-fixture.json", {k: v.hex() for k, v in inputs.items()})
            device = {"name": "mock GPU"}
            prov = {"formal_gate_passed": True, "source_sha256": {"mock": "hash"}, "library_sha256": "library",
                "plan_sha256": cpu.file_sha(args.plan), "build_record_sha256": "build", "freeze_sha256": "freeze",
                "device_identity": device, "classification": "formal", "final": True}
            affinity = {"cpus": [0], "verified_physical": True, "physical_cores": [{"cpu": 0, "core": 0, "socket": 0, "node": 0}]}
            env = {"host": "mock-host", "cpu": "mock-cpu", "affinity": affinity, "governor": "mock", "turbo": "mock"}
            gpu = {"identity": {"gpus": [{"uuid": "GPU-MOCK", "power.limit": "100"}]}, "observations": {}}
            state = {"calls": 0, "reservations": [], "finishes": [], "native_contexts": 0}
            class Budget:
                ledger_uuid = "2"*32
                records = {}
                def __init__(self, path): pass
                def reserve(self, algorithm, public, message):
                    receipt = "receipt-"+str(len(state["reservations"]))
                    state["reservations"].append(receipt)
                    self.records[receipt] = {"ledger_uuid": self.ledger_uuid, "receipt": receipt,
                        "algorithm": cpu.canonical_algorithm(algorithm), "key_id": cpu.canonical_key_id(algorithm, public),
                        "public_key_sha256": cpu.sha(public), "message_sha256": cpu.sha(message), "signature_sha256": None,
                        "status": "reserved"}
                    return receipt
                def finish(self, receipt, result=None):
                    state["finishes"].append((receipt, result is not None))
                    self.records[receipt].update(status="committed" if result is not None else "failed",
                                                signature_sha256=cpu.sha(result) if result is not None else None)
                def validate_receipt(self, receipt, **unused): return dict(self.records[receipt])
            state["budget_type"] = Budget
            class Native:
                def __init__(self, pid, threads, flags, library):
                    state["native_contexts"] += 1
                    self.backend = flags; self.pk_bytes = 32; self.sk_bytes = 64; self.sig_bytes = cpu.SIG_BYTES[pid]; self.lib = object()
                def __enter__(self): return self
                def __exit__(self, *unused): pass
                def bind_key(self, key): pass
                def set_cache_level(self, level): pass
                def keygen_internal(self, seed, prf, public): return b"p"*32, seed+prf+b"p"*32
                def sign(self, *unused): return b"S"*self.sig_bytes
                def verify(self, *unused): return True
                def _check(self, op, code):
                    if code: raise ValueError("mock operation returned " + str(code))
            def operation():
                state["calls"] += 1
                return -2 if state["calls"] == fail_call else 0
            fake = FakeStats(); fake.info = lambda: device
            ticks = iter(range(100, 10000000, 100))
            real_sample = sample_once
            stack = ExitStack()
            patches = [
                (module, "provenance", {"return_value": prov}),
                (module, "validate_freeze", {"return_value": prov}),
                (module, "NativeSlhDsa", {"side_effect": Native}),
                (module, "Statistics", {"return_value": fake}),
                (module, "SigningBudget", {"side_effect": Budget}),
                (module, "gpu_environment", {"return_value": gpu}),
                (module, "raw_operation", {"return_value": (operation, lambda: b"S"*cpu.SIG_BYTES[2])}),
                (module, "sample_once", {"side_effect": lambda call, stats, permit: real_sample(call, stats, permit=permit, clock=lambda: next(ticks))}),
                (cpu, "bind", {"return_value": affinity}), (cpu, "environment", {"return_value": env}),
                (cpu, "sample_environment", {"return_value": {"mock": "observation"}}),
                (cpu, "verify_library_runtime", {"return_value": {"counter_probe": "mock", "timed": False}}),
                (cpu, "theoretical", {"side_effect": ValueError("model after finalize") } if model_error else {"return_value": {"hash_calls": 123, "compressions": 123}}),
                (cpu, "topology", {"return_value": ([{"cpu": 0, "core": 0, "socket": 0, "node": 0}], {"mock": True})})]
            if real_fixture:
                patches += [(cpu, "NativeSlhDsa", {"side_effect": Native}), (cpu, "SigningBudget", {"side_effect": Budget})]
            else:
                patches.append((cpu, "fixture", {"return_value": (inputs, {str(input_path): cpu.file_sha(input_path)})}))
            for owner, name, kwargs in patches:
                stack.enter_context(patch.object(owner, name, **kwargs))
            stack.enter_context(patch.dict(os.environ, cpu.openmp_environment(1, [0])))
            self.addCleanup(stack.close)
            return args, case, state, prov, gpu
        def test_abi_layout(self):
            self.assertEqual((ct.sizeof(CudaInfo), CudaInfo.total_memory.offset, CudaInfo.name.offset), (128, 24, 32))
            self.assertEqual(ct.sizeof(CudaStats), 48)
        def test_normative_plan(self):
            plan = make_plan(); check_plan(plan)
            self.assertEqual(len(plan["cases"]), 64)
            self.assertEqual({c["op"] for c in plan["cases"]}, {"sign", "fors_subtree"})
            self.assertEqual({c["threads"] for c in plan["cases"]}, {1, 2, 4, 8, 16, 32, 64})
        def test_invalid_plan(self):
            for pids, threads in (([101], [1]), ([201], [1]), ([1, 1], [1]), ([1], [0])):
                with self.assertRaises(ValueError): make_plan(pids, threads)
            for field, value in (("backend_id", 2), ("samples", 1), ("op", "verify")):
                plan = make_plan(); plan["cases"][0][field] = value
                with self.assertRaises(ValueError): check_plan(plan)
        def test_two_scopes(self):
            stats = FakeStats(); clock = iter([100, 250])
            sample = sample_once(lambda: 0, stats, permit={"formal_gate_passed": True}, clock=lambda: next(clock))
            self.assertEqual((sample["end_to_end_ns"], sample["kernel_ns"]), (150, 40))
            self.assertEqual(stats.resets, [True, False])
        def test_full_worker_raw_statistics_and_skip(self):
            args, case, state, _, _ = self.worker_harness()
            worker(args)
            rows = cpu.rows(args.output)
            raw = [r for r in rows if r["kind"] == "sample"]
            complete = next(r for r in rows if r["kind"] == "case_complete")
            self.assertEqual(len(raw), 100)
            self.assertEqual((complete["median"], complete["kernel_summary"]["median"]), (100, 40))
            self.assertEqual(len(state["reservations"]), 101)
            self.assertEqual(len({r[0] for r in state["finishes"]}), 101)
            self.assertTrue(all(r["schema"] == SCHEMA for r in rows))
            old_calls = state["calls"]; worker(args)
            self.assertEqual(state["calls"], old_calls)
            args.fixtures.joinpath("fixture.json").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "input file changed"): worker(args)

        def test_completed_case_rejects_other_ledger_before_native(self):
            args, _, state, _, _ = self.worker_harness()
            worker(args)
            state["budget_type"].ledger_uuid = "4"*32
            count = state["native_contexts"]
            with self.assertRaisesRegex(ValueError, "resume"):
                worker(args)
            self.assertEqual(state["native_contexts"], count)

        def test_completed_case_reconciles_live_receipt(self):
            args, _, state, _, _ = self.worker_harness()
            worker(args)
            state["budget_type"].records["receipt-0"]["signature_sha256"] = "0"*64
            count = state["native_contexts"]
            with self.assertRaisesRegex(ValueError, "live receipt"):
                worker(args)
            self.assertEqual(state["native_contexts"], count)
        def test_real_fixture_helper_uses_cuda_schema_and_budget(self):
            args, case, state, _, _ = self.worker_harness(real_fixture=True)
            worker(args)
            rows = cpu.rows(args.output)
            setup = [r for r in rows if r["kind"] == "setup_signature"]
            self.assertEqual(len(setup), 1)
            self.assertTrue(all(r["schema"] == SCHEMA for r in rows))
            self.assertEqual(len(state["reservations"]), 102)  # fixture + warmup +100
            self.assertEqual(len(state["finishes"]), 102)
            self.assertTrue(all(success for _, success in state["finishes"]))
            ready = next(r for r in rows if r["kind"] == "inputs_ready")
            self.assertEqual(len(ready["input_files"]), 2)  # actual helper writes both files
            loaded, files = cpu.fixture(args, {**case, "backend": "REF"}, args.output, emit=append)
            self.assertEqual(len(state["reservations"]), 102)  # reused signature is free
            self.assertEqual(files, ready["input_files"])
            self.assertEqual(cpu.sha(loaded["sig"]), ready["input_hashes"]["sig"])
            calls = state["calls"]; worker(args)  # would reject mixed schemas before fix
            self.assertEqual(state["calls"], calls)
        def test_subtree_worker_has_no_signature_budget(self):
            args, case, state, _, _ = self.worker_harness()
            plan = cpu.read_json(args.plan); subtree = plan["cases"][-2]
            args.worker_case = subtree["case_id"]; args.plan.write_text(json.dumps(plan))
            expected = (b"r"*16, b"")
            with patch.object(module, "raw_operation", return_value=(lambda: 0, lambda: expected)), \
                    patch.object(module, "result_check", return_value={"passed": True}), \
                    patch.object(module, "NativeSlhDsa") as ctor:
                native = ctor.return_value.__enter__.return_value
                native.backend = 5; native.pk_bytes = 32; native.sk_bytes = 64; native.sig_bytes = cpu.SIG_BYTES[2]
                native.subtree.return_value = expected
                worker(args)
            complete = next(r for r in cpu.rows(args.output) if r["kind"] == "case_complete")
            self.assertEqual((complete["n"], complete["kernel_summary"]["n"]), (5, 5))
            self.assertEqual(state["reservations"], [])
            self.assertEqual(complete["hash_calls"], 3*(1 << subtree["height"])-1)
        def test_partial_resume_consumes_failed_attempt(self):
            args, case, state, _, _ = self.worker_harness(fail_call=3)
            with self.assertRaisesRegex(ValueError, "returned -2"): worker(args)
            self.assertEqual(len([r for r in cpu.rows(args.output) if r.get("kind") == "sample" and r.get("passed")]), 1)
            worker(args)
            rows = cpu.rows(args.output)
            self.assertEqual(len([r for r in rows if r.get("kind") == "sample" and r.get("passed")]), 100)
            self.assertEqual((len(state["reservations"]), len(state["finishes"])), (102, 102))
            self.assertEqual(sum(not success for _, success in state["finishes"]), 1)
        def test_gpu_change_rejects_completed_resume(self):
            args, case, state, _, gpu = self.worker_harness(); worker(args)
            contexts = state["native_contexts"]
            gpu["identity"]["gpus"][0]["uuid"] = "GPU-OTHER"
            with self.assertRaisesRegex(ValueError, "conditions changed"): worker(args)
            self.assertEqual(state["native_contexts"], contexts)
        def test_post_finalize_error_has_one_finish(self):
            args, case, state, _, _ = self.worker_harness(model_error=True)
            with self.assertRaisesRegex(ValueError, "model after finalize"): worker(args)
            self.assertEqual(len(state["finishes"]), len(set(r[0] for r in state["finishes"])))
            self.assertTrue(all(success for _, success in state["finishes"]))
        def test_parent_timeout_and_no_native_calls(self):
            args, case, state, _, _ = self.worker_harness()
            with patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired("mock child", 10)):
                with self.assertRaisesRegex(RuntimeError, "exceeded timeout"): run_cases(args)
            self.assertEqual(state["native_contexts"], 0)
            self.assertTrue(any(r["kind"] == "case_process_timeout" for r in cpu.rows(args.output)))
        def test_parent_sequential_dispatch_omp(self):
            args, case, state, _, _ = self.worker_harness()
            with patch.object(subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
                with patch.dict(os.environ, {"GOMP_CPU_AFFINITY": "999", "OMP_THREAD_LIMIT": "1"}):
                    run_cases(args)
            self.assertEqual(run.call_count, 1)
            kwargs = run.call_args.kwargs
            self.assertEqual(kwargs["timeout"], 10)
            self.assertEqual(kwargs["env"]["OMP_PLACES"], "{0}")
            self.assertEqual(kwargs["env"]["CUDA_DEVICE_ORDER"], "PCI_BUS_ID")
            self.assertNotIn("OMP_THREAD_LIMIT", kwargs["env"])
            self.assertNotIn("GOMP_CPU_AFFINITY", kwargs["env"])
            self.assertEqual(state["native_contexts"], 0)
        def test_parent_worker_gate_precedes_native_affinity(self):
            args, case, state, _, _ = self.worker_harness()
            with patch.object(module, "provenance", side_effect=ValueError("changed frozen plan")), patch.object(cpu, "bind") as bind:
                with self.assertRaisesRegex(ValueError, "frozen plan"): worker(args)
                with self.assertRaisesRegex(ValueError, "frozen plan"): run_cases(args)
                bind.assert_not_called()
            self.assertEqual(state["native_contexts"], 0)
        def test_kernel_resume_integrity(self):
            case = make_plan([2], [1])["cases"][0]
            row = {"kind": "sample", "passed": True, "sample_index": 0, "duration_ns": 100, "end_to_end_ns": 100,
                "kernel_ns": 40, "actual_backend": 5, "input_hashes": {}, "cuda_stats": FakeStats().row}
            self.assertEqual(len(resume_samples([row], case, {})), 1)
            with self.assertRaisesRegex(ValueError, "duplicate"): resume_samples([row, row], case, {})
            for replacement in (0, 101, True):
                with self.assertRaises(ValueError): resume_samples([{**row, "kernel_ns": replacement}], case, {})
        def test_no_cpu_only_gpu_claim(self):
            stats = FakeStats({"timing_enabled": 1, "kernel_launches": 0, "device_hashes": 0, "kernel_ns": 0})
            clock = iter([1, 100])
            with self.assertRaises(ValueError): sample_once(lambda: 0, stats, permit={"formal_gate_passed": True}, clock=lambda: next(clock))
            self.assertEqual(stats.resets[-1], False)
        def test_timing_permit_before_any_native(self):
            stats = FakeStats()
            with self.assertRaises(ValueError): sample_once(lambda: self.fail("operation called"), stats, permit=None)
            self.assertEqual(stats.resets, [])
        def test_error_disables_events(self):
            stats = FakeStats(); clock = iter([1, 100])
            with self.assertRaises(ValueError): sample_once(lambda: -2, stats, permit={"formal_gate_passed": True}, clock=lambda: next(clock))
            self.assertEqual(stats.resets, [True, False])
        def test_disable_error_preserves_original(self):
            stats = FakeStats()
            def reset(enabled):
                if not enabled: raise RuntimeError("secondary reset failure")
            stats.reset = reset
            clock = iter([1, 100])
            with self.assertRaisesRegex(ValueError, "operation returned -2") as error:
                sample_once(lambda: -2, stats, permit={"formal_gate_passed": True}, clock=lambda: next(clock))
            self.assertIn("secondary", error.exception.__notes__[0])
        def test_build_commands_release_only(self):
            commands = build_commands(Path("/fresh"), "/gcc", "/nvcc", "/g++", "sm_80")
            self.assertEqual(commands[-1][-1], str(Path("/fresh") / "libslhdsa_sm3.so"))
            for argv in commands[:-1]:
                self.assertIn("-DSLH_RELEASE_BUILD", argv)
                self.assertNotIn("-DSLH_COUNTERS", argv)
                self.assertNotIn("-DSLH_TEST_BUILD", argv)
            self.assertFalse(any("stub" in token for cmd in commands for token in cmd))
            with self.assertRaises(ValueError): build_commands(Path("/fresh"), "/gcc", "/nvcc", "/g++", "sm_80 -G")
        def test_freeze_build_plan_evidence_binding(self):
            paths = {"build": {"release_probe": {"device": {"name": "mock"}}, "source_sha256": {"c": "hash"}, "library_sha256": "library-hash"}, "plan": make_plan(),
                     "mock": {"passed": True, "native_calls": 0, "real_timing_samples": 0, "source_sha256": {"tools": "hash"}},
                     "correctness": {"passed": True, "real_timing_samples": 0, "source_sha256": {"c": "hash"}, "library_sha256": "library-hash", "build_record_sha256": "build-hash", "device_identity": {"name": "mock"}}}
            freeze = {"schema": "a15-cuda-freeze-v1", "final": True, "correctness_passed": True,
                "formal_performance_started": False, "real_timing_samples": 0,
                "source_sha256": {"tools": "hash"}, "library_sha256": "library-hash", "build_record_sha256": "build-hash",
                "plans": {"cuda_b1": {"sha256": "plan-hash"}}, "device_identity": {"name": "mock"},
                "evidence": {k: {"path": k, "sha256": k+"-hash"} for k in ("mock", "correctness")}}
            paths["freeze"] = freeze
            args = SimpleNamespace(library="library", build_record="build", plan="plan", freeze="freeze")
            with patch.object(module, "checked_build"), patch.object(cpu, "validate_published_freeze"), patch.object(cpu, "read_json", side_effect=lambda p: paths[p]), \
                    patch.object(cpu, "file_sha", side_effect=lambda p: p+"-hash"), patch.object(cpu, "hashes", return_value={"tools": "hash"}):
                self.assertTrue(validate_freeze(args)["formal_gate_passed"])
                content = validate_freeze_content(args)
                self.assertTrue(content["content_gate_passed"])
                self.assertFalse(content["formal_gate_passed"])
                with self.assertRaisesRegex(ValueError, "device identity"): validate_freeze(args, device={"name": "other"})
                for field, replacement in (("build_record_sha256", "old"), ("plans", {}), ("device_identity", {"name": "other"})):
                    old = freeze[field]; freeze[field] = replacement
                    with self.assertRaises(ValueError): validate_freeze(args)
                    freeze[field] = old
                paths["mock"]["native_calls"] = 1
                with self.assertRaises(ValueError): validate_freeze(args)
        def test_freeze_lifecycle_rejected_before_provenance(self):
            valid = {"schema": "a15-cuda-freeze-v1", "final": True, "correctness_passed": True,
                "formal_performance_started": False, "real_timing_samples": 0}
            missing = object()
            mutations = [("formal_performance_started", missing), ("formal_performance_started", True),
                ("formal_performance_started", 0), ("formal_performance_started", None),
                ("real_timing_samples", missing), ("real_timing_samples", False),
                ("real_timing_samples", 0.0), ("real_timing_samples", "0"),
                ("real_timing_samples", 1), ("real_timing_samples", -1), ("real_timing_samples", None)]
            args = SimpleNamespace(library="library", build_record="build", plan="plan", freeze="freeze")
            for field, replacement in mutations:
                with self.subTest(field=field, replacement=str(replacement)):
                    freeze = dict(valid)
                    if replacement is missing: freeze.pop(field)
                    else: freeze[field] = replacement
                    paths = {"build": {}, "plan": make_plan(), "freeze": freeze}
                    with patch.object(module, "checked_build"), patch.object(cpu, "validate_published_freeze"), \
                            patch.object(cpu, "read_json", side_effect=lambda p: paths[p]), patch.object(cpu, "hashes") as hashes:
                        for validator in (validate_freeze_content, validate_freeze):
                            with self.assertRaisesRegex(ValueError, "freeze lifecycle"):
                                validator(args)
                        hashes.assert_not_called()
        def test_candidate_content_is_never_formal_permit(self):
            candidate = self.folder/"freeze.candidate.json"
            candidate.write_text(json.dumps({"source_sha256": {}}))
            args = SimpleNamespace(freeze=candidate)
            with patch.object(module, "validate_freeze_content") as check:
                with self.assertRaisesRegex(ValueError, "canonical published"):
                    validate_freeze(args)
                check.assert_not_called()
        def test_public_gate_rechecks_budget_snapshots_before_content(self):
            out = self.folder/"published"; out.mkdir()
            directory = out/"budget-evidence"; directory.mkdir()
            live = self.folder/"live.sqlite"; live.write_bytes(b"live budget")
            snapshot = directory/"budget-0.sqlite"; snapshot.write_bytes(b"accepted SQL snapshot")
            wal = Path(str(snapshot)+"-wal"); wal.write_bytes(b"accepted WAL snapshot")
            recorded = {str(p.resolve()): cpu.file_sha(p) for p in (snapshot, wal)}
            freeze = {"schema": "a15-cuda-freeze-v1", "source_sha256": {"source": "hash"},
                "correctness_evidence_sha256": recorded,
                "budget_snapshots": [{"live_database": str(live.resolve()), "snapshot_database": str(snapshot.resolve()),
                    "files_sha256": recorded.copy()}]}
            canonical = out/"freeze.json"; canonical.write_text(json.dumps(freeze))
            for name in ("source.tar.gz", "REVIEW.md"): (out/name).write_bytes(b"mock package")
            (out/"source-manifest.json").write_text(json.dumps(freeze["source_sha256"]))
            (out/"package.json").write_text(json.dumps({"passed": True, "formal_performance_started": False,
                "real_timing_samples": 0, "files_sha256": {name: cpu.file_sha(out/name) for name in
                ("freeze.json", "source.tar.gz", "source-manifest.json", "REVIEW.md")}}))
            args = SimpleNamespace(freeze=canonical)
            with patch.object(module, "validate_freeze_content", return_value={"formal_gate_passed": False}) as content:
                self.assertTrue(validate_freeze(args)["formal_gate_passed"])
                live.write_bytes(b"future signed records")
                self.assertTrue(validate_freeze(args)["formal_gate_passed"])
                for target in (snapshot, wal):
                    original = target.read_bytes(); content.reset_mock()
                    target.write_bytes(b"changed acceptance snapshot")
                    with self.assertRaisesRegex(ValueError, "correctness evidence file"):
                        validate_freeze(args)
                    content.assert_not_called()
                    target.unlink()
                    with self.assertRaisesRegex(ValueError, "correctness evidence file"):
                        validate_freeze(args)
                    content.assert_not_called(); target.write_bytes(original)
    with patch.object(module, "NativeSlhDsa", side_effect=AssertionError("mock tests prohibit native load")), \
            patch.object(ct, "CDLL", side_effect=AssertionError("mock tests prohibit native load")), \
            patch.object(time, "perf_counter_ns", side_effect=AssertionError("mock tests prohibit real timer")), \
            patch.object(cpu, "command", side_effect=AssertionError("mock tests prohibit subprocess")):
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Checks))
    if not result.wasSuccessful():
        raise ValueError("CUDA preparation mock checks failed")
    record = {"schema": "a15-cuda-selftest-v1", "created_utc": cpu.utc(), "passed": True,
        "mock_checks": result.testsRun, "native_calls": 0, "real_timing_samples": 0,
        "tool_sha256": cpu.file_sha(__file__), "source_sha256": cpu.hashes(TOOL_FILES),
        "scope": "mock plan/build/freeze/stats/scopes/full-worker/budget/fixtures/resume/timeout/affinity/environment checks; native libraries, subprocess and real timers blocked"}
    if output is not None: cpu.atomic_json(output, record)
    print(cpu.canonical(record))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan")
    plan.add_argument("--pids", type=cpu.integers, default=[1, 2, 3])
    plan.add_argument("--threads", type=cpu.integers, default=[1, 2, 4, 8, 16, 32, 64])
    plan.add_argument("--output", type=Path, required=True)
    tests = sub.add_parser("self-test")
    tests.add_argument("--output", type=Path)
    build_parser = sub.add_parser("build", help="compile release CUDA plus untimed counter/device correctness probe")
    build_parser.add_argument("--out", type=Path, required=True)
    build_parser.add_argument("--cc", default="gcc")
    build_parser.add_argument("--nvcc", default="nvcc")
    build_parser.add_argument("--host-cxx", default="g++")
    build_parser.add_argument("--arch", default="sm_75")
    validate = sub.add_parser("validate", help="hash/dependency/plan freeze gate only; no native load or timing")
    for name in ("library", "build-record", "plan", "freeze"):
        validate.add_argument("--"+name, type=Path, required=True)
    for command in ("run", "worker"):
        runner = sub.add_parser(command, help="explicit final frozen CUDA campaign; preparation uses mocks only")
        for name in ("library", "build-record", "plan", "freeze", "output", "fixtures", "budget-db"):
            runner.add_argument("--"+name, type=Path, required=True)
        runner.add_argument("--cpus", type=cpu.integers)
        runner.add_argument("--timeout-seconds", type=float, default=7200)
        if command == "run": runner.add_argument("--case", action="append")
        else:
            runner.add_argument("--worker-case", required=True)
            runner.add_argument("--parent-pid", type=int, required=True, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.command == "plan":
        result = make_plan(args.pids, args.threads); check_plan(result); cpu.atomic_json(args.output, result)
        print(args.output)
    elif args.command == "self-test": self_test(args.output)
    elif args.command == "build": build(args)
    elif args.command == "run":
        with cpu.output_lock(args.output): run_cases(args)
    elif args.command == "worker":
        if args.parent_pid != os.getppid(): raise ValueError("CUDA worker is internal; use run")
        worker(args)
    else: print(cpu.canonical(validate_freeze(args)))


if __name__ == "__main__":
    try: main()
    except (ValueError, RuntimeError) as exc:
        print("CUDA preparation error: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
