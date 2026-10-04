#!/usr/bin/env python3
"""Sequential, resumable CPU cases; samples are perf_counter_ns around ctypes.

All outputs are diagnostic until a matching final freeze manifest is supplied.
No cycle count is inferred from CPU MHz or TSC reference-clock frequency.
"""
from __future__ import annotations

import argparse
import ctypes as ct
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import socket
import statistics
import subprocess
import sys
import time
import uuid
import math

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from native import NativeSlhDsa, NAMES, _buffer
from signing_budget import SigningBudget, canonical_algorithm
canonical_key_id = SigningBudget.key_id

SCHEMA = "a15-cpu-bench-v2"
ALGORITHMS = {pid: name for name, pid in NAMES.items()}
BACKENDS = {"REF": 1, "AVX2": 2}
HP = {1: 9, 2: 3, 3: 22, 101: 9, 102: 3, 103: 22, 201: 10}
SIG_BYTES = {1: 7856, 2: 17088, 3: 3856, 101: 7856, 102: 17088, 103: 3856, 201: 2320}
OPS = ("keygen", "sign", "verify", "cache_build", "cache_load")
BUILD_FILES = ["c/Makefile", "c/include/slhdsa_sm3.h", "c/src/engine.c",
               "c/src/sm3.c", "c/src/sm3.h", "c/src/sm3x8.c", "c/src/sm3x8.h",
               "c/src/secure_zero.h",
               "c/src/sm3_cuda.h", "c/src/sm3_cuda_stub.c", "c/src/sm3_cuda_device.cuh",
               *["third_party/slhdsa-c/" + p for p in
                 ("sha2_256.c", "sha2_512.c", "sha2_api.h", "sha3_api.c",
                  "sha3_api.h", "sha3_f1600.c", "plat_local.h")]]
TOOL_FILES = ["tools/bench_cpu.py", "tools/bench_sm3_harness.c", "tools/native.py", "tools/signing_budget.py", "tools/count_model.py", "reference/sm3.py"]


def utc():
    return datetime.now(timezone.utc).isoformat()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hashes(files):
    return {name: file_sha(ROOT / name) for name in files}


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def atomic_json(path, value, private=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise ValueError("artifact already exists: " + str(path))
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600 if private else 0o644)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(value, indent=2, ensure_ascii=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        # Same-directory hard link publishes without replacing a racing writer.
        os.link(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def append(path, row):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(canonical({"schema": SCHEMA, "ts": utc(), **row}) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def rows(path):
    path = Path(path)
    if not path.exists():
        return []
    content = path.read_bytes()
    if content and not content.endswith(b"\n"):
        raise ValueError("incomplete trailing JSONL line; preserve file and start a fresh campaign")
    result = []
    for number, line in enumerate(content.splitlines(), 1):
        try:
            row = json.loads(line)
        except ValueError as exc:
            raise ValueError(f"invalid preserved JSONL line {number}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"JSONL line {number} must be an object")
        row["_line"] = number
        result.append(row)
    return result


def command(argv, timeout=20, env=None):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                                cwd=ROOT, env={**(os.environ if env is None else env), "LC_ALL": "C"})
        return {"argv": argv, "returncode": result.returncode,
                "stdout": result.stdout.strip(), "stderr": result.stderr.strip()}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"argv": argv, "error": str(exc)}


def read_text(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def topology_from_csv(text, allowed=None):
    result = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split(",")
        if len(fields) != 5:
            raise ValueError("unexpected lscpu CPU,CORE,SOCKET,NODE,ONLINE row")
        cpu, core, sock, node, online = fields
        if online.upper() not in ("Y", "YES", "1") or (allowed is not None and int(cpu) not in allowed):
            continue
        result.append({"cpu": int(cpu), "core": int(core), "socket": int(sock),
                       "node": int(node) if node not in ("", "-") else None})
    return sorted(result, key=lambda r: (r["node"] if r["node"] is not None else -1,
                                        r["socket"], r["core"], r["cpu"]))


def physical_cpus(topology, count, explicit=None):
    if not 1 <= count <= 64:
        raise ValueError("physical core count must be 1..64")
    choices, seen = [], set()
    by_cpu = {r["cpu"]: r for r in topology}
    if explicit is not None and (len(set(explicit)) != len(explicit) or any(c not in by_cpu for c in explicit)):
        raise ValueError("explicit affinity repeats or includes disallowed CPUs")
    candidates = [by_cpu[c] for c in explicit] if explicit is not None else topology
    for row in candidates:
        key = (row["socket"], row["core"])
        if key in seen:
            if explicit is not None:
                raise ValueError("explicit affinity includes SMT siblings of one physical core")
            continue
        choices.append(row)
        seen.add(key)
    if len(choices) < count:
        raise ValueError(f"need {count} allowed physical cores; have {len(choices)}")
    return choices[:count]


def topology():
    info = command(["lscpu", "-p=CPU,CORE,SOCKET,NODE,ONLINE"])
    if info.get("returncode") != 0:
        return [], info
    allowed = set(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None
    return topology_from_csv(info["stdout"], allowed), info


def bind(case, formal, explicit):
    topo, raw = topology()
    if not topo or not hasattr(os, "sched_setaffinity"):
        if formal:
            raise ValueError("formal cases require Linux physical-core affinity")
        return {"verified_physical": False, "requested_cores": case["threads"],
                "cpus": [], "nodes": [], "cross_numa": None, "lscpu": raw,
                "reason": "diagnostic host without Linux affinity"}
    selected = physical_cpus(topo, case["threads"], explicit)
    cpus = [row["cpu"] for row in selected]
    os.sched_setaffinity(0, cpus)
    if set(os.sched_getaffinity(0)) != set(cpus):
        raise ValueError("kernel affinity differs from requested physical CPUs")
    nodes = sorted({r["node"] for r in selected if r["node"] is not None})
    return {"verified_physical": True, "cpus": cpus, "physical_cores": selected,
            "nodes": nodes, "cross_numa": len(nodes) > 1,
            "memory_policy": "kernel default; first touch under worker affinity; no numactl memory binding",
            "lscpu": raw}


def openmp_environment(threads, cpus):
    result = {"OMP_NUM_THREADS": str(threads), "OMP_DYNAMIC": "FALSE",
              "OMP_PROC_BIND": "close", "OMP_MAX_ACTIVE_LEVELS": "1"}
    result["OMP_PLACES"] = ",".join("{" + str(cpu) + "}" for cpu in cpus) if cpus else "cores"
    return result


def environment(affinity):
    cpus = affinity["cpus"]
    governors, frequency = {}, {}
    for cpu in cpus:
        folder = Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq")
        governors[str(cpu)] = read_text(folder / "scaling_governor")
        frequency[str(cpu)] = {name: read_text(folder / name) for name in
                               ("scaling_cur_freq", "cpuinfo_cur_freq", "scaling_min_freq", "scaling_max_freq")}
    boost = {name: read_text(path) for name, path in {
        "generic_boost": "/sys/devices/system/cpu/cpufreq/boost",
        "intel_no_turbo": "/sys/devices/system/cpu/intel_pstate/no_turbo"}.items()}
    return {"host": socket.gethostname(), "cpu": platform.processor(), "platform": platform.platform(),
            "python": sys.version, "lscpu": command(["lscpu", "-J"]),
            "affinity": affinity, "numa": command(["numactl", "--show"]),
            "governor": governors, "turbo": boost, "frequency_khz": frequency,
            "loadavg": list(os.getloadavg()) if hasattr(os, "getloadavg") else None,
            "proc_loadavg": read_text("/proc/loadavg"),
            "clocksource": read_text("/sys/devices/system/clocksource/clocksource0/current_clocksource"),
            "available_clocksources": read_text("/sys/devices/system/clocksource/clocksource0/available_clocksource"),
            "clock": vars(time.get_clock_info("perf_counter")),
            "tsc": {"use": "not sampled; if supplied externally it is reference-clock only",
                    "core_cycles": None},
            "openmp": {k: v for k, v in os.environ.items() if k.startswith(("OMP_", "GOMP_", "KMP_"))}}


def sample_environment(cpus):
    return {"loadavg": list(os.getloadavg()) if hasattr(os, "getloadavg") else None,
            "frequency_khz": {str(cpu): read_text(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_cur_freq") for cpu in cpus}}


def environment_identity(info):
    """Stable conditions for resume; changing load/frequency are observations."""
    raw = info.get("lscpu", {}).get("stdout", "")
    try:
        fields = json.loads(raw).get("lscpu", [])
        cpu = [row for row in fields if "scaling MHz" not in row.get("field", "")
               and row.get("field", "") not in ("CPU MHz:", "BogoMIPS:")]
    except (ValueError, AttributeError):
        cpu = raw
    keys = ("host", "cpu", "platform", "python", "governor", "turbo", "clocksource", "clock", "openmp")
    return {**{key: info.get(key) for key in keys}, "cpu_topology": cpu,
            "affinity": {k: info.get("affinity", {}).get(k) for k in ("verified_physical", "cpus", "physical_cores", "nodes", "cross_numa", "memory_policy")}}


def resume_samples(existing, case, input_hashes):
    good = {}
    for row in existing:
        if row.get("kind") != "sample" or row.get("passed") is not True:
            continue
        index = row.get("sample_index")
        duration = row.get("duration_ns")
        if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < case["samples"]:
            raise ValueError("preserved sample index outside case range")
        if index in good:
            raise ValueError("duplicate passed sample index in preserved evidence")
        if not isinstance(duration, int) or isinstance(duration, bool) or duration <= 0:
            raise ValueError("preserved sample duration is invalid")
        if row.get("input_hashes") != input_hashes:
            raise ValueError("preserved sample input hashes differ")
        good[index] = row
    return good


def budget_binding(budget, case, inputs):
    encoded = b"\x00" + bytes([len(inputs["context"])]) + inputs["context"] + inputs["message"]
    return {"ledger_uuid": budget.ledger_uuid, "algorithm": canonical_algorithm(ALGORITHMS[case["pid"]]),
            "key_id": canonical_key_id(ALGORITHMS[case["pid"]], inputs["pk"]),
            "public_key_sha256": sha(inputs["pk"]), "message_sha256": sha(encoded)}


def receipt_evidence(budget, receipt):
    return budget.validate_receipt(receipt, statuses=("committed", "failed", "reserved")) if receipt else None


def failure_receipt_evidence(budget, receipt, original):
    try:
        return receipt_evidence(budget, receipt)
    except Exception as failure:
        original.add_note("budget reconciliation also failed: " + str(failure))
        return None  # Missing reconciliation prevents later resume.


def validate_fixture_receipts(fixtures, pid, budget):
    folder = Path(fixtures).resolve()
    signature_path = folder / f"p{pid}-signature.json"
    if not signature_path.exists():
        return  # Imported independent vectors have no newly charged signature.
    record = read_json(folder / f"p{pid}-fixture.json")
    saved = read_json(signature_path)
    if saved.get("ledger_uuid") != budget.ledger_uuid or saved.get("fixture_sha256") != file_sha(folder / f"p{pid}-fixture.json"):
        raise ValueError("fixture signature ledger/input binding differs")
    message, context, public = (bytes.fromhex(record[k]) for k in ("message", "context", "pk"))
    encoded = b"\x00" + bytes([len(context)]) + context + message
    budget.validate_receipt(saved.get("receipt"), algorithm=ALGORITHMS[pid], public_key=public,
                            message=encoded, signature=bytes.fromhex(saved["sig"]))


def validate_preserved_budget(existing, case, budget):
    """Audit even complete cases before skipping; no native calls or timers."""
    ready = [row for row in existing if row.get("kind") == "inputs_ready"]
    for row in existing:
        if row.get("kind") in ("case_start", "inputs_ready", "case_complete") and row.get("ledger_uuid") != budget.ledger_uuid:
            raise ValueError("preserved case ledger UUID differs or is missing")
    binding = ready[0].get("budget_binding") if ready else None
    if ready:
        if (not isinstance(binding, dict) or binding.get("ledger_uuid") != budget.ledger_uuid
                or binding.get("algorithm") != canonical_algorithm(ALGORITHMS[case["pid"]])
                or binding.get("public_key_sha256") != ready[0]["input_hashes"].get("pk")
                or any(row.get("budget_binding") != binding for row in ready)):
            raise ValueError("preserved input budget binding differs")
    requests = []
    for row in existing:
        if row.get("kind") in ("operation_start", "sample", "warmup"):
            if row.get("receipt"):
                requests.append({"receipt": row["receipt"], "statuses": ("committed", "failed", "reserved")})
            token = (row.get("validation") or {}).get("rng_validation_receipt")
            if token:
                requests.append({"receipt": token})
    live = ({value["receipt"]: value for value in budget.validate_receipts(requests)}
            if hasattr(budget, "validate_receipts") else
            {request["receipt"]: budget.validate_receipt(**request) for request in requests})
    seen = set()
    for row in existing:
        if row.get("kind") not in ("operation_start", "sample", "warmup"):
            continue
        receipt = row.get("receipt")
        if case["op"] == "sign":
            if not receipt or binding is None:
                raise ValueError("preserved signing operation lacks receipt/input binding")
            evidence = row.get("budget_evidence")
            if not isinstance(evidence, dict) or evidence.get("receipt") != receipt or any(evidence.get(k) != v for k, v in binding.items()):
                raise ValueError("preserved receipt key/message/ledger binding differs")
            if row.get("kind") == "operation_start":
                if evidence.get("status") != "reserved" or evidence.get("signature_sha256") is not None:
                    raise ValueError("preserved reservation evidence is not a fresh charged attempt")
                if any(live[receipt].get(k) != v for k, v in binding.items()) or live[receipt].get("receipt") != receipt:
                    raise ValueError("live reservation identity differs")
                continue  # A killed attempt may remain reserved or finish before result emission.
            if row.get("passed", True) and (evidence.get("status") != "committed" or
                    (row.get("kind") == "sample" and evidence.get("signature_sha256") != row.get("result_sha256"))):
                raise ValueError("passed signing sample receipt/signature differs")
            if receipt in seen:
                raise ValueError("preserved signing receipt reused across operations")
            seen.add(receipt)
            if live[receipt] != evidence:
                raise ValueError("live receipt differs from preserved operation")
        elif receipt is not None:
            raise ValueError("non-signing operation has a signing receipt")
        validation = row.get("validation") or {}
        rng_receipt = validation.get("rng_validation_receipt")
        if rng_receipt:
            evidence = validation.get("budget_evidence")
            if (not isinstance(evidence, dict) or evidence.get("ledger_uuid") != budget.ledger_uuid
                    or evidence.get("algorithm") != canonical_algorithm(ALGORITHMS[case["pid"]])
                    or evidence.get("message_sha256") != binding["message_sha256"]
                    or evidence.get("public_key_sha256") != validation.get("public_key_sha256")
                    or evidence.get("status") != "committed" or rng_receipt in seen
                    or live[rng_receipt] != evidence):
                raise ValueError("RNG validation receipt differs from live ledger")
            seen.add(rng_receipt)


def execution_binding(case, prov, identity, ledger_uuid, plan_digest, schema=SCHEMA):
    """Identity shared by every record of a case, including failed attempts."""
    keys = ("source_sha256", "library_sha256", "build_record_sha256", "freeze_sha256", "final", "classification")
    return {"schema": schema, "case": case, "plan_sha256": plan_digest,
            "provenance": {key: prov.get(key) for key in keys},
            "environment_identity": identity, "ledger_uuid": ledger_uuid}


def binding_fields(binding):
    case, prov = binding["case"], binding["provenance"]
    backend = 5 if case["backend"] == "CUDA" else BACKENDS[case["backend"]]
    return {"case_id": case["case_id"], "pid": case["pid"], "op": case["op"],
            "backend": case["backend"], "actual_backend": backend, "threads": case["threads"],
            "cores": case["threads"], "requested_cache_t": case.get("cache"),
            "cache_t": case.get("cache_t"), "keygen_mode": case.get("keygen_mode"),
            "family": case.get("family"), "final": prov["final"], "classification": prov["classification"],
            "ledger_uuid": binding["ledger_uuid"], "execution_binding": binding}


def emit_bound(emit, path, binding, segment_id, row):
    fields = binding_fields(binding)
    if any(key in row and row[key] != value for key, value in fields.items()):
        raise ValueError("attempted record metadata differs from case binding")
    operation = ({"operation_id": row.get("operation_id", uuid.uuid4().hex)}
                 if row["kind"] in ("operation_start", "warmup", "sample") else {})
    untimed = {"timed": False} if row["kind"] in ("operation_start", "warmup") else {}
    emit(path, {**untimed, **row, **fields, "case_key": sha(canonical(binding).encode()),
                "segment_id": segment_id, **operation})


def validate_case_records(existing, case, expected_binding=None):
    if not existing:
        return
    starts = [r for r in existing if r.get("kind") == "case_start"]
    if not starts:
        raise ValueError("preserved case lacks execution segment start")
    binding = starts[0].get("execution_binding")
    if (not isinstance(binding, dict) or binding.get("case") != case or
            expected_binding is not None and binding != expected_binding):
        raise ValueError("preserved case identity differs from plan/build/environment")
    try:
        fields, key = binding_fields(binding), sha(canonical(binding).encode())
        if not isinstance(binding["environment_identity"], dict) or not isinstance(binding["provenance"], dict):
            raise ValueError("malformed execution identity")
    except (KeyError, TypeError) as error:
        raise ValueError("preserved execution binding is malformed") from error
    segments, warmed, ready, passed_indices, operations, outcomes = {}, {}, {}, set(), {}, set()
    stopped, pending, completed = set(), {}, False
    for row in existing:
        if row.get("schema") != binding.get("schema") or row.get("case_key") != key:
            raise ValueError("preserved case schema/key differs from bound identity")
        if any(row.get(name) != value for name, value in fields.items()):
            raise ValueError("preserved record metadata differs from case binding")
        segment = row.get("segment_id")
        if not isinstance(segment, str) or not re.fullmatch("[0-9a-f]{32}", segment):
            raise ValueError("preserved record lacks execution segment identity")
        kind = row.get("kind")
        if completed:
            raise ValueError("preserved case has records after completion")
        if kind == "case_start":
            if segment in segments or row.get("case") != case or row.get("environment_identity") != binding["environment_identity"]:
                raise ValueError("preserved execution segment start differs or repeats")
            prov = row.get("provenance", {})
            if any(prov.get(k) != v for k, v in binding["provenance"].items()):
                raise ValueError("preserved segment build provenance differs")
            segments[segment], warmed[segment] = row, set()
        elif segment not in segments:
            raise ValueError("preserved operation precedes its execution segment")
        if kind == "inputs_ready":
            if segment in ready or not isinstance(row.get("input_hashes"), dict) or not isinstance(row.get("input_files"), dict):
                raise ValueError("preserved segment inputs missing or repeated")
            if ready and any(row.get(k) != next(iter(ready.values())).get(k) for k in ("input_hashes", "input_files", "budget_binding")):
                raise ValueError("preserved segment immutable input binding differs")
            ready[segment] = row
        if kind in ("operation_start", "warmup", "sample"):
            if kind in ("operation_start", "warmup") and row.get("timed") is not False:
                raise ValueError("preserved setup/warmup incorrectly claims timing")
            if segment in stopped:
                raise ValueError("preserved segment continued after a failed operation")
            if segment not in ready or row.get("input_hashes") != ready[segment]["input_hashes"]:
                raise ValueError("preserved operation input/segment binding differs")
            if not isinstance(row.get("operation_id"), str) or not re.fullmatch("[0-9a-f]{32}", row["operation_id"]):
                raise ValueError("preserved operation identity is missing")
            operation_id = row["operation_id"]
            operation_kind = row.get("operation_kind") if kind == "operation_start" else kind
            if operation_kind not in ("warmup", "sample"):
                raise ValueError("preserved operation kind differs")
            index_field = "index" if operation_kind == "warmup" else "sample_index"
            if kind == "operation_start":
                if operation_id in operations or segment in pending:
                    raise ValueError("preserved operation start repeated or precedes prior outcome")
                operations[operation_id] = row
                pending[segment] = operation_id
            else:
                start = operations.get(operation_id)
                if (not start or operation_id in outcomes or start.get("segment_id") != segment or
                        start.get("operation_kind") != kind or start.get(index_field) != row.get(index_field) or
                        start.get("receipt") != row.get("receipt") or pending.get(segment) != operation_id):
                    raise ValueError("preserved result lacks matching operation reservation")
                outcomes.add(operation_id)
                del pending[segment]
            if kind != "operation_start" and not isinstance(row.get("passed"), bool):
                raise ValueError("preserved operation status is missing")
            if kind != "operation_start" and not row["passed"]:
                if not isinstance(row.get("error"), str) or not row["error"]:
                    raise ValueError("preserved failed attempt lacks diagnostic status")
                stopped.add(segment)
            if operation_kind == "warmup":
                index = row.get("index")
                if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < case["warmups"] or index in warmed[segment]:
                    raise ValueError("preserved warmup index invalid or repeated")
                if kind != "operation_start" and row["passed"]:
                    warmed[segment].add(index)
            else:
                index = row.get("sample_index")
                if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < case["samples"]:
                    raise ValueError("preserved sample index outside case range")
                if len(warmed[segment]) != case["warmups"]:
                    raise ValueError("preserved sample lacks its segment warmups")
                if kind != "operation_start" and row["passed"]:
                    if index in passed_indices:
                        raise ValueError("duplicate passed sample index in preserved evidence")
                    passed_indices.add(index)
        if kind == "case_complete":
            if segment not in ready or segment in stopped or segment in pending:
                raise ValueError("completion segment lacks ready/successful finalized operations")
            completed = True
            reference = next(iter(ready.values()), None)
            if reference is None or any(row.get(k) != reference.get(k) for k in ("input_hashes",)) or row.get("input_files_before") != reference["input_files"] or row.get("input_files_after") != reference["input_files"]:
                raise ValueError("completion input binding differs from segment inputs")
            prov = binding["provenance"]
            for field in ("source_sha256", "library_sha256"):
                if any(row.get(field+suffix) != prov[field] for suffix in ("_before", "_after")):
                    raise ValueError("completion source/library provenance differs")
            if any(row.get(k) != prov[k] for k in ("build_record_sha256", "freeze_sha256")) or row.get("environment_identity") != binding["environment_identity"]:
                raise ValueError("completion build/environment provenance differs")
            expected_lines = [r["_line"] for r in existing if r.get("kind") == "sample" and r.get("passed") and "_line" in r]
            if len(expected_lines) == len(passed_indices) and row.get("sample_lines") != expected_lines:
                raise ValueError("completion sample line references differ")


def audit_campaign_evidence(evidence, plan, budget, fixtures, schema=SCHEMA, provenance=None, plan_digest=None,
                            sample_validator=None, completion_validator=None):
    """Audit every case before filtering/skipping; fixture references are reusable."""
    if any(r.get("schema") != schema for r in evidence):
        raise ValueError("legacy/foreign benchmark evidence: preserve it and start a fresh v2 campaign; no implicit migration")
    cases = {c["case_id"]: c for c in plan["cases"]}
    grouped, operations, receipts, result_operations, case_keys = {}, set(), {}, set(), {}
    campaigns = [row for row in evidence if row.get("kind") == "campaign_start"]
    if len(campaigns) > 1:
        raise ValueError("preserved campaign start repeated")
    if campaigns:
        campaign = campaigns[0]
        if (evidence[0] is not campaign or campaign.get("ledger_uuid") != budget.ledger_uuid or
                provenance is not None and campaign.get("provenance") != provenance or
                schema == SCHEMA and plan_digest is not None and campaign.get("plan_sha256") != plan_digest):
            raise ValueError("preserved campaign metadata differs from current plan/build/ledger")
    fixture_receipts = set()
    for path in Path(fixtures).glob("p*-signature.json"):
        saved = read_json(path)
        receipt = saved.get("receipt")
        if receipt:
            fixture_receipts.add(receipt)
    for row in evidence:
        case_kinds = ("case_start", "inputs_ready", "setup_cache", "operation_start", "warmup", "sample", "case_complete")
        allowed = case_kinds + ("campaign_start", "setup_signature", "case_unavailable", "case_process_timeout", "case_process_failed")
        if row.get("kind") not in allowed or row.get("kind") in case_kinds and not row.get("case_key"):
            raise ValueError("preserved record kind/case identity missing or unknown")
        if row.get("case_key"):
            if row.get("case_id") not in cases:
                raise ValueError("preserved case absent from current plan")
            previous_key = case_keys.setdefault(row["case_id"], row["case_key"])
            if previous_key != row["case_key"]:
                raise ValueError("preserved case split across different execution identities")
            grouped.setdefault(row["case_key"], []).append(row)
        if row.get("kind") == "setup_signature":
            if row.get("case_id") not in cases:
                raise ValueError("signature setup absent from current plan")
            pid = cases[row["case_id"]]["pid"]
            saved = read_json(Path(fixtures)/f"p{pid}-signature.json")
            validate_fixture_receipts(fixtures, pid, budget)
            if (row.get("timed") is not False or row.get("ledger_uuid") != budget.ledger_uuid or
                    row.get("receipt") != saved.get("receipt") or
                    row.get("budget_evidence") != budget.validate_receipt(saved.get("receipt"))):
                raise ValueError("signature setup receipt/ledger metadata differs from fixture")
        if row.get("kind") in ("case_unavailable", "case_process_timeout", "case_process_failed") and row.get("case_id") not in cases:
            raise ValueError("preserved process outcome absent from current plan")
        if row.get("kind") in ("operation_start", "sample", "warmup"):
            operation = row.get("operation_id")
            if row["kind"] == "operation_start":
                if not operation or operation in operations:
                    raise ValueError("campaign operation identity missing or reused")
                operations.add(operation)
            elif operation not in operations or operation in result_operations:
                raise ValueError("campaign result operation identity missing or reused")
            else:
                result_operations.add(operation)
            tokens = [row.get("receipt"), (row.get("validation") or {}).get("rng_validation_receipt")]
            for token in filter(None, tokens):
                owner = receipts.get(token)
                if (owner is not None and owner != operation) or token in fixture_receipts:
                    raise ValueError("campaign signing receipt reused across independent operations/fixture")
                receipts[token] = operation
    for existing in grouped.values():
        case = cases[existing[0]["case_id"]]
        binding = existing[0].get("execution_binding") or {}
        expected = (execution_binding(case, provenance, binding.get("environment_identity"),
                                      budget.ledger_uuid, plan_digest, schema) if provenance is not None else None)
        validate_case_records(existing, case, expected)
        if campaigns:
            identity = binding["environment_identity"]
            host = identity if schema == SCHEMA else identity.get("cpu", {})
            # Parent placement differs from per-case worker OMP/affinity by design.
            if ({k: v for k, v in host.items() if k not in ("affinity", "openmp")} !=
                    {k: v for k, v in campaigns[0].get("host_environment", {}).items() if k not in ("affinity", "openmp")} or
                    schema != SCHEMA and identity.get("gpu") != campaigns[0].get("gpu_environment", {}).get("identity")):
                raise ValueError("preserved campaign host/device metadata differs from case")
        validate_preserved_budget(existing, case, budget)
        inputs = next((r for r in existing if r.get("kind") == "inputs_ready"), None)
        for setup in (row for row in existing if row.get("kind") == "setup_cache"):
            if case.get("cache_t") is None or case["op"] not in ("sign", "cache_load") or setup.get("timed") is not False:
                raise ValueError("preserved cache setup differs from planned operation")
            fixture_record = read_json(Path(fixtures)/f"p{case['pid']}-fixture.json")
            cache = Path(fixtures)/f"p{case['pid']}-{sha(bytes.fromhex(fixture_record['pk']))[:16]}-t{case['cache_t']}.cache"
            if setup.get("cache_file_sha256") != file_sha(cache):
                raise ValueError("preserved cache setup hash differs from input file")
        if inputs:
            (sample_validator or resume_samples)(existing, case, inputs["input_hashes"])
            for name, digest in inputs["input_files"].items():
                path = Path(name).resolve()
                if not path.is_relative_to(Path(fixtures).resolve()) or file_sha(path) != digest:
                    raise ValueError("preserved case input file changed or leaves fixture directory")
            record = read_json(Path(fixtures)/f"p{case['pid']}-fixture.json")
            values = {k: bytes.fromhex(record[k]) for k in ("pk", "message", "context")}
            if (inputs.get("budget_binding") != budget_binding(budget, case, values) or
                    any(inputs["input_hashes"].get(k) != sha(v) for k, v in values.items())):
                raise ValueError("preserved fixture budget/input binding differs")
            validate_fixture_receipts(fixtures, case["pid"], budget)
        if any(r.get("kind") == "case_complete" for r in existing):
            (completion_validator or validate_completed)(existing, case, fixtures, budget, expected)


def validate_completed(existing, case, fixtures, budget=None, expected_binding=None):
    validate_case_records(existing, case, expected_binding)
    if budget is not None:
        validate_preserved_budget(existing, case, budget)
    complete = [row for row in existing if row.get("kind") == "case_complete"]
    if not complete:
        return False
    if len(complete) != 1:
        raise ValueError("duplicate case completion records")
    inputs = [row for row in existing if row.get("kind") == "inputs_ready"]
    if not inputs or any(row.get("input_hashes") != inputs[0].get("input_hashes") or
                         row.get("input_files") != inputs[0].get("input_files") for row in inputs):
        raise ValueError("completed case lacks one immutable input binding")
    for name, digest in inputs[0]["input_files"].items():
        path = Path(name).resolve()
        if not path.is_relative_to(Path(fixtures).resolve()) or file_sha(path) != digest:
            raise ValueError("completed case input file changed or leaves fixture directory")
    if budget is not None:
        record = read_json(Path(fixtures) / f"p{case['pid']}-fixture.json")
        values = {k: bytes.fromhex(record[k]) for k in ("pk", "message", "context")}
        if (inputs[0].get("budget_binding") != budget_binding(budget, case, values)
                or any(inputs[0]["input_hashes"].get(k) != sha(v) for k, v in values.items())):
            raise ValueError("completed case budget binding differs from immutable fixture")
    good = resume_samples(existing, case, inputs[0]["input_hashes"])
    if len(good) != case["samples"]:
        raise ValueError("completed case lacks all unique passed samples")
    values = [good[index]["duration_ns"] for index in range(case["samples"])]
    if any(complete[0].get(k) != v for k, v in summary(values).items()) or complete[0].get("samples") != values:
        raise ValueError("completion statistics differ from preserved raw samples")
    return True


@contextmanager
def output_lock(path):
    """Kernel releases the lock after interruption; the sidecar stays for resume."""
    path = Path(str(path)+".lock")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as stream:
        if os.name == "nt":
            import msvcrt
            stream.seek(0, os.SEEK_END)
            if stream.tell() == 0:
                stream.write(b"\0")
                stream.flush()
            stream.seek(0)
            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise ValueError("another campaign owns this output") from exc
            try:
                yield
            finally:
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise ValueError("another campaign owns this output") from exc
            try:
                yield
            finally:
                fcntl.flock(stream, fcntl.LOCK_UN)


def protected_paths(args):
    output = args.output.resolve()
    inputs = [args.plan, args.library, args.build_record, args.freeze, args.budget_db]
    if output.suffix.lower() != ".jsonl" or any(x and output == Path(x).resolve() for x in inputs):
        raise ValueError("output must be a separate .jsonl evidence file")
    if output.is_relative_to(args.fixtures.resolve()):
        raise ValueError("evidence output must be outside immutable fixtures")
    if args.budget_db.resolve().is_relative_to(args.fixtures.resolve()):
        raise ValueError("mutable signing ledger must be outside immutable fixtures")


def quantile(values, probability):
    """Type 7 linear interpolation, including the n=1 case."""
    if not 0 <= probability <= 1:
        raise ValueError("quantile probability outside 0..1")
    data = sorted(values)
    if not data:
        raise ValueError("empty samples")
    position = (len(data) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(data) - 1)
    return data[lower] + (data[upper] - data[lower]) * (position - lower)


def summary(values):
    if not values or any(not isinstance(v, int) or isinstance(v, bool) or v <= 0 for v in values):
        raise ValueError("sample durations must be positive integer nanoseconds")
    q1, q3 = quantile(values, .25), quantile(values, .75)
    return {"n": len(values), "median": statistics.median(values), "q1": q1,
            "q3": q3, "iqr": q3 - q1, "min": min(values), "max": max(values),
            "unit": "ns", "quartile_method": "Hyndman-Fan type 7 linear interpolation"}


def minimum_samples(case):
    if case["op"] == "verify":
        return 10000
    if case["pid"] in (3, 103):
        return 30 if case["op"] == "sign" and case["cache"] != "none" else 5
    return 100 if case["op"] == "sign" else 5


def case_record(pid, op, backend="REF", cache="none", threads=1, family="R3", keygen="seeded", samples=None):
    cache = str(cache)
    effective = None if cache == "none" else min(int(cache), HP[pid])
    case = {"pid": pid, "op": op, "backend": backend, "cache": cache,
            "cache_t": effective, "threads": threads, "family": family,
            "keygen_mode": keygen if op == "keygen" else None,
            "warmups": 0 if op in ("keygen", "cache_build") or pid in (3, 103) and op == "sign" else 1}
    case["samples"] = minimum_samples(case) if samples is None else samples
    case["case_id"] = f"{family}-p{pid}-{op}-{backend}-c{cache}-p{threads}" + ("-" + keygen if op == "keygen" else "")
    return case


def make_plan(suite, pids, threads, r4_levels, samples=None):
    if len(set(pids)) != len(pids) or len(set(threads)) != len(threads) or len(set(r4_levels)) != len(r4_levels):
        raise ValueError("plan parameter/thread/cache lists must be unique")
    if any(pid not in HP for pid in pids) or any(not 1 <= t <= 64 for t in threads) or any(not 0 <= t <= 22 for t in r4_levels):
        raise ValueError("plan parameters, physical threads or cache levels outside supported ranges")
    cases = []
    if suite == "smoke":
        cases = [case_record(201, op, cache="5" if op in ("cache_build", "cache_load", "keygen") else "none",
                             family="smoke", samples=2) for op in OPS]
        cases += [case_record(201, "sign", cache="5", family="smoke", samples=2)]
    else:
        if suite in ("r3", "all"):
            for pid in pids:
                choices = ("REF", "AVX2") if pid < 100 else ("REF",)
                for backend in choices:
                    for mode in ("seeded", "rng"):
                        # Native key generation always records a root cache. State
                        # t explicitly instead of labelling it as cache=none.
                        cases.append(case_record(pid, "keygen", backend, "12", keygen=mode, samples=samples))
                    for cache in ("none", "12", "0"):
                        cases.append(case_record(pid, "sign", backend, cache, samples=samples))
                    cases.append(case_record(pid, "verify", backend, samples=samples))
        if suite in ("r4", "all"):
            for pid in (p for p in pids if p in (3, 103)):
                for t in r4_levels:
                    for backend in (("REF", "AVX2") if pid == 3 else ("REF",)):
                        for op in ("cache_build", "cache_load", "sign"):
                            cases.append(case_record(pid, op, backend, str(t), family="R4", samples=samples))
        if suite in ("r5", "all"):
            for pid in pids:
                # Matched REF/AVX2 at every p/cache gives SIMD comparisons; REF
                # p>1 versus REF p=1 is the OpenMP-only control.
                configurations = [(backend, cache, count)
                    for backend in (("REF", "AVX2") if pid < 100 else ("REF",))
                    for cache in ("none", "12") for count in threads]
                for backend, cache, count in configurations:
                    cases.append(case_record(pid, "sign", backend, cache, count, "R5", samples=samples))
                for backend in (("REF", "AVX2") if pid < 100 else ("REF",)):
                    for count in threads:
                        for mode in ("seeded", "rng"):
                            cases.append(case_record(pid, "keygen", backend, "12", count,
                                                     "R5", keygen=mode, samples=samples))
    for case in cases:
        validate_case(case)
    if not cases:
        raise ValueError("selected suite/parameters have no cases")
    if len({case["case_id"] for case in cases}) != len(cases):
        raise ValueError("duplicate generated case IDs")
    return {"schema": "a15-cpu-plan-v1", "created_utc": utc(), "suite": suite,
            "formal_minimums": "verify=10000; small sign>=100; limited cached sign>=30; limited uncached/keygen=5",
            "cases": cases, "diagnostic_sample_override": samples is not None or suite == "smoke",
            "case_order": "listed order, independent sequential subprocesses",
            "comparison_policy": "REF/AVX2 matched pid/input/cache/physical threads; REF scaling is OpenMP-only",
            "r4_sampling": "each requested t has build=5/load=5/sign=30 by default; default t=0..22",
            "estimated_timed_signatures": sum(c["samples"]+c["warmups"] for c in cases if c["op"] == "sign"),
            "r4_theoretical_storage": [{"t": t, "payload_bytes": 16 * (1 << (22 - t)),
                "file_bytes": 96 + 16 * (1 << (22 - t)), "node_ram_bytes": 16 * ((1 << (23 - t)) - 1)} for t in range(23)]}


def validate_case(case):
    if case["pid"] not in HP or case["op"] not in OPS or case["backend"] not in BACKENDS:
        raise ValueError("invalid case parameter/operation/backend")
    if case["pid"] >= 100 and case["pid"] != 201 and case["backend"] != "REF":
        raise ValueError("SHA2 uses REF")
    if not 1 <= case["threads"] <= 64 or case["samples"] < 1 or case["warmups"] < 0:
        raise ValueError("invalid case cores/samples/warmups")
    if case["cache"] != "none" and not 0 <= int(case["cache"]) <= 22:
        raise ValueError("invalid requested cache height")
    expected = None if case["cache"] == "none" else min(int(case["cache"]), HP[case["pid"]])
    if case["cache_t"] != expected:
        raise ValueError("case effective cache level differs from parameter height")
    if case["op"] in ("cache_build", "cache_load") and case["cache"] == "none":
        raise ValueError("cache operations require a cache height")
    if case["op"] == "keygen" and (case["cache_t"] is None or case["keygen_mode"] not in ("seeded", "rng")):
        raise ValueError("keygen requires an explicit native cache height and seeded/rng mode")


def validate_formal_plan(plan):
    if plan.get("diagnostic_sample_override"):
        raise ValueError("formal campaign rejects diagnostic sample override")
    for case in plan["cases"]:
        if case["samples"] < minimum_samples(case) or case["pid"] == 201:
            raise ValueError("formal campaign has insufficient samples or toy parameter")


def build(args):
    output = args.out.resolve()
    # A build never replaces an existing measurement binary or directory.
    output.mkdir(parents=True, exist_ok=False)
    record = output / "build-record.json"
    if record.exists():
        raise ValueError("build record already exists; choose a fresh build directory")
    flags = args.cflags
    tokens = shlex.split(flags)
    if not tokens or any(token not in ("-O2", "-O3", "-DNDEBUG") for token in tokens):
        raise ValueError("benchmark CFLAGS allow only -O2/-O3/-DNDEBUG; no instrumentation, response files or global ISA flags")
    if not args.cc or not re.fullmatch(r"[A-Za-z0-9_./+-]+", args.cc):
        raise ValueError("CC must name one compiler executable without make/shell syntax")
    before = hashes(BUILD_FILES)
    argv = ["make", "-B", "-C", "c", "OUT=" + str(output), "CC=" + args.cc,
            "CFLAGS=" + flags, "AVX2=" + ("0" if args.portable else "1"), "COUNTERS=0", "CUDA=0", "all"]
    started = utc()
    build_env = {key: value for key, value in os.environ.items()
                 if key not in {"MAKEFLAGS", "MFLAGS", "MAKEOVERRIDES", "MAKELEVEL", "CFLAGS", "CPPFLAGS", "LDFLAGS", "BASE"}}
    result = command(argv, timeout=600, env=build_env)
    after = hashes(BUILD_FILES)
    library = output / "libslhdsa_sm3.so"
    if result.get("returncode") != 0 or before != after or not library.is_file():
        atomic_json(output / "build-failure.json", {"started_utc": started, "result": result, "before": before, "after": after})
        raise RuntimeError("benchmark build failed or sources changed")
    compile_argv = inspect_compile_output(result["stdout"], args.cc, library)
    if any(token not in compile_argv for token in tokens):
        raise ValueError("actual compiler command differs from requested optimization flags")
    compiler_path = shutil.which(args.cc)
    if compiler_path is None:
        raise ValueError("compiler executable disappeared after build")
    atomic_json(record, {"schema": "a15-cpu-build-v1", "started_utc": started, "finished_utc": utc(),
                         "command": argv, "compiler": command(shlex.split(args.cc) + ["--version"]),
                         "compiler_path": compiler_path, "compiler_sha256": file_sha(compiler_path),
                         "flags": flags, "compile_argv": compile_argv, "compile_output_checked": True,
                         "result": result, "source_sha256": after,
                         "library": str(library), "library_sha256": file_sha(library),
                         "counters": False, "test_injection": False, "sanitizer": False,
                         "tool_sha256": file_sha(Path(__file__)), "final": False})
    print(record)


def inspect_compile_output(output, compiler, library):
    matches = []
    for line in output.splitlines():
        try:
            argv = shlex.split(line)
        except ValueError:
            continue
        if argv and argv[0] == compiler and "-shared" in argv and "-o" in argv:
            matches.append(argv)
    if len(matches) != 1:
        raise ValueError("build output must contain exactly one shared-library compiler command")
    argv = matches[0]
    if argv[argv.index("-o")+1] != str(library):
        raise ValueError("compiler output path differs from fresh benchmark library")
    forbidden = r"SLH_(?:COUNTERS|TEST)|sanitize|profile|instrument|^-m|^-pg$|^@|^-include|^-specs|^-fplugin"
    if any(re.search(forbidden, token) for token in argv):
        raise ValueError("instrumentation or global ISA flag found in actual compiler command")
    if "-DSLH_RELEASE_BUILD" not in argv or "-fopenmp" not in argv or "-std=c11" not in argv:
        raise ValueError("actual compiler command lacks release/OpenMP/C11 flags")
    expected = {name.removeprefix("c/") if name.startswith("c/") else "../"+name
                for name in BUILD_FILES if name.endswith(".c")}
    if not expected.issubset(argv):
        raise ValueError("actual compiler command omits a hashed source")
    return argv


def validate_correctness_evidence(directory, freeze):
    """Recheck preserved files; budget dependencies are immutable package clones."""
    directory = Path(directory).resolve()
    schema = freeze.get("schema")
    field = {"a15-cpu-freeze-v1": "correctness_evidence",
             "a15-cuda-freeze-v1": "correctness_evidence_sha256"}.get(schema)
    if field is None:
        raise ValueError("formal freeze correctness evidence schema differs")

    def mapping(value, label):
        if not isinstance(value, dict) or not value:
            raise ValueError(label + " hash map is missing or empty")
        result = {}
        for name, digest in value.items():
            if not isinstance(name, str) or not name or not Path(name).is_absolute():
                raise ValueError(label + " requires absolute file paths")
            target = Path(name).resolve()
            if target != Path(name):
                raise ValueError(label + " requires canonical absolute file paths")
            if target in result:
                raise ValueError(label + " contains duplicate resolved file paths")
            if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                raise ValueError(label + " SHA256 is malformed")
            result[target] = digest
        return result

    evidence = mapping(freeze.get(field), "formal freeze correctness evidence")
    snapshots = freeze.get("budget_snapshots", [])
    if not isinstance(snapshots, list) or schema == "a15-cuda-freeze-v1" and not snapshots:
        raise ValueError("CUDA formal freeze budget snapshots are missing")
    budget_directory = directory / "budget-evidence"
    preserved, live_files, live_databases = {}, set(), set()
    for entry in snapshots:
        if not isinstance(entry, dict):
            raise ValueError("formal freeze budget snapshot identity is malformed")
        names = [entry.get(key) for key in ("live_database", "snapshot_database")]
        if any(not isinstance(name, str) or not name or not Path(name).is_absolute() for name in names):
            raise ValueError("formal freeze budget snapshot identity requires absolute paths")
        live, snapshot = (Path(name).resolve() for name in names)
        if live in live_databases or live.is_relative_to(directory):
            raise ValueError("formal freeze live budget identity is duplicated or inside the package")
        live_databases.add(live)
        live_files.update(Path(str(live) + suffix).resolve() for suffix in ("", "-wal", "-shm"))
        if snapshot != Path(names[1]) or snapshot.parent != budget_directory:
            raise ValueError("formal freeze budget snapshot must be a canonical package budget-evidence file")
        recorded = mapping(entry.get("files_sha256"), "formal freeze budget snapshot")
        allowed = {snapshot, Path(str(snapshot) + "-wal")}
        if snapshot not in recorded or not set(recorded).issubset(allowed):
            raise ValueError("formal freeze budget snapshot requires exact database and optional WAL files")
        for target, digest in recorded.items():
            if target.parent != budget_directory or target in preserved or evidence.get(target) != digest:
                raise ValueError("formal freeze budget snapshot path/hash mapping differs from correctness evidence")
            preserved[target] = digest
    if live_files.intersection(evidence):
        raise ValueError("formal freeze correctness evidence binds a mutable live budget ledger")
    for target, digest in evidence.items():
        if (target.is_relative_to(budget_directory) or target.suffix.lower() in (".sqlite", ".sqlite3", ".db")
                or target.name.endswith(("-wal", "-shm"))) and target not in preserved:
            raise ValueError("formal freeze budget file lacks an immutable snapshot identity")
        if not target.is_file() or file_sha(target) != digest:
            raise ValueError("formal freeze correctness evidence file missing or SHA256 differs: " + str(target))
        if target in preserved and (target.is_symlink() or target.stat().st_nlink != 1):
            raise ValueError("formal freeze budget snapshot must be an independent regular copy")


def validate_published_freeze(path, freeze):
    """Only the final canonical publication plus its complete package is a gate.

    Freeze authors can check candidate content before publication separately;
    candidate JSON never grants a formal timing permit.
    """
    path = Path(path).resolve()
    if path.name != "freeze.json":
        raise ValueError("formal freeze requires canonical published freeze.json")
    package_path = path.parent / "package.json"
    if not package_path.is_file():
        raise ValueError("formal freeze package.json is missing; publication incomplete")
    package = read_json(package_path)
    expected = {"freeze.json", "source.tar.gz", "source-manifest.json", "REVIEW.md"}
    recorded = package.get("files_sha256", {})
    if (package.get("passed") is not True or package.get("formal_performance_started") is not False
            or package.get("real_timing_samples", 0) != 0 or set(recorded) != expected):
        raise ValueError("formal freeze package is incomplete or not a preparation package")
    for name, digest in recorded.items():
        artifact = path.parent / name
        if not artifact.is_file() or file_sha(artifact) != digest:
            raise ValueError("formal freeze package artifact hash differs: " + name)
    archived_sources = read_json(path.parent / "source-manifest.json")
    if not isinstance(archived_sources, dict) or any(archived_sources.get(k) != v for k, v in freeze.get("source_sha256", {}).items()):
        raise ValueError("formal freeze source manifest omits frozen sources")
    validate_correctness_evidence(path.parent, freeze)


def provenance(args):
    library = args.library.resolve()
    current = hashes(BUILD_FILES + TOOL_FILES)
    record = read_json(args.build_record) if args.build_record else None
    if record:
        if record.get("schema") != "a15-cpu-build-v1" or record.get("source_sha256") != {k: current[k] for k in BUILD_FILES}:
            raise ValueError("build record does not match current compiled sources")
        if record.get("library_sha256") != file_sha(library):
            raise ValueError("library SHA256 differs from recorded build")
        argv = record.get("command", [])
        compiler_arg = next((x[3:] for x in argv if isinstance(x, str) and x.startswith("CC=")), None)
        if not compiler_arg or record.get("compile_output_checked") is not True or record.get("compile_argv") != inspect_compile_output(
                record.get("result", {}).get("stdout", ""), compiler_arg, Path(record.get("library", ""))):
            raise ValueError("build record lacks checked actual compiler output")
        flags = shlex.split(record.get("flags", ""))
        if not flags or any(x not in ("-O2", "-O3", "-DNDEBUG") or x not in record["compile_argv"] for x in flags):
            raise ValueError("recorded optimization flags differ from actual compile command")
        if not record.get("compiler_path") or record.get("compiler_sha256") != file_sha(record["compiler_path"]):
            raise ValueError("compiler executable differs from the recorded build")
        if any(record.get(k) for k in ("counters", "test_injection", "sanitizer")) or re.search(r"SLH_(?:COUNTERS|TEST)|fsanitize", canonical(record)):
            raise ValueError("instrumented builds are excluded from benchmark timing")
    final = False
    freeze = read_json(args.freeze) if args.freeze else None
    if freeze:
        validate_published_freeze(args.freeze, freeze)
        if not record or freeze.get("schema") != "a15-cpu-freeze-v1" or freeze.get("final") is not True or freeze.get("correctness_passed") is not True:
            raise ValueError("final timing requires a final freeze with correctness_passed=true and a recorded build")
        if freeze.get("source_sha256") != current or freeze.get("library_sha256") != file_sha(library):
            raise ValueError("final freeze does not match library, C sources and measurement tools")
        if freeze.get("build_record_sha256") != file_sha(args.build_record):
            raise ValueError("final freeze build-record SHA256 differs from current checked record")
        final = True
    elif not record:
        raise ValueError("timing requires a source-associated checked no-counter build record")
    return {"library": str(library), "library_sha256": file_sha(library), "source_sha256": current,
            "build_record": record, "build_record_sha256": file_sha(args.build_record) if args.build_record else None,
            "freeze": freeze, "freeze_sha256": file_sha(args.freeze) if args.freeze else None,
            "final": final, "classification": "formal" if final else "diagnostic",
            "git": command(["git", "rev-parse", "HEAD"]),
            "timing_scope": "perf_counter_ns around one preallocated ctypes ABI call; includes libffi/ABI, excludes Python serialization, budget, setup and validation",
            "core_cycles": None, "clock_policy": "observed; no frequency/boost mutation; no TSC-to-core-cycle conversion"}


def validate_frozen_plan(plan, digest, prov):
    if plan.get("schema") != "a15-cpu-plan-v1":
        raise ValueError("unsupported plan schema")
    if not prov["final"]:
        return
    validate_formal_plan(plan)
    suite = plan.get("suite")
    frozen = prov["freeze"].get("plans", {})
    entry = frozen.get(suite) if isinstance(frozen, dict) else None
    if not isinstance(entry, dict) or entry.get("sha256") != digest:
        raise ValueError("runtime plan suite/digest is absent from final freeze plans")


def fixture(args, case, log, *, emit=None):
    # Shared immutable fixture preparation retains the caller's evidence
    # schema. CPU callers use the default; CUDA supplies its own JSONL emitter.
    emit = append if emit is None else emit
    pid = case["pid"]
    folder = args.fixtures.resolve()
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"p{pid}-fixture.json"
    if path.exists():
        record = read_json(path)
    elif pid == 3:
        source = ROOT / "reference/evidence/python-sm3-128-24.jsonl"
        record = next(r for r in rows(source) if r.get("pid") == 3)
        record = {k: record[k] for k in ("pk", "sk", "sig", "message", "context", "sk_seed", "sk_prf", "pk_seed")}
        record.update({"pid": pid, "schema": "a15-bench-fixture-v1", "origin": str(source.relative_to(ROOT)), "origin_sha256": file_sha(source)})
        atomic_json(path, record, private=True)
    else:
        setup_started = utc()
        seed = hashlib.sha512(f"A1-5 reproducible CPU benchmark fixture pid={pid}".encode()).digest()[:48]
        with NativeSlhDsa(pid, case["threads"], BACKENDS[case["backend"]], args.library) as c:
            c.set_cache_level(HP[pid])
            pk, sk = c.keygen_internal(seed[:16], seed[16:32], seed[32:])
        record = {"schema": "a15-bench-fixture-v1", "pid": pid, "pk": pk.hex(), "sk": sk.hex(),
                  "sk_seed": seed[:16].hex(), "sk_prf": seed[16:32].hex(), "pk_seed": seed[32:].hex(),
                  "message": (b"A1-5 CPU benchmark deterministic fixture\x00\xff" + bytes(range(128))).hex(),
                  "context": b"A1-5 CPU bench".hex(), "origin": "native seeded setup outside timing",
                  "setup_library_sha256": file_sha(args.library), "setup_sources_sha256": hashes(BUILD_FILES+TOOL_FILES),
                  "setup_started_utc": setup_started, "setup_finished_utc": utc()}
        atomic_json(path, record, private=True)
    if record.get("pid") != pid or len(bytes.fromhex(record["pk"])) != 32 or len(bytes.fromhex(record["sk"])) != 64:
        raise ValueError("fixture parameter/key length mismatch")
    if bytes.fromhex(record["sk"])[32:] != bytes.fromhex(record["pk"]):
        raise ValueError("fixture public key differs from secret-key public half")
    signature_path = folder / f"p{pid}-signature.json"
    if case["op"] in ("sign", "verify") and not record.get("sig"):
        if signature_path.exists():
            saved = read_json(signature_path)
            if saved["fixture_sha256"] != file_sha(path):
                raise ValueError("prepared signature refers to another fixture")
            record["sig"] = saved["sig"]
        else:
            with NativeSlhDsa(pid, case["threads"], BACKENDS[case["backend"]], args.library) as c:
                pk, sk, message, context = (bytes.fromhex(record[k]) for k in ("pk", "sk", "message", "context"))
                ledger = SigningBudget(args.budget_db)
                receipt = ledger.reserve(ALGORITHMS[pid], pk, b"\x00" + bytes([len(context)]) + context + message)
                finished = False
                try:
                    sig = c.sign(message, sk, context)
                    if not c.verify(message, sig, pk, context):
                        raise ValueError("fixture setup signature verification failed")
                    finished = True
                    ledger.finish(receipt, sig)
                except BaseException as exc:
                    if not finished:
                        finish_failure(ledger, receipt, exc)
                    raise
            atomic_json(signature_path, {"fixture_sha256": file_sha(path), "sig": sig.hex(), "receipt": receipt,
                                         "ledger_uuid": ledger.ledger_uuid}, private=True)
            record["sig"] = sig.hex()
            emit(log, {"kind": "setup_signature", "case_id": case["case_id"], "receipt": receipt,
                       "ledger_uuid": ledger.ledger_uuid, "budget_evidence": ledger.validate_receipt(receipt), "timed": False})
    inputs = {k: bytes.fromhex(record[k]) for k in ("pk", "sk", "message", "context", "sk_seed", "sk_prf", "pk_seed")}
    if record.get("sig"):
        inputs["sig"] = bytes.fromhex(record["sig"])
    if any(len(inputs[k]) != 16 for k in ("sk_seed", "sk_prf", "pk_seed")) or len(inputs["context"]) > 255:
        raise ValueError("fixture seed or context length mismatch")
    sources = {str(path): file_sha(path)}
    if signature_path.exists():
        sources[str(signature_path)] = file_sha(signature_path)
        saved = read_json(signature_path)
        ledger = SigningBudget(args.budget_db)
        encoded = b"\x00" + bytes([len(inputs["context"])]) + inputs["context"] + inputs["message"]
        if saved.get("ledger_uuid") != ledger.ledger_uuid:
            raise ValueError("fixture signature ledger UUID differs or is missing")
        ledger.validate_receipt(saved.get("receipt"), algorithm=ALGORITHMS[pid], public_key=inputs["pk"],
                                message=encoded, signature=bytes.fromhex(saved["sig"]))
    return inputs, sources


def counters_enabled(c):
    get = c.lib.slh_counters_get
    reset = c.lib.slh_counters_reset
    get.argtypes, get.restype = [ct.POINTER(ct.c_uint64)], None
    reset.argtypes, reset.restype = [], None
    values = (ct.c_uint64 * 7)()
    reset()
    # A one-leaf FORS subtree costs constant work for all parameters.
    c.subtree("fors", bytes(32), 0, 0)
    get(values)
    return any(values)


def verify_library_runtime(library):
    # Constant-work untimed check before any expensive setup/signature attempt.
    with NativeSlhDsa(201, 1, 1, library) as probe:
        probe.bind_key(bytes(64))
        if (probe.pk_bytes, probe.sk_bytes) != (32, 64) or not hasattr(probe.lib, "slh_ctx_backend"):
            raise ValueError("unexpected native ABI sizes or missing backend introspection")
        if counters_enabled(probe):
            raise ValueError("counter-enabled binary detected; excluded from timing")
    return {"counter_probe": "one FORS leaf, all seven counters zero", "timed": False}


def finish_failure(budget, receipt, original):
    try:
        budget.finish(receipt)
    except Exception as finalization:
        original.add_note("budget finalization also failed: " + str(finalization))


def theoretical(case, inputs, result=None):
    import count_model as model
    p = model.parameters()[case["pid"]]
    op = case["op"]
    if op == "keygen":
        predicted = model.keygen_model(p, case["threads"], case["cache_t"])
    elif op in ("cache_build", "cache_load"):
        predicted = model.cache_model(p, op, case["cache_t"], case["threads"])
    else:
        sig = result if op == "sign" else inputs["sig"]
        encoded = b"\x00" + bytes([len(inputs["context"])]) + inputs["context"] + inputs["message"]
        trace = model.signature_trace(p, encoded, sig, inputs["pk"])
        if not trace["public_root_matches"]:
            raise ValueError("independent signature trace differs from public root")
        predicted = model.sign_model(p, len(encoded), trace["chain_sums"], case["cache_t"], case["threads"]) if op == "sign" else model.verify_model(p, len(encoded), trace["chain_sums"])
    counts = predicted["counts"]
    source_lines = []
    functions = {"keygen": ["slh_keygen_internal", "treehash", "wots_leaf", "wots_leaf8"],
                 "sign": ["sign_core", "sign_fors_tree", "xmss_sign", "wots_sign8"],
                 "verify": ["verify_core", "xmss_from_sig", "wots_from_sig8"],
                 "cache_build": ["slh_cache_build", "treehash", "wots_leaf8"],
                 "cache_load": ["slh_cache_load", "cache_digest"]}[op]
    for number, line in enumerate((ROOT/"c/src/engine.c").read_text().splitlines(), 1):
        for function in functions:
            if re.match(r"(?:static\s+)?(?:int|void|hash_state)\s+"+function+r"\s*\(", line):
                source_lines.append({"path": "c/src/engine.c", "line": number, "function": function})
    return {"hash_calls": sum(counts[k] for k in ("prf", "f", "h", "t")),
            "compressions": counts["compress"], "primitive_counts": counts,
            "count_basis": "analytical implemented-path prediction; not measured in timing binary",
            "hash_calls_scope": "PRF+F+H+T; excludes PRF_msg and H_msg; logical scalar compression equivalents of core primitives",
            "model_components": predicted["components"], "model_metadata": predicted["metadata"],
            "model_source_locations": source_lines,
            "simd_count_policy": "inactive SIMD lanes are physically evaluated but not logically counted; counts are not hardware SIMD instruction/block totals",
            "cache_checksum_policy": "cache digest SM3 is outside public core counters; see model_metadata for checksum blocks"}


def raw_operation(c, case, inputs, cache_path):
    """Allocate all ctypes buffers before the timer starts."""
    pk, sk, msg, context = (_buffer(inputs[k]) for k in ("pk", "sk", "message", "context"))
    signature = (ct.c_uint8 * c.sig_bytes)()
    length = ct.c_size_t()
    op, lib, ctx = case["op"], c.lib, c.ctx
    if op == "sign":
        call = lambda: lib.slh_sign(ctx, signature, ct.byref(length), msg, len(inputs["message"]), context, len(inputs["context"]), sk, None)
        extract = lambda: bytes(signature[:length.value])
    elif op == "verify":
        sig = _buffer(inputs["sig"])
        call = lambda: lib.slh_verify(ctx, sig, len(inputs["sig"]), msg, len(inputs["message"]), context, len(inputs["context"]), pk)
        extract = lambda: True
    elif op == "keygen":
        output_pk, output_sk = (ct.c_uint8 * 32)(), (ct.c_uint8 * 64)()
        if case["keygen_mode"] == "rng":
            call = lambda: lib.slh_keygen(ctx, output_pk, output_sk)
        else:
            seed, prf, public = (_buffer(inputs[k]) for k in ("sk_seed", "sk_prf", "pk_seed"))
            call = lambda: lib.slh_keygen_internal(ctx, output_pk, output_sk, seed, prf, public)
        extract = lambda: (bytes(output_pk), bytes(output_sk))
    elif op == "cache_build":
        call = lambda: lib.slh_cache_build(ctx, sk, case["cache_t"])
        extract = lambda: True
    else:
        path = os.fsencode(cache_path)
        call = lambda: lib.slh_cache_load(ctx, path, pk)
        extract = lambda: True
    return call, extract


def validate_result(verifier, case, inputs, result, budget):
    op = case["op"]
    if op == "sign" and not verifier.verify(inputs["message"], result, inputs["pk"], inputs["context"]):
        raise ValueError("measured signature verification failed")
    if op == "keygen":
        pk, sk = result
        if sk[32:] != pk:
            raise ValueError("generated key serialization differs")
        if case["keygen_mode"] == "seeded":
            if pk != inputs["pk"] or sk != inputs["sk"]:
                raise ValueError("seeded key differs from fixed fixture")
        else:
            encoded = b"\x00" + bytes([len(inputs["context"])]) + inputs["context"] + inputs["message"]
            receipt = budget.reserve(ALGORITHMS[case["pid"]], pk, encoded)
            finished = False
            try:
                sig = verifier.sign(inputs["message"], sk, inputs["context"])
                if not verifier.verify(inputs["message"], sig, pk, inputs["context"]):
                    raise ValueError("RNG keygen validation signature failed")
                finished = True
                budget.finish(receipt, sig)
            except BaseException as exc:
                if not finished:
                    finish_failure(budget, receipt, exc)
                raise
            return {"rng_validation_receipt": receipt, "public_key_sha256": sha(pk),
                    "budget_evidence": budget.validate_receipt(receipt), "timed": False}
    if op in ("cache_build", "cache_load"):
        # Round trip outside the timed ABI call, with no additional signatures.
        return {"valid": True, "timed": False, "cache_roundtrip_required": True}
    return {"valid": True, "timed": False}


def validate_cache_result(c, case, inputs, path, verifier):
    temporary = Path(path).with_name(Path(path).name+".validate-"+uuid.uuid4().hex)
    try:
        c.cache_save(temporary)
        with temporary.open("rb") as stream:
            header = stream.read(96)
        if len(header) != 96 or header[:8] != b"A15CACHE" or int.from_bytes(header[16:20], "big") != case["cache_t"]:
            raise ValueError("measured cache result has incorrect cache level/header")
        verifier.cache_load(temporary, inputs["pk"])
        # Native load reconstructs all upper nodes and checks the full root.
        return {"cache_roundtrip": "save then separate REF load/root reconstruction", "timed": False,
                "cache_result_sha256": file_sha(temporary)}
    finally:
        if temporary.exists():
            temporary.unlink()


def worker(args):
    plan_bytes = Path(args.plan).read_bytes()
    plan, plan_digest = json.loads(plan_bytes.decode("utf-8-sig")), sha(plan_bytes)
    case = next(c for c in plan["cases"] if c["case_id"] == args.worker_case)
    validate_case(case)
    provenance_before = provenance(args)
    validate_frozen_plan(plan, plan_digest, provenance_before)
    formal = provenance_before["final"]
    if formal and (plan.get("diagnostic_sample_override") or case["samples"] < minimum_samples(case)):
        raise ValueError("formal campaign has insufficient/overridden samples")
    if formal and case["pid"] == 201:
        raise ValueError("toy parameter is always diagnostic")
    affinity = bind(case, formal, args.cpus)
    expected_omp = openmp_environment(case["threads"], affinity["cpus"])
    for key, value in expected_omp.items():
        if os.environ.get(key) != value:
            raise ValueError("OpenMP environment must be set before child/native startup: " + key)
    initial = environment(affinity)
    identity = environment_identity(initial)
    budget = SigningBudget(args.budget_db)
    binding = execution_binding(case, provenance_before, identity, budget.ledger_uuid, plan_digest)
    case_key = sha(canonical(binding).encode())
    evidence = rows(args.output)
    audit_campaign_evidence(evidence, plan, budget, args.fixtures, provenance=provenance_before, plan_digest=plan_digest)
    if any(r.get("kind") == "case_start" and r.get("case", {}).get("case_id") == case["case_id"]
           and r.get("case_key") != case_key for r in evidence):
        raise ValueError("case resume environment/source/build differs; use fresh evidence")
    existing = [r for r in evidence if r.get("case_key") == case_key]
    if validate_completed(existing, case, args.fixtures, budget, binding):
        validate_fixture_receipts(args.fixtures, case["pid"], budget)
        return
    segment_id = uuid.uuid4().hex
    def emit(row):
        emit_bound(append, args.output, binding, segment_id, row)
    def begin(kind, index, receipt, input_hashes):
        operation_id = uuid.uuid4().hex
        emit({"kind": "operation_start", "operation_kind": kind, "operation_id": operation_id,
              "index" if kind == "warmup" else "sample_index": index,
              "receipt": receipt, "budget_evidence": receipt_evidence(budget, receipt),
              "input_hashes": input_hashes, "timed": False})
        return operation_id
    emit({"kind": "case_start", "case_key": case_key, "case": case,
                         "provenance": provenance_before, "environment": initial,
                         "environment_identity": identity, "ledger_uuid": budget.ledger_uuid, "pid_process": os.getpid()})
    runtime = verify_library_runtime(args.library)
    inputs, input_files = fixture(args, case, args.output)
    cache_path = args.fixtures.resolve() / f"p{case['pid']}-{sha(inputs['pk'])[:16]}-t{case['cache_t']}.cache"
    with NativeSlhDsa(case["pid"], case["threads"], BACKENDS[case["backend"]], args.library) as c, \
            NativeSlhDsa(case["pid"], 1, 1, args.library) as verifier:
        # Fresh signing context plus explicit bind: no keygen-derived root cache.
        c.bind_key(inputs["sk"])
        if c.backend != BACKENDS[case["backend"]]:
            raise ValueError("actual native backend differs from requested comparison")
        if (c.pk_bytes, c.sk_bytes, c.sig_bytes) != (32, 64, SIG_BYTES[case["pid"]]):
            raise ValueError("native ABI parameter sizes differ from planned variant")
        if counters_enabled(c):
            raise ValueError("counter-enabled binary detected; excluded from timing")
        if case["op"] in ("sign", "cache_load") and case["cache_t"] is not None:
            if not cache_path.exists():
                with NativeSlhDsa(case["pid"], case["threads"], BACKENDS[case["backend"]], args.library) as prepare:
                    prepare.cache_build(inputs["sk"], case["cache_t"])
                    prepare.cache_save(cache_path)
                emit({"kind": "setup_cache", "case_key": case_key, "cache_file_sha256": file_sha(cache_path), "timed": False})
            c.cache_load(cache_path, inputs["pk"])
            input_files[str(cache_path)] = file_sha(cache_path)
        if case["op"] == "keygen":
            c.set_cache_level(case["cache_t"] if case["cache_t"] is not None else HP[case["pid"]])
        if inputs.get("sig") and not verifier.verify(inputs["message"], inputs["sig"], inputs["pk"], inputs["context"]):
            raise ValueError("stored fixture signature rejected before timing")
        input_hashes = {k: sha(v) for k, v in inputs.items()}
        old_starts = [r for r in existing if r.get("kind") == "inputs_ready"]
        if any(r.get("input_hashes") != input_hashes or r.get("input_files") != input_files for r in old_starts):
            raise ValueError("fixture input changed during partial-case resume")
        if any(r.get("budget_binding") != budget_binding(budget, case, inputs) for r in old_starts):
            raise ValueError("partial-case budget binding differs from immutable fixture")
        emit({"kind": "inputs_ready", "case_key": case_key, "input_hashes": input_hashes,
                             "input_files": input_files, "actual_backend": c.backend,
                             "ledger_uuid": budget.ledger_uuid, "budget_binding": budget_binding(budget, case, inputs),
                             "runtime_checks": runtime,
                             "self_verify": False, "validation": "separate REF context after timing",
                             "uncached_sign_context": "new context; bind_key only; no keygen and no cache_build/load" if case["cache"] == "none" else None})
        call, extract = raw_operation(c, case, inputs, cache_path)
        encoded = b"\x00" + bytes([len(inputs["context"])]) + inputs["context"] + inputs["message"]
        good = resume_samples(existing, case, input_hashes)
        validate_preserved_budget(existing, case, budget)
        if len(good) < case["samples"]:
            for warmup in range(case["warmups"]):
                receipt = budget.reserve(ALGORITHMS[case["pid"]], inputs["pk"], encoded) if case["op"] == "sign" else None
                operation_id = begin("warmup", warmup, receipt, input_hashes)
                finished = False
                try:
                    c._check(case["op"], call())
                    result = extract()
                    validation = validate_result(verifier, case, inputs, result, budget)
                    if case["op"] in ("cache_build", "cache_load"):
                        validation.update(validate_cache_result(c, case, inputs, cache_path, verifier))
                    if receipt:
                        finished = True
                        budget.finish(receipt, result)
                except BaseException as exc:
                    if receipt and not finished:
                        finish_failure(budget, receipt, exc)
                    emit({"kind": "warmup", "index": warmup, "passed": False, "operation_id": operation_id,
                          "input_hashes": input_hashes, "receipt": receipt, "error": type(exc).__name__+": "+str(exc),
                          "budget_evidence": failure_receipt_evidence(budget, receipt, exc), "timed": False})
                    raise
                emit({"kind": "warmup", "case_key": case_key, "index": warmup,
                                     "operation_id": operation_id,
                                     "passed": True, "input_hashes": input_hashes,
                                     "receipt": receipt, "budget_evidence": receipt_evidence(budget, receipt), "validation": validation, "timed": False})
        prediction = None
        for index in range(case["samples"]):
            if index in good:
                continue
            receipt = budget.reserve(ALGORITHMS[case["pid"]], inputs["pk"], encoded) if case["op"] == "sign" else None
            operation_id = begin("sample", index, receipt, input_hashes)
            before = sample_environment(affinity["cpus"])
            finished, duration = False, None
            try:
                started_ns = time.perf_counter_ns()
                code = call()
                ended_ns = time.perf_counter_ns()
                duration = ended_ns - started_ns
                if duration <= 0:
                    raise ValueError("monotonic timer returned a nonpositive duration")
                c._check(case["op"], code)
                result = extract()
                if case["op"] == "sign" and len(result) != c.sig_bytes:
                    raise ValueError("measured signature ABI length differs from parameter")
                validation = validate_result(verifier, case, inputs, result, budget)
                if case["op"] in ("cache_build", "cache_load"):
                    validation.update(validate_cache_result(c, case, inputs, cache_path, verifier))
                if receipt:
                    finished = True
                    budget.finish(receipt, result)
                if prediction is None:
                    prediction = theoretical(case, inputs, result)
            except BaseException as exc:
                if receipt and not finished:
                    finish_failure(budget, receipt, exc)
                emit({"kind": "sample", "case_key": case_key, "sample_index": index,
                                     "operation_id": operation_id,
                                     "input_hashes": input_hashes,
                                     "passed": False, "duration_ns": duration, "error": type(exc).__name__+": "+str(exc), "receipt": receipt,
                                     "budget_evidence": failure_receipt_evidence(budget, receipt, exc)})
                raise
            result_hash = sha(result) if isinstance(result, bytes) else sha(b"".join(result)) if isinstance(result, tuple) else None
            row = {"kind": "sample", "case_key": case_key, "case_id": case["case_id"],
                   "operation_id": operation_id,
                   "sample_index": index, "duration_ns": duration, "passed": True,
                   "receipt": receipt, "budget_evidence": receipt_evidence(budget, receipt), "result_sha256": result_hash, "input_hashes": input_hashes,
                   "environment_before": before, "environment_after": sample_environment(affinity["cpus"]),
                   "validation": validation, "classification": provenance_before["classification"]}
            emit(row)
            good[index] = row
        provenance_after = provenance(args)
        if any(provenance_before.get(k) != provenance_after.get(k) for k in
               ("source_sha256", "library_sha256", "build_record_sha256", "freeze_sha256", "final", "classification")):
            raise ValueError("sources/library/build/freeze changed while measuring; case remains incomplete")
        if any(file_sha(path) != digest for path, digest in input_files.items()):
            raise ValueError("input file changed while measuring")
        if file_sha(args.plan) != plan_digest:
            raise ValueError("plan file changed while measuring")
        environment_end = environment(affinity)
        if environment_identity(environment_end) != identity:
            raise ValueError("stable host/affinity/governor/boost/OpenMP conditions changed during case")
        if prediction is None:
            # Completed raw samples survived a crash before summary emission.
            prediction = theoretical(case, inputs, inputs.get("sig"))
        latest = rows(args.output)
        sample_lines = [r["_line"] for r in latest if r.get("case_key") == case_key and r.get("kind") == "sample" and r.get("passed")]
        values = [good[index]["duration_ns"] for index in range(case["samples"])]
        emit({"kind": "case_complete", "case_key": case_key, "case_id": case["case_id"],
            "ledger_uuid": budget.ledger_uuid,
            **summary(values), "samples": values, "sample_lines": sample_lines, **prediction,
            "host": initial["host"], "cpu": initial["lscpu"], "cores": case["threads"], "threads": case["threads"],
            "turbo": initial["turbo"], "governor": initial["governor"],
            "compiler": provenance_before["build_record"]["compiler"] if provenance_before["build_record"] else None,
            "flags": provenance_before["build_record"]["flags"] if provenance_before["build_record"] else None,
            "backend": case["backend"], "actual_backend": c.backend, "pid": case["pid"], "op": case["op"],
            "cache_t": case["cache_t"], "requested_cache_t": case["cache"], "keygen_mode": case["keygen_mode"],
            "family": case["family"], "git": provenance_before["git"], "final": formal,
            "classification": provenance_before["classification"], "environment_end": environment_end,
            "environment_identity": identity,
            "input_hashes": input_hashes, "input_files_before": input_files,
            "input_files_after": {path: file_sha(path) for path in input_files},
            "source_sha256_before": provenance_before["source_sha256"], "source_sha256_after": provenance_after["source_sha256"],
            "library_sha256_before": provenance_before["library_sha256"], "library_sha256_after": provenance_after["library_sha256"],
            "build_record_sha256": provenance_before["build_record_sha256"], "freeze_sha256": provenance_before["freeze_sha256"],
            "affinity": affinity, "timing_scope": provenance_before["timing_scope"], "core_cycles": None,
            "cache_io_policy": "repeated load of prepared file; warm page cache; file I/O+SM3+root reconstruction included" if case["op"] == "cache_load" else None})


def run_cases(args):
    protected_paths(args)
    if not math.isfinite(args.timeout_seconds) or args.timeout_seconds <= 0:
        raise ValueError("case process timeout must be finite and positive")
    plan_bytes = Path(args.plan).read_bytes()
    plan, plan_digest = json.loads(plan_bytes.decode("utf-8-sig")), sha(plan_bytes)
    if plan.get("schema") != "a15-cpu-plan-v1":
        raise ValueError("unsupported plan schema")
    ids = [c["case_id"] for c in plan["cases"]]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate case IDs")
    for case in plan["cases"]:
        validate_case(case)
    prov = provenance(args)
    validate_frozen_plan(plan, plan_digest, prov)
    topo, topo_result = topology()
    host_identity = environment_identity(environment({"cpus": [], "verified_physical": bool(topo), "physical_cores": topo}))
    budget = SigningBudget(args.budget_db)
    campaign_key = sha(canonical({"plan": file_sha(args.plan), "library": prov["library_sha256"],
                                  "sources": prov["source_sha256"], "freeze": prov["freeze_sha256"],
                                  "host_environment": host_identity, "explicit_cpus": args.cpus, "ledger_uuid": budget.ledger_uuid}).encode())
    old = rows(args.output)
    audit_campaign_evidence(old, plan, budget, args.fixtures, provenance=prov, plan_digest=plan_digest)
    if any(row.get("schema") != SCHEMA for row in old):
        raise ValueError("preserved output contains foreign records")
    starts = [r for r in old if r.get("kind") == "campaign_start"]
    if old and not starts or len(starts) > 1:
        raise ValueError("preserved output must contain exactly one campaign start")
    if starts and any(r["campaign_key"] != campaign_key for r in starts):
        raise ValueError("preserved file belongs to a different plan/build/freeze; use a fresh output")
    if starts and any(starts[0].get(k) != v for k, v in {
            "plan_sha256": plan_digest, "ledger_uuid": budget.ledger_uuid,
            "provenance": prov, "host_environment": host_identity}.items()):
        raise ValueError("preserved campaign metadata differs from current plan/build/host")
    if not starts:
        append(args.output, {"kind": "campaign_start", "campaign_key": campaign_key, "plan_sha256": file_sha(args.plan),
                             "ledger_uuid": budget.ledger_uuid,
                             "provenance": prov, "host_environment": host_identity, "topology_probe": topo_result})
    selected_ids = set(args.case or ids)
    if not selected_ids.issubset(ids):
        raise ValueError("--case name not in plan")
    for case in plan["cases"]:
        if case["case_id"] not in selected_ids:
            continue
        current = provenance(args)
        if file_sha(args.plan) != plan_digest or any(current[k] != prov[k] for k in ("library_sha256", "source_sha256", "freeze_sha256", "build_record_sha256")):
            raise ValueError("plan/source/build/freeze changed between sequential cases")
        try:
            cpus = [r["cpu"] for r in physical_cpus(topo, case["threads"], args.cpus)] if topo else []
        except ValueError as exc:
            append(args.output, {"kind": "case_unavailable", "case_id": case["case_id"], "reason": str(exc), "passed": False})
            print(case["case_id"] + ": physical cores unavailable", flush=True)
            continue
        if not cpus and prov["final"]:
            raise ValueError("formal cases require physical CPU topology")
        omp = openmp_environment(case["threads"], cpus)
        argv = [sys.executable, str(Path(__file__).resolve()), "worker", "--plan", str(args.plan.resolve()),
                "--worker-case", case["case_id"], "--library", str(args.library.resolve()),
                "--output", str(args.output.resolve()), "--fixtures", str(args.fixtures.resolve()),
                "--budget-db", str(args.budget_db.resolve()), "--parent-pid", str(os.getpid())]
        if cpus:
            argv += ["--cpus", ",".join(map(str, cpus))]
        for option in ("build_record", "freeze"):
            if getattr(args, option):
                argv += ["--" + option.replace("_", "-"), str(getattr(args, option).resolve())]
        print(case["case_id"] + ": sequential child", flush=True)
        # Clear inherited placement/thread-limit overrides before libgomp starts.
        child_env = {key: value for key, value in os.environ.items() if not key.startswith(("OMP_", "GOMP_", "KMP_"))}
        try:
            child = subprocess.run(argv, cwd=ROOT, env={**child_env, **omp}, timeout=args.timeout_seconds)
        except subprocess.TimeoutExpired:
            append(args.output, {"kind": "case_process_timeout", "case_id": case["case_id"],
                                 "timeout_seconds": args.timeout_seconds, "passed": False,
                                 "budget_policy": "reserved attempts stay consumed; no refund"})
            raise RuntimeError("case worker exceeded timeout: " + case["case_id"]) from None
        if child.returncode:
            append(args.output, {"kind": "case_process_failed", "case_id": case["case_id"], "returncode": child.returncode})
            raise RuntimeError("case worker failed: " + case["case_id"])
    print(canonical({"output": str(args.output), "classification": prov["classification"],
                     "complete_cases": sum(r.get("kind") == "case_complete" for r in rows(args.output))}))


def integers(value):
    result = []
    for item in value.split(","):
        if "-" in item:
            start, end = map(int, item.split("-", 1))
            if end < start or end-start > 1024:
                raise ValueError("invalid integer range")
            result.extend(range(start, end+1))
        else:
            result.append(int(item))
    return result


def sm3_check_record(args):
    binary = args.binary.resolve()
    argv = [str(binary), "check"]
    result = command(argv, timeout=30)
    if result.get("returncode") != 0:
        raise ValueError("SM3 harness correctness check failed")
    check = json.loads(result["stdout"])
    if check.get("schema") != "a15-sm3-check-v1" or not check.get("passed") or check.get("real_timing_samples") != 0:
        raise ValueError("SM3 check emitted unexpected or timed evidence")
    atomic_json(args.output, {"schema": "a15-sm3-preparation-v1", "created_utc": utc(), "passed": True,
        "native_calls": check["comparisons"]+1, "real_timing_samples": 0, "check": check,
        "native_calls_scope": "native correctness work items: one SM3 known-answer case plus 256 eight-lane compression comparisons; this field does not count nested C function calls",
        "binary": str(binary), "binary_sha256": file_sha(binary), "command": argv,
        "sources_sha256": hashes(["tools/bench_sm3_harness.c", "c/src/sm3.c", "c/src/sm3.h", "c/src/sm3x8.c", "c/src/sm3x8.h"]),
        "compiler": command([args.cc, "--version"]), "build_command": args.build_command,
        "scope": "known-answer and scalar/x8 final-block correctness; sample command not called"})


def self_test(output=None):
    """Exercise orchestration with fake native calls and fixed synthetic times."""
    import tempfile
    import unittest
    from contextlib import ExitStack
    from types import SimpleNamespace
    from unittest.mock import Mock, patch
    module = sys.modules[__name__]

    class Checks(unittest.TestCase):
        def setUp(self):
            self.scratch = tempfile.TemporaryDirectory(prefix="a15-bench-mock-")
            self.addCleanup(self.scratch.cleanup)
            self.folder = Path(self.scratch.name)

        def test_plan_minimums_and_pairing(self):
            plan = make_plan("all", [1, 2, 3, 101, 102, 103], [1, 2, 4, 8, 16, 32, 64], list(range(23)))
            self.assertEqual({c["cache_t"] for c in plan["cases"] if c["family"] == "R4"}, set(range(23)))
            for case in plan["cases"]:
                self.assertGreaterEqual(case["samples"], minimum_samples(case))
                if case["pid"] < 100:
                    pair = {c["backend"] for c in plan["cases"] if all(c[k] == case[k] for k in
                        ("pid", "op", "cache", "threads", "family", "keygen_mode"))}
                    self.assertEqual(pair, {"REF", "AVX2"})
            self.assertEqual(minimum_samples(case_record(3, "sign", cache="12")), 30)
            self.assertEqual(minimum_samples(case_record(3, "sign")), 5)
            self.assertEqual(minimum_samples(case_record(1, "sign")), 100)
            self.assertEqual(minimum_samples(case_record(1, "verify")), 10000)
            self.assertEqual(minimum_samples(case_record(3, "keygen", cache="12")), 5)

        def test_plan_ranges_and_rejections(self):
            self.assertEqual(integers("1-3,8"), [1, 2, 3, 8])
            for arguments in [("r3", [3, 3], [1], [12]), ("r5", [3], [0], [12]),
                              ("r4", [3], [1], [23]), ("r4", [1], [1], [12])]:
                with self.assertRaises(ValueError):
                    make_plan(*arguments)
            with self.assertRaises(ValueError):
                validate_case(case_record(3, "keygen"))
            with self.assertRaises(ValueError):
                validate_formal_plan(make_plan("r3", [3], [1], [12], samples=1))
            plan = make_plan("r5", [3], list(range(1, 65)), [12])
            self.assertEqual({c["threads"] for c in plan["cases"] if c["op"] == "keygen"}, set(range(1, 65)))

        def test_statistics(self):
            self.assertEqual(summary([10, 20, 30, 40])["iqr"], 15)
            self.assertEqual(summary([10])["iqr"], 0)
            self.assertEqual(summary([10, 20])["median"], 15)
            for values in ([], [0], [-1], [True], [1.5]):
                with self.assertRaises(ValueError):
                    summary(values)

        def test_topology_and_smt(self):
            parsed = topology_from_csv("# header\n0,0,0,0,Y\n1,0,0,0,Y\n2,1,0,0,Y\n3,2,1,1,N", {0, 1, 2})
            self.assertEqual([r["cpu"] for r in physical_cpus(parsed, 2)], [0, 2])
            for explicit in ([0, 1], [0, 0], [9]):
                with self.assertRaises(ValueError):
                    physical_cpus(parsed, 1, explicit)
            with self.assertRaises(ValueError):
                physical_cpus(parsed, 3)
            self.assertEqual(openmp_environment(2, [0, 2])["OMP_PLACES"], "{0},{2}")

        def test_atomic_creation_and_foreign_writer(self):
            path = self.folder/"artifact.json"
            atomic_json(path, {"first": True})
            with self.assertRaises(ValueError):
                atomic_json(path, {"second": True})
            self.assertTrue(read_json(path)["first"])
            other = self.folder/"race.json"
            def racer(source, destination):
                Path(destination).write_text("foreign")
                raise FileExistsError("racing writer")
            with patch.object(os, "link", side_effect=racer), self.assertRaises(FileExistsError):
                atomic_json(other, {"ours": True})
            self.assertEqual(other.read_text(), "foreign")

        def test_jsonl_tail_and_foreign_rows(self):
            path = self.folder/"evidence.jsonl"
            append(path, {"kind": "sample", "duration_ns": 10})
            self.assertEqual(rows(path)[0]["_line"], 1)
            path.write_bytes(path.read_bytes().rstrip(b"\n"))
            with self.assertRaises(ValueError):
                rows(path)
            path.write_text("[]\n")
            with self.assertRaises(ValueError):
                rows(path)

        def test_kernel_lock_released(self):
            path = self.folder/"locked.jsonl"
            with output_lock(path):
                with self.assertRaises(ValueError), output_lock(path):
                    pass
            with output_lock(path):
                pass

        def test_resume_indices_and_hashes(self):
            case = case_record(201, "verify", samples=2)
            row = {"kind": "sample", "passed": True, "sample_index": 0, "duration_ns": 10, "input_hashes": {"pk": "fixed"}}
            self.assertEqual(len(resume_samples([row], case, row["input_hashes"])), 1)
            for evidence in ([row, row], [{**row, "sample_index": 2}], [{**row, "duration_ns": 0}]):
                with self.assertRaises(ValueError):
                    resume_samples(evidence, case, row["input_hashes"])
            with self.assertRaises(ValueError):
                resume_samples([row], case, {"pk": "changed"})

        def test_environment_freeze(self):
            info = {"host": "one", "affinity": {"cpus": [0]}, "governor": {"0": "performance"},
                    "lscpu": {"stdout": json.dumps({"lscpu": [{"field": "CPU MHz:", "data": "1000"},
                                                             {"field": "Model name:", "data": "fixed"}]})}}
            modified = {**info, "loadavg": [100, 0, 0], "frequency_khz": {"0": "2000"},
                        "lscpu": {"stdout": info["lscpu"]["stdout"].replace("1000", "2000")}}
            self.assertEqual(environment_identity(info), environment_identity(modified))
            self.assertNotEqual(environment_identity(info), environment_identity({**info, "host": "two"}))

        def compile_line(self, library):
            sources = [name.removeprefix("c/") if name.startswith("c/") else "../"+name for name in BUILD_FILES if name.endswith(".c")]
            return shlex.join(["gcc", "-std=c11", "-fopenmp", "-O3", "-DSLH_RELEASE_BUILD", "-shared", *sources, "-o", str(library)])

        def test_actual_compile_command_gate(self):
            library = self.folder/"library.so"
            line = self.compile_line(library)
            self.assertIn("-fopenmp", inspect_compile_output(line, "gcc", library))
            for flag in ("-DSLH_COUNTERS", "-DSLH_TEST_BUILD", "-fsanitize=address", "-march=native", "-mavx2", "@flags", "-fprofile-generate"):
                with self.assertRaises(ValueError):
                    inspect_compile_output(line.replace("-O3", "-O3 "+flag), "gcc", library)
            with self.assertRaises(ValueError):
                build(SimpleNamespace(out=self.folder/"fresh-build", cc="gcc", cflags="-O3 -march=native", portable=False))
            with self.assertRaises(FileExistsError):
                build(SimpleNamespace(out=self.folder, cc="gcc", cflags="-O3", portable=False))

        def test_counter_probe_with_mock_abi(self):
            state = {"enabled": False, "value": 0}
            def reset():
                state["value"] = 0
            def get(output):
                output[0] = state["value"]
            def subtree(*unused):
                state["value"] = 1 if state["enabled"] else 0
            native = SimpleNamespace(lib=SimpleNamespace(slh_counters_get=get, slh_counters_reset=reset), subtree=subtree)
            self.assertFalse(counters_enabled(native))
            state["enabled"] = True
            self.assertTrue(counters_enabled(native))

        def test_cache_roundtrip_with_mock_abi(self):
            case = case_record(3, "cache_build", cache="12", samples=1)
            def save(path):
                header = bytearray(96)
                header[:8] = b"A15CACHE"
                header[16:20] = (12).to_bytes(4, "big")
                Path(path).write_bytes(header)
            verifier = SimpleNamespace(cache_load=Mock())
            result = validate_cache_result(SimpleNamespace(cache_save=save), case, {"pk": b"p"*32},
                                          self.folder/"prepared.cache", verifier)
            self.assertIn("cache_result_sha256", result)
            self.assertEqual(verifier.cache_load.call_count, 1)
            self.assertEqual(list(self.folder.glob("*.validate-*")), [])

        def test_mock_build_entry_records_checked_output(self):
            destination = self.folder/"mock-build"
            library = destination/"libslhdsa_sm3.so"
            compiler = self.folder/"mock-compiler"
            compiler.write_bytes(b"mock compiler")
            def fake_command(argv, **unused):
                if argv[0] == "make":
                    library.write_bytes(b"mock library; never load it")
                    return {"returncode": 0, "stdout": self.compile_line(library), "stderr": ""}
                return {"returncode": 0, "stdout": "mock compiler version", "stderr": ""}
            with patch.object(module, "command", side_effect=fake_command), \
                    patch.object(module, "hashes", return_value={name: "fixed-source" for name in BUILD_FILES}), \
                    patch.object(shutil, "which", return_value=str(compiler)):
                build(SimpleNamespace(out=destination, cc="gcc", cflags="-O3", portable=False))
            record = read_json(destination/"build-record.json")
            self.assertTrue(record["compile_output_checked"])
            self.assertFalse(record["counters"])
            self.assertEqual(record["library_sha256"], file_sha(library))
            self.assertIn("COUNTERS=0", record["command"])

        def test_provenance_hash_gate(self):
            library, compiler = self.folder/"library.so", self.folder/"compiler"
            library.write_bytes(b"binary-fixture")
            compiler.write_bytes(b"compiler-fixture")
            current = {name: "fixed-source" for name in BUILD_FILES+TOOL_FILES}
            record = {"schema": "a15-cpu-build-v1", "source_sha256": {k: current[k] for k in BUILD_FILES},
                "library": str(library), "library_sha256": file_sha(library), "flags": "-O3",
                "command": ["make", "CC=gcc"], "compile_output_checked": True,
                "compile_argv": shlex.split(self.compile_line(library)), "result": {"stdout": self.compile_line(library)},
                "compiler_path": str(compiler), "compiler_sha256": file_sha(compiler)}
            path = self.folder/"build.json"
            path.write_text(json.dumps(record))
            args = SimpleNamespace(library=library, build_record=path, freeze=None)
            with patch.object(module, "hashes", return_value=current), patch.object(module, "command", return_value={"returncode": 0}):
                self.assertEqual(provenance(args)["classification"], "diagnostic")
                library.write_bytes(b"changed")
                with self.assertRaisesRegex(ValueError, "SHA256"):
                    provenance(args)
                library.write_bytes(b"binary-fixture")
                record["counters"] = True
                path.write_text(json.dumps(record))
                with self.assertRaisesRegex(ValueError, "instrumented"):
                    provenance(args)

        def test_freeze_build_record_and_plan_binding(self):
            plan = make_plan("r3", [3], [1], [12])
            digest = sha(canonical(plan).encode())
            prov = {"final": True, "freeze": {"plans": {"r3": {"sha256": digest}}}}
            validate_frozen_plan(plan, digest, prov)
            for changed in (sha(b"other plan"), ""):
                with self.assertRaisesRegex(ValueError, "plan suite/digest"):
                    validate_frozen_plan(plan, changed, prov)
            with self.assertRaisesRegex(ValueError, "plan suite/digest"):
                validate_frozen_plan({**plan, "suite": "r4"}, digest, prov)
            library, compiler = self.folder/"final.so", self.folder/"compiler"
            library.write_bytes(b"final library")
            compiler.write_bytes(b"compiler")
            sources = {name: "current" for name in BUILD_FILES+TOOL_FILES}
            record = {"schema": "a15-cpu-build-v1", "source_sha256": {k: sources[k] for k in BUILD_FILES},
                "library": str(library), "library_sha256": file_sha(library), "flags": "-O3",
                "command": ["make", "CC=gcc"], "compile_output_checked": True,
                "compile_argv": shlex.split(self.compile_line(library)), "result": {"stdout": self.compile_line(library)},
                "compiler_path": str(compiler), "compiler_sha256": file_sha(compiler)}
            build_path, freeze_path = self.folder/"build.json", self.folder/"freeze.json"
            build_path.write_text(json.dumps(record))
            freeze = {"schema": "a15-cpu-freeze-v1", "final": True, "correctness_passed": True,
                "source_sha256": sources, "library_sha256": file_sha(library), "build_record_sha256": file_sha(build_path),
                "correctness_evidence": {str(build_path.resolve()): file_sha(build_path)},
                "plans": {"r3": {"sha256": digest}}}
            freeze_path.write_text(json.dumps(freeze))
            for name in ("source.tar.gz", "REVIEW.md"):
                (self.folder/name).write_bytes(b"mock package artifact")
            (self.folder/"source-manifest.json").write_text(json.dumps(sources))
            def publish_mock_package():
                (self.folder/"package.json").write_text(json.dumps({"passed": True, "formal_performance_started": False,
                    "real_timing_samples": 0, "files_sha256": {name: file_sha(self.folder/name) for name in
                    ("freeze.json", "source.tar.gz", "source-manifest.json", "REVIEW.md")}}))
            publish_mock_package()
            args = SimpleNamespace(library=library, build_record=build_path, freeze=freeze_path)
            with patch.object(module, "hashes", return_value=sources), patch.object(module, "command", return_value={}):
                self.assertTrue(provenance(args)["final"])
                freeze["build_record_sha256"] = "wrong"
                freeze_path.write_text(json.dumps(freeze))
                publish_mock_package()
                with self.assertRaisesRegex(ValueError, "build-record SHA256"):
                    provenance(args)

        def test_published_freeze_package_gate(self):
            sources = {"mock/source": "hash"}
            accepted = self.folder/"accepted.json"
            accepted.write_bytes(b"mock accepted evidence")
            freeze = {"schema": "a15-cpu-freeze-v1", "source_sha256": sources,
                "correctness_evidence": {str(accepted.resolve()): file_sha(accepted)}}
            canonical = self.folder/"freeze.json"
            canonical.write_text(json.dumps(freeze))
            candidate = self.folder/"freeze.candidate.json"
            candidate.write_text(json.dumps(freeze))
            with self.assertRaisesRegex(ValueError, "canonical published"):
                validate_published_freeze(candidate, freeze)
            with self.assertRaisesRegex(ValueError, "publication incomplete"):
                validate_published_freeze(canonical, freeze)
            for name in ("source.tar.gz", "REVIEW.md"): (self.folder/name).write_bytes(b"mock")
            (self.folder/"source-manifest.json").write_text(json.dumps(sources))
            package = {"passed": True, "formal_performance_started": False, "real_timing_samples": 0,
                "files_sha256": {name: file_sha(self.folder/name) for name in
                ("freeze.json", "source.tar.gz", "source-manifest.json", "REVIEW.md")}}
            (self.folder/"package.json").write_text(json.dumps(package))
            validate_published_freeze(canonical, freeze)
            (self.folder/"REVIEW.md").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "artifact hash differs"):
                validate_published_freeze(canonical, freeze)

        def published_budget_fixture(self, schema):
            out = self.folder/uuid.uuid4().hex
            out.mkdir(); directory = out/"budget-evidence"; directory.mkdir()
            live = self.folder/(out.name+".sqlite"); live.write_bytes(b"mutable live budget")
            live_wal = Path(str(live)+"-wal"); live_wal.write_bytes(b"mutable live WAL")
            snapshot = directory/"budget-0.sqlite"; snapshot.write_bytes(b"accepted SQL bytes")
            wal = Path(str(snapshot)+"-wal"); wal.write_bytes(b"accepted WAL bytes")
            accepted = self.folder/(out.name+".json"); accepted.write_bytes(b"accepted external evidence")
            recorded = {str(p.resolve()): file_sha(p) for p in (snapshot, wal)}
            field = "correctness_evidence" if schema == "a15-cpu-freeze-v1" else "correctness_evidence_sha256"
            freeze = {"schema": schema, "source_sha256": {"source": "hash"},
                field: {**recorded, str(accepted.resolve()): file_sha(accepted)},
                "budget_snapshots": [{"live_database": str(live.resolve()), "snapshot_database": str(snapshot.resolve()),
                    "files_sha256": recorded.copy()}]}
            for name in ("source.tar.gz", "REVIEW.md"): (out/name).write_bytes(b"mock package")
            (out/"source-manifest.json").write_text(json.dumps(freeze["source_sha256"]))
            def publish():
                (out/"freeze.json").write_text(json.dumps(freeze))
                (out/"package.json").write_text(json.dumps({"passed": True, "formal_performance_started": False,
                    "real_timing_samples": 0, "files_sha256": {name: file_sha(out/name) for name in
                    ("freeze.json", "source.tar.gz", "source-manifest.json", "REVIEW.md")}}))
            publish()
            return out, freeze, field, live, snapshot, wal, accepted, publish

        def test_all_correctness_evidence_files_are_rechecked(self):
            for schema in ("a15-cpu-freeze-v1", "a15-cuda-freeze-v1"):
                out, freeze, field, _, _, _, accepted, publish = self.published_budget_fixture(schema)
                validate_published_freeze(out/"freeze.json", freeze)
                original = accepted.read_bytes()
                accepted.write_bytes(b"changed external accepted evidence")
                with self.assertRaisesRegex(ValueError, "correctness evidence file"):
                    validate_published_freeze(out/"freeze.json", freeze)
                accepted.unlink()
                with self.assertRaisesRegex(ValueError, "correctness evidence file"):
                    validate_published_freeze(out/"freeze.json", freeze)
                accepted.write_bytes(original)
                old = freeze[field]; freeze[field] = {}; publish()
                with self.assertRaisesRegex(ValueError, "hash map is missing or empty"):
                    validate_published_freeze(out/"freeze.json", freeze)
                freeze[field] = old; publish()
                validate_published_freeze(out/"freeze.json", freeze)

        def test_missing_or_changed_budget_snapshots_block_both_schemas(self):
            for schema in ("a15-cpu-freeze-v1", "a15-cuda-freeze-v1"):
                out, freeze, _, _, snapshot, wal, _, _ = self.published_budget_fixture(schema)
                for target in (snapshot, wal):
                    with self.subTest(schema=schema, file=target.name):
                        original = target.read_bytes()
                        target.write_bytes(b"tampered immutable budget snapshot")
                        with self.assertRaisesRegex(ValueError, "correctness evidence file"):
                            validate_published_freeze(out/"freeze.json", freeze)
                        target.unlink()
                        with self.assertRaisesRegex(ValueError, "correctness evidence file"):
                            validate_published_freeze(out/"freeze.json", freeze)
                        target.write_bytes(original)
                validate_published_freeze(out/"freeze.json", freeze)

        def test_budget_snapshot_mapping_and_live_ledger_independence(self):
            for schema in ("a15-cpu-freeze-v1", "a15-cuda-freeze-v1"):
                out, freeze, field, live, snapshot, _, _, publish = self.published_budget_fixture(schema)
                live_wal = Path(str(live)+"-wal")
                for target in (live, live_wal): target.write_bytes(b"future signed records")
                original_sha = file_sha
                def read_only_snapshot(path):
                    self.assertNotIn(Path(path).resolve(), {live.resolve(), live_wal.resolve()})
                    return original_sha(path)
                with patch.object(module, "file_sha", side_effect=read_only_snapshot):
                    validate_published_freeze(out/"freeze.json", freeze)
                    live.unlink(); live_wal.unlink()
                    validate_published_freeze(out/"freeze.json", freeze)
                entry = freeze["budget_snapshots"][0]
                original = dict(entry["files_sha256"])
                entry["files_sha256"][str(snapshot.resolve())] = "0"*64; publish()
                with self.assertRaisesRegex(ValueError, "path/hash mapping differs"):
                    validate_published_freeze(out/"freeze.json", freeze)
                entry["files_sha256"] = original
                freeze[field][str(live.resolve())] = "0"*64; publish()
                with self.assertRaisesRegex(ValueError, "mutable live budget"):
                    validate_published_freeze(out/"freeze.json", freeze)
                del freeze[field][str(live.resolve())]
                entry["snapshot_database"] = str(live.resolve()); publish()
                with self.assertRaisesRegex(ValueError, "canonical package"):
                    validate_published_freeze(out/"freeze.json", freeze)
                entry["snapshot_database"] = str(snapshot.resolve())
                entry["files_sha256"].pop(str(snapshot.resolve())); publish()
                with self.assertRaisesRegex(ValueError, "exact database"):
                    validate_published_freeze(out/"freeze.json", freeze)

        def test_budget_snapshot_path_identity_and_independent_copy(self):
            out, freeze, field, live, snapshot, wal, _, publish = self.published_budget_fixture("a15-cuda-freeze-v1")
            entry = freeze["budget_snapshots"][0]
            original = dict(entry["files_sha256"])
            entry["files_sha256"][str(Path(str(snapshot)+"-shm"))] = "0"*64; publish()
            with self.assertRaisesRegex(ValueError, "exact database"):
                validate_published_freeze(out/"freeze.json", freeze)
            entry["files_sha256"] = original.copy()
            entry["files_sha256"]["relative.sqlite"] = "0"*64; publish()
            with self.assertRaisesRegex(ValueError, "absolute file paths"):
                validate_published_freeze(out/"freeze.json", freeze)
            entry["files_sha256"] = original.copy()
            old = freeze[field][str(snapshot.resolve())]
            freeze[field][str(snapshot.resolve())] = "0"*64; publish()
            with self.assertRaisesRegex(ValueError, "path/hash mapping differs"):
                validate_published_freeze(out/"freeze.json", freeze)
            freeze[field][str(snapshot.resolve())] = old
            freeze["budget_snapshots"] = []; publish()
            with self.assertRaisesRegex(ValueError, "budget snapshots are missing"):
                validate_published_freeze(out/"freeze.json", freeze)
            freeze["budget_snapshots"] = [entry, entry]; publish()
            with self.assertRaisesRegex(ValueError, "live budget identity is duplicated"):
                validate_published_freeze(out/"freeze.json", freeze)
            freeze["budget_snapshots"] = [entry]
            wal.unlink(); entry["files_sha256"].pop(str(wal)); freeze[field].pop(str(wal)); publish()
            validate_published_freeze(out/"freeze.json", freeze)
            snapshot.unlink(); os.link(live, snapshot)
            entry["files_sha256"][str(snapshot)] = file_sha(snapshot)
            freeze[field][str(snapshot)] = file_sha(snapshot); publish()
            with self.assertRaisesRegex(ValueError, "independent regular copy"):
                validate_published_freeze(out/"freeze.json", freeze)

        def harness(self, op="sign"):
            case = case_record(201, op, samples=2, family="unit")
            case["warmups"] = 0
            args = SimpleNamespace(plan=self.folder/"plan.json", worker_case=case["case_id"],
                output=self.folder/"evidence.jsonl", fixtures=self.folder/"fixtures", library=self.folder/"library.so",
                budget_db=self.folder/"budget.sqlite", build_record=None, freeze=None, cpus=None, timeout_seconds=1, case=None)
            args.plan.write_text(json.dumps({"schema": "a15-cpu-plan-v1", "cases": [case], "diagnostic_sample_override": True}))
            args.fixtures.mkdir()
            fixture_path = args.fixtures/"fixture.bin"
            fixture_path.write_bytes(b"immutable")
            inputs = {"pk": b"p"*32, "sk": b"s"*32+b"p"*32, "message": b"m", "context": b"c",
                      "sk_seed": b"s"*16, "sk_prf": b"s"*16, "pk_seed": b"p"*16, "sig": b"S"*2320}
            atomic_json(args.fixtures/"p201-fixture.json", {k: v.hex() for k, v in inputs.items()})
            class Budget:
                def __init__(self):
                    self.states, self.finishes, self.records = {}, [], {}
                    self.ledger_uuid = "1"*32
                def reserve(self, algorithm, public, message):
                    receipt = str(len(self.states)+1)
                    self.states[receipt] = "reserved"
                    self.records[receipt] = {"ledger_uuid": self.ledger_uuid, "receipt": receipt,
                        "algorithm": canonical_algorithm(algorithm), "key_id": canonical_key_id(algorithm, public),
                        "public_key_sha256": sha(public), "message_sha256": sha(message), "signature_sha256": None}
                    return receipt
                def finish(self, receipt, signature=None):
                    if self.states[receipt] != "reserved":
                        raise AssertionError("receipt finished twice")
                    self.states[receipt] = "committed" if signature is not None else "failed"
                    self.records[receipt]["signature_sha256"] = sha(signature) if signature is not None else None
                    self.finishes.append(receipt)
                def validate_receipt(self, receipt, **unused):
                    return {**self.records[receipt], "status": self.states[receipt]}
            budget = Budget()
            class Native:
                def __init__(self, pid, threads, flags, library):
                    self.backend, self.pk_bytes, self.sk_bytes, self.sig_bytes = flags, 32, 64, 2320
                def __enter__(self):
                    return self
                def __exit__(self, *unused):
                    pass
                def bind_key(self, key):
                    pass
                def verify(self, *unused):
                    return True
                def _check(self, op, code):
                    if code:
                        raise RuntimeError("mock ABI failure")
            call = Mock(return_value=0)
            stack = ExitStack()
            stack.enter_context(patch.object(module, "provenance", return_value={"final": False, "classification": "diagnostic",
                "source_sha256": {}, "library_sha256": "fixed", "freeze_sha256": None, "build_record_sha256": None,
                "build_record": None, "git": {}, "timing_scope": "mock"}))
            affinity = {"cpus": [0], "verified_physical": True}
            stack.enter_context(patch.object(module, "bind", return_value=affinity))
            stack.enter_context(patch.object(module, "environment", side_effect=lambda a: {"host": "mock", "affinity": a, "lscpu": {}, "turbo": {}, "governor": {}}))
            stack.enter_context(patch.dict(os.environ, openmp_environment(1, [0]), clear=True))
            stack.enter_context(patch.object(module, "fixture", return_value=(inputs, {str(fixture_path): file_sha(fixture_path)})))
            stack.enter_context(patch.object(module, "SigningBudget", return_value=budget))
            stack.enter_context(patch.object(module, "NativeSlhDsa", side_effect=Native))
            stack.enter_context(patch.object(module, "verify_library_runtime", return_value={"mock": True}))
            stack.enter_context(patch.object(module, "counters_enabled", return_value=False))
            stack.enter_context(patch.object(module, "sample_environment", return_value={}))
            stack.enter_context(patch.object(module, "raw_operation", return_value=(call, lambda: inputs["sig"])))
            stack.enter_context(patch.object(module, "validate_result", return_value={"valid": True}))
            stack.enter_context(patch.object(module, "theoretical", return_value={"hash_calls": 0, "compressions": 0}))
            self.addCleanup(stack.close)
            return args, budget, call

        def test_mock_worker_complete_and_skip(self):
            args, budget, call = self.harness()
            with patch.object(time, "perf_counter_ns", side_effect=[0, 10, 100, 130]):
                worker(args)
            self.assertEqual(call.call_count, 2)
            complete = next(r for r in rows(args.output) if r["kind"] == "case_complete")
            self.assertEqual((complete["n"], complete["median"], complete["iqr"]), (2, 20, 10))
            call.reset_mock()
            worker(args)
            self.assertEqual(call.call_count, 0)
            self.assertEqual(len(budget.finishes), 2)
            (args.fixtures/"fixture.bin").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "input file changed"):
                worker(args)

        def test_mock_interruption_and_partial_resume(self):
            args, budget, call = self.harness()
            call.side_effect = [0, RuntimeError("interrupted mock")]
            with patch.object(time, "perf_counter_ns", side_effect=[0, 10, 20]), self.assertRaisesRegex(RuntimeError, "interrupted"):
                worker(args)
            call.reset_mock()
            call.side_effect = None
            with patch.object(time, "perf_counter_ns", side_effect=[50, 70]):
                worker(args)
            self.assertEqual(call.call_count, 1)
            passed = [r["sample_index"] for r in rows(args.output) if r["kind"] == "sample" and r["passed"]]
            self.assertEqual(passed, [0, 1])
            self.assertEqual(list(budget.states.values()), ["committed", "failed", "committed"])

        def test_post_finalize_model_failure_preserves_original(self):
            args, budget, call = self.harness()
            with patch.object(module, "theoretical", side_effect=RuntimeError("model failure")), \
                    patch.object(time, "perf_counter_ns", side_effect=[0, 10]), self.assertRaisesRegex(RuntimeError, "model failure"):
                worker(args)
            self.assertEqual(budget.finishes, ["1"])
            self.assertEqual(budget.states["1"], "committed")

        def test_resume_environment_change_rejected(self):
            args, budget, call = self.harness()
            with patch.object(time, "perf_counter_ns", side_effect=[0, 10, 100, 130]):
                worker(args)
            with patch.object(module, "environment", return_value={"host": "other", "affinity": {"cpus": [0]}}), \
                    self.assertRaisesRegex(ValueError, "environment"):
                worker(args)

        def test_completed_case_rejects_other_ledger_before_native(self):
            args, budget, call = self.harness()
            with patch.object(time, "perf_counter_ns", side_effect=[0, 10, 100, 130]):
                worker(args)
            budget.ledger_uuid = "3"*32
            call.reset_mock()
            with self.assertRaisesRegex(ValueError, "resume|identity|ledger"):
                worker(args)
            self.assertEqual(call.call_count, 0)

        def test_completed_case_reconciles_live_receipt(self):
            args, budget, call = self.harness()
            with patch.object(time, "perf_counter_ns", side_effect=[0, 10, 100, 130]):
                worker(args)
            budget.records["1"]["signature_sha256"] = "0"*64
            call.reset_mock()
            with self.assertRaisesRegex(ValueError, "live receipt"):
                worker(args)
            self.assertEqual(call.call_count, 0)

        def test_mock_case_timeout(self):
            args, budget, call = self.harness("verify")
            topo = [{"cpu": 0, "core": 0, "socket": 0, "node": 0}]
            with patch.object(module, "topology", return_value=(topo, {})), \
                    patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired("mock", 1)), \
                    self.assertRaisesRegex(RuntimeError, "timeout"):
                run_cases(args)
            self.assertEqual(rows(args.output)[-1]["kind"], "case_process_timeout")
            self.assertEqual(call.call_count, 0)

        def test_output_protection(self):
            args, budget, call = self.harness("verify")
            args.output = args.fixtures/"bad.jsonl"
            with self.assertRaisesRegex(ValueError, "outside immutable"):
                protected_paths(args)

    # Any accidental real timing/native call makes the preparation tests fail.
    with patch.object(module, "NativeSlhDsa", side_effect=AssertionError("real native call forbidden in self-test")), \
            patch.object(time, "perf_counter_ns", side_effect=AssertionError("real sample timer forbidden in self-test")):
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Checks))
    if not result.wasSuccessful():
        raise RuntimeError("mock preparation checks failed")
    record = {"schema": "a15-bench-selftest-v1", "created_utc": utc(), "mock_checks": result.testsRun,
              "passed": True, "native_calls": 0, "real_timing_samples": 0,
              "tool_sha256": file_sha(Path(__file__)), "source_sha256": hashes(TOOL_FILES),
              "scope": "mock planning/statistics/file/resume/timeout/freeze orchestration only"}
    if output is not None:
        atomic_json(output, record)
    print(canonical(record))


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build", help="make -B optimized library and record source/build association")
    b.add_argument("--out", type=Path, required=True)
    b.add_argument("--cc", default="gcc")
    b.add_argument("--cflags", default="-O3")
    b.add_argument("--portable", action="store_true")
    plan = sub.add_parser("plan", help="emit cases only; never starts timing")
    plan.add_argument("--suite", choices=("smoke", "r3", "r4", "r5", "all"), default="smoke")
    plan.add_argument("--pids", type=integers, default=[1, 2, 3, 101, 102, 103])
    plan.add_argument("--threads", type=integers, default=[1, 2, 4, 8, 16, 32, 64])
    plan.add_argument("--r4-levels", type=integers, default=list(range(23)))
    plan.add_argument("--samples", type=int, help="diagnostic override only")
    plan.add_argument("--output", type=Path)
    plan.add_argument("--dry-run", action="store_true", help="validate and print plan statistics; no file/native/timer writes")
    for name in ("run", "worker", "smoke"):
        r = sub.add_parser(name)
        r.add_argument("--library", type=Path, required=True)
        r.add_argument("--build-record", type=Path)
        r.add_argument("--freeze", type=Path)
        r.add_argument("--plan", type=Path, required=name != "smoke")
        r.add_argument("--output", type=Path, required=True)
        r.add_argument("--fixtures", type=Path, required=True)
        r.add_argument("--budget-db", type=Path, required=True)
        r.add_argument("--cpus", type=integers)
        r.add_argument("--timeout-seconds", type=float, default=7200, help="whole sequential case subprocess timeout")
        if name == "worker":
            r.add_argument("--worker-case", required=True)
            r.add_argument("--parent-pid", required=True, type=int, help=argparse.SUPPRESS)
        else:
            r.add_argument("--case", action="append", help="exact case ID; may repeat; order remains plan order")
    inspect = sub.add_parser("inspect", help="print summaries and completion without executing C")
    inspect.add_argument("output", type=Path)
    sm3 = sub.add_parser("sm3-check", help="untimed known-answer/scalar-x8 correctness only")
    sm3.add_argument("--binary", type=Path, required=True)
    sm3.add_argument("--cc", default="gcc")
    sm3.add_argument("--build-command", required=True)
    sm3.add_argument("--output", type=Path, required=True)
    tests = sub.add_parser("self-test", help="mock-only unit checks; never loads C or calls a real timer")
    tests.add_argument("--output", type=Path, help="write actual passed mock evidence tied to source hashes")
    return p


def main():
    args = parser().parse_args()
    if args.command == "build":
        build(args)
    elif args.command == "plan":
        plan = make_plan(args.suite, args.pids, args.threads, args.r4_levels, args.samples)
        if args.dry_run:
            print(canonical({"schema": plan["schema"], "suite": plan["suite"], "cases": len(plan["cases"]),
                "timed_signatures": plan["estimated_timed_signatures"], "timed_calls": sum(c["samples"] for c in plan["cases"]),
                "minimums": plan["formal_minimums"], "r4_levels": sorted({c["cache_t"] for c in plan["cases"] if c["family"] == "R4"}),
                "physical_threads": sorted({c["threads"] for c in plan["cases"]}), "executes_native_or_timing": False}))
        elif args.output is None:
            raise ValueError("plan requires --output or --dry-run")
        else:
            atomic_json(args.output, plan)
            print(args.output)
    elif args.command == "worker":
        if args.parent_pid != os.getppid():
            raise ValueError("worker is internal; use run to hold the campaign output lock")
        worker(args)
    elif args.command == "smoke":
        if args.freeze:
            raise ValueError("toy smoke is always diagnostic")
        args.plan = args.output.with_suffix(".plan.json")
        if not args.plan.exists():
            atomic_json(args.plan, make_plan("smoke", [], [], []))
        with output_lock(args.output):
            run_cases(args)
    elif args.command == "run":
        with output_lock(args.output):
            run_cases(args)
    elif args.command == "self-test":
        self_test(args.output)
    elif args.command == "sm3-check":
        sm3_check_record(args)
    else:
        for row in rows(args.output):
            if row.get("kind") == "case_complete":
                print(canonical({k: row.get(k) for k in ("case_id", "n", "median", "q1", "q3", "iqr", "unit", "classification", "_line")}))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError) as exc:
        print("benchmark error: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
