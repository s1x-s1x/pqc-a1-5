"""Audit preserved parallel CPU correctness evidence using only the stdlib.

This module neither imports the native harness nor opens the live signing ledger.
Only the hash-bound, settled SQLite backup is read (immutable, read-only).
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sqlite3

SCHEMA = "a15-optimization-correctness-v1"
PROVENANCE = "a15-parallel-correctness-provenance-v1"
SETTLEMENT = "a15-cpu-correctness-budget-settlement-v1"
HASH = re.compile(r"[0-9a-f]{64}\Z")
FIELDS = ("prf", "prf_msg", "h_msg", "f", "h", "t", "compress")
MODELLED = {"counter_probe", "subtree", "subtree_reference", "verify", "verify_generated", "keygen",
            "cache_build", "cache_prepare", "cache_save", "cache_load_roundtrip", "cache_load_setup", "cache_root_binding", "sign"}
ALGORITHMS = {pid: f"slh-dsa-{family}-{parameter}" for family, parameter, pid in (
    ("sm3", "128s", 1), ("sm3", "128f", 2), ("sm3", "128-24", 3),
    ("sha2", "128s", 101), ("sha2", "128f", 102),
    ("sha2", "128-24", 103), ("sm3", "toy", 201))}
ALGORITHM_IDS = {name: f"a15:slh:pid:{pid}" for pid, name in ALGORITHMS.items()}
ALGORITHM_IDS["ml-dsa-44"] = "oid:2.16.840.1.101.3.4.3.17"
CHECKS = {
    "counter_probe": {"counters_enabled"},
    "verify": {"existing_signature_valid", "independent_trace_root"},
    "subtree": {"root_equals_scalar_REF", "auth_equals_scalar_REF"},
    "keygen": {"public_key_matches_existing_vector", "secret_key_matches_existing_vector"},
    "derive_cache": {"all_levels_exported", "top_root_matches"},
    "cache_build": {"native_nodes_equal_independent_level"},
    "cache_load_roundtrip": {"load_save_bytes_identical"},
    "cache_root_binding": {"recomputed_checksum_changed_root_rejected", "old_good_cache_preserved"},
    "sign": {"signature_equals_existing_complete_vector"},
    "verify_generated": {"new_signature_valid"},
    "sign_fault": {"self_check_error_returned", "failed_attempt_budget_consumed"},
    "backend_rejection": {"explicit_SHA2_AVX2_rejected"},
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate parallel JSON key: " + key)
        result[key] = value
    return result


def parse(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_keys)


def case_id(case):
    return "/".join(str(case[key]) for key in ("library", "pid", "backend", "threads", "operation", "variant"))


class Evidence:
    def __init__(self, root, stage, remote_stage):
        self.root, self.stage = Path(root).resolve(), Path(stage).resolve()
        require(self.stage.is_relative_to(self.root), "Parallel stage leaves project")
        self.remote_stage = remote_stage.rstrip("/")
        relative_stage = self.stage.relative_to(self.root).as_posix()
        suffix = "/" + relative_stage
        require(self.remote_stage.endswith(suffix), "Parallel remote stage mapping differs")
        self.remote_root = self.remote_stage[:-len(suffix)]
        self.files = {}

    def local(self, path):
        path = Path(path)
        require(".." not in path.parts, "Parallel evidence path contains parent traversal")
        require(path.is_absolute() and path.resolve().is_relative_to(self.root), "Parallel evidence leaves project")
        cursor = path
        while cursor != self.root:
            require(not cursor.is_symlink(), "Parallel evidence contains a symbolic link")
            cursor = cursor.parent
        return path

    def map(self, name, base=None):
        require(isinstance(name, str) and name, "Parallel evidence path missing")
        name = name.replace("\\", "/")
        if name.startswith(self.remote_stage + "/"):
            relative = name[len(self.remote_stage) + 1:]
            require(".." not in PurePosixPath(relative).parts, "Parallel stage evidence contains parent traversal")
            path = self.stage / relative
        elif name.startswith(self.remote_root + "/"):
            path = self.root / name[len(self.remote_root) + 1:]
        elif Path(name).is_absolute():
            path = Path(name)
        else:
            parts = PurePosixPath(name).parts
            require(parts and all(part not in ("", ".", "..") for part in parts), "Invalid relative parallel path")
            path = Path(base or self.stage).joinpath(*parts)
        return self.local(path)

    def read(self, path, expected=None):
        path = self.local(path)
        require(path.is_file(), "Required parallel evidence missing: " + str(path))
        raw = path.read_bytes()
        observed = digest(raw)
        require(expected is None or isinstance(expected, str) and HASH.fullmatch(expected) and observed == expected,
                "Parallel evidence SHA256 differs: " + str(path))
        relative = path.relative_to(self.root).as_posix()
        require(self.files.setdefault(relative, observed) == observed, "Parallel evidence changed during audit")
        return raw

    def json(self, path, expected=None):
        data = parse(self.read(path, expected))
        require(isinstance(data, dict), "Parallel JSON object expected")
        return data

    def verify(self):
        for name, expected in list(self.files.items()):
            self.read(self.root / name, expected)


def parallel_declared(cpu_dir):
    """Absent serial-era manifests remain compatible with existing fixtures."""
    directory = Path(cpu_dir)
    if any((directory / name).exists() for name in ("provenance.json", "settlement.json", "settled-budget.sqlite")):
        return True
    for filename in ("manifest.json", "summary.json"):
        path = directory / filename
        if path.is_file():
            try:
                data = parse(path.read_bytes())
            except (ValueError, UnicodeError):
                return True  # Let the named audit check report malformed evidence.
            if isinstance(data, dict) and ("parallel_provenance" in data
                    or "counter_measurements_serialized_per_process" in data
                    or "budget_snapshot_sha256" in data):
                return True
    return False


def auxiliary_cases(plan):
    allowed = {case["case_id"]: case for case in plan}
    required = {}
    def add(parent, mandatory=True, **changes):
        auxiliary = {**parent, **changes}
        auxiliary["case_id"] = case_id(auxiliary)
        identifier = auxiliary["case_id"]
        require(identifier not in allowed or allowed[identifier] == auxiliary, "Parallel auxiliary collision")
        allowed[identifier] = auxiliary
        if mandatory:
            required.setdefault(parent["case_id"], []).append(identifier)
        return auxiliary
    for case in plan:
        operation, level = case["operation"], case.get("cache_t")
        if operation == "subtree":
            add(case, backend="REF", threads=1, operation="subtree_reference")
        if operation == "keygen" and case["variant"] == "native-t0-source":
            add(case, operation="cache_save")
        if operation == "cache_build":
            add(case, operation="cache_save", variant="real-build-save-t" + str(level))
        if operation in {"sign", "cache_load_roundtrip", "cache_root_binding"} and level is not None:
            add(case, operation="cache_load_setup", variant=case["variant"] + "/load")
            if operation == "sign" and case["pid"] not in (3, 103):
                prepared = add(case, mandatory=False, operation="cache_prepare", variant="native-t" + str(level))
                add(prepared, mandatory=False, operation="cache_save")
        if operation == "sign":
            add(case, operation="verify_generated")
    return allowed, required


def rows(evidence, path, expected=None):
    raw = evidence.read(path, expected)
    require(not raw or raw.endswith(b"\n"), "Parallel JSONL has an incomplete final line")
    result = []
    for line in raw.splitlines(keepends=True):
        require(line.strip(), "Parallel JSONL has a blank row")
        row = parse(line)
        require(isinstance(row, dict), "Parallel case object expected")
        checksum = row.get("record_sha256")
        require(isinstance(checksum, str) and HASH.fullmatch(checksum)
                and canonical({key: value for key, value in row.items() if key != "record_sha256"}) == checksum,
                "Parallel case record checksum differs")
        result.append(row)
    return raw, result


def check_summary(data, row_list, plan_ids, identity, *, aggregate=False):
    latest = {row["case_id"]: row for row in row_list}
    passed = plan_ids & set(latest)
    require(data.get("schema") == SCHEMA and data.get("final") is True
            and data.get("source_hashes") == identity["sources_sha256"]
            and data.get("libraries") == identity["libraries"]
            and data.get("planned_cases") == len(plan_ids) and data.get("passed_planned") == len(passed)
            and data.get("records") == len(row_list) and data.get("pending_case_ids") == sorted(plan_ids - passed),
            "Parallel summary identity or coverage differs")
    require(data.get("suite") == "full" and data.get("full_sha2") is True
            and data.get("formal_performance_started") is False and data.get("measured_durations") is False
            and data.get("deferred_scope") == []
            and all(data.get(field) == [] for field in ("failed_case_ids", "unavailable_case_ids", "failed_auxiliary_case_ids")),
            "Parallel summary failure or timing state differs")
    if aggregate:
        require(passed == plan_ids and data.get("passed") is True and data.get("completed_requested_scope") is True
                and data.get("error") is None and data.get("global_atomic_measurements_serialized") is False
                and data.get("counter_measurements_serialized_per_process") is True,
                "Parallel aggregate acceptance or process-local counter disclosure differs")
    else:
        require(data.get("global_atomic_measurements_serialized") is True, "Worker counter serialization differs")


def audit_parallel(root, stage, remote_stage, cpu_dir, expected_plan_count=3471):
    evidence = Evidence(root, stage, remote_stage)
    directory = evidence.local(Path(cpu_dir).resolve())
    manifest = evidence.json(directory / "manifest.json")
    summary = evidence.json(directory / "summary.json")
    proof = evidence.json(directory / "provenance.json")
    parallel = manifest.get("parallel_provenance")
    require(isinstance(parallel, dict) and parallel.get("schema") == PROVENANCE,
            "Parallel manifest provenance missing")
    require(proof.get("schema") == PROVENANCE and proof.get("kind") == "aggregate"
            and proof.get("native_calls") == proof.get("real_timing_samples") == 0
            and proof.get("formal_performance_started") is False and proof.get("original_identity_preserved") is True,
            "Parallel aggregate provenance state differs")
    require(parallel.get("process_local_measurements_serialized") is True
            and parallel.get("real_timing_samples") == 0 and parallel.get("formal_performance_started") is False,
            "Parallel manifest timing or counter state differs")
    identity, plan = manifest.get("identity"), manifest.get("plan")
    require(isinstance(identity, dict) and identity.get("schema") == SCHEMA, "Parallel original identity missing")
    config = identity.get("configuration")
    require(isinstance(config, dict) and config.get("suite") == "full" and config.get("full_sha2") is True
            and config.get("backends") == ["REF", "AVX2"] and config.get("threads") == [1, 2, 4, 8, 16, 32, 64],
            "Parallel original full configuration differs")
    require(isinstance(plan, list) and len(plan) == expected_plan_count and all(isinstance(case, dict) for case in plan),
            "Parallel full plan size differs")
    plan_ids = {case["case_id"] for case in plan}
    require(len(plan_ids) == len(plan) and all(case_id(case) == case["case_id"] for case in plan),
            "Parallel full plan case IDs differ or repeat")
    if expected_plan_count == 3471:
        require({case["pid"] for case in plan} == set(ALGORITHMS)
                and {case["threads"] for case in plan} == set(config["threads"])
                and {case["backend"] for case in plan} == set(config["backends"]),
                "Parallel full parameter, thread or backend coverage differs")
    require(evidence.map(config["run_dir"]) == directory, "Parallel aggregate canonical directory differs")
    budget = evidence.map(config["budget_db"])
    require(evidence.map(identity["budget_database_path"]) == budget, "Parallel original budget path differs")
    sources = identity.get("sources_sha256")
    require(isinstance(sources, dict) and sources, "Parallel source identity empty")
    for name, value in sources.items():
        evidence.read(evidence.map(name, evidence.root), value)
    libraries = identity.get("libraries")
    require(isinstance(libraries, dict) and libraries and len(libraries) == len(config.get("library", [])), "Parallel libraries missing")
    for index, (label, member) in enumerate(libraries.items()):
        require(isinstance(member, dict) and isinstance(member.get("sha256"), str)
                and label == f"lib{index}-{member['sha256'][:12]}"
                and evidence.map(member["path"]) == evidence.map(config["library"][index]), "Parallel library identity differs")
        evidence.read(evidence.map(member["path"]), member["sha256"])
    helper = evidence.root / "ops/parallel_correctness.py"
    helper_sha = digest(evidence.read(helper))
    require(parallel.get("helper_sha256") == proof.get("helper_sha256") == helper_sha, "Parallel helper hash differs")
    evidence.read(evidence.map(parallel["helper_path"]), helper_sha)
    acceptance_dir = evidence.stage / "build/repair-delivery-tools/parallel-regression"
    acceptance = evidence.json(acceptance_dir / "selftest.json")
    require(acceptance.get("schema") == "a15-parallel-correctness-selftest-v1" and acceptance.get("passed") is True
            and type(acceptance.get("mock_checks")) is int and acceptance["mock_checks"] >= 55
            and acceptance.get("failures") == acceptance.get("errors") == acceptance.get("native_calls") == acceptance.get("real_timing_samples") == 0
            and acceptance.get("formal_performance_started") is False and acceptance.get("actual_matrix_acceptance") is False
            and acceptance.get("tool_sha256") == helper_sha, "Parallel helper launch acceptance differs")
    acceptance_test_sha = acceptance.get("test_tool_sha256")
    evidence.read(evidence.root / "ops/test_parallel_correctness.py", acceptance_test_sha)
    evidence.read(evidence.stage / "ops/test_parallel_correctness.py", acceptance_test_sha)
    require(evidence.read(acceptance_dir / "selftest.log").strip(), "Parallel helper launch acceptance log empty")
    vector_path = evidence.map(config["vectors"])
    vector_raw = evidence.read(vector_path, identity["vector_sha256"])
    fingerprints = {}
    for line_number, line in enumerate(vector_raw.splitlines(), 1):
        if not line:
            continue
        vector = parse(line)
        if "record_sha256" in vector:
            require(canonical({key: value for key, value in vector.items() if key != "record_sha256"}) == vector["record_sha256"],
                    "Parallel vector record checksum differs")
        pid = vector["pid"]
        require(pid not in fingerprints, "Parallel vector PID repeats")
        fingerprint = dict(case_id=vector["case_id"], pid=pid, vector_line=line_number,
            vector_file_sha256=identity["vector_sha256"], original_source=vector.get("source"),
            original_source_hashes=vector.get("source_hashes", vector.get("source_sha256")))
        for field, stored in (("public_key", "pk"), ("secret_key", "sk"), ("encoded_message", "mp"),
                              ("opt_rand", "opt_rand"), ("signature", "sig")):
            fingerprint[field + "_sha256"] = digest(bytes.fromhex(vector[stored]))
        fingerprints[pid] = fingerprint
    require({case["pid"] for case in plan} <= set(fingerprints), "Parallel planned vector PID missing")
    allowed, required_aux = auxiliary_cases(plan)
    receipts, receipt_cases = {}, {}

    def validate(row):
        case, identifier = row.get("case"), row.get("case_id")
        require(isinstance(case, dict) and allowed.get(identifier) == case and case_id(case) == identifier,
                "Parallel raw case differs from the full or auxiliary plan")
        require(row.get("schema") == SCHEMA and row.get("source_hashes") == sources
                and row.get("library") == libraries.get(case["library"]) and row.get("formal_performance") is False
                and row.get("status") == "passed" and row.get("passed") is True,
                "Parallel raw case identity or status differs")
        checks = row.get("checks")
        require(isinstance(checks, dict) and all(value is True for value in checks.values())
                and CHECKS.get(case["operation"], set()) <= set(checks), "Parallel required case checks differ")
        fingerprint = row.get("input")
        require(isinstance(fingerprint, dict) and "vector_file" in fingerprint
                and evidence.map(fingerprint["vector_file"]) == vector_path
                and {key: value for key, value in fingerprint.items() if key != "vector_file"} == fingerprints[case["pid"]]
                and row.get("input_sha256") == canonical({"case": case, "input": fingerprint}),
                "Parallel raw vector fingerprint differs")
        require(row.get("result_sha256") == canonical(row.get("result")), "Parallel raw result checksum differs")
        prediction, observed = row.get("prediction"), row.get("observed")
        require((prediction is not None) == (case["operation"] in MODELLED),
                "Parallel modeled count prediction missing or unexpected")
        if prediction is not None:
            require(isinstance(prediction, dict) and isinstance(prediction.get("counts"), dict)
                    and set(prediction["counts"]) == set(FIELDS) and isinstance(observed, dict)
                    and set(observed) == set(FIELDS) and all(type(value) is int and value >= 0 for value in observed.values())
                    and prediction["counts"] == observed and row.get("field_matches") == dict.fromkeys(FIELDS, True),
                    "Parallel seven-field count reconciliation differs")
        else:
            require(row.get("field_matches") == {}, "Parallel unmodelled field matches differ")
        operation, result = case["operation"], row.get("result") or {}
        if operation in {"sign", "verify", "verify_generated"}:
            require(result.get("signature_sha256") == fingerprint["signature_sha256"], "Parallel fixed signature digest differs")
        if operation in {"sign", "sign_fault"}:
            receipt, status = row.get("budget_receipt"), "committed" if operation == "sign" else "failed"
            require(isinstance(receipt, str) and receipt and row.get("budget_status") == status, "Parallel signing receipt missing")
            if status == "failed":
                require(result.get("error_code") == -5, "Parallel expected sign-fault result differs")
            binding = dict(ledger_uuid=proof["ledger_uuid"], receipt=receipt, algorithm=ALGORITHMS[case["pid"]],
                public_key_sha256=fingerprint["public_key_sha256"], message_sha256=fingerprint["encoded_message_sha256"],
                status=status, signature_sha256=fingerprint["signature_sha256"] if status == "committed" else None)
            require(receipt_cases.setdefault(receipt, identifier) == identifier, "Parallel receipt reused across distinct cases")
            require(receipts.setdefault(receipt, binding) == binding, "Parallel receipt bindings conflict")
        return row

    aggregate_raw, aggregate_rows = rows(evidence, directory / "cases.jsonl", summary.get("cases_jsonl_sha256"))
    for row in aggregate_rows:
        validate(row)
    check_summary(summary, aggregate_rows, plan_ids, identity, aggregate=True)
    latest = {row["case_id"]: row for row in aggregate_rows}
    def complete(case, observed):
        return case["case_id"] in observed and all(identifier in observed for identifier in required_aux.get(case["case_id"], []))
    for case in plan:
        require(complete(case, latest), "Parallel direct auxiliary evidence missing: " + case["case_id"])
        if case["operation"] == "subtree":
            reference = next(latest[identifier]["result"] for identifier in required_aux[case["case_id"]]
                             if latest[identifier]["case"]["operation"] == "subtree_reference")
            require(all(latest[case["case_id"]]["result"].get(field) == reference.get(field)
                        for field in ("root_hex", "auth_hex", "adrs_hex")), "Parallel subtree scalar reference differs")
    input_runs = parallel.get("input_runs")
    require(isinstance(input_runs, list) and len(input_runs) >= 2 and proof.get("input_runs") == input_runs,
            "Parallel input-run provenance differs")
    input_paths = [evidence.map(member["directory"]) for member in input_runs]
    require(len(set(input_paths)) == len(input_paths) and directory not in input_paths, "Parallel input directories repeat or overlap aggregate")
    history = evidence.stage / "validation/cpu-full-repair-r3-serial-history"
    work = evidence.stage / "validation/parallel-correctness-r3"
    generated_serial = work / "serial-snapshot"
    require(input_paths[0] in {history, generated_serial} and all(path.parent == work for path in input_paths[1:]),
            "Parallel serial or worker path identity differs")
    require(evidence.map(parallel["original_manifest_path"]) == history / "manifest.json", "Parallel original manifest path differs")
    require(proof.get("input_files_sha256", {}).get(parallel["original_manifest_path"]) == parallel["original_manifest_sha256"],
            "Parallel aggregate original manifest hash closure missing")
    original = evidence.json(history / "manifest.json", parallel["original_manifest_sha256"])
    expected_manifest = deepcopy(manifest)
    expected_manifest.pop("parallel_provenance", None)
    require(original == expected_manifest, "Parallel original manifest was changed")
    controller = evidence.read(work / "controller.py")
    handoff = evidence.json(work / "handoff.json")
    require(handoff.get("controller_sha256") == digest(controller)
            and handoff.get("cpu_signal") in {"SIGINT", "SIGTERM after stable SIGSTOP snapshot"}
            and handoff.get("waiting_signal") == "SIGSTOP"
            and handoff.get("formal_performance_started") is False and handoff.get("real_timing_samples") == 0,
            "Parallel controller handoff identity or timing differs")
    external_termination = handoff["cpu_signal"] == "SIGTERM after stable SIGSTOP snapshot"
    require((input_paths[0] == generated_serial) == external_termination,
            "Parallel serial snapshot does not match handoff signal")
    terminated_receipts = []
    if external_termination:
        termination = evidence.json(work / "termination.json")
        require(termination.get("original_raw_evidence_preserved") is True
                and termination.get("native_calls") == termination.get("real_timing_samples") == 0
                and evidence.map(termination["generated_snapshot"]) == generated_serial,
                "Parallel external termination disclosure differs")
        original_hashes = termination.get("original_files_sha256")
        require(isinstance(original_hashes, dict) and set(original_hashes) == {"manifest.json", "summary.json", "cases.jsonl"},
                "Parallel external termination original-file closure differs")
        for name, expected in original_hashes.items():
            evidence.read(history / name, expected)
        historical_summary = evidence.json(history / "summary.json")
        require(termination.get("original_summary_final") is historical_summary.get("final"),
                "Parallel original raw summary final state was changed")
        require(historical_summary.get("schema") == SCHEMA
                and historical_summary.get("source_hashes") == sources and historical_summary.get("libraries") == libraries
                and historical_summary.get("planned_cases") == len(plan)
                and historical_summary.get("formal_performance_started") is False
                and historical_summary.get("measured_durations") is False,
                "Parallel original raw summary identity differs")
        terminated_receipts = termination.get("charged_aborted_receipts")
        require(isinstance(terminated_receipts, list) and len(terminated_receipts) == len(set(terminated_receipts))
                and all(isinstance(receipt, str) and receipt for receipt in terminated_receipts),
                "Parallel interrupted receipt inventory differs")
    cores = handoff.get("physical_cpus")
    require(isinstance(cores, list) and cores and all(type(value) is int and value >= 0 for value in cores)
            and len(set(cores)) == len(cores) == handoff.get("core_budget"), "Parallel physical-core inventory differs")
    affinity = None
    extension = handoff.get("external_affinity_adjustment")
    if extension is not None:
        require(isinstance(extension, dict) and set(extension) == {"path", "sha256", "original_handoff_sha256"}
                and evidence.map(extension["path"]) == work / "affinity-adjustment.json", "Parallel affinity handoff extension differs")
        affinity = evidence.json(work / "affinity-adjustment.json", extension["sha256"])
        before_raw = evidence.read(work / "handoff.before-affinity.json", extension["original_handoff_sha256"])
        before = parse(before_raw)
        require(isinstance(before, dict) and {key: value for key, value in handoff.items() if key != "external_affinity_adjustment"} == before,
                "Parallel affinity adjustment changed original handoff fields")
        require(affinity.get("schema") == "a15-correctness-affinity-adjustment-v1" and affinity.get("status") == "applied"
                and affinity.get("original_handoff_sha256") == extension["original_handoff_sha256"]
                and affinity.get("controller_sha256") == digest(evidence.read(work / "affinity-controller.py"))
                and affinity.get("all_groups_launched") is True and affinity.get("core_budget") == len(cores)
                and affinity.get("native_calls") == affinity.get("real_timing_samples") == 0
                and affinity.get("formal_performance_started") is False,
                "Parallel affinity controller or disclosure differs")
        idle = affinity.get("observed_idle_percent")
        require(isinstance(idle, dict) and set(idle) == {str(core) for core in cores}
                and all(type(value) in (int, float) and 0 <= value <= 100 for value in idle.values()),
                "Parallel affinity resource snapshot differs")
        changes = affinity.get("changes")
        require(isinstance(changes, list) and changes and len({change["worker"] for change in changes}) == len(changes),
                "Parallel affinity change inventory differs")
    elif any((work / name).exists() for name in ("affinity-adjustment.json", "affinity-controller.py", "handoff.before-affinity.json")):
        raise ValueError("Parallel affinity artifacts lack handoff hash binding")
    assignments = evidence.json(work / "assignments.json")
    assigned = assignments.get("assignments")
    require(isinstance(assigned, list) and len(assigned) == len(input_runs) - 1, "Parallel assignment count differs")
    require([evidence.map(item["directory"]) for item in assigned] == input_paths[1:], "Parallel assignment order differs from raw merge inputs")
    all_assigned, serial_latest, concatenated, input_rows, worker_proofs = set(), {}, bytearray(), [], []
    observed_copied_caches = set()
    copied_caches = parallel.get("copied_cache_inputs")
    require(isinstance(copied_caches, list), "Parallel copied cache inventory missing")
    cache_aliases = {}
    for member in copied_caches:
        preserved = evidence.map(member["preserved_path"], directory)
        require(preserved.is_relative_to(directory / "provenance"), "Parallel preserved cache leaves provenance")
        evidence.read(preserved, member["sha256"])
        for field in ("source_path", "worker_path"):
            alias = evidence.map(member[field])
            require(alias not in cache_aliases or cache_aliases[alias][1] == member["sha256"], "Parallel cache alias conflict")
            cache_aliases[alias] = (preserved, member["sha256"])
        require(evidence.map(member["input_run"]) in input_paths[1:], "Parallel cache input run is not an assigned worker")

    def input_hashes(mapping):
        require(isinstance(mapping, dict) and mapping, "Parallel input hash closure missing")
        for name, expected in mapping.items():
            path = evidence.map(name)
            require(path != budget, "Parallel audit input closure names active budget")
            if path in cache_aliases:
                preserved, cache_sha = cache_aliases[path]
                require(expected == cache_sha, "Parallel cache input hash binding differs")
                evidence.read(preserved, expected)
            else:
                evidence.read(path, expected)

    for index, (member, input_path) in enumerate(zip(input_runs, input_paths)):
        preserved = directory / "provenance" / f"input-{index}"
        for filename, field in (("manifest.json", "manifest_sha256"), ("summary.json", "summary_sha256"), ("cases.jsonl", "cases_jsonl_sha256")):
            original_raw = evidence.read(input_path / filename, member[field])
            require(evidence.read(preserved / filename, member[field]) == original_raw, "Parallel preserved input bytes differ")
        input_manifest = evidence.json(input_path / "manifest.json")
        observed_identity, expected_identity = deepcopy(input_manifest.get("identity")), deepcopy(identity)
        require(isinstance(observed_identity, dict), "Parallel input identity missing")
        observed_identity.get("configuration", {}).pop("run_dir", None)
        expected_identity["configuration"].pop("run_dir", None)
        require(observed_identity == expected_identity and input_manifest.get("plan") == plan, "Parallel input full identity or plan differs")
        if index:
            require(evidence.map(input_manifest["identity"]["configuration"]["run_dir"]) == input_path, "Parallel worker run directory differs")
        raw, retained = rows(evidence, input_path / "cases.jsonl", member["cases_jsonl_sha256"])
        require(member.get("records") == len(retained), "Parallel input record count differs")
        for row in retained:
            validate(row)
        input_summary = evidence.json(input_path / "summary.json")
        check_summary(input_summary, retained, plan_ids, identity)
        require(input_summary.get("cases_jsonl_sha256") == member["cases_jsonl_sha256"]
                and evidence.map(input_summary["budget_database"]) == budget, "Parallel input summary raw hash or budget identity differs")
        concatenated.extend(raw)
        input_rows.append(retained)
        observed = {row["case_id"]: row for row in retained}
        if index == 0:
            serial_latest = observed
            if external_termination:
                require(evidence.read(history / "cases.jsonl") == raw,
                        "Parallel generated snapshot changed original serial raw records")
                require(evidence.map(input_manifest["identity"]["configuration"]["run_dir"]) == generated_serial
                        and isinstance(input_summary.get("error"), str)
                        and input_summary["error"].startswith("External SIGTERM handoff: controller-generated snapshot;")
                        and input_summary.get("passed") is False and input_summary.get("completed_requested_scope") is False,
                        "Parallel generated serial checkpoint disclosure differs")
            continue
        item = assigned[index - 1]
        require(item.get("name") == input_path.name and type(item.get("threads")) is int and item["threads"] in config["threads"],
                "Parallel worker assignment identity differs")
        case_file = evidence.map(item["cases_file"])
        require(case_file == work / (item["name"] + ".cases.json"), "Parallel cases-file path differs")
        selected = parse(evidence.read(case_file))
        require(isinstance(selected, list) and selected and selected == item.get("case_ids")
                and len(selected) == len(set(selected)) and set(selected) <= plan_ids and not all_assigned.intersection(selected),
                "Parallel assigned case IDs missing, duplicated or overlapping")
        all_assigned.update(selected)
        by_id = {case["case_id"]: case for case in plan}
        require(all((by_id[identifier]["pid"], by_id[identifier]["backend"], by_id[identifier]["threads"])
                    == (item["pid"], item["backend"], item["threads"]) for identifier in selected), "Parallel assignment group identity differs")
        worker = evidence.json(input_path / "worker-provenance.json", member.get("worker_provenance_sha256"))
        require(input_summary.get("error") is None, "Parallel worker summary error present")
        require(evidence.read(preserved / "worker-provenance.json", member.get("worker_provenance_sha256"))
                == evidence.read(input_path / "worker-provenance.json"), "Parallel preserved worker proof bytes differ")
        require(worker.get("schema") == PROVENANCE and worker.get("kind") == "worker"
                and worker.get("requested_scope_complete") is True and worker.get("error") is None
                and worker.get("global_atomic_measurements_serialized") is True
                and worker.get("formal_performance_started") is False and worker.get("real_timing_samples") == 0
                and worker.get("helper_sha256") == helper_sha
                and worker.get("original_manifest_sha256") == parallel["original_manifest_sha256"]
                and evidence.map(worker["original_manifest_path"]) == history / "manifest.json"
                and worker.get("requested_case_ids") == selected
                and worker.get("cases_jsonl_sha256") == member["cases_jsonl_sha256"]
                and worker.get("worker_summary_sha256") == member["summary_sha256"], "Parallel worker provenance identity or completion differs")
        probes = [case["case_id"] for case in plan if case["operation"] == "counter_probe"
                  and case["library"] in {by_id[identifier]["library"] for identifier in selected}]
        schedule = probes + [identifier for identifier in selected if by_id[identifier]["operation"] != "counter_probe"]
        require(worker.get("executed_case_ids") == schedule and all(complete(by_id[identifier], observed) for identifier in schedule),
                "Parallel worker executed scope or direct auxiliaries differ")
        require(set(observed).intersection(plan_ids) == set(schedule), "Parallel worker contains unassigned planned execution")
        local_receipts = {row["budget_receipt"] for row in retained if row["case"]["operation"] in {"sign", "sign_fault"}}
        worker_bindings = worker.get("receipt_bindings")
        require(isinstance(worker_bindings, list) and len(worker_bindings) == len(local_receipts)
                and {row.get("receipt") for row in worker_bindings} == local_receipts,
                "Parallel worker receipt scope differs")
        worker_proofs.extend(worker_bindings)
        caches = worker.get("copied_caches")
        require(isinstance(caches, list), "Parallel worker cache inventory missing")
        for cache in caches:
            source = evidence.map(cache["source_path"])
            destination = evidence.map(cache["destination_path"])
            require(destination.is_relative_to(input_path / "cache") and source.is_relative_to(history / "cache"), "Parallel worker cache paths differ")
            require(source in cache_aliases and destination in cache_aliases
                    and cache_aliases[source][1] == cache_aliases[destination][1] == cache["sha256"], "Parallel copied-cache provenance differs")
            observed_copied_caches.add((input_path, source, destination, cache["sha256"]))
            cache_records = evidence.map(cache["source_records_snapshot_path"])
            require(cache_records == input_path / "cache-source-records.jsonl"
                    and evidence.map(cache["source_records_path"]) == history / "cases.jsonl", "Parallel cache source-record path differs")
            cache_raw, cache_rows = rows(evidence, cache_records, cache["source_records_snapshot_sha256"])
            require(evidence.read(preserved / "cache-source-records.jsonl", cache["source_records_snapshot_sha256"]) == cache_raw,
                    "Parallel preserved cache source-record bytes differ")
            require(evidence.read(history / "cases.jsonl").startswith(cache_raw), "Parallel cache source rows differ from serial prefix")
            bindings = {}
            for row in cache_rows:
                case, result = row["case"], row.get("result") or {}
                if case["operation"] == "derive_cache":
                    for entry in result.get("family", []):
                        key = (case["library"], case["pid"], entry["level"])
                        require(key not in bindings or bindings[key] == entry["file_sha256"], "Parallel cache raw derivation hashes conflict")
                        bindings[key] = entry["file_sha256"]
                elif case["operation"] == "cache_load_setup":
                    key = (case["library"], case["pid"], case["cache_t"])
                    require(key not in bindings or bindings[key] == result.get("cache_file_sha256"), "Parallel cache raw load hashes conflict")
                    bindings[key] = result.get("cache_file_sha256")
            match = re.fullmatch(r"pid(\d+)-t(\d+)\.cache", destination.name)
            require(match is not None and bindings.get((destination.parent.parent.name, int(match[1]), int(match[2]))) == cache["sha256"],
                    "Parallel cache bytes lack raw derivation/load binding")
        worker_inputs = worker.get("input_files_sha256")
        require(isinstance(worker_inputs, dict) and worker_inputs.get(item["cases_file"]) == digest(evidence.read(case_file))
                and worker_inputs.get(worker["original_manifest_path"]) == parallel["original_manifest_sha256"],
                "Parallel worker assignment/original manifest input hashes missing")
        input_hashes(worker_inputs)
        log = evidence.read(work / (item["name"] + ".log"))
        require(log.strip(), "Parallel worker log is empty")
    require(bytes(concatenated) == aggregate_raw, "Parallel aggregate is not exact concatenation of retained raw input bytes")
    require(len(copied_caches) == len(observed_copied_caches) and observed_copied_caches ==
            {(evidence.map(member["input_run"]), evidence.map(member["source_path"]), evidence.map(member["worker_path"]), member["sha256"])
             for member in copied_caches}, "Parallel aggregate cache input inventory differs from workers")
    unfinished = {case["case_id"] for case in plan if not complete(case, serial_latest)}
    require(all_assigned == unfinished and assignments.get("pending_cases") == len(unfinished)
            and assignments.get("completed_serial") == len(plan_ids.intersection(serial_latest))
            and assignments.get("full_plan") == len(plan), "Parallel assignment coverage differs from settled serial prefix")
    input_hashes(proof.get("input_files_sha256"))
    require({evidence.map(name) for name in proof["input_files_sha256"]} >=
            {path / filename for path in input_paths for filename in ("manifest.json", "summary.json", "cases.jsonl")},
            "Parallel aggregate raw input closure incomplete")
    output_hashes = proof.get("output_files_sha256")
    require(isinstance(output_hashes, dict) and set(output_hashes) == {"manifest.json", "cases.jsonl", "summary.json", "settled-budget.sqlite", "settlement.json"},
            "Parallel aggregate output hash closure differs")
    for name, expected in output_hashes.items():
        evidence.read(directory / name, expected)
    execution = evidence.json(work / "execution.json")
    require(execution.get("all_workers_exited") is True and execution.get("all_returncodes_zero") is True
            and execution.get("core_budget") == len(cores) and execution.get("formal_performance_started") is False
            and execution.get("real_timing_samples") == 0, "Parallel worker exit summary differs")
    by_name = {item["name"]: item for item in assigned}
    running, started, finished, start_events = {}, set(), set(), {}
    for event in execution.get("events", []):
        name = event.get("worker")
        require(name in by_name and type(event.get("pid")) is int and event["pid"] > 0, "Parallel execution worker identity differs")
        if event.get("event") == "started":
            allocated = event.get("cores")
            busy = {core for member in running.values() for core in member[1]}
            require(name not in started and isinstance(allocated, list) and len(allocated) == len(set(allocated))
                    == event.get("threads") == by_name[name]["threads"] and set(allocated) <= set(cores)
                    and not set(allocated).intersection(busy), "Parallel worker physical-core allocation differs")
            started.add(name)
            start_events[name] = event
            running[name] = (event["pid"], allocated)
        else:
            require(event.get("event") == "finished" and name in running and running[name][0] == event["pid"]
                    and type(event.get("returncode")) is int and event["returncode"] == 0 and name not in finished,
                    "Parallel worker exit code or event order differs")
            running.pop(name)
            finished.add(name)
    require(not running and started == finished == set(by_name), "Parallel workers did not all settle")
    controller_log = evidence.read(evidence.stage / "validation/repair-pipeline/speed-controller.log")
    logged_starts, logged_finishes = {}, {}
    for line in controller_log.splitlines():
        try:
            event = parse(line)
        except (ValueError, UnicodeError):
            continue
        if not isinstance(event, dict):
            continue
        if "started" in event:
            require(event["started"] not in logged_starts, "Parallel controller log repeats a worker start")
            logged_starts[event["started"]] = event
        if "finished" in event:
            require(event["finished"] not in logged_finishes, "Parallel controller log repeats a worker finish")
            logged_finishes[event["finished"]] = event
    require(set(logged_starts) == set(logged_finishes) == set(by_name)
            and all(logged_starts[name].get("pid") == start_events[name]["pid"]
                    and logged_starts[name].get("threads") == by_name[name]["threads"]
                    and logged_starts[name].get("cores") == start_events[name]["cores"]
                    and logged_finishes[name].get("returncode") == 0 for name in by_name),
            "Parallel controller raw log differs from settled execution events")
    if affinity is not None:
        occupied_targets, changed_tids = set(), set()
        for change in affinity["changes"]:
            name = change.get("worker")
            require(name in by_name and name in start_events, "Parallel affinity worker was not assigned or started")
            initial, targets = change.get("assigned_initial_cores"), change.get("new_cores")
            event = start_events[name]
            require(type(change.get("threads")) is int and 1 <= change["threads"] <= 4
                    and change["threads"] == by_name[name]["threads"] == event["threads"]
                    and change.get("pid") == event["pid"] and initial == event["cores"]
                    and isinstance(targets, list) and len(targets) == len(set(targets)) == change["threads"]
                    and set(targets) <= set(cores) and not set(targets).intersection(occupied_targets)
                    and not set(targets).intersection(initial) and all(affinity["observed_idle_percent"][str(core)] >= 90 for core in targets),
                    "Parallel affinity worker PID/thread/old/new core binding differs")
            occupied_targets.update(targets)
            tasks = change.get("tasks")
            require(isinstance(tasks, list) and tasks and any(task.get("tid") == event["pid"] for task in tasks),
                    "Parallel affinity process TID evidence missing")
            for task in tasks:
                require(type(task.get("tid")) is int and task["tid"] > 0 and task["tid"] not in changed_tids
                        and task.get("before") == initial and task.get("after") == targets, "Parallel affinity TID before/after evidence differs")
                changed_tids.add(task["tid"])
            command = change.get("command")
            require(isinstance(command, str) and "ops/parallel_correctness.py worker " in command
                    and "--run-dir " + by_name[name]["directory"] + " " in command
                    and "--cases " + by_name[name]["cases_file"] + " " in command
                    and "--manifest " + parallel["original_manifest_path"] + " " in command,
                    "Parallel affinity worker command identity differs")
    publication = evidence.json(work / "published.json")
    require(publication.get("passed") is True and evidence.map(publication["canonical_path"]) == directory
            and publication.get("summary_sha256") == digest(evidence.read(directory / "summary.json"))
            and publication.get("formal_performance_started") is False and publication.get("real_timing_samples") == 0,
            "Parallel publication binding differs")
    settle_path = evidence.map(parallel["settlement_path"])
    snapshot = evidence.map(parallel["settled_budget_path"])
    require(settle_path == directory / "settlement.json" and snapshot == directory / "settled-budget.sqlite"
            and evidence.map(summary["budget_database"]) == snapshot, "Parallel settled evidence path differs")
    settlement = evidence.json(settle_path, parallel["settlement_sha256"])
    snapshot_sha = digest(evidence.read(snapshot, parallel["settled_budget_sha256"]))
    uuid = proof.get("ledger_uuid")
    require(isinstance(uuid, str) and uuid and uuid == parallel.get("ledger_uuid") == summary.get("budget_ledger_uuid") == settlement.get("ledger_uuid"),
            "Parallel ledger UUID differs")
    require(settlement.get("schema") == SETTLEMENT and settlement.get("snapshot_sha256") == summary.get("budget_snapshot_sha256") == snapshot_sha
            and evidence.map(settlement["snapshot_database_path"]) == snapshot
            and evidence.map(settlement["live_database_path"]) == budget
            and settlement.get("all_fees_preserved") is True and settlement.get("ordinals_reconciled") is True
            and settlement.get("reserved_attempts") == settlement.get("native_calls") == settlement.get("real_timing_samples") == 0,
            "Parallel settled budget state differs")
    require(not any(snapshot.with_name(snapshot.name + suffix).exists() for suffix in ("-wal", "-shm", "-journal")),
            "Parallel settled budget has pending side files")
    connection = sqlite3.connect(snapshot.as_uri() + "?mode=ro&immutable=1", uri=True)
    try:
        require(connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)], "Parallel settled budget integrity differs")
        metadata = dict(connection.execute("SELECT name,value FROM ledger_metadata"))
        require(metadata.get("identity_schema") == "2" and metadata.get("ledger_uuid") == uuid, "Parallel SQLite UUID or identity schema differs")
        statuses, ledger_bindings, ledger_receipts = [], {}, []
        for key_id, algorithm, public, limit_text, used_text in connection.execute(
                "SELECT key_id,algorithm,public_key,limit_text,used_text FROM keys ORDER BY key_id"):
            require(algorithm in ALGORITHM_IDS and key_id == digest(ALGORITHM_IDS[algorithm].encode("ascii") + b"\0" + public),
                    "Parallel settled canonical key identity differs")
            used, limit = int(used_text), int(limit_text)
            attempts = connection.execute("SELECT receipt,ordinal_text,message_sha256,status,signature_sha256 FROM reservations WHERE key_id=?", (key_id,)).fetchall()
            require(0 <= used <= limit and used == len(attempts)
                    and sorted(int(row[1]) for row in attempts) == list(range(1, used + 1)), "Parallel settled charge or ordinal reconciliation differs")
            states = {}
            for receipt, ordinal, message, status, signature in attempts:
                require(status in {"failed", "committed"} and isinstance(message, str) and HASH.fullmatch(message)
                        and (status != "committed" or isinstance(signature, str) and HASH.fullmatch(signature)), "Parallel settled receipt state differs")
                states[status] = states.get(status, 0) + 1
                ledger_receipts.append(dict(receipt=receipt, key_id=key_id, ordinal=int(ordinal), message_sha256=message, status=status, signature_sha256=signature))
                ledger_bindings[receipt] = dict(ledger_uuid=uuid, receipt=receipt, key_id=key_id, algorithm=algorithm,
                    public_key_sha256=digest(public), message_sha256=message, status=status, signature_sha256=signature)
            statuses.append(dict(key_id=key_id, algorithm=algorithm, limit=limit, used=used, remaining=limit-used, states=states, count_reconciled=True))
        total = connection.execute("SELECT COUNT(*) FROM reservations").fetchone()[0]
        require(total == len(ledger_receipts), "Parallel settled ledger contains orphaned reservations")
    finally:
        connection.close()
    require(settlement.get("keys") == summary.get("budget_status") == statuses
            and settlement.get("receipts") == sorted(ledger_receipts, key=lambda row: row["receipt"])
            and settlement.get("charged_attempts") == total and settlement.get("record_receipts_verified") == parallel.get("receipts_verified") == len(receipts)
            and settlement.get("charged_attempts_without_matrix_rows") == total - len(receipts) >= 0,
            "Parallel settlement does not preserve every charged attempt")
    bindings = proof.get("receipt_bindings")
    require(isinstance(bindings, list) and len(bindings) == len(receipts)
            and {member.get("receipt") for member in bindings} == set(receipts), "Parallel aggregate receipt inventory differs")
    for binding in bindings + worker_proofs:
        receipt = binding.get("receipt")
        require(receipt in receipts and binding == ledger_bindings.get(receipt)
                and {key: value for key, value in binding.items() if key != "key_id"} == receipts[receipt], "Parallel preserved signing receipt differs from settled ledger")
    require(all(receipt in ledger_bindings and ledger_bindings[receipt]["status"] == "failed"
                and receipt not in receipts for receipt in terminated_receipts),
            "Parallel interrupted attempts were not preserved as separately charged failures")
    evidence.read(evidence.root / "ops/audit_parallel_correctness.py")
    evidence.verify()
    return dict(details=dict(planned=len(plan), workers=len(assigned), preserved_raw_records=len(aggregate_rows),
                exact_raw_concatenation=True, assignment_coverage_complete=True, all_worker_exit_codes_zero=True,
                charged_attempts=total, receipts_bound_to_rows=len(receipts), settled_ledger_uuid=uuid,
                process_local_counter_measurements=True), evidence_sha256=evidence.files,
                native_calls=0, real_timing_samples=0, formal_performance_started=False)
