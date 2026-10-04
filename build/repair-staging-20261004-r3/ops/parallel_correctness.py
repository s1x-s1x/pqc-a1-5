"""External CPU correctness workers and strict record merge; never benchmarks.

The worker command intentionally performs native correctness calls. The merge
command performs no native calls. Scheduling and stopping the serial process
belong to the caller; this tool never signals a process or writes an active run.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import sqlite3
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import check_optimization as opt

SigningBudget = opt.SigningBudget
HASH = re.compile(r"[0-9a-f]{64}\Z")
PROVENANCE_SCHEMA = "a15-parallel-correctness-provenance-v1"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def utc():
    return datetime.now(timezone.utc).isoformat()


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key: " + key)
        result[key] = value
    return result


class Snapshot:
    """Parse and hash the same bytes, then reject concurrent input changes."""

    def __init__(self):
        self.files = {}

    def read(self, path):
        path = Path(path).resolve()
        data = path.read_bytes()
        digest = sha_bytes(data)
        original = self.files.setdefault(str(path), digest)
        require(original == digest, "Input changed after snapshot: " + str(path))
        return data

    def json(self, path):
        return json.loads(self.read(path).decode("utf-8"), object_pairs_hook=no_duplicate_keys)

    def verify(self):
        for path, digest in self.files.items():
            require(opt.file_sha(path) == digest, "Input changed during operation: " + path)


def arguments(configuration, *, run_dir=None, resume=False):
    values = deepcopy(configuration)
    for field in ("run_dir", "budget_db", "vectors"):
        require(isinstance(values.get(field), str) and bool(values[field]), "Configuration path missing: " + field)
        values[field] = Path(values[field])
    require(isinstance(values.get("library"), list) and bool(values["library"]), "Library configuration empty")
    values["library"] = [Path(path) for path in values["library"]]
    if run_dir is not None:
        values["run_dir"] = Path(run_dir).resolve()
    values["resume"] = resume
    return SimpleNamespace(**values)


def load_original(manifest_path, budget_db, snapshot):
    manifest = snapshot.json(manifest_path)
    identity = manifest.get("identity")
    require(isinstance(identity, dict) and identity.get("schema") == opt.SCHEMA, "Original identity schema differs")
    config = identity.get("configuration")
    require(isinstance(config, dict) and config.get("suite") == "full" and config.get("full_sha2") is True
            and config.get("backends") == ["REF", "AVX2"]
            and config.get("threads") == [1, 2, 4, 8, 16, 32, 64], "Original complete configuration differs")
    args = arguments(config)
    require(Path(budget_db).resolve() == Path(identity["budget_database_path"]).resolve()
            == args.budget_db.resolve(), "Shared budget path differs from original")
    require(opt.source_hashes() == identity.get("sources_sha256") and bool(identity["sources_sha256"]), "Current source identity differs")
    libraries = identity.get("libraries")
    require(isinstance(libraries, dict) and bool(libraries) and len(libraries) == len(args.library), "Original libraries missing")
    for index, (label, entry) in enumerate(libraries.items()):
        require(isinstance(entry, dict) and isinstance(entry.get("sha256"), str) and HASH.fullmatch(entry["sha256"]), "Library hash malformed")
        require(label == f"lib{index}-{entry['sha256'][:12]}"
                and Path(entry["path"]).resolve() == args.library[index].resolve()
                and opt.file_sha(entry["path"]) == entry["sha256"], "Library identity differs")
        snapshot.read(entry["path"])
    require(sha_bytes(snapshot.read(args.vectors)) == identity.get("vector_sha256"), "Vector file differs")
    plan = opt.build_plan(args, libraries)
    require(plan == manifest.get("plan") and bool(plan), "Original full plan differs")
    require(len({case["case_id"] for case in plan}) == len(plan)
            and all(opt.case_id(case) == case["case_id"] for case in plan), "Original case identity duplicated or malformed")
    return manifest, args


def compatible(identity, original, *, worker=False):
    require(isinstance(identity, dict), "Input identity missing")
    expected = deepcopy(original)
    observed = deepcopy(identity)
    if worker:
        expected["configuration"].pop("run_dir", None)
        observed.get("configuration", {}).pop("run_dir", None)
    require(observed == expected, "Input manifest identity differs")


def selected_cases(plan, cases_path, snapshot):
    requested = snapshot.json(cases_path)
    require(isinstance(requested, list) and bool(requested), "Explicit case list is empty")
    by_id = {case["case_id"]: case for case in plan}
    result, seen = [], set()
    for item in requested:
        identifier = item if isinstance(item, str) else item.get("case_id") if isinstance(item, dict) else None
        require(identifier in by_id and identifier not in seen, "Requested case missing or duplicated")
        require(isinstance(item, str) or item == by_id[identifier], "Requested case definition differs")
        result.append(deepcopy(by_id[identifier]))
        seen.add(identifier)
    return result


def load_rows(path, snapshot):
    data = snapshot.read(path)
    require(not data or data.endswith(b"\n"), "Case file has an incomplete final line")
    rows = []
    for raw in data.splitlines(keepends=True):
        require(raw.strip(), "Case file has a blank record")
        row = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicate_keys)
        require(isinstance(row, dict), "Case record is not an object")
        checksum = row.get("record_sha256")
        body = {key: value for key, value in row.items() if key != "record_sha256"}
        require(isinstance(checksum, str) and HASH.fullmatch(checksum)
                and opt.sha(opt.canonical(body)) == checksum, "Case record checksum differs")
        rows.append((raw, row))
    return rows


def validate_checksum(row):
    checksum = row.get("record_sha256")
    body = {key: value for key, value in row.items() if key != "record_sha256"}
    require(isinstance(checksum, str) and HASH.fullmatch(checksum)
            and opt.sha(opt.canonical(body)) == checksum, "Case record checksum differs")


def auxiliary_plan(plan):
    """Exact auxiliary case forms emitted by the unchanged Runner."""
    allowed = {case["case_id"]: case for case in plan}
    origins = {}

    def add(parent, **changes):
        case = {**parent, **changes}
        case["case_id"] = opt.case_id(case)
        old = allowed.get(case["case_id"])
        require(old is None or old == case, "Auxiliary case definition collision")
        allowed[case["case_id"]] = case
        origins.setdefault(case["case_id"], set()).add(parent["case_id"])
        return case

    for case in plan:
        operation = case["operation"]
        if operation == "subtree":
            add(case, backend="REF", threads=1, operation="subtree_reference")
        elif operation == "keygen" and case["variant"] == "native-t0-source":
            add(case, operation="cache_save")
        elif operation == "cache_build":
            add(case, operation="cache_save", variant="real-build-save-t" + str(case["cache_t"]))
        elif operation in {"sign", "cache_load_roundtrip", "cache_root_binding"} and case["cache_t"] is not None:
            add(case, operation="cache_load_setup", variant=case["variant"] + "/load")
            if operation == "sign" and case["pid"] not in (3, 103):
                prep = add(case, operation="cache_prepare", variant=f"native-t{case['cache_t']}")
                saved = {**prep, "operation": "cache_save"}
                saved["case_id"] = opt.case_id(saved)
                allowed[saved["case_id"]] = saved
                origins.setdefault(saved["case_id"], set()).add(case["case_id"])
        if operation == "sign":
            add(case, operation="verify_generated")
    return allowed, origins


def expected_prediction(case, vector, parameter):
    operation = case["operation"]
    length = len(vector["mp_bytes"])
    sums = vector["trace"]["chain_sums"]
    if operation == "counter_probe":
        return opt.subtree_model(parameter, "fors", 0)
    if operation in {"subtree", "subtree_reference"}:
        return opt.subtree_model(parameter, case["kind"], case["height"], case["threads"])
    if operation in {"verify", "verify_generated"}:
        return opt.verify_model(parameter, length, sums)
    if operation == "keygen":
        return opt.keygen_model(parameter, case["threads"], case["cache_t"])
    if operation in {"cache_build", "cache_prepare"}:
        return opt.cache_model(parameter, "cache_build", case["cache_t"], case["threads"])
    if operation in {"cache_save", "cache_load_roundtrip"}:
        return opt.cache_model(parameter, "cache_save", case["cache_t"])
    if operation in {"cache_load_setup", "cache_root_binding"}:
        return opt.cache_model(parameter, "cache_load", case["cache_t"])
    if operation == "sign":
        return opt.sign_model(parameter, length, sums, case["cache_t"], case["threads"])
    return None


REQUIRED_CHECKS = {
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


def validate_row(row, identity, allowed, vectors, ps, ledger):
    validate_checksum(row)
    case = row.get("case")
    require(isinstance(case, dict) and row.get("case_id") == case.get("case_id")
            and allowed.get(row["case_id"]) == case and opt.case_id(case) == row["case_id"], "Record case differs from full or auxiliary plan")
    require(row.get("schema") == opt.SCHEMA and row.get("source_hashes") == identity["sources_sha256"]
            and row.get("library") == identity["libraries"].get(case["library"])
            and row.get("formal_performance") is False, "Record source/library/schema identity differs")
    require(row.get("status") == "passed" and row.get("passed") is True, "Unsuccessful raw record retained; preserve the original run separately")
    checks = row.get("checks")
    require(isinstance(checks, dict) and all(value is True for value in checks.values())
            and REQUIRED_CHECKS.get(case["operation"], set()).issubset(checks), "Required correctness checks missing or failed")
    vector = vectors[case["pid"]]
    fingerprint = opt.vector_fingerprint(vector)
    require(row.get("input") == fingerprint
            and row.get("input_sha256") == opt.sha(opt.canonical({"case": case, "input": fingerprint})), "Record vector fingerprint differs")
    require(row.get("result_sha256") == opt.sha(opt.canonical(row.get("result"))), "Record result digest differs")
    prediction = expected_prediction(case, vector, ps[case["pid"]])
    require(row.get("prediction") == prediction, "Independent count prediction differs")
    if prediction is not None:
        observed = row.get("observed")
        require(isinstance(observed, dict) and set(observed) == set(opt.FIELDS)
                and all(type(value) is int and value >= 0 for value in observed.values())
                and observed == prediction["counts"]
                and row.get("field_matches") == dict.fromkeys(opt.FIELDS, True), "Seven-field direct counts differ")
    else:
        require(row.get("field_matches") == {}, "Unexpected count matches for an unmodelled case")
    if case["operation"] in {"sign", "verify", "verify_generated"}:
        require(row.get("result", {}).get("signature_sha256") == opt.sha(vector["sig_bytes"]), "Signature result differs from fixed vector")
    if case["operation"] in {"sign", "sign_fault"}:
        receipt = row.get("budget_receipt")
        status = "committed" if case["operation"] == "sign" else "failed"
        require(isinstance(receipt, str) and receipt and row.get("budget_status") == status, "Signing receipt or status missing")
        if status == "failed":
            require(row.get("result", {}).get("error_code") == -5, "Expected self-check failure differs")
        binding = ledger.validate_receipt(receipt, algorithm=opt.ALGORITHMS[case["pid"]],
            public_key=vector["pk_bytes"], message=vector["mp_bytes"],
            signature_sha256=opt.sha(vector["sig_bytes"]) if status == "committed" else None,
            statuses=(status,))
        require(binding["ledger_uuid"] == ledger.ledger_uuid, "Receipt ledger UUID differs")
        return binding
    return None


def required_auxiliaries(case, allowed):
    operation = case["operation"]
    results = []

    def add(**changes):
        aux = {**case, **changes}
        aux["case_id"] = opt.case_id(aux)
        require(allowed.get(aux["case_id"]) == aux, "Expected auxiliary form missing")
        results.append(aux["case_id"])

    if operation == "sign":
        add(operation="verify_generated")
    if operation in {"sign", "cache_load_roundtrip", "cache_root_binding"} and case["cache_t"] is not None:
        add(operation="cache_load_setup", variant=case["variant"] + "/load")
    if operation == "keygen" and case["variant"] == "native-t0-source":
        add(operation="cache_save")
    if operation == "cache_build":
        add(operation="cache_save", variant="real-build-save-t" + str(case["cache_t"]))
    if operation == "subtree":
        add(backend="REF", threads=1, operation="subtree_reference")
    return results


def validate_auxiliary_results(case, latest, allowed):
    required = required_auxiliaries(case, allowed)
    require(all(identifier in latest for identifier in required), "Aggregate direct auxiliary evidence missing: " + case["case_id"])
    result = latest[case["case_id"]].get("result") or {}
    if case["operation"] == "subtree":
        reference = next(latest[identifier]["result"] for identifier in required
                         if latest[identifier]["case"]["operation"] == "subtree_reference")
        require(all(result.get(field) == reference.get(field) for field in ("root_hex", "auth_hex", "adrs_hex")), "Direct subtree differs from preserved scalar reference")
    if case["operation"] == "sign":
        verified = next(latest[identifier]["result"] for identifier in required
                        if latest[identifier]["case"]["operation"] == "verify_generated")
        require(result.get("signature_sha256") == verified.get("signature_sha256"), "Generated signature verifier digest differs")


def cache_bindings(rows):
    bindings = {}
    for _, row in rows:
        case, result = row["case"], row.get("result") or {}
        if row.get("status") != "passed":
            continue
        if case["operation"] == "derive_cache":
            for member in result.get("family", []):
                key = (case["library"], case["pid"], member["level"])
                digest = member["file_sha256"]
                require(key not in bindings or bindings[key] == digest, "Derived cache bindings conflict")
                bindings[key] = digest
        elif case["operation"] == "cache_load_setup":
            key = (case["library"], case["pid"], case["cache_t"])
            digest = result.get("cache_file_sha256")
            require(key not in bindings or bindings[key] == digest, "Loaded cache bindings conflict")
            bindings[key] = digest
    return bindings


def copy_worker_caches(cases, original_run, runner, snapshot):
    keys = {(case["library"], case["pid"], case["cache_t"]) for case in cases
            if case["operation"] in {"sign", "cache_build", "cache_load_roundtrip", "cache_root_binding"}
            and case["cache_t"] is not None}
    if not keys:
        return []
    # The serial JSONL may continue growing. Preserve the exact flushed prefix
    # used for cache provenance, rather than pretending the live file is frozen.
    cache_snapshot = Snapshot()
    source_records = original_run / "cases.jsonl"
    rows = load_rows(source_records, cache_snapshot)
    preserved_records = runner.run_dir / "cache-source-records.jsonl"
    with preserved_records.open("xb") as stream:
        stream.write(b"".join(raw for raw, _ in rows))
    snapshot.read(preserved_records)
    bindings = cache_bindings(rows)
    copied = []
    for label, pid, level in sorted(keys):
        source = original_run / "cache" / label / f"pid{pid}" / f"pid{pid}-t{level}.cache"
        if not source.exists():
            require(pid not in (3, 103), "Required large-pid cache is absent")
            continue
        require((label, pid, level) in bindings, "Cache lacks preserved derivation/load hash binding")
        content = snapshot.read(source)
        require(sha_bytes(content) == bindings[(label, pid, level)], "Cache bytes differ from preserved rows")
        opt.cache_payload(source, runner.ps[pid], runner.vectors[pid]["pk_bytes"], level)
        destination = runner.run_dir / "cache" / label / f"pid{pid}" / source.name
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(content)
        copied.append(dict(source_path=str(source.resolve()), destination_path=str(destination), sha256=sha_bytes(content),
            source_records_path=str(source_records.resolve()), source_records_snapshot_path=str(preserved_records),
            source_records_snapshot_sha256=cache_snapshot.files[str(source_records.resolve())]))
    return copied


def settle_budget(database, destination, ledger_uuid, expected_statuses):
    """Take a consistent SQLite backup and reconcile every charge, not just rows.

    The snapshot is the frozen evidence. Later CUDA use of the shared live DB
    does not alter this CPU settlement or its UUID/receipt/ordinal identities.
    """
    destination = Path(destination)
    require(not destination.exists(), "Budget settlement destination already exists")
    require(expected_statuses and all(row.get("count_reconciled") is True
            and row.get("states", {}).get("reserved", 0) == 0 for row in expected_statuses), "Budget still has reserved attempts")
    source = sqlite3.connect(Path(database).resolve().as_uri() + "?mode=ro", uri=True, timeout=60)
    target = sqlite3.connect(destination)
    try:
        source.backup(target)
        target.execute("PRAGMA journal_mode=DELETE")
        target.commit()
    finally:
        target.close()
        source.close()
    require(not any(destination.with_name(destination.name + suffix).exists() for suffix in ("-wal", "-shm", "-journal")), "Snapshot retains pending side files")
    connection = sqlite3.connect(destination.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
    try:
        require(connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)], "Settled ledger integrity failed")
        metadata = dict(connection.execute("SELECT name,value FROM ledger_metadata"))
        require(metadata.get("identity_schema") == "2" and metadata.get("ledger_uuid") == ledger_uuid, "Settled ledger UUID/schema differs")
        require(connection.execute("SELECT COUNT(*) FROM reservations WHERE status='reserved'").fetchone()[0] == 0, "Settled ledger has unfinished reservations")
        statuses, total = [], 0
        for key_id, algorithm, public, limit_text, used_text in connection.execute(
                "SELECT key_id,algorithm,public_key,limit_text,used_text FROM keys ORDER BY key_id"):
            require(key_id == SigningBudget.key_id(algorithm, public), "Settled canonical key identity differs")
            used, limit = int(used_text), int(limit_text)
            reservations = connection.execute("SELECT ordinal_text,status,signature_sha256 FROM reservations WHERE key_id=?", (key_id,)).fetchall()
            require(0 <= used <= limit and used == len(reservations)
                    and sorted(int(row[0]) for row in reservations) == list(range(1, used + 1)), "Settled fee or ordinal reconciliation failed")
            states = {}
            for ordinal, state, digest in reservations:
                require(state in {"failed", "committed"} and (state != "committed" or isinstance(digest, str) and HASH.fullmatch(digest)), "Settled receipt status/signature differs")
                states[state] = states.get(state, 0) + 1
            total += used
            statuses.append(dict(key_id=key_id, algorithm=algorithm, limit=limit, used=used,
                remaining=limit - used, states=states, count_reconciled=True))
        require(statuses == expected_statuses, "Budget changed before settlement; repeat on a settled database")
        # Capture every receipt, including interrupted attempts absent from JSONL.
        receipts = [{"receipt": row[0], "key_id": row[1], "ordinal": int(row[2]),
                     "message_sha256": row[3], "status": row[4], "signature_sha256": row[5]}
            for row in connection.execute("SELECT receipt,key_id,ordinal_text,message_sha256,status,signature_sha256 FROM reservations ORDER BY receipt")]
        require(total == len(receipts), "Unbound or orphaned settled reservation")
    finally:
        connection.close()
    return dict(schema="a15-cpu-correctness-budget-settlement-v1", ledger_uuid=ledger_uuid,
        live_database_path=str(Path(database).resolve()), snapshot_database_path=str(destination.resolve()),
        snapshot_sha256=opt.file_sha(destination), all_fees_preserved=True, ordinals_reconciled=True,
        reserved_attempts=0, charged_attempts=total, keys=statuses, receipts=receipts,
        native_calls=0, real_timing_samples=0, created_utc=utc())


def worker(manifest_path, cases_path, run_dir, budget_db, *, cache_source=None):
    snapshot = Snapshot()
    manifest, args = load_original(manifest_path, budget_db, snapshot)
    cases = selected_cases(manifest["plan"], cases_path, snapshot)
    run_dir = Path(run_dir).resolve()
    require(not run_dir.exists(), "Choose a new private worker directory")
    require(run_dir != args.run_dir.resolve() and not run_dir.is_relative_to(args.run_dir.resolve()), "Worker directory overlaps original run")
    original_run = Path(cache_source).resolve() if cache_source else Path(manifest_path).resolve().parent
    runner = opt.Runner(arguments(manifest["identity"]["configuration"], run_dir=run_dir))
    provenance = dict(schema=PROVENANCE_SCHEMA, kind="worker", original_manifest_path=str(Path(manifest_path).resolve()),
        original_manifest_sha256=snapshot.files[str(Path(manifest_path).resolve())],
        requested_case_ids=[case["case_id"] for case in cases], created_utc=utc(),
        global_atomic_measurements_serialized=True, formal_performance_started=False, real_timing_samples=0)
    error = None
    executed, bindings, current_case = [], [], None
    try:
        compatible(runner.identity, manifest["identity"], worker=True)
        require(runner.plan == manifest["plan"], "Worker full plan differs")
        copied = copy_worker_caches(cases, original_run, runner, snapshot)
        allowed, _ = auxiliary_plan(manifest["plan"])
        # Each worker probes its own process-local counter state before the
        # requested ordered cases; no existing row substitutes a native probe.
        probes = [case for case in manifest["plan"] if case["operation"] == "counter_probe"
                  and case["library"] in {item["library"] for item in cases}]
        schedule = probes + [case for case in cases if case["operation"] != "counter_probe"]
        for case in schedule:
            current_case = case
            start = len(runner.records)
            runner.run_case(case)
            require(len(runner.records) > start, "Worker emitted no native case record")
            for row in runner.records[start:]:
                binding = validate_row(row, runner.identity, allowed, runner.vectors, runner.ps, runner.ledger)
                if binding:
                    bindings.append(binding)
            runner.checkpoint()
            executed.append(case["case_id"])
        require(opt.source_hashes() == runner.sources
                and opt.file_sha(args.vectors) == manifest["identity"]["vector_sha256"]
                and all(opt.file_sha(item["path"]) == item["sha256"] for item in runner.libraries.values()), "Source/library/vector changed during worker")
        snapshot.verify()
        provenance["copied_caches"] = copied
    except BaseException as exc:
        error = f"{type(exc).__name__}: {exc}"
        receipt = getattr(exc, "budget_receipt", None)
        if receipt and current_case is not None:
            vector = runner.vectors[current_case["pid"]]
            try:
                bindings.append(runner.ledger.validate_receipt(receipt,
                    algorithm=opt.ALGORITHMS[current_case["pid"]], public_key=vector["pk_bytes"],
                    message=vector["mp_bytes"], statuses=("failed", "reserved")))
            except Exception as binding_error:
                error += "; receipt reconciliation: " + str(binding_error)
    finally:
        summary = runner.checkpoint(error, final=True)
        runner.close()
        provenance.update(executed_case_ids=executed, requested_scope_complete=error is None
            and all(runner.latest.get(case["case_id"], {}).get("passed") is True
                    and all(runner.latest.get(aux, {}).get("passed") is True
                            for aux in required_auxiliaries(case, auxiliary_plan(manifest["plan"])[0])) for case in cases),
            error=error, receipt_bindings=bindings, input_files_sha256=snapshot.files,
            cases_jsonl_sha256=opt.file_sha(runner.output), worker_summary_sha256=opt.file_sha(runner.summary_path),
            helper_sha256=opt.file_sha(Path(__file__)))
        opt.atomic_json(run_dir / "worker-provenance.json", provenance)
    require(provenance["requested_scope_complete"], "Worker requested scope did not pass: " + str(error))
    return provenance


def merge(manifest_path, input_runs, output, budget_db):
    snapshot = Snapshot()
    original, args = load_original(manifest_path, budget_db, snapshot)
    output = Path(output).resolve()
    require(not output.exists() and output == args.run_dir.resolve(), "Aggregate must be new and use the original configured run path")
    require(input_runs and len({str(Path(path).resolve()) for path in input_runs}) == len(input_runs), "Input runs empty or duplicated")
    vectors = opt.load_vectors(args.vectors)
    ps = opt.parameters()
    ledger = SigningBudget(budget_db)
    allowed, _ = auxiliary_plan(original["plan"])
    all_rows, provenance_runs, receipt_bindings, receipt_cases, cache_inputs = [], [], {}, {}, []
    for directory in input_runs:
        directory = Path(directory).resolve()
        require(directory != output and not output.is_relative_to(directory)
                and not directory.is_relative_to(output), "Aggregate overlaps an input run")
        manifest = snapshot.json(directory / "manifest.json")
        compatible(manifest.get("identity"), original["identity"], worker=True)
        require(manifest.get("plan") == original["plan"], "Input full plan differs")
        summary = snapshot.json(directory / "summary.json")
        rows = load_rows(directory / "cases.jsonl", snapshot)
        require(summary.get("schema") == opt.SCHEMA and summary.get("final") is True
                and summary.get("source_hashes") == original["identity"]["sources_sha256"]
                and summary.get("libraries") == original["identity"]["libraries"]
                and summary.get("records") == len(rows)
                and summary.get("cases_jsonl_sha256") == snapshot.files[str(directory / "cases.jsonl")]
                and summary.get("formal_performance_started") is False and summary.get("measured_durations") is False
                and summary.get("suite") == "full" and summary.get("full_sha2") is True
                and summary.get("deferred_scope") == [] and summary.get("global_atomic_measurements_serialized") is True
                and Path(summary["budget_database"]).resolve() == Path(budget_db).resolve(),
                "Input settled summary identity/count/hash differs")
        observed = {row["case_id"]: row for _, row in rows}
        plan_ids = {case["case_id"] for case in original["plan"]}
        passed_ids = plan_ids & {identifier for identifier, row in observed.items() if row.get("passed") is True}
        require(summary.get("planned_cases") == len(plan_ids) and summary.get("passed_planned") == len(passed_ids)
                and summary.get("pending_case_ids") == sorted(plan_ids - passed_ids)
                and summary.get("failed_case_ids") == [] and summary.get("unavailable_case_ids") == []
                and summary.get("failed_auxiliary_case_ids") == [], "Input summary case coverage differs")
        for raw, row in rows:
            binding = validate_row(row, original["identity"], allowed, vectors, ps, ledger)
            if binding:
                previous = receipt_bindings.setdefault(binding["receipt"], binding)
                require(previous == binding, "Receipt binding conflict")
                previous_case = receipt_cases.setdefault(binding["receipt"], row["case_id"])
                require(previous_case == row["case_id"], "One charged receipt was reused across distinct signing cases")
            all_rows.append((raw, row))
        source = dict(directory=str(directory), manifest_sha256=snapshot.files[str(directory / "manifest.json")],
            summary_sha256=snapshot.files[str(directory / "summary.json")],
            cases_jsonl_sha256=snapshot.files[str(directory / "cases.jsonl")], records=len(rows))
        worker_record = directory / "worker-provenance.json"
        if worker_record.exists():
            proof = snapshot.json(worker_record)
            require(proof.get("schema") == PROVENANCE_SCHEMA and proof.get("kind") == "worker"
                    and proof.get("requested_scope_complete") is True and proof.get("error") is None
                    and proof.get("cases_jsonl_sha256") == source["cases_jsonl_sha256"]
                    and proof.get("worker_summary_sha256") == source["summary_sha256"]
                    and proof.get("helper_sha256") == opt.file_sha(Path(__file__)), "Worker provenance incomplete or mismatched")
            source["worker_provenance_sha256"] = snapshot.files[str(worker_record)]
            for member in proof.get("copied_caches", []):
                cache_path = Path(member["destination_path"]).resolve()
                require(cache_path.is_relative_to(directory) and not cache_path.is_symlink(), "Worker copied cache leaves its private run")
                raw_cache = snapshot.read(cache_path)
                require(sha_bytes(raw_cache) == member.get("sha256"), "Worker copied cache bytes changed")
                record_path = Path(member["source_records_snapshot_path"]).resolve()
                require(record_path.is_relative_to(directory) and not record_path.is_symlink(), "Worker cache record snapshot leaves private run")
                require(sha_bytes(snapshot.read(record_path)) == member.get("source_records_snapshot_sha256"), "Worker cache record snapshot differs")
                cache_inputs.append(dict(input_run=str(directory), source_path=member.get("source_path"),
                    worker_path=str(cache_path), sha256=sha_bytes(raw_cache), raw_bytes=raw_cache))
        provenance_runs.append(source)
    latest = {row["case_id"]: row for _, row in all_rows}
    for case in original["plan"]:
        require(latest.get(case["case_id"], {}).get("case") == case, "Aggregate planned case missing: " + case["case_id"])
        validate_auxiliary_results(case, latest, allowed)
    statuses = ledger.status()
    require(statuses and all(row.get("count_reconciled") is True
            and row.get("states", {}).get("reserved", 0) == 0 for row in statuses), "Live budget reconciliation failed or attempts still reserved")
    snapshot.verify()
    output.mkdir()
    try:
        preserved = output / "provenance"
        preserved.mkdir()
        for index, source in enumerate(provenance_runs):
            folder = preserved / f"input-{index}"
            folder.mkdir()
            directory = Path(source["directory"])
            for filename in ("manifest.json", "summary.json", "cases.jsonl", "worker-provenance.json", "cache-source-records.jsonl"):
                path = directory / filename
                if path.exists():
                    with (folder / filename).open("xb") as stream:
                        stream.write(snapshot.read(path))
        cache_provenance = []
        for index, member in enumerate(cache_inputs):
            filename = f"provenance/cache-input-{index}.bin"
            with (output / filename).open("xb") as stream:
                stream.write(member["raw_bytes"])
            cache_provenance.append({key: value for key, value in member.items() if key != "raw_bytes"} | {"preserved_path": filename})
        settlement = settle_budget(budget_db, output / "settled-budget.sqlite", ledger.ledger_uuid, statuses)
        settled_receipts = {row["receipt"]: row for row in settlement["receipts"]}
        for receipt, binding in receipt_bindings.items():
            require(receipt in settled_receipts and all(settled_receipts[receipt][field] == binding[field]
                    for field in ("key_id", "message_sha256", "status", "signature_sha256")), "Settled receipt differs from verified matrix operation")
        settlement["record_receipts_verified"] = len(receipt_bindings)
        settlement["charged_attempts_without_matrix_rows"] = settlement["charged_attempts"] - len(receipt_bindings)
        require(settlement["charged_attempts_without_matrix_rows"] >= 0, "More bound receipts than settled charges")
        opt.atomic_json(output / "settlement.json", settlement)
        with (output / "cases.jsonl").open("xb") as stream:
            for raw, _ in all_rows:
                stream.write(raw)
        final_manifest = deepcopy(original)
        final_manifest["parallel_provenance"] = dict(schema=PROVENANCE_SCHEMA, input_runs=provenance_runs,
            original_manifest_path=str(Path(manifest_path).resolve()), original_manifest_sha256=snapshot.files[str(Path(manifest_path).resolve())],
            helper_path=str(Path(__file__).resolve()), helper_sha256=opt.file_sha(Path(__file__)),
            receipts_verified=len(receipt_bindings), ledger_uuid=ledger.ledger_uuid, created_utc=utc(),
            settled_budget_path=str(output / "settled-budget.sqlite"), settled_budget_sha256=settlement["snapshot_sha256"],
            settlement_path=str(output / "settlement.json"), settlement_sha256=opt.file_sha(output / "settlement.json"),
            copied_cache_inputs=cache_provenance,
            process_local_measurements_serialized=True, real_timing_samples=0, formal_performance_started=False)
        opt.atomic_json(output / "manifest.json", final_manifest)
        # Resume only parses preserved bytes and recomputes the original summary.
        # execute()/run_case()/native() are deliberately never called here.
        runner = opt.Runner(arguments(original["identity"]["configuration"], resume=True))
        try:
            require(runner.identity == original["identity"] and runner.plan == original["plan"], "Aggregate resume identity differs")
            summary = runner.checkpoint(final=True)
        finally:
            runner.close()
        require(summary["passed"] and summary["completed_requested_scope"] and summary["final"]
                and not summary["pending_case_ids"] and not summary["failed_case_ids"]
                and not summary["unavailable_case_ids"] and not summary["failed_auxiliary_case_ids"]
                and not summary["deferred_scope"] and not summary["error"], "Aggregate checkpoint incomplete")
        summary["global_atomic_measurements_serialized"] = False
        summary["counter_measurements_serialized_per_process"] = True
        summary["budget_database"] = str(output / "settled-budget.sqlite")
        summary["budget_status"] = settlement["keys"]
        summary["budget_ledger_uuid"] = ledger.ledger_uuid
        summary["budget_snapshot_sha256"] = settlement["snapshot_sha256"]
        opt.atomic_json(output / "summary.json", summary)
        snapshot.verify()
        provenance = dict(schema=PROVENANCE_SCHEMA, kind="aggregate", native_calls=0, real_timing_samples=0,
            formal_performance_started=False, original_identity_preserved=True,
            input_files_sha256=snapshot.files, input_runs=provenance_runs,
            receipt_bindings=list(receipt_bindings.values()), ledger_uuid=ledger.ledger_uuid,
            output_files_sha256={name: opt.file_sha(output / name) for name in ("manifest.json", "cases.jsonl", "summary.json", "settled-budget.sqlite", "settlement.json")},
            helper_sha256=opt.file_sha(Path(__file__)), created_utc=utc())
        opt.atomic_json(output / "provenance.json", provenance)
    except BaseException:
        # Only this invocation's new aggregate is removed; source runs remain.
        shutil.rmtree(output)
        raise
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("worker", help="Execute explicit correctness cases in one private process")
    run.add_argument("--manifest", type=Path, required=True)
    run.add_argument("--cases", type=Path, required=True, help="JSON array of exact case IDs or exact plan objects, executed in given order")
    run.add_argument("--run-dir", type=Path, required=True)
    run.add_argument("--budget-db", type=Path, required=True)
    run.add_argument("--cache-source", type=Path)
    combine = sub.add_parser("merge", help="Merge settled raw records at the original configured path; no native calls")
    combine.add_argument("--manifest", type=Path, required=True)
    combine.add_argument("--input-run", type=Path, action="append", required=True)
    combine.add_argument("--output", type=Path, required=True)
    combine.add_argument("--budget-db", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "worker":
        result = worker(args.manifest, args.cases, args.run_dir, args.budget_db, cache_source=args.cache_source)
    else:
        result = merge(args.manifest, args.input_run, args.output, args.budget_db)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
