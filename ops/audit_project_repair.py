"""Read-only audit of current repair evidence; no native calls or timing workers."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import sqlite3
import sys

from audit_optimization_delivery import Audit, hash_map, read_json, relative_name

ROOT = Path(__file__).resolve().parents[1]
STAGE_NAME = "build/repair-staging-20261004-r3"
REMOTE = "/home/guest-experiment/pqc-a1-5/" + STAGE_NAME
CPU_STEPS = ("avx2-build-and-tests", "counter-build-and-tests", "portable-build-and-tests", "sanitizer-tests",
             "external-avx2", "external-portable", "complete-128-24", "toy-differential",
             "subtree-differential", "exact-counts", "cli-and-budget")
CUDA_STEPS = ("release-kernels-faults-guards", "counter-kernels", "disabled-build-dispatch",
              "hidden-device-dispatch", "release-library-dependencies")
FUNCTIONAL_STEPS = ("budget-repair", "native-boundary", "tls-pytest", "tls-live-checks", "dependency-locks",
                    "native-source-guards", "bench_cpu-mock", "bench_cuda-mock", "freeze_cuda-mock",
                    "real-ca-dual-verification", "p0-p4-serialized-functional")
CLEAN_STEPS = ("clean-build", "clean-real-profiles", "clean-native-boundaries")
CONFIG_STEPS = ("A-first", "B", "A-return", "A-repeat", "C-flags", "A-flags-return")
CONFIG_CHECKS = {"changed_settings_rebuild", "A_B_A_rebuild", "A_repeat_reuses", "flags_rebuild",
                 "flags_return_rebuild", "A_bytes_reproducible", "source_unchanged"}
BASE_SOURCES = {"c/Makefile", "c/include/slhdsa_sm3.h", "c/src/engine.c", "c/src/secure_zero.h", "c/src/sm3.c"}
FIXTURE_ALGORITHMS = {"slh-dsa-sm3-128-24": "a15:slh:pid:3", "slh-dsa-sm3-128s": "a15:slh:pid:1",
                      "ml-dsa-44": "oid:2.16.840.1.101.3.4.3.17"}
TEST_KEY_FILES = {"handshake-test-key.json", "root-test-key.pem", "intermediate-test-key.pem", "leaf-test-key.pem"}
FIXTURE_FILES = TEST_KEY_FILES | {"root.der", "intermediate.der", "leaf.der", "intermediate-pre-tbs.der", "leaf-pre-tbs.der"}
FIXTURE_FILES |= {kind + "-" + edge + ".der" for kind in ("classical", "hybrid") for edge in ("root", "intermediate", "leaf")}


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            h.update(chunk)
    return h.hexdigest()


def sha_canonical(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    stage = ROOT / STAGE_NAME
    checks, records, errors, test_keys = [], {}, [], {}

    def local(name):
        name = relative_name(name)
        path = ROOT.joinpath(*PurePosixPath(name).parts)
        require(path.resolve().is_relative_to(ROOT.resolve()), "local evidence leaves project")
        cursor = path
        while cursor != ROOT:
            require(not cursor.is_symlink(), "local evidence contains a symbolic link")
            cursor = cursor.parent
        return path

    def verified(path, digest=None):
        relative = path.relative_to(ROOT).as_posix()
        require(local(relative).is_file(), "required evidence file missing: " + relative)
        observed = sha(path)
        require(digest is None or observed == digest, "evidence SHA256 differs: " + relative)
        records[relative] = observed
        return observed

    def read(path):
        verified(path)
        data = read_json(path)
        require(isinstance(data, dict), "expected JSON evidence object")
        return data

    def mapped(name):
        if name.startswith(REMOTE + "/"):
            candidate = stage / name[len(REMOTE) + 1:]
        else:
            candidate = stage / relative_name(name)
        require(candidate.resolve().is_relative_to(stage.resolve()), "evidence leaves repair mirror")
        return local(candidate.relative_to(ROOT).as_posix())

    def source_map(data, field, required=()):
        entries = hash_map(data.get(field), field)
        require(set(required) <= set(entries), "required current source missing")
        for name, digest in entries.items():
            verified(local(name), digest)

    def steps(data, expected, directory):
        observed = data.get("steps")
        require(isinstance(observed, list) and [x.get("name") for x in observed] == list(expected), "required step set differs")
        require(all(type(x.get("returncode")) is int and x["returncode"] == 0 for x in observed), "required step failed")
        for step in observed:
            log = directory / (step["name"] + ".log")
            require(isinstance(step.get("log_sha256"), str), "step log hash missing")
            if "log" in step:
                require(mapped(step["log"]).resolve() == log.resolve(), "step log identity differs")
            verified(log, step["log_sha256"])

    def check(name, action):
        try:
            details = action()
            checks.append(dict(name=name, passed=True, details=details))
        except Exception as error:
            errors.append(dict(name=name, error=str(error)))
            checks.append(dict(name=name, passed=False))

    def native(kind, count):
        directory = stage / ("validation/" + kind + "-native-repair-r3" if kind == "cuda"
                             else "validation/native-repair-r3")
        data = read(directory / "manifest.json")
        require(data.get("schema") == ("a15-cuda-native-v1" if kind == "cuda" else "a15-native-stage2-v1"), "native schema differs")
        require(data["passed"] is True and data["source_unchanged"] is True, "native acceptance failed")
        steps(data, CUDA_STEPS if kind == "cuda" else CPU_STEPS, directory)
        source_map(data, "source_hashes" if kind == "cuda" else "source_sha256", BASE_SOURCES)
        evidence = hash_map(data.get("evidence_sha256"), "native evidence")
        builds = hash_map(data.get("build_sha256"), "native build")
        for name, digest in evidence.items():
            verified(mapped(name), digest)
        required_logs = {directory / (name + ".log") for name in (CUDA_STEPS if kind == "cuda" else CPU_STEPS)}
        require(required_logs <= {mapped(name) for name in evidence}, "required native logs missing from evidence")
        for name, digest in builds.items():
            verified(mapped(name), digest)
        build_prefix = "build/" + ("cuda-native-repair-r3" if kind == "cuda" else "native-repair-r3")
        variants = ("release", "counters", "disabled") if kind == "cuda" else ("avx2", "counters", "portable")
        require({stage / build_prefix / variant / "libslhdsa_sm3.so" for variant in variants}
                <= {mapped(name) for name in builds}, "required native libraries missing")
        if kind == "cpu":
            require(data.get("inputs_unchanged") is True, "native input currentness missing")
            for name, digest in hash_map(data.get("inputs_sha256"), "native inputs").items():
                verified(local(name), digest)
        else:
            require(data.get("real_timing_samples") == 0 and data.get("formal_performance_started") is False
                    and data.get("measured_durations") is False, "CUDA native timing state differs")
        return dict(steps=count)

    def matrix(kind, count):
        directory = stage / ("validation/" + kind + "-full-repair-r3")
        data = read(directory / "summary.json")
        schema = "a15-optimization-correctness-v1" if kind == "cpu" else "a15-cuda-correctness-v1"
        require(data.get("schema") == schema, "matrix schema differs")
        require(data["passed"] is True and data["final"] is True and data["completed_requested_scope"] is True, "matrix acceptance incomplete")
        require(data["suite"] == "full" and not data["deferred_scope"], "matrix scope incomplete")
        require(data["planned_cases"] == data["passed_planned"] == count, "matrix count differs")
        require(data["formal_performance_started"] is False and data["measured_durations"] is False, "matrix timing state differs")
        require(all(data.get(name) == [] for name in ("failed_case_ids", "pending_case_ids", "unavailable_case_ids")), "matrix has uncovered cases")
        require(not data.get("failed_auxiliary_case_ids") and not data.get("error"), "matrix has auxiliary failures")
        require(kind != "cpu" or data.get("full_sha2") is True, "CPU full SHA2 coverage missing")
        source_map(data, "source_hashes", BASE_SOURCES | {"tools/native.py", "tools/signing_budget.py"})
        path = directory / "cases.jsonl"
        verified(path, data["cases_jsonl_sha256"])
        actual = 0
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                row = json.loads(line)
                digest = row.pop("record_sha256")
                require(sha_canonical(row) == digest, "matrix row checksum differs")
                require(row.get("schema") == schema and row.get("status") == "passed" and row.get("passed") is True,
                        "matrix row is not passed")
                require(row.get("formal_performance") is False, "matrix row timing state differs")
                require(row.get("source_hashes") == data["source_hashes"], "matrix row source binding differs")
                require(row.get("case_id") == row.get("case", {}).get("case_id") and isinstance(row.get("case_id"), str),
                        "matrix row case identity differs")
                require(isinstance(row.get("checks"), dict) and all(value is True for value in row["checks"].values()), "matrix row check failed")
                require(all(value is True for value in row.get("field_matches", {}).values()), "matrix count prediction differs")
                actual += 1
        require(isinstance(data["records"], int) and data["records"] == actual and actual >= count, "matrix actual record count differs")
        return dict(planned=count, records=actual)

    def functional():
        directory = stage / "validation/project-functional-repair-r3-final3"
        data = read(directory / "manifest.json")
        require(data.get("schema") == "a15-project-functional-v1", "functional schema differs")
        require(data["passed"] is True and data["source_unchanged"] is True and data["library_unchanged"] is True, "functional acceptance incomplete")
        require(data["real_timing_samples"] == 0 and data["formal_performance_started"] is False, "functional timing state differs")
        steps(data, FUNCTIONAL_STEPS, directory)
        source_map(data, "source_sha256", BASE_SOURCES | {"tools/bind_project_results.py", "tools/native.py",
            "base_tls/tls/alt_chain.py", "base_tls/tls/handshake/client.py", "base_tls/tests/test_merged_tls_fixes.py"})
        evidence = hash_map(data.get("evidence_sha256"), "functional evidence")
        require({name + ".log" for name in FUNCTIONAL_STEPS} | {"bench_cpu-mock.json", "bench_cuda-mock.json",
            "freeze_cuda-mock.json", "ca-verification.json", "p0-p4-size-functional.jsonl"} <= set(evidence), "required functional evidence missing")
        for name, digest in evidence.items():
            verified(directory / relative_name(name), digest)
        return dict(steps=11)

    def clean():
        directory = stage / "validation/clean-reproduction-repair-r3-final2"
        data = read(directory / "manifest.json")
        require(data.get("schema") == "a15-clean-reproduction-v1", "clean schema differs")
        require(data["passed"] is True and data["source_unchanged"] is True and data["real_timing_samples"] == 0
                and data.get("formal_performance_started") is False, "clean reproduction incomplete")
        steps(data, CLEAN_STEPS, directory)
        source_map(data, "source_sha256", (BASE_SOURCES - {"c/Makefile"}) | {"tools/native.py", "tools/reproduce_project.py"})
        hash_map(data.get("external_provider_sha256"), "clean installed provider inventory")
        return dict(steps=3)

    def config():
        directory = stage / "validation/build-config-repair-r3"
        data = read(directory / "manifest.json")
        require(data.get("schema") == "a15-build-config-regression-v1", "configuration schema differs")
        require(data["passed"] is True and isinstance(data.get("checks"), dict) and set(data["checks"]) == CONFIG_CHECKS
                and all(value is True for value in data["checks"].values()), "build configuration check set differs")
        require(data.get("native_calls") == data.get("real_timing_samples") == 0 and data.get("formal_performance_started") is False,
                "configuration timing state differs")
        verified(local("c/Makefile"), data["makefile_sha256"])
        steps(data, CONFIG_STEPS, directory)
        return dict(checks=len(data["checks"]))

    def binding():
        directory = stage / "report-data/DP1-final-repair-r3"
        data = read(directory / "package.json")
        require(data.get("schema") == "a15-final-correctness-analysis-binding-v1", "binding schema differs")
        require(data["passed"] is True and data["final"] is True and data["real_timing_samples"] == 0, "result binding incomplete")
        require(data.get("formal_performance_started") is False and data.get("performance_results") is None
                and data.get("network_performance_results") is None, "binding timing state differs")
        verified(local("tools/bind_project_results.py"), data["tool_sha256"])
        files = hash_map(data.get("files_sha256"), "binding files")
        require(set(files) == {"R1-current-case-index.csv", "R2-current-exact-counts.csv"}, "required bound CSV set differs")
        for name, digest in files.items():
            verified(directory / relative_name(name), digest)
        evidence = hash_map(data.get("evidence_sha256"), "binding input evidence")
        required = {stage / ("validation/" + kind + "-full-repair-r3/" + name)
                    for kind in ("cpu", "cuda") for name in ("summary.json", "cases.jsonl")}
        required |= {stage / "validation/project-functional-repair-r3-final3/manifest.json",
                     stage / "report-data/DP1-analysis-repair-20261004/analysis-checks.summary.json"}
        require({mapped(name) for name in evidence} == required, "binding input set differs")
        for name, digest in evidence.items():
            verified(mapped(name), digest)
        analysis = read(stage / "report-data/DP1-analysis-repair-20261004/analysis-checks.summary.json")
        require(analysis.get("passed") is True and analysis.get("no_native_execution") is True
                and analysis.get("checks") == data.get("analysis_checks") == 121, "analytical checks incomplete")
        source_map(analysis, "source_hashes")
        for name, digest in hash_map(analysis.get("package_files"), "analysis files").items():
            verified(stage / "report-data/DP1-analysis-repair-20261004" / relative_name(name), digest)
        return dict(analysis_checks=data["analysis_checks"], final=True)

    def demo():
        directory = stage / "validation/project-demo-repair-r3"
        data = read(directory / "manifest.json")
        require(data.get("schema") == "a15-demo-artifacts-v1", "demo schema differs")
        require(data["video_status"] == "generated" and data["performance_samples"] == 0, "demo state differs")
        require(not data["contains_private_keys"] and not data["contains_elapsed_times"], "demo disclosure state differs")
        artifacts = hash_map(data.get("artifacts_sha256"), "demo artifacts")
        require({"evidence-demo.mp4", "captions.srt", "evidence.json"}
                | {"slide-0" + str(i) + ".png" for i in range(1, 5)} <= set(artifacts), "required demo media missing")
        for name, digest in artifacts.items():
            verified(directory / relative_name(name), digest)
        return dict(frames=4, video="evidence presentation with Chinese captions")

    def resources():
        directory = stage / "validation/cuda-native-repair-r3"
        data = read(directory / "device-code-resource-sass.json")
        require(data.get("schema") == "a15-cuda-device-code-review-v1" and data.get("passed") is True,
                "CUDA device resource review incomplete")
        require(data.get("native_calls") == data.get("real_timing_samples") == 0, "resource review timing state differs")
        require(set(data.get("kernels", [])) == {"fors_leaf_kernel", "fors_reduce_kernel", "sm3_kernel"}, "resource kernel set differs")
        verified(directory / "device-code-resource-sass.log", data["sass_resource_sha256"])
        build = stage / "build/cuda-native-repair-r3/release/cuda-resources"
        verified(build / "sm3_cuda.o", data["object_sha256"])
        verified(build / "ptxas.log")
        require((build / "ptxas.log").stat().st_size > 0, "ptxas resource evidence empty")
        return dict(kernels=3, scope="Compiled SM86 resources and SASS; no runtime occupancy or performance measurement")

    def fixtures():
        directory = stage / "validation/real-alt-fixtures-repair-r3-parallel2"
        data = read(directory / "MANIFEST.json")
        require(data.get("schema") == "a15-alt-fixtures-v1" and data.get("test_only") is True
                and data.get("source_unchanged") is True and data.get("library_unchanged") is True,
                "test fixture bundle identity differs")
        source_map(data, "sources_sha256", {"base_tls/tls/alt_chain.py", "tools/alt_chain_fixtures.py", "tools/native.py"})
        verified(stage / "build/native-repair-r3/avx2/libslhdsa_sm3.so", data["library_sha256"])
        entries = data.get("fixtures")
        require(isinstance(entries, list) and len(entries) == 3
                and {entry.get("algorithm") for entry in entries} == set(FIXTURE_ALGORITHMS), "required fixture set differs")
        expected_receipts, key_files = {}, {}
        for entry in entries:
            algorithm = entry["algorithm"]
            fixture_dir = directory / algorithm
            require(mapped(entry["fixture_path"]).resolve() == fixture_dir.resolve(), "fixture path identity differs")
            verified(fixture_dir / "fixture.json", entry["fixture_sha256"])
            fixture = read(fixture_dir / "fixture.json")
            require(fixture.get("schema") == "a15-alt-fixture-v1" and fixture.get("test_only") is True
                    and fixture.get("alt_algorithm") == algorithm, "fixture is not the declared test instance")
            require(fixture.get("budget_ledger_uuid") == data.get("budget_ledger_uuid")
                    and fixture.get("library_sha256") == data["library_sha256"], "fixture ledger or library identity differs")
            source_map(fixture, "sources_sha256", {"base_tls/tls/alt_chain.py", "tools/alt_chain_fixtures.py", "tools/native.py"})
            files = hash_map(fixture.get("files_sha256"), "test fixture files")
            require(set(files) == FIXTURE_FILES, "required fixture file set differs")
            for name, digest in files.items():
                path = fixture_dir / relative_name(name)
                verified(path, digest)
                if name in TEST_KEY_FILES:
                    key_files[path.relative_to(ROOT).as_posix()] = digest
            signing = fixture.get("signing_records")
            require(isinstance(signing, list) and len(signing) == 2, "fixture CA signing records missing")
            pre_tbs = {files[name]: (fixture_dir / name).stat().st_size for name in ("intermediate-pre-tbs.der", "leaf-pre-tbs.der")}
            require({row.get("pre_tbs_sha256") for row in signing} == set(pre_tbs), "CA signed messages differ from fixture")
            for row in signing:
                require(row.get("algorithm") == algorithm and row.get("budget_status") == "committed"
                        and row.get("ledger_uuid") == data["budget_ledger_uuid"], "CA record identity or completion differs")
                require(row.get("message_bytes") == pre_tbs[row["pre_tbs_sha256"]], "CA preTBS length differs")
                receipt = row.get("budget_receipt")
                require(isinstance(receipt, str) and receipt and receipt not in expected_receipts, "CA receipt missing or duplicated")
                expected_receipts[receipt] = row
        ledger = stage / "validation/functional-parallel/ca-budget.sqlite"
        before = verified(ledger)
        require(not any(ledger.with_name(ledger.name + suffix).exists() for suffix in ("-wal", "-shm", "-journal")),
                "CA ledger snapshot has pending side files")
        connection = sqlite3.connect(ledger.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
        try:
            require(connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)], "CA ledger integrity check failed")
            metadata = dict(connection.execute("SELECT name,value FROM ledger_metadata"))
            require(metadata.get("identity_schema") == "2" and metadata.get("ledger_uuid") == data["budget_ledger_uuid"],
                    "live CA ledger UUID or identity schema differs")
            rows = connection.execute("SELECT r.receipt,r.status,r.message_sha256,r.signature_sha256,k.algorithm,k.public_key,k.key_id "
                                      "FROM reservations r JOIN keys k ON k.key_id=r.key_id").fetchall()
            observed = {row[0]: row[1:] for row in rows}
            for receipt, expected in expected_receipts.items():
                require(receipt in observed, "CA receipt absent from ledger")
                status, message, signature, algorithm, public, key_id = observed[receipt]
                require(status == "committed" and algorithm == expected["algorithm"] and message == expected["pre_tbs_sha256"]
                        and signature == expected["signature_sha256"]
                        and hashlib.sha256(public).hexdigest() == expected["issuer_public_key_sha256"], "CA receipt digest or status differs")
                require(key_id == hashlib.sha256(FIXTURE_ALGORITHMS[algorithm].encode("ascii") + b"\0" + public).hexdigest(),
                        "CA canonical key identity differs")
            for key_id, used, limit in connection.execute("SELECT key_id,used_text,limit_text FROM keys"):
                reservations = connection.execute("SELECT ordinal_text FROM reservations WHERE key_id=?", (key_id,)).fetchall()
                ordinals = sorted(int(row[0]) for row in reservations)
                require(int(used) == len(reservations) and ordinals == list(range(1, int(used) + 1))
                        and 0 <= int(used) <= int(limit), "CA ledger charge reconciliation differs")
        finally:
            connection.close()
        require(verified(ledger) == before, "CA ledger changed during read-only audit")
        verification = read(stage / "validation/project-functional-repair-r3-final3/ca-verification.json")
        require(verification.get("schema") == "a15-alt-fixture-verification-v1" and verification.get("passed") is True,
                "CA fixture functional verification incomplete")
        verified_signatures = {(item.get("algorithm"), item.get("public_key_sha256"), item.get("message_sha256"), item.get("signature_sha256"))
            for row in verification.get("rows", []) if row.get("passed") is True
            for item in row.get("verifiers", []) if item.get("passed") is True}
        require(all((row["algorithm"], row["issuer_public_key_sha256"], row["pre_tbs_sha256"], row["signature_sha256"])
                    in verified_signatures for row in expected_receipts.values()), "CA verification signature binding differs")
        test_keys.update(key_files)
        return dict(test_only=True, algorithms=3, signed_edges=6, hash_bound_test_key_files=len(key_files),
                    ledger_uuid=data["budget_ledger_uuid"], ledger_receipts_reconciled=True)

    def models():
        data = read(ROOT / "validation/ca-models-v2-summary-20261004.json")
        require(data["security_validation_complete"] is False, "expected separately disclosed unresolved search")
        for run in data["runs"]:
            manifest_path = local(run["manifest"])
            verified(manifest_path, run["manifest_sha256"])
            manifest = read(manifest_path)
            source_map(manifest, "source_sha256")
            verified(manifest_path.parent / "source.zip", manifest["source_archive_sha256"])
        for invocation in data["invocations"]:
            verified(local(invocation["first_text"]), invocation["first_text_sha256"])
        return dict(full_model_completed_verdicts=data["full_model_completed_verdicts"],
                    full_model_timeouts=data["full_model_timeouts"], incomplete_accepted_by_user=True)

    check("cpu-native", lambda: native("cpu", 11))
    check("cpu-full", lambda: matrix("cpu", 3471))
    # Serial-era fixtures have no parallel sidecars. Once any parallel marker
    # appears, all handoff, raw shard, exit and immutable ledger evidence is
    # mandatory; a missing sidecar must fail the named read-only check.
    cpu_directory = stage / "validation/cpu-full-repair-r3"
    cpu_parallel = any((cpu_directory / name).exists() for name in
                       ("provenance.json", "settlement.json", "settled-budget.sqlite"))
    for filename in ("manifest.json", "summary.json"):
        path = cpu_directory / filename
        if path.is_file():
            try:
                cpu_marker = read_json(path)
                cpu_parallel |= isinstance(cpu_marker, dict) and any(name in cpu_marker for name in
                                ("counter_measurements_serialized_per_process", "budget_snapshot_sha256", "parallel_provenance"))
            except (ValueError, UnicodeError):
                cpu_parallel = True
    if cpu_parallel:
        def parallel_cpu():
            from audit_parallel_correctness import audit_parallel, parallel_declared
            require(parallel_declared(cpu_directory), "parallel evidence marker missing")
            result = audit_parallel(ROOT, stage, REMOTE, cpu_directory)
            require(result["native_calls"] == result["real_timing_samples"] == 0
                    and result["formal_performance_started"] is False, "parallel audit executed runtime work")
            for name, value in result["evidence_sha256"].items():
                verified(local(name), value)
            return result["details"]
        check("cpu-parallel-provenance", parallel_cpu)
    check("cuda-native", lambda: native("cuda", 5))
    check("cuda-device-resources", resources)
    check("cuda-full", lambda: matrix("cuda", 1789))
    check("functional", functional)
    check("test-fixtures-and-ca-ledger", fixtures)
    check("clean-reproduction", clean)
    check("same-output-build-identity", config)
    check("correctness-analysis-binding", binding)
    check("demo-media", demo)
    check("formal-search-disclosure", models)
    delivery_audit = Audit(ROOT, readiness=STAGE_NAME + "/validation/repair-final-readiness-r3.json",
                     staging_root=STAGE_NAME, remote_staging_root=REMOTE,
                     external_manifest="validation/repair-external-evidence-r3-manifest.json")
    delivery = delivery_audit.run()
    require(delivery["native_calls"] == delivery["real_timing_samples"] == 0, "delivery audit executed runtime work")
    check("frozen-delivery-19", lambda: require(delivery["passed"], json.dumps(delivery["errors"])) or dict(checks=len(delivery["checks"])))
    if delivery["passed"]:
        verified(stage / "validation/repair-final-readiness-r3.json")
        verified(local("validation/repair-external-evidence-r3-manifest.json"))
    for path in sorted(delivery_audit.protected):
        verified(path)
    verified(local("ops/audit_project_repair.py"))
    verified(local("ops/audit_optimization_delivery.py"))
    result = dict(schema="a15-project-repair-local-audit-v1", passed=not errors,
                  created_utc=datetime.now(timezone.utc).isoformat(), checks=checks, errors=errors,
                  evidence_sha256=records, native_calls=0, real_timing_samples=0,
                  test_fixture_keys_sha256=test_keys, test_fixture_keys_test_only=True,
                  formal_performance_started=False, formal_full_session_security_complete=False,
                  user_accepted_incomplete=["full-session symbolic search"],
                  scope="Preserved evidence and current source audit; does not rerun Linux/CUDA execution or establish a cryptographic proof.")
    if args.output:
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return int(not result["passed"])


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
