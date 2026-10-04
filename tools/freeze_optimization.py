"""Verify optimization evidence and prepare a source freeze, without timing."""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import bench_cpu
import check_optimization


def digest(path):
    state = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            state.update(block)
    return state.hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


class InputSnapshot:
    """Bind parsed evidence to its first bytes, then reject later changes."""

    def __init__(self):
        self.sha256 = {}
        self.parsed_paths = set()

    def read_bytes(self, path, *, parsed=False):
        path = Path(path).resolve()
        data = path.read_bytes()
        current = hashlib.sha256(data).hexdigest()
        key = str(path)
        original = self.sha256.setdefault(key, current)
        require(current == original, "input changed after first snapshot: " + key)
        if parsed:
            self.parsed_paths.add(key)
        return data

    def digest(self, path):
        return hashlib.sha256(self.read_bytes(path)).hexdigest()

    def read_json(self, path):
        return json.loads(self.read_bytes(path, parsed=True).decode("utf8"))

    def lines(self, path):
        return self.read_bytes(path, parsed=True).decode("utf8").splitlines()

    def archive(self, path):
        return tarfile.open(fileobj=io.BytesIO(self.read_bytes(path, parsed=True)), mode="r:*")

    def evidence_hashes(self, paths):
        for path in paths:
            self.read_bytes(path, parsed=True)
        return {path: self.sha256[path] for path in sorted(self.parsed_paths)}

    def verify(self):
        for path, expected in self.sha256.items():
            require(digest(path) == expected, "input changed during validation/packaging: " + path)


def publish_freeze(out, freeze, snapshot):
    """The canonical permit is the final commit; no candidate permit is saved."""
    encoded = (json.dumps(freeze, indent=2, ensure_ascii=False) + "\n").encode("utf8")
    result = {name: digest(out / name) for name in ("source.tar.gz", "source-manifest.json", "REVIEW.md")}
    result["freeze.json"] = hashlib.sha256(encoded).hexdigest()
    bench_cpu.atomic_json(out / "package.json", {"passed": True, "files_sha256": result,
                          "formal_performance_started": False})
    for name, expected in result.items():
        if name != "freeze.json":
            require(digest(out / name) == expected, "package artifact changed before publication: " + name)
    snapshot.verify()
    bench_cpu.atomic_json(out / "freeze.json", freeze)
    return result


def self_test(output=None):
    """Exercise publication failures with fixtures; native calls/timers are blocked."""
    import tempfile
    import unittest
    from unittest.mock import patch

    class Checks(unittest.TestCase):
        def fixture(self):
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            out = Path(temporary.name)
            for name in ("source.tar.gz", "source-manifest.json", "REVIEW.md"):
                (out / name).write_bytes(name.encode("utf8"))
            source = out / "evidence.json"
            source.write_bytes(b'{"passed":true}')
            snapshot = InputSnapshot()
            self.assertEqual(snapshot.read_json(source), {"passed": True})
            freeze = {"schema": "a15-cpu-freeze-v1", "final": True, "correctness_passed": True,
                      "classification": "模拟证据", "correctness_evidence": snapshot.evidence_hashes(())}
            return out, source, snapshot, freeze

        def test_json_and_digest_share_first_bytes(self):
            _, source, snapshot, _ = self.fixture()
            self.assertEqual(snapshot.sha256[str(source.resolve())], digest(source))
            source.write_bytes(b'{"passed":false}')
            with self.assertRaisesRegex(ValueError, "first snapshot"):
                snapshot.digest(source)

        def test_jsonl_hash_is_bound_before_parsing(self):
            out, _, snapshot, _ = self.fixture()
            path = out / "cases.jsonl"
            path.write_bytes(b'{"case":1}\n{"case":2}\n')
            initial = snapshot.digest(path)
            self.assertEqual([json.loads(line) for line in snapshot.lines(path)], [{"case": 1}, {"case": 2}])
            self.assertEqual(snapshot.evidence_hashes(())[str(path.resolve())], initial)
            path.write_bytes(b'{"case":3}\n')
            with self.assertRaisesRegex(ValueError, "first snapshot"):
                snapshot.lines(path)

        def test_archive_uses_hashed_bytes(self):
            out, _, snapshot, _ = self.fixture()
            path = out / "input.tar.gz"
            with tarfile.open(path, "w:gz") as archive:
                info = tarfile.TarInfo("input.txt"); info.size = 5
                archive.addfile(info, io.BytesIO(b"input"))
            initial = snapshot.digest(path)
            with snapshot.archive(path) as archive:
                self.assertEqual(archive.extractfile("input.txt").read(), b"input")
            self.assertEqual(snapshot.evidence_hashes(())[str(path.resolve())], initial)
            path.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "first snapshot"):
                snapshot.archive(path)

        def test_changed_binary_is_rejected_at_final_check(self):
            out, _, snapshot, _ = self.fixture()
            binary = out / "library.so"; binary.write_bytes(b"original")
            snapshot.digest(binary)
            binary.write_bytes(b"replacement")
            with self.assertRaisesRegex(ValueError, "validation/packaging"):
                snapshot.verify()

        def test_package_write_failure_leaves_no_permit(self):
            out, _, snapshot, freeze = self.fixture()
            with patch.object(bench_cpu, "atomic_json", side_effect=OSError("package write failure")):
                with self.assertRaisesRegex(OSError, "package write"):
                    publish_freeze(out, freeze, snapshot)
            self.assertFalse((out / "freeze.json").exists())
            self.assertEqual(list(out.glob("freeze*.json*")), [])

        def test_evidence_change_during_package_write_leaves_no_permit(self):
            out, source, snapshot, freeze = self.fixture()
            write = bench_cpu.atomic_json
            def changed(path, value):
                write(path, value)
                if Path(path).name == "package.json": source.write_bytes(b'{"passed":false}')
            with patch.object(bench_cpu, "atomic_json", side_effect=changed):
                with self.assertRaisesRegex(ValueError, "validation/packaging"):
                    publish_freeze(out, freeze, snapshot)
            self.assertTrue((out / "package.json").exists())
            self.assertFalse((out / "freeze.json").exists())

        def test_artifact_change_during_package_write_leaves_no_permit(self):
            out, _, snapshot, freeze = self.fixture()
            write = bench_cpu.atomic_json
            def changed(path, value):
                write(path, value)
                if Path(path).name == "package.json": (out / "REVIEW.md").write_bytes(b"changed")
            with patch.object(bench_cpu, "atomic_json", side_effect=changed):
                with self.assertRaisesRegex(ValueError, "package artifact changed"):
                    publish_freeze(out, freeze, snapshot)
            self.assertFalse((out / "freeze.json").exists())

        def test_atomic_publish_failure_removes_temporary_permit(self):
            out, _, snapshot, freeze = self.fixture()
            link = bench_cpu.os.link
            def failed(source, target):
                if Path(target).name == "freeze.json": raise OSError("publication failure")
                return link(source, target)
            with patch.object(bench_cpu.os, "link", side_effect=failed):
                with self.assertRaisesRegex(OSError, "publication failure"):
                    publish_freeze(out, freeze, snapshot)
            self.assertFalse((out / "freeze.json").exists())
            self.assertEqual(list(out.glob("freeze*.tmp")), [])

        def test_successful_permit_is_last_and_package_hash_matches(self):
            out, _, snapshot, freeze = self.fixture()
            write = bench_cpu.atomic_json; order = []
            def checked(path, value):
                order.append(Path(path).name)
                if Path(path).name == "freeze.json":
                    self.assertTrue((out / "package.json").is_file())
                    self.assertFalse((out / "freeze.json").exists())
                write(path, value)
            with patch.object(bench_cpu, "atomic_json", side_effect=checked):
                publish_freeze(out, freeze, snapshot)
            self.assertEqual(order, ["package.json", "freeze.json"])
            package = json.loads((out / "package.json").read_bytes())
            self.assertEqual(package["files_sha256"]["freeze.json"], digest(out / "freeze.json"))
            self.assertTrue(json.loads((out / "freeze.json").read_bytes())["final"])

    blocked = AssertionError("freeze self-tests prohibit native calls, subprocesses and real timers")
    with patch.object(bench_cpu, "NativeSlhDsa", side_effect=blocked), \
            patch.object(bench_cpu, "command", side_effect=blocked), \
            patch("ctypes.CDLL", side_effect=blocked), \
            patch("time.perf_counter", side_effect=blocked), patch("time.perf_counter_ns", side_effect=blocked):
        names = unittest.defaultTestLoader.getTestCaseNames(Checks)
        # Python 3.13's TestCase.run measures duration; call fixture checks directly.
        for name in names:
            case = Checks(name)
            try:
                getattr(case, name)()
            finally:
                case.doCleanups()
    record = {"schema": "a15-cpu-freeze-selftest-v1", "passed": True, "mock_checks": len(names),
              "native_calls": 0, "real_timing_samples": 0, "formal_performance_started": False,
              "tool_sha256": digest(__file__), "scope": "first-byte JSON/JSONL/archive binding; input/artifact mutation; package/publication failure; canonical permit last"}
    if output is not None:
        bench_cpu.atomic_json(output, record)
    return record


def check_archived_sources(run_dir, expected, snapshot):
    """Bind historical coverage to the bytes tested before CUDA integration."""
    read, digest = snapshot.read_json, snapshot.digest
    archive_path = run_dir / "tested-source.tar.gz"
    record_path = run_dir / "tested-source.json"
    record = read(record_path)
    require(digest(archive_path) == record["archive_sha256"], "historical source archive changed")
    require(all(record["sources_sha256"].get(name) == value for name, value in expected.items()),
            "historical source record omits tested files")
    with snapshot.archive(archive_path) as archive:
        for name, value in record["sources_sha256"].items():
            member = archive.getmember(name)
            require(member.isfile() and not Path(name).is_absolute() and ".." not in Path(name).parts,
                    "historical source archive contains invalid member")
            require(hashlib.sha256(archive.extractfile(member).read()).hexdigest() == value,
                    "historical source archive differs: " + name)
    return archive_path, record_path


def check_current_matrix(directory, native, snapshot):
    """Require fresh CPU dispatch/count/cache coverage after CUDA integration."""
    read, digest = snapshot.read_json, snapshot.digest
    summary_path, manifest_path = directory / "summary.json", directory / "manifest.json"
    summary, manifest = read(summary_path), read(manifest_path)
    require(summary["passed"] and summary["completed_requested_scope"] and summary["final"]
            and not summary["formal_performance_started"] and not summary["measured_durations"],
            "current CPU regression incomplete")
    identity = manifest["identity"]
    require(identity["sources_sha256"] == summary["source_hashes"]
            and identity["libraries"] == summary["libraries"], "current CPU regression identity differs")
    for name, value in summary["source_hashes"].items():
        require(digest(ROOT / name) == value, "current CPU regression source differs: " + name)
    config = identity["configuration"]
    require(config["backends"] == ["REF", "AVX2"] and {1, 64}.issubset(config["threads"]),
            "current CPU regression must cover both backends and thread endpoints")
    require(digest(config["vectors"]) == identity["vector_sha256"], "current CPU regression vector differs")
    expected = check_optimization.build_plan(SimpleNamespace(**config), identity["libraries"])
    require(expected == manifest["plan"] and len(expected) == summary["planned_cases"],
            "current CPU regression plan differs")
    accepted = {v for k, v in native["build_sha256"].items() if k.endswith("/counters/libslhdsa_sm3.so")}
    for library in identity["libraries"].values():
        require(library["sha256"] in accepted and digest(library["path"]) == library["sha256"],
                "current CPU regression library differs")
    cases_path = directory / "cases.jsonl"
    require(digest(cases_path) == summary["cases_jsonl_sha256"], "current CPU regression records differ")
    latest, count = {}, 0
    for line in snapshot.lines(cases_path):
        row = json.loads(line)
        saved = row.pop("record_sha256")
        require(hashlib.sha256(check_optimization.canonical(row)).hexdigest() == saved,
                "current CPU regression record hash differs")
        require(row["schema"] == check_optimization.SCHEMA and row["passed"] and row["status"] == "passed"
                and all(row["checks"].values()) and all(row["field_matches"].values())
                and row["source_hashes"] == summary["source_hashes"] and not row["formal_performance"]
                and row["library"] == identity["libraries"][row["case"]["library"]],
                "current CPU regression contains an invalid record")
        if row["prediction"] is not None and row["observed"] is not None:
            require(row["prediction"]["counts"] == row["observed"], "current CPU counts differ")
        latest[row["case_id"]] = row
        count += 1
    require(count == summary["records"] and all(c["case_id"] in latest
            and latest[c["case_id"]]["case"] == c for c in expected), "current CPU regression coverage differs")
    require(summary["coverage"]["verify_existing_pids"] == [1, 2, 3, 101, 102, 103, 201]
            and all(r["count_reconciled"] for r in summary["budget_status"]),
            "current CPU regression parameters/budget incomplete")
    return summary_path, manifest_path, cases_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-run", type=Path, required=True)
    parser.add_argument("--matrix-run", type=Path, required=True)
    parser.add_argument("--matrix-baseline-run", type=Path,
                        help="accepted native build used by historical CPU matrix")
    parser.add_argument("--current-matrix-run", type=Path,
                        help="fresh CPU dispatch regression required with historical matrix")
    parser.add_argument("--build-record", type=Path, required=True)
    parser.add_argument("--mock-record", type=Path, required=True)
    parser.add_argument("--sm3-correctness", type=Path, required=True)
    parser.add_argument("--plan", type=Path, action="append", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    snapshot = InputSnapshot()
    read, digest = snapshot.read_json, snapshot.digest
    require(not args.matrix_baseline_run or args.current_matrix_run,
            "historical matrix requires a fresh current-source CPU regression")
    native_path = args.native_run / "manifest.json"
    native = read(native_path)
    require(native["passed"] and native["source_unchanged"] and native["inputs_unchanged"], "native acceptance incomplete")
    expected_steps = ["avx2-build-and-tests", "counter-build-and-tests", "portable-build-and-tests", "sanitizer-tests",
                      "external-avx2", "external-portable", "complete-128-24", "toy-differential",
                      "subtree-differential", "exact-counts", "cli-and-budget"]
    require([step["name"] for step in native["steps"]] == expected_steps
            and all(step["returncode"] == 0 for step in native["steps"]), "native steps differ")
    for name, expected in native["inputs_sha256"].items():
        require(digest(ROOT / name) == expected, "native input changed: " + name)
    for name, expected in native["source_sha256"].items():
        require(digest(ROOT / name) == expected, "native source changed: " + name)
    for name, expected in native["evidence_sha256"].items():
        require(digest(ROOT / name) == expected, "native evidence changed: " + name)
    for name, expected in native["build_sha256"].items():
        require(digest(ROOT / name) == expected, "native build changed: " + name)
    complete = read(args.native_run / "complete-128-24.summary.json")
    require(complete["total"] == complete["passed"] == 3 and complete["selected_backend_counts"] == {"2": 3},
            "three complete AVX2 pid3 cases are required")
    rng_path = args.native_run / "rng.json"
    rng = read(rng_path)
    release_library = ROOT / next(name for name in native["build_sha256"] if name.endswith("/avx2/libslhdsa_sm3.so"))
    require(rng["schema"] == "a15-native-rng-v1" and rng["passed"] and len(rng["results"]) == 6
            and all(row["passed"] for row in rng["results"]) and rng["library_sha256"] == digest(release_library)
            and not rng["formal_performance_started"] and not rng["duration_measured"], "native RNG check incomplete")
    for name, expected in rng["sources_sha256"].items():
        require(digest(ROOT / name) == expected, "RNG source changed: " + name)
    matrix_path = args.matrix_run / "summary.json"
    matrix = read(matrix_path)
    require(matrix["passed"] and matrix["completed_requested_scope"] and matrix["final"], "matrix acceptance incomplete")
    require(matrix["suite"] == "full" and matrix["full_sha2"] and not matrix["deferred_scope"], "full parameter scope is required")
    require(not matrix["formal_performance_started"] and not matrix["measured_durations"], "checkpoint must precede timing")
    require(digest(args.matrix_run / "cases.jsonl") == matrix["cases_jsonl_sha256"], "matrix case hash differs")
    historical_files = ()
    current_matrix_files = check_current_matrix(args.current_matrix_run, native, snapshot) if args.current_matrix_run else ()
    if args.matrix_baseline_run:
        historical_files = check_archived_sources(args.matrix_run, matrix["source_hashes"], snapshot)
    else:
        for name, expected in matrix["source_hashes"].items():
            require(digest(ROOT / name) == expected, "matrix source changed: " + name)
    matrix_manifest_path = args.matrix_run / "manifest.json"
    matrix_manifest = read(matrix_manifest_path)
    identity = matrix_manifest["identity"]
    require(identity["sources_sha256"] == matrix["source_hashes"] and identity["libraries"] == matrix["libraries"],
            "matrix manifest identity differs from summary")
    config = identity["configuration"]
    require(config["suite"] == "full" and config["full_sha2"] and config["backends"] == ["REF", "AVX2"]
            and config["threads"] == [1, 2, 4, 8, 16, 32, 64], "complete requested backend/thread matrix required")
    vector_path = Path(config["vectors"])
    require(digest(vector_path) == identity["vector_sha256"], "matrix vector changed")
    expected_plan = check_optimization.build_plan(SimpleNamespace(**config), identity["libraries"])
    require(expected_plan == matrix_manifest["plan"] and len(expected_plan) == matrix["planned_cases"],
            "matrix plan differs from frozen implementation")
    baseline = read(args.matrix_baseline_run / "manifest.json") if args.matrix_baseline_run else native
    require(baseline["passed"] and baseline["source_unchanged"] and baseline["inputs_unchanged"],
            "matrix native baseline was not accepted")
    require(all(baseline["source_sha256"].get(name) == value
                for name, value in matrix["source_hashes"].items() if name in baseline["source_sha256"]),
            "matrix and accepted baseline sources differ")
    if args.matrix_baseline_run:
        archive_path = args.matrix_baseline_run / "source.tar.gz"
        archive_record_path = args.matrix_baseline_run / "source-archive.json"
        archive_record = read(archive_record_path)
        require(digest(archive_path) == archive_record["source_archive_sha256"]
                and digest(args.matrix_baseline_run / "manifest.json") == archive_record["manifest_sha256"],
                "native baseline source archive identity differs")
        with snapshot.archive(archive_path) as archive:
            for name, value in baseline["source_sha256"].items():
                require(hashlib.sha256(archive.extractfile(name).read()).hexdigest() == value,
                        "native baseline archived source differs: " + name)
        for group in ("evidence_sha256", "build_sha256", "inputs_sha256"):
            for name, value in baseline[group].items():
                require(digest(ROOT / name) == value, "native baseline artifact differs: " + name)
        historical_files += (archive_path, archive_record_path)
    counter_hashes = {value for name, value in baseline["build_sha256"].items() if name.endswith("/counters/libslhdsa_sm3.so")}
    for library in identity["libraries"].values():
        require(library["sha256"] in counter_hashes and digest(library["path"]) == library["sha256"],
                "matrix library does not match accepted native counter build")
    latest = {}
    record_count = 0
    for line in snapshot.lines(args.matrix_run / "cases.jsonl"):
        row = json.loads(line)
        checksum = row.pop("record_sha256")
        require(hashlib.sha256(check_optimization.canonical(row)).hexdigest() == checksum, "matrix record hash differs")
        require(row["schema"] == check_optimization.SCHEMA and row["source_hashes"] == matrix["source_hashes"]
                and row["library"] == identity["libraries"][row["case"]["library"]]
                and row["formal_performance"] is False, "matrix record identity differs")
        require(row["passed"] == (row["status"] == "passed"), "matrix record status differs")
        if row["passed"]:
            require(all(row["checks"].values()) and all(row["field_matches"].values()), "passed matrix row has failed checks")
            if row["prediction"] is not None and row["observed"] is not None:
                require(row["prediction"]["counts"] == row["observed"], "seven-field counts differ")
        latest[row["case_id"]] = row
        record_count += 1
    require(record_count == matrix["records"] and all(row["passed"] for row in latest.values()), "failed or omitted matrix records")
    for case in expected_plan:
        require(case["case_id"] in latest and latest[case["case_id"]]["case"] == case
                and latest[case["case_id"]]["passed"], "matrix combination missing: " + case["case_id"])
    coverage = matrix["coverage"]
    threads = [1, 2, 4, 8, 16, 32, 64]
    pids = [1, 2, 3, 101, 102, 103, 201]
    require(coverage["complete_sign_pids"] == pids and coverage["verify_existing_pids"] == pids, "seven parameters required")
    require(coverage["threads_with_direct_execution"] == threads, "full thread matrix required")
    require(coverage["backends_with_direct_execution"] == ["AVX2", "REF"], "both CPU backends required")
    for pid in (3, 103):
        require(coverage["cache_loaded_levels"][str(pid)] == list(range(23)), "all cache levels required")
        for field in ("direct_keygen_threads", "direct_cache_build_threads", "direct_cache_load_threads"):
            require(coverage[field][str(pid)] == threads, "full " + field + " required")
    require(all(row["count_reconciled"] for row in matrix["budget_status"]), "budget reconciliation failed")
    mock = read(args.mock_record)
    require(mock.get("passed", mock.get("mock_passed")) is True
            and mock.get("native_calls", mock.get("real_native_calls")) == 0
            and mock["real_timing_samples"] == 0
            and mock.get("bench_tool_sha256", mock.get("tool_sha256")) == digest(ROOT / "tools/bench_cpu.py"),
            "current mock checks required")
    require(mock["source_sha256"] == bench_cpu.hashes(bench_cpu.TOOL_FILES), "mock helper sources changed")
    sm3 = read(args.sm3_correctness)
    require(sm3["schema"] == "a15-sm3-preparation-v1" and sm3["passed"]
            and sm3["real_timing_samples"] == 0 and sm3["check"]["passed"]
            and sm3["check"]["comparisons"] == 256 and sm3["check"]["avx2_available"]
            and digest(sm3["binary"]) == sm3["binary_sha256"], "SM3 harness correctness incomplete")
    for name, value in sm3["sources_sha256"].items():
        require(digest(ROOT / name) == value, "SM3 harness source changed: " + name)
    build = read(args.build_record)
    current = bench_cpu.hashes(bench_cpu.BUILD_FILES + bench_cpu.TOOL_FILES)
    require(build["source_sha256"] == {name: current[name] for name in bench_cpu.BUILD_FILES}, "timing build source differs")
    require(digest(build["library"]) == build["library_sha256"], "timing library differs")
    require(build["library_sha256"] == digest(release_library),
            "CPU measurement library must be byte-identical to the accepted no-counter native release")
    require(build["compile_output_checked"] and not any(build[k] for k in ("counters", "test_injection", "sanitizer")),
            "clean timing build required")
    compiler_arg = next(value[3:] for value in build["command"] if value.startswith("CC="))
    require(bench_cpu.inspect_compile_output(build["result"]["stdout"], compiler_arg, Path(build["library"])) == build["compile_argv"],
            "actual compile command differs")
    require(len(args.plan) == 3, "exactly three benchmark plans required")
    plans = {read(path)["suite"]: {"path": str(path.resolve()), "sha256": digest(path), "cases": len(read(path)["cases"])}
             for path in args.plan}
    require(set(plans) == {"r3", "r4", "r5"}, "R3/R4/R5 plans required")
    for path in args.plan:
        plan = read(path)
        require(plan["schema"] == "a15-cpu-plan-v1", "benchmark plan schema differs")
        bench_cpu.validate_formal_plan(plan)
        expected = bench_cpu.make_plan(plan["suite"], [1, 2, 3, 101, 102, 103], threads, list(range(23)))
        require(plan["cases"] == expected["cases"], "benchmark plan omitted or changed normative cases")
        for case in plan["cases"]:
            bench_cpu.validate_case(case)
            require(case["samples"] >= bench_cpu.minimum_samples(case), "insufficient samples in plan")
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=False)
    freeze = {"schema": "a15-cpu-freeze-v1", "created_utc": datetime.now(timezone.utc).isoformat(),
              "final": True, "correctness_passed": True, "formal_performance_started": False,
              "source_sha256": current, "library_sha256": build["library_sha256"],
              "build_record_sha256": digest(args.build_record), "plans": plans,
              "correctness_evidence": snapshot.evidence_hashes(
                  (native_path, matrix_path, matrix_manifest_path, args.matrix_run / "cases.jsonl",
                   vector_path, rng_path, args.mock_record, args.sm3_correctness, *historical_files, *current_matrix_files,
                   *((args.matrix_baseline_run / "manifest.json",) if args.matrix_baseline_run else ()))),
              "historical_cpu_matrix": bool(args.matrix_baseline_run),
              "current_cpu_regression": bool(args.current_matrix_run),
              "classification": "source/build ready for measurement; contains no performance result"}
    archive_sources = dict(native["source_sha256"])
    if not args.matrix_baseline_run:
        archive_sources.update(matrix["source_hashes"])
    archive_sources.update(current)
    for name in ("SPEC.md", "docs/OPTIMIZATION_CHECKPOINT.md", "c/src/WOTS_DESIGN.md", "tools/freeze_optimization.py"):
        archive_sources[name] = digest(ROOT / name)
    with tarfile.open(out / "source.tar.gz", "x:gz") as archive:
        for name in sorted(archive_sources):
            archive.add(ROOT / name, arcname=name)
    with tarfile.open(out / "source.tar.gz") as archive:
        for name, expected in archive_sources.items():
            require(hashlib.sha256(archive.extractfile(name).read()).hexdigest() == expected, "archive source differs: " + name)
    for name, expected in archive_sources.items():
        require(digest(ROOT / name) == expected, "source changed during packaging: " + name)
    for path, expected in freeze["correctness_evidence"].items():
        require(digest(path) == expected, "evidence changed during packaging: " + path)
    require(digest(build["library"]) == freeze["library_sha256"] and digest(args.build_record) == freeze["build_record_sha256"],
            "measurement build changed during packaging")
    for plan in plans.values():
        require(digest(plan["path"]) == plan["sha256"], "plan changed during packaging")
    bench_cpu.atomic_json(out / "source-manifest.json", archive_sources)
    review = ("# CPU 优化验收完成，停于性能测试之前\n\n"
              "实现：midstate、缓存、OpenMP、AVX2 FORS、WOTS x8 与流式 T_len。\n\n"
              f"原生验收 {len(native['steps'])} 项；全矩阵 {matrix['passed_planned']}/{matrix['planned_cases']} 项、"
              f"{matrix['records']} 条记录全部通过。七参数与 1/2/4/8/16/32/64 线程直接执行。\n\n"
              "完整矩阵按其受测源码归档；集成 CUDA 后另有当前版本 CPU 原生回归和"
              "REF/AVX2 调度、计数、缓存矩阵证据。\n\n"
              "128-24 t=0…22 缓存读写、root 绑定及完整签名对照通过；"
              "native cache-build 直接覆盖 t0/t12/t22 与 t12 全线程，其余文件由独立父节点计算生成。\n\n"
              "REF/AVX2 字节与七字段计数一致，真实 Linux RNG、故障、自验清零、portable、"
              "release 隔离、ASan/UBSan 与独立 Python/外部输入检查通过。\n\n"
              "独立无计数器基准库与 R3/R4/R5 最小样本计划已准备。正式计时样本数为 0，"
              "不报告加速比。此包覆盖 CPU；CUDA 有独立验收与冻结包。"
              "硬件 AVX-512 缺席，海光/Windows DLL 未包含。\n\n"
              "追溯：freeze.json、source-manifest.json 以及所列 native/matrix/build/plan 证据。\n")
    (out / "REVIEW.md").write_text(review, encoding="utf8")
    publish_freeze(out, freeze, snapshot)
    print(json.dumps({"passed": True, "output": str(out), "matrix_cases": matrix["planned_cases"],
                      "formal_performance_started": False}))


if __name__ == "__main__":
    main()
