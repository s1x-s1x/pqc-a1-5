"""Read and archive incremental acceptance evidence; never execute a kernel or timer."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import sqlite3
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "validation/incremental-20261005"
FIXTURE = "reference/evidence/python-sm3-128-24.jsonl"
BASELINE = "4ad41308ad537e0578f6dea6d85ebcd7535c46b1"
BASELINE_ENGINE = "e9ef382c21ee8ae7576d524959a6d12808c848b00ad5d728cbb0bcc1eb5d227b"
SCHEMA = "a15-incremental-freeze-v1"
sys.path.insert(0, str(ROOT / "tools"))
from signing_budget import SigningBudget


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf8")


def relative(path):
    return Path(path).resolve().relative_to(ROOT).as_posix()


def local(name, parent=ROOT):
    require(isinstance(name, str), "evidence path must be a string")
    part = PurePosixPath(name)
    require(part.parts and not part.is_absolute() and ".." not in part.parts and "\\" not in name and
            ":" not in part.parts[0],
            "evidence path must be a relative POSIX path: " + name)
    path = (parent / name).resolve()
    require(path.is_relative_to(parent.resolve()), "evidence path escapes its root: " + name)
    return path


class Snapshot:
    def __init__(self):
        self.files = {}
        self.archived = {}

    def read(self, path):
        path = Path(path).resolve()
        name = relative(path)
        require(path.is_file() or name in self.archived, "missing evidence: " + str(path))
        data = path.read_bytes() if path.is_file() else self.archived[name]
        actual = hashlib.sha256(data).hexdigest()
        require(self.files.setdefault(name, actual) == actual, "input changed after capture: " + name)
        return data

    def json(self, path):
        return json.loads(self.read(path))

    def hash(self, path, expected=None):
        actual = hashlib.sha256(self.read(path)).hexdigest()
        require(expected is None or actual == expected.lower(), "SHA-256 differs: " + relative(path))
        return actual

    def verify(self):
        for name, expected in list(self.files.items()):
            self.hash(local(name), expected)


class ReadOnlyBudget(SigningBudget):
    """Reuse receipt validation without the ledger constructor's migration/write path."""
    def __init__(self, path):
        self.path = Path(path).resolve()
        require(self.path.is_file(), "existing signing ledger is required")
        wal = Path(str(self.path) + "-wal")
        require(not wal.exists() or wal.stat().st_size == 0,
                "freeze requires a checkpointed signing-ledger snapshot")
        with self.connection() as database:
            self.ledger_uuid = self._read_uuid(database)
            self._check_schema(database)

    @contextmanager
    def connection(self):
        database = sqlite3.connect(self.path.as_uri() + "?mode=ro&immutable=1", uri=True, isolation_level=None)
        try:
            database.execute("PRAGMA query_only=ON")
            yield database
        finally:
            database.close()


def hash_mapping(snapshot, values, parent=ROOT):
    require(isinstance(values, dict) and values, "nonempty SHA-256 mapping required")
    for name, expected in values.items():
        require(isinstance(expected, str) and len(expected) == 64, "malformed SHA-256: " + name)
        snapshot.hash(local(name, parent), expected)


def production_dependencies(source_map):
    return {name for name in source_map
            if name == "c/Makefile" or name.startswith(("c/src/", "c/include/")) or
            (name.startswith("third_party/slhdsa-c/") and "/test/" not in name)}


def check_run(snapshot, suffix, phase, expected_steps, dependency_scope="all"):
    directory = ROOT / "validation" / ("incremental-20261005-" + suffix)
    value = snapshot.json(directory / "manifest.json")
    require(value.get("schema") == "a15-incremental-correctness-v1" and value.get("phase") == phase,
            "acceptance schema/phase differs: " + suffix)
    require(value.get("passed") is True and value.get("source_unchanged") is True and
            value.get("performance_samples") == 0 and value.get("performance_enabled") is False,
            "acceptance must pass before performance: " + suffix)
    steps = value.get("steps", [])
    require([step["name"] for step in steps] == expected_steps and
            all(step.get("returncode") == 0 for step in steps), "acceptance steps differ: " + suffix)
    for step in steps:
        log = local(step["log"])
        require(log.parent == directory, "log belongs to another run: " + suffix)
        snapshot.hash(log, step["log_sha256"])
    snapshot.hash(ROOT / FIXTURE, value["fixture_sha256"])
    sources = value["source_sha256"]
    require(isinstance(sources, dict) and sources, "acceptance source binding absent: " + suffix)
    if dependency_scope == "kernel":
        selected = {"c/Makefile", "c/src/sm3_incremental.c", "c/src/sm3_incremental.h",
                    "c/src/sm3.c", "c/src/sm3.h", "c/src/sm3x8.c", "c/src/sm3x8.h",
                    "c/src/secure_zero.h", "c/tests/test_incremental_kernel.c"}
    elif dependency_scope == "release":
        selected = production_dependencies(sources) | {
            "c/tests/test_incremental_v1.c", "c/tests/test_wots.c",
            "c/tests/test_prehash.c", "c/tests/test_repair.c"}
    elif dependency_scope == "historical_harness":
        selected = production_dependencies(sources)
    else:
        selected = set(sources)
    require(selected <= set(sources), "required source dependency absent: " + suffix)
    hash_mapping(snapshot, {name: sources[name] for name in sorted(selected)})
    ignored = {name: expected for name, expected in sources.items() if name not in selected}
    return value, {"run": suffix, "phase": phase, "steps": len(steps),
                   "dependency_scope": dependency_scope,
                   "checked_source_dependencies": sorted(selected),
                   "unasserted_source_snapshot": ignored,
                   "historical_harness_scope": (
                       "Production bytes match; this run retains its earlier harness/runner identity. "
                       "It supports its recorded full-signature result, not current harness execution."
                       if dependency_scope == "historical_harness" else None)}


def check_full_result(snapshot, suffix, value, mode, fault):
    require(value.get("mode") == mode and value.get("b1") == 1 and value.get("fault_point") == fault,
            "full-signature configuration differs: " + suffix)
    path = ROOT / "validation" / ("incremental-20261005-" + suffix) / "full-signature.log"
    result = json.loads(snapshot.read(path))
    require(result.get("mode") == mode and result.get("b1") == 1 and result.get("fault_point") == fault and
            result.get("independent_REF_self_verify") is True and result.get("performance_samples") == 0 and
            result.get("PRF_x8_packages") == 12582912 and result.get("streams", 0) > 0,
            "full-signature route/self-check evidence differs: " + suffix)
    require(result.get("full_signature_equal") is (fault == 0) and
            result.get("full_fault_detected_and_cleared") is (fault != 0),
            "full-signature expected result differs: " + suffix)
    cache = ROOT / "validation/optimization-full-20261004-0228/cache/lib0-b45efe0ce1c1/pid3/pid3-t12.cache"
    snapshot.hash(cache, value["cache_sha256"])


def check_isolation(snapshot, fixture):
    directory = ROOT / "validation/incremental-20261005-isolation-r2"
    value = snapshot.json(directory / "manifest.json")
    require(value.get("schema") == "a15-incremental-isolation-v1" and value.get("passed") is True and
            value.get("source_unchanged") is True and value.get("performance_samples") == 0 and
            value.get("performance_enabled") is False, "isolation acceptance incomplete")
    require([step["name"] for step in value["steps"]] ==
            ["sanitizer-build", "sanitizer-isolation", "cuda-build", "cuda-isolation"],
            "bounded sanitizer/CUDA isolation steps required")
    hash_mapping(snapshot, value["source_sha256"])
    recipe = snapshot.read(ROOT / "c/Makefile").decode("utf8").replace("\r\n", "\n").replace(
        "tests/test_incremental_engine.c", "tests/test_incremental_isolation.c")
    require(hashlib.sha256(recipe.encode("utf8")).hexdigest() == value["private_makefile_sha256"],
            "derived isolation Make recipe differs")
    for name in ("pk", "sig", "message", "context"):
        require(value["fixture_sha256"][name] == hashlib.sha256(bytes.fromhex(fixture[name])).hexdigest(),
                "isolation fixture binding differs: " + name)
    snapshot.hash(ROOT / FIXTURE, value["public_fixture_source_sha256"])
    for step in value["steps"]:
        require(step.get("returncode") == 0, "isolation step failed: " + step["name"])
        log = local(step["log"])
        require(log.parent == directory, "isolation log belongs to another run")
        snapshot.hash(log, step["log_sha256"])
        if step["name"].endswith("-isolation"):
            rows = [json.loads(line) for line in snapshot.read(log).decode("utf8").splitlines()
                    if line.startswith("{")]
            concurrent = next((row for row in rows if "concurrent_requests" in row), {})
            require(concurrent.get("passed") is True and concurrent.get("concurrent_requests") == 64 and
                    concurrent.get("valid") == concurrent.get("invalid") == 32 and
                    concurrent.get("V1_hits") == 64 and concurrent.get("REF_per_request") is True and
                    concurrent.get("shared_and_private_contexts") is True and
                    concurrent.get("performance_samples") == 0, "concurrent V1 evidence incomplete")
            if step["name"] == "cuda-isolation":
                cuda = next((row for row in rows if "CUDA_subtrees" in row), {})
                require(cuda.get("passed") is True and cuda.get("CUDA_subtrees") == 8 and
                        cuda.get("CUDA_verify_cases") == 2 and cuda.get("V1_hits") == 0 and
                        cuda.get("AF_streams") == 0 and cuda.get("new_B1_hits") == 0 and
                        cuda.get("kernel_launches", 0) > 0 and cuda.get("device_hashes", 0) > 0 and
                        cuda.get("timed") is False and cuda.get("performance_samples") == 0,
                        "real untimed CUDA dispatch/exclusion evidence incomplete")
    artifacts = value.get("artifacts", [])
    require(artifacts and len({row["path"] for row in artifacts}) == len(artifacts),
            "captured build artifacts absent or duplicate")
    for row in artifacts:
        require(row.get("capture") in {"immediately after accepted run", "retained post-run artifact"},
                "artifact capture scope missing")
        snapshot.hash(local(row["path"]), row["sha256"])
    return {"run": "isolation-r2", "steps": len(value["steps"]), "artifacts": artifacts,
            "captured_at_utc": value["captured_at_utc"], "capture_scope": value["capture_scope"],
            "binary_scope": "Earlier binaries are retained post-run bytes, not hashes captured at invocation."}


def check_analysis_tests(snapshot):
    directory = BASE / "analysis-final-r2"
    value = snapshot.json(directory / "manifest.json")
    require(value.get("schema") == "a15-incremental-analysis-final-v1" and value.get("passed") is True and
            value.get("parameter_tests") == 19 and value.get("scheduler_tests") == 27 and
            value.get("real_scheduler_clocks_forbidden") is True and value.get("native_crypto_calls") == 0 and
            value.get("new_performance_samples") == 0, "final P/scheduler test evidence incomplete")
    hash_mapping(snapshot, value["source_sha256"])
    require([step["name"] for step in value["steps"]] == ["parameters", "scheduler-real-clocks-forbidden"],
            "final P/scheduler test steps differ")
    for step in value["steps"]:
        require(step.get("returncode") == 0, "analysis step failed: " + step["name"])
        path = local(step["log"])
        require(path.parent == directory, "analysis log belongs to another run")
        snapshot.hash(path, step["log_sha256"])
        text = snapshot.read(path).decode("utf8")
        if step["name"] == "parameters":
            require("Ran 19 tests" in text and text.rstrip().endswith("OK"), "P test result differs")
        else:
            row = json.loads(text)
            require(row.get("status") == "passed" and row.get("tests") == 27 and not row.get("failures") and
                    not row.get("errors") and row.get("mock_clock_only") is True and
                    row.get("native_crypto_calls") == 0 and row.get("performance_samples") == 0,
                    "mock-only scheduler result differs")
    return {"run": "analysis-final-r2", "parameter_tests": 19, "scheduler_tests": 27,
            "real_scheduler_clocks_forbidden": True, "native_crypto_calls": 0}


def check_analysis_and_preparation(snapshot):
    parameters = snapshot.json(BASE / "parameters/manifest.json")
    require(parameters.get("new_performance_samples") == 0 and
            parameters.get("cryptographic_kernel_invoked") is False and
            parameters.get("parameter_cache_count") == 8 and parameters.get("resource_shape_count") == 32 and
            parameters.get("pairwise_region_count") == 168, "P finite-analysis scope differs")
    hash_mapping(snapshot, parameters["source_hashes"])
    hash_mapping(snapshot, parameters["files"], BASE / "parameters")
    for item in parameters["upstream"]["files"]:
        snapshot.hash(local(item["path"], BASE / "parameters"), item["sha256"])
    neighbors = snapshot.json(BASE / "neighbors/manifest.json")
    require(neighbors.get("new_performance_samples") == 0, "neighbor reads must precede performance")
    for item in neighbors["sources"]:
        snapshot.hash(local(item["name"], BASE / "neighbors"), item["sha256"])
    codegen = snapshot.json(BASE / "codegen-r1/manifest.json")
    require(codegen.get("performance_samples") == 0 and codegen.get("round_AVX2_present") is True and
            codegen.get("baseline_initializer_AVX_free") is True, "code-generation checks incomplete")
    hash_mapping(snapshot, codegen["source_sha256"])
    hash_mapping(snapshot, codegen["files_sha256"], BASE / "codegen-r1")
    guards = snapshot.json(BASE / "codegen-r1/release-guards.json")
    require(guards.get("release_private_code_erased") is True and guards.get("invalid_builds_rejected") == 9 and
            guards.get("incremental_ABI_exports") == 0 and guards.get("performance_samples") == 0,
            "incremental release guards incomplete")
    from incremental_perf_plan import validate
    plan = snapshot.json(BASE / "performance/plan.json")
    validate(plan)
    import csv
    results = csv.DictReader(io.StringIO(snapshot.read(BASE / "performance/results.csv").decode("utf8")))
    require(results.fieldnames is not None and "seconds" in results.fieldnames and not list(results),
            "performance result template must contain no samples")
    makefile = snapshot.read(ROOT / "c/Makefile").decode("utf8")
    for switch in ("INCREMENTAL_MODE", "INCREMENTAL_B1", "INCREMENTAL_V1"):
        require(switch + " ?= 0" in makefile, "research switch must default to zero: " + switch)
    require(".DEFAULT_GOAL := all" in makefile, "default Make goal changed")
    with zipfile.ZipFile(io.BytesIO(snapshot.read(BASE / "K0-source.zip"))) as archive:
        require(len(archive.namelist()) == len(set(archive.namelist())), "duplicate K0 archive entries")
        require(hashlib.sha256(archive.read("c/src/engine.c")).hexdigest() == BASELINE_ENGINE,
                "K0 archive engine differs from the fixed baseline")
    return {"P_parameter_cache_count": 8, "P_resource_shape_count": 32, "P_pairwise_region_count": 168,
            "performance_enabled": False, "execution_permit": False, "new_performance_samples": 0,
            "K0_commit": BASELINE, "external_adapters_accepted": False}


def check_budget(snapshot, manifests, fixture):
    path = BASE / "signing-budget.sqlite"
    snapshot.hash(path)
    requests = []
    for suffix in ("full-af-r1", "full-a8-r1", "full-af-r2", "full-fault5-r1"):
        value = manifests[suffix]
        fault = suffix == "full-fault5-r1"
        requests.append({"receipt": value["budget_receipt"], "algorithm": "SLH-DSA-SM3-128-24",
                         "public_key": bytes.fromhex(fixture["pk"]), "message": bytes.fromhex(fixture["mp"]),
                         "signature": None if fault else bytes.fromhex(fixture["sig"]),
                         "statuses": ("failed",) if fault else ("committed",)})
    require(len({row["receipt"] for row in requests}) == 4, "four distinct full-signature receipts required")
    receipts = ReadOnlyBudget(path).validate_receipts(requests)
    for suffix, actual in zip(("full-af-r1", "full-a8-r1", "full-af-r2", "full-fault5-r1"), receipts):
        require(actual == manifests[suffix]["budget_validation"], "preserved budget validation differs: " + suffix)
    snapshot.hash(path)
    return receipts


def validate_evidence(snapshot, output):
    records = [json.loads(line) for line in snapshot.read(ROOT / FIXTURE).decode("utf8").splitlines() if line.strip()]
    fixtures = [row for row in records if row.get("case_id") == "python-3-0"]
    require(len(fixtures) == 1, "one fixed independent signing fixture required")
    fixture = fixtures[0]
    require(len(bytes.fromhex(fixture["pk"])) == 32 and len(bytes.fromhex(fixture["sig"])) == 3856,
            "fixed fixture lengths differ")
    integration_steps = [name for mode, b1 in ((0, 0), (0, 1), *((m, b) for m in range(1, 5) for b in (0, 1)))
                         for name in (f"m{mode}-b{b1}-build", f"m{mode}-b{b1}-trees")]
    integration_steps += [name for config in ("sanitizer", "reversed", "fault-2", "fault-5")
                          for name in (config + "-build", config + "-trees")]
    configurations = (
        ("integration-r2", "integration", integration_steps, "all"),
        ("full-af-r2", "full", ["full-build", "full-signature"], "all"),
        ("kernel-r1", "kernel", [name for config in ("normal", "sanitizer", "portable")
                                  for name in (config + "-build", config + "-kernel")], "kernel"),
        ("release-r1", "release", ["default-release", "candidate-release", "portable-release", "combined-v1-build",
                                     "combined-v1-python-3-0", "combined-v1-python-3-1", "combined-v1-python-3-2"], "release"),
        ("full-a8-r1", "full", ["full-build", "full-signature"], "historical_harness"),
        ("full-fault5-r1", "full", ["full-build", "full-signature"], "historical_harness"),
    )
    manifests, accepted = {}, []
    for suffix, phase, steps, scope in configurations:
        value, record = check_run(snapshot, suffix, phase, steps, scope)
        manifests[suffix] = value
        accepted.append(record)
    for suffix, mode, fault in (("full-af-r2", 4, 0), ("full-a8-r1", 2, 0), ("full-fault5-r1", 4, 5)):
        check_full_result(snapshot, suffix, manifests[suffix], mode, fault)
    historical = []
    for suffix in ("v1-r1", "integration-r1", "full-af-r1"):
        directory = ROOT / "validation" / ("incremental-20261005-" + suffix)
        value = snapshot.json(directory / "manifest.json")
        require(value.get("passed") is True and value.get("performance_samples") == 0 and
                value.get("performance_enabled") is False, "historical record status differs: " + suffix)
        for step in value["steps"]:
            snapshot.hash(local(step["log"]), step["log_sha256"])
        snapshot.hash(ROOT / FIXTURE, value["fixture_sha256"])
        historical.append({"run": suffix, "scope": "historical only; not final acceptance"})
        manifests[suffix] = value
    isolation = check_isolation(snapshot, fixture)
    analysis = check_analysis_tests(snapshot)
    preparation = check_analysis_and_preparation(snapshot)
    receipts = check_budget(snapshot, manifests, fixture)
    # Bind all new notes and supporting logs, including the final analysis runs.
    for folder in (BASE, ROOT / "docs/research"):
        for path in sorted(folder.rglob("*")):
            if path.is_file() and not path.is_relative_to(output) and not path.is_relative_to(BASE / "final") and not path.name.endswith(("-wal", "-shm")):
                snapshot.hash(path)
    return {"accepted_runs": accepted, "historical_runs": historical, "isolation": isolation, "analysis": analysis,
            "budget_receipts": receipts, "preparation": preparation}


def source_paths():
    paths = set()
    for directory in (ROOT / "c", ROOT / "third_party/slhdsa-c", ROOT / "docs/research", ROOT / "tools"):
        for path in directory.rglob("*"):
            if path.is_file() and (path.suffix in {".c", ".h", ".inc", ".cu", ".cuh", ".cpp", ".py", ".md"} or
                                   path.name == "Makefile" or path.name.startswith(("LICENSE", "COPYING"))):
                paths.add(path)
    paths.update(ROOT / name for name in ("README.md", "SPEC.md", "docs/LICENSE_STATUS.md", ".gitignore", ".gitattributes", ".github/workflows/correctness.yml", FIXTURE))
    return sorted(paths)


def validate_archive(snapshot, archive_path, sources):
    with zipfile.ZipFile(io.BytesIO(snapshot.read(archive_path))) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)) and set(names) == set(sources), "source archive entry set differs")
        for name, expected in sources.items():
            require(hashlib.sha256(archive.read(name)).hexdigest() == expected, "archived source differs: " + name)


def write_archive(snapshot, path, members):
    with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(members):
            entry = zipfile.ZipInfo(name, date_time=(2026, 10, 5, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, snapshot.read(local(name)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=BASE / "final")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    out = args.output.resolve()
    require(out.is_relative_to(ROOT / "validation") and out != ROOT / "validation",
            "output must be a validation child")
    require(args.check or not out.exists(), "preserve existing package; use --check or a fresh output path")
    snapshot = Snapshot()
    if args.check:
        freeze = snapshot.json(out / "freeze.json")
        require(freeze.get("schema") == SCHEMA, "incremental freeze schema differs")
        snapshot.hash(out / "artifacts.zip", freeze["files_sha256"]["artifacts.zip"])
        with zipfile.ZipFile(io.BytesIO(snapshot.read(out / "artifacts.zip"))) as archive:
            names = archive.namelist()
            require(len(names) == len(set(names)) and set(names) == set(freeze["artifact_sha256"]),
                    "retained artifact archive inventory differs")
            for name in names:
                local(name)
                data = archive.read(name)
                require(hashlib.sha256(data).hexdigest() == freeze["artifact_sha256"][name],
                        "retained artifact archive hash differs: " + name)
                snapshot.archived[name] = data
    evidence = validate_evidence(snapshot, out)
    sources = {relative(path): snapshot.hash(path) for path in source_paths()}
    evidence_hashes = {name: expected for name, expected in sorted(snapshot.files.items())
                       if not local(name).is_relative_to(out)}
    if args.check:
        freeze = snapshot.json(out / "freeze.json")
        require(freeze.get("schema") == SCHEMA and freeze.get("correctness_passed") is True and
                freeze.get("performance_enabled") is False and freeze.get("execution_permit") is False and
                freeze.get("new_performance_samples") == 0 and freeze.get("baseline_commit") == BASELINE and
                freeze.get("source_file_count") == len(sources), "existing freeze is not a closed acceptance package")
        require(freeze["acceptance"] == evidence, "acceptance interpretation changed after freeze")
        require(freeze["evidence_sha256"] == evidence_hashes, "frozen evidence inventory differs")
        hash_mapping(snapshot, freeze["evidence_sha256"])
        hash_mapping(snapshot, freeze["files_sha256"], out)
        stored_sources = snapshot.json(out / "source-manifest.json")
        require(stored_sources == sources, "current source inventory differs from freeze")
        validate_archive(snapshot, out / "source.zip", stored_sources)
    else:
        snapshot.verify()
        out.mkdir(parents=True, exist_ok=False)
        write_archive(snapshot, out / "source.zip", sources)
        artifacts = {name: expected for name, expected in evidence_hashes.items()
                     if name.startswith("build/") or "/cache/" in name or name.endswith((".o", ".so"))}
        write_archive(snapshot, out / "artifacts.zip", artifacts)
        validate_archive(snapshot, out / "artifacts.zip", artifacts)
        with (out / "source-manifest.json").open("xb") as stream:
            stream.write(canonical(sources))
        validate_archive(snapshot, out / "source.zip", sources)
        files = {name: snapshot.hash(out / name) for name in ("source.zip", "source-manifest.json", "artifacts.zip")}
        snapshot.verify()
        freeze = {"schema": SCHEMA, "created_utc": datetime.now(timezone.utc).isoformat(),
                  "correctness_passed": True, "performance_enabled": False, "execution_permit": False,
                  "new_performance_samples": 0, "baseline_commit": BASELINE,
                  "acceptance": evidence, "evidence_sha256": evidence_hashes, "files_sha256": files,
                  "artifact_sha256": artifacts,
                  "scope": "fixed pid3 implementation acceptance and closed preparation; no performance permit",
                  "source_file_count": len(sources)}
        with (out / "freeze.json").open("xb") as stream:
            stream.write(canonical(freeze))
    snapshot.verify()
    print(json.dumps({"passed": True, "checked_existing_package": args.check, "output": str(out),
                      "source_files": len(sources), "performance_enabled": False,
                      "execution_permit": False, "new_performance_samples": 0}))


if __name__ == "__main__":
    main()
