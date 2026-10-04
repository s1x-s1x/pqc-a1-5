#!/usr/bin/env python3
"""Audit preserved optimization delivery bytes using only the standard library.

This is a local mirror audit, not the Linux runtime provenance gate. It never
imports project tools, loads native libraries, spawns processes, or measures
performance. By default it only prints JSON. --output creates a new JSON audit
record exclusively; it never replaces an existing file.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sqlite3
import sys
import tarfile


REMOTE_ROOT = "/home/guest-experiment/pqc-a1-5"
ARTIFACTS = {"freeze.json", "source.tar.gz", "source-manifest.json", "REVIEW.md"}
READINESS = "validation/optimization-final-readiness.json"
EXTERNAL_MANIFEST = "validation/optimization-external-evidence/manifest.json"
HASH_RE = re.compile(r"[0-9a-f]{64}")
BENCH_SCHEMAS = {"a15-cpu-bench-v1", "a15-cuda-bench-v1"}


class AuditError(ValueError):
    """A redacted, reviewable failure that contains no host credentials."""


def require(condition, message):
    if not condition:
        raise AuditError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON object key")
        result[key] = value
    return result


def read_json(path):
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream, object_pairs_hook=unique_object)


def file_sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def hash_map(value, label):
    require(isinstance(value, dict) and bool(value), label + " map missing")
    require(all(isinstance(name, str) and isinstance(digest, str)
                and HASH_RE.fullmatch(digest) for name, digest in value.items()),
            label + " map malformed")
    return value


def relative_name(name):
    require(isinstance(name, str) and bool(name) and "\\" not in name
            and ":" not in name, "relative path malformed")
    path = PurePosixPath(name)
    require(not path.is_absolute() and str(path) == name
            and all(part not in (".", "..") for part in path.parts),
            "relative path is not canonical")
    return name


def remote_name(name):
    require(isinstance(name, str) and name.startswith("/") and "\\" not in name,
            "remote evidence path malformed")
    path = PurePosixPath(name)
    require(str(path) == name and ".." not in path.parts,
            "remote evidence path is not canonical")
    return name


class Audit:
    def __init__(self, root, *, readiness=READINESS, staging_root=None,
                 remote_staging_root=None, external_manifest=EXTERNAL_MANIFEST):
        self.root = root.resolve()
        self.readiness_name = relative_name(readiness)
        self.external_manifest_name = relative_name(external_manifest)
        self.repair = self.readiness_name != READINESS
        require((staging_root is None) == (remote_staging_root is None),
                "local/remote staging roots must be supplied together")
        require(self.repair == (staging_root is not None),
                "repair audit requires explicit readiness and staging root mapping")
        self.staging_root = relative_name(staging_root) if staging_root is not None else None
        self.remote_staging_root = remote_name(remote_staging_root) if remote_staging_root is not None else None
        if self.repair:
            require(self.remote_staging_root.startswith(REMOTE_ROOT + "/build/")
                    and self.remote_staging_root != REMOTE_ROOT,
                    "repair remote staging root must be inside the project build directory")
            require(self.staging_root.startswith("build/"), "repair local staging root must be inside build")
        self.errors = []
        self.checks = []
        self.packages = {}
        self.external = {}
        self.protected = set()

    def local(self, name):
        name = relative_name(name)
        path = self.root.joinpath(*PurePosixPath(name).parts)
        require(path.resolve().is_relative_to(self.root), "local path leaves project")
        # Reject symlinks at every level rather than trusting relocated targets.
        cursor = path
        while cursor != self.root:
            require(not cursor.is_symlink(), "local evidence contains a symbolic link")
            cursor = cursor.parent
        return path

    def mapped(self, original):
        original = remote_name(original)
        if self.remote_staging_root is not None and original.startswith(self.remote_staging_root + "/"):
            return self.local(self.staging_root + "/" + original[len(self.remote_staging_root) + 1:])
        if original.startswith(REMOTE_ROOT + "/"):
            return self.local(original[len(REMOTE_ROOT) + 1:])
        require(original in self.external, "external evidence manifest entry missing")
        return self.local(self.external[original]["local_path"])

    def checked_file(self, path, expected):
        require(isinstance(expected, str) and HASH_RE.fullmatch(expected), "SHA256 malformed")
        require(path.is_file(), "evidence file missing")
        require(not path.is_symlink(), "evidence file is symbolic link")
        require(file_sha(path) == expected, "evidence SHA256 differs")
        self.protected.add(path.resolve())

    def check(self, label, action):
        try:
            result = action()
            self.checks.append({"check": label, "passed": True})
            return result
        except Exception as error:
            # Raw OSError/JSON messages can disclose absolute local paths or
            # document content, so only deliberate AuditError messages pass.
            message = str(error) if isinstance(error, AuditError) else type(error).__name__
            self.errors.append({"check": label, "error": message})
            self.checks.append({"check": label, "passed": False})
            return None

    def external_manifest(self):
        path = self.local(self.external_manifest_name)
        manifest = read_json(path)
        require(manifest.get("schema") == "a15-external-evidence-mirror-v1",
                "external manifest schema differs")
        require(manifest.get("remote_project_root") in {REMOTE_ROOT, self.remote_staging_root} - {None},
                "external manifest remote root differs")
        entries = manifest.get("files")
        require(isinstance(entries, dict) and bool(entries), "external manifest empty")
        paths = set()
        for original, entry in entries.items():
            remote_name(original)
            require(not original.startswith(REMOTE_ROOT + "/") and isinstance(entry, dict),
                    "external manifest entry malformed")
            expected_path = "validation/optimization-external-evidence/" + original.lstrip("/")
            require(entry.get("local_path") == expected_path,
                    "external manifest path identity differs")
            local = self.local(expected_path)
            require(local not in paths, "duplicate external local path")
            paths.add(local)
            self.checked_file(local, entry.get("sha256"))
            require(type(entry.get("size_bytes")) is int
                    and local.stat().st_size == entry["size_bytes"],
                    "external evidence size differs")
        self.external = entries
        self.protected.add(path.resolve())
        return {"files": len(entries), "manifest_sha256": file_sha(path)}

    def published_package(self, kind, readiness):
        expected = readiness["packages"][kind]
        if self.repair:
            original_directory = remote_name(expected.get("directory"))
            require(original_directory.startswith(self.remote_staging_root + "/validation/"),
                    "repair package directory must be in the explicit staging validation directory")
            directory = self.mapped(original_directory)
        else:
            folder = "validation/optimization-" + kind + "-final"
            original_directory = REMOTE_ROOT + "/" + folder
            directory = self.local(folder)
        package = read_json(directory / "package.json")
        freeze = read_json(directory / "freeze.json")
        sources = hash_map(read_json(directory / "source-manifest.json"), "source manifest")
        require(package.get("passed") is True and package.get("formal_performance_started") is False
                and type(package.get("real_timing_samples", 0)) is int
                and package.get("real_timing_samples", 0) == 0, "package is not preparation")
        recorded = hash_map(package.get("files_sha256"), "package artifacts")
        require(set(recorded) == ARTIFACTS, "package artifact set differs")
        for name, digest in recorded.items():
            self.checked_file(directory / name, digest)
        require(expected.get("passed") is True and expected.get("files_sha256") == recorded,
                "readiness package artifact identity differs")
        self.checked_file(directory / "package.json", expected.get("package_sha256"))
        require(expected.get("freeze_sha256") == recorded["freeze.json"],
                "readiness freeze identity differs")
        require(freeze.get("schema") == "a15-" + kind + "-freeze-v1"
                and freeze.get("final") is True and freeze.get("correctness_passed") is True
                and freeze.get("formal_performance_started") is False
                and type(freeze.get("real_timing_samples", 0)) is int
                and freeze.get("real_timing_samples", 0) == 0, "freeze final state differs")
        frozen = hash_map(freeze.get("source_sha256"), "frozen sources")
        if self.repair:
            require("c/src/secure_zero.h" in frozen and "c/Makefile" in frozen,
                    "repair freeze omits secure-zero/build configuration source identity")
        require(all(sources.get(name) == digest for name, digest in frozen.items()),
                "source manifest omits frozen source")
        field = "correctness_evidence" if kind == "cpu" else "correctness_evidence_sha256"
        evidence = hash_map(freeze.get(field), "correctness evidence")
        require(type(expected.get("source_files")) is int and expected["source_files"] == len(sources)
                and type(expected.get("evidence_files")) is int
                and expected["evidence_files"] == len(evidence), "readiness file counts differ")
        result = {"freeze": freeze, "sources": sources, "evidence": evidence, "directory": directory,
                  "remote_directory": original_directory, "readiness_entry": expected,
                  "summary": {"source_files": len(sources), "frozen_sources": len(frozen),
                              "evidence_files": len(evidence), "package_sha256": file_sha(directory / "package.json"),
                              "freeze_sha256": recorded["freeze.json"], "files_sha256": recorded}}
        self.packages[kind] = result
        return result

    def archive(self, data):
        sources = data["sources"]
        names = []
        with tarfile.open(data["directory"] / "source.tar.gz", "r:gz") as archive:
            for member in archive:
                relative_name(member.name)
                require(member.isfile() and not member.issym() and not member.islnk(),
                        "archive contains nonregular file or link")
                require(member.name not in names, "archive contains duplicate member")
                names.append(member.name)
                require(member.name in sources, "archive member absent from manifest")
                stream = archive.extractfile(member)
                require(stream is not None, "archive member unreadable")
                with stream:
                    digest = hashlib.sha256()
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
                require(digest.hexdigest() == sources[member.name], "archive source SHA256 differs")
        require(set(names) == set(sources), "archive member set differs from manifest")
        return len(names)

    def current_sources(self, data):
        for name, digest in data["freeze"]["source_sha256"].items():
            self.checked_file(self.local(name), digest)

    def correctness(self, data):
        counter = Counter()
        for original, digest in data["evidence"].items():
            self.checked_file(self.mapped(original), digest)
            if original.startswith(REMOTE_ROOT + "/"):
                counter["project_files"] += 1
            else:
                require(self.external[original]["sha256"] == digest,
                        "external evidence manifest SHA256 differs from freeze")
                counter["external_files"] += 1
        return dict(counter)

    def build_and_plans(self, kind, data):
        freeze = data["freeze"]
        if self.repair:
            candidates = []
            for original, digest in data["evidence"].items():
                if digest == freeze.get("build_record_sha256") and original.endswith(".json"):
                    path = self.mapped(original)
                    self.checked_file(path, digest)
                    record = read_json(path)
                    if isinstance(record, dict) and record.get("schema") == "a15-" + kind + "-build-v1":
                        candidates.append((original, path, record))
            require(len(candidates) == 1, "repair release build must have one exact frozen evidence binding")
            original, record_path, record = candidates[0]
            require(original.startswith(self.remote_staging_root + "/"), "repair release build leaves staging")
            library_original = remote_name(record.get("library"))
            require(library_original.startswith(self.remote_staging_root + "/"), "repair release library leaves staging")
            library_path = self.mapped(library_original)
        else:
            build_dir = "build/cuda-staging-20261004/build/bench-" + kind + "-prep-20261004/"
            record_path = self.local(build_dir + "build-record.json")
            library_path = self.local(build_dir + "libslhdsa_sm3.so")
        self.checked_file(record_path, freeze.get("build_record_sha256"))
        self.checked_file(library_path, freeze.get("library_sha256"))
        record = read_json(record_path)
        require(record.get("schema") == "a15-" + kind + "-build-v1"
                and record.get("library_sha256") == freeze["library_sha256"]
                and self.mapped(record.get("library")) == library_path,
                "release build/library binding differs")
        for flag in ("counters", "test_injection", "sanitizer"):
            require(record.get(flag) is False, "release record instrumentation enabled")
        require(record.get("compile_output_checked") is True, "release compile output unchecked")
        compiled = hash_map(record.get("source_sha256"), "build source")
        if self.repair:
            require("c/src/secure_zero.h" in compiled and "c/Makefile" in compiled,
                    "repair release compiled sources omit secure-zero/build configuration identity")
        require(all(freeze["source_sha256"].get(name) == digest for name, digest in compiled.items()),
                "release compiled sources differ from freeze")
        plans = freeze.get("plans")
        required_counts = {"r3": 54, "r4": 207, "r5": 252} if kind == "cpu" else {"cuda_b1": 64}
        require(isinstance(plans, dict) and set(plans) == set(required_counts), "plan suites differ")
        summary = {}
        for name, entry in plans.items():
            require(isinstance(entry, dict), "plan binding malformed")
            path = self.mapped(entry.get("path"))
            self.checked_file(path, entry.get("sha256"))
            require(data["evidence"].get(entry["path"]) == entry["sha256"],
                    "plan is not bound in correctness evidence")
            plan = read_json(path)
            cases = plan.get("cases")
            require(plan.get("schema") == "a15-" + kind + "-plan-v1"
                    and plan.get("suite") == name and isinstance(cases, list)
                    and type(entry.get("cases")) is int
                    and len(cases) == entry["cases"] == required_counts[name], "plan cases differ")
            ids = [case.get("case_id") for case in cases if isinstance(case, dict)]
            require(len(ids) == len(cases) and all(isinstance(x, str) and x for x in ids)
                    and len(set(ids)) == len(ids), "plan case identity malformed or duplicate")
            summary[name] = {"cases": len(cases), "sha256": entry["sha256"]}
        return {"library_sha256": freeze["library_sha256"],
                "build_record_sha256": freeze["build_record_sha256"], "plans": summary}

    def mocks(self, kind, data):
        schema = "a15-bench-selftest-v1" if kind == "cpu" else "a15-cuda-selftest-v1"
        tool = "tools/bench_" + kind + ".py"
        if self.repair:
            count = data["readiness_entry"].get("mock_checks")
            minimum = 28 if kind == "cpu" else 25
            require(type(count) is int and count >= minimum, "repair readiness mock count missing or below accepted scope")
            candidates = []
            for original, digest in data["evidence"].items():
                if not original.endswith(".json"):
                    continue
                path = self.mapped(original)
                self.checked_file(path, digest)
                mock = read_json(path)
                if (isinstance(mock, dict) and mock.get("schema") == schema
                        and mock.get("tool_sha256") == data["freeze"]["source_sha256"].get(tool)):
                    candidates.append((original, mock))
            require(len(candidates) == 1, "repair freeze must bind one mock for the exact current tool")
            original, mock = candidates[0]
            require(original.startswith(self.remote_staging_root + "/"), "repair mock leaves explicit staging")
            if kind == "cuda":
                require(data["freeze"].get("evidence", {}).get("mock", {}).get("path") == original,
                        "repair CUDA mock differs from explicit release evidence")
        else:
            version, count = ("v6", 26) if kind == "cpu" else ("v7", 23)
            name = "build/cuda-staging-20261004/preparation/bench_" + kind + "-mock-final-" + version + ".json"
            original = REMOTE_ROOT + "/" + name
            require(original in data["evidence"], "final mock is not bound in correctness evidence")
            path = self.local(name)
            self.checked_file(path, data["evidence"][original])
            mock = read_json(path)
        require(mock.get("schema") == schema and mock.get("passed") is True
                and type(mock.get("mock_checks")) is int and mock["mock_checks"] == count,
                "final mock count/state differs")
        require(type(mock.get("native_calls")) is int and mock["native_calls"] == 0
                and type(mock.get("real_timing_samples")) is int and mock["real_timing_samples"] == 0,
                "final mock native/timing count differs")
        sources = hash_map(mock.get("source_sha256"), "mock sources")
        require(mock.get("tool_sha256") == sources.get(tool) == data["freeze"]["source_sha256"].get(tool),
                "final mock tool binding differs")
        for name, digest in sources.items():
            require(data["freeze"]["source_sha256"].get(name) == digest, "mock source differs from freeze")
            self.checked_file(self.local(name), digest)
        return {"checks": count, "passed": True, "native_calls": 0, "real_timing_samples": 0,
                "tool_sha256": mock["tool_sha256"], "evidence_path": original}

    def cuda_release(self, data):
        freeze = data["freeze"]
        entries = freeze.get("evidence")
        require(isinstance(entries, dict) and set(entries) == {"correctness", "mock"},
                "CUDA release evidence binding malformed")
        for entry in entries.values():
            require(isinstance(entry, dict) and data["evidence"].get(entry.get("path")) == entry.get("sha256"),
                    "CUDA release evidence omitted from correctness map")
            self.checked_file(self.mapped(entry["path"]), entry["sha256"])
        release = read_json(self.mapped(entries["correctness"]["path"]))
        require(release.get("passed") is True and release.get("library_sha256") == freeze["library_sha256"]
                and release.get("build_record_sha256") == freeze["build_record_sha256"]
                and release.get("device_identity") == freeze.get("device_identity")
                and release.get("formal_performance_started") is False
                and release.get("measured_durations") is False
                and type(release.get("real_timing_samples")) is int and release["real_timing_samples"] == 0,
                "CUDA release identity/state differs")
        for name, digest in hash_map(release.get("sources_and_tools_sha256"), "CUDA release sources").items():
            self.checked_file(self.local(name), digest)
        rows = release.get("rows")
        require(isinstance(rows, list) and len(rows) == 14 and all(row.get("passed") is True for row in rows),
                "CUDA release correctness checks differ")
        return {"checks": len(rows), "passed": True, "device_identity": freeze["device_identity"]}

    def budgets(self, kind, data):
        snapshots = data["freeze"].get("budget_snapshots", [])
        require(isinstance(snapshots, list) and (kind != "cuda" or bool(snapshots)),
                "budget snapshots missing")
        directory = data["directory"]
        preserved, live = set(), set()
        summary = []
        for entry in snapshots:
            require(isinstance(entry, dict), "budget snapshot entry malformed")
            original = remote_name(entry.get("snapshot_database"))
            live_original = remote_name(entry.get("live_database"))
            require(live_original not in live and not live_original.startswith(data["remote_directory"] + "/"),
                    "budget live identity duplicated or inside package")
            live.add(live_original)
            for suffix in ("", "-wal", "-shm"):
                require(live_original + suffix not in data["evidence"], "mutable live budget bound as evidence")
            path = self.mapped(original)
            require(path.parent == directory / "budget-evidence", "budget snapshot outside package")
            recorded = hash_map(entry.get("files_sha256"), "budget snapshot")
            # Settled delivery snapshots have no WAL. immutable=1 provides an
            # explicitly read-only connection without creating WAL/SHM files.
            require(set(recorded) == {original}, "budget snapshot is not a settled single database")
            require(original not in preserved and data["evidence"].get(original) == recorded[original],
                    "budget snapshot evidence identity differs")
            preserved.add(original)
            self.checked_file(path, recorded[original])
            require(path.stat().st_nlink == 1, "budget snapshot is not an independent copy")
            sidecars = [Path(str(path) + suffix) for suffix in ("-wal", "-shm", "-journal")]
            require(not any(p.exists() for p in sidecars), "budget snapshot has sidecars")
            connection = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)
            try:
                connection.execute("PRAGMA query_only=ON")
                result = connection.execute("PRAGMA integrity_check").fetchall()
            finally:
                connection.close()
            require(result == [("ok",)], "budget SQLite integrity differs")
            require(not any(p.exists() for p in sidecars), "budget audit created sidecars")
            self.checked_file(path, recorded[original])
            summary.append({"path": path.relative_to(self.root).as_posix(), "sha256": recorded[original],
                            "sqlite_integrity": "ok", "immutable_read_only": True})
        for original in data["evidence"]:
            lower = original.lower()
            require(not (lower.endswith((".sqlite", ".sqlite3", ".db", "-wal", "-shm")))
                    or original in preserved, "budget evidence lacks immutable snapshot identity")
        return summary

    def performance(self):
        directories, files, sample_rows, bench_rows = [], [], 0, 0
        # Scan the project tree for real benchmark schemas, even if a result was
        # moved away from the prescribed bench-out folder. Correctness JSONL is
        # evidence and is not treated as formal timing.
        for path in sorted(self.root.rglob("*.jsonl")):
            relative = path.relative_to(self.root).as_posix()
            relevant = any(part in {"bench-out", "performance", "performance-out", "perf-out", "benchmark-out"}
                           for part in path.relative_to(self.root).parts)
            if relevant:
                directories.append(path.parent.relative_to(self.root).as_posix())
            path = self.local(relative)
            with path.open("r", encoding="utf-8") as stream:
                for line in stream:
                    if not line.strip():
                        continue
                    try:
                        row = json.loads(line, object_pairs_hook=unique_object)
                    except (ValueError, json.JSONDecodeError):
                        require(not relevant, "performance JSONL malformed")
                        continue
                    if isinstance(row, dict) and row.get("schema") in BENCH_SCHEMAS:
                        bench_rows += 1
                        if relative not in files:
                            files.append(relative)
                        if row.get("kind") == "sample":
                            sample_rows += 1
        require(bench_rows == 0 and sample_rows == 0, "local performance campaign has benchmark records")
        return {"scope": "all local project JSONL files; CPU/CUDA benchmark schemas",
                "directories": sorted(set(directories)), "performance_jsonl_files": files,
                "benchmark_records": bench_rows, "formal_samples": sample_rows,
                "active_process_check": "not performed by local read-only audit; server readiness is authoritative"}

    def run(self):
        readiness = self.check("server_readiness", lambda: self.server_readiness())
        external_summary = self.check("external_evidence_manifest", self.external_manifest)
        package_summaries = {}
        if readiness is not None:
            for kind in ("cpu", "cuda"):
                data = self.check(kind + ".published_package", lambda kind=kind: self.published_package(kind, readiness))
                if data is None:
                    continue
                summary = data["summary"]
                self.check(kind + ".archive_exact_members_and_hashes", lambda: self.archive(data))
                self.check(kind + ".current_frozen_source_hashes", lambda: self.current_sources(data))
                summary["correctness_evidence"] = self.check(kind + ".correctness_evidence", lambda: self.correctness(data))
                summary["release_build_and_plans"] = self.check(kind + ".release_build_and_plans", lambda: self.build_and_plans(kind, data))
                summary["final_mock"] = self.check(kind + ".final_mock", lambda: self.mocks(kind, data))
                summary["budget_snapshots"] = self.check(kind + ".budget_snapshots", lambda: self.budgets(kind, data))
                if kind == "cuda":
                    summary["release_correctness"] = self.check("cuda.release_correctness", lambda: self.cuda_release(data))
                package_summaries[kind] = summary
        external_paths = {original for data in self.packages.values() for original in data["evidence"]
                          if not original.startswith(REMOTE_ROOT + "/")}
        self.check("external_manifest_exact_evidence_set", lambda: require(set(self.external) == external_paths,
                                                                          "external manifest evidence set differs"))
        performance = self.check("local_performance_campaign_not_started", self.performance)
        return {"schema": "a15-optimization-local-delivery-v1", "created_utc": datetime.now(timezone.utc).isoformat(),
                "passed": not self.errors, "classification": "local mirror byte/provenance audit; Linux execution runtime remains on server",
                "linux_runtime_gate_executed": False, "native_calls": 0, "timing_samples": 0,
                "real_timing_samples": 0, "formal_performance_started": False if performance is not None else None,
                "audit_profile": "repair" if self.repair else "historical optimization delivery",
                "staging_mapping": {"local": self.staging_root, "remote": self.remote_staging_root} if self.repair else None,
                "server_gate_evidence": {"path": self.readiness_name, "sha256": file_sha(self.local(self.readiness_name)) if readiness is not None else None,
                                         "passed": readiness.get("passed") if readiness is not None else False,
                                         "cpu_gate_passed": readiness.get("cpu_gate_passed") if readiness is not None else False,
                                         "cuda_gate_passed": readiness.get("cuda_gate_passed") if readiness is not None else False,
                                         "scope": "preserved server readiness; this audit does not rerun Linux runtime gates"},
                "external_evidence": external_summary, "packages": package_summaries,
                "local_performance": performance, "checks": self.checks, "errors": self.errors}

    def server_readiness(self):
        path = self.local(self.readiness_name)
        result = read_json(path)
        require(result.get("schema") == "a15-optimization-final-readiness-v1" and result.get("passed") is True
                and result.get("cpu_gate_passed") is True and result.get("cuda_gate_passed") is True,
                "server readiness gate state differs")
        require(result.get("formal_performance_started") is False
                and type(result.get("real_native_calls")) is int and result["real_native_calls"] == 0
                and type(result.get("real_timing_samples")) is int and result["real_timing_samples"] == 0
                and result.get("active_benchmark_processes") == [] and result.get("performance_jsonl_files") == [],
                "server readiness performance state differs")
        require(isinstance(result.get("packages"), dict) and set(result["packages"]) == {"cpu", "cuda"},
                "server readiness package set differs")
        self.protected.add(path.resolve())
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1], help="local project root")
    parser.add_argument("--readiness", default=READINESS, help="explicit project-relative repair readiness JSON; default preserves historical scope")
    parser.add_argument("--staging-root", help="repair evidence mirror directory relative to the local project, inside build")
    parser.add_argument("--remote-staging-root", help="canonical absolute remote repair project root inside the original project's build directory")
    parser.add_argument("--external-manifest", default=EXTERNAL_MANIFEST, help="project-relative external evidence manifest")
    parser.add_argument("--output", type=Path,
                        help="create a new audit JSON directly under validation or build (project-relative or absolute)")
    args = parser.parse_args()
    try:
        audit = Audit(args.root, readiness=args.readiness, staging_root=args.staging_root,
                      remote_staging_root=args.remote_staging_root, external_manifest=args.external_manifest)
    except AuditError as error:
        parser.error(str(error))
    try:
        result = audit.run()
    except Exception as error:
        message = str(error) if isinstance(error, AuditError) else type(error).__name__
        result = {"schema": "a15-optimization-local-delivery-v1", "passed": False,
                  "classification": "local mirror audit; Linux runtime gate was not executed",
                  "linux_runtime_gate_executed": False, "native_calls": 0, "timing_samples": 0,
                  "errors": [{"check": "audit_execution", "error": message}]}
    if args.output is not None:
        try:
            output = args.output if args.output.is_absolute() else audit.root / args.output
            output = output.absolute()
            require(output.resolve().is_relative_to(audit.root), "audit output must stay inside project")
            relative_output = output.relative_to(audit.root).as_posix()
            output = audit.local(relative_output)
            require(output.parent in {audit.root / "validation", audit.root / "build"},
                    "new audit output must be directly under validation or build")
            require(output.suffix.lower() == ".json" and output.resolve() not in audit.protected,
                    "audit output overlaps protected evidence")
            require(not output.exists() and output.parent.is_dir() and not output.is_symlink(),
                    "audit output must be a new file in an existing directory")
            # The exclusive create guarantees that original evidence cannot be
            # replaced even if another process creates the path after checking.
            with output.open("x", encoding="utf-8", newline="\n") as stream:
                json.dump(result, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
        except Exception as error:
            result["passed"] = False
            message = str(error) if isinstance(error, AuditError) else type(error).__name__
            result["errors"].append({"check": "audit_output", "error": message})
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
