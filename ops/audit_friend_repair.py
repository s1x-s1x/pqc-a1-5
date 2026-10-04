"""Read-only engineering delta acceptance; never load native code or time work.

The historical 3471/1789 matrices and freezes remain historical. This report is
not a formal benchmark permit, and cannot override an old freeze's source gate.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "validation/project-repair-final-audit-r3.json"
BASELINE_SHA256 = "88a00911796b2ecfb6b6eb24b91fa3a436d62041ea1c2f4c8d72f93aba733764"
BASE_ARCHIVE = "build/repair-staging-20261004-r3/validation/optimization-cuda-repair-r3-final/source.tar.gz"
BASE_CPU_LIBRARY = "build/repair-staging-20261004-r3/build/native-repair-r3/avx2/libslhdsa_sm3.so"
ALLOWED_SOURCE_CHANGES = {
    "tools/native.py", "tools/test_native_boundaries.py", "tools/signing_budget.py",
    "tools/test_budget_repair.py", "tools/bench_cpu.py", "tools/bench_cuda.py",
    "tools/freeze_cuda.py", "ops/test_parallel_correctness.py",
    "base_tls/tls/alt_chain.py", "base_tls/tls/config.py", "base_tls/tls/handshake/client.py",
    "c/Makefile", "c/src/sm3_cuda.cu", "tools/run_cuda_native.py",
    "tools/run_project_functional.py",
    # Only a deselection/guard for the existing optional timing test is allowed
    # as part of the review runner's explicit no-performance profile.
    "base_tls/tests/conftest.py",
}
CUDA_STEPS = ("release-kernels-faults-guards", "counter-kernels", "disabled-build-dispatch",
              "hidden-device-dispatch", "release-library-dependencies")
FUNCTIONAL_STEPS = ("budget-repair", "native-boundary", "tls-pytest", "tls-live-checks", "dependency-locks",
                    "native-source-guards", "bench_cpu-mock", "bench_cuda-mock", "freeze_cuda-mock",
                    "real-ca-dual-verification", "p0-p4-serialized-functional")
REVIEW_STEPS = {
    "native-adapter", "budget", "review-matrix", "bench-resume", "cpu-mock", "cuda-mock", "freeze-mock",
    "tls-full", "tls-live", "dependency-lock", "native-source-guards", "parser-fuzz-smoke",
    "native-prehash", "native-cache-fuzz",
    "fresh-native-cpu", "native-sanitizers",
}
REQUIRED_SOURCES = {
    "ops/run_review_checks.py", "ops/audit_friend_repair.py", "ops/repro/Dockerfile",
    "ops/repro/fetch_base_image.py", ".github/workflows/correctness.yml", ".dockerignore",
    "base_tls/requirements.lock.txt", "base_tls/requirements-falcon.lock.txt", "reference/requirements.lock.txt",
    "tools/native.py", "tools/signing_budget.py", "tools/bench_cpu.py", "tools/bench_cuda.py",
    "tools/test_bench_resume_repair.py", "tools/test_friend_budget_scalability.py", "tools/freeze_cuda.py",
    "tools/run_cuda_native.py", "tools/run_project_functional.py", "tools/fuzz_inputs.py",
    "tools/test_native_digest_matrix.py", "tools/check_native_guards.py", "c/Makefile",
    "c/src/cuda_cleanup.h", "c/tests/test_cuda_cleanup_host.cpp", "base_tls/tls/alt_chain.py",
    "base_tls/tls/config.py", "base_tls/tls/handshake/client.py",
    "third_party/slhdsa-c/sha2_256.c", "third_party/slhdsa-c/sha3_api.c",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_value(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "malformed SHA256")
    return value


def relative_name(name):
    require(isinstance(name, str) and name and "\\" not in name and ":" not in name, "invalid relative evidence path")
    path = PurePosixPath(name)
    require(not path.is_absolute() and ".." not in path.parts and path.as_posix() == name and name != ".",
            "evidence path escapes or is noncanonical")
    return name


def hash_map(value):
    require(isinstance(value, dict) and value, "required hash inventory is missing or empty")
    for name, value_hash in value.items():
        relative_name(name)
        hash_value(value_hash)
    return value


def no_timing(data):
    require(data.get("formal_performance_started") is False and
            type(data.get("real_timing_samples")) is int and data["real_timing_samples"] == 0,
            "evidence contains timing or lacks explicit zero-sample lifecycle")
    if "performance_authorized" in data:
        require(data["performance_authorized"] is False, "engineering delta cannot authorize performance")
    if "measured_durations" in data:
        require(data["measured_durations"] is False, "measured native durations present")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def load_json(path):
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    require(isinstance(value, dict), "expected a JSON evidence object")
    return value


def cuda_math_suffix(value):
    marker = b"struct kernel_clock {"
    require(value.count(marker) == 1, "CUDA mathematical boundary marker differs")
    return value[value.index(marker):]


def e1_messages(messages):
    require(isinstance(messages, list) and len(messages) >= 7, "E1 serialized handshake records incomplete")
    flights = []
    for message in messages:
        require(isinstance(message, dict), "E1 record metadata is not an object")
        identity = message.get("sender"), message.get("name")
        if identity != (flights[-1] if flights else None):
            flights.append(identity)
        else:
            require(identity == ("server", "Certificate"), "unexpected E1 split message")
    require(flights == [("client", "ClientHello"), ("server", "ServerHello"),
        ("server", "EncryptedExtensions"), ("server", "Certificate"),
        ("server", "CertificateVerify"), ("server", "Finished"), ("client", "Finished")],
        "E1 handshake message ordering incomplete")


class Auditor:
    def __init__(self, root=ROOT):
        self.root = Path(root).resolve()
        self.records, self.checks, self.errors = {}, [], []
        self.baseline_preserved = set()

    def local(self, name):
        name = relative_name(name)
        path = self.root.joinpath(*PurePosixPath(name).parts)
        require(path.resolve().is_relative_to(self.root), "evidence resolves outside checkout")
        cursor = path
        while cursor != self.root:
            require(not cursor.is_symlink(), "evidence contains symbolic link")
            if hasattr(cursor, "is_junction"):
                require(not cursor.is_junction(), "evidence contains junction")
            cursor = cursor.parent
        require(path.is_file(), "evidence file missing: " + name)
        return path

    def verified(self, name, expected=None):
        path = self.local(name)
        observed = digest(path)
        require(expected is None or observed == hash_value(expected), "SHA256 differs: " + name)
        self.records[name] = observed
        return path

    def read(self, name, expected=None):
        return load_json(self.verified(name, expected))

    def inventory(self, entries):
        for name, expected in hash_map(entries).items():
            self.verified(name, expected)

    def current_sources(self, data, field):
        values = hash_map(data.get(field))
        self.inventory(values)
        return values

    def mapped(self, name, checkpoint, directory=None):
        remote = checkpoint.get("remote_root", "/home/guest-experiment/pqc-a1-5").rstrip("/")
        require(isinstance(remote, str) and remote.startswith("/") and ".." not in PurePosixPath(remote).parts,
                "remote root is malformed")
        if name.startswith(remote + "/"):
            name = name[len(remote) + 1:]
            prefix = checkpoint.get("local_root", ".")
            require(prefix == "." or relative_name(prefix), "local mirror root is malformed")
            return name if prefix == "." else prefix + "/" + name
        require(not PurePosixPath(name).is_absolute(), "foreign remote evidence path")
        if directory is not None and "/" not in name:
            return directory + "/" + relative_name(name)
        return relative_name(name)

    def evidence(self, data, checkpoint, directory):
        values = data.get("evidence_sha256")
        require(isinstance(values, dict) and values, "manifest evidence inventory missing")
        paths = set()
        for name, expected in values.items():
            path = self.mapped(name, checkpoint, directory)
            self.verified(path, expected)
            paths.add(path)
        return paths

    def steps(self, data, expected_names, checkpoint, directory):
        steps = data.get("steps")
        require(isinstance(steps, list) and all(isinstance(s, dict) for s in steps), "step records malformed")
        names = [s.get("name") for s in steps]
        require(len(names) == len(set(names)), "step identity reused")
        if isinstance(expected_names, tuple):
            require(names == list(expected_names), "required ordered step set differs")
        else:
            require(expected_names <= set(names), "required review step missing")
            require(all(n in expected_names or isinstance(n, str) and n.startswith("operations-") for n in names),
                    "unexpected review command scope")
        logs = set()
        for step in steps:
            require(type(step.get("returncode")) is int and step["returncode"] == 0, "required check failed")
            path = directory + "/" + step["name"] + ".log"
            if "log" in step:
                require(self.mapped(step["log"], checkpoint) == path, "step log path differs")
            self.verified(path, hash_value(step.get("log_sha256")))
            logs.add(path)
        return steps, logs

    def check(self, name, action):
        try:
            details = action()
            self.checks.append(dict(name=name, passed=True, details=details))
        except Exception as error:
            self.errors.append(dict(name=name, error=f"{type(error).__name__}: {error}"))
            self.checks.append(dict(name=name, passed=False))

    def baseline(self, checkpoint):
        old = self.read(BASELINE, BASELINE_SHA256)
        require(old.get("schema") == "a15-project-repair-local-audit-v1" and old.get("passed") is True,
                "historical baseline acceptance differs")
        no_timing(old)
        previous = hash_map(old.get("evidence_sha256"))
        preserved, changed = 0, {}
        for name, expected in previous.items():
            path = self.local(name)
            source = (path.suffix in {".py", ".c", ".h", ".cu", ".cuh", ".cpp"} or path.name == "Makefile")
            historical = name.startswith(("build/", "validation/", "report-data/"))
            observed = digest(path)
            if historical or source:
                if observed != expected:
                    require(not historical and name in ALLOWED_SOURCE_CHANGES, "unexpected baseline byte change: " + name)
                    changed[name] = dict(baseline=expected, current=observed)
                else:
                    preserved += 1
                    self.baseline_preserved.add(name)
                self.records[name] = observed
        require("c/src/sm3_cuda.cu" in changed, "expected cleanup wrapper delta missing")
        archive = self.verified(BASE_ARCHIVE, previous[BASE_ARCHIVE])
        with tarfile.open(archive, "r:gz") as tar:
            matches = [m for m in tar.getmembers() if m.name == "c/src/sm3_cuda.cu"]
            require(len(matches) == 1 and matches[0].isfile() and matches[0].size < 1048576, "historical CUDA archive member differs")
            stream = tar.extractfile(matches[0])
            require(stream is not None, "historical CUDA source missing")
            original = stream.read()
        require(hashlib.sha256(original).hexdigest() == previous["c/src/sm3_cuda.cu"], "historical CUDA archive source hash differs")
        current = self.local("c/src/sm3_cuda.cu").read_bytes()
        require(cuda_math_suffix(original) == cuda_math_suffix(current), "CUDA kernel/operation bytes changed beyond cleanup wrapper")
        prefix = current[:current.index(b"struct kernel_clock {")]
        require(b'#include "cuda_cleanup.h"' in prefix and b"cleanup_poisoned" in prefix
                and b"a15_cuda_buffer_owner<cuda_cleanup_driver>" in prefix, "cleanup wrapper delta missing expected owner policy")
        cpu = self.read("build/repair-staging-20261004-r3/validation/cpu-full-repair-r3/summary.json")
        cuda = self.read("build/repair-staging-20261004-r3/validation/cuda-full-repair-r3/summary.json")
        require(cpu.get("passed") is True and cpu.get("planned_cases") == cpu.get("passed_planned") == 3471,
                "historical CPU full scope differs")
        require(cuda.get("passed") is True and cuda.get("planned_cases") == cuda.get("passed_planned") == 1789,
                "historical CUDA full scope differs")
        return dict(preserved_files=preserved, allowed_changed_sources=changed,
                    historical_full=dict(cpu=3471, cuda=1789, classified="historical unchanged bytes"),
                    current_full_matrix_reexecuted=False, cuda_operation_suffix_sha256=hashlib.sha256(cuda_math_suffix(current)).hexdigest())

    def review(self, name, checkpoint):
        data = self.read(name)
        require(data.get("schema") == "a15-friend-repair-checks-v1" and data.get("passed") is True
                and data.get("error") is None and data.get("sources_unchanged") is True, "review runner acceptance differs")
        no_timing(data)
        self.current_sources(data, "sources_sha256")
        require(data.get("native_library_unchanged") is True, "review native library currentness missing")
        library_name = data.get("native_library_path")
        require(isinstance(library_name, str), "review native library identity missing")
        self.verified(library_name, hash_value(data.get("native_library_sha256")))
        baseline = self.read(BASELINE, BASELINE_SHA256)
        require(data["native_library_sha256"] == baseline["evidence_sha256"][BASE_CPU_LIBRARY],
                "fresh CPU release bytes differ from historical mathematical build")
        self.verified(BASE_CPU_LIBRARY, data["native_library_sha256"])
        directory = str(PurePosixPath(name).parent)
        steps, logs = self.steps(data, REVIEW_STEPS, checkpoint, directory)
        fresh = next(s for s in steps if s["name"] == "fresh-native-cpu").get("command", [])
        sanitizer = next(s for s in steps if s["name"] == "native-sanitizers").get("command", [])
        require("make" in fresh and all(target in fresh for target in ("all", "fault-test", "guard-test", "cuda-cleanup-host-test")),
                "fresh CPU build did not execute required fault/cleanup gates")
        require("make" in sanitizer and "sanitizer" in sanitizer, "CPU sanitizers not executed")
        evidence = self.evidence(data, checkpoint, directory)
        require(logs <= evidence, "review step logs missing from closure")
        tls = next(s for s in steps if s["name"] == "tls-full")["command"]
        deselected = (isinstance(tls, list) and any(v == "--deselect=tests/test_wots_xmss.py::test_default_height_performance_budget" for v in tls))
        filtered = (isinstance(tls, list) and "-k" in tls and tls.index("-k") + 1 < len(tls) and
                    "not test_default_height_performance_budget" in tls[tls.index("-k") + 1])
        require(deselected or filtered, "review TLS command includes optional performance test")
        commands = [s.get("command") for s in steps]
        require(all(isinstance(c, list) and "worker" not in c and not any("--worker-case" == v for v in c) for c in commands),
                "review commands contain performance worker")
        report_path = directory + "/bench-resume.json"
        require(report_path in evidence, "B01/B02 dedicated report absent from review closure")
        report = self.read(report_path)
        require(report.get("schema") == "a15-bench-resume-repair-tests-v1" and report.get("passed") is True
                and type(report.get("checks")) is int and report["checks"] >= 34
                and report.get("native_loads") == report.get("cryptographic_operations") == report.get("formal_performance_samples") == 0,
                "B01/B02 dedicated regression report incomplete")
        self.current_sources(report, "source_sha256")
        for filename in ("cpu-mock.json", "cuda-mock.json", "freeze-mock.json", "fuzz-smoke.json", "digest-matrix.json", "native-fuzz.json"):
            child_name = directory + "/" + filename
            require(child_name in evidence, "required report missing: " + filename)
            child = self.read(child_name)
            require(child.get("passed") is True and type(child.get("real_timing_samples")) is int
                    and child["real_timing_samples"] == 0, "review child report failed or timed")
            if filename in ("digest-matrix.json", "native-fuzz.json"):
                require(child.get("library_sha256") == data["native_library_sha256"], "native regression library differs from review build")
            for field in ("source_sha256", "tool_sha256"):
                if isinstance(child.get(field), dict):
                    self.current_sources(child, field)
        return dict(steps=len(steps), evidence_files=len(evidence), dedicated_resume_checks=report["checks"],
                    cpu_release_byte_identical_to_historical=True, cpu_release_sha256=data["native_library_sha256"],
                    inherited_scope="CPU native mathematical bytes; Python adapter/ledger/benchmark wrapper matrix not rerun")

    def native(self, name, checkpoint):
        data = self.read(name)
        require(data.get("schema") == "a15-cuda-native-v1" and data.get("passed") is True
                and data.get("source_unchanged") is True and data.get("error") is None, "new CUDA native acceptance differs")
        no_timing(data)
        require(data.get("measured_durations") is False, "CUDA timing lifecycle missing")
        source = self.current_sources(data, "source_hashes")
        require({"c/src/cuda_cleanup.h", "c/src/sm3_cuda.cu", "c/tests/test_cuda_cleanup_host.cpp", "tools/run_cuda_native.py"} <= set(source),
                "new cleanup/native sources absent")
        directory = str(PurePosixPath(name).parent)
        steps, logs = self.steps(data, CUDA_STEPS, checkpoint, directory)
        evidence = self.evidence(data, checkpoint, directory)
        require(logs <= evidence, "CUDA logs missing from evidence closure")
        builds = data.get("build_sha256")
        require(isinstance(builds, dict) and builds, "new CUDA build inventory missing")
        build_paths = set()
        for path, expected in builds.items():
            local = self.mapped(path, checkpoint)
            self.verified(local, expected)
            build_paths.add(local)
        remote = checkpoint.get("remote_root", "/home/guest-experiment/pqc-a1-5").rstrip("/")
        build_base = self.mapped(remote + "/build/" + PurePosixPath(directory).name, checkpoint)
        require({build_base + "/" + variant + "/libslhdsa_sm3.so" for variant in ("release", "counters", "disabled")} <= build_paths,
                "new CUDA library variants missing")
        require({build_base + "/release/test_cuda_fault_" + str(i) for i in range(6)} <= build_paths,
                "new CUDA fault executables missing")
        require(build_base + "/release/test_cuda_cleanup_host" in build_paths, "cleanup fake-driver executable missing")
        release = steps[0].get("argv", [])
        require("cuda-cleanup-host-test" in release and "cuda-fault-test" in release and "guard-test" in release,
                "new cleanup/fault/guard checks not executed")
        scope = data.get("cleanup_fault_scope")
        require(isinstance(scope, dict) and scope.get("real_gpu_driver_faults_injected") is False,
                "fake driver faults must not be claimed as real GPU failure injection")
        text = self.local(directory + "/release-kernels-faults-guards.log").read_text(encoding="utf-8", errors="replace")
        require(re.search(r"CUDA cleanup host fake-driver: [1-9][0-9]* policy cases PASS", text), "cleanup host policy PASS absent")
        require("native guard compiler checks PASS" in text and
                "fault point 0: 32 control signing calls" in text and
                all(f"fault point {point}: 32 signing calls" in text for point in range(1, 6)),
                "CUDA native fault/guard logs do not establish expected scope")
        for logname in ("hidden-device-dispatch.log", "disabled-build-dispatch.log"):
            log_text = self.local(directory + "/" + logname).read_text(encoding="utf-8", errors="replace")
            rows = [json.loads(line, object_pairs_hook=unique_object) for line in log_text.splitlines() if line.startswith('{"')]
            require(len(rows) == 1 and rows[0].get("passed") is True and rows[0].get("cuda_available") is False
                    and rows[0].get("timed") is False, "CUDA absence guard log differs")
        require(steps[3].get("hidden_device") is True, "hidden-device execution metadata missing")
        kernel_name = directory + "/kernel.json"
        require(kernel_name in evidence, "new CUDA kernel report absent")
        kernel = self.read(kernel_name)
        no_timing(kernel)
        require(kernel.get("schema") == "a15-cuda-kernel-v1" and kernel.get("passed") is True
                and kernel.get("actual_selected_backend") == 5, "new CUDA backend5 execution missing")
        self.current_sources(kernel, "source_hashes")
        stats = kernel.get("gpu_stats")
        require(isinstance(stats, dict) and stats.get("kernel_ns") == stats.get("timing_enabled") == 0
                and stats.get("kernel_launches", 0) > 0 and stats.get("device_hashes", 0) > 0, "new CUDA untimed work stats differ")
        require(kernel.get("log_sha256") == digest(self.local(directory + "/counter-kernels.log")), "new CUDA kernel log hash differs")
        require(kernel.get("library_sha256") == digest(self.local(build_base + "/counters/libslhdsa_sm3.so"))
                and kernel.get("executable_sha256") == digest(self.local(build_base + "/counters/test_cuda")), "CUDA kernel build linkage differs")
        cases = kernel.get("cases")
        require(isinstance(cases, list) and len(cases) == 4 and all(c.get("passed") is True and c.get("timed") is False for c in cases),
                "new CUDA kernel case scope differs")
        require([(c.get("case"), c.get("comparisons")) for c in cases[:-1]] ==
                [("gpu-sm3", 7294), ("gpu-fors-subtrees-and-hybrid-wots", 148),
                 ("gpu-full-signatures-cache-randomized-inputs-and-guards", 12)], "CUDA native comparison coverage differs")
        return dict(steps=5, backend=5, timing_enabled=False, cleanup_fault_driver="host fake driver", new_full_matrix=False)

    def functional(self, name, checkpoint):
        data = self.read(name)
        require(data.get("schema") == "a15-project-functional-v1" and data.get("passed") is True
                and data.get("error") is None and data.get("source_unchanged") is True
                and data.get("library_unchanged") is True, "new functional acceptance differs")
        no_timing(data)
        self.current_sources(data, "source_sha256")
        review = self.read(checkpoint["review_checks"])
        require(data.get("library_sha256") == review.get("native_library_sha256"),
                "functional and review evidence use different native libraries")
        directory = str(PurePosixPath(name).parent)
        _steps, logs = self.steps(data, FUNCTIONAL_STEPS, checkpoint, directory)
        tls_command = next(s for s in _steps if s["name"] == "tls-pytest").get("command", [])
        require("--deselect=tests/test_wots_xmss.py::test_default_height_performance_budget" in tls_command,
                "functional TLS command includes optional performance test")
        evidence = self.evidence(data, checkpoint, directory)
        require(logs <= evidence, "functional logs missing from closure")
        ca_name = directory + "/ca-verification.json"
        sizes_name = directory + "/p0-p4-size-functional.jsonl"
        require(ca_name in evidence and sizes_name in evidence, "CA dual verification/E1 artifacts missing")
        ca = self.read(ca_name)
        require(ca.get("passed") is True, "real CA dual verification failed")
        self.current_sources(ca, "sources_sha256")
        rows = ca.get("rows")
        expected_ca = {(algorithm, verifier) for algorithm in ("slh-dsa-sm3-128-24", "slh-dsa-sm3-128s") for verifier in ("native", "python")} | {("ml-dsa-44", "provider")}
        require(isinstance(rows, list) and len(rows) == 5 and {(r.get("algorithm"), r.get("verifier")) for r in rows} == expected_ca,
                "CA independent verifier scope differs")
        edges = {}
        for row in rows:
            require(row.get("passed") is True and type(row.get("checked_edges")) is int and row["checked_edges"] == 2,
                    "CA row did not verify both edges")
            verifiers = row.get("verifiers")
            require(isinstance(verifiers, list) and len(verifiers) == 2 and {v.get("edge") for v in verifiers} == {0, 1},
                    "CA verifier edge evidence missing")
            for verifier in verifiers:
                require(verifier.get("passed") is True and verifier.get("mode") == row["verifier"], "CA verifier mode/status differs")
                binding = tuple(hash_value(verifier.get(k)) for k in ("message_sha256", "public_key_sha256", "signature_sha256"))
                pair = row["algorithm"], verifier["edge"]
                require(pair not in edges or edges[pair] == binding, "CA independent verifiers did not consume identical bytes")
                edges[pair] = binding
                if row["verifier"] == "native":
                    library = self.mapped(verifier.get("library_path", ""), checkpoint)
                    self.verified(library, verifier.get("library_sha256"))
                    require(verifier.get("library_sha256") == data.get("library_sha256"), "CA native library differs from functional build")
        sizes = [json.loads(line, object_pairs_hook=unique_object) for line in self.local(sizes_name).read_text(encoding="utf-8").splitlines() if line.strip()]
        require(len(sizes) == 5 and {r.get("profile") for r in sizes} == {"P0", "P1", "P2", "P3", "P4"}, "E1 P0/P4 functional scope incomplete")
        for row in sizes:
            require(row.get("schema") == "a15-E1-v2" and row.get("passed") is True and row.get("tcp_ip_bytes") is None,
                    "E1 profile status or unmeasured network boundary differs")
            require(not any(row.get(k) is not None for k in ("duration_ns", "latency_ns", "throughput")), "E1 contains performance samples")
            self.current_sources(row, "sources_sha256")
            messages = row.get("per_message")
            # E1 emits one entry per record fragment. Long Certificates can
            # occupy multiple adjacent entries, while remaining one message.
            e1_messages(messages)
            for field, per_field in (("handshake_message_bytes", "plaintext_bytes"), ("harness_record_bytes", "harness_record_bytes"),
                                     ("harness_tcp_framed_bytes_model", "harness_tcp_framed_bytes_model"),
                                     ("standard_tls_record_bytes_model", "standard_tls_record_bytes_model")):
                require(all(type(m.get(per_field)) is int and m[per_field] > 0 for m in messages) and
                        row.get(field) == sum(m[per_field] for m in messages), "E1 serialized byte sum differs")
        require(any(self.local(name).name == "p0-p4-serialized-functional.log" for name in evidence), "E1 functional log missing")
        return dict(steps=11, scope="current CA/TLS and serialized size functionality", performance=False)

    def environment(self, name, checkpoint):
        data = self.read(name)
        require(data.get("schema") == "a15-friend-environment-v1" and data.get("passed") is True, "new environment acceptance differs")
        no_timing(data)
        directory = str(PurePosixPath(name).parent)
        evidence = self.evidence(data, checkpoint, directory)
        require(isinstance(data.get("checks"), dict) and all(data["checks"].get(k) is True for k in
                ("container_build", "container_run", "falcon_provider", "sanitizers",
                 "final_sources_match", "final_review_sources_match")), "environment build/run/provider/source gates missing")
        sources = self.current_sources(data, "sources_sha256")
        require(sources == checkpoint.get("source_sha256"), "environment source inventory differs from checkpoint")
        final = data.get("final_review_manifest")
        require(isinstance(final, dict) and self.mapped(final.get("path", ""), checkpoint) == checkpoint["review_checks"],
                "environment final review identity differs")
        host = self.read(checkpoint["review_checks"], hash_value(final.get("sha256")))
        require(host.get("sources_sha256") == sources, "environment and current review sources differ")
        container_name = directory + "/container-review/manifest.json"
        require(container_name in evidence, "container review manifest absent from environment closure")
        container = self.read(container_name)
        require(container.get("schema") == "a15-friend-repair-checks-v1" and container.get("passed") is True
                and container.get("error") is None and container.get("sources_unchanged") is True
                and container.get("native_library_unchanged") is True,
                "container review acceptance differs")
        no_timing(container)
        require(container.get("sources_sha256") == sources, "container review sources differ from current sources")
        _steps, logs = self.steps(container, REVIEW_STEPS, checkpoint, directory + "/container-review")
        require(logs <= evidence, "container review step logs absent from environment closure")
        require(data.get("sanitizer_scope") == "container", "environment sanitizer gate is not in the container")
        require(data.get("base_image_index_digest") == "sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed",
                "container immutable base identity differs")
        identity = data.get("image_identity")
        require(isinstance(identity, dict) and isinstance(identity.get("runtime_image_id"), str)
                and re.fullmatch(r"sha256:[0-9a-f]{64}", identity["runtime_image_id"])
                and identity["runtime_image_id"] == identity.get("container_image_id")
                and identity.get("locked_base_image_id") == "sha256:dd23478b05784908485d6f06855b95297a407e29df69e6799da55408bca31a53",
                "container/base runtime image identity differs")
        return dict(verified_evidence_files=len(evidence), source_files=len(sources),
                    container_steps=len(_steps), scope="new CPU environment; historical CUDA dependencies retain original bytes")

    def audit(self, checkpoint_name):
        checkpoint = self.read(checkpoint_name)
        require(checkpoint.get("schema") == "a15-friend-repair-checkpoint-v1" and checkpoint.get("scope") == "engineering-delta",
                "checkpoint schema or delta scope differs")
        no_timing(checkpoint)
        require(checkpoint.get("performance_authorized") is False and checkpoint.get("current_full_matrix_reexecuted") is False,
                "delta checkpoint must not claim new full matrices or a timing permit")
        require(checkpoint.get("baseline_sha256") == BASELINE_SHA256, "historical baseline anchor differs")
        inventory = hash_map(checkpoint.get("evidence_sha256"))
        current = hash_map(checkpoint.get("source_sha256"))
        require(REQUIRED_SOURCES <= set(current), "current source/check-runner dependency closure incomplete")
        require(all(n not in current or current[n] == h for n, h in inventory.items()), "source/evidence inventories disagree")
        self.check("current-inventory", lambda: (self.inventory(inventory), self.inventory(current), dict(files=len(inventory), sources=len(current)))[2])
        self.check("historical-bytes-and-math-delta", lambda: self.baseline(checkpoint))
        for field, action in (("review_checks", self.review), ("cuda_native", self.native),
                              ("functional", self.functional), ("environment", self.environment)):
            name = checkpoint.get(field)
            require(isinstance(name, str) and name in inventory, "required input absent from checkpoint inventory: " + field)
            self.check(field, lambda name=name, action=action: action(name, checkpoint))
        # The inventory is a byte closure: every input transitively consumed by
        # new acceptance must also be listed explicitly in the checkpoint.
        new_records = {n: h for n, h in self.records.items() if n != checkpoint_name and n not in self.baseline_preserved}
        self.check("new-evidence-closure", lambda: require(all(n in inventory or n in current or n == BASELINE for n in new_records),
                                                          "new audit inputs omitted from explicit byte closure"))
        self.check("inputs-remain-unchanged", lambda: require(all(digest(self.local(n)) == h for n, h in self.records.items()),
                                                             "audit input changed while being checked"))
        return dict(schema="a15-friend-repair-audit-v1", passed=not self.errors, checks=self.checks,
                    errors=self.errors, created_utc=datetime.now(timezone.utc).isoformat(),
                    evidence_sha256=self.records, baseline_sha256=BASELINE_SHA256,
                    scope="engineering-delta", current_full_matrix_reexecuted=False,
                    performance_authorized=False, formal_performance_started=False, real_timing_samples=0,
                    native_calls=0, old_freeze_mismatch_is_expected=True,
                    checkpoint_sha256=self.records[checkpoint_name],
                    graph=dict(baseline="historical r3 CPU3471/CUDA1789 unchanged",
                               delta="current functionality/mocks/native cleanup evidence",
                               permit="none"))


def self_test():
    class PollutionTests(unittest.TestCase):
        def test_e1_long_certificate_and_corrupt_order(self):
            names = [("client", "ClientHello"), ("server", "ServerHello"),
                ("server", "EncryptedExtensions"), ("server", "Certificate"),
                ("server", "CertificateVerify"), ("server", "Finished"), ("client", "Finished")]
            short = [dict(sender=sender, name=name) for sender, name in names]
            e1_messages(short)
            e1_messages(short[:4] + [short[3]] * 3 + short[4:])
            for rows in (short[:-1], short[:2] + [short[1]] + short[2:],
                         short[:3] + short[4:] + short[3:4], short + [short[-1]]):
                with self.assertRaises(ValueError):
                    e1_messages(rows)
        def test_timing_and_permit_fields_fail_closed(self):
            good = dict(formal_performance_started=False, real_timing_samples=0, performance_authorized=False)
            no_timing(good)
            for key, value in (("real_timing_samples", False), ("real_timing_samples", "0"),
                               ("real_timing_samples", 1), ("formal_performance_started", None),
                               ("formal_performance_started", True), ("performance_authorized", True),
                               ("measured_durations", True)):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    no_timing({**good, key: value})
        def test_paths_and_duplicate_json_fail_closed(self):
            for path in ("../file", "/absolute", "a/../b", "C:/x", "a\\b", "a/./b", ""):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    relative_name(path)
            with self.assertRaises(ValueError):
                json.loads('{"passed":true,"passed":false}', object_pairs_hook=unique_object)
        def test_hash_failure_and_missing_file(self):
            with tempfile.TemporaryDirectory(prefix="a15-audit-check-") as folder:
                root = Path(folder); (root / "evidence").write_bytes(b"old")
                auditor = Auditor(root)
                auditor.verified("evidence", hashlib.sha256(b"old").hexdigest())
                (root / "evidence").write_bytes(b"new")
                with self.assertRaises(ValueError):
                    auditor.verified("evidence", hashlib.sha256(b"old").hexdigest())
                with self.assertRaises(ValueError):
                    auditor.verified("missing")
        def test_cuda_math_boundary_rejects_kernel_delta(self):
            old = b"old cleanup\nstruct kernel_clock { preserved kernel }"
            new = b"new cleanup\nstruct kernel_clock { preserved kernel }"
            self.assertEqual(cuda_math_suffix(old), cuda_math_suffix(new))
            self.assertNotEqual(cuda_math_suffix(old), cuda_math_suffix(new.replace(b"preserved kernel", b"changed kernel")))
            with self.assertRaises(ValueError):
                cuda_math_suffix(b"missing marker")
        def test_step_failure_and_missing_hash(self):
            with tempfile.TemporaryDirectory(prefix="a15-audit-step-") as folder:
                root = Path(folder); (root / "d").mkdir(); (root / "d/gate.log").write_bytes(b"PASS")
                auditor = Auditor(root)
                row = dict(name="gate", returncode=0, log_sha256=hashlib.sha256(b"PASS").hexdigest())
                auditor.steps(dict(steps=[row]), ("gate",), {}, "d")
                for value in (1, False, "0"):
                    with self.assertRaises(ValueError):
                        auditor.steps(dict(steps=[{**row, "returncode": value}]), ("gate",), {}, "d")
                with self.assertRaises(ValueError):
                    auditor.steps(dict(steps=[{**row, "log_sha256": "0"*64}]), ("gate",), {}, "d")
                with self.assertRaises(ValueError):
                    auditor.steps(dict(steps=[{**row, "log_sha256": None}]), ("gate",), {}, "d")
        def test_environment_rejects_stale_source_and_failed_container(self):
            import copy
            with tempfile.TemporaryDirectory(prefix="a15-audit-env-") as folder:
                root = Path(folder)
                (root / "d/container-review").mkdir(parents=True)
                (root / "current.py").write_bytes(b"current")
                sources = {"current.py": digest(root / "current.py")}
                def write(name, value):
                    (root / name).write_text(json.dumps(value), encoding="utf8")
                write("host.json", dict(sources_sha256=sources))
                steps = []
                evidence = {}
                for name in sorted(REVIEW_STEPS):
                    log = "d/container-review/" + name + ".log"
                    (root / log).write_bytes(b"PASS")
                    evidence[log] = digest(root / log)
                    steps.append(dict(name=name, returncode=0, log_sha256=evidence[log]))
                container = dict(schema="a15-friend-repair-checks-v1", passed=True, error=None,
                    sources_unchanged=True, native_library_unchanged=True, sources_sha256=sources,
                    formal_performance_started=False, real_timing_samples=0, steps=steps)
                child_name = "d/container-review/manifest.json"
                write(child_name, container)
                evidence[child_name] = digest(root / child_name)
                environment = dict(schema="a15-friend-environment-v1", passed=True,
                    formal_performance_started=False, real_timing_samples=0, sources_sha256=sources,
                    checks={k: True for k in ("container_build", "container_run", "falcon_provider",
                        "sanitizers", "final_sources_match", "final_review_sources_match")},
                    final_review_manifest=dict(path="host.json", sha256=digest(root / "host.json")),
                    sanitizer_scope="container", evidence_sha256=evidence,
                    base_image_index_digest="sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed",
                    image_identity=dict(runtime_image_id="sha256:" + "1"*64, container_image_id="sha256:" + "1"*64,
                        locked_base_image_id="sha256:dd23478b05784908485d6f06855b95297a407e29df69e6799da55408bca31a53"))
                checkpoint = dict(source_sha256=sources, review_checks="host.json")
                write("d/environment.json", environment)
                Auditor(root).environment("d/environment.json", checkpoint)
                for field, value in (("sources_sha256", {"current.py": "0"*64}),
                                      ("sanitizer_scope", "separate host")):
                    bad = copy.deepcopy(environment); bad[field] = value
                    write("d/environment.json", bad)
                    with self.subTest(field=field), self.assertRaises(ValueError):
                        Auditor(root).environment("d/environment.json", checkpoint)
                bad = copy.deepcopy(environment); bad["checks"]["final_review_sources_match"] = False
                write("d/environment.json", bad)
                with self.assertRaises(ValueError):
                    Auditor(root).environment("d/environment.json", checkpoint)
                for field, value in (("sources_sha256", {"current.py": "0"*64}), ("passed", False)):
                    bad_child = copy.deepcopy(container); bad_child[field] = value
                    write(child_name, bad_child)
                    bad = copy.deepcopy(environment); bad["evidence_sha256"][child_name] = digest(root / child_name)
                    write("d/environment.json", bad)
                    with self.subTest(field=field), self.assertRaises(ValueError):
                        Auditor(root).environment("d/environment.json", checkpoint)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(PollutionTests))
    return int(not result.wasSuccessful())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if not args.checkpoint:
        parser.error("--checkpoint is required")
    auditor = Auditor()
    try:
        checkpoint_name = args.checkpoint.resolve().relative_to(ROOT).as_posix()
        report = auditor.audit(checkpoint_name)
    except Exception as error:
        report = dict(schema="a15-friend-repair-audit-v1", passed=False,
                      errors=[dict(name="checkpoint", error=f"{type(error).__name__}: {error}")],
                      performance_authorized=False, formal_performance_started=False, real_timing_samples=0, native_calls=0)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
    print(json.dumps({k: report[k] for k in ("passed", "performance_authorized", "real_timing_samples")}, ensure_ascii=False))
    if not report["passed"]:
        print(json.dumps(report.get("errors"), ensure_ascii=False))
    return int(not report["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
