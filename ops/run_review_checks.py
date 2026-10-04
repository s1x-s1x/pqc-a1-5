"""Repeatable review regression gates. Never invoke a performance worker."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes():
    result = {p.relative_to(ROOT).as_posix(): sha(p)
            for folder in ("tools", "ops", "base_tls/tls", "base_tls/tests", "base_tls/tools",
                           "c", "reference", "third_party/slhdsa-c", "third_party/py-acvp-pqc")
            for p in sorted((ROOT / folder).rglob("*"))
            if p.is_file() and (p.suffix in {".py", ".c", ".h", ".cu", ".cuh", ".cpp"}
                                or p.name == "Makefile")}
    for name in ("base_tls/requirements.lock.txt", "base_tls/requirements-falcon.lock.txt",
                 "reference/requirements.lock.txt", "ops/repro/Dockerfile",
                 ".dockerignore", ".github/workflows/correctness.yml"):
        result[name] = sha(ROOT / name)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    native = parser.add_mutually_exclusive_group()
    native.add_argument("--native-library", type=Path)
    native.add_argument("--fresh-native-build", type=Path, help="fresh CPU build directory; includes fault checks and sanitizers")
    args = parser.parse_args()
    if args.native_library:
        args.native_library = args.native_library.resolve()
        if not args.native_library.is_relative_to(ROOT) or not args.native_library.is_file():
            parser.error("native library must be an existing file inside the project")
    if args.fresh_native_build:
        args.fresh_native_build = args.fresh_native_build.resolve()
        if not args.fresh_native_build.is_relative_to(ROOT / "build") or args.fresh_native_build.exists():
            parser.error("choose a fresh native directory inside build")
        args.native_library = args.fresh_native_build / "libslhdsa_sm3.so"
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    before = source_hashes()
    py = sys.executable
    commands = [
        ("native-adapter", [py, "-B", "tools/test_native_boundaries.py"], ROOT),
        ("budget", [py, "-B", "tools/test_budget_repair.py"], ROOT),
        ("review-matrix", [py, "-B", "-m", "unittest", "discover", "-s", "tools", "-p", "test_friend_*.py"], ROOT),
        ("bench-resume", [py, "-B", "tools/test_bench_resume_repair.py", "--output", str(output / "bench-resume.json")], ROOT),
        ("cpu-mock", [py, "-B", "tools/bench_cpu.py", "self-test", "--output", str(output / "cpu-mock.json")], ROOT),
        ("cuda-mock", [py, "-B", "tools/bench_cuda.py", "self-test", "--output", str(output / "cuda-mock.json")], ROOT),
        ("freeze-mock", [py, "-B", "tools/freeze_cuda.py", "--self-test", "--self-test-output", str(output / "freeze-mock.json")], ROOT),
        ("tls-full", [py, "-B", "-m", "pytest", "tests", "-q", "-ra", "--deselect=tests/test_wots_xmss.py::test_default_height_performance_budget"], ROOT / "base_tls"),
        ("tls-live", [py, "-B", "tools/audit_live_checks.py"], ROOT / "base_tls"),
        ("dependency-lock", [py, "-B", "tools/verify_dependency_lock.py"], ROOT / "base_tls"),
        ("native-source-guards", [py, "-B", "tools/check_native_guards.py", "--source-only"], ROOT),
        ("parser-fuzz-smoke", [py, "-B", "tools/fuzz_inputs.py", "--iterations", "1000", "--output", str(output / "fuzz-smoke.json")], ROOT),
    ]
    # Some historical synthetic gates are standalone argparse programs, rather
    # than importable unittest suites. Invoke their supported entry points.
    commands[6:6] = [("operations-" + path.stem, [py, "-B", str(path)], ROOT)
                     for path in sorted((ROOT / "ops").glob("test_*.py"))]
    if args.fresh_native_build:
        relative = "../" + args.fresh_native_build.relative_to(ROOT).as_posix()
        commands[0:0] = [
            ("fresh-native-cpu", ["make", "CC=gcc", "CFLAGS=-O3", "CUDA=0", "OUT=" + relative,
                "all", "test", "review-test", "repair-test", "avx2-test", "wots-test", "prehash-test",
                "fault-test", "guard-test", "cuda-cleanup-host-test"], ROOT / "c"),
            ("native-sanitizers", ["make", "CC=gcc", "CUDA=0", "OUT=" + relative + "-sanitizers", "sanitizer"], ROOT / "c"),
        ]
    if args.native_library:
        commands += [
            ("native-prehash", [py, "-B", "tools/test_native_digest_matrix.py", "--library", str(args.native_library.resolve()), "--output", str(output / "digest-matrix.json")], ROOT),
            ("native-cache-fuzz", [py, "-B", "tools/fuzz_inputs.py", "--iterations", "1000", "--library", str(args.native_library.resolve()), "--output", str(output / "native-fuzz.json")], ROOT),
        ]
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    if args.native_library:
        env.update(A15_NATIVE_LIBRARY=str(args.native_library.resolve()), SLHDSA_SM3_LIB=str(args.native_library.resolve()))
    manifest = dict(schema="a15-friend-repair-checks-v1", started_utc=datetime.now(timezone.utc).isoformat(),
                    sources_sha256=before, steps=[], formal_performance_started=False, real_timing_samples=0,
                    native_library_sha256=(sha(args.native_library.resolve())
                        if args.native_library and args.native_library.is_file() else None))
    accepted_library_digest = manifest["native_library_sha256"]
    error = None
    try:
        for name, command, cwd in commands:
            print(json.dumps({"phase": name}), flush=True)
            log = output / (name + ".log")
            with log.open("xb") as stream:
                process = subprocess.Popen(command, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT,
                    start_new_session=os.name == "posix")
                timed_out = False
                try:
                    code = process.wait(timeout=1800)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    if os.name == "posix":
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    else:
                        process.kill()
                    process.wait()
                    code = 124
                    stream.write(b"\nReview check exceeded timeout; process group terminated.\n")
            manifest["steps"].append(dict(name=name, command=command, returncode=code,
                                         timed_out=timed_out, log_sha256=sha(log)))
            if code:
                print(log.read_text(encoding="utf-8", errors="replace")[-6000:])
                raise ValueError("Review check failed: " + name)
            if name == "fresh-native-cpu":
                accepted_library_digest = sha(args.native_library.resolve())
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    manifest.update(error=error, sources_unchanged=before == source_hashes(), completed_utc=datetime.now(timezone.utc).isoformat())
    if args.native_library and args.native_library.is_file():
        manifest["native_library_sha256"] = sha(args.native_library.resolve())
        manifest["native_library_path"] = args.native_library.resolve().relative_to(ROOT).as_posix()
    manifest["native_library_unchanged"] = (not args.native_library or
        accepted_library_digest is not None and accepted_library_digest == manifest["native_library_sha256"])
    manifest["passed"] = error is None and manifest["sources_unchanged"] and manifest["native_library_unchanged"]
    manifest["evidence_sha256"] = {p.name: sha(p) for p in sorted(output.iterdir()) if p.is_file()}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"passed": manifest["passed"], "steps": len(manifest["steps"]), "error": error, "real_timing_samples": 0}))
    return int(not manifest["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
