"""Freeze and validate native AVX2/prehash, portable fallback and file CLI."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def sources():
    files = []
    for folder in ("c", "third_party/slhdsa-c"):
        files.extend(p for p in (ROOT / folder).rglob("*")
                     if p.is_file() and p.suffix in {".c", ".h", ".cu", ".cuh"})
    files.extend(ROOT / name for name in (
        "c/Makefile", "tools/native.py", "tools/cli.py", "tools/signing_budget.py",
        "tools/check_cli_budget.py", "tools/check_native_guards.py", "tools/check_counts.py",
        "tools/count_model.py", "tools/recheck_external.py", "tools/external_vectors.py",
        "tools/run_native_stage2.py", "reference/differential.py", "reference/slhdsa.py",
        "reference/sm3.py", "third_party/py-acvp-pqc/fips205.py"))
    return {p.relative_to(ROOT).as_posix(): sha(p) for p in sorted(set(files))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=24)
    parser.add_argument("--threads", type=int, default=32)
    parser.add_argument("--cpus", type=int, nargs="+")
    args = parser.parse_args()
    out = args.run_dir.resolve()
    if not out.is_relative_to(ROOT / "validation"):
        parser.error("run-dir must be inside validation")
    build = ROOT / "build" / out.name
    if out.exists() or build.exists():
        parser.error("choose a fresh validation and build basename")
    out.mkdir(parents=True)
    os.sched_setaffinity(0, args.cpus or json.loads((ROOT / "validation/environment.json").read_text())["selected_physical_cpus"])
    env = dict(os.environ, OMP_DYNAMIC="FALSE", PYTHONUNBUFFERED="1",
               ASAN_OPTIONS="halt_on_error=1:abort_on_error=1:detect_leaks=1",
               UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
    before = sources()
    inputs = ["validation/environment.json", "validation/external-EVIDENCE.json",
              "reference/evidence/python-sm3-128-24.jsonl"]
    inputs += ["vectors/external-" + suite + "-inputs.jsonl" for suite in ("acvp", "xous", "gmsm")]
    manifest = {"schema": "a15-native-stage2-v1", "started_at_utc": datetime.now(timezone.utc).isoformat(),
                "acceptance_scope": "native AVX2/prehash/portable/CLI correctness; performance and new TLS pending",
                "source_sha256": before, "inputs_sha256": {p: sha(ROOT / p) for p in inputs},
                "compiler": subprocess.check_output(["gcc", "--version"], text=True).splitlines()[0],
                "affinity": sorted(os.sched_getaffinity(0)), "python": sys.version,
                "sanitizer_options": {p: env[p] for p in ("ASAN_OPTIONS", "UBSAN_OPTIONS")},
                "steps": [], "passed": False}
    def save():
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf8")
    def run(name, command, cwd=ROOT, timeout=1800):
        print(json.dumps({"phase": name, "command": command}), flush=True)
        log = out / (name + ".log")
        started = time.monotonic()
        with log.open("x", encoding="utf8") as stream:
            process = subprocess.Popen(command, cwd=cwd, env=env, stdout=stream,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                code = 124
        step = {"name": name, "command": command, "returncode": code,
                "cwd": str(cwd.relative_to(ROOT)), "diagnostic_seconds": time.monotonic() - started,
                "log": log.relative_to(ROOT).as_posix(), "log_sha256": sha(log)}
        manifest["steps"].append(step)
        save()
        print(json.dumps(step), flush=True)
        if code:
            print(log.read_text(encoding="utf8")[-6000:], flush=True)
            raise RuntimeError("stage failed: " + name)
    try:
        prefix = "../build/" + out.name + "/"
        common = ["all", "test", "review-test", "avx2-test", "wots-test", "prehash-test", "fault-test", "guard-test"]
        make = ["make", "CC=gcc", "CFLAGS=-O3"]
        run("avx2-build-and-tests", [*make, "OUT=" + prefix + "avx2", *common], ROOT / "c")
        run("counter-build-and-tests", [*make, "OUT=" + prefix + "counters", "COUNTERS=1",
            "all", "review-test", "avx2-test", "wots-test", "prehash-test"], ROOT / "c")
        run("portable-build-and-tests", [*make, "OUT=" + prefix + "portable", "AVX2=0", *common], ROOT / "c")
        run("sanitizer-tests", [*make, "OUT=" + prefix + "avx2", "SAN_OUT=" + prefix + "sanitizer", "sanitizer"], ROOT / "c")
        for backend in ("avx2", "portable"):
            library = build / backend / "libslhdsa_sm3.so"
            run("external-" + backend, [sys.executable, "tools/recheck_external.py", "--library", str(library),
                "--backend", "auto" if backend == "avx2" else "ref",
                "--output", str(out / ("external-" + backend + ".jsonl")), "--workers", str(args.workers),
                "--large-threads", str(args.threads)])
            summary = json.loads((out / ("external-" + backend + ".summary.json")).read_text())
            if (summary["total"] != 351 or summary["failed"] or summary["passed"] != 351
                    or summary["library_sha256"] != sha(library) or not summary["library_unchanged"]):
                raise ValueError("external acceptance mismatch: " + backend)
            expected_backends = {"1": 211, "2": 140} if backend == "avx2" else {"1": 351, "2": 0}
            if summary["selected_backend_counts"] != expected_backends:
                raise ValueError("external actual-backend acceptance mismatch: " + backend)
        library = build / "avx2/libslhdsa_sm3.so"
        run("complete-128-24", [sys.executable, "reference/differential.py", "--library", str(library),
            "--backend", "avx2",
            "--output", str(out / "complete-128-24.jsonl"), "--threads", str(args.threads), "complete",
            "--input", str(ROOT / "reference/evidence/python-sm3-128-24.jsonl")])
        summary = json.loads((out / "complete-128-24.summary.json").read_text())
        if (summary["total"] != 3 or summary["passed"] != 3 or summary["failed"]
                or not summary["native_library_unchanged"] or summary["native_library_sha256"] != sha(library)
                or summary["selected_backend_counts"] != {"2": 3}):
            raise ValueError("complete-128-24 acceptance mismatch")
        for suite in ("toy", "subtree"):
            run(suite + "-differential", [sys.executable, "reference/differential.py", "--library", str(library),
                "--backend", "auto", "--output", str(out / (suite + ".jsonl")),
                "--workers", str(min(args.workers, 8) if suite == "subtree" else args.workers),
                suite, "--count", "1000"])
            summary = json.loads((out / (suite + ".summary.json")).read_text())
            if (summary["total"] != 1000 or summary["passed"] != 1000 or summary["failed"]
                    or not summary["native_library_unchanged"] or summary["native_library_sha256"] != sha(library)):
                raise ValueError(suite + " acceptance mismatch")
            if suite == "toy" and summary["selected_backend_counts"] != {"2": 1000}:
                raise ValueError("toy actual-backend acceptance mismatch")
        run("exact-counts", [sys.executable, "tools/check_counts.py", "--library", str(build / "counters/libslhdsa_sm3.so"),
            "--output", str(out / "exact-counts.jsonl")])
        summary = json.loads((out / "exact-counts.summary.json").read_text())
        if summary["passed"] is not True or not summary["records"] or summary["error"]:
            raise ValueError("counter acceptance mismatch")
        run("cli-and-budget", [sys.executable, "tools/check_cli_budget.py", "--library", str(library),
            "--output", str(out / "cli-budget.json")])
        summary = json.loads((out / "cli-budget.json").read_text())
        if summary["failed"] or summary["passed"] != summary["total"] or summary["library_sha256"] != sha(library):
            raise ValueError("CLI acceptance mismatch")
        manifest["source_unchanged"] = before == sources()
        manifest["inputs_unchanged"] = all(sha(ROOT / name) == digest for name, digest in manifest["inputs_sha256"].items())
        manifest["build_sha256"] = {str(p.resolve()): sha(p) for p in sorted(build.rglob("*"))
                                     if p.is_file() and (p.suffix == ".so" or p.name.startswith("test_"))}
        manifest["passed"] = manifest["source_unchanged"] and manifest["inputs_unchanged"]
    except Exception as error:
        manifest["error"] = f"{type(error).__name__}: {error}"
    manifest["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
    manifest["evidence_sha256"] = {str(p.resolve()): sha(p) for p in sorted(out.iterdir())
                                  if p.is_file() and p.name != "manifest.json"}
    save()
    print(json.dumps({"run": str(out.relative_to(ROOT)), "passed": manifest["passed"], "error": manifest.get("error")}), flush=True)
    return int(not manifest["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
