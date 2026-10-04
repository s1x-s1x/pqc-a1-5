"""Run and freeze the scalar correctness review in an append-only directory."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources():
    files = []
    for folder in ("c", "tools", "reference"):
        files.extend(p for p in (ROOT / folder).rglob("*")
                     if p.is_file() and "__pycache__" not in p.parts and p.suffix in {".c", ".h", ".py"})
    files.extend(ROOT / p for p in ("c/Makefile", "SPEC.md", "docs/plans/manifest.json",
                                   "third_party/slhdsa-c/sha2_256.c", "third_party/slhdsa-c/sha2_api.h",
                                   "third_party/slhdsa-c/plat_local.h",
                                   "third_party/py-acvp-pqc/fips205.py"))
    return {p.relative_to(ROOT).as_posix(): sha(p) for p in sorted(set(files))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=24)
    parser.add_argument("--threads", type=int, default=32)
    args = parser.parse_args()
    out = args.run_dir.resolve()
    if not out.is_relative_to(ROOT / "validation"):
        parser.error("run-dir must be inside validation")
    build = ROOT / "build" / out.name
    if build.exists():
        parser.error("build directory exists; choose a fresh run-dir basename")
    out.mkdir(parents=True, exist_ok=False)
    build_rel = Path("../build") / out.name
    env = dict(os.environ, OMP_DYNAMIC="FALSE", PYTHONUNBUFFERED="1",
               UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1",
               ASAN_OPTIONS="halt_on_error=1:detect_leaks=1")
    observed = json.loads((ROOT / "validation/environment.json").read_text(encoding="utf8"))
    cpus = observed.get("selected_physical_cpus", [])
    if cpus:
        os.sched_setaffinity(0, cpus)
    source_before = sources()
    manifest = {"schema": "a15-stage1-run-v1", "started_at_utc": datetime.now(timezone.utc).isoformat(),
                "review_boundary": "scalar correctness; final performance and SIMD/CUDA/TLS integration follow user review",
                "source_sha256": source_before, "platform": platform.platform(), "python": sys.version,
                "affinity": sorted(os.sched_getaffinity(0)), "steps": [], "passed": False}
    reference_input = ROOT / "reference/evidence/python-sm3-128-24.jsonl"
    input_paths = [reference_input, ROOT / "validation/environment.json", ROOT / "validation/external-EVIDENCE.json"]
    input_paths.extend(ROOT / ("vectors/external-" + suite + "-inputs.jsonl") for suite in ("acvp", "xous", "gmsm"))
    manifest["inputs_sha256"] = {p.relative_to(ROOT).as_posix(): sha(p) for p in input_paths}
    manifest["sanitizer_options"] = {k: env[k] for k in ("ASAN_OPTIONS", "UBSAN_OPTIONS")}
    manifest["compiler"] = subprocess.check_output(["gcc", "--version"], text=True).splitlines()[0]
    def save():
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf8")
    def run(name, command, cwd=ROOT, timeout=1800):
        print(json.dumps({"phase": name, "command": command}), flush=True)
        begin = time.monotonic()
        log = out / (name + ".log")
        with log.open("x", encoding="utf8") as stream:
            try:
                process = subprocess.Popen(command, cwd=cwd, env=env, stdout=stream,
                                           stderr=subprocess.STDOUT, start_new_session=True)
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                code = 124
        record = {"name": name, "command": command, "cwd": str(cwd.relative_to(ROOT)),
                  "returncode": code, "diagnostic_seconds": time.monotonic() - begin,
                  "log": log.relative_to(ROOT).as_posix(), "log_sha256": sha(log)}
        manifest["steps"].append(record)
        save()
        print(json.dumps(record), flush=True)
        if code:
            print(log.read_text(encoding="utf8")[-5000:], flush=True)
            raise RuntimeError(f"stage failed: {name}")
    try:
        run("reference-build-and-tests", ["make", "OUT=" + str(build_rel / "ref"), "all", "test", "review-test", "fault-test", "guard-test"], ROOT / "c")
        run("counter-build-and-tests", ["make", "OUT=" + str(build_rel / "counters"), "COUNTERS=1", "all", "review-test", "guard-test"], ROOT / "c")
        run("sanitizer-tests", ["make", "OUT=" + str(build_rel / "sanitizer"),
            "CFLAGS=-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer", "test", "review-test", "fault-test"], ROOT / "c")
        library = build / "ref/libslhdsa_sm3.so"
        run("external-recheck", [sys.executable, "tools/recheck_external.py", "--library", str(library),
            "--output", str(out / "external.jsonl"), "--workers", str(args.workers), "--large-threads", str(args.threads)])
        run("complete-128-24", [sys.executable, "reference/differential.py", "--library", str(library),
            "--output", str(out / "complete-128-24.jsonl"), "--threads", str(args.threads), "complete",
            "--input", str(reference_input)])
        for suite in ("toy", "subtree"):
            run(suite + "-differential", [sys.executable, "reference/differential.py", "--library", str(library),
                "--output", str(out / (suite + ".jsonl")), "--workers", str(min(args.workers, 8) if suite == "subtree" else args.workers), suite, "--count", "1000"])
        run("exact-counts", [sys.executable, "tools/check_counts.py", "--library", str(build / "counters/libslhdsa_sm3.so"),
            "--output", str(out / "exact-counts.jsonl")])
        for suite, expected_total in (("external", 351), ("complete-128-24", 3), ("toy", 1000), ("subtree", 1000)):
            summary = json.loads((out / (suite + ".summary.json")).read_text(encoding="utf8"))
            library_key = "library_sha256" if suite == "external" else "native_library_sha256"
            unchanged_key = "library_unchanged" if suite == "external" else "native_library_unchanged"
            if (summary["total"] != expected_total or summary["passed"] != expected_total or summary["failed"] != 0
                    or not summary[unchanged_key] or summary[library_key] != sha(library)):
                raise ValueError(f"suite count/library acceptance mismatch: {suite}")
        ext = json.loads((out / "external.summary.json").read_text(encoding="utf8"))
        for group, expected_total in (("A", 208), ("B", 3), ("C", 140)):
            if sum(v["total"] for k, v in ext["counts"].items() if k.startswith(group + "/")) != expected_total:
                raise ValueError(f"external group count mismatch: {group}")
        count_summary = json.loads((out / "exact-counts.summary.json").read_text(encoding="utf8"))
        if (count_summary["passed"] is not True or not count_summary["records"] or count_summary["error"]
                or count_summary["counter_build_sha256"] != sha(build / "counters/libslhdsa_sm3.so")):
            raise ValueError("exact-counter acceptance mismatch")
        manifest["source_unchanged"] = source_before == sources()
        manifest["inputs_unchanged"] = all(sha(ROOT / p) == h for p, h in manifest["inputs_sha256"].items())
        manifest["build_sha256"] = {p.relative_to(ROOT).as_posix(): sha(p) for p in sorted(build.rglob("*"))
                                     if p.is_file() and (p.suffix == ".so" or p.name.startswith("test_"))}
        manifest["passed"] = manifest["source_unchanged"] and manifest["inputs_unchanged"] and all(s["returncode"] == 0 for s in manifest["steps"])
    except Exception as error:
        manifest["error"] = f"{type(error).__name__}: {error}"
    manifest["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
    manifest["evidence_sha256"] = {p.relative_to(ROOT).as_posix(): sha(p) for p in sorted(out.iterdir()) if p.is_file() and p.name != "manifest.json"}
    save()
    print(json.dumps({"run": str(out.relative_to(ROOT)), "passed": manifest["passed"], "error": manifest.get("error")}), flush=True)
    return int(not manifest["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
