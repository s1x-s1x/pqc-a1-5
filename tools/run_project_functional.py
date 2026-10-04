"""Run the project functional gates, with performance commands excluded."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def sources():
    paths = [p for folder in ("tools", "c", "base_tls/tls", "base_tls/tests", "base_tls/tools", "reference")
             for p in (ROOT / folder).rglob("*") if p.is_file() and p.suffix in {".py", ".c", ".h", ".cu", ".cuh", ".cpp"}]
    paths.append(ROOT / "c/Makefile")
    return {p.relative_to(ROOT).as_posix(): sha(p) for p in sorted(set(paths))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path)
    args = parser.parse_args()
    out = args.run_dir.resolve()
    out.mkdir(parents=True, exist_ok=False)
    library = args.library.resolve()
    before = sources()
    manifest = dict(schema="a15-project-functional-v1", started_utc=datetime.now(timezone.utc).isoformat(),
        source_sha256=before, library_sha256=sha(library), python=sys.version, steps=[],
        formal_performance_started=False, real_timing_samples=0,
        scope="Native/ABI, budget, dependency, TLS unit/negative/DER/live-path acceptance; no performance workers.")
    env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONDONTWRITEBYTECODE="1",
               A15_NATIVE_LIBRARY=str(library), SLHDSA_SM3_LIB=str(library))
    if args.fixtures:
        env["A15_ALT_FIXTURES"] = str(args.fixtures.resolve())

    def run(name, command, cwd=ROOT, timeout=1200):
        print(json.dumps({"phase": name, "command": command}), flush=True)
        with (out / (name + ".log")).open("xb") as stream:
            result = subprocess.run(command, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
        row = dict(name=name, command=command, cwd=cwd.relative_to(ROOT).as_posix(), returncode=result.returncode,
                   log_sha256=sha(out / (name + ".log")))
        manifest["steps"].append(row)
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        if result.returncode:
            print((out / (name + ".log")).read_text(encoding="utf-8")[-6000:], flush=True)
            raise ValueError("Functional gate failed: " + name)

    error = None
    try:
        run("budget-repair", [sys.executable, "tools/test_budget_repair.py"])
        run("native-boundary", [sys.executable, "tools/test_native_boundaries.py"])
        run("tls-pytest", [sys.executable, "-m", "pytest", "tests", "-q", "-ra"], ROOT / "base_tls", timeout=1800)
        run("tls-live-checks", [sys.executable, "tools/audit_live_checks.py"], ROOT / "base_tls")
        run("dependency-locks", [sys.executable, "tools/verify_dependency_lock.py"], ROOT / "base_tls")
        run("native-source-guards", [sys.executable, "tools/check_native_guards.py", "--source-only"])
        for tool in ("bench_cpu", "bench_cuda", "freeze_cuda"):
            switches = ["self-test", "--output"] if tool.startswith("bench_") else ["--self-test", "--self-test-output"]
            run(tool + "-mock", [sys.executable, "tools/" + tool + ".py", *switches, str(out / (tool + "-mock.json"))])
        if args.fixtures:
            run("real-ca-dual-verification", [sys.executable, "tools/alt_chain_fixtures.py", "verify", "--fixtures", str(args.fixtures.resolve()), "--library", str(library), "--output", str(out / "ca-verification.json")], timeout=1800)
            run("p0-p4-serialized-functional", [sys.executable, "tools/alt_chain_fixtures.py", "e1", "--fixtures", str(args.fixtures.resolve()), "--output", str(out / "p0-p4-size-functional.jsonl")])
        manifest["source_unchanged"] = before == sources()
        manifest["library_unchanged"] = sha(library) == manifest["library_sha256"]
        manifest["passed"] = manifest["source_unchanged"] and manifest["library_unchanged"]
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        manifest["passed"] = False
    manifest["error"] = error
    manifest["completed_utc"] = datetime.now(timezone.utc).isoformat()
    manifest["evidence_sha256"] = {p.name: sha(p) for p in out.iterdir() if p.is_file() and p.name != "manifest.json"}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": manifest["passed"], "error": error}), flush=True)
    return int(not manifest["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
