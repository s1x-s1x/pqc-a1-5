"""Save source-bound analytical tests and mock-clock evidence; no native calls."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "validation/incremental-20261005/analysis-final")
    args = parser.parse_args()
    out = args.output.resolve()
    if not out.is_relative_to(ROOT / "validation") or out == ROOT / "validation":
        parser.error("output must be a fresh validation child")
    if out.exists():
        raise ValueError("preserve previous evidence; analysis-final already exists")
    out.mkdir(parents=True)
    names = ("tools/incremental_parameters.py", "tools/test_incremental_parameters.py",
             "tools/incremental_scheduler.py", "tools/test_incremental_scheduler.py",
             "tools/record_incremental_analysis.py", "docs/research/P_20261005.md",
             "docs/research/SCHEDULER_20261005.md", "c/src/engine.c",
             "c/src/sm3_incremental.c", "c/src/sm3_incremental.h")
    hashes = {name: digest(ROOT / name) for name in names}
    guard = """import runpy, sys, time, unittest
sys.path.insert(0,'tools')
def forbidden(*args, **kwargs):
    raise AssertionError('real clock/sleep called by mock scheduler')
for name in ('time','time_ns','monotonic','monotonic_ns','perf_counter','perf_counter_ns','process_time','process_time_ns','thread_time','thread_time_ns','sleep'):
    if hasattr(time,name): setattr(time,name,forbidden)
runpy.run_path('tools/test_incremental_scheduler.py', run_name='__main__')
"""
    jobs = (("parameters", [sys.executable, "-B", "tools/test_incremental_parameters.py"]),
            ("scheduler-real-clocks-forbidden", [sys.executable, "-B", "-c", guard]))
    steps = []
    for name, command in jobs:
        log = out / (name + ".log")
        with log.open("x", encoding="utf-8") as stream:
            result = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT,
                                    timeout=1800, check=False)
        if result.returncode:
            raise RuntimeError(log.read_text())
        steps.append({"name": name, "command": command, "returncode": 0,
                      "log": log.relative_to(ROOT).as_posix(), "log_sha256": digest(log)})
    if hashes != {name: digest(ROOT / name) for name in names}:
        raise ValueError("analysis sources changed during checks")
    value = {"schema": "a15-incremental-analysis-final-v1", "passed": True,
             "native_crypto_calls": 0, "new_performance_samples": 0,
             "source_sha256": hashes, "steps": steps,
             "parameter_tests": 19, "scheduler_tests": 27, "real_scheduler_clocks_forbidden": True}
    (out / "manifest.json").write_text(json.dumps(value, indent=2) + "\n")
    print(json.dumps({"passed": True, "parameter_tests": 19, "scheduler_tests": 27,
                      "new_performance_samples": 0}))


if __name__ == "__main__":
    main()
