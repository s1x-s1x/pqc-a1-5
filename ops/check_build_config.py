"""Compile same-output A/B/A configurations and check stamp-driven rebuilds."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    library_dir = output / "same-output"
    original = sha(ROOT / "c/Makefile")
    steps = []
    configurations = (("A-first", "-O3", 0, 1), ("B", "-O3", 1, 0),
                      ("A-return", "-O3", 0, 1), ("A-repeat", "-O3", 0, 1),
                      ("C-flags", "-O2", 0, 1), ("A-flags-return", "-O3", 0, 1))
    for name, flags, counters, avx2 in configurations:
        command = ["make", "-C", "c", "OUT=" + str(library_dir), "CC=gcc",
                   "CFLAGS=" + flags, "COUNTERS=" + str(counters), "AVX2=" + str(avx2), "all"]
        result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=180)
        log = output / (name + ".log")
        log.write_bytes(result.stdout)
        if result.returncode:
            raise ValueError("configuration build failed: " + name)
        stamps = list(library_dir.glob(".a15-config-*"))
        if len(stamps) != 1:
            raise ValueError("configuration identity stamp set differs")
        library = library_dir / "libslhdsa_sm3.so"
        steps.append(dict(name=name, command=command, returncode=0, stamp=stamps[0].name,
                          library_sha256=sha(library), build_mtime_ns=library.stat().st_mtime_ns,
                          compiler_executed=b" -shared " in result.stdout, log_sha256=sha(log)))
    a, b, ar, repeat, c, af = steps
    checks = dict(changed_settings_rebuild=b["compiler_executed"] and b["stamp"] != a["stamp"],
                  A_B_A_rebuild=ar["compiler_executed"] and ar["stamp"] == a["stamp"],
                  A_repeat_reuses=not repeat["compiler_executed"] and repeat["build_mtime_ns"] == ar["build_mtime_ns"],
                  flags_rebuild=c["compiler_executed"] and c["stamp"] != a["stamp"],
                  flags_return_rebuild=af["compiler_executed"] and af["stamp"] == a["stamp"],
                  A_bytes_reproducible=len({x["library_sha256"] for x in (a, ar, repeat, af)}) == 1,
                  source_unchanged=sha(ROOT / "c/Makefile") == original)
    manifest = dict(schema="a15-build-config-regression-v1", passed=all(checks.values()),
                    checks=checks, steps=steps, makefile_sha256=original,
                    native_calls=0, real_timing_samples=0, formal_performance_started=False)
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": manifest["passed"], "checks": len(checks), "real_timing_samples": 0}))
    return int(not manifest["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
