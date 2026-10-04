"""Rebuild and functionally replay from a clean copied checkout; no timings."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    args = parser.parse_args()
    if os.name != "posix":
        parser.error("Linux native acceptance environment is required")
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    checkout = out / "checkout"
    checkout.mkdir()
    ignore = shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", ".deps", ".deps-falcon",
                                    ".deps-falcon-cp310-rejected", "*.so", "*.o")
    for name in ("c", "tools", "reference", "base_tls"):
        shutil.copytree(ROOT / name, checkout / name, ignore=ignore)
    # The independent Python verifier imports the pinned py-acvp-pqc reference;
    # the C library alone does not supply the dual-verification dependency set.
    shutil.copytree(ROOT / "third_party", checkout / "third_party", ignore=ignore)
    provider = ROOT / "base_tls/.deps-falcon"
    if provider.exists():
        # External provider is a separately pinned installed dependency, not a
        # previous project build. It is explicitly inventoried below.
        shutil.copytree(provider, checkout / "base_tls/.deps-falcon", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(args.fixtures.resolve(), checkout / "fixtures")
    for name in ("SPEC.md", "README.md"):
        shutil.copy2(ROOT / name, checkout / name)
    source = {p.relative_to(checkout).as_posix(): sha(p) for p in checkout.rglob("*")
              if p.is_file() and p.suffix in {".py", ".c", ".h", ".cu", ".cuh", ".cpp"}
              and ".deps-falcon" not in p.parts and "fixtures" not in p.parts}
    external = {p.relative_to(checkout).as_posix(): sha(p) for p in (checkout / "base_tls/.deps-falcon").rglob("*") if p.is_file()}
    manifest = dict(schema="a15-clean-reproduction-v1", started_utc=datetime.now(timezone.utc).isoformat(),
        source_sha256=source, external_provider_sha256=external, steps=[],
        formal_performance_started=False, real_timing_samples=0,
        scope="Clean source copy, fresh CPU release build/repair tests, all five authenticated fixture profiles and strict CA negatives; pinned provider installed separately.")
    def run(name, command, env=None):
        print(json.dumps({"phase": name, "command": command}), flush=True)
        with (out / (name + ".log")).open("xb") as stream:
            result = subprocess.run(command, cwd=checkout, env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=1200)
        manifest["steps"].append(dict(name=name, command=command, returncode=result.returncode, log_sha256=sha(out / (name + ".log"))))
        if result.returncode:
            raise ValueError("Clean reproduction failed: " + name)
    error = None
    try:
        run("clean-build", ["make", "-C", "c", "OUT=../build/reproduce", "CC=gcc", "CFLAGS=-O3", "all", "test", "repair-test", "guard-test"])
        library = checkout / "build/reproduce/libslhdsa_sm3.so"
        env = dict(os.environ, A15_NATIVE_LIBRARY=str(library), SLHDSA_SM3_LIB=str(library), OMP_DYNAMIC="FALSE")
        run("clean-real-profiles", [sys.executable, "tools/demo_project.py", "--fixtures", str(checkout / "fixtures"),
                                   "--library", str(library), "--output", str(out / "reproduced-demo")], env)
        run("clean-native-boundaries", [sys.executable, "tools/test_native_boundaries.py"], env)
        manifest["source_unchanged"] = all(sha(checkout / name) == digest for name, digest in source.items())
        manifest["library_sha256"] = sha(library)
        manifest["passed"] = manifest["source_unchanged"]
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        manifest["passed"] = False
    manifest.update(error=error, completed_utc=datetime.now(timezone.utc).isoformat())
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": manifest["passed"], "error": error, "real_timing_samples": 0}))
    return int(not manifest["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
