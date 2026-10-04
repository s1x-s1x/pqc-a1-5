#!/usr/bin/env python3
"""Check fault-build isolation; --source-only needs no native compiler."""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit("native guard FAIL: " + message)


def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, timeout=60, **kwargs)


def source_checks() -> None:
    engine = (ROOT / "c/src/engine.c").read_text(encoding="utf-8")
    header = (ROOT / "c/include/slhdsa_sm3.h").read_text(encoding="utf-8")
    makefile = (ROOT / "c/Makefile").read_text(encoding="utf-8")
    require("SLH_TEST_FAULT_POINT requires SLH_TEST_BUILD" in engine, "missing two-macro gate")
    require("Release library must not include SLH_TEST_BUILD" in engine, "missing release-build exclusion")
    require("#define TEST_FAULT(w,point,index,output) ((void)0)" in engine, "release fault macro is not erased")
    require("SLH_TEST" not in header, "test hook leaked into public header")
    require("-DSLH_RELEASE_BUILD -shared" in makefile, "shared library lacks release guard")
    require("-DSLH_TEST_BUILD -DSLH_TEST_FAULT_POINT=$*" in makefile, "standalone fault target lacks test gate")
    for point in range(1, 6):
        require(re.search(r"TEST_FAULT\([^\n]*," + str(point) + r",", engine) is not None, f"fault point {point} missing")
    require("INJECT(" not in engine, "old signature-byte injection remains")
    print("native guard source checks PASS: two-macro test gate, release exclusion, five calculation sites")


def compiler_checks(cc: str, library: Path | None) -> None:
    prefix = shlex.split(cc)
    require(bool(prefix), "empty compiler command")
    common = prefix + ["-std=c11", "-I" + str(ROOT / "c/include"), "-I" + str(ROOT / "c/src"),
                       "-I" + str(ROOT / "third_party/slhdsa-c")]
    source = str(ROOT / "c/src/engine.c")
    release = run(common + ["-DSLH_RELEASE_BUILD", "-E", source])
    require(release.returncode == 0, "release preprocessing failed: " + release.stderr[:1000])
    require(re.search(r"\b(test_site|test_index|TEST_FAULT|TEST_SITE)\b", release.stdout) is None,
            "fault state/code remains in preprocessed release")
    enabled = run(common + ["-DSLH_TEST_BUILD", "-DSLH_TEST_FAULT_POINT=3", "-E", source])
    require(enabled.returncode == 0 and "test_site" in enabled.stdout, "test build did not contain fault state")
    invalid = [
        (["-DSLH_TEST_FAULT_POINT=1"], "SLH_TEST_FAULT_POINT requires SLH_TEST_BUILD"),
        (["-DSLH_RELEASE_BUILD", "-DSLH_TEST_BUILD", "-DSLH_TEST_FAULT_POINT=1"], "Release library must not include SLH_TEST_BUILD"),
        (["-DSLH_TEST_BUILD", "-DSLH_TEST_FAULT_POINT=6"], "Invalid SLH_TEST_FAULT_POINT"),
        (["-DSLH_TEST_BUILD", "-DSLH_TEST_FAULT_POINT=-1"], "Invalid SLH_TEST_FAULT_POINT"),
    ]
    for flags, diagnostic in invalid:
        rejected = run(common + flags + ["-E", source])
        require(rejected.returncode != 0 and diagnostic in rejected.stderr, "invalid build accepted: " + " ".join(flags))
    with tempfile.TemporaryDirectory(prefix="a15-guards-") as folder:
        obj = Path(folder) / "engine.o"
        compiled = run(common + ["-O2", "-fPIC", "-fopenmp", "-DSLH_RELEASE_BUILD", "-c", source, "-o", str(obj)])
        require(compiled.returncode == 0, "release object compile failed: " + compiled.stderr[:1000])
        require(shutil.which("nm") is not None, "nm is required for symbol inspection")
        symbols = run(["nm", "--defined-only", str(obj)])
        require(symbols.returncode == 0, "release object symbol inspection failed")
        require(re.search(r"(?im)\b(?:\w*(?:fault|inject)|test_site|test_index)\w*$", symbols.stdout) is None,
                "test/fault symbol in release object")
    if library is not None:
        require(library.is_file(), "release library not found: " + str(library))
        symbols = run(["nm", "-D", "--defined-only", str(library)])
        require(symbols.returncode == 0, "release shared-library symbol inspection failed")
        exported = [line.split()[-1] for line in symbols.stdout.splitlines() if line.split()]
        require("slh_sign" in exported and "slh_sign_internal" in exported, "expected signing ABI missing")
        require(not any(re.search(r"fault|inject|test_", name, re.I) for name in exported), "test/fault ABI exported")
    print("native guard compiler checks PASS: release code erased; four bad builds rejected; release symbols clean")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--library", type=Path)
    parser.add_argument("--source-only", action="store_true")
    args = parser.parse_args()
    source_checks()
    if not args.source_only:
        compiler_checks(args.cc, args.library)


if __name__ == "__main__":
    main()
