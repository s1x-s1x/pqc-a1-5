"""Fresh, untimed acceptance of incremental research paths. Never benchmarks."""
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


def source_hashes():
    paths = [p for folder in ("c", "third_party/slhdsa-c")
             for p in (ROOT / folder).rglob("*")
             if p.is_file() and p.suffix in {".c", ".h", ".inc", ".cu", ".cuh"}]
    paths += [ROOT / "c/Makefile", Path(__file__).resolve()]
    return {p.relative_to(ROOT).as_posix(): sha(p) for p in sorted(paths)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--phase", choices=("v1", "kernel", "integration", "full", "release"), default="v1")
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--threads", type=int, default=96)
    parser.add_argument("--mode", type=int, choices=(1,2,3,4), default=4)
    parser.add_argument("--b1", type=int, choices=(0,1), default=1)
    parser.add_argument("--fault-point", type=int, choices=(0,2,5), default=0)
    args = parser.parse_args()
    out = args.run_dir.resolve()
    build = ROOT / "build" / out.name
    if not out.is_relative_to(ROOT / "validation") or out == ROOT / "validation":
        parser.error("run-dir must be a fresh child of validation")
    if out.exists() or build.exists():
        parser.error("preserve existing evidence and choose a fresh run basename")
    if sys.platform != "linux":
        parser.error("native acceptance requires the existing Linux AVX2 environment")
    if not 1 <= args.threads <= 96:
        parser.error("threads must be within the fixed correctness allocation")
    if args.phase == "full" and (args.cache is None or not args.cache.is_file()):
        parser.error("full signing requires an existing bound t12 cache")
    before = source_hashes()
    inputs = ROOT / "reference/evidence/python-sm3-128-24.jsonl"
    records = [json.loads(line) for line in inputs.read_text().splitlines() if line.strip()]
    selected = [row for row in records if row["case_id"] in {"python-3-0", "python-3-1", "python-3-2"}]
    if len(selected) != 3 or len({row["case_id"] for row in selected}) != 3:
        raise ValueError("expected the three independent public pure fixtures")
    out.mkdir(parents=True)
    fixtures = build / "fixtures"
    fixtures.mkdir(parents=True)
    manifest = {"schema": "a15-incremental-correctness-v1", "phase": args.phase,
                "started_at_utc": datetime.now(timezone.utc).isoformat(),
                "performance_samples": 0, "performance_enabled": False,
                "source_sha256": before, "fixture_sha256": sha(inputs),
                "compiler": subprocess.check_output(["gcc", "--version"], text=True).splitlines()[0],
                "cpu_affinity": sorted(os.sched_getaffinity(0)),
                "steps": [], "passed": False}
    if args.cache:
        manifest["cache_sha256"] = sha(args.cache)
    env = dict(os.environ, OMP_DYNAMIC="FALSE", PYTHONUNBUFFERED="1",
               ASAN_OPTIONS="halt_on_error=1:abort_on_error=1:detect_leaks=1",
               UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")

    def save():
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    def run(name, command, cwd=ROOT):
        log = out / (name + ".log")
        print(json.dumps({"phase": name, "command": command}), flush=True)
        with log.open("x") as stream:
            result = subprocess.run(command, cwd=cwd, env=env, stdout=stream,
                                    stderr=subprocess.STDOUT, timeout=1800)
        manifest["steps"].append({"name": name, "command": command,
                                  "returncode": result.returncode,
                                  "log": log.relative_to(ROOT).as_posix(), "log_sha256": sha(log)})
        save()
        if result.returncode:
            print(log.read_text()[-6000:], flush=True)
            raise RuntimeError("correctness step failed: " + name)

    save()
    try:
        fixture_args = []
        for row in selected:
            directory = fixtures / row["case_id"]
            directory.mkdir()
            paths = []
            for field in ("pk", "sig", "message", "context"):
                payload = bytes.fromhex(row[field])
                if (field == "pk" and len(payload) != 32) or (field == "sig" and len(payload) != 3856):
                    raise ValueError("fixture length differs")
                path = directory / (field + ".bin")
                path.write_bytes(payload)
                paths.append(str(path))
            fixture_args.append((row["case_id"], paths))
        configs = (("normal", "-O3"),
                   ("sanitizer", "-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer"))
        if args.phase == "v1":
          for config, flags in configs:
            target = build / config
            relative = "../" + target.relative_to(ROOT).as_posix()
            run(config + "-build", ["make", "CC=gcc", "OUT=" + relative,
                "CFLAGS=" + flags, "INCREMENTAL_V1=1", relative + "/test_incremental_v1"], ROOT / "c")
            for case, paths in fixture_args:
                run(config + "-" + case, [str(target / "test_incremental_v1"), *paths])
        elif args.phase == "kernel":
            for config, flags in (*configs, ("portable", "-O3")):
                target = build / config
                relative = "../" + target.relative_to(ROOT).as_posix()
                options = ["AVX2=0"] if config == "portable" else []
                run(config+"-build", ["make", "OUT="+relative, "CFLAGS="+flags, *options,
                                     relative+"/test_incremental_kernel"], ROOT/"c")
                run(config+"-kernel", [str(target/"test_incremental_kernel")])
        elif args.phase == "integration":
            for mode,b1 in ((0,0),(0,1),*((m,b) for m in range(1,5) for b in (0,1))):
                target=build/f"m{mode}-b{b1}"
                relative="../"+target.relative_to(ROOT).as_posix()
                run(target.name+"-build",["make","OUT="+relative,"CFLAGS=-O3","COUNTERS=1",
                    f"INCREMENTAL_MODE={mode}",f"INCREMENTAL_B1={b1}","INCREMENTAL_V1=1",
                    relative+"/test_incremental_engine"],ROOT/"c")
                run(target.name+"-trees",[str(target/"test_incremental_engine")])
            for config,flags in (("sanitizer",configs[1][1]),("reversed","-O3 -DSLH_TEST_REVERSE_TASKS")):
                target=build/config;relative="../"+target.relative_to(ROOT).as_posix()
                run(config+"-build",["make","OUT="+relative,"CFLAGS="+flags,"COUNTERS=1",
                    "INCREMENTAL_MODE=4","INCREMENTAL_B1=1","INCREMENTAL_V1=1",
                    relative+"/test_incremental_engine"],ROOT/"c")
                run(config+"-trees",[str(target/"test_incremental_engine")])
            for point in (2,5):
                target=build/f"fault-{point}";relative="../"+target.relative_to(ROOT).as_posix()
                run(target.name+"-build",["make","OUT="+relative,"CFLAGS=-O3","COUNTERS=1",
                    "INCREMENTAL_MODE=4","INCREMENTAL_B1=1","INCREMENTAL_V1=1",
                    relative+f"/test_incremental_fault_{point}"],ROOT/"c")
                run(target.name+"-trees",[str(target/f"test_incremental_fault_{point}")])
        elif args.phase == "full":
            from signing_budget import SigningBudget
            target=build/"full";relative="../"+target.relative_to(ROOT).as_posix()
            binary="test_incremental_engine" if not args.fault_point else f"test_incremental_fault_{args.fault_point}"
            run("full-build",["make","OUT="+relative,"CFLAGS=-O3",f"INCREMENTAL_MODE={args.mode}",
                f"INCREMENTAL_B1={args.b1}","INCREMENTAL_V1=1",relative+"/"+binary],ROOT/"c")
            row=selected[0]
            for field in ("sk","opt_rand"):
                (fixtures/row["case_id"]/(field+".bin")).write_bytes(bytes.fromhex(row[field]))
            ledger=SigningBudget(ROOT/"validation/incremental-20261005/signing-budget.sqlite")
            receipt=ledger.reserve("SLH-DSA-SM3-128-24",bytes.fromhex(row["pk"]),bytes.fromhex(row["mp"]))
            manifest["budget_receipt"]=receipt;manifest["mode"]=args.mode;manifest["b1"]=args.b1;manifest["fault_point"]=args.fault_point
            save()
            paths=[str(fixtures/row["case_id"]/(field+".bin"))
                   for field in ("pk","sk","opt_rand","sig","message","context")]
            try:
                run("full-signature",[str(target/binary),*paths,str(args.cache.resolve()),str(args.threads)])
            except BaseException:
                ledger.finish(receipt)
                raise
            ledger.finish(receipt,None if args.fault_point else bytes.fromhex(row["sig"]))
            manifest["budget_validation"]=ledger.validate_receipt(receipt,algorithm="SLH-DSA-SM3-128-24",
                public_key=bytes.fromhex(row["pk"]),message=bytes.fromhex(row["mp"]),
                signature=None if args.fault_point else bytes.fromhex(row["sig"]),
                statuses=("failed",) if args.fault_point else ("committed",))
            manifest["budget_status"]=ledger.status()
        elif args.phase == "release":
            for config,options in (("default",[]),("candidate",["INCREMENTAL_MODE=4","INCREMENTAL_B1=1","INCREMENTAL_V1=1"]),
                                   ("portable",["AVX2=0","INCREMENTAL_MODE=4","INCREMENTAL_B1=1","INCREMENTAL_V1=1"])):
                target=build/config;relative="../"+target.relative_to(ROOT).as_posix()
                run(config+"-release",["make","OUT="+relative,"CFLAGS=-O3",*options,"all","guard-test","wots-test","prehash-test","repair-test"],ROOT/"c")
            # The combined B1/V1 branch gets the same independent fixture controls.
            target=build/"combined-v1";relative="../"+target.relative_to(ROOT).as_posix()
            run("combined-v1-build",["make","OUT="+relative,"CFLAGS="+configs[1][1],
                "INCREMENTAL_MODE=4","INCREMENTAL_B1=1","INCREMENTAL_V1=1",relative+"/test_incremental_v1"],ROOT/"c")
            for case,paths in fixture_args:
                run("combined-v1-"+case,[str(target/"test_incremental_v1"),*paths])
        manifest["source_unchanged"] = before == source_hashes()
        if not manifest["source_unchanged"]:
            raise ValueError("source changed during acceptance")
        manifest["passed"] = True
        manifest["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
        save()
        print(json.dumps({"passed": True, "phase": args.phase, "steps": len(manifest["steps"]),
                          "performance_samples": 0}), flush=True)
    except BaseException as error:
        manifest["error"] = str(error)
        save()
        raise


if __name__ == "__main__":
    main()
