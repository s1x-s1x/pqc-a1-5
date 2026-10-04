"""Bounded untimed isolation checks and post-run capture of retained artifacts."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from run_incremental_correctness import source_hashes, sha

RUNS = ("v1-r1", "kernel-r1", "integration-r1", "integration-r2", "full-af-r1",
        "full-a8-r1", "full-af-r2", "full-fault5-r1", "release-r1")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("use the existing Linux/CUDA correctness environment")
    out = args.output.resolve()
    if not out.is_relative_to(ROOT / "validation") or out.exists():
        parser.error("choose a fresh validation child")
    out.mkdir(parents=True)
    sources = source_hashes()
    sources["tools/close_incremental_correctness.py"] = sha(__file__)
    value = {"schema": "a15-incremental-isolation-v1", "performance_samples": 0,
             "performance_enabled": False, "source_sha256": sources, "steps": [],
             "passed": False, "artifacts": [], "captured_at_utc": datetime.now(timezone.utc).isoformat(),
             "capture_scope": "retained post-run bytes; earlier runners did not hash binaries at invocation"}

    def save():
        (out / "manifest.json").write_text(json.dumps(value, indent=2) + "\n")

    def run(name, command, cwd=ROOT):
        log = out / (name + ".log")
        with log.open("x") as stream:
            result = subprocess.run(command, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT,
                                    timeout=1800, check=False)
        value["steps"].append({"name": name, "command": command,
                               "returncode": result.returncode, "log": log.relative_to(ROOT).as_posix(),
                               "log_sha256": sha(log)})
        save()
        if result.returncode:
            raise RuntimeError(name + " failed: " + log.read_text()[-4000:])

    # Reuse a Make recipe with an isolated test source; production prerequisites
    # and already accepted harnesses remain byte-identical.
    makefile = (ROOT / "c/Makefile").read_text()
    recipe = makefile.replace("tests/test_incremental_engine.c", "tests/test_incremental_isolation.c")
    private_makefile = ROOT / "build/incremental-isolation.Makefile"
    private_makefile.write_text(recipe)
    value["private_makefile_sha256"] = sha(private_makefile)
    fixture_source = ROOT / "reference/evidence/python-sm3-128-24.jsonl"
    selected = [json.loads(line) for line in fixture_source.read_text().splitlines()
                if line.strip() and json.loads(line)["case_id"] == "python-3-0"]
    if len(selected) != 1:
        raise ValueError("expected exactly one independent public fixture")
    fixture = ROOT / "build" / out.name / "fixtures"
    fixture.mkdir(parents=True)
    fields = ("pk", "sig", "message", "context")
    for name in fields:
        data = bytes.fromhex(selected[0][name])
        if (name == "pk" and len(data) != 32) or (name == "sig" and len(data) != 3856):
            raise ValueError("independent fixture length differs")
        (fixture / (name + ".bin")).write_bytes(data)
    inputs = [str(fixture / (name + ".bin")) for name in fields]
    value["public_fixture_source_sha256"] = sha(fixture_source)
    value["compiler"] = subprocess.check_output(["gcc", "--version"], text=True).splitlines()[0]
    value["fixture_sha256"] = {name: sha(path) for name, path in zip(("pk", "sig", "message", "context"), inputs)}
    for kind, flags, cuda in (("sanitizer", "-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer", False),
                              ("cuda", "-O3", True)):
        target = ROOT / "build" / out.name / kind
        relative = "../" + target.relative_to(ROOT).as_posix()
        binary = target / "test_incremental_engine"
        run(kind + "-build", ["make", "-f", str(private_makefile), "OUT=" + relative,
            "CFLAGS=" + flags, "INCREMENTAL_MODE=4", "INCREMENTAL_B1=1", "INCREMENTAL_V1=1",
            *(["CUDA=1"] if cuda else []), relative + "/test_incremental_engine"], ROOT / "c")
        run(kind + "-isolation", [str(binary), *inputs, *(["cuda"] if cuda else [])])
        value["artifacts"].append({"path": binary.relative_to(ROOT).as_posix(), "sha256": sha(binary),
                                    "capture": "immediately after accepted run"})
    for suffix in RUNS:
        run_dir = ROOT / "validation" / ("incremental-20261005-" + suffix)
        build = ROOT / "build" / run_dir.name
        for path in sorted(build.rglob("*")):
            if path.is_file() and (path.name.startswith("test_") or path.suffix == ".so"):
                value["artifacts"].append({"path": path.relative_to(ROOT).as_posix(), "sha256": sha(path),
                                            "capture": "retained post-run artifact"})
    current = source_hashes()
    current["tools/close_incremental_correctness.py"] = sha(__file__)
    if current != sources:
        raise ValueError("sources changed during isolation acceptance")
    value["source_unchanged"] = True
    value["passed"] = True
    save()
    print(json.dumps({"passed": True, "steps": len(value["steps"]),
                      "artifacts": len(value["artifacts"]), "performance_samples": 0}))


if __name__ == "__main__":
    main()
