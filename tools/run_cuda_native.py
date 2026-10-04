"""Build and accept real CUDA B1 kernels/faults/absence; no performance timing."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def sources():
    paths = [ROOT / "c/Makefile", Path(__file__).resolve(), ROOT / "tools/check_native_guards.py"]
    for folder in ("c", "third_party/slhdsa-c"):
        paths += [p for p in (ROOT / folder).rglob("*") if p.is_file()
                  and p.suffix in {".c", ".h", ".cu", ".cuh", ".cpp"}]
    return {p.relative_to(ROOT).as_posix(): sha(p) for p in sorted(set(paths))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--device", default="0")
    args = parser.parse_args()
    out = args.run_dir.resolve()
    if not out.is_relative_to(ROOT / "validation") or out.exists():
        parser.error("choose a fresh directory inside validation")
    build = ROOT / "build" / out.name
    if build.exists():
        parser.error("build basename already exists")
    out.mkdir(parents=True)
    before = sources()
    env = dict(os.environ, CUDA_VISIBLE_DEVICES=args.device, OMP_DYNAMIC="FALSE")
    manifest = dict(schema="a15-cuda-native-v1", started_utc=datetime.now(timezone.utc).isoformat(),
                    source_hashes=before, CUDA_VISIBLE_DEVICES=args.device, steps=[], passed=False,
                    formal_performance_started=False, measured_durations=False, real_timing_samples=0)

    def save():
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf8")

    def run(name, command, cwd=ROOT, hidden=False):
        log = out / (name + ".log")
        print(json.dumps(dict(step=name, command=command)), flush=True)
        with log.open("x", encoding="utf8") as stream:
            process = subprocess.Popen(command, cwd=cwd,
                env=dict(env, CUDA_VISIBLE_DEVICES="") if hidden else env,
                stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                code = process.wait(timeout=1200)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                code = 124
        manifest["steps"].append(dict(name=name, argv=command, cwd=str(cwd), returncode=code,
                                      log=str(log), log_sha256=sha(log), hidden_device=hidden))
        save()
        if code:
            raise ValueError("CUDA native step failed: " + name)
        return log

    error = None
    try:
        base = ["make", "CC=gcc", "NVCC=nvcc", "CUDA_ARCH=compute_86", "CFLAGS=-O3"]
        prefix = "../build/" + out.name + "/"
        run("release-kernels-faults-guards", [*base, "CUDA=1", "OUT=" + prefix + "release",
             "all", "repair-test", "cuda-test", "cuda-fault-test", "cuda-cleanup-host-test", "guard-test", "cuda-resource-report"], ROOT / "c")
        manifest["cleanup_fault_scope"] = {
            "driver": "deterministic host callbacks exercising the production ownership policy",
            "real_gpu_driver_faults_injected": False,
            "policy": "checked destructor retry; persistent wipe/sync/free failure retains allocation and poisons subsequent GPU work until process exit; no device reset"}
        counter_log = run("counter-kernels", [*base, "CUDA=1", "COUNTERS=1", "OUT=" + prefix + "counters",
             "all", "cuda-test"], ROOT / "c")
        lines = counter_log.read_text(encoding="utf8").splitlines()
        rows = [json.loads(line) for line in lines if line.startswith('{"')]
        if len(rows) != 4 or not all(row["passed"] and row["timed"] is False for row in rows):
            raise ValueError("CUDA native kernel rows incomplete")
        actual = rows[-1]
        if not actual.get("cuda_available") or actual.get("actual_backend") != 5:
            raise ValueError("CUDA kernel execution was not established")
        kernel = dict(schema="a15-cuda-kernel-v1", passed=True, actual_selected_backend=5,
                      formal_performance_started=False, measured_durations=False, real_timing_samples=0,
                      source_hashes={name: value for name, value in before.items()
                                     if "cuda" in name and name.startswith("c/")},
                      gpu_stats=dict(kernel_launches=actual["kernel_launches"], device_hashes=actual["device_hashes"],
                                     kernel_ns=0, timing_enabled=0), cases=rows,
                      library_sha256=sha(build / "counters/libslhdsa_sm3.so"),
                      executable_sha256=sha(build / "counters/test_cuda"), log_sha256=sha(counter_log))
        (out / "kernel.json").write_text(json.dumps(kernel, indent=2) + "\n", encoding="utf8")
        run("disabled-build-dispatch", [*base, "CUDA=0", "COUNTERS=1", "OUT=" + prefix + "disabled",
             "all", "cuda-test"], ROOT / "c")
        hidden_log = run("hidden-device-dispatch", [str(build / "release/test_cuda")], hidden=True)
        absent = json.loads(hidden_log.read_text(encoding="utf8").strip())
        if not absent["passed"] or absent["cuda_available"] or absent["timed"]:
            raise ValueError("hidden device rejection incomplete")
        run("release-library-dependencies", ["ldd", str(build / "release/libslhdsa_sm3.so")])
        manifest["source_unchanged"] = sources() == before
        manifest["build_sha256"] = {str(p.resolve()): sha(p)
                                     for p in build.rglob("*") if p.is_file()
                                     and (p.suffix == ".so" or p.name.startswith("test_"))}
        manifest["passed"] = manifest["source_unchanged"]
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    manifest["error"] = error
    manifest["evidence_sha256"] = {str(p.resolve()): sha(p) for p in out.iterdir()
                                   if p.is_file() and p.name != "manifest.json"}
    manifest["completed_utc"] = datetime.now(timezone.utc).isoformat()
    save()
    print(json.dumps(dict(passed=manifest["passed"], error=error)), flush=True)
    return int(not manifest["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
