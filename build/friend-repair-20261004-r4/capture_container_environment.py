"""Capture completed reproducible-container checks without running workloads."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--image", default="a15-friend-correctness")
parser.add_argument("--container", required=True)
parser.add_argument("--out", type=Path, required=True)
parser.add_argument("--build-exit", type=Path, required=True)
parser.add_argument("--host-review", type=Path)
parser.add_argument("--final-review", type=Path, required=True)
args = parser.parse_args()
root = Path.cwd()
args.out.mkdir(parents=True, exist_ok=True)
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def command(name, argv, *, timeout=60):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    target = args.out / (name + ".json")
    record = {"argv": argv, "returncode": result.returncode,
              "stdout": result.stdout, "stderr": result.stderr}
    target.write_text(json.dumps(record, indent=2)+"\n")
    return record
image = command("runtime-image", ["docker", "image", "inspect", args.image])
base = command("base-image", ["docker", "image", "inspect", "a15-python-base:locked-5024f48b"])
container = command("container-inspect", ["docker", "inspect", args.container])
assert not image["returncode"] and not base["returncode"] and not container["returncode"]
runtime_image = json.loads(image["stdout"])[0]
base_image = json.loads(base["stdout"])[0]
container_record = json.loads(container["stdout"])[0]
assert base_image["Id"] == "sha256:dd23478b05784908485d6f06855b95297a407e29df69e6799da55408bca31a53"
cmd = ["docker", "run", "--rm", "--entrypoint", "python", args.image, "-B", "-c"]
inspect_code = '''import sys,json,platform,subprocess,importlib.metadata
from pathlib import Path
root=Path.cwd()
packages={p.metadata["Name"]:p.version for p in importlib.metadata.distributions()}
tools={name:subprocess.run(argv,capture_output=True,text=True).stdout for name,argv in {
"gcc":["gcc","--version"],"g++":["g++","--version"],"make":["make","--version"],
"glibc":["ldd","--version"],"debian_packages":["dpkg-query","-W"]}.items()}
provider=json.loads((root/"base_tls/.deps-falcon/installation.json").read_text())
print(json.dumps({"python":sys.version,"platform":platform.platform(),"packages":packages,
"tool_versions":tools,"falcon_installation":provider,
"apt_source":Path("/etc/apt/sources.list").read_text()},indent=2))'''
environment = command("runtime-environment", cmd + [inspect_code])
assert not environment["returncode"]
runtime = json.loads(environment["stdout"])
provider = runtime["falcon_installation"]
review = json.loads((args.out / "container-review/manifest.json").read_text())
host = json.loads(args.host_review.read_text()) if args.host_review else None
host_san = next((row for row in host.get("steps", []) if row["name"] == "native-sanitizers"), None) if host else None
container_san = next((row for row in review.get("steps", []) if row["name"] == "native-sanitizers"), None)
host_native_sources = {n: h for n, h in host.get("sources_sha256", {}).items()
                       if n.startswith(("c/", "third_party/slhdsa-c/"))} if host else {}
host_native_match = bool(host_native_sources) and all((root / n).is_file() and sha(root / n) == h for n, h in host_native_sources.items())
sanitizers = bool(container_san and container_san["returncode"] == 0 or
                  host and host.get("passed") and host_san and host_san["returncode"] == 0 and host_native_match)
checks = {"container_build": args.build_exit.read_text().strip() == "0" and runtime_image["Id"] == container_record["Image"],
          "container_run": container_record["State"]["Status"] == "exited" and container_record["State"]["ExitCode"] == 0 and review["passed"],
          "falcon_provider": provider["passed"] and {r["algorithm"] for r in provider["checks"] if r["passed"]} == {"falcon-512", "falcon-1024"},
          "sanitizers": sanitizers}
assert review["formal_performance_started"] is False and review["real_timing_samples"] == 0
current = {name: sha(root / name) for name in review["sources_sha256"]}
checks["final_sources_match"] = current == review["sources_sha256"] and review["sources_unchanged"]
final_review = json.loads(args.final_review.read_text())
checks["final_review_sources_match"] = final_review["sources_sha256"] == review["sources_sha256"]
record = {"schema": "a15-friend-environment-v1", "captured_utc": datetime.now(timezone.utc).isoformat(),
          "passed": all(checks.values()), "checks": checks,
          "formal_performance_started": False, "real_timing_samples": 0,
          "measured_durations": False,
          "base_image_index_digest": "sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed",
          "image_identity": {"runtime_image_id": runtime_image["Id"], "runtime_repo_digests": runtime_image.get("RepoDigests", []),
              "locked_base_image_id": base_image["Id"],
              "locked_base_manifest_digest": "sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed",
              "container_image_id": container_record["Image"]},
          "sources_sha256": review["sources_sha256"],
          "sanitizer_scope": "container" if container_san else "separate host final-source native review",
          "host_sanitizer_native_sources_match": host_native_match,
          "host_sanitizer_sources_sha256": host_native_sources,
          "host_sanitizer_manifest": None if args.host_review is None else {"path": str(args.host_review), "sha256": sha(args.host_review)},
          "final_review_manifest": {"path": str(args.final_review), "sha256": sha(args.final_review)},
          "failure_logs_retained": [p.name for p in args.out.glob("container-build*.log")],
          "evidence_sha256": {p.resolve().relative_to(root).as_posix(): sha(p) for p in args.out.rglob("*") if p.is_file() and p.name != "environment.json"}}
(args.out / "environment.json").write_text(json.dumps(record, indent=2)+"\n")
print(json.dumps({"passed": record["passed"], "checks": checks, "real_timing_samples": 0}))
