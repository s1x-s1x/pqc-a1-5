"""Recheck the imported TLS harness with its pinned, isolated Falcon provider."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "base_tls"
OUT = ROOT / "validation" / "baseline"


def run(command, name, cwd=BASE):
    start = time.monotonic()
    with (OUT / (name + ".log")).open("w", encoding="utf-8") as stream:
        environment = dict(os.environ, UV_CACHE_DIR=str(ROOT / "runtime" / "uv-cache"))
        result = subprocess.run(command, cwd=cwd, env=environment,
                                stdout=stream, stderr=subprocess.STDOUT)
    record = {"name": name, "command": command, "returncode": result.returncode,
              "elapsed_seconds": time.monotonic() - start,
              "log": str((OUT / (name + ".log")).relative_to(ROOT))}
    print(json.dumps(record), flush=True)
    if result.returncode:
        print((OUT / (name + ".log")).read_text(encoding="utf-8")[-5000:])
        raise RuntimeError(f"{name} failed")
    return record


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    provider = BASE / ".deps-falcon"
    renamed = provider / "pqcrypto_pqclean"
    records = []
    if not renamed.is_dir():
        records.append(run([str(ROOT / "runtime" / "uv"), "pip", "install",
                            "--python", sys.executable, "--target", str(provider),
                            "--no-deps", "--require-hashes", "-r",
                            str(BASE / "requirements-falcon.lock.txt")], "falcon-install"))
        shutil.copytree(provider / "pqcrypto", renamed)
    records.append(run([sys.executable, "-m", "pytest", "tests", "-q", "-ra",
                        "--junitxml=" + str(OUT / "pytest.xml")], "pytest"))
    data = {"timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "scope": "imported TLS baseline; not new SLH or alt-chain functionality",
            "python": sys.version, "records": records,
            "lock_hashes": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in BASE.glob("requirements*.lock.txt")}}
    (OUT / "manifest.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print((OUT / "pytest.log").read_text(encoding="utf-8")[-1500:])


if __name__ == "__main__":
    main()
