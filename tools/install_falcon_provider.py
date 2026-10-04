"""Install the hash-pinned optional Falcon provider beside base_tls.

The primary TLS dependency lock must already be installed. The separate target
and renamed package preserve pqcrypto 1.x for ML-KEM/ML-DSA.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", default=sys.executable, help="interpreter with pip and matching ABI")
    args = parser.parse_args()
    target = ROOT / "base_tls/.deps-falcon"
    target.mkdir(parents=True, exist_ok=False)
    lock = ROOT / "base_tls/requirements-falcon.lock.txt"
    command = [args.python, "-m", "pip", "install", "--no-deps", "--no-input",
               "--disable-pip-version-check", "--target", str(target), "--require-hashes", "-r", str(lock)]
    with (target / "install.log").open("xb") as stream:
        result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=600)
    if result.returncode:
        raise RuntimeError("Provider installation failed; retained install.log contains diagnostics")
    shutil.copytree(target / "pqcrypto", target / "pqcrypto_pqclean")
    sys.path.insert(0, str(ROOT / "base_tls"))
    from tls.pq.signature import get_pq_signer
    from tls.pq.kem import get_kem
    get_kem("ml-kem-768")
    rows = []
    for name in ("falcon-512", "falcon-1024"):
        signer = get_pq_signer(name)
        secret, public = signer.keygen()
        signature = signer.sign(secret, b"functional provider verification")
        if not signer.verify(public, b"functional provider verification", signature) or signer.verify(public, b"changed", signature):
            raise ValueError("Provider sign/verify/tamper verification failed")
        rows.append({"algorithm": name, "passed": True})
    hashes = {p.relative_to(target).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in target.rglob("*") if p.is_file() and "__pycache__" not in p.parts}
    record = {"schema": "a15-falcon-provider-install-v1", "version": "0.4.0", "passed": True,
              "lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(), "command": command,
              "checks": rows, "files_sha256": hashes, "real_timing_samples": 0}
    (target / "installation.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": True, "provider": str(target), "checks": len(rows)}))


if __name__ == "__main__":
    main()
