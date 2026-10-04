"""Install a project-local Python runtime and the original locked TLS dependencies."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
UV_VERSION = "0.12.22"


def download(url, path):
    if not path.exists():
        print(f"Downloading {url}", flush=True)
        request = urllib.request.Request(url, headers={"User-Agent": "A1-5-bootstrap"})
        with urllib.request.urlopen(request, timeout=90) as source, path.open("wb") as target:
            while True:
                block = source.read(1024 * 1024)
                if not block:
                    break
                target.write(block)


def main():
    runtime = ROOT / "runtime"
    installers = runtime / "installers"
    installers.mkdir(parents=True, exist_ok=True)
    archive = installers / f"uv-{UV_VERSION}-linux-x86_64.tar.gz"
    checksum = archive.with_suffix(archive.suffix + ".sha256")
    base = f"https://github.com/astral-sh/uv/releases/download/{UV_VERSION}/"
    artifact = "uv-x86_64-unknown-linux-gnu.tar.gz"
    download(base + artifact, archive)
    download(base + artifact + ".sha256", checksum)
    expected = checksum.read_text().split()[0]
    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
    if actual != expected:
        raise RuntimeError("uv archive checksum mismatch")
    binary = runtime / "uv"
    if not binary.exists():
        with tarfile.open(archive) as package:
            member = next(m for m in package.getmembers() if m.name.endswith("/uv"))
            binary.write_bytes(package.extractfile(member).read())
        binary.chmod(0o755)
    environment = dict(os.environ)
    environment.update({
        "UV_CACHE_DIR": str(runtime / "uv-cache"),
        "UV_PYTHON_INSTALL_DIR": str(runtime / "python"),
        "UV_PYTHON_BIN_DIR": str(runtime / "bin"),
        "UV_TOOL_DIR": str(runtime / "tools"),
    })
    commands = [
        [str(binary), "python", "install", "3.13"],
        [str(binary), "venv", "--python", "3.13", str(ROOT / ".venv")],
        [str(binary), "pip", "install", "--python", str(ROOT / ".venv/bin/python"),
         "--require-hashes", "-r", str(ROOT / "base_tls/requirements.lock.txt")],
        [str(binary), "pip", "install", "--python", str(ROOT / ".venv/bin/python"),
         "pycryptodome==3.23.0"],
    ]
    for command in commands:
        subprocess.run(command, env=environment, check=True)
    manifest = {
        "uv_version": UV_VERSION, "uv_archive_sha256": actual,
        "python": subprocess.check_output(
            [str(ROOT / ".venv/bin/python"), "--version"], text=True,
        ).strip(),
        "dependency_policy": "original hashed TLS lock; pycryptodome==3.23.0 reference dependency",
    }
    (ROOT / "validation").mkdir(exist_ok=True)
    (ROOT / "validation/runtime.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
