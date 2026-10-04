"""Fetch the pinned official Verifpal binary without modifying the system."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import platform
import urllib.request
import zipfile

VERSION = "1.4.12"
BASE = f"https://github.com/symbolicsoft/verifpal/releases/download/v{VERSION}/"


def fetch(name):
    request = urllib.request.Request(BASE + name, headers={"User-Agent": "A1-5-project-verification"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    osname = {"Windows": "windows", "Linux": "linux"}.get(platform.system())
    if osname is None or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise ValueError("This pinned installer supports Windows/Linux amd64")
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    name = f"verifpal_{VERSION}_{osname}_amd64.zip"
    checksums = fetch(f"verifpal_{VERSION}_checksums.txt")
    expected = {line.split()[-1]: line.split()[0] for line in checksums.decode().splitlines()}[name]
    payload = fetch(name)
    digest = hashlib.sha256(payload).hexdigest()
    if digest != expected:
        raise ValueError("Official release checksum mismatch")
    (directory / name).write_bytes(payload)
    (directory / "checksums.txt").write_bytes(checksums)
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        for member in archive.infolist():
            target = (directory / member.filename).resolve()
            if not target.is_relative_to(directory) or member.filename.startswith(("/", "\\")):
                raise ValueError("Archive path leaves install directory")
        archive.extractall(directory)
    binary = directory / ("verifpal.exe" if osname == "windows" else "verifpal")
    if not binary.is_file():
        raise ValueError("Pinned binary absent after extraction")
    if osname == "linux":
        binary.chmod(0o755)
    manifest = {"version": VERSION, "url": BASE + name, "archive_sha256": digest,
                "checksum_source": BASE + f"verifpal_{VERSION}_checksums.txt",
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "platform": osname, "binary": binary.name, "system_modified": False}
    (directory / "installation.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest))


if __name__ == "__main__":
    main()
