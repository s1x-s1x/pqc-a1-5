#!/usr/bin/env python3
"""Restore hash-bound system evidence from the accepted host or a local root.

Copies files only; no compiler, library, GPU or performance execution occurs.
The exact original system dependencies are declared in the frozen manifest.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import sys


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "validation/optimization-external-evidence/manifest.json"


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--source-root", type=Path, help="accepted system root, normally / on Linux")
    source.add_argument("--ssh", action="store_true", help="accepted host through ops.remote environment settings")
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if manifest.get("schema") != "a15-external-evidence-mirror-v1":
        raise ValueError("Unexpected external evidence manifest")
    jump = remote = sftp = None
    copied = present = 0
    try:
        if args.ssh:
            import remote as connection
            jump, remote = connection.connect()
            sftp = remote.open_sftp()
        for original, entry in manifest["files"].items():
            original_path = PurePosixPath(original)
            if not original_path.is_absolute() or ".." in original_path.parts:
                raise ValueError("Invalid system evidence identity")
            expected_relative = "validation/optimization-external-evidence/" + original.lstrip("/")
            if entry["local_path"] != expected_relative:
                raise ValueError("Invalid external evidence destination")
            destination = ROOT.joinpath(*PurePosixPath(expected_relative).parts)
            if not destination.resolve().is_relative_to(ROOT / "validation/optimization-external-evidence"):
                raise ValueError("External evidence destination leaves mirror")
            if destination.is_file() and sha(destination) == entry["sha256"]:
                present += 1
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_name(destination.name + ".download-" + str(os.getpid()))
            try:
                with temporary.open("xb") as target:
                    if sftp is not None:
                        sftp.getfo(original, target)
                    else:
                        local_source = args.source_root.joinpath(*original_path.parts[1:])
                        with local_source.open("rb") as stream:
                            for block in iter(lambda: stream.read(1024 * 1024), b""):
                                target.write(block)
                if temporary.stat().st_size != entry["size_bytes"] or sha(temporary) != entry["sha256"]:
                    raise ValueError("System dependency differs from frozen bytes: " + original)
                os.replace(temporary, destination)
                copied += 1
            finally:
                if temporary.is_file():
                    temporary.unlink()
    finally:
        if sftp is not None:
            sftp.close()
        if remote is not None:
            remote.close()
        if jump is not None:
            jump.close()
    print(json.dumps({"passed": True, "copied_files": copied, "already_present": present,
                      "native_calls": 0, "real_timing_samples": 0}))


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    main()
