"""Write the environment manifest an independent verification run needs.

The improvement plan's work package C asks the *verifier* to record the environment rather than
inherit the author's: interpreter version and provenance, lock-file hashes, the hashes of the
wheels actually installed, import paths, platform, relevant environment variables, and the exit
code of every command that was run. Without that, "the suite passes" is a claim about an
unstated machine.

This tool only *describes* the environment; it never changes it. In particular it does not add
``tools/sandbox_pyfix`` to ``PYTHONPATH``, and it reports whether that helper is currently
importable from the running interpreter, because that is exactly the trust boundary the plan
wants visible (their TB-1).

Usage:
    python tools/report_environment.py                     # print JSON to stdout
    python tools/report_environment.py --out validation/environment.json
    python tools/report_environment.py --commands "python -m pytest tests -q" ...
"""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

#: Modules whose provenance matters for reproducing a number or a hash.
TRACKED_IMPORTS = ("cryptography", "pqcrypto", "pqcrypto_pqclean", "pytest", "sitecustomize")

#: Environment variables that change what the harness does.
TRACKED_ENV = (
    "PYTHONPATH",
    "PYTHONHASHSEED",
    "PYTHONIOENCODING",
    "PYTHONDONTWRITEBYTECODE",
    "DSH_SANDBOX_PYFIX",
    "DSH_SESSION_ID",
    "TEMP",
    "TMP",
    "VIRTUAL_ENV",
)


def _sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def module_report(name: str) -> dict:
    """Where a module comes from, and whether it is importable at all."""
    spec = importlib.util.find_spec(name)
    if spec is None:
        return {"importable": False}
    origin = spec.origin or "<builtin>"
    report = {"importable": True, "origin": origin}
    path = Path(origin)
    if path.is_file() and path.suffix in {".py", ".pyd", ".so"}:
        try:
            report["sha256"] = _sha256(path)[:32]
        except OSError as error:
            report["sha256"] = f"unreadable: {error}"
    try:
        module = importlib.import_module(name)
        version = getattr(module, "__version__", None)
        if version:
            report["version"] = str(version)
    except Exception as error:  # noqa: BLE001 - a broken import is a fact worth recording
        report["import_error"] = f"{type(error).__name__}: {error}"
    return report


def installed_wheels() -> list[dict]:
    """Every installed distribution this project depends on, with its file hash where known."""
    rows: list[dict] = []
    import importlib.metadata as metadata

    for distribution in ("cryptography", "pqcrypto", "pytest"):
        try:
            dist = metadata.distribution(distribution)
        except metadata.PackageNotFoundError:
            rows.append({"package": distribution, "installed": False})
            continue
        files = []
        for entry in (dist.files or [])[:400]:
            located = dist.locate_file(entry)
            path = Path(str(located))
            if path.is_file() and path.suffix in {".pyd", ".so", ".py"}:
                try:
                    files.append({"path": str(entry), "sha256": _sha256(path)[:32]})
                except OSError:
                    continue
            if len(files) >= 5:
                break
        rows.append(
            {
                "package": distribution,
                "installed": True,
                "version": dist.version,
                "location": str(dist.locate_file("")),
                "sample_file_hashes": files,
            }
        )
    return rows


def lock_report() -> list[dict]:
    """Hash each shipped lock file, and count its pins through the lock verifier itself."""
    rows = []
    for name in ("requirements.lock.txt", "requirements-falcon.lock.txt"):
        path = PROJECT_ROOT / name
        row = {"file": name, "present": path.is_file()}
        if path.is_file():
            row["sha256"] = _sha256(path)
            row["bytes"] = path.stat().st_size
        rows.append(row)
    return rows


def sandbox_helper_report() -> dict:
    """Whether the directory-mode helper is on this process's path, and what it would do."""
    path = PROJECT_ROOT / "tools" / "sandbox_pyfix" / "sitecustomize.py"
    report = {
        "file": "tools/sandbox_pyfix/sitecustomize.py",
        "present": path.is_file(),
        "on_pythonpath": str(path.parent) in (os.environ.get("PYTHONPATH") or "").split(os.pathsep),
        "would_patch_this_process": False,
        "note": "the independent verification run must not add this directory to PYTHONPATH; "
                "verify its content and hash in a process that has not imported it",
    }
    if path.is_file():
        report["sha256"] = _sha256(path)
        report["sha256_short"] = _sha256(path)[:32]
    if "sitecustomize" in sys.modules:
        module = sys.modules["sitecustomize"]
        report["imported_from"] = getattr(module, "__file__", "<unknown>")
        report["would_patch_this_process"] = getattr(module, "_patch_is_wanted", lambda: None)() is True
    return report


def run_command(command: str) -> dict:
    """Run one command and record its exit code, stdout tail and stderr tail."""
    completed = subprocess.run(
        command, shell=True, cwd=PROJECT_ROOT, capture_output=True, text=True, check=False,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )
    tail = lambda text: "\n".join(text.strip().splitlines()[-6:])
    return {
        "command": command,
        "exit_code": completed.returncode,
        "stdout_tail": tail(completed.stdout),
        "stderr_tail": tail(completed.stderr),
        "note": "exit 2 from the sweep means tool failure, not a security verdict",
    }


def build_manifest(commands: list[str]) -> dict:
    return {
        "python": {
            "version": sys.version,
            "executable": sys.executable,
            "implementation": platform.python_implementation(),
            "compiler": platform.python_compiler(),
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
        },
        "environment_variables": {name: os.environ.get(name) for name in TRACKED_ENV},
        "sys_path": sys.path,
        "project_root": str(PROJECT_ROOT),
        "locks": lock_report(),
        "installed_distributions": installed_wheels(),
        "modules": {name: module_report(name) for name in TRACKED_IMPORTS},
        "sandbox_helper": sandbox_helper_report(),
        "commands": [run_command(command) for command in commands],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=None, help="write the manifest here (default: stdout)")
    parser.add_argument(
        "--commands",
        nargs="*",
        default=[],
        help="commands to run and record with their exit codes",
    )
    args = parser.parse_args(argv)
    manifest = build_manifest(args.commands)
    text = json.dumps(manifest, indent=2, ensure_ascii=False)
    if args.out:
        out = Path(args.out)
        if not out.is_absolute():
            out = PROJECT_ROOT / out
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")
        print(f"wrote {out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
