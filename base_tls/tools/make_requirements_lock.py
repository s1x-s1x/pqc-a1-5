"""Regenerate the hash-pinned dependency locks from PyPI metadata.

An audit of this repository pointed out that `tools/bootstrap_env.ps1` installed with
lower-bound constraints and `--upgrade`, so two installs at different times could resolve
to different cryptography versions — a reproducibility problem, not a compromised one.
`requirements.lock.txt` and `requirements-falcon.lock.txt` are the answer: exact versions
plus the SHA-256 of every file PyPI serves for them, so `pip --require-hashes` refuses
anything else.

Run it after upgrading a dependency:

    python tools/make_requirements_lock.py

It reads the versions **this interpreter** reports for the pinned packages, asks PyPI for
each version's file list, and writes both lock files beside the project root. It needs
network access and is not part of any acceptance check: the locks themselves are what the
checks use.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from importlib import metadata
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

#: The environment the harness runs in: the three direct dependencies plus the closure
#: pip resolves for them on this platform.
MAIN_PACKAGES = (
    "cryptography",
    "cffi",
    "pycparser",
    "pqcrypto",
    "pytest",
    "pluggy",
    "iniconfig",
    "packaging",
    "colorama",
    "pygments",
)

#: The optional Falcon provider. This one is an **explicit version**, not "whatever is
#: installed": 1.0.0 is what the main environment wants and 0.4.0 is the PQClean release
#: that still carries Falcon, so reading it from the interpreter would overwrite the pin
#: with the wrong release every time this script ran from the main environment.
FALCON_PACKAGES: tuple[tuple[str, str], ...] = (("pqcrypto", "0.4.0"),)

MAIN_LOCK = PROJECT_ROOT / "requirements.lock.txt"
FALCON_LOCK = PROJECT_ROOT / "requirements-falcon.lock.txt"


def distribution_files(name: str, version: str) -> list[tuple[str, str]]:
    """Return ``(filename, sha256)`` for every file PyPI publishes for this version."""
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    try:
        with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 - fixed https URL
            payload = json.load(response)
    except OSError as error:
        raise SystemExit(f"could not reach PyPI for {name}=={version}: {error}") from error
    files = [
        (entry["filename"], entry["digests"]["sha256"])
        for entry in payload.get("urls", [])
        if entry.get("digests", {}).get("sha256")
    ]
    if not files:
        raise SystemExit(f"PyPI lists no distribution files for {name}=={version}")
    return sorted(files)


def installed_versions(names: tuple[str, ...]) -> list[tuple[str, str]]:
    """Pair each name with the version this interpreter has installed."""
    versions: list[tuple[str, str]] = []
    for name in names:
        try:
            versions.append((name, metadata.version(name)))
        except metadata.PackageNotFoundError:
            raise SystemExit(
                f"{name} is not installed in this interpreter; install the pinned set first, "
                "then regenerate the lock"
            ) from None
    return versions


def write_lock(path: Path, packages: list[tuple[str, str]], header: list[str]) -> int:
    """Write one ``--require-hashes`` lock file.

    The distribution filenames go in a trailing comment block, not next to each hash:
    pip joins continued lines *before* it strips comments, so a ``#`` inside a
    requirement's continuation is read as part of the requirement.
    """
    lines = [*header, "--require-hashes", ""]
    appendix: list[str] = []
    hashed = 0
    for name, version in packages:
        files = distribution_files(name, version)
        hashed += len(files)
        lines.append(f"{name}=={version} \\")
        for index, (_filename, digest) in enumerate(files):
            continuation = "" if index == len(files) - 1 else " \\"
            lines.append(f"    --hash=sha256:{digest}{continuation}")
        lines.append("")
        appendix.append(f"#   {name}=={version}: {len(files)} files")
        for filename, _digest in files:
            appendix.append(f"#     {filename}")
    lines.append("# What the hashes above cover, so a reviewer can check the provenance of")
    lines.append("# each pinned version against PyPI without re-deriving them:")
    lines.extend(appendix)
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8", newline="\n")
    return hashed


def main() -> int:
    python = ".".join(str(part) for part in sys.version_info[:3])
    platform_note = f"{sys.platform}, Python {python}"
    main_hashed = write_lock(
        MAIN_LOCK,
        installed_versions(MAIN_PACKAGES),
        [
            "# Locked dependencies for the hybrid-tls13 harness, with hashes over every file",
            "# PyPI serves for each pinned version, so the lock is platform independent.",
            "#",
            "# Install with:  python -m pip install --require-hashes -r requirements.lock.txt",
            "# Regenerate with: python tools/make_requirements_lock.py (needs network access)",
            "#",
            f"# Versions last verified on: {platform_note}",
        ],
    )
    falcon_hashed = write_lock(
        FALCON_LOCK,
        list(FALCON_PACKAGES),
        [
            "# The optional Falcon provider: pqcrypto 0.4.0 (PQClean), installed into its own",
            "# target directory and copied to the top-level name `pqcrypto_pqclean`, because",
            "# pqcrypto 1.0.0 owns the name `pqcrypto` and ships no Falcon.",
            "# See tools/install_falcon_provider.ps1.",
        ],
    )
    print(f"{MAIN_LOCK.name}: {main_hashed} hashed files")
    print(f"{FALCON_LOCK.name}: {falcon_hashed} hashed files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
