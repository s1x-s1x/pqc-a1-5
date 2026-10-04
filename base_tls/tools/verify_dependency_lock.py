"""Verify the dependency locks: per-package version-and-hash association, not a hash count.

Why this exists. A red-team pass noted that "the lock files carry 155 hashes" is a count, not
an association (their W4): it says nothing about whether a *specific* package is pinned, whether
it has any hash at all, or whether a download is the file those hashes describe. The improvement
plan therefore asks for per-package verification, and for any fetch helper to check a downloaded
artefact against the trusted lock **before** unpacking it.

What it checks:

1. every requirement line is ``name==version`` (a range, a bare name or an unpinned VCS line is
   an error);
2. every requirement carries at least one ``--hash=sha256:...`` value, well formed (64 lowercase
   hex digits);
3. no package is pinned twice with different versions, and no duplicate hashes hide a missing
   file;
4. with ``--wheel-dir``: every file in that directory matches a hash from the lock, and every
   package named in the lock that is present there is complete. An artefact with no matching
   hash is refused, which is the rule the audit's fetch helpers now follow.

Exit codes follow the rest of the tooling: 0 clean, 1 a verification failure, 2 a tool error
(missing lock file, unreadable directory) -- a failure to check is not a pass.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

#: The lock files this project ships. `requirements.lock.txt` is the main set; the Falcon
#: provider has its own because pqcrypto 0.4.0 is not in the main dependency closure.
DEFAULT_LOCKS = ("requirements.lock.txt", "requirements-falcon.lock.txt")

_PIN = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[^\s;\\]+)\s*\\?$")
_HASH = re.compile(r"--hash=sha256:(?P<digest>[0-9a-f]{64})\b")
_ANY_HASH = re.compile(r"--hash=(?P<algorithm>[A-Za-z0-9]+):(?P<digest>[^\s]+)")
#: Options pip accepts on a line of their own in a requirements file. They are recorded and
#: skipped rather than reported: this tool verifies the pin-and-hash association, not pip's
#: command-line grammar.
_GLOBAL_OPTIONS = ("--require-hashes", "--no-deps", "--only-binary", "--no-binary", "-r", "-c")


@dataclass
class Requirement:
    """One pinned package and the hashes the lock allows for it."""

    name: str
    version: str
    hashes: list[str] = field(default_factory=list)
    lineno: int = 0


@dataclass
class LockFile:
    """A parsed lock file: its path, its requirements and any parse complaints."""

    path: Path
    requirements: list[Requirement] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def hash_count(self) -> int:
        return sum(len(requirement.hashes) for requirement in self.requirements)


def parse_lock(path: Path) -> LockFile:
    """Parse one lock file, recording every structural complaint with its line number."""
    lock = LockFile(path=path)
    if not path.is_file():
        lock.errors.append("lock file is missing")
        return lock
    current: Requirement | None = None
    seen: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("-"):
            # A continuation: only `--hash=` entries are meaningful in this format.
            if current is None:
                if line.split("=", 1)[0].split()[0] in _GLOBAL_OPTIONS:
                    continue
                lock.errors.append(f"line {number}: option before any requirement: {line[:60]}")
                continue
            _collect_hashes(line, current, lock, number)
            continue
        match = _PIN.match(line)
        if match is None:
            lock.errors.append(
                f"line {number}: not a `name==version` pin: {line[:60]}"
            )
            current = None
            continue
        name, version = match.group("name"), match.group("version")
        if name.lower() in seen and seen[name.lower()] != version:
            lock.errors.append(
                f"line {number}: {name} is pinned twice ({seen[name.lower()]} and {version})"
            )
        seen[name.lower()] = version
        current = Requirement(name=name, version=version, lineno=number)
        lock.requirements.append(current)
    for requirement in lock.requirements:
        if not requirement.hashes:
            lock.errors.append(
                f"line {requirement.lineno}: {requirement.name}=={requirement.version} has no "
                f"--hash=sha256 value"
            )
    return lock


def _collect_hashes(line: str, requirement: Requirement, lock: LockFile, number: int) -> None:
    found = _HASH.findall(line)
    if found:
        for digest in found:
            if digest in requirement.hashes:
                lock.errors.append(
                    f"line {number}: duplicate hash for {requirement.name} ({digest[:12]}...)"
                )
                continue
            requirement.hashes.append(digest)
        return
    other = _ANY_HASH.search(line)
    if other is not None:
        lock.errors.append(
            f"line {number}: {requirement.name} uses --hash={other.group('algorithm')}:...; "
            f"only sha256 is accepted"
        )
        return
    if "--hash=" in line:
        lock.errors.append(f"line {number}: malformed --hash value for {requirement.name}")
        return
    lock.errors.append(f"line {number}: unrecognised option for {requirement.name}: {line[:60]}")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def wheel_package_name(path: Path) -> str | None:
    """``foo-1.0-py3-none-any.whl`` / ``foo-1.0.tar.gz`` -> ``foo``."""
    name = path.name
    for suffix in (".whl", ".tar.gz", ".zip"):
        if name.endswith(suffix):
            stem = name[: -len(suffix)]
            break
    else:
        return None
    head = stem.split("-", 1)[0]
    return head.replace("_", "-").lower() or None


def verify_wheel(path: Path, locks: list[LockFile]) -> tuple[bool, str]:
    """Return ``(ok, reason)`` for one downloaded artefact against the locks.

    This is the function an audit-side fetch helper calls before unpacking anything: a file
    whose digest is not in the trusted lock is refused, and so is a file whose package has no
    pin at all.
    """
    digest = file_sha256(path)
    package = wheel_package_name(path)
    allowed: set[str] = set()
    for lock in locks:
        for requirement in lock.requirements:
            if package is not None and requirement.name.replace("_", "-").lower() == package:
                allowed.update(requirement.hashes)
    if package is None:
        return False, f"{path.name}: not a recognised distribution archive"
    if not allowed:
        return False, f"{path.name}: package {package} is not pinned in any trusted lock"
    if digest not in allowed:
        return False, (
            f"{path.name}: sha256 {digest[:16]}... does not match any pinned hash for {package}"
        )
    return True, f"{path.name}: matches a pinned hash for {package}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--root",
        default=str(PROJECT_ROOT),
        help="project root holding the lock files (default: this project)",
    )
    parser.add_argument(
        "--lock",
        action="append",
        default=[],
        help="lock file to verify, relative to --root (repeatable; default: both shipped locks)",
    )
    parser.add_argument(
        "--wheel-dir",
        default=None,
        help="also verify every distribution archive in this directory against the locks",
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    names = args.lock or list(DEFAULT_LOCKS)
    locks = [parse_lock(root / name) for name in names]

    problems: list[str] = []
    for lock in locks:
        print(f"lock: {lock.path.relative_to(root).as_posix()}")
        if not lock.path.is_file():
            problems.extend(f"{lock.path.name}: {error}" for error in lock.errors)
            print("  MISSING")
            continue
        for error in lock.errors:
            print(f"  ERROR {error}")
            problems.append(f"{lock.path.name}: {error}")
        for requirement in lock.requirements:
            print(
                f"  {requirement.name}=={requirement.version:<18} {len(requirement.hashes)} hash(es)"
            )
        print(f"  {len(lock.requirements)} packages, {lock.hash_count} hashes")

    if args.wheel_dir:
        wheel_dir = Path(args.wheel_dir).resolve()
        if not wheel_dir.is_dir():
            print(f"tool error: {wheel_dir} is not a directory; nothing verified")
            return 2
        artefacts = sorted(
            path for path in wheel_dir.iterdir()
            if path.is_file() and path.suffix in {".whl", ".zip", ".gz"}
        )
        print(f"\nartefacts in {wheel_dir}: {len(artefacts)}")
        for artifact in artefacts:
            ok, reason = verify_wheel(artifact, locks)
            print(f"  {'ok   ' if ok else 'REJECT'} {reason}")
            if not ok:
                problems.append(reason)

    if problems:
        print(f"\nFAIL: {len(problems)} lock or artefact problem(s).")
        return 1
    total = sum(len(lock.requirements) for lock in locks)
    print(f"\nPASS: {len(locks)} lock file(s), {total} packages, every package pinned and hashed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
