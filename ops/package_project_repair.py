"""Package committed source and audited evidence; verify the clean extracted copy."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "pqc-a1-5/"
RECORD_NAME = "OFFLINE-PACKAGE.json"
AUDIT_SCHEMA = "a15-project-repair-local-audit-v1"
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
EXTERNAL_MANIFESTS = ("validation/optimization-external-evidence/manifest.json",
                      "validation/repair-external-evidence-r3-manifest.json")
PRIVATE_FIXTURE_NAMES = {"handshake-test-key.json", "root-test-key.pem",
                         "intermediate-test-key.pem", "leaf-test-key.pem"}
TEST_FIXTURE_ROOT = "build/repair-staging-20261004-r3/validation/real-alt-fixtures-repair-r3-parallel2"
TEST_FIXTURE_ALGORITHMS = {"slh-dsa-sm3-128-24", "slh-dsa-sm3-128s", "ml-dsa-44"}
WINDOWS_DEVICES = {"CON", "PRN", "AUX", "NUL", *("COM" + str(x) for x in range(1, 10)),
                   *("LPT" + str(x) for x in range(1, 10))}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            h.update(chunk)
    return h.hexdigest()


def member_name(name):
    """Accept one canonical portable root-relative file name."""
    require(isinstance(name, str) and bool(name), "Package path is empty")
    require(not any(ord(c) < 32 for c in name) and "\\" not in name and ":" not in name,
            "Package path has a platform-specific separator or drive")
    relative = PurePosixPath(name)
    require(bool(relative.parts) and not relative.is_absolute() and relative.as_posix() == name
            and all(part not in {".", ".."} for part in relative.parts),
            "Package path is not canonical and relative")
    require(all(not part.endswith((".", " "))
                and part.split(".", 1)[0].upper() not in WINDOWS_DEVICES
                for part in relative.parts), "Package path has a Windows alias")
    return name


def local_file(root, name):
    name = member_name(name)
    path = root.joinpath(*PurePosixPath(name).parts)
    require(path.resolve().is_relative_to(root.resolve()), "Package path leaves project root")
    cursor = path
    while cursor != root:
        require(not cursor.is_symlink(), "Package source contains a symbolic link")
        cursor = cursor.parent
    require(path.is_file(), "Package member is missing: " + name)
    return path


def hash_map(data, label):
    require(isinstance(data, dict) and bool(data), label + " is empty")
    result = {}
    for name, digest in data.items():
        member_name(name)
        require(isinstance(digest, str) and HASH_RE.fullmatch(digest), label + " SHA256 is malformed")
        result[name] = digest
    return result


def audit(root):
    command = [sys.executable, "ops/audit_project_repair.py"]
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    result = subprocess.run(command, cwd=root, check=True, capture_output=True,
                            text=True, encoding="utf-8", env=env)
    data = json.loads(result.stdout)
    require(data.get("schema") == AUDIT_SCHEMA and data.get("passed") is True,
            "Project evidence audit did not pass")
    require(type(data.get("native_calls")) is int and data["native_calls"] == 0
            and type(data.get("real_timing_samples")) is int and data["real_timing_samples"] == 0
            and data.get("formal_performance_started") is False,
            "Project evidence audit executed runtime work")
    evidence = hash_map(data.get("evidence_sha256"), "Audited evidence closure")
    require("ops/audit_project_repair.py" in evidence,
            "Audited evidence closure omits its audit tool")
    for name, digest in evidence.items():
        require(sha(local_file(root, name)) == digest, "Audited evidence differs: " + name)
    test_fixture_keys(root, data, evidence)
    return data, evidence


def test_fixture_keys(root, data, evidence):
    keys = data.get("test_fixture_keys_sha256", {})
    require(isinstance(keys, dict), "Test fixture key map is malformed")
    if not keys:
        return {}
    keys = hash_map(keys, "Test-only fixture keys")
    require(data.get("test_fixture_keys_test_only") is True, "Test fixture keys lack test_only identity")
    expected = {TEST_FIXTURE_ROOT + "/" + algorithm + "/" + name
                for algorithm in TEST_FIXTURE_ALGORITHMS for name in PRIVATE_FIXTURE_NAMES}
    require(set(keys) == expected, "Test fixture keys leave the declared fixture bundle")
    bundle_name = TEST_FIXTURE_ROOT + "/MANIFEST.json"
    require(bundle_name in evidence, "Test fixture bundle manifest absent from audited closure")
    bundle_path = local_file(root, bundle_name)
    require(sha(bundle_path) == evidence[bundle_name], "Test fixture bundle manifest differs")
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    require(bundle.get("schema") == "a15-alt-fixtures-v1" and bundle.get("test_only") is True,
            "Test fixture bundle is not marked test_only")
    fixtures = bundle.get("fixtures")
    require(isinstance(fixtures, list) and len(fixtures) == 3
            and {entry.get("algorithm") for entry in fixtures} == TEST_FIXTURE_ALGORITHMS,
            "Test fixture algorithm set differs")
    for entry in fixtures:
        algorithm = entry["algorithm"]
        name = TEST_FIXTURE_ROOT + "/" + algorithm + "/fixture.json"
        require(name in evidence and evidence[name] == entry.get("fixture_sha256"), "Test fixture manifest hash binding missing")
        path = local_file(root, name)
        require(sha(path) == evidence[name], "Test fixture manifest differs")
        fixture = json.loads(path.read_text(encoding="utf-8"))
        require(fixture.get("schema") == "a15-alt-fixture-v1" and fixture.get("test_only") is True
                and fixture.get("alt_algorithm") == algorithm, "Test fixture identity differs")
        for filename in PRIVATE_FIXTURE_NAMES:
            member = TEST_FIXTURE_ROOT + "/" + algorithm + "/" + filename
            require(keys[member] == evidence.get(member) == fixture.get("files_sha256", {}).get(filename),
                    "Test fixture key lacks manifest/hash binding")
            require(sha(local_file(root, member)) == keys[member], "Test fixture key differs from audited bytes")
    return keys


def collect(root, evidence, allowed_test_keys=None):
    allowed_test_keys = allowed_test_keys or {}
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode("utf-8").split("\0")
    paths = {member_name(name): local_file(root, name) for name in tracked if name}
    for name, digest in evidence.items():
        path = local_file(root, name)
        require(sha(path) == digest, "Audited evidence differs: " + name)
        paths[name] = path
    external_count = 0
    for name in EXTERNAL_MANIFESTS:
        manifest_path = local_file(root, name)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        require(manifest.get("schema") == "a15-external-evidence-mirror-v1",
                "External evidence manifest schema differs")
        entries = manifest.get("files")
        require(isinstance(entries, dict) and bool(entries), "External evidence manifest is empty")
        paths[name] = manifest_path
        seen = set()
        for original, entry in entries.items():
            require(isinstance(original, str) and original.startswith("/")
                    and original != "/" and not original.startswith("//")
                    and "\\" not in original and ":" not in original
                    and PurePosixPath(original).as_posix() == original
                    and all(part not in {".", ".."} for part in PurePosixPath(original).parts),
                    "External original path is not canonical")
            require(isinstance(entry, dict), "External evidence entry is malformed")
            relative = "validation/optimization-external-evidence/" + original.lstrip("/")
            require(entry.get("local_path") == relative, "External path identity differs")
            require(relative not in seen, "External evidence path is duplicated")
            seen.add(relative)
            path = local_file(root, relative)
            digest, size = entry.get("sha256"), entry.get("size_bytes")
            require(isinstance(digest, str) and HASH_RE.fullmatch(digest)
                    and type(size) is int and size >= 0, "External evidence metadata is malformed")
            require(sha(path) == digest and path.stat().st_size == size, "External bytes differ")
            paths[relative] = path
            external_count += 1
    require(RECORD_NAME not in paths, "Package metadata name is reserved")
    aliases = [name.casefold() for name in paths]
    require(len(set(aliases)) == len(aliases), "Package member names have a case alias")
    for name in paths:
        if PurePosixPath(name).name.lower() in PRIVATE_FIXTURE_NAMES:
            require(name in allowed_test_keys and evidence.get(name) == allowed_test_keys[name],
                    "Test fixture key lacks explicit test-only binding")
    files = {name: dict(sha256=sha(path), size_bytes=path.stat().st_size)
             for name, path in sorted(paths.items())}
    for name, digest in evidence.items():
        require(files[name]["sha256"] == digest, "Packaged audit closure differs: " + name)
    return paths, files, external_count


def verify_archive(path, files, record):
    expected = {PREFIX + name for name in files} | {PREFIX + RECORD_NAME}
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        require(len(names) == len(expected) and set(names) == expected,
                "Package membership differs")
        require(json.loads(archive.read(PREFIX + RECORD_NAME)) == record, "Package metadata differs")
        for name, entry in files.items():
            info = archive.getinfo(PREFIX + name)
            require(info.file_size == entry["size_bytes"], "Packaged member size differs")
            h = hashlib.sha256()
            with archive.open(info) as stream:
                for chunk in iter(lambda: stream.read(1048576), b""):
                    h.update(chunk)
            require(h.hexdigest() == entry["sha256"], "Packaged member differs")


def extract_and_audit(path, destination, files, evidence):
    project = destination / "pqc-a1-5"
    project.mkdir()
    with zipfile.ZipFile(path) as archive:
        for name in [*sorted(files), RECORD_NAME]:
            member_name(name)
            target = project.joinpath(*PurePosixPath(name).parts)
            require(target.resolve().is_relative_to(project.resolve()), "Extracted member leaves project")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(PREFIX + name) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
    _, extracted_evidence = audit(project)
    require(extracted_evidence == evidence, "Clean extracted audit closure differs")


def publish_exclusive(source, destination):
    """Create the destination exclusively, preferring atomic same-filesystem linking."""
    try:
        os.link(source, destination)
    except FileExistsError:
        raise
    except OSError:
        created = False
        try:
            with destination.open("xb") as output:
                created = True
                with source.open("rb") as stream:
                    shutil.copyfileobj(stream, output)
        except BaseException:
            if created:
                destination.unlink(missing_ok=True)
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.is_symlink(), "Choose a package filename without a symbolic link")
    output = args.output.resolve()
    sidecar = output.with_suffix(".manifest.json")
    require(output != sidecar, "Package and manifest names coincide")
    for path in (output, sidecar):
        require(not path.exists() and not path.is_symlink(), "Choose new package and manifest filenames")
    subprocess.run(["git", "diff", "--quiet"], cwd=ROOT, check=True)
    subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=ROOT, check=True)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode("ascii").strip()
    audit_data, evidence = audit(ROOT)
    allowed_test_keys = test_fixture_keys(ROOT, audit_data, evidence)
    paths, files, external_count = collect(ROOT, evidence, allowed_test_keys)
    record = dict(schema="a15-project-repair-offline-package-v1", commit=commit,
                  created_utc=datetime.now(timezone.utc).isoformat(), files=files,
                  audited_evidence_sha256=evidence, audit_schema=AUDIT_SCHEMA,
                  test_only_fixture_material=bool(allowed_test_keys), test_fixture_keys_sha256=allowed_test_keys,
                  test_fixture_material=dict(test_only=True, bundle=TEST_FIXTURE_ROOT,
                                             hash_bound_key_files=len(allowed_test_keys)),
                  real_timing_samples=0, formal_performance_started=False,
                  full_session_symbolic_search_complete=False,
                  scope="Committed source, exact audited evidence and external provenance bytes; dependencies need a matching installed environment; full-session symbolic search remains incomplete by user delivery choice.")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".a15-offline-package-", dir=output.parent) as temporary:
        work = Path(temporary).resolve()
        require(work.is_relative_to(output.parent), "Package temporary directory leaves output directory")
        archive_path = work / "package.zip"
        with zipfile.ZipFile(archive_path, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for name, path in sorted(paths.items()):
                archive.write(path, PREFIX + name)
            archive.writestr(PREFIX + RECORD_NAME, json.dumps(record, indent=2) + "\n")
        verify_archive(archive_path, files, record)
        # Keep the verified ZIP beside its eventual output for atomic publishing,
        # but extract under the short system scratch root. Deep output folders
        # combined with the declared evidence paths exceed Windows MAX_PATH.
        with tempfile.TemporaryDirectory(prefix="a15-unpack-") as unpacked:
            extract_and_audit(archive_path, Path(unpacked).resolve(), files, evidence)
        for name, entry in files.items():
            path = local_file(ROOT, name)
            require(sha(path) == entry["sha256"] and path.stat().st_size == entry["size_bytes"],
                    "Source or evidence changed while packaging: " + name)
        subprocess.run(["git", "diff", "--quiet"], cwd=ROOT, check=True)
        subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=ROOT, check=True)
        require(subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode("ascii").strip() == commit,
                "Commit changed while packaging")
        result = dict(passed=True, commit=commit, members=len(files), archive_members=len(files) + 1,
                      audited_files=len(evidence), external_entries=external_count,
                      archive_sha256=sha(archive_path), size_bytes=archive_path.stat().st_size,
                      test_only_fixture_material=bool(allowed_test_keys), hash_bound_test_key_files=len(allowed_test_keys),
                      unpacked_audit_passed=True, native_calls=0, real_timing_samples=0,
                      formal_performance_started=False, full_session_symbolic_search_complete=False)
        manifest_path = work / "package.manifest.json"
        manifest_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        published = False
        try:
            publish_exclusive(archive_path, output)
            published = True
            publish_exclusive(manifest_path, sidecar)
        except BaseException:
            if published:
                output.unlink(missing_ok=True)
            raise
    print(json.dumps(result))


if __name__ == "__main__":
    main()
