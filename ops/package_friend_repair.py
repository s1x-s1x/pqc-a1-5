"""Package version-bound engineering acceptance; never grant a timing permit."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tarfile

from audit_friend_repair import Auditor, BASELINE_SHA256, load_json, no_timing, require
from run_review_checks import ROOT, source_hashes


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            h.update(block)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for kind in ("review", "cuda", "functional"):
        parser.add_argument("--" + kind + "-run", type=Path, required=True)
    parser.add_argument("--environment-record", type=Path, required=True)
    parser.add_argument("--extra-evidence", type=Path, action="append", default=[])
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    remote = "/home/guest-experiment/pqc-a1-5"
    before = source_hashes()
    inventory = {}

    def add(path):
        path = Path(path).resolve()
        require(path.is_relative_to(ROOT) and path.is_file(), "evidence missing or outside project")
        name = path.relative_to(ROOT).as_posix()
        value = sha(path)
        require(name not in inventory or inventory[name] == value, "evidence changed while collecting")
        inventory[name] = value
        return name

    def resolve(name, directory):
        if name.startswith(remote + "/"):
            return ROOT / name[len(remote) + 1:]
        path = Path(name)
        require(not path.is_absolute(), "foreign evidence identity")
        return directory / name if "/" not in name else ROOT / name

    def manifest(path):
        add(path)
        data = load_json(path)
        no_timing(data)
        require(data.get("passed") is True, "acceptance is not passed")
        for field in ("evidence_sha256", "build_sha256"):
            for name, value in data.get(field, {}).items():
                actual = resolve(name, path.parent)
                add(actual)
                require(sha(actual) == value, "manifest artifact changed: " + name)
        if data.get("native_library_path"):
            add(ROOT / data["native_library_path"])
        return data

    inputs = {
        "review_checks": args.review_run.resolve() / "manifest.json",
        "cuda_native": args.cuda_run.resolve() / "manifest.json",
        "functional": args.functional_run.resolve() / "manifest.json",
        "environment": args.environment_record.resolve(),
    }
    records = {kind: manifest(path) for kind, path in inputs.items()}
    for path in args.extra_evidence:
        path = path.resolve()
        if path.is_dir():
            for member in sorted(path.rglob("*")):
                if member.is_file() and "__pycache__" not in member.parts:
                    add(member)
        else:
            add(path)
    out = args.output_dir.resolve()
    require(out.is_relative_to(ROOT / "validation") and not out.exists(), "choose a fresh validation directory")
    out.mkdir(parents=True)
    documentation = {p.relative_to(ROOT).as_posix(): sha(p)
        for p in [ROOT / "README.md", ROOT / ".gitattributes", ROOT / ".gitignore",
                  *(ROOT / "docs").rglob("*.md"), ROOT / "docs/plans/manifest.json"] if p.is_file()}
    sources = {**before, **documentation}
    source_record = out / "source-manifest.json"
    source_record.write_text(json.dumps(sources, indent=2, ensure_ascii=False) + "\n", encoding="utf8")
    with tarfile.open(out / "source.tar.gz", "x:gz") as archive:
        for name in sorted(sources):
            archive.add(ROOT / name, arcname=name, recursive=False)
    with tarfile.open(out / "source.tar.gz", "r:gz") as archive:
        for member in archive.getmembers():
            stream = archive.extractfile(member)
            require(member.isfile() and stream is not None and
                hashlib.sha256(stream.read()).hexdigest() == sources[member.name], "source archive identity differs")
    (out / "REVIEW.md").write_text(
        "# Engineering acceptance snapshot\n\n"
        "Current targeted regression/native/functional/environment evidence plus unchanged historical matrices.\n"
        "CPU full3471 and CUDA full1789 remain historical; this does not claim their reexecution.\n"
        "Formal performance samples: 0. Full-session symbolic verdicts: 0 (accepted incomplete).\n"
        "No formal timing permit is published by this package. Old freeze hash gates remain enforced.\n", encoding="utf8")
    for path in (source_record, out / "source.tar.gz", out / "REVIEW.md"):
        add(path)
    require(before == source_hashes() and all(sha(ROOT / name) == value for name, value in sources.items()),
            "source changed while packaging")
    require(all(sha(ROOT / name) == value for name, value in inventory.items()), "evidence changed while packaging")
    checkpoint = dict(schema="a15-friend-repair-checkpoint-v1", scope="engineering-delta",
        created_utc=datetime.now(timezone.utc).isoformat(), baseline_sha256=BASELINE_SHA256,
        remote_root=remote, local_root=".", formal_performance_started=False, real_timing_samples=0,
        performance_authorized=False, current_full_matrix_reexecuted=False,
        source_sha256=before, document_sha256=documentation, evidence_sha256=inventory,
        full_session_verdicts=0, accepted_incomplete=["full-session symbolic search"],
        **{kind: path.relative_to(ROOT).as_posix() for kind, path in inputs.items()})
    (out / "checkpoint.json").write_text(json.dumps(checkpoint, indent=2, ensure_ascii=False) + "\n", encoding="utf8")
    auditor = Auditor()
    audit = auditor.audit((out / "checkpoint.json").relative_to(ROOT).as_posix())
    (out / "audit.json").write_text(json.dumps(audit, indent=2, ensure_ascii=False) + "\n", encoding="utf8")
    package = dict(schema="a15-friend-repair-package-v1", engineering_acceptance_passed=audit["passed"],
        performance_authorized=False, files_sha256={p.name: sha(p) for p in sorted(out.iterdir()) if p.is_file()})
    (out / "package.json").write_text(json.dumps(package, indent=2) + "\n", encoding="utf8")
    print(json.dumps(dict(passed=audit["passed"], errors=audit["errors"], checks=len(audit["checks"]), real_timing_samples=0)))
    return int(not audit["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
