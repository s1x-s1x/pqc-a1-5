"""Package a checked incremental handoff; no native execution or measurement."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FINAL = ROOT / "validation/incremental-20261005/final"
STEM = "A1-5_增量优化_性能前交付_20261005"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--delivery-dir", type=Path, default=ROOT.parent / "交付")
    args = parser.parse_args()
    delivery = args.delivery_dir.resolve()
    delivery.mkdir(parents=True, exist_ok=True)
    output = delivery / (STEM + ".zip")
    note = delivery / (STEM + ".md")
    manifest_path = delivery / (STEM + ".manifest.json")
    if any(path.exists() for path in (output, note, manifest_path)):
        raise ValueError("preserve existing delivery and use a fresh directory")
    subprocess.run([sys.executable, "-B", "tools/freeze_incremental.py", "--check"], cwd=ROOT, check=True)
    freeze = json.loads((FINAL / "freeze.json").read_text())
    sources = json.loads((FINAL / "source-manifest.json").read_text())
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    paper_record = json.loads((delivery / "A1-5_论文交付核验_20261004.json").read_text(encoding="utf-8-sig"))
    papers = {name: sha(delivery / name) for name in paper_record["files"]}
    if papers != paper_record["files"]:
        raise ValueError("paper/LaTeX delivery identity differs from the accepted version")
    evidence = {name: digest for name, digest in freeze["evidence_sha256"].items()
                if name not in freeze["artifact_sha256"]}
    members = dict(sources)
    members.update(evidence)
    for name in ("freeze.json", "source-manifest.json", "source.zip", "artifacts.zip"):
        relative = (FINAL / name).relative_to(ROOT).as_posix()
        members[relative] = sha(FINAL / name)
    for name, expected in members.items():
        if sha(ROOT / name) != expected:
            raise ValueError("delivery input hash changed: " + name)
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(members):
            entry = zipfile.ZipInfo(name, date_time=(2026, 10, 5, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, (ROOT / name).read_bytes())
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None or set(archive.namelist()) != set(members):
            raise ValueError("delivery ZIP CRC/inventory differs")
        for name, expected in members.items():
            if hashlib.sha256(archive.read(name)).hexdigest() != expected:
                raise ValueError("delivery ZIP member hash differs: " + name)
    handoff = (ROOT / "docs/research/HANDOFF_20261005.md").read_text(encoding="utf-8")
    note.write_text(handoff + "\n## 交付身份\n\n" +
                    f"项目提交：`{commit}`。ZIP 为本轮增量源码、配置与证据包；完整基础项目取自指定 GitHub 仓库该提交。\n\n" +
                    "在完整 checkout 上合入本包后，执行 `python -B tools/freeze_incremental.py --check` 复核。保留编译产物及缓存由 artifacts.zip 只读核对，日常复核无需重签或计时。\n\n" +
                    f"交付 ZIP SHA-256：`{sha(output)}`。论文/PDF/LaTeX 本轮无改动。\n", encoding="utf-8")
    value = {"schema": "a15-incremental-delivery-v1", "project_commit": commit,
             "correctness_passed": True, "new_performance_samples": 0,
             "performance_enabled": False, "execution_permit": False,
             "paper_unchanged": True, "paper_sha256": papers,
             "zip_crc_and_member_hashes_checked": True, "archive_member_count": len(members),
             "scope": "incremental source and evidence overlay on the full repository commit",
             "files": {output.name: sha(output), note.name: sha(note)}, "members_sha256": members}
    manifest_path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"passed": True, "project_commit": commit, "members": len(members),
                      "archive_bytes": output.stat().st_size, "new_performance_samples": 0,
                      "paper_unchanged": True}, ensure_ascii=True))


if __name__ == "__main__":
    main()
