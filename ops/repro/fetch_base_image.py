"""Fetch the pinned linux/amd64 base as a verified Docker load archive.

Useful when a server's configured registry mirror rejects immutable manifests.
No daemon configuration is changed. Each registry blob and its unpacked diff_id
are checked before publishing the archive and identity record.
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import urllib.request

INDEX = "sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed"
TAG = "a15-python-base:locked-5024f48b"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.with_suffix(".identity.json").exists():
        parser.error("choose a fresh archive path")
    with urllib.request.urlopen("https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/python:pull", timeout=30) as response:
        token = json.load(response)["token"]
    def get(kind, digest):
        request = urllib.request.Request("https://registry-1.docker.io/v2/library/python/" + kind + "/" + digest,
            headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.oci.image.index.v1+json,application/vnd.oci.image.manifest.v1+json", "User-Agent": "A1-5-repro"})
        with urllib.request.urlopen(request, timeout=90) as response:
            value = response.read()
        if "sha256:" + hashlib.sha256(value).hexdigest() != digest:
            raise ValueError("registry content digest differs")
        return value
    index = json.loads(get("manifests", INDEX))
    candidates = [x for x in index["manifests"] if x.get("platform") == {"architecture": "amd64", "os": "linux"}]
    if len(candidates) != 1:
        raise ValueError("pinned amd64 manifest is ambiguous")
    manifest_digest = candidates[0]["digest"]
    manifest = json.loads(get("manifests", manifest_digest))
    config_digest = manifest["config"]["digest"]
    config_bytes = get("blobs", config_digest)
    config = json.loads(config_bytes)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="a15-base-") as temporary:
        directory = Path(temporary)
        config_name = config_digest.split(":")[1] + ".json"
        (directory / config_name).write_bytes(config_bytes)
        layers = []
        if len(config["rootfs"]["diff_ids"]) != len(manifest["layers"]):
            raise ValueError("layer/diff identity length differs")
        for layer, diff in zip(manifest["layers"], config["rootfs"]["diff_ids"]):
            value = get("blobs", layer["digest"])
            if layer["mediaType"].endswith("+gzip"):
                value = gzip.decompress(value)
            elif not layer["mediaType"].endswith(".tar"):
                raise ValueError("unsupported pinned layer media type")
            if "sha256:" + hashlib.sha256(value).hexdigest() != diff:
                raise ValueError("unpacked layer identity differs")
            name = diff.split(":")[1] + "/layer.tar"
            path = directory / name
            path.parent.mkdir()
            path.write_bytes(value)
            layers.append(name)
        (directory / "manifest.json").write_text(json.dumps([dict(Config=config_name, RepoTags=[TAG], Layers=layers)]), encoding="utf-8")
        with tarfile.open(args.output, "x:gz") as archive:
            for path in [directory / config_name, directory / "manifest.json", *(directory / name for name in layers)]:
                archive.add(path, arcname=path.relative_to(directory).as_posix(), recursive=False)
    record = dict(schema="a15-pinned-base-image-v1", index_digest=INDEX, platform_manifest_digest=manifest_digest,
                  image_config_digest=config_digest, local_tag=TAG, platform="linux/amd64", diff_ids=config["rootfs"]["diff_ids"],
                  archive_sha256=hashlib.sha256(args.output.read_bytes()).hexdigest(), bytes=args.output.stat().st_size)
    args.output.with_suffix(".identity.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record))


if __name__ == "__main__":
    main()
