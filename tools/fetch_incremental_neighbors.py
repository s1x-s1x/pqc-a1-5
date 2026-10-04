"""Bind a bounded set of public mechanism neighbors. No native execution."""
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    ("isa-l-sm3-x8.asm", "intel/isa-l_crypto", "f22c49aef162d7632bde4f22dc7491b22f0a7fc2", "sm3_mb/sm3_mb_x8_avx2.asm", ("TRANSPOSE8", "W16", "EXPAND")),
    ("gmssl-sm3-avx2.c", "guanzhi/GmSSL", "24ae482701a7b124826c382fffc55c19f76d475d", "src/sm3_avx2.c", ("sm3_x8_compress_blocks", "W[68]", "gather")),
    ("openssl-sm3-local.h", "openssl/openssl", "4d25710dbfeacbb36d055592a3bc6811172248b1", "crypto/sm3/sm3_local.h", ("EXPAND", "P1", "SM3")),
    ("sphincs-fors.c", "sphincs/sphincsplus", "7ec789ace6874d875f4bb84cb61b81155398167e", "sha2-avx2/fors.c", ("fors_sign", "fors_pk_from_sig", "thashx8", "compute_root")),
    ("sphincs-wots.c", "sphincs/sphincsplus", "7ec789ace6874d875f4bb84cb61b81155398167e", "sha2-avx2/wots.c", ("wots_pk_from_sig", "chain", "thashx8")),
    ("isa-l-LICENSE.txt", "intel/isa-l_crypto", "f22c49aef162d7632bde4f22dc7491b22f0a7fc2", "LICENSE", ()),
    ("gmssl-LICENSE.txt", "guanzhi/GmSSL", "24ae482701a7b124826c382fffc55c19f76d475d", "LICENSE", ()),
    ("openssl-LICENSE.txt", "openssl/openssl", "4d25710dbfeacbb36d055592a3bc6811172248b1", "LICENSE.txt", ()),
    ("sphincs-LICENSE.txt", "sphincs/sphincsplus", "7ec789ace6874d875f4bb84cb61b81155398167e", "LICENSE", ()),
)


def main():
    out = ROOT / "validation/incremental-20261005/neighbors"
    out.mkdir(parents=True, exist_ok=True)
    records = []
    for name, repo, commit, path, terms in SOURCES:
        url = f"https://raw.githubusercontent.com/{repo}/{commit}/{path}"
        destination = out / name
        if destination.exists():
            payload = destination.read_bytes()
        else:
            request = urllib.request.Request(url, headers={"User-Agent": "A1-5-mechanism-source-check"})
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = response.read()
            destination.write_bytes(payload)
        lines = payload.decode("utf-8").splitlines()
        records.append({"name": name, "repository": repo, "commit": commit,
                        "path": path, "url": url, "sha256": hashlib.sha256(payload).hexdigest(),
                        "positions": [{"line": n, "source": line.strip()}
                                      for n,line in enumerate(lines,1) if any(term in line for term in terms)]})
    manifest = {"scope": "bounded code-neighbor checks, not a global novelty search",
                "new_performance_samples": 0, "sources": records,
                "literature_gaps": ["ParaSM2 complete mechanism text", "AsicBoost complete mechanism comparison", "global patent and novelty coverage"]}
    (out / "manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
    print(json.dumps({"sources":len(records),"performance_samples":0}))


if __name__ == "__main__":
    main()
