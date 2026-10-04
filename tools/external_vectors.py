"""Acquire pinned independent vectors and check the native public ABI."""

import argparse
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import tarfile
import time
import urllib.request

try:
    from .native import NativeSlhDsa
except ImportError:
    from native import NativeSlhDsa


ROOT = Path(__file__).resolve().parents[1]
EXTERNAL = ROOT / "third_party" / "external_vectors"
ACVP_COMMIT = "1c859956c0217b04fa5ae76e338e5570aba622c5"
XOUS_COMMIT = "f239b847d9d864d7ee19651a7d29acd4f7104921"
GMSM_COMMIT = "84294d95666c7b628a45896b2ab068081591ef27"
GO_VERSION = "go1.27.1"
GO_SHA256 = "63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445"


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def download(url, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "pqc-a1-5-vector-audit"})
    with urllib.request.urlopen(request, timeout=120) as response, path.open("wb") as output:
        shutil.copyfileobj(response, output)
    return sha256(path)


def acquire():
    records = []
    upstream = ROOT / "third_party" / "py-acvp-pqc" / "json-copy"
    for operation in ("keyGen", "sigGen", "sigVer"):
        name = "SLH-DSA-" + operation + "-FIPS205"
        for file in ("prompt.json", "expectedResults.json", "internalProjection.json"):
            source, destination = upstream / name / file, EXTERNAL / "acvp" / name / file
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            records.append({"path": str(destination.relative_to(ROOT)), "sha256": sha256(destination),
                "url": f"https://raw.githubusercontent.com/mjosaarinen/py-acvp-pqc/{ACVP_COMMIT}/json-copy/{name}/{file}",
                "origin": "NIST ACVP-Server/gen-val/json-files, pinned public mirror"})
    base = "bao1x-boot/slh-dsa-kat/"
    for file in ("vectors/vec_sphincs-sha2-128-24.txt", "vectors/sig_sphincs-sha2-128-24.hex",
                 "slh_kat.c", "params/params-sphincs-sha2-128-24.h", "build_vectors.sh", "base_2b.patch"):
        destination = EXTERNAL / "xous" / file
        url = f"https://raw.githubusercontent.com/betrusted-io/xous-core/{XOUS_COMMIT}/{base}{file}"
        records.append({"path": str(destination.relative_to(ROOT)), "sha256": download(url, destination), "url": url})
    write_json(EXTERNAL / "SOURCES.json", {"schema": "a15-external-sources-v1", "acvp_mirror_commit": ACVP_COMMIT,
        "xous_commit": XOUS_COMMIT, "xous_pull_request": "https://github.com/betrusted-io/xous-core/pull/1002",
        "note": "The xous vector producer uses SPHINCS+ internal messages; no pure-mode prefix is added.", "files": records})
    print(json.dumps({"phase": "acquire", "files": len(records)}), flush=True)


def install_go():
    runtime = ROOT / "runtime"
    archive = runtime / (GO_VERSION + ".linux-amd64.tar.gz")
    if not archive.exists() or sha256(archive) != GO_SHA256:
        download(f"https://go.dev/dl/{archive.name}", archive)
    if sha256(archive) != GO_SHA256:
        raise ValueError("Go archive checksum mismatch")
    with tarfile.open(archive) as bundle:
        for member in bundle.getmembers():
            target = (runtime / member.name).resolve()
            if not target.is_relative_to(runtime.resolve()):
                raise ValueError("Go archive path escapes runtime")
        bundle.extractall(runtime)
    url = f"https://codeload.github.com/emmansun/gmsm/tar.gz/{GMSM_COMMIT}"
    source_archive = EXTERNAL / "gmsm-v0.44.1.tar.gz"
    archive_hash = download(url, source_archive)
    parent = ROOT / "third_party"
    with tarfile.open(source_archive) as bundle:
        for member in bundle.getmembers():
            target = (parent / member.name).resolve()
            if not target.is_relative_to(parent.resolve()):
                raise ValueError("gmsm archive path escapes third_party")
        bundle.extractall(parent)
    extracted = parent / ("gmsm-" + GMSM_COMMIT)
    destination = parent / "gmsm"
    if destination.exists():
        raise FileExistsError("gmsm destination exists; preserve it and reuse the pinned source")
    extracted.rename(destination)
    records = {str(path.relative_to(destination)): sha256(path) for path in sorted(destination.rglob("*")) if path.is_file()}
    write_json(EXTERNAL / "GMSM_SOURCE.json", {"repository": "https://github.com/emmansun/gmsm", "tag": "v0.44.1",
        "commit": GMSM_COMMIT, "archive_sha256": archive_hash, "go_version": GO_VERSION,
        "go_archive_sha256": GO_SHA256, "files_sha256": records})
    print(json.dumps({"phase": "go-installed", "version": GO_VERSION, "gmsm_commit": GMSM_COMMIT}), flush=True)


def load_acvp():
    cases, inputs = [], {}
    for operation in ("keyGen", "sigGen", "sigVer"):
        directory = EXTERNAL / "acvp" / ("SLH-DSA-" + operation + "-FIPS205")
        documents = {}
        for name in ("prompt.json", "expectedResults.json", "internalProjection.json"):
            path = directory / name
            documents[name] = json.loads(path.read_text())
            inputs[str(path.relative_to(ROOT))] = sha256(path)
        expected = {(group["tgId"], test["tcId"]): test
                    for group in documents["expectedResults.json"]["testGroups"] for test in group["tests"]}
        projections = {(group["tgId"], test["tcId"]): test
                       for group in documents["internalProjection.json"]["testGroups"] for test in group["tests"]}
        for group in documents["prompt.json"]["testGroups"]:
            pid = {"SLH-DSA-SHA2-128s": 101, "SLH-DSA-SHA2-128f": 102}.get(group["parameterSet"])
            if pid is None:
                continue
            for question in group["tests"]:
                key = group["tgId"], question["tcId"]
                test = {**question, **expected[key]}
                if operation == "sigVer":
                    test.update(projections[key])
                    test["pk"] = question["pk"]
                cases.append({"suite": "acvp", "operation": operation, "pid": pid,
                    "group": {k: v for k, v in group.items() if k != "tests"}, "test": test})
    if len(cases) != 208:
        raise ValueError(f"Pinned SHA2-128s/128f scope changed: {len(cases)}")
    return cases, inputs


PREHASH = {
    "SHA2-256": (1, "sha256", None), "SHA2-384": (2, "sha384", None),
    "SHA2-512": (3, "sha512", None), "SHA2-224": (4, "sha224", None),
    "SHA2-512/224": (5, "sha512_224", None), "SHA2-512/256": (6, "sha512_256", None),
    "SHA3-224": (7, "sha3_224", None), "SHA3-256": (8, "sha3_256", None),
    "SHA3-384": (9, "sha3_384", None), "SHA3-512": (10, "sha3_512", None),
    "SHAKE-128": (11, "shake_128", 32), "SHAKE-256": (12, "shake_256", 64),
}


def encoded_message(group, test):
    message = bytes.fromhex(test["message"])
    if group["signatureInterface"] == "internal":
        return message
    context = bytes.fromhex(test["context"])
    if len(context) > 255:
        raise ValueError("ACVP context length exceeds FIPS 205 maximum")
    if group.get("preHash") != "preHash":
        return b"\0" + bytes([len(context)]) + context + message
    number, algorithm, xof_bytes = PREHASH[test["hashAlg"]]
    hash_object = hashlib.new(algorithm, message)
    digest = hash_object.digest() if xof_bytes is None else hash_object.digest(xof_bytes)
    oid = bytes.fromhex("06096086480165030402") + bytes([number])
    return b"\1" + bytes([len(context)]) + context + oid + digest


def run_case(case):
    started = time.perf_counter()
    result = {k: case[k] for k in ("suite", "operation", "pid")}
    group, test = case["group"], case["test"]
    result.update({"tgId": group.get("tgId"), "tcId": test["tcId"]})
    decode = lambda key: bytes.fromhex(test[key])
    try:
        with NativeSlhDsa(case["pid"], threads=1, flags=1) as model:
            operation = case["operation"]
            if operation == "keyGen":
                pk, sk = model.keygen_internal(decode("skSeed"), decode("skPrf"), decode("pkSeed"))
                result["pk_equal"] = pk == decode("pk")
                result["sk_equal"] = sk == decode("sk")
                passed = result["pk_equal"] and result["sk_equal"]
            else:
                encoded = encoded_message(group, test)
                if operation == "sigGen":
                    randomizer = None if group["deterministic"] else decode("additionalRandomness")
                    signature = model.sign_internal(encoded, decode("sk"), randomizer)
                    result["expected_signature_sha256"] = hashlib.sha256(decode("signature")).hexdigest()
                    result["actual_signature_sha256"] = hashlib.sha256(signature).hexdigest()
                    passed = signature == decode("signature")
                else:
                    actual = model.verify_internal(encoded, decode("signature"), decode("pk"))
                    result["expected"], result["actual"] = test["testPassed"], actual
                    passed = actual == test["testPassed"]
            result["passed"] = passed
    except Exception as error:
        result.update({"passed": False, "error": f"{type(error).__name__}: {error}"})
    result["seconds"] = time.perf_counter() - started
    return result


def xous_verify():
    metadata_path = EXTERNAL / "xous" / "vectors" / "vec_sphincs-sha2-128-24.txt"
    signature_path = metadata_path.with_name("sig_sphincs-sha2-128-24.hex")
    fields = dict(line.split("=", 1) for line in metadata_path.read_text().splitlines() if "=" in line)
    fields = {key.strip(): value.strip() for key, value in fields.items()}
    signature = bytes.fromhex(signature_path.read_text())
    if hashlib.sha256(signature).hexdigest() != fields["sig_digest"]:
        raise ValueError("xous signature digest mismatch")
    case = {"suite": "xous-128-24", "operation": "sigVer", "pid": 103,
        "group": {"signatureInterface": "internal", "tgId": 1},
        "test": {"tcId": 1, "pk": fields["pk"], "message": fields["message_hex"],
                 "signature": signature.hex(), "testPassed": True}}
    return [case], {str(path.relative_to(ROOT)): sha256(path) for path in (metadata_path, signature_path)}


def xous_full_cases():
    cases, inputs = xous_verify()
    verify_case = cases[0]
    metadata_path = EXTERNAL / "xous" / "vectors" / "vec_sphincs-sha2-128-24.txt"
    fields = dict(line.split("=", 1) for line in metadata_path.read_text().splitlines() if "=" in line)
    fields = {key.strip(): value.strip() for key, value in fields.items()}
    sk = fields["sk_seed"] + fields["sk_prf"] + fields["pk"]
    keygen_case = {"suite": "xous-128-24", "operation": "keyGen", "pid": 103, "group": {},
        "test": {"tcId": 1, "skSeed": fields["sk_seed"], "skPrf": fields["sk_prf"],
            "pkSeed": fields["pk_seed"], "pk": fields["pk"], "sk": sk}}
    siggen_case = {"suite": "xous-128-24", "operation": "sigGen", "pid": 103,
        "group": {"signatureInterface": "internal", "deterministic": False},
        "test": {**verify_case["test"], "sk": sk, "additionalRandomness": fields["opt_rand"]}}
    return [keygen_case, siggen_case, verify_case], inputs


def gmsm_cases(path):
    vectors = json.loads(Path(path).read_text())
    cases = []
    for vector in vectors["cases"]:
        pid = vector["pid"]
        test = {**vector, "tcId": vector["index"]}
        seeds = bytes.fromhex(test["seeds"])
        test.update({"skSeed": seeds[:16].hex(), "skPrf": seeds[16:32].hex(), "pkSeed": seeds[32:].hex()})
        cases.append({"suite": "gmsm", "operation": "keyGen", "pid": pid, "group": {}, "test": test})
        for mode in ("deterministic", "randomized"):
            cases.append({"suite": "gmsm", "operation": "sigGen", "pid": pid,
                "group": {"signatureInterface": "external", "preHash": "pure", "deterministic": mode == "deterministic"},
                "test": {**test, "signature": test[mode + "Signature"]}})
            cases.append({"suite": "gmsm", "operation": "sigVer", "pid": pid,
                "group": {"signatureInterface": "external", "preHash": "pure"},
                "test": {**test, "signature": test[mode + "Signature"], "testPassed": True}})
            bad_signature = bytearray.fromhex(test[mode + "Signature"])
            bad_signature[(vector["index"] * 313) % len(bad_signature)] ^= 1
            cases.append({"suite": "gmsm-tamper", "operation": "sigVer", "pid": pid,
                "group": {"signatureInterface": "external", "preHash": "pure"},
                "test": {**test, "signature": bad_signature.hex(), "testPassed": False}})
    return cases, {str(Path(path).relative_to(ROOT)): sha256(path)}


def validate(suite, workers, output, gmsm_path):
    started = time.perf_counter()
    if suite == "acvp":
        cases, inputs = load_acvp()
    elif suite == "xous":
        cases, inputs = xous_verify()
    else:
        cases, inputs = gmsm_cases(gmsm_path)
    print(json.dumps({"phase": "start", "suite": suite, "total": len(cases), "workers": workers}), flush=True)
    with ProcessPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(run_case, cases, chunksize=1))
    with NativeSlhDsa(102) as model:
        library_path = Path(model.library_path)
    counts = {}
    for result in results:
        label = f"{result['pid']}/{result['suite']}/{result['operation']}"
        count = counts.setdefault(label, {"total": 0, "passed": 0})
        count["total"] += 1
        count["passed"] += int(result["passed"])
    summary = {"schema": "a15-native-external-v1", "suite": suite, "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "total": len(results), "passed": sum(item["passed"] for item in results),
        "failed": sum(not item["passed"] for item in results), "workers": workers,
        "elapsed_seconds": time.perf_counter() - started, "counts": counts,
        "library_sha256": sha256(library_path), "sources_sha256": inputs, "results": results,
        "scope": "Reference backend. Pure mode uses public/internal encoding; prehash uses independently encoded M' and internal ABI."}
    write_json(output, summary)
    print(json.dumps({key: value for key, value in summary.items() if key not in ("results", "sources_sha256")}), flush=True)
    return int(summary["failed"] != 0)


def verify_sources():
    """Verify pinned files through Git blob IDs without modifying tested inputs."""
    sources = json.loads((EXTERNAL / "SOURCES.json").read_text())
    repositories = {
        "acvp": ("mjosaarinen/py-acvp-pqc", ACVP_COMMIT),
        "xous": ("betrusted-io/xous-core", XOUS_COMMIT),
    }
    trees = {}
    tree_sources = {}
    for name, (repository, commit) in repositories.items():
        url = f"https://api.github.com/repos/{repository}/git/trees/{commit}?recursive=1"
        cached = EXTERNAL / ("api-tree-" + name + ".json")
        if not cached.exists():
            download(url, cached)
        tree = json.loads(cached.read_text())
        if tree.get("truncated"):
            raise ValueError(f"Git tree is truncated: {repository}")
        trees[name] = {item["path"]: item["sha"] for item in tree["tree"] if item["type"] == "blob"}
        tree_sources[name] = {"url": url, "path": str(cached.relative_to(ROOT)), "sha256": sha256(cached)}
    results = []
    for record in sources["files"]:
        url = record["url"]
        repository = "acvp" if "py-acvp-pqc" in url else "xous"
        commit = repositories[repository][1]
        remote_path = url.split("/" + commit + "/", 1)[1]
        relative_path = record["path"].replace("\\", "/")
        path = ROOT / relative_path
        data = path.read_bytes()
        blob_hash = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        lf_data = data.replace(b"\r\n", b"\n")
        lf_blob_hash = hashlib.sha1(b"blob " + str(len(lf_data)).encode() + b"\0" + lf_data).hexdigest()
        expected_blob = trees[repository][remote_path]
        results.append({"path": relative_path, "sha256": sha256(path), "git_blob_sha1": blob_hash,
            "expected_git_blob_sha1": expected_blob, "commit": commit,
            "lf_normalized_git_blob_sha1": lf_blob_hash,
            "lf_normalized_sha256": hashlib.sha256(lf_data).hexdigest(),
            "identity_mode": "raw-bytes" if blob_hash == expected_blob else "CRLF-to-LF-only",
            "passed": (blob_hash == expected_blob or lf_blob_hash == expected_blob)
                      and sha256(path) == record["sha256"]})
    output = {"schema": "a15-pinned-source-check-v1", "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "total": len(results), "passed": sum(row["passed"] for row in results),
        "failed": sum(not row["passed"] for row in results), "git_tree_sources": tree_sources, "results": results}
    write_json(ROOT / "validation" / "external-source-check.json", output)
    print(json.dumps({key: value for key, value in output.items() if key != "results"}), flush=True)
    return int(output["failed"] != 0)


def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as output:
        for row in rows:
            output.write(json.dumps(row, separators=(",", ":"), ensure_ascii=False) + "\n")
    temporary.replace(path)


def export_evidence(gmsm_path):
    """Export already completed results; this command runs no crypto operations."""
    exported = datetime.now(timezone.utc).isoformat()
    with NativeSlhDsa(102) as native:
        current_library_hash = sha256(native.library_path)
    source_check_path = ROOT / "validation" / "external-source-check.json"
    source_check = json.loads(source_check_path.read_text()) if source_check_path.exists() else None
    sets = []
    for label, suite, loader in (("A", "acvp", load_acvp), ("B", "xous", xous_verify),
                                 ("C", "gmsm", lambda: gmsm_cases(gmsm_path))):
        original_path = ROOT / "validation" / ("external-" + suite + ".json")
        prior_verify = None
        full_path = ROOT / "validation" / "external-xous-full.json"
        if suite == "xous" and full_path.exists() and json.loads(full_path.read_text()).get("total") == 3:
            prior_verify = {"path": str(original_path.relative_to(ROOT)), "sha256": sha256(original_path)}
            original_path, loader = full_path, xous_full_cases
        original = json.loads(original_path.read_text())
        if suite == "xous" and prior_verify:
            original["results"] = [{"suite": "xous-128-24", "pid": 103, "tcId": 1, **result}
                                   for result in original["results"]]
            original["counts"] = {f"103/xous-128-24/{row['operation']}": {"total": 1, "passed": int(row["passed"])}
                                  for row in original["results"]}
        cases, inputs = loader()
        if inputs != original["sources_sha256"]:
            raise ValueError(f"Input files changed after {suite} validation")
        if current_library_hash != original["library_sha256"]:
            raise ValueError(f"Current library changed after {suite} validation")
        if len(cases) != len(original["results"]):
            raise ValueError(f"Unexpected {suite} result count")
        input_rows, result_rows = [], []
        for index, (case, result) in enumerate(zip(cases, original["results"]), 1):
            for key in ("suite", "operation", "pid"):
                if case[key] != result[key]:
                    raise ValueError(f"{suite} result ordering changed at {index}")
            if case["test"]["tcId"] != result["tcId"]:
                raise ValueError(f"{suite} test identifier changed at {index}")
            case_id = f"{label}-{index:04d}"
            input_rows.append({"schema": "a15-external-input-v1", "vector_set": label, "case_id": case_id, **case})
            result_rows.append({"schema": "a15-external-result-v1", "vector_set": label, "case_id": case_id,
                "executed_at_utc": original["generated_at_utc"], "library_sha256": original["library_sha256"], **result})
        input_path = ROOT / "vectors" / ("external-" + suite + "-inputs.jsonl")
        result_path = ROOT / "validation" / ("external-" + suite + "-results.jsonl")
        write_jsonl(input_path, input_rows)
        write_jsonl(result_path, result_rows)
        sets.append({"vector_set": label, "suite": suite, "total": original["total"],
            "passed": original["passed"], "failed": original["failed"], "counts": original["counts"],
            "executed_at_utc": original["generated_at_utc"], "inputs_path": str(input_path.relative_to(ROOT)),
            "inputs_sha256": sha256(input_path), "results_path": str(result_path.relative_to(ROOT)),
            "results_sha256": sha256(result_path), "original_summary_path": str(original_path.relative_to(ROOT)),
            "original_summary_sha256": sha256(original_path), "raw_sources_sha256": inputs})
        if prior_verify:
            sets[-1]["preserved_prior_verify_summary"] = prior_verify
    provenance = {}
    for relative in ("third_party/external_vectors/SOURCES.json", "third_party/external_vectors/GMSM_SOURCE.json",
                     "tools/gmsm_vectors.go", "tools/native.py", "tools/external_vectors.py"):
        provenance[relative] = sha256(ROOT / relative)
    manifest = {"schema": "a15-external-evidence-v1", "exported_at_utc": exported,
        "milestone": "DP1", "report_sections": ["5.2", "5.3", "5.4", "9.1", "Appendix C"],
        "vector_sets": sets, "total": sum(item["total"] for item in sets),
        "passed": sum(item["passed"] for item in sets), "failed": sum(item["failed"] for item in sets),
        "library_sha256": current_library_hash, "acvp_mirror_commit": ACVP_COMMIT,
        "xous_commit": XOUS_COMMIT, "gmsm_commit": GMSM_COMMIT, "gmsm_tag": "v0.44.1",
        "provenance_sha256": provenance,
        "source_identity_check": None if source_check is None else {"path": str(source_check_path.relative_to(ROOT)),
            "sha256": sha256(source_check_path), "passed": source_check["passed"], "failed": source_check["failed"]},
        "scope_limits": ["B contains one external SHA2-128-24 seeded vector; full keygen/sign is counted only when its supplementary summary is complete.",
            "A covers 208 pinned SHA2-128s/128f cases, not all 12 FIPS 205 parameter sets.",
            "C has 10 seeded key pairs per SM3 parameter, 20 full signatures per parameter, plus verification/tamper checks.",
            "C is pure-mode; gmsm rejects an empty message, so C messages contain at least one byte.",
            "A/B/C checks call native internal APIs. The runner independently formats pure/prehash messages; these suites do not directly exercise the public pure-mode C API.",
            "JSONL is exported from completed result summaries; export timestamps are distinct from execution timestamps.",
            "External-vector success is functional evidence, not a security proof or formal certification."]}
    write_json(ROOT / "validation" / "external-EVIDENCE.json", manifest)
    print(json.dumps({key: manifest[key] for key in ("schema", "total", "passed", "failed", "library_sha256")}), flush=True)
    return int(manifest["failed"] != 0 or source_check is None or source_check["failed"] != 0)


def xous_full(threads):
    """Supplement the preserved B verify-only result with seeded keygen/sign."""
    cases, inputs = xous_verify()
    metadata = EXTERNAL / "xous" / "vectors" / "vec_sphincs-sha2-128-24.txt"
    fields = dict(line.split("=", 1) for line in metadata.read_text().splitlines() if "=" in line)
    fields = {key.strip(): value.strip() for key, value in fields.items()}
    decode = lambda key: bytes.fromhex(fields[key])
    expected_pk = decode("pk")
    expected_sk = decode("sk_seed") + decode("sk_prf") + expected_pk
    expected_signature = bytes.fromhex(cases[0]["test"]["signature"])
    started = time.perf_counter()
    output = {"schema": "a15-xous-full-v1", "vector_set": "B", "pid": 103,
        "source_commit": XOUS_COMMIT, "sources_sha256": inputs, "threads": threads,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(), "results": []}
    path = ROOT / "validation" / "external-xous-full.json"
    with NativeSlhDsa(103, threads=threads, flags=1) as native:
        output["library_sha256"] = sha256(native.library_path)
        print(json.dumps({"phase": "xous-full-keygen", "threads": threads}), flush=True)
        phase = time.perf_counter()
        pk, sk = native.keygen_internal(decode("sk_seed"), decode("sk_prf"), decode("pk_seed"))
        row = {"operation": "keyGen", "pk_equal": pk == expected_pk, "sk_equal": sk == expected_sk,
            "passed": pk == expected_pk and sk == expected_sk, "seconds": time.perf_counter() - phase,
            "expected_pk": expected_pk.hex(), "actual_pk": pk.hex()}
        output["results"].append(row)
        write_json(path, output)
        print(json.dumps(row), flush=True)
        phase = time.perf_counter()
        signature = native.sign_internal(decode("message_hex"), sk, decode("opt_rand"))
        row = {"operation": "sigGen", "passed": signature == expected_signature,
            "seconds": time.perf_counter() - phase,
            "expected_signature_sha256": hashlib.sha256(expected_signature).hexdigest(),
            "actual_signature_sha256": hashlib.sha256(signature).hexdigest()}
        output["results"].append(row)
        print(json.dumps(row), flush=True)
        output["results"].append({"operation": "sigVer", "passed": native.verify_internal(
            decode("message_hex"), signature, pk)})
    output.update({"total": len(output["results"]), "passed": sum(row["passed"] for row in output["results"]),
        "failed": sum(not row["passed"] for row in output["results"]), "elapsed_seconds": time.perf_counter() - started})
    write_json(path, output)
    write_jsonl(path.with_suffix(".jsonl"), output["results"])
    write_json(ROOT / "vectors" / "external-xous-full-output.json", {"pk": pk.hex(), "sk": sk.hex(),
        "signature": signature.hex(), "message": fields["message_hex"], "randomizer": fields["opt_rand"]})
    print(json.dumps({key: value for key, value in output.items() if key != "results"}), flush=True)
    return int(output["failed"] != 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("acquire", "install-go", "acvp", "xous", "xous-full", "gmsm", "verify-sources", "export-evidence"))
    parser.add_argument("--workers", type=int, default=24)
    parser.add_argument("--threads", type=int, default=32)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--gmsm-vectors", type=Path, default=ROOT / "vectors" / "external-gmsm.json")
    args = parser.parse_args()
    if args.action == "acquire":
        acquire()
        return 0
    if args.action == "install-go":
        install_go()
        return 0
    if args.action == "verify-sources":
        return verify_sources()
    if args.action == "export-evidence":
        return export_evidence(args.gmsm_vectors)
    if args.action == "xous-full":
        return xous_full(args.threads)
    output = args.output or ROOT / "validation" / ("external-" + args.action + ".json")
    return validate(args.action, args.workers, output, args.gmsm_vectors)


if __name__ == "__main__":
    raise SystemExit(main())
