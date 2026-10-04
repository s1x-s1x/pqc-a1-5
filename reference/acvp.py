"""Run all pinned upstream SHA2-128s/128f ACVP cases against the model.

Prehash test messages are encoded through upstream's unchanged formatting
helper and then passed to the internal API; no prehash project ABI is added.
"""

import argparse
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time

from .slhdsa import ReferenceSlhDsa, UPSTREAM_COMMIT, _UPSTREAM, encode_message


def load_cases():
    cases = []
    paths = []
    for operation in ("keyGen", "sigGen", "sigVer"):
        directory = _UPSTREAM / "json-copy" / ("SLH-DSA-" + operation + "-FIPS205")
        prompt_path, expected_path = directory / "prompt.json", directory / "expectedResults.json"
        prompt = json.loads(prompt_path.read_text())
        expected = json.loads(expected_path.read_text())
        paths.extend([prompt_path, expected_path])
        answers = {(group["tgId"], test["tcId"]): test
                   for group in expected["testGroups"] for test in group["tests"]}
        projections = {}
        if operation == "sigVer":
            projection_path = directory / "internalProjection.json"
            projection = json.loads(projection_path.read_text())
            paths.append(projection_path)
            projections = {(group["tgId"], test["tcId"]): test
                           for group in projection["testGroups"] for test in group["tests"]}
        for group in prompt["testGroups"]:
            pid = {"SLH-DSA-SHA2-128s": 101, "SLH-DSA-SHA2-128f": 102}.get(group["parameterSet"])
            if pid is None:
                continue
            for question in group["tests"]:
                key = (group["tgId"], question["tcId"])
                test = {**question, **answers[key], **projections.get(key, {})}
                if operation == "sigVer":
                    test["pk"] = question["pk"]
                cases.append({"operation": operation, "pid": pid,
                              "group": {k: v for k, v in group.items() if k != "tests"},
                              "test": test})
    sources = {str(path.relative_to(_UPSTREAM)): hashlib.sha256(path.read_bytes()).hexdigest()
               for path in paths}
    return cases, sources


def run_case(case):
    started = time.perf_counter()
    model = ReferenceSlhDsa(case["pid"])
    group, test = case["group"], case["test"]
    operation = case["operation"]
    decode = lambda key: bytes.fromhex(test[key])
    if operation == "keyGen":
        pk, sk = model.keygen_internal(decode("skSeed"), decode("skPrf"), decode("pkSeed"))
        passed = pk == decode("pk") and sk == decode("sk")
    else:
        message = decode("message")
        if group["signatureInterface"] == "internal":
            encoded = message
        elif group["preHash"] == "preHash":
            encoded = bytes(model.hash_slh_dsa_pad(message, decode("context"), test["hashAlg"]))
        else:
            encoded = encode_message(message, decode("context"))
        if operation == "sigGen":
            randomizer = None if group["deterministic"] else decode("additionalRandomness")
            passed = model.sign_internal(encoded, decode("sk"), randomizer) == decode("signature")
        else:
            passed = model.verify_internal(encoded, decode("signature"), decode("pk")) == test["testPassed"]
    return {"operation": operation, "pid": case["pid"], "tgId": group["tgId"],
            "tcId": test["tcId"], "passed": passed,
            "seconds": time.perf_counter() - started}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    cases, sources = load_cases()
    counts = {operation: sum(case["operation"] == operation for case in cases)
              for operation in ("keyGen", "sigGen", "sigVer")}
    print(json.dumps({"phase": "start", "counts": counts, "total": len(cases)}), flush=True)
    started = time.perf_counter()
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(run_case, cases, chunksize=1))
    output = {"schema": "a15-python-acvp-v1", "upstream_commit": UPSTREAM_COMMIT,
              "generated_at_utc": datetime.now(timezone.utc).isoformat(),
              "counts": counts, "total": len(cases), "passed": sum(result["passed"] for result in results),
              "failed": sum(not result["passed"] for result in results),
              "workers": args.workers, "elapsed_seconds": time.perf_counter() - started,
              "sources_sha256": sources, "results": results,
              "prehash_scope": "upstream formatting helper plus project internal API"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in output.items() if key not in ("results", "sources_sha256")}), flush=True)
    return 0 if output["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
