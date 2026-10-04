"""Untimed correctness of the exact no-counter CUDA benchmark library."""
import argparse
import ctypes as ct
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import bench_cpu
import bench_cuda
from native import NativeSlhDsa
from signing_budget import SigningBudget
from count_model import FIELDS


class Counters(ct.Structure):
    _fields_ = [(name, ct.c_uint64) for name in FIELDS]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def signature_input(pid, api, message, context, pk, *, raw_message=None,
                    hash_alg=None, randomization="deterministic", opt_rand=None):
    sha = lambda value: hashlib.sha256(value).hexdigest()
    return dict(pid=pid, api=api, hash_alg=hash_alg, randomization=randomization,
                api_input_sha256=sha(message), message_sha256=sha(message if raw_message is None else raw_message),
                context_sha256=sha(context), opt_rand_sha256=None if opt_rand is None else sha(opt_rand),
                public_key_hex=pk.hex(), public_key_sha256=sha(pk),
                budget_algorithm="SLH-DSA-SM3-128-24" if pid == 3 else "SLH-DSA-SM3-TOY",
                budget_message_sha256=sha(message))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--build-record", type=Path, required=True)
    parser.add_argument("--budget-db", type=Path, required=True)
    parser.add_argument("--vectors", type=Path, default=ROOT / "reference/evidence/python-sm3-128-24.jsonl")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--threads", type=int, default=64)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("choose a fresh output")
    build_bytes = args.build_record.read_bytes()
    build = json.loads(build_bytes.decode("utf8"))
    build_record_digest = hashlib.sha256(build_bytes).hexdigest()
    library_digest = digest(args.library)
    before = bench_cpu.hashes(bench_cuda.BUILD_FILES + bench_cuda.TOOL_FILES + ["tools/check_cuda_release.py"])
    bench_cuda.checked_build(build, args.library)
    vector_bytes = args.vectors.read_bytes()
    input_digest = hashlib.sha256(vector_bytes).hexdigest()
    ledger = SigningBudget(args.budget_db)
    rows = []
    device = None
    prehash_public_key = None

    def record(case_id, checks, stats=None, **details):
        if stats is not None:
            expected_fields = {name for name, _ in bench_cuda.CudaStats._fields_}
            if (set(stats) != expected_fields or any(type(value) is not int or value < 0 for value in stats.values())):
                raise ValueError("CUDA release statistics require six nonnegative integer fields")
            checks = dict(checks, events_disabled=stats["timing_enabled"] == 0 and stats["kernel_ns"] == 0,
                          actual_GPU_work=stats["kernel_launches"] > 0 and stats["device_hashes"] > 0)
        row = dict(case_id=case_id, checks=checks, passed=all(checks.values()),
                   gpu_stats=stats, **details)
        row["record_sha256"] = hashlib.sha256(bench_cpu.canonical(row).encode()).hexdigest()
        rows.append(row)
        print(json.dumps({"case_id": case_id, "passed": row["passed"]}), flush=True)
        if not row["passed"]:
            raise ValueError("CUDA release correctness failed: " + case_id)

    def sign(native, stats, message, sk, pk, operation):
        receipt = ledger.reserve("SLH-DSA-SM3-128-24" if native.pid == 3 else "SLH-DSA-SM3-TOY", pk, message)
        try:
            stats.reset(False)
            signature = operation()
        except BaseException:
            ledger.finish(receipt)
            raise
        else:
            ledger.finish(receipt, signature)
        return signature, stats.get(), receipt

    error = None
    try:
        vectors = [json.loads(line) for line in vector_bytes.decode("utf8").splitlines() if line]
        if (len(vectors) != 3 or any(v["pid"] != 3 for v in vectors)
                or len({v["case_id"] for v in vectors}) != 3
                or len({v["pk"] for v in vectors}) != 3
                or len({v["sk_seed"] for v in vectors}) != 3
                or {v["randomization"] for v in vectors} != {"deterministic", "explicit"}):
            raise ValueError("three complete SM3-128-24 Python vectors required")
        for vector in vectors:
            original = dict(vector)
            saved = original.pop("record_sha256")
            encoded = json.dumps(original, sort_keys=True, separators=(",", ":")).encode()
            if hashlib.sha256(encoded).hexdigest() != saved:
                raise ValueError("Python vector record hash differs")
            decode = lambda name: bytes.fromhex(vector[name])
            with NativeSlhDsa(3, args.threads, 5 | 0x100, args.library) as native:
                stats = bench_cuda.Statistics(native.lib)
                stats.reset(False)
                info = stats.info()
                if device is None:
                    device = info
                if info != device or info != build["release_probe"]["device"]:
                    raise ValueError("CUDA release device differs from checked build")
                pk, sk = native.keygen_internal(decode("sk_seed"), decode("sk_prf"), decode("pk_seed"))
                record(vector["case_id"] + "/keygen", dict(actual_backend=native.backend == 5,
                       pk_equals_Python=pk == decode("pk"), sk_equals_Python=sk == decode("sk")),
                       actual_selected_backend=native.backend, input_reference_record_sha256=saved,
                       public_key_sha256=hashlib.sha256(pk).hexdigest())
                randomizer = None if vector["randomization"] == "deterministic" else decode("opt_rand")
                signature, observed, receipt = sign(native, stats, decode("mp"), sk, pk,
                    lambda: native.sign_internal(decode("mp"), sk, randomizer))
                checks = dict(signature_equals_Python=signature == decode("sig"),
                              verify_internal=native.verify_internal(decode("mp"), signature, pk),
                              pure_verify=native.verify(decode("message"), signature, pk, decode("context")),
                              changed_message_rejected=not native.verify_internal(decode("mp") + b"!", signature, pk))
                with NativeSlhDsa(3, 1, 1, args.library) as ref:
                    checks["REF_verify"] = ref.verify_internal(decode("mp"), signature, pk)
                record(vector["case_id"] + "/sign", checks, observed, budget_receipt=receipt,
                       budget_status="committed", actual_selected_backend=native.backend,
                       input=signature_input(3, "sign_internal", decode("mp"), decode("context"), pk,
                                             raw_message=decode("message"), randomization=vector["randomization"], opt_rand=randomizer),
                       input_reference_record_sha256=saved, signature_sha256=hashlib.sha256(signature).hexdigest())
                native.lib.slh_counters_get.argtypes = [ct.POINTER(Counters)]
                native.lib.slh_counters_get.restype = None
                counts = Counters()
                native.lib.slh_counters_get(ct.byref(counts))
                record(vector["case_id"] + "/release-counts",
                       dict(counters_disabled=all(getattr(counts, k) == 0 for k in FIELDS)),
                       input_reference_record_sha256=saved)
        with NativeSlhDsa(201, 1, 5 | 0x100, args.library) as gpu, NativeSlhDsa(201, 1, 1, args.library) as ref:
            seed = bytes(range(48))
            pk, sk = gpu.keygen_internal(seed[:16], seed[16:32], seed[32:])
            prehash_public_key = pk.hex()
            stats = bench_cuda.Statistics(gpu.lib)
            message, context = b"\0CUDA release prehash\xff", b"CUDA"
            for hash_alg in range(1, 6):
                signature, observed, receipt = sign(gpu, stats, message, sk, pk,
                    lambda: gpu.sign_prehash(message, sk, hash_alg, context))
                checks = dict(CUDA_verify=gpu.verify_prehash(message, signature, pk, hash_alg, context),
                              REF_verify=ref.verify_prehash(message, signature, pk, hash_alg, context),
                              wrong_context_rejected=not gpu.verify_prehash(message, signature, pk, hash_alg, context + b"!"))
                record("toy/prehash-" + str(hash_alg), checks, observed, budget_receipt=receipt,
                       budget_status="committed", actual_selected_backend=gpu.backend,
                       input=signature_input(201, "sign_prehash", message, context, pk, hash_alg=hash_alg),
                       signature_sha256=hashlib.sha256(signature).hexdigest())
        if (digest(args.vectors) != input_digest or before != bench_cpu.hashes(list(before))
                or digest(args.build_record) != build_record_digest or digest(args.library) != library_digest):
            raise ValueError("release acceptance source/vector changed")
        bench_cuda.checked_build(build, args.library)
        if not ledger.status() or not all(row["count_reconciled"] for row in ledger.status()):
            raise ValueError("CUDA release signing budget does not reconcile")
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    result = dict(schema="a15-cuda-release-correctness-v1", timestamp_utc=datetime.now(timezone.utc).isoformat(),
                  passed=error is None and len(rows) == 14 and all(r["passed"] for r in rows),
                  error=error, rows=rows, source_sha256=build["source_sha256"], sources_and_tools_sha256=before,
                  library_sha256=library_digest, build_record_sha256=build_record_digest,
                  input_sha256={str(args.vectors.resolve()): input_digest}, device_identity=device,
                  budget_database_path=str(args.budget_db.resolve()), prehash_public_key_hex=prehash_public_key,
                  prehash_seed_sha256=hashlib.sha256(bytes(range(48))).hexdigest(),
                  budget_status=ledger.status(), real_timing_samples=0, formal_performance_started=False,
                  measured_durations=False, actual_selected_backend=5)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf8") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps(dict(passed=result["passed"], error=error, checks=len(rows))), flush=True)
    return int(not result["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
