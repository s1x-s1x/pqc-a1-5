"""Compare every scalar native counter against an exact implemented-path model.

Build a separate library with COUNTERS=1, then run this tool sequentially.
The counters are global atomics: no other client may call this library while
an operation is measured.  Full pid3/pid103 signatures are never generated.
"""

import argparse
from collections import Counter
from contextlib import ExitStack
import ctypes as ct
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.count_model import (FIELDS, cache_model,
                               keygen_model, parameters, prediction, sign_model,
                               signature_trace, subtree_model, verify_model)
from tools.native import NativeSlhDsa


class Counters(ct.Structure):
    _fields_ = [(field, ct.c_uint64) for field in FIELDS]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source_hashes():
    paths = ("c/src/engine.c", "c/src/sm3.c", "c/src/sm3.h",
             "c/include/slhdsa_sm3.h", "third_party/slhdsa-c/sha2_256.c",
             "third_party/slhdsa-c/sha2_api.h", "reference/sm3.py",
             "tools/native.py", "tools/count_model.py", "tools/check_counts.py")
    return {name: sha((ROOT / name).read_bytes()) for name in paths}


def source_commit():
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                       text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def seed_material(index=0):
    return [hashlib.sha256(f"A1-5/exact-counts/v1/key/{index}/{field}".encode()).digest()[:16]
            for field in ("sk_seed", "sk_prf", "pk_seed")]


def payload(label, length):
    return hashlib.shake_256(f"A1-5/exact-counts/v1/{label}".encode()).digest(length)


def encode_message(message, context):
    if len(context) > 255:
        raise ValueError("context length exceeds the public ABI")
    return b"\x00" + bytes([len(context)]) + context + message


def scenarios(lengths):
    cases = []
    for ordinal, length in enumerate(lengths):
        cases.append({"case": f"internal-mp-{length}", "encoding": "internal",
                      "mp": payload(f"mp/{length}", length), "message": None,
                      "context": None,
                      "opt_rand": payload(f"randomizer/{ordinal}", 16) if ordinal % 2 else None})
    for length in (0, 255):
        context = payload(f"context/{length}", length)
        message = payload(f"pure-message/{length}", 64 if length else 0)
        cases.append({"case": f"pure-context-{length}", "encoding": "pure",
                      "mp": encode_message(message, context), "message": message,
                      "context": context, "opt_rand": payload("pure-randomizer", 16) if length else None})
    return cases


class Suite:
    def __init__(self, args, stream):
        self.args, self.stream = args, stream
        self.parameters = parameters()
        self.hashes = source_hashes()
        self.library = str(args.library.resolve())
        self.library_hash = sha(args.library.read_bytes())
        self.commit = source_commit()
        self.rows = []
        self.traces = {}
        self.signature_equivalence = {}
        self.started = time.perf_counter()

    def native(self, pid, threads, flags=1):
        obj = NativeSlhDsa(pid, threads=threads, flags=flags, library=self.library)
        obj.lib.slh_counters_reset.argtypes = []
        obj.lib.slh_counters_reset.restype = None
        obj.lib.slh_counters_get.argtypes = [ct.POINTER(Counters)]
        obj.lib.slh_counters_get.restype = None
        return obj

    def measure(self, native, function):
        native.lib.slh_counters_reset()
        result = function()
        observed = Counters()
        native.lib.slh_counters_get(ct.byref(observed))
        return result, {field: getattr(observed, field) for field in FIELDS}

    def emit(self, case_id, predicted, observed, *, threads=1, checks=None,
             inputs=None, **details):
        matches = {field: predicted["counts"][field] == observed[field] for field in FIELDS}
        checks = checks or {}
        inputs = inputs or {}
        input_hash = sha(json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode())
        row = {"schema_version": 1, "suite": "exact-native-counts",
               "stage": "scalar-correctness", "final": False,
               "evidence_id": "R2/" + case_id, "case_id": case_id,
               "pid": predicted["pid"], "operation": predicted["operation"],
               "native_threads": threads, "message_encoding": details.get("message_encoding"),
               "cache_t": details.get("cache_t"), "input_sha256": input_hash,
               "inputs": inputs, "predicted": predicted["counts"], "observed": observed,
               "field_matches": matches, "checks": checks,
               "passed": all(matches.values()) and all(checks.values()),
               "prediction_detail": predicted,
               "implementation_hashes": self.hashes,
               "counter_build_sha256": self.library_hash,
               "counter_library": self.library, "source_commit": self.commit,
               "counting_scope": "public seven fields; raw cache-checksum SM3 calls excluded",
               **details}
        canonical = json.dumps(row, sort_keys=True, separators=(",", ":")).encode()
        row["record_sha256"] = sha(canonical)
        self.stream.write(json.dumps(row, sort_keys=True) + "\n")
        self.stream.flush()
        self.rows.append(row)
        print(json.dumps({"case_id": case_id, "operation": row["operation"],
                          "passed": row["passed"]}), flush=True)
        return row

    def trace(self, p, mp, signature, pk):
        key = (p.pid, sha(mp), sha(signature), sha(pk))
        if key not in self.traces:
            self.traces[key] = signature_trace(p, mp, signature, pk)
        return self.traces[key]

    def keygen(self, pid, threads, index=0):
        p = self.parameters[pid]
        seeds = seed_material(index)
        with self.native(pid, threads) as native:
            (pk, sk), counts = self.measure(native, lambda: native.keygen_internal(*seeds))
        self.emit(f"pid{pid}/key{index}/keygen/t{threads}", keygen_model(p, threads, min(p.hp, 12)),
                  counts, threads=threads, cache_t=min(p.hp, 12),
                  inputs={"seed_hex": [seed.hex() for seed in seeds]},
                  checks={"public_key_length": len(pk) == 32, "secret_key_length": len(sk) == 64},
                  public_key_hex=pk.hex(), secret_key_sha256=sha(sk))
        return pk, sk

    def probe(self):
        p = self.parameters[201]
        seeds = seed_material()
        with self.native(201, 1) as native:
            native.bind_key(b"".join(seeds) + bytes(16))
            result, counts = self.measure(native, lambda: native.subtree("fors", bytes(32), 0, 0))
        row = self.emit("counter-build-probe", subtree_model(p, "fors", 0), counts,
                        checks={"counters_enabled": counts["compress"] > 0},
                        inputs={"seed_hex": [seed.hex() for seed in seeds], "height": 0})
        return row["passed"]

    def sign_case(self, native, sk, pk, case, threads, route, cache_t=None,
                  verify_after_sign=False, effective_cache_t=None, verify=True):
        p = self.parameters[native.pid]
        if case["encoding"] == "pure":
            call = lambda: native.sign(case["message"], sk, case["context"], case["opt_rand"])
        else:
            call = lambda: native.sign_internal(case["mp"], sk, case["opt_rand"])
        signature, observed = self.measure(native, call)
        trace = self.trace(p, case["mp"], signature, pk)
        predicted = sign_model(p, len(case["mp"]), trace["chain_sums"],
                               effective_cache_t, threads, verify_after_sign)
        key = (p.pid, pk, case["case"], case["encoding"])
        baseline = self.signature_equivalence.setdefault(key, signature)
        inputs = {"public_key_hex": pk.hex(), "secret_key_sha256": sha(sk),
                  "encoded_message_hex": case["mp"].hex(),
                  "opt_rand_hex": None if case["opt_rand"] is None else case["opt_rand"].hex(),
                  "randomization": "deterministic" if case["opt_rand"] is None else "explicit",
                  "message_hex": None if case["message"] is None else case["message"].hex(),
                  "context_hex": None if case["context"] is None else case["context"].hex()}
        label = f"pid{p.pid}/{case['case']}/{route}/t{threads}"
        checks = {"signature_equivalent_across_cache_threads": signature == baseline,
                  "independent_trace_root_matches": trace["public_root_matches"]}
        self.emit(label + "/sign", predicted, observed, threads=threads, checks=checks,
                  inputs=inputs, message_encoding=case["encoding"], cache_t=cache_t,
                  cache_state=route, effective_cache_t=effective_cache_t,
                  verify_after_sign=verify_after_sign, actual_signature_trace=trace,
                  signature_hex=signature.hex())
        if verify:
            if case["encoding"] == "pure":
                call = lambda: native.verify(case["message"], signature, pk, case["context"])
            else:
                call = lambda: native.verify_internal(case["mp"], signature, pk)
            valid, counts = self.measure(native, call)
            self.emit(label + "/verify", verify_model(p, len(case["mp"]), trace["chain_sums"]),
                      counts, threads=threads, checks={"native_signature_valid": valid},
                      inputs={**inputs, "signature_sha256": sha(signature)},
                      message_encoding=case["encoding"], cache_t=cache_t,
                      actual_signature_trace=trace)
        return signature

    def subtrees(self, sk):
        p = self.parameters[201]
        reference = {}
        for threads in self.args.threads:
            with self.native(201, threads) as native:
                native.bind_key(sk)
                for kind in ("fors", "wots"):
                    for height in (0, 4, 5, 10):
                        start = (2 << p.a) if kind == "fors" else 0
                        maximum = p.a if kind == "fors" else p.hp
                        if height < maximum:
                            start += 1 << height
                        address = bytearray(32)
                        address[19] = 3 if kind == "fors" else 0
                        address[23] = 13
                        for selected in (False, True):
                            target = start + (1 << height) // 3 if selected else None
                            result, observed = self.measure(native, lambda: native.subtree(
                                kind, address, start, height, target))
                            key = (kind, height, selected)
                            expected = reference.setdefault(key, result)
                            self.emit(f"toy/subtree/{kind}/z{height}/auth{int(selected)}/t{threads}",
                                      subtree_model(p, kind, height, threads), observed,
                                      threads=threads,
                                      checks={"root_auth_equivalent_across_threads": result == expected},
                                      inputs={"secret_key_sha256": sha(sk), "adrs_hex": address.hex(),
                                              "leaf_start": start, "height": height, "target": target},
                                      root_hex=result[0].hex(), auth_hex=result[1].hex())

    def toy(self):
        p = self.parameters[201]
        pk, sk = self.keygen(201, self.args.threads[0])
        for threads in self.args.threads[1:]:
            threaded_pk, threaded_sk = self.keygen(201, threads)
            if (threaded_pk, threaded_sk) != (pk, sk):
                raise AssertionError("seeded toy keygen differs across thread counts")
        self.subtrees(sk)
        other_pk, other_sk = self.keygen(201, self.args.threads[0], 1)
        cases = scenarios(self.args.message_lengths)
        with tempfile.TemporaryDirectory(prefix="a15-counts-") as temporary:
            for threads in self.args.threads:
                with ExitStack() as stack:
                    routes = {}
                    plain = stack.enter_context(self.native(201, threads))
                    plain.bind_key(sk)
                    routes["none"] = (plain, None)
                    for level in (0, 5, p.hp):
                        builder = stack.enter_context(self.native(201, threads))
                        _, observed = self.measure(builder, lambda: builder.cache_build(sk, level))
                        self.emit(f"toy/cache-build/t{level}/threads{threads}",
                                  cache_model(p, "cache_build", level, threads), observed,
                                  threads=threads, cache_t=level,
                                  inputs={"secret_key_sha256": sha(sk), "cache_t": level})
                        path = Path(temporary) / f"toy-t{level}-threads{threads}.cache"
                        _, observed = self.measure(builder, lambda: builder.cache_save(path))
                        self.emit(f"toy/cache-save/t{level}/threads{threads}",
                                  cache_model(p, "cache_save", level, threads), observed,
                                  threads=threads, cache_t=level,
                                  checks={"file_length_exact": path.stat().st_size == 96 + 16 * (1 << (p.hp - level))},
                                  inputs={"public_key_hex": pk.hex(), "cache_t": level},
                                  cache_file_sha256=sha(path.read_bytes()))
                        loaded = stack.enter_context(self.native(201, threads))
                        _, observed = self.measure(loaded, lambda: loaded.cache_load(path, pk))
                        self.emit(f"toy/cache-load/t{level}/threads{threads}",
                                  cache_model(p, "cache_load", level, threads), observed,
                                  threads=threads, cache_t=level,
                                  inputs={"public_key_hex": pk.hex(), "cache_file_sha256": sha(path.read_bytes())})
                        routes[f"loaded-t{level}"] = (loaded, level)
                    for route, (native, level) in routes.items():
                        for case in cases:
                            self.sign_case(native, sk, pk, case, threads, route, level,
                                           effective_cache_t=level)
                    # A loaded cache for another key must take the uncached path.
                    native, level = routes["loaded-t0"]
                    self.sign_case(native, other_sk, other_pk, cases[-1], threads,
                                   "key-mismatch", level, effective_cache_t=None)
                    # Pure and internal APIs hash exactly the same encoded bytes.
                    pure = cases[-1]
                    alias = {**pure, "case": pure["case"] + "-internal-alias", "encoding": "internal"}
                    signature = self.sign_case(plain, sk, pk, alias, threads, "none")
                    pure_signature = self.signature_equivalence[(201, pk, pure["case"], "pure")]
                    if signature != pure_signature:
                        raise AssertionError("pure/internal encoding signature mismatch")
                    self_checked = stack.enter_context(self.native(201, threads, flags=1 | 0x100))
                    self_checked.cache_build(sk, 5)
                    self.sign_case(self_checked, sk, pk, cases[-1], threads, "self-verify-t5", 5,
                                   effective_cache_t=5, verify_after_sign=True)
                    # Length rejection precedes init_work, so every field is zero.
                    valid, observed = self.measure(plain, lambda: plain.verify_internal(b"", b"", pk))
                    self.emit(f"toy/verify-invalid-length/t{threads}",
                              prediction(p, "verify_invalid_length", []), observed,
                              threads=threads, checks={"invalid_length_rejected": not valid},
                              inputs={"signature_length": 0, "public_key_hex": pk.hex()})

    def multilayer(self):
        # pid2/102 have only 2,112 FORS leaves; this tests nonfinal-layer root
        # reconstruction and two-block MGF1 without large limited-use trees.
        case = {"case": "multilayer-internal-mp-40", "encoding": "internal",
                "mp": payload("multilayer/mp40", 40), "message": None,
                "context": None, "opt_rand": payload("multilayer/randomizer", 16)}
        for pid in (2, 102):
            p = self.parameters[pid]
            pk, sk = self.keygen(pid, self.args.threads[0])
            for threads in self.args.threads:
                with self.native(pid, threads) as plain:
                    self.sign_case(plain, sk, pk, case, threads, "none")
                    plain.cache_build(sk, 0)
                    self.sign_case(plain, sk, pk, case, threads, "built-t0", 0,
                                   effective_cache_t=0)

    def summary(self, error=None):
        fields = {field: {"passed": sum(row["field_matches"][field] for row in self.rows),
                          "failed": sum(not row["field_matches"][field] for row in self.rows)}
                  for field in FIELDS}
        chain_sums = sorted({trace["chain_sums"][0] for key, trace in self.traces.items() if key[0] == 201})
        coverage = {
            "all_seven_fields_compared": len(fields) == 7,
            "thread_counts": sorted({row["native_threads"] for row in self.rows}),
            "parameters": sorted({row["pid"] for row in self.rows}),
            "operations": dict(Counter(row["operation"] for row in self.rows)),
            "message_encodings": sorted({row["message_encoding"] for row in self.rows if row["message_encoding"]}),
            "toy_actual_chain_sums": chain_sums,
            "actual_chain_steps_vary": len(chain_sums) > 1,
            "cache_paths": sorted({row["cache_state"] for row in self.rows if "cache_state" in row}),
            "no_full_limited_use_signature_generated": True,
        }
        return {"schema_version": 1, "suite": "exact-native-counts",
                "generated_utc": datetime.now(timezone.utc).isoformat(),
                "stage": "scalar-correctness", "final": False,
                "passed": error is None and bool(self.rows) and all(row["passed"] for row in self.rows),
                "records": len(self.rows), "passing_records": sum(row["passed"] for row in self.rows),
                "failed_case_ids": [row["case_id"] for row in self.rows if not row["passed"]],
                "per_field": fields, "coverage": coverage,
                "counter_build_sha256": self.library_hash, "implementation_hashes": self.hashes,
                "source_commit": self.commit, "output_sha256": sha(self.args.output.read_bytes()),
                "diagnostic_seconds": time.perf_counter() - self.started,
                "error": error,
                "limitations": ["global atomic counters require exclusive sequential library use",
                                "cache checksum calls use raw SM3 and are outside public compress counter",
                                "counts validate the implemented path; they are not benchmark or security claims",
                                "toy plus bounded pid2/102 tests do not measure full pid3/103 signing"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--threads", type=int, nargs="+", default=[1, 4])
    parser.add_argument("--message-lengths", type=int, nargs="+", default=[0, 1, 7, 8, 39, 40, 47, 48, 55, 56, 63, 64, 257],
                        help="internal M' lengths, before adding the two pure-API cases")
    parser.add_argument("--toy-only", action="store_true", help="omit bounded pid2/102 multi-layer cases")
    args = parser.parse_args()
    if any(not 1 <= value <= 1024 for value in args.threads):
        parser.error("resolved thread counts must be between 1 and 1024")
    if any(not 0 <= value <= 1_048_576 for value in args.message_lengths):
        parser.error("message lengths must be between 0 and 1048576")
    if not args.library.is_file():
        parser.error("the counter library does not exist")
    args.threads = list(dict.fromkeys(args.threads))
    args.message_lengths = list(dict.fromkeys(args.message_lengths))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    summary_path = args.output.with_suffix(".summary.json")
    if args.output.exists() or summary_path.exists():
        parser.error("evidence output exists; choose a fresh output path to preserve earlier runs")
    error = None
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        suite = Suite(args, stream)
        try:
            if not suite.probe():
                error = "counter-build probe failed; rebuild a separate library with COUNTERS=1"
            else:
                suite.toy()
                if not args.toy_only:
                    suite.multilayer()
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
    summary = suite.summary(error)
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"summary": str(summary_path), "passed": summary["passed"],
                      "records": summary["records"], "error": error}), flush=True)
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
