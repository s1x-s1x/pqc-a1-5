"""CPU optimization correctness and exact-counter validation; no benchmarks.

All native calls are serialized because the counters are global atomics.
The default light suite never builds/signs pid3 or pid103 complete trees.
Use --suite full for the explicit large-tree correctness workloads. Every
signing attempt is charged to SigningBudget before entering the native ABI.
"""

import argparse
import ctypes as ct
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
from time import sleep


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.count_model import (FIELDS, cache_model, keygen_model, parameters,
                               signature_trace, sign_model, subtree_model, verify_model)
from tools.native import NativeSlhDsa, NativeError, NAMES
from tools.signing_budget import SigningBudget

BACKENDS = {"REF": 1, "AVX2": 2}
ALGORITHMS = {pid: name for name, pid in NAMES.items()}
SCHEMA = "a15-optimization-correctness-v1"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    for attempt in range(9):
        try:
            temporary.replace(path)
            return
        except OSError as exc:
            # Indexers/antivirus can hold a briefly shared-read Windows handle
            # while checkpoint files are replaced. Never discard the temp or
            # overwrite a preserved case record when that happens.
            if os.name != "nt" or getattr(exc, "winerror", None) not in (5, 32, 33) or attempt == 8:
                raise
            sleep(min(0.01 * (2 ** attempt), 0.1))


def native_file_call(function, path, *args):
    """Call the narrow C file ABI with a basename on Windows.

    Windows Python encodes filesystem paths as UTF-8, while the C library's
    fopen uses the active ANSI code page. Changing only this process's cwd
    with Python's wide-character API keeps Unicode workspace directories
    usable without changing the ABI or copying evidence to another location.
    Native calls in this runner are serialized; the cwd is always restored.
    """
    path = Path(path).resolve()
    if os.name != "nt":
        return function(path, *args)
    previous = Path.cwd()
    try:
        os.chdir(path.parent)
        return function(path.name, *args)
    finally:
        os.chdir(previous)


def source_hashes():
    names = ["c/Makefile", "c/src/engine.c", "c/src/sm3.c", "c/src/sm3.h",
             "c/src/sm3x8.c", "c/src/sm3x8.h", "c/include/slhdsa_sm3.h",
             "third_party/slhdsa-c/sha2_256.c", "third_party/slhdsa-c/sha2_512.c",
             "third_party/slhdsa-c/sha2_api.h", "third_party/slhdsa-c/sha3_api.c",
             "third_party/slhdsa-c/sha3_f1600.c", "tools/native.py",
             "tools/count_model.py", "tools/signing_budget.py", "tools/check_optimization.py",
             "reference/sm3.py"]
    return {name: file_sha(ROOT / name) for name in names if (ROOT / name).exists()}


_SM3_CLASS = None


def new_hash(sm3, data=b""):
    if not sm3:
        return hashlib.sha256(data)
    if "sm3" in hashlib.algorithms_available:
        return hashlib.new("sm3", data)
    global _SM3_CLASS
    if _SM3_CLASS is None:
        spec = importlib.util.spec_from_file_location("a15_optimization_sm3", ROOT / "reference/sm3.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _SM3_CLASS = module.Sm3
    return _SM3_CLASS(data)


def cache_header(p, level, public_key, payload):
    header = bytearray(96)
    header[:8] = b"A15CACHE"
    struct.pack_into(">6I", header, 8, 1, p.pid, level, p.hp, p.n, len(payload))
    header[32:64] = public_key
    digest = new_hash(True, header[:64])
    digest.update(payload)
    header[64:96] = digest.digest()
    return bytes(header)


def cache_payload(path, p, public_key, expected_level=None):
    """Strict independent cache-v1 format/checksum parser; no native ABI."""
    with Path(path).open("rb") as stream:
        header = stream.read(96)
        if len(header) != 96 or header[:8] != b"A15CACHE":
            raise ValueError("cache header/magic mismatch")
        version, pid, level, hp, n, size = struct.unpack_from(">6I", header, 8)
        if (version, pid, hp, n) != (1, p.pid, p.hp, p.n) or not 0 <= level <= hp:
            raise ValueError("cache version/parameter fields mismatch")
        if expected_level is not None and level != expected_level:
            raise ValueError("cache level differs from the requested fixture")
        if size != p.n * (1 << (p.hp - level)) or header[32:64] != public_key:
            raise ValueError("cache node count or public-key binding mismatch")
        payload = stream.read(size)
        if len(payload) != size or stream.read(1):
            raise ValueError("cache file is truncated or has trailing bytes")
    digest = new_hash(True, header[:64])
    digest.update(payload)
    if digest.digest() != header[64:96]:
        raise ValueError("cache checksum mismatch")
    return level, payload


def write_cache(path, p, level, public_key, payload):
    path = Path(path)
    if len(payload) != p.n * (1 << (p.hp - level)):
        raise ValueError("cache payload length mismatch")
    content_header = cache_header(p, level, public_key, payload)
    if path.exists():
        old_level, old_payload = cache_payload(path, p, public_key, level)
        if old_payload != payload:
            raise ValueError("existing derived cache differs; preserve earlier output")
        return
    temporary = path.with_suffix(path.suffix + ".partial")
    with temporary.open("wb") as stream:
        stream.write(content_header)
        stream.write(payload)
        stream.flush()
    temporary.replace(path)


def parent_layer(p, public_seed, level, payload):
    """Independent scalar HASH-copy construction of public TREE parents."""
    if len(payload) % (2 * p.n):
        raise ValueError("parent layer needs complete sibling pairs")
    prefix = new_hash(p.sm3, public_seed + bytes(64 - p.n))
    compressed_address = bytearray(22)
    compressed_address[0] = p.d - 1
    compressed_address[9] = 2  # TREE; tree index and key-pair fields are zero.
    struct.pack_into(">I", compressed_address, 14, level)
    output = bytearray(len(payload) // 2)
    view = memoryview(payload)
    for index in range(len(payload) // (2 * p.n)):
        struct.pack_into(">I", compressed_address, 18, index)
        state = prefix.copy()
        state.update(compressed_address)
        state.update(view[index * 2 * p.n:(index + 1) * 2 * p.n])
        output[index * p.n:(index + 1) * p.n] = state.digest()[:p.n]
    return bytes(output)


def derive_cache_family(p, public_key, source_t0, directory):
    """Save every level using one t0 public-leaf payload, not repeated keygen.

    The header checksum is always SM3. TREE parent hashing follows the
    parameter's SM3/SHA2 construction. The final root must equal PK.root.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    _, payload = cache_payload(source_t0, p, public_key, 0)
    manifest = []
    for level in range(p.hp + 1):
        path = directory / f"pid{p.pid}-t{level}.cache"
        write_cache(path, p, level, public_key, payload)
        manifest.append({"level": level, "path": str(path), "payload_bytes": len(payload),
                         "file_bytes": 96 + len(payload), "file_sha256": file_sha(path),
                         "payload_sha256": sha(payload),
                         "basis": "independent HASH.copy parents from native t0 public leaves"})
        if level < p.hp:
            payload = parent_layer(p, public_key[:p.n], level + 1, payload)
    if payload != public_key[p.n:]:
        raise ValueError("independently derived top root differs from PK.root")
    return manifest


class Counters(ct.Structure):
    _fields_ = [(field, ct.c_uint64) for field in FIELDS]


class CorrectnessFailure(RuntimeError):
    """A persisted failed check stops --fail-fast before more native work."""


def load_vectors(path):
    ps = parameters()
    vectors = {}
    for line_no, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            continue
        row = json.loads(line)
        stored = row.get("record_sha256")
        if stored:
            body = {key: value for key, value in row.items() if key != "record_sha256"}
            if sha(canonical(body)) != stored:
                raise ValueError(f"input record checksum mismatch at line {line_no}")
        p = ps[row["pid"]]
        for name in ("sk_seed", "sk_prf", "pk_seed", "pk", "sk", "mp", "sig", "opt_rand"):
            row[name + "_bytes"] = bytes.fromhex(row[name])
        trace = signature_trace(p, row["mp_bytes"], row["sig_bytes"], row["pk_bytes"])
        if not trace["public_root_matches"]:
            raise ValueError(f"input vector signature trace root mismatch at line {line_no}")
        row["trace"] = trace
        row["vector_file"] = str(Path(path).resolve())
        row["vector_line"] = line_no
        row["vector_sha256"] = file_sha(path)
        vectors[p.pid] = row
    if set(vectors) != set(ps):
        raise ValueError("input fixture file must supply each of the seven fixed parameter pids")
    return vectors


def vector_fingerprint(vector):
    return {"case_id": vector["case_id"], "pid": vector["pid"],
            "vector_file": vector["vector_file"], "vector_line": vector["vector_line"],
            "vector_file_sha256": vector["vector_sha256"],
            "original_source": vector.get("source"),
            "original_source_hashes": vector.get("source_hashes", vector.get("source_sha256")),
            "public_key_sha256": sha(vector["pk_bytes"]), "secret_key_sha256": sha(vector["sk_bytes"]),
            "encoded_message_sha256": sha(vector["mp_bytes"]),
            "opt_rand_sha256": sha(vector["opt_rand_bytes"]), "signature_sha256": sha(vector["sig_bytes"])}


def case_id(case):
    return "/".join(str(case[key]) for key in ("library", "pid", "backend", "threads", "operation", "variant"))


def build_plan(args, libraries):
    """Produce explicit plan rows so omitted large cases remain pending."""
    ps = parameters()
    plan = []
    light_pids = [201, 2, 102] if not args.full_small else [201, 1, 2, 101, 102]
    complete_pids = [pid for pid in ps if pid != 103 or args.full_sha2] if args.suite == "full" else light_pids
    def add(lib, pid, backend, threads, operation, variant, **extra):
        case = {"library": lib, "pid": pid, "backend": backend, "threads": threads,
                "operation": operation, "variant": variant, **extra}
        case["case_id"] = case_id(case)
        plan.append(case)
    for label in libraries:
        add(label, 201, "REF", 1, "counter_probe", "enabled")
        for pid, p in ps.items():
            choices = args.backends if p.sm3 else ["REF"]
            for backend in choices:
                for threads in args.threads:
                    add(label, pid, backend, threads, "verify", "existing-vector")
                    for kind in ("wots", "fors"):
                        maximum = p.hp if kind == "wots" else p.a
                        heights = sorted({min(z, maximum) for z in args.subtree_heights})
                        for height in heights:
                            # End of the final FORS tree stresses absolute uint32
                            # offsets; WOTS end includes the high-hp address case.
                            start = ((1 << p.hp) - (1 << height) if kind == "wots" else
                                     (p.k << p.a) - (1 << height))
                            targets = [None, start, start + (1 << height) - 1]
                            for target in dict.fromkeys(targets):
                                tag = "none" if target is None else "first" if target == start else "last"
                                add(label, pid, backend, threads, "subtree", f"{kind}-z{height}-{tag}",
                                    kind=kind, height=height, start=start, target=target)
            if not p.sm3 and "AVX2" in args.backends:
                add(label, pid, "AVX2", 1, "backend_rejection", "SHA2-must-reject-explicit-AVX2")
        cache_pids = [201]
        if args.suite in ("cache", "full"):
            cache_pids.append(3)
        if args.full_sha2:
            cache_pids.append(103)
        for pid in cache_pids:
            p = ps[pid]
            choices = args.backends if p.sm3 else ["REF"]
            prep_backend = args.cache_source_backend if p.sm3 else "REF"
            add(label, pid, prep_backend, max(args.threads), "keygen", "native-t0-source", cache_t=0)
            add(label, pid, prep_backend, max(args.threads), "derive_cache", "all-levels-from-t0")
            real_levels = sorted(set((0, min(12, p.hp), p.hp)))
            for backend in choices:
                for level in real_levels:
                    add(label, pid, backend, max(args.threads), "cache_build", f"native-t{level}", cache_t=level)
                for level in range(p.hp + 1):
                    add(label, pid, backend, max(args.threads), "cache_load_roundtrip", f"t{level}", cache_t=level)
                    add(label, pid, backend, max(args.threads), "cache_root_binding", f"t{level}", cache_t=level)
                    if pid == 201 or args.suite == "full":
                        add(label, pid, backend, max(args.threads), "sign", f"every-cache-t{level}", cache_t=level)
        for pid in complete_pids:
            p = ps[pid]
            choices = args.backends if p.sm3 else ["REF"]
            for backend in choices:
                for threads in args.threads:
                    if args.suite == "full" and pid in (3, 103):
                        level = min(12, p.hp)
                        add(label, pid, backend, threads, "keygen", f"matrix-t{level}", cache_t=level)
                        # The max-thread build was already planned above.
                        if threads != max(args.threads):
                            add(label, pid, backend, threads, "cache_build", f"matrix-t{level}", cache_t=level)
                    for cache in (None, min(12, p.hp)):
                        add(label, pid, backend, threads, "sign", "uncached" if cache is None else f"matrix-t{cache}",
                            cache_t=cache)
                    # Deliberately wrong SK.root exercises verify-after-sign;
                    # it consumes a reservation and returns an erased signature.
                    if pid == 201:
                        add(label, pid, backend, threads, "sign_fault", "changed-root-self-check")
    return plan


class Runner:
    def __init__(self, args):
        self.args = args
        self.ps = parameters()
        self.run_dir = args.run_dir.resolve()
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.output = self.run_dir / "cases.jsonl"
        self.summary_path = self.run_dir / "summary.json"
        self.vectors = load_vectors(args.vectors)
        self.sources = source_hashes()
        self.libraries = {}
        for index, path in enumerate(args.library):
            path = path.resolve()
            if not path.is_file():
                raise ValueError(f"library missing: {path}")
            label = f"lib{index}-{file_sha(path)[:12]}"
            self.libraries[label] = {"path": str(path), "sha256": file_sha(path)}
        self.ledger = SigningBudget(args.budget_db)
        self.records = []
        self.latest = {}
        self.reference_subtrees = {}
        self.available = {}
        self.plan = build_plan(args, self.libraries)
        config = {key: value for key, value in vars(args).items() if key != "resume"}
        config = json.loads(json.dumps(config, default=str))
        self.identity = {"schema": SCHEMA, "sources_sha256": self.sources, "libraries": self.libraries,
                         "vector_sha256": file_sha(args.vectors), "configuration": config,
                         "budget_database_path": str(self.ledger.path)}
        manifest = self.run_dir / "manifest.json"
        if args.resume:
            if not manifest.exists():
                raise ValueError("resume requires an existing manifest")
            old = json.loads(manifest.read_text(encoding="utf-8"))
            if old["identity"] != self.identity:
                raise ValueError("resume source/library/input/configuration hashes changed; use a fresh run directory")
            if self.output.exists():
                for line in self.output.read_text(encoding="utf-8").splitlines():
                    row = json.loads(line)
                    stored = row.pop("record_sha256")
                    if sha(canonical(row)) != stored:
                        raise ValueError("preserved case record checksum mismatch")
                    row["record_sha256"] = stored
                    self.records.append(row)
                    self.latest[row["case_id"]] = row
        else:
            if manifest.exists() or self.output.exists():
                raise ValueError("run output exists; choose a fresh directory or exact-hash --resume")
            atomic_json(manifest, {"identity": self.identity, "plan": self.plan,
                                  "created_utc": datetime.now(timezone.utc).isoformat(),
                                  "boundary": "optimization correctness; formal performance has not started"})
        self.stream = self.output.open("a", encoding="utf-8", newline="\n")

    def close(self):
        self.stream.close()

    def native(self, case, flags=None, backend=None):
        native = NativeSlhDsa(case["pid"], case["threads"],
                             BACKENDS[backend or case["backend"]] if flags is None else flags,
                             self.libraries[case["library"]]["path"])
        native.lib.slh_counters_reset.argtypes = []
        native.lib.slh_counters_reset.restype = None
        native.lib.slh_counters_get.argtypes = [ct.POINTER(Counters)]
        native.lib.slh_counters_get.restype = None
        return native

    def supported(self, case):
        key = (case["library"], case["backend"])
        if key not in self.available:
            if case["backend"] == "REF":
                self.available[key] = True
            else:
                probe = {**case, "pid": 201}
                try:
                    with self.native(probe) as native:
                        self.available[key] = native.backend == BACKENDS[case["backend"]]
                except NativeError as exc:
                    if exc.code != -2:
                        raise
                    self.available[key] = False
        return self.available[key]

    def measure(self, native, function):
        native.lib.slh_counters_reset()
        result = None
        error = None
        try:
            result = function()
        except BaseException as exc:
            error = exc
        snapshot = Counters()
        native.lib.slh_counters_get(ct.byref(snapshot))
        counts = {field: getattr(snapshot, field) for field in FIELDS}
        if error:
            setattr(error, "optimization_counts", counts)
            raise error
        return result, counts

    def record(self, case, status, *, checks=None, predicted=None, observed=None,
               result=None, stop_on_failure=True, **details):
        checks = checks or {}
        matches = ({field: predicted["counts"][field] == observed[field] for field in FIELDS}
                   if predicted is not None and observed is not None else {})
        if status == "passed" and (not all(checks.values()) or not all(matches.values())):
            status = "failed"
        fingerprint = vector_fingerprint(self.vectors[case["pid"]])
        row = {"schema": SCHEMA, "case_id": case["case_id"], "case": case,
               "status": status, "passed": status == "passed", "checks": checks,
               "prediction": predicted, "observed": observed, "field_matches": matches,
               "input": fingerprint, "input_sha256": sha(canonical({"case": case, "input": fingerprint})),
               "result": result, "result_sha256": sha(canonical(result)),
               "source_hashes": self.sources, "library": self.libraries[case["library"]],
               "formal_performance": False, "recorded_utc": datetime.now(timezone.utc).isoformat(),
               **details}
        row["record_sha256"] = sha(canonical(row))
        self.stream.write(json.dumps(row, sort_keys=True) + "\n")
        self.stream.flush()
        self.records.append(row)
        self.latest[row["case_id"]] = row
        print(json.dumps({"case_id": row["case_id"], "status": status}), flush=True)
        if status == "failed" and self.args.fail_fast and stop_on_failure:
            raise CorrectnessFailure("persisted failed check: " + row["case_id"])
        return row

    def cache_directory(self, case):
        return self.run_dir / "cache" / case["library"] / f"pid{case['pid']}"

    def cache_path(self, case, level):
        return self.cache_directory(case) / f"pid{case['pid']}-t{level}.cache"

    def ensure_small_cache(self, case, level):
        """For low-cost pids not in all-level cache suites; build at most once.

        This preparation is independently recorded with its own seven fields.
        It is never silently used for pid3/103 large-tree signing.
        """
        path = self.cache_path(case, level)
        if path.exists():
            cache_payload(path, self.ps[case["pid"]], self.vectors[case["pid"]]["pk_bytes"], level)
            return
        if case["pid"] in (3, 103):
            raise ValueError("large pid cache missing: run explicit all-level preparation first")
        prep = {**case, "operation": "cache_prepare", "variant": f"native-t{level}", "cache_t": level}
        prep["case_id"] = case_id(prep)
        with self.native(case) as native:
            _, counts = self.measure(native, lambda: native.cache_build(self.vectors[case["pid"]]["sk_bytes"], level))
            self.record(prep, "passed", predicted=cache_model(self.ps[case["pid"]], "cache_build", level, case["threads"]),
                        observed=counts, result={"cache_t": level})
            path.parent.mkdir(parents=True, exist_ok=True)
            _, saved = self.measure(native, lambda: native_file_call(native.cache_save, path))
            savecase = {**prep, "operation": "cache_save"}
            savecase["case_id"] = case_id(savecase)
            self.record(savecase, "passed", predicted=cache_model(self.ps[case["pid"]], "cache_save", level),
                        observed=saved, result={"cache_file_sha256": file_sha(path)})

    def measured_load(self, native, case, path, level):
        vector = self.vectors[case["pid"]]
        _, counts = self.measure(native, lambda: native_file_call(native.cache_load, path, vector["pk_bytes"]))
        loadcase = {**case, "operation": "cache_load_setup", "variant": case["variant"] + "/load"}
        loadcase["case_id"] = case_id(loadcase)
        return self.record(loadcase, "passed", predicted=cache_model(self.ps[case["pid"]], "cache_load", level),
                           observed=counts, result={"cache_file_sha256": file_sha(path), "level": level})

    def run_case(self, case):
        p = self.ps[case["pid"]]
        vector = self.vectors[p.pid]
        operation = case["operation"]
        if operation == "backend_rejection":
            rejected = False
            try:
                with self.native(case):
                    pass
            except NativeError as exc:
                if exc.code != -2:
                    raise
                rejected = True
            return self.record(case, "passed", checks={"explicit_SHA2_AVX2_rejected": rejected})
        if not self.supported(case):
            return self.record(case, "unavailable", reason="requested backend is absent in this build or runtime")
        if operation == "derive_cache":
            source = self.cache_directory(case) / "native-source-t0.cache"
            family = derive_cache_family(p, vector["pk_bytes"], source, self.cache_directory(case))
            atomic_json(self.cache_directory(case) / "independent-cache-family.json", family)
            return self.record(case, "passed", checks={"all_levels_exported": len(family) == p.hp + 1,
                                                       "top_root_matches": cache_payload(self.cache_path(case, p.hp), p,
                                                       vector["pk_bytes"], p.hp)[1] == vector["pk_bytes"][p.n:]},
                               result={"family": family, "native_t0_source_sha256": file_sha(source)})
        with self.native(case) as native:
            if native.backend != BACKENDS[case["backend"]]:
                raise ValueError("actual context backend differs from requested backend")
            if operation == "counter_probe":
                native.bind_key(vector["sk_bytes"])
                _, counts = self.measure(native, lambda: native.subtree("fors", bytes(32), 0, 0))
                row = self.record(case, "passed", predicted=subtree_model(p, "fors", 0), observed=counts,
                                  checks={"counters_enabled": counts["compress"] > 0})
                if not row["passed"]:
                    raise ValueError("COUNTERS=1 library probe failed")
                return row
            if operation == "verify":
                valid, counts = self.measure(native, lambda: native.verify_internal(vector["mp_bytes"], vector["sig_bytes"], vector["pk_bytes"]))
                return self.record(case, "passed", predicted=verify_model(p, len(vector["mp_bytes"]), vector["trace"]["chain_sums"]),
                                   observed=counts, checks={"existing_signature_valid": valid, "independent_trace_root": vector["trace"]["public_root_matches"]},
                                   result={"signature_sha256": sha(vector["sig_bytes"]), "actual_chain_sums": vector["trace"]["chain_sums"]})
            if operation == "subtree":
                native.bind_key(vector["sk_bytes"])
                address = bytearray(32)
                struct.pack_into(">I", address, 0, p.d - 1)
                treebits = p.h - p.hp
                address[8:16] = (((1 << treebits) - 1) if treebits else 0).to_bytes(8, "big")
                struct.pack_into(">I", address, 16, 3 if case["kind"] == "fors" else 0)
                struct.pack_into(">I", address, 20, (1 << p.hp) - 1)
                actual, counts = self.measure(native, lambda: native.subtree(case["kind"], address, case["start"], case["height"], case["target"]))
                # Reference baseline runs outside measured reset/read and is
                # separately logged. It is always explicit REF, one thread.
                key = (p.pid, case["kind"], bytes(address), case["start"], case["height"], case["target"])
                if key not in self.reference_subtrees:
                    refcase = {**case, "backend": "REF", "threads": 1, "operation": "subtree_reference"}
                    refcase["case_id"] = case_id(refcase)
                    with self.native(refcase) as reference:
                        reference.bind_key(vector["sk_bytes"])
                        expected, refcounts = self.measure(reference, lambda: reference.subtree(case["kind"], address,
                                                  case["start"], case["height"], case["target"]))
                    self.reference_subtrees[key] = expected
                    self.record(refcase, "passed", predicted=subtree_model(p, case["kind"], case["height"], 1),
                                observed=refcounts, result={"root_hex": expected[0].hex(), "auth_hex": expected[1].hex(),
                                                           "adrs_hex": address.hex()})
                expected = self.reference_subtrees[key]
                return self.record(case, "passed", predicted=subtree_model(p, case["kind"], case["height"], case["threads"]),
                                   observed=counts, checks={"root_equals_scalar_REF": actual[0] == expected[0],
                                                            "auth_equals_scalar_REF": actual[1] == expected[1]},
                                   result={"root_hex": actual[0].hex(), "auth_hex": actual[1].hex(), "adrs_hex": address.hex()})
            if operation == "keygen":
                level = case["cache_t"]
                native.set_cache_level(level)
                actual, counts = self.measure(native, lambda: native.keygen_internal(vector["sk_seed_bytes"], vector["sk_prf_bytes"], vector["pk_seed_bytes"]))
                row = self.record(case, "passed", predicted=keygen_model(p, case["threads"], level), observed=counts,
                                  checks={"public_key_matches_existing_vector": actual[0] == vector["pk_bytes"],
                                          "secret_key_matches_existing_vector": actual[1] == vector["sk_bytes"]},
                                  result={"public_key_hex": actual[0].hex(), "secret_key_sha256": sha(actual[1])})
                if not row["passed"]:
                    raise ValueError("seeded keygen differs from existing vector")
                if case["variant"] != "native-t0-source":
                    return row
                source = self.cache_directory(case) / "native-source-t0.cache"
                source.parent.mkdir(parents=True, exist_ok=True)
                _, saved = self.measure(native, lambda: native_file_call(native.cache_save, source))
                savecase = {**case, "operation": "cache_save", "variant": "native-t0-source"}
                savecase["case_id"] = case_id(savecase)
                self.record(savecase, "passed", predicted=cache_model(p, "cache_save", 0), observed=saved,
                            result={"cache_file_sha256": file_sha(source)})
                return row
            if operation == "cache_build":
                level = case["cache_t"]
                _, counts = self.measure(native, lambda: native.cache_build(vector["sk_bytes"], level))
                built = self.cache_directory(case) / f"native-{case['backend']}-{case['threads']}-t{level}.cache"
                built.parent.mkdir(parents=True, exist_ok=True)
                _, saved = self.measure(native, lambda: native_file_call(native.cache_save, built))
                expected = self.cache_path(case, level)
                row = self.record(case, "passed", predicted=cache_model(p, "cache_build", level, case["threads"]),
                                  observed=counts, checks={"native_nodes_equal_independent_level": file_sha(built) == file_sha(expected)},
                                  result={"native_cache_sha256": file_sha(built), "derived_cache_sha256": file_sha(expected)})
                savecase = {**case, "operation": "cache_save", "variant": "real-build-save-t" + str(level)}
                savecase["case_id"] = case_id(savecase)
                self.record(savecase, "passed", predicted=cache_model(p, "cache_save", level), observed=saved,
                            result={"cache_file_sha256": file_sha(built)})
                return row
            if operation in ("cache_load_roundtrip", "cache_root_binding"):
                level = case["cache_t"]
                path = self.cache_path(case, level)
                cache_payload(path, p, vector["pk_bytes"], level)
                self.measured_load(native, case, path, level)
                if operation == "cache_load_roundtrip":
                    saved = self.cache_directory(case) / f"roundtrip-{case['backend']}-t{level}.cache"
                    _, counts = self.measure(native, lambda: native_file_call(native.cache_save, saved))
                    return self.record(case, "passed", predicted=cache_model(p, "cache_save", level), observed=counts,
                                       checks={"load_save_bytes_identical": file_sha(saved) == file_sha(path)},
                                       result={"original_file_sha256": file_sha(path), "saved_file_sha256": file_sha(saved)})
                # Matching checksum and matching supplied changed public root
                # must still fail the TREE-root comparison, at every t.
                badpath = self.cache_directory(case) / f"root-tampered-t{level}.cache"
                data = bytearray(path.read_bytes())
                data[48] ^= 1
                wrong_pk = bytes(data[32:64])
                digest = new_hash(True, data[:64]); digest.update(data[96:]); data[64:96] = digest.digest()
                badpath.write_bytes(data)
                caught = None
                try:
                    _, counts = self.measure(native, lambda: native_file_call(native.cache_load, badpath, wrong_pk))
                except NativeError as exc:
                    caught = exc.code
                    counts = exc.optimization_counts
                preserved = self.cache_directory(case) / f"preserved-{case['backend']}-t{level}.cache"
                native_file_call(native.cache_save, preserved)
                return self.record(case, "passed", predicted=cache_model(p, "cache_load", level), observed=counts,
                                   checks={"recomputed_checksum_changed_root_rejected": caught == -4,
                                           "old_good_cache_preserved": file_sha(preserved) == file_sha(path)},
                                   result={"returned_code": caught, "bad_file_sha256": file_sha(badpath),
                                           "preserved_file_sha256": file_sha(preserved)})
            if operation == "sign":
                level = case["cache_t"]
                if level is not None:
                    self.ensure_small_cache(case, level)
                    self.measured_load(native, case, self.cache_path(case, level), level)
                # Explicit signing key, no preparatory keygen on this context:
                # the uncached case is genuinely cache absent.
                signature, counts, receipt = self.sign_attempt(native, vector, vector["sk_bytes"])
                row = self.record(case, "passed", predicted=sign_model(p, len(vector["mp_bytes"]), vector["trace"]["chain_sums"], level, case["threads"]),
                                  observed=counts, checks={"signature_equals_existing_complete_vector": signature == vector["sig_bytes"]},
                                  result={"signature_sha256": sha(signature), "actual_chain_sums": vector["trace"]["chain_sums"]},
                                  budget_receipt=receipt, budget_status="committed")
                if row["passed"]:
                    valid, vcounts = self.measure(native, lambda: native.verify_internal(vector["mp_bytes"], signature, vector["pk_bytes"]))
                    verifycase = {**case, "operation": "verify_generated"}
                    verifycase["case_id"] = case_id(verifycase)
                    self.record(verifycase, "passed", predicted=verify_model(p, len(vector["mp_bytes"]), vector["trace"]["chain_sums"]),
                                observed=vcounts, checks={"new_signature_valid": valid}, result={"signature_sha256": sha(signature)})
                return row
            if operation == "sign_fault":
                # Fresh self-verification context; signing with a changed root
                # is deterministic input corruption, not software injection.
                altered = bytearray(vector["sk_bytes"]); altered[-1] ^= 1
                faultcase = {**case}
                flags = BACKENDS[case["backend"]] | 0x100
                with self.native(faultcase, flags=flags) as checked:
                    try:
                        self.sign_attempt(checked, vector, bytes(altered))
                    except NativeError as exc:
                        return self.record(case, "passed", checks={"self_check_error_returned": exc.code == -5,
                                                                  "failed_attempt_budget_consumed": bool(getattr(exc,"budget_receipt",None))},
                                           observed=getattr(exc,"optimization_counts",None),
                                           result={"error_code": exc.code}, budget_receipt=getattr(exc,"budget_receipt",None),
                                           budget_status="failed", count_model_scope="corrupt input: no successful-path seven-field prediction")
                return self.record(case, "failed", checks={"self_check_error_returned":False})
        raise ValueError("unknown correctness operation")

    def sign_attempt(self, native, vector, sk):
        receipt = self.ledger.reserve(ALGORITHMS[native.pid], vector["pk_bytes"], vector["mp_bytes"])
        try:
            signature, counts = self.measure(native, lambda: native.sign_internal(vector["mp_bytes"], sk,
                None if vector["randomization"] == "deterministic" else vector["opt_rand_bytes"]))
        except BaseException as exc:
            self.ledger.finish(receipt)
            setattr(exc,"budget_receipt",receipt)
            raise
        self.ledger.finish(receipt, signature)
        return signature, counts, receipt

    def deferred_scope(self):
        deferred = []
        if self.args.suite != "full":
            deferred.append("pid3 complete signing, keygen and cache-build thread matrices require --suite full")
            if not self.args.full_small:
                deferred.append("pid1/101 complete signing matrices require --full-small or --suite full")
        if self.args.suite == "light":
            deferred.append("pid3 all-level cache format, load and root-binding require --suite cache or full")
        if not self.args.full_sha2:
            deferred.append("pid103 complete keygen/cache/sign workloads require --suite full --full-sha2")
        return deferred

    def checkpoint(self, error=None, final=False):
        planned_ids = {case["case_id"] for case in self.plan}
        passed = sorted(cid for cid in planned_ids if self.latest.get(cid,{}).get("status") == "passed")
        # A failed auxiliary preparation/reference/load/generated-verify row
        # invalidates the whole run, even if its parent plan row passed.
        failed = sorted(cid for cid, row in self.latest.items() if row["status"] == "failed")
        unavailable = sorted(cid for cid, row in self.latest.items() if row["status"] == "unavailable")
        pending = sorted(planned_ids - set(passed) - set(failed) - set(unavailable))
        observed = [row for row in self.latest.values() if row["passed"]]
        summary = {"schema": SCHEMA, "completed_requested_scope": not (failed or unavailable or pending or error),
                   "passed": not (failed or unavailable or pending or error), "planned_cases": len(self.plan),
                   "passed_planned": len(passed), "failed_case_ids": failed, "unavailable_case_ids": unavailable,
                   "pending_case_ids": pending, "records": len(self.records), "error": error,
                   "failed_auxiliary_case_ids": sorted(set(failed) - planned_ids),
                   "coverage": {"verify_existing_pids": sorted({row["case"]["pid"] for row in observed if row["case"]["operation"]=="verify"}),
                                "complete_sign_pids": sorted({row["case"]["pid"] for row in observed if row["case"]["operation"]=="sign"}),
                                "threads_with_direct_execution": sorted({row["case"]["threads"] for row in observed}),
                                "backends_with_direct_execution": sorted({row["case"]["backend"] for row in observed if row["case"]["operation"]!="backend_rejection"}),
                                "cache_loaded_levels": {str(pid):sorted({row["case"]["cache_t"] for row in observed if row["case"]["pid"]==pid and row["case"]["operation"]=="cache_load_roundtrip"}) for pid in (201,3,103)},
                                "direct_cache_build_levels": {str(pid):sorted({row["case"]["cache_t"] for row in observed if row["case"]["pid"]==pid and row["case"]["operation"]=="cache_build"}) for pid in (201,3,103)},
                                "direct_keygen_threads": {str(pid):sorted({row["case"]["threads"] for row in observed if row["case"]["pid"]==pid and row["case"]["operation"]=="keygen"}) for pid in (201,3,103)},
                                "direct_cache_build_threads": {str(pid):sorted({row["case"]["threads"] for row in observed if row["case"]["pid"]==pid and row["case"]["operation"]=="cache_build"}) for pid in (201,3,103)},
                                "direct_cache_load_threads": {str(pid):sorted({row["case"]["threads"] for row in observed if row["case"]["pid"]==pid and row["case"]["operation"]=="cache_load_setup"}) for pid in (201,3,103)}},
                   "suite": self.args.suite, "full_small":self.args.full_small,"full_sha2":self.args.full_sha2,
                   "global_atomic_measurements_serialized": True, "source_hashes":self.sources,
                   "libraries":self.libraries,"cases_jsonl_sha256":file_sha(self.output),
                   "budget_database":str(self.ledger.path), "budget_status":self.ledger.status(),
                   "formal_performance_started":False,"measured_durations":False,
                   "deferred_scope": self.deferred_scope(), "final": final}
        atomic_json(self.summary_path,summary)
        return summary

    def execute(self):
        error = None
        try:
            for case in self.plan:
                old = self.latest.get(case["case_id"])
                if old and old["status"] == "passed":
                    continue
                try:
                    first_record = len(self.records)
                    self.run_case(case)
                    failed_checks = [row["case_id"] for row in self.records[first_record:] if row["status"] == "failed"]
                    if failed_checks and (self.args.fail_fast or case["operation"] in ("counter_probe","keygen","derive_cache")):
                        error="correctness checks failed: " + ", ".join(failed_checks)
                        break
                except CorrectnessFailure as exc:
                    error=str(exc)
                    break
                except Exception as exc:
                    self.record(case,"failed",observed=getattr(exc,"optimization_counts",None),
                                error=f"{type(exc).__name__}: {exc}",budget_receipt=getattr(exc,"budget_receipt",None),
                                stop_on_failure=False)
                    if self.args.fail_fast or case["operation"] in ("counter_probe","keygen","derive_cache"):
                        error=f"{type(exc).__name__}: {exc}"
                        break
                self.checkpoint()
            # The source must stay unchanged throughout the suite. Another
            # task editing C while a run is active invalidates this evidence.
            if (source_hashes()!=self.sources or file_sha(self.args.vectors)!=self.identity["vector_sha256"] or
                    any(file_sha(item["path"])!=item["sha256"] for item in self.libraries.values())):
                error="source, library or vector input changed during correctness run; preserve records and rerun a frozen build"
        except BaseException as exc:
            error=f"{type(exc).__name__}: {exc}"
        finally:
            summary=self.checkpoint(error, final=True)
            self.close()
        return summary


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library",type=Path,action="append",required=True,
                        help="COUNTERS=1 shared library; repeat for portable and optimized builds")
    parser.add_argument("--run-dir",type=Path,required=True,help="new append-only correctness evidence directory")
    parser.add_argument("--budget-db",type=Path,required=True,help="shared durable ledger for all experimental signing keys")
    parser.add_argument("--vectors",type=Path,default=ROOT/"report-data/DP1-analysis/count-replay-inputs.jsonl")
    parser.add_argument("--suite",choices=("light","cache","full"),default="light",
                        help="cache additionally builds pid3 all-level caches; full also signs pid3 at every level and matrix")
    parser.add_argument("--full-small",action="store_true",help="include pid1/101 complete signing matrix in light/cache suites")
    parser.add_argument("--full-sha2",action="store_true",help="with --suite full, explicitly add pid103 full keygen/cache/sign workloads")
    parser.add_argument("--threads",type=int,nargs="+",default=[1,2,4,8,16,32,64])
    parser.add_argument("--backends",choices=tuple(BACKENDS),nargs="+",default=["REF","AVX2"])
    parser.add_argument("--cache-source-backend",choices=tuple(BACKENDS),default="REF",
                        help="explicit backend used once for the reusable native t0 source; REF supports portable builds")
    parser.add_argument("--subtree-heights",type=int,nargs="+",default=[0,1,2,3,4,5,6])
    parser.add_argument("--resume",action="store_true")
    parser.add_argument("--fail-fast",action="store_true")
    args=parser.parse_args()
    if args.full_sha2 and args.suite != "full":parser.error("--full-sha2 requires --suite full")
    if any(not 1<=n<=1024 for n in args.threads):parser.error("resolved threads must be 1..1024")
    if any(not 0<=z<=12 for z in args.subtree_heights):parser.error("bounded subtrees require heights0..12")
    args.threads=list(dict.fromkeys(args.threads))
    args.backends=list(dict.fromkeys(args.backends))
    args.subtree_heights=list(dict.fromkeys(args.subtree_heights))
    args.library=list(dict.fromkeys(args.library))
    try:
        runner=Runner(args)
        result=runner.execute()
    except Exception as exc:
        print(json.dumps({"passed":False,"initialization_error":f"{type(exc).__name__}: {exc}"}),flush=True)
        return 1
    print(json.dumps({"summary":str(args.run_dir/"summary.json"),"passed":result["passed"],
                      "planned_cases":result["planned_cases"],"passed_planned":result["passed_planned"],
                      "pending":len(result["pending_case_ids"]),"unavailable":len(result["unavailable_case_ids"]),
                      "formal_performance_started":False}),flush=True)
    return 0 if result["passed"] else 1


if __name__=="__main__":
    raise SystemExit(main())
