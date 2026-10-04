"""Finite d=1 parameter/cache analysis; never executes a cryptographic kernel.

All costs are exact analytical work, not timing. New parameter IDs and resource
shapes are research records only and do not register production parameters.
"""

import argparse
import csv
from dataclasses import asdict, dataclass
from decimal import Decimal, localcontext
from fractions import Fraction
import hashlib
from itertools import combinations
import json
from pathlib import Path
import sys
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.count_model import Parameter, cache_model, parameters
from tools.parameter_grid import candidate_constraints, theoretical_cost
from tools.security_terms import fors_probability

UPSTREAM_COMMIT = "375c69e638b079fdf4bb8ef10c9c3549f08e05f9"
UPSTREAM_BASE = "https://raw.githubusercontent.com/chrisfenner/slh-dsa-rls/" + UPSTREAM_COMMIT
SOURCE_PATHS = ("README.md", "pkg/slhdsa/param.go", "LICENSE")
CACHE_LEVELS = (10, 12)
EXECUTION_MODES = ("F8", "A8", "F1", "AF")
VERIFICATION_MODES = ("V0", "V1")
USAGE_LIMIT = 1 << 24


@dataclass(frozen=True)
class Candidate:
    identity: str
    a: int
    k: int
    upstream_id: str
    native_pid: int | None = None
    n: int = 16
    h: int = 22
    d: int = 1
    lgw: int = 2
    length: int = 68

    def model_parameter(self):
        m = (self.k * self.a + 7) // 8 + (self.h + 7) // 8
        return Parameter(self.native_pid or 0, 1, self.h, 1, self.h,
                         self.a, self.k, self.lgw, self.length, m, self.n)


CANDIDATES = (
    Candidate("pid3", 24, 6, "rls128cs1", 3),
    Candidate("rls128cs3", 21, 7, "rls128cs3"),
    Candidate("rls128cs11", 19, 8, "rls128cs11"),
    Candidate("rls128cs18", 17, 9, "rls128cs18"),
)


@dataclass(frozen=True)
class ResourceProfile:
    active_keys: int = 1
    workers: int = 1
    # This explicit design reserve covers work snapshots, pointers, round state,
    # F/H scratch and compiler spills; it is not a measured stack/RSS guarantee.
    auxiliary_workspace_per_worker: int = 16384
    verifier_buffers_bytes: int = 16384
    other_live_memory_bytes: int = 65536
    public_table_copies: int = 1

    def validate(self):
        for name, value in asdict(self).items():
            if type(value) is not int or value < (1 if name in (
                    "active_keys", "workers", "public_table_copies") else 0):
                raise ValueError("invalid resource profile field: " + name)


@dataclass(frozen=True)
class Budgets:
    total_memory_bytes: int = 512 * 1024
    cache_files_bytes: int = 256 * 1024
    signature_bytes: int = 4096
    per_worker_workspace_bytes: int = 32768
    signature_lifetime_count: int = USAGE_LIMIT
    require_native_parameter: bool = False

    def validate(self):
        for name, value in asdict(self).items():
            if name == "require_native_parameter":
                if type(value) is not bool:
                    raise ValueError("require_native_parameter must be boolean")
            elif type(value) is not int or value < 0:
                raise ValueError("invalid budget field: " + name)


@dataclass(frozen=True)
class Workload:
    signatures: int
    external_verifications: int
    transmissions: int
    byte_weight: Fraction = Fraction(0)
    preparations: int = 1

    def validate(self):
        for name in ("signatures", "external_verifications", "transmissions", "preparations"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError("invalid workload field: " + name)
        if not isinstance(self.byte_weight, (int, Fraction)) or self.byte_weight < 0:
            raise ValueError("byte_weight must be a nonnegative exact rational")


def exact_text(value):
    value = Fraction(value)
    return str(value.numerator) if value.denominator == 1 else f"{value.numerator}/{value.denominator}"


def decimal_text(value, places=6):
    value = Fraction(value)
    with localcontext() as context:
        context.prec = 70
        return format(Decimal(value.numerator) / Decimal(value.denominator), f".{places}f")


def json_value(value):
    if isinstance(value, Fraction):
        return {"numerator": str(value.numerator), "denominator": str(value.denominator)}
    if isinstance(value, dict):
        return {key: json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_value(item) for item in value]
    return value


def authentication_calls(t):
    if type(t) is not int or not 0 <= t <= 22:
        raise ValueError("the finite d=1 model requires 0<=t<=22")
    return 274 * ((1 << t) - 1) - t


def validate_candidate(candidate):
    if (candidate.n, candidate.h, candidate.d, candidate.lgw, candidate.length) != (16, 22, 1, 2, 68):
        raise ValueError("candidate is outside the frozen d=1 structure")
    if type(candidate.a) is not int or type(candidate.k) is not int or not 1 <= candidate.a <= 24 or not 1 <= candidate.k <= 35:
        raise ValueError("candidate a/k is outside the bounded positive domain")
    failures = candidate_constraints(candidate.n, candidate.h, candidate.d,
                                    candidate.a, candidate.k, candidate.lgw)
    if failures:
        raise ValueError("candidate violates structure: " + ",".join(failures))
    if candidate.native_pid is not None:
        actual = parameters()[candidate.native_pid]
        if actual != candidate.model_parameter():
            raise ValueError("candidate differs from the native pid table")


def analytical_row(candidate, t):
    validate_candidate(candidate)
    if t not in CACHE_LEVELS:
        raise ValueError("cache level is outside the frozen set")
    cost = theoretical_cost(candidate.n, candidate.h, candidate.d, candidate.a,
                            candidate.k, candidate.lgw, t, message_length=64)
    p = candidate.model_parameter()
    load = cache_model(p, "cache_load", t)
    keygen = cache_model(p, "cache_build", t)
    checksum = load["metadata"]["cache_checksum_compressions_uninstrumented"]
    row = {"configuration": candidate.identity + "-t" + str(t),
           "parameter_identity": candidate.identity, "native_pid": candidate.native_pid,
           "upstream_id": candidate.upstream_id, "a": candidate.a, "k": candidate.k,
           "cache_t": t, "signature_bytes": cost["signature_bytes"],
           "fors_sign_calls": cost["fors_sign_primitive_calls"],
           "authentication_calls": authentication_calls(t),
           "sign_calls_without_self_verify": cost["expected_sign_primitive_calls"],
           "verify_calls": cost["expected_verify_primitive_calls"],
           "sign_calls_with_ref_self_verify": cost["expected_sign_primitive_calls"] + cost["expected_verify_primitive_calls"],
           "sign_compressions_without_self_verify": cost["expected_sign_compressions"],
           "verify_compressions": cost["expected_verify_compressions"],
           "sign_compressions_with_ref_self_verify": cost["expected_sign_compressions"] + cost["expected_verify_compressions"],
           "cache_file_bytes": cost["cache_file_bytes"],
           "cache_node_ram_bytes": cost["cache_node_ram_bytes"],
           "keygen_or_cache_build_calls": sum(keygen["counts"][name] for name in ("prf", "prf_msg", "h_msg", "f", "h", "t")),
           "keygen_or_cache_build_compressions": keygen["counts"]["compress"],
           "cache_load_calls": load["counts"]["h"],
           "cache_load_counted_compressions": load["counts"]["compress"],
           "cache_load_checksum_hashes_uninstrumented": 1,
           "cache_load_checksum_compressions_uninstrumented": checksum,
           "cache_load_total_hash_compressions": load["counts"]["compress"] + checksum,
           "wots_uniform_chain_steps": cost["wots_uniform_chain_steps_expected"],
           "analysis_only": True, "new_performance_samples": 0}
    return row


def resources(row, mode, profile):
    profile.validate()
    if mode not in EXECUTION_MODES:
        raise ValueError("unknown execution mode")
    z = min(24, row["a"])
    q = z - 3
    secret = 2176 if mode in ("F8", "A8") else 272
    offsets = 2176 if mode in ("F1", "AF") else 0
    deltas = 272 * q if mode in ("A8", "AF") else 0
    tree_and_levels = (z + 1) * (8 * 16 + 4)
    # Current 64-bit prototype reserves the same stream union for every mode
    # and all q tables in BSS. Charge capacity rather than just populated data.
    stream_reserved = 2304
    tree_reserved = 25 * (8 * 16 + 4)
    public_reserved = 5712 + 47872 + 23 * 4
    worker = stream_reserved + tree_reserved + profile.auxiliary_workspace_per_worker
    public = public_reserved * profile.public_table_copies
    node_ram = row["cache_node_ram_bytes"] * profile.active_keys
    total = (node_ram + profile.workers * worker + public
             + profile.verifier_buffers_bytes + profile.other_live_memory_bytes)
    return {"execution_mode": mode, "tile_height": z, "q": q,
            "persistent_secret_schedule_bytes_per_worker": secret,
            "public_offsets_bytes_per_copy": offsets,
            "public_deltas_bytes_per_copy": deltas,
            "tree_stack_and_level_bytes_per_worker": tree_and_levels,
            "stream_object_reserved_bytes_per_worker": stream_reserved,
            "tree_stack_and_level_reserved_bytes_per_worker": tree_reserved,
            "public_tables_and_atomic_state_reserved_bytes_per_copy": public_reserved,
            "auxiliary_reserve_bytes_per_worker": profile.auxiliary_workspace_per_worker,
            "workspace_bytes_per_worker": worker, "shared_public_bytes": public,
            "active_cache_node_ram_bytes": node_ram,
            "cache_files_bytes": row["cache_file_bytes"] * profile.active_keys,
            "verifier_buffers_bytes": profile.verifier_buffers_bytes,
            "other_live_memory_bytes": profile.other_live_memory_bytes,
            "modeled_total_live_bytes": total,
            "mode_applicability": "pid3 current 64-bit prototype reservation plus explicit reserve" if row["native_pid"] == 3 else "hypothetical same-capacity adaptation; native adaptation pending",
            "is_measured_peak_memory": False}


def excluded_constraints(row, usage, mode, profile, budgets):
    budgets.validate()
    if type(usage) is not int or usage < 0:
        raise ValueError("usage must be a nonnegative integer")
    memory = resources(row, mode, profile)
    failures = []
    for actual, limit, reason in (
            (memory["modeled_total_live_bytes"], budgets.total_memory_bytes, "modeled_total_memory"),
            (memory["cache_files_bytes"], budgets.cache_files_bytes, "aggregate_cache_files"),
            (row["signature_bytes"], budgets.signature_bytes, "signature_size"),
            (memory["workspace_bytes_per_worker"], budgets.per_worker_workspace_bytes, "per_worker_workspace"),
            (usage, min(USAGE_LIMIT, budgets.signature_lifetime_count), "strict_per_key_lifetime_signatures")):
        if actual > limit:
            failures.append(reason)
    if budgets.require_native_parameter and row["native_pid"] is None:
        failures.append("native_parameter_absent")
    return failures


def coefficients(row, metric="calls", preparation="load"):
    if metric not in ("calls", "compressions") or preparation not in ("load", "build", "none"):
        raise ValueError("unknown work metric or preparation")
    if metric == "calls":
        prep = {"load": row["cache_load_calls"], "build": row["keygen_or_cache_build_calls"], "none": 0}[preparation]
        sign, verify = row["sign_calls_with_ref_self_verify"], row["verify_calls"]
    else:
        prep = {"load": row["cache_load_total_hash_compressions"], "build": row["keygen_or_cache_build_compressions"], "none": 0}[preparation]
        sign, verify = row["sign_compressions_with_ref_self_verify"], row["verify_compressions"]
    return {"preparation": Fraction(prep), "sign": Fraction(sign),
            "external_verify": Fraction(verify), "bytes": Fraction(row["signature_bytes"])}


def analytical_cost(row, workload, metric="calls", preparation="load"):
    workload.validate()
    c = coefficients(row, metric, preparation)
    return (workload.preparations * c["preparation"] + workload.signatures * c["sign"]
            + workload.external_verifications * c["external_verify"]
            + workload.transmissions * workload.byte_weight * c["bytes"])


def region_difference(x, y, metric="calls", preparation="load"):
    xc, yc = coefficients(x, metric, preparation), coefficients(y, metric, preparation)
    return {name: xc[name] - yc[name] for name in xc}


def pareto_relations(rows):
    fields = ("sign_calls_with_ref_self_verify", "verify_calls", "signature_bytes",
              "cache_node_ram_bytes", "cache_file_bytes", "cache_load_total_hash_compressions")
    def dominates(x, y):
        return all(x[f] <= y[f] for f in fields) and any(x[f] < y[f] for f in fields)
    return {row["configuration"]: [x["configuration"] for x in rows if dominates(x, row)] for row in rows}


def minimax_regret(rows, scenarios, metric="calls", preparation="load"):
    if not rows or not scenarios:
        raise ValueError("a fixed nonempty feasible set and scenario set are required")
    costs = [{row["configuration"]: analytical_cost(row, scenario, metric, preparation)
              for row in rows} for scenario in scenarios]
    best = [min(cost.values()) for cost in costs]
    regrets = {row["configuration"]: max(cost[row["configuration"]] - optimal
                                        for cost, optimal in zip(costs, best)) for row in rows}
    minimum = min(regrets.values())
    return {"worst_regret": regrets,
            "minimax_ids": sorted(identity for identity, regret in regrets.items() if regret == minimum),
            "scope": "exact logical-work regret on this fixed finite feasible/scenario set"}


def verify_upstream_readme(text):
    evidence = []
    for candidate in CANDIDATES:
        lines = [line for line in text.splitlines() if line.startswith("| " + candidate.upstream_id + " |")]
        if len(lines) != 1:
            raise ValueError("missing or duplicate pinned upstream row: " + candidate.upstream_id)
        cells = [cell.strip() for cell in lines[0].strip("|").split("|")]
        observed = tuple(map(int, cells[1:7]))
        if observed != (22, 1, 22, candidate.a, candidate.k, 2):
            raise ValueError("pinned upstream structure mismatch: " + candidate.upstream_id)
        expected_bytes = candidate.model_parameter().signature_bytes
        if int(cells[8]) != expected_bytes:
            raise ValueError("pinned upstream signature length mismatch")
        evidence.append({"id": candidate.upstream_id, "exact_table_line": lines[0],
                         "readme_line": text.splitlines().index(lines[0]) + 1,
                         "w_column_interpreted_as_lgw": 2})
    return evidence


def source_files(output, fetch):
    source_dir = output / "sources"
    if fetch:
        source_dir.mkdir(parents=True, exist_ok=True)
        for source in SOURCE_PATHS:
            with urlopen(UPSTREAM_BASE + "/" + source, timeout=30) as response:
                data = response.read()
            (source_dir / Path(source).name).write_bytes(data)
    readme, param = source_dir / "README.md", source_dir / "param.go"
    if not readme.exists() or not param.exists():
        raise ValueError("pinned sources missing; use --fetch-source once")
    matches = verify_upstream_readme(readme.read_text(encoding="utf-8"))
    go = param.read_text(encoding="utf-8")
    if "LgW int" not in go or "w := 1 << p.LgW" not in go:
        raise ValueError("pinned LgW meaning was not confirmed")
    return {"commit": UPSTREAM_COMMIT, "license": "Apache-2.0", "table_rows": matches,
            "files": [{"path": "sources/" + Path(name).name,
                       "url": UPSTREAM_BASE + "/" + name,
                       "sha256": hashlib.sha256((source_dir / Path(name).name).read_bytes()).hexdigest()}
                      for name in SOURCE_PATHS],
            "upstream_costs_imported": False,
            "reason": "upstream full-cache and approximate WOTS costs differ from current execution formulas"}


def write_csv(path, rows):
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        for row in rows:
            writer.writerow({key: exact_text(value) if isinstance(value, Fraction) else value
                             for key, value in row.items()})


def write_json(path, data):
    path.write_text(json.dumps(json_value(data), ensure_ascii=True, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def build_package(output, fetch_source=False):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    upstream = source_files(output, fetch_source)
    rows = [analytical_row(candidate, t) for candidate in CANDIDATES for t in CACHE_LEVELS]
    write_csv(output / "parameter-cache-exact.csv", rows)
    public_probabilities = [dict(parameter_identity=c.identity, **fors_probability(
        c.h, c.a, c.k, USAGE_LIMIT, precision=100)) for c in CANDIDATES]
    write_json(output / "FORS-single-term-intervals.json", public_probabilities)
    profile = ResourceProfile()
    memory_rows = [dict(configuration=row["configuration"], **resources(row, mode, profile))
                   for row in rows for mode in EXECUTION_MODES]
    write_csv(output / "resource-shapes.csv", memory_rows)
    constraints = []
    examples = (
        ("single-key-512KiB", profile, Budgets()),
        ("four-keys-four-workers-512KiB", ResourceProfile(active_keys=4, workers=4), Budgets()),
        ("signature-cap-3856B", profile, Budgets(signature_bytes=3856)),
        ("native-parameters-only", profile, Budgets(require_native_parameter=True)),
    )
    for name, resource, budget in examples:
        for row in rows:
            for mode in EXECUTION_MODES:
                failures = excluded_constraints(row, USAGE_LIMIT, mode, resource, budget)
                constraints.append({"scenario": name, "configuration": row["configuration"],
                                    "execution_mode": mode, "analytically_feasible": not failures,
                                    "excluded_constraints": ";".join(failures),
                                    "modeled_total_live_bytes": resources(row, mode, resource)["modeled_total_live_bytes"]})
    write_csv(output / "constraints.csv", constraints)
    regions = []
    for metric in ("calls", "compressions"):
        for preparation in ("load", "build", "none"):
            for x, y in combinations(rows, 2):
                regions.append({"x": x["configuration"], "y": y["configuration"],
                                "metric": metric, "preparation_mode": preparation,
                                **region_difference(x, y, metric, preparation),
                                "inequality": "preparations*dF + Q*dS + V*dG + N*beta*dB <= 0"})
    write_csv(output / "pairwise-selection-regions.csv", regions)
    workloads = (Workload(1, 0, 1), Workload(1, 1 << 30, 1 << 30, Fraction(1, 64)),
                 Workload(1024, 1024, 1024), Workload(0, 1 << 30, 1 << 30, Fraction(1, 64)))
    feasible = [row for row in rows if not excluded_constraints(
        row, max(w.signatures for w in workloads), "AF", profile, Budgets())]
    if not feasible:
        raise ValueError("the fixed analytical scenario set has no feasible configurations")
    scenarios = []
    for metric in ("calls", "compressions"):
        for index, workload in enumerate(workloads):
            values = {r["configuration"]: analytical_cost(r, workload, metric) for r in feasible}
            optimum = min(values.values())
            scenarios.append({"scenario_id": index, "metric": metric, "workload": asdict(workload),
                              "costs": values, "minimum_ids": sorted(k for k, value in values.items() if value == optimum)})
    write_json(output / "finite-scenarios.json", scenarios)
    write_json(output / "pareto-and-regret.json", {
        "dominated_by": pareto_relations(rows),
        "fixed_feasible_set": [row["configuration"] for row in feasible],
        "feasible_set_execution_resource_shape": "AF",
        "feasible_set_resource_profile": asdict(profile), "budgets": asdict(Budgets()),
        "calls": minimax_regret(feasible, workloads), "compressions": minimax_regret(feasible, workloads),
        "not_global_optimum": True})
    write_json(output / "parameter-applicability.json", [
        {"parameter_identity": c.identity, "native_pid": c.native_pid,
         "native_parameter_available": c.native_pid is not None,
         "analysis_structure_constraints": "passed bounded d=1 structural checks",
         "analysis_usage_limit": str(USAGE_LIMIT),
         "full_scheme_applicability_status": "pending candidate-specific review",
         "source_parameter_claim_transferred_to_SM3": False,
         "FORS_term_record": "FORS-single-term-intervals.json",
         "production_parameter_registration_performed": False,
         "required_before_new_parameter_prototype": [
             "complete versioned security argument and signing/attack-query assumptions",
             "classical and quantum scope, multi-target losses and all non-FORS terms",
             "SM3 PRF/hash-family substitution assumptions",
             "distinct parameter encoding/OID, key identity and bound cache identity",
             "independent reference vectors and aggregate per-key usage budget"],
         "historical_pid3_delivery_status_changed": False} for c in CANDIDATES])
    lines = ["# Finite d=1 analytical parameter/cache table", "",
             "Exact rational work; no measured timings; new performance samples: 0.",
             "Signing includes independent REF self-verification in the `with self verify` column.", "",
             "| Parameter | t | Signature B | Sign calls, no self verify | Sign calls, with self verify | Verify calls | Cache file B | Cache node RAM B |",
             "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for row in rows:
        lines.append(f"| {row['parameter_identity']} | {row['cache_t']} | {row['signature_bytes']} | "
                     f"{decimal_text(row['sign_calls_without_self_verify'])} | {exact_text(row['sign_calls_with_ref_self_verify'])} | "
                     f"{decimal_text(row['verify_calls'])} | {row['cache_file_bytes']} | {row['cache_node_ram_bytes']} |")
    lines.extend(["", "C_auth(12)-C_auth(10)=841726 logical calls; compression difference=893950.",
                  "The resource model is an explicit shape plus reserve, not measured peak RSS.",
                  "A/V elapsed costs remain unknown F_x, S_x, G_x; logical work does not rank execution modes.",
                  "Published neighbors are analytical candidates; full applicability and native adaptation remain pending.", ""])
    (output / "tables.md").write_text("\n".join(lines), encoding="utf-8")
    source_names = ("tools/incremental_parameters.py", "tools/test_incremental_parameters.py",
                    "tools/parameter_grid.py", "tools/count_model.py", "tools/security_terms.py", "SPEC.md",
                    "c/src/engine.c", "c/src/sm3_incremental.c", "c/src/sm3_incremental.h", "docs/research/P_20261005.md")
    files = {str(path.relative_to(output)).replace("\\", "/"): hashlib.sha256(path.read_bytes()).hexdigest()
             for path in output.rglob("*") if path.is_file() and path.name != "manifest.json"}
    metadata = {"schema_version": 1, "analysis_id": "P-finite-d1-20261005",
                "new_performance_samples": 0, "cryptographic_kernel_invoked": False,
                "candidate_count": len(CANDIDATES), "parameter_cache_count": len(rows),
                "resource_shape_count": len(memory_rows), "pairwise_region_count": len(regions),
                "upstream": upstream, "resource_profile": asdict(profile),
                "execution_modes": EXECUTION_MODES, "verification_modes": VERIFICATION_MODES,
                "execution_timing_model": "F_x + Q*S_x + V*G_x + N*B_x*beta; F/S/G unknown for each p,t,e,v",
                "resource_model_scope": "represented objects plus explicit design reserve, not measured RSS/stack",
                "parameter_cache_lifetime": "parameter fixed at key creation; cache identity bound to pid/key/t",
                "native_pid3_parameters_as_read": asdict(parameters()[3]),
                "usage_limit": str(USAGE_LIMIT), "usage_scope": "strict aggregate per key across copies/devices",
                "security_scope": "FORS target coverage term only; no full-scheme security label",
                "source_hashes": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in source_names},
                "files": files}
    write_json(output / "manifest.json", metadata)
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "validation/incremental-20261005/parameters")
    parser.add_argument("--fetch-source", action="store_true", help="download public analysis sources and license at the fixed upstream commit")
    args = parser.parse_args()
    result = build_package(args.output, args.fetch_source)
    print(json.dumps({key: result[key] for key in ("analysis_id", "candidate_count", "parameter_cache_count",
                      "resource_shape_count", "pairwise_region_count", "new_performance_samples")}))


if __name__ == "__main__":
    main()
