"""Freeze and explore a finite analytical SLH-DSA parameter grid.

Candidates are not new engine parameters or completed security assessments.
Only the explicitly labeled FORS probability term is filtered at 2^24 signing
observations. Counts are current scalar-path formulas with an exact uniform-
message WOTS expectation, not case-specific observations or runtime estimates.
"""

import argparse
from collections import defaultdict
from datetime import datetime, timezone
from decimal import Decimal
from fractions import Fraction
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.count_model import hash_compressions, parameters
from tools.security_terms import file_hash, fors_probabilities, source_metadata, write_csv

CONFIG = {
    "schema_version": 1, "grid_id": "limited-use-analytic-grid-v1",
    "n_values": [16], "h_values": list(range(20, 33, 2)), "d_values": list(range(1, 9)),
    "a_values": list(range(8, 25, 2)), "k_values": sorted(set(range(4, 35, 2)) | {33}),
    "lgw_values": [2, 3, 4], "q": str(1 << 24), "FORS_term_min_exponent": 128,
    "precision_decimal_digits": 100, "relative_tail": "1e-40",
    "message_length_internal": 64, "cache_level_rule": "min(12,hp) top-layer only",
    "constraints": ["h divisible by d", "hp<=24", "h-hp<=64", "k<=35", "a<=24",
                    "k*2^a<=2^32", "ceil(8n/lgw)+floor(log_w(len1*(w-1)))+1<=68",
                    "m=ceil(k*a/8)+ceil((h-hp)/8)+ceil(hp/8)<=49"],
    "primary_pareto_minimize": ["signature_bytes", "expected_sign_primitive_calls_no_cache"],
    "secondary_pareto_minimize": ["signature_bytes", "expected_sign_primitive_calls_t12"],
    "secondary_cache_storage_constraint": "none; each row reports different storage",
    "screening_scope": "FORS target-coverage term only; does not certify overall security or NIST category",
    "candidate_status": "analytical candidate; not implemented except exact matches in the fixed C pid table",
    "lgw3_encoding": "ceil length; final message digit zero-padded on the right (2 data bits then 1 zero bit)",
    "no_global_optimality_claim": True,
}


def wots_lengths(n, lgw):
    w = 1 << lgw
    l1 = (8 * n + lgw - 1) // lgw
    value = l1 * (w - 1)
    l2 = 0
    while value:
        l2 += 1
        value //= w
    return l1, l2, l1 + l2


def base_w_digit_sum(value, lgw):
    mask = (1 << lgw) - 1
    result = 0
    while value:
        result += value & mask
        value >>= lgw
    return result


@lru_cache(maxsize=None)
def wots_distribution(n, lgw):
    """Exact expectation over all uniformly distributed 8n-bit messages.

    A dynamic program counts possible sums of message digits; checksum digits
    depend only on that sum. The final incomplete digit for lgw=3 is explicitly
    padded, so the sample space stays 2^(8n), not 2^(len1*lgw).
    """
    l1, l2, length = wots_lengths(n, lgw)
    w = 1 << lgw
    counts = {0: 1}
    remainder = 8 * n % lgw
    for ordinal in range(l1):
        values = (range(w) if ordinal < l1 - 1 or remainder == 0 else
                  [value << (lgw - remainder) for value in range(1 << remainder)])
        next_counts = defaultdict(int)
        for total, ways in counts.items():
            for value in values:
                next_counts[total + value] += ways
        counts = next_counts
    sums = defaultdict(int)
    for digit_sum, ways in counts.items():
        checksum = l1 * (w - 1) - digit_sum
        sums[digit_sum + base_w_digit_sum(checksum, lgw)] += ways
    population = sum(sums.values())
    if population != 1 << (8 * n):
        raise AssertionError("WOTS uniform-message population mismatch")
    expected = Fraction(sum(total * ways for total, ways in sums.items()), population)
    return {"len1": l1, "len2": l2, "length": length, "capacity": length * (w - 1),
            "expectation": expected, "minimum": min(sums), "maximum": max(sums),
            "population": population, "distribution": dict(sorted(sums.items()))}


def theoretical_cost(n, h, d, a, k, lgw, cache_t=None, message_length=64):
    hp = h // d
    distribution = wots_distribution(n, lgw)
    length, capacity = distribution["length"], distribution["capacity"]
    expected = distribution["expectation"]
    m = (k * a + 7) // 8 + (h - hp + 7) // 8 + (hp + 7) // 8
    cw, cf = hash_compressions(22 + length * n), hash_compressions(22 + k * n)
    top_limit = hp if cache_t is None else cache_t
    leaves = (d - 1) * ((1 << hp) - 1) + (1 << top_limit) - 1
    sibling_h = (d - 1) * ((1 << hp) - 1 - hp) + (1 << top_limit) - 1 - top_limit
    prf = k * ((1 << a) + 1) + length * (leaves + d)
    f_fixed = k * (1 << a) + capacity * leaves + (d - 1) * capacity
    hh = k * ((1 << a) - 1) + sibling_h + (d - 1) * hp
    tw = leaves + d - 1
    cc = 1 + (hash_compressions(64 + n + message_length) + hash_compressions(96))
    cc += hash_compressions(3 * n + message_length) + ((m + 31) // 32) * hash_compressions(2 * n + 36)
    sign_fixed = prf + f_fixed + hh + tw + 1 + 2  # T_fors plus two message primitives.
    sign_compress_fixed = cc + prf + f_fixed + hh + cw * tw + cf
    verify_fixed = k + d * capacity + k * a + d * hp + d + 1 + 1
    verify_compress_fixed = (1 + hash_compressions(3 * n + message_length)
                             + ((m + 31) // 32) * hash_compressions(2 * n + 36)
                             + k + d * capacity + k * a + d * hp + d * cw + cf)
    return {"signature_bytes": n * (1 + k * (a + 1) + h + d * length), "m": m,
            "wots_len1": distribution["len1"], "wots_len2": distribution["len2"], "wots_len": length,
            "wots_actual_chain_steps_min": distribution["minimum"],
            "wots_actual_chain_steps_max": distribution["maximum"],
            "wots_uniform_chain_steps_expected": expected,
            "sign_primitive_fixed_before_final_chain": sign_fixed,
            "expected_sign_primitive_calls": Fraction(sign_fixed) + expected,
            "sign_primitive_calls_min": sign_fixed + distribution["minimum"],
            "sign_primitive_calls_max": sign_fixed + distribution["maximum"],
            "expected_sign_compressions": Fraction(sign_compress_fixed) + expected,
            "expected_verify_primitive_calls": Fraction(verify_fixed) - d * expected,
            "verify_primitive_calls_min": verify_fixed - d * distribution["maximum"],
            "verify_primitive_calls_max": verify_fixed - d * distribution["minimum"],
            "expected_verify_compressions": Fraction(verify_compress_fixed) - d * expected,
            "keygen_primitive_calls": (1 << hp) * (length + capacity + 1) + (1 << hp) - 1,
            "keygen_compressions": 1 + (1 << hp) * (length + capacity + cw) + (1 << hp) - 1,
            "fors_sign_primitive_calls": 3 * k * (1 << a) + 1,
            "cache_t": cache_t, "cache_payload_bytes": 0 if cache_t is None else n * (1 << (hp - cache_t)),
            "cache_file_bytes": 0 if cache_t is None else 96 + n * (1 << (hp - cache_t)),
            "cache_node_ram_bytes": 0 if cache_t is None else n * ((1 << (hp - cache_t + 1)) - 1)}


def serialize_cost(cost):
    result = {}
    for key, value in cost.items():
        if isinstance(value, Fraction):
            result[key] = format(float(value), ".12g")
            if key == "wots_uniform_chain_steps_expected":
                result["wots_uniform_expectation_exact_fraction"] = f"{value.numerator}/{value.denominator}"
        else:
            result[key] = value
    return result


def candidate_constraints(n, h, d, a, k, lgw):
    failures = []
    if h % d:
        failures.append("h_not_divisible_by_d")
        return failures
    hp = h // d
    length = wots_lengths(n, lgw)[2]
    m = (k * a + 7) // 8 + (h - hp + 7) // 8 + (hp + 7) // 8
    if hp > 24: failures.append("hp_above_structural_limit24")
    if h - hp > 64: failures.append("tree_index_above_uint64")
    if k * (1 << a) > 1 << 32: failures.append("fors_offset_above_uint32")
    if k > 35: failures.append("fors_roots_array_bound")
    if a > 24: failures.append("tree_height_bound")
    if length > 68: failures.append("wots_array_bound")
    if m > 49: failures.append("digest_array_bound")
    return failures


def pareto_ids(rows, x, y):
    """Exact weak-dominance with at least one strict objective improvement."""
    grouped = defaultdict(list)
    for row in rows:
        grouped[int(row[x])].append(row)
    best_before = None
    result = set()
    for size in sorted(grouped):
        at_size = grouped[size]
        best_at = min(row[y] for row in at_size)
        if best_before is None or best_at < best_before:
            result.update(row["candidate_id"] for row in at_size if row[y] == best_at)
        best_before = best_at if best_before is None else min(best_before, best_at)
    return result


def build_package(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    config_canonical = json.dumps(CONFIG, sort_keys=True, separators=(",", ":")).encode()
    config_hash = hashlib.sha256(config_canonical).hexdigest()
    (output / "grid-config.json").write_text(json.dumps({**CONFIG, "configuration_sha256": config_hash}, indent=2) + "\n", encoding="utf-8")
    implemented = parameters()
    matching = {(p.n, p.h, p.d, p.a, p.k, p.lgw): [q.pid for q in implemented.values()
                if (q.n,q.h,q.d,q.a,q.k,q.lgw)==(p.n,p.h,p.d,p.a,p.k,p.lgw)] for p in implemented.values()}
    probability_cache = {}
    for h in CONFIG["h_values"]:
        for a in CONFIG["a_values"]:
            probability_cache[(h,a)] = fors_probabilities(h, a, CONFIG["k_values"], int(CONFIG["q"]),
                precision=CONFIG["precision_decimal_digits"], relative_tail=CONFIG["relative_tail"])
    rows, exact_frontier_inputs = [], []
    for n in CONFIG["n_values"]:
        for h in CONFIG["h_values"]:
            for d in CONFIG["d_values"]:
                for a in CONFIG["a_values"]:
                    for k in CONFIG["k_values"]:
                        for lgw in CONFIG["lgw_values"]:
                            cid = f"n{n}-h{h}-d{d}-a{a}-k{k}-b{lgw}"
                            failures = candidate_constraints(n,h,d,a,k,lgw)
                            value = probability_cache[(h,a)][k]
                            lower = Decimal(value["negative_log2_probability_lower"])
                            accepted = not failures and lower >= Decimal(CONFIG["FORS_term_min_exponent"])
                            row = {"candidate_id":cid, "n":n, "h":h, "d":d, "a":a, "k":k, "lgw":lgw,
                                   "hp":h//d if not h%d else "", "q":CONFIG["q"],
                                   "structural_status":"rejected" if failures else "valid",
                                   "rejection_reasons":";".join(failures),
                                   "FORS_term_exponent_lower":value["negative_log2_probability_lower"],
                                   "FORS_term_exponent_upper":value["negative_log2_probability_upper"],
                                   "FORS_term_screening_status": "accepted_term_only" if accepted else
                                      "structural_rejection" if failures else "below_term_threshold",
                                   "implemented_pids":";".join(map(str,matching.get((n,h,d,a,k,lgw),[]))),
                                   "implementation_status":"fixed_parameter_implemented" if (n,h,d,a,k,lgw) in matching else
                                       "theoretical_only; lgw3 padded-digit extension not implemented" if lgw==3 else "theoretical_only",
                                   "NIST_category_assigned_to_candidate":False,
                                   "completed_overall_security_assessment":False,
                                   "precision_decimal_digits":CONFIG["precision_decimal_digits"],
                                   "config_sha256":config_hash}
                            if not failures:
                                no_cache = theoretical_cost(n,h,d,a,k,lgw,message_length=CONFIG["message_length_internal"])
                                t12 = theoretical_cost(n,h,d,a,k,lgw, min(12,h//d), CONFIG["message_length_internal"])
                                flat = serialize_cost(no_cache)
                                flat.pop("cache_t")
                                flat.pop("cache_payload_bytes")
                                flat.pop("cache_file_bytes")
                                flat.pop("cache_node_ram_bytes")
                                for field in ("expected_sign_primitive_calls", "sign_primitive_calls_min",
                                              "sign_primitive_calls_max", "expected_sign_compressions"):
                                    flat[field+"_no_cache"] = flat.pop(field)
                                for field in ("expected_sign_primitive_calls", "sign_primitive_calls_min",
                                              "sign_primitive_calls_max", "expected_sign_compressions"):
                                    value_t12 = t12[field]
                                    flat[field+"_t12"] = format(float(value_t12),".12g") if isinstance(value_t12,Fraction) else value_t12
                                flat.update({field:t12[field] for field in ("cache_t","cache_payload_bytes","cache_file_bytes","cache_node_ram_bytes")})
                                row.update(flat)
                                if accepted:
                                    exact_frontier_inputs.append({"candidate_id":cid, "signature_bytes":no_cache["signature_bytes"],
                                        "expected_sign_primitive_calls_no_cache":no_cache["expected_sign_primitive_calls"],
                                        "expected_sign_primitive_calls_t12":t12["expected_sign_primitive_calls"]})
                            rows.append(row)
    p1 = pareto_ids(exact_frontier_inputs,"signature_bytes","expected_sign_primitive_calls_no_cache")
    p2 = pareto_ids(exact_frontier_inputs,"signature_bytes","expected_sign_primitive_calls_t12")
    fieldnames = list(dict.fromkeys(field for row in rows for field in row))
    for row in rows:
        for field in fieldnames:
            row.setdefault(field, "")
        row.update({"pareto_no_cache":row["candidate_id"] in p1, "pareto_t12":row["candidate_id"] in p2,
                    "count_scope":"current scalar-path formulas; message primitives/midstate included; exact uniform-message WOTS expectation",
                    "final":False})
    write_csv(output / "grid-all-candidates.csv", rows)
    write_csv(output / "grid-Pareto-no-cache.csv", [row for row in rows if row["candidate_id"] in p1])
    write_csv(output / "grid-Pareto-t12.csv", [row for row in rows if row["candidate_id"] in p2])
    # Existing fixed parameters are also exported at the same q and same count
    # convention, including baselines outside the finite exploration range.
    baseline = []
    for pid in (1,2,3):
        p = implemented[pid]
        value = fors_probabilities(p.h,p.a,[p.k],int(CONFIG["q"]))[p.k]
        cost = theoretical_cost(p.n,p.h,p.d,p.a,p.k,p.lgw)
        cached = theoretical_cost(p.n,p.h,p.d,p.a,p.k,p.lgw,min(12,p.hp))
        dominance = [r["candidate_id"] for r in exact_frontier_inputs if r["signature_bytes"]<=p.signature_bytes and
            r["expected_sign_primitive_calls_no_cache"]<=cost["expected_sign_primitive_calls"] and
            (r["signature_bytes"]<p.signature_bytes or r["expected_sign_primitive_calls_no_cache"]<cost["expected_sign_primitive_calls"])]
        baseline.append({"pid_structure":pid,"parameter_structure":{1:"128s",2:"128f",3:"128-24"}[pid],
                         "h":p.h,"d":p.d,"a":p.a,"k":p.k,"lgw":p.lgw,"q":CONFIG["q"],
                         "FORS_term_exponent":value["negative_log2_probability"],
                         "candidate_id":f"n16-h{p.h}-d{p.d}-a{p.a}-k{p.k}-b{p.lgw}",
                         "within_frozen_grid":p.h in CONFIG["h_values"] and p.d in CONFIG["d_values"],
                         **serialize_cost(cost),
                         "expected_sign_primitive_calls_t12":format(float(cached["expected_sign_primitive_calls"]),".12g"),
                         "dominating_grid_candidates_no_cache":len(dominance),
                         "dominating_example_ids":";".join(dominance[:10]),
                         "comparison_scope":"finite term-screened grid only", "final":False})
    write_csv(output / "parameter-baselines.csv", baseline)
    table=["# 固定参数与有限网格：理论比较", "",
           "仅在冻结网格、指定FORS概率项筛选和均匀WOTS消息条件下比较。调用数含消息原语，压缩数含midstate；不转换成时间。", "",
           "| 参数结构 | 签名B | 无缓存期望签名调用 | t12期望签名调用 | 期望验证调用 | 支配该参数的无缓存候选数 |",
           "|---|---:|---:|---:|---:|---:|"]
    for r in baseline:
        table.append(f"| {r['parameter_structure']} | {r['signature_bytes']} | {r['expected_sign_primitive_calls']} | "
                     f"{r['expected_sign_primitive_calls_t12']} | {r['expected_verify_primitive_calls']} | {r['dominating_grid_candidates_no_cache']} |")
    table.extend(["", "无缓存前沿候选（仅列签名<=5500B的例子；全部见CSV）：", "",
                  "| 候选 | 签名B | 期望签名调用 | 期望验证调用 | FORS概率项指数 |",
                  "|---|---:|---:|---:|---:|"])
    for r in sorted((r for r in rows if r["candidate_id"] in p1 and r["signature_bytes"]<=5500),key=lambda r:r["signature_bytes"]):
        table.append(f"| {r['candidate_id']} | {r['signature_bytes']} | {r['expected_sign_primitive_calls_no_cache']} | "
                     f"{r['expected_verify_primitive_calls']} | {float(r['FORS_term_exponent_lower']):.9f} |")
    table.extend(["", "所有新候选均待完整安全评估与实现；lgw3补零规则是理论扩展。未声明整体安全、标准类别或全局最优。", ""])
    (output/"grid-tables.md").write_text("\n".join(table),encoding="utf-8")
    wots_rows=[]
    for lgw in CONFIG["lgw_values"]:
        dist=wots_distribution(16,lgw)
        for steps,ways in dist["distribution"].items():
            wots_rows.append({"n":16,"lgw":lgw,"len1":dist["len1"],"len2":dist["len2"],
                              "wots_len":dist["length"],"chain_steps":steps,"message_count":str(ways),
                              "population":str(dist["population"]),"uniform_probability_exact":f"{ways}/{dist['population']}",
                              "basis":"exact enumeration by digit-sum dynamic programming", "final":False})
    write_csv(output / "wots-uniform-chain-distribution.csv",wots_rows)
    result={"schema_version":1,"generated_utc":datetime.now(timezone.utc).isoformat(),"configuration":CONFIG,
            "configuration_sha256":config_hash,"total_candidates":len(rows),
            "structurally_valid":sum(r["structural_status"]=="valid" for r in rows),
            "term_screened_candidates":len(exact_frontier_inputs),"Pareto_no_cache":len(p1),"Pareto_t12":len(p2),
            "source_hashes":{**source_metadata(),"tools/parameter_grid.py":file_hash(Path(__file__))},
            "not_overall_security_or_global_optimum":True,"final":False,
            "files":{name:file_hash(output/name) for name in ("grid-config.json","grid-all-candidates.csv",
                     "grid-Pareto-no-cache.csv","grid-Pareto-t12.csv","parameter-baselines.csv","grid-tables.md","wots-uniform-chain-distribution.csv")}}
    (output / "grid.manifest.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,default=ROOT/"report-data/DP1-analysis")
    args=parser.parse_args()
    result=build_package(args.output)
    print(json.dumps({key:result[key] for key in ("total_candidates","structurally_valid","term_screened_candidates","Pareto_no_cache","Pareto_t12")}))


if __name__=="__main__":
    main()
