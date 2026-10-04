"""Bound the specified FORS target-coverage probability term, using Decimal.

The output is not a full EUF-CMA bound or an assigned NIST security category.
All binomial masses are computed by recurrence, with outward-rounded interval
arithmetic and an analytic geometric bound for the omitted positive tail.
No Poisson approximation is used for the published probability.
"""

import argparse
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Context, Decimal, ROUND_CEILING, ROUND_FLOOR
import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.count_model import parameters

LABEL = "FORS target-coverage probability term"
ASSUMPTIONS = (
    "q classical signing observations; independent uniform h-bit FORS-instance indices",
    "independent uniform a-bit leaf choices in each of k FORS trees",
    "one fresh target coverage event; no adversarial search/quantum amplification factor",
    "other primitive, hypertree, PRF, implementation and protocol attack terms excluded",
)


@dataclass(frozen=True)
class Interval:
    lower: Decimal
    upper: Decimal


class Arithmetic:
    """Nonnegative interval arithmetic with directed Decimal rounding."""
    def __init__(self, precision):
        self.precision = precision
        self.down = Context(prec=precision, rounding=ROUND_FLOOR, Emax=999999, Emin=-999999)
        self.up = Context(prec=precision, rounding=ROUND_CEILING, Emax=999999, Emin=-999999)
        self.zero = Interval(Decimal(0), Decimal(0))
        self.one = Interval(Decimal(1), Decimal(1))

    def integer(self, value):
        return Interval(Decimal(value), Decimal(value))

    def add(self, a, b):
        return Interval(self.down.add(a.lower, b.lower), self.up.add(a.upper, b.upper))

    def multiply(self, a, b):
        return Interval(self.down.multiply(a.lower, b.lower), self.up.multiply(a.upper, b.upper))

    def divide(self, a, b):
        if b.lower <= 0:
            raise ValueError("interval division needs a positive denominator")
        return Interval(self.down.divide(a.lower, b.upper), self.up.divide(a.upper, b.lower))

    def complement(self, a):
        return Interval(self.down.subtract(Decimal(1), a.upper),
                        self.up.subtract(Decimal(1), a.lower))

    def power(self, a, exponent):
        # Integral powers use only multiply, never the implementation-dependent
        # correctly-rounded status of Decimal's general power operation.
        result = self.one
        while exponent:
            if exponent & 1:
                result = self.multiply(result, a)
            exponent >>= 1
            if exponent:
                a = self.multiply(a, a)
        return result

    def exponent_bounds(self, probability):
        if probability.lower <= 0:
            return None, None
        # Decimal ln is correctly rounded to nearest. One adjacent Decimal in
        # each direction encloses the exact result, independent of that mode.
        log_two = self.down.ln(Decimal(2))
        log_two_lo, log_two_hi = self.down.next_minus(log_two), self.up.next_plus(log_two)
        log_hi = self.up.next_plus(self.up.ln(probability.upper))
        log_lo = self.down.next_minus(self.down.ln(probability.lower))
        lower = self.down.divide(self.down.minus(log_hi), log_two_hi)
        upper = self.up.divide(self.up.minus(log_lo), log_two_lo)
        return lower, upper


def fors_probabilities(h, a, ks, q, precision=100, relative_tail="1e-40", max_terms=20000):
    """Return certified probability/exponent intervals for several k values.

    P = sum_(gamma=1..q) Binomial(q,gamma;2^-h)
            * (1-(1-2^-a)^gamma)^k.
    q is an exact integer, even when q > binary64's exact-integer range.
    """
    ks = tuple(sorted(set(ks)))
    if h < 1 or a < 1 or q < 0 or not ks or min(ks) < 1:
        raise ValueError("positive h/a/k and nonnegative integer q are required")
    if precision < max(h, a) + 15:
        raise ValueError("precision must exceed h and a by at least 15 decimal digits")
    arithmetic = Arithmetic(precision)
    p = arithmetic.divide(arithmetic.one, arithmetic.integer(1 << h))
    leaf_p = arithmetic.divide(arithmetic.one, arithmetic.integer(1 << a))
    miss_instance, miss_leaf = arithmetic.complement(p), arithmetic.complement(leaf_p)
    mass = arithmetic.power(miss_instance, q)
    miss_coverage = arithmetic.one
    totals = {k: arithmetic.zero for k in ks}
    tail = Decimal(0)
    last_ratio = Decimal(0)
    completed = q == 0
    terms = 0
    if q:
        for gamma in range(1, min(q, max_terms) + 1):
            ratio = arithmetic.divide(
                arithmetic.multiply(arithmetic.integer(q - gamma + 1), p),
                arithmetic.multiply(arithmetic.integer(gamma), miss_instance))
            mass = arithmetic.multiply(mass, ratio)
            miss_coverage = arithmetic.multiply(miss_coverage, miss_leaf)
            coverage = arithmetic.complement(miss_coverage)
            power = arithmetic.one
            for k in range(1, max(ks) + 1):
                power = arithmetic.multiply(power, coverage)
                if k in totals:
                    totals[k] = arithmetic.add(totals[k], arithmetic.multiply(mass, power))
            terms = gamma
            if gamma == q:
                tail = Decimal(0)
                completed = True
                break
            next_ratio = arithmetic.divide(
                arithmetic.multiply(arithmetic.integer(q - gamma), p),
                arithmetic.multiply(arithmetic.integer(gamma + 1), miss_instance))
            last_ratio = next_ratio.upper
            if last_ratio < 1:
                # Binomial successive ratios decrease. The entire unweighted
                # tail is <= mass_(gamma+1)/(1-ratio_(gamma+1)); coverage <= 1.
                next_mass = arithmetic.multiply(mass, next_ratio)
                denominator = arithmetic.down.subtract(Decimal(1), last_ratio)
                tail = arithmetic.up.divide(next_mass.upper, denominator)
                if totals[max(ks)].lower > 0:
                    relative = arithmetic.up.divide(tail, totals[max(ks)].lower)
                    if relative <= Decimal(relative_tail):
                        completed = True
                        break
        if not completed:
            raise RuntimeError(f"tail tolerance not met after {max_terms} terms (h={h}, q={q})")
    result = {}
    for k, total in totals.items():
        bounded = Interval(total.lower, min(Decimal(1), arithmetic.up.add(total.upper, tail)))
        low_exponent, high_exponent = arithmetic.exponent_bounds(bounded)
        relative = arithmetic.up.divide(tail, total.lower) if total.lower else Decimal(0)
        result[k] = {
            "term_label": LABEL, "h": h, "a": a, "k": k, "q": str(q),
            "lambda": str(arithmetic.divide(arithmetic.integer(q), arithmetic.integer(1 << h)).lower),
            "probability_lower": str(bounded.lower), "probability_upper": str(bounded.upper),
            "negative_log2_probability_lower": None if low_exponent is None else str(low_exponent),
            "negative_log2_probability_upper": None if high_exponent is None else str(high_exponent),
            "negative_log2_probability": None if low_exponent is None else str(
                arithmetic.down.divide(arithmetic.down.add(low_exponent, high_exponent), Decimal(2))),
            "q_zero_exponent": "infinity" if not q else None,
            "summed_gamma_through": terms, "absolute_tail_upper": str(tail),
            "relative_tail_upper": str(relative), "last_successive_ratio_upper": str(last_ratio),
            "precision_decimal_digits": precision, "requested_relative_tail": relative_tail,
            "method": "exact-binomial recurrence / outward-rounded Decimal intervals / geometric tail",
            "poisson_approximation_used": False, "is_full_EUF_CMA_bound": False,
            "assumptions": ASSUMPTIONS,
        }
    return result


def fors_probability(h, a, k, q, **kwargs):
    return fors_probabilities(h, a, (k,), q, **kwargs)[k]


def file_hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_metadata():
    names = ("SPEC.md", "c/src/engine.c", "tools/security_terms.py", "tools/count_model.py",
             "reference/sm3.py",
             "docs/plans/A1-5_设计报告框架_150页.md",
             "docs/plans/A1-5_单人开发实施计划_v3.md",
             "docs/plans/A1-5_分工实施计划_国一冲刺.md")
    result = {name: file_hash(ROOT / name) for name in names}
    sources = ROOT / "report-data/DP1-analysis/sources"
    for name in ("NIST.FIPS.205.pdf", "NIST.SP.800-230.ipd.pdf", "MANIFEST.json"):
        if (sources / name).exists():
            result[str((sources / name).relative_to(ROOT)).replace("\\", "/")] = file_hash(sources / name)
    return result


def write_csv(path, rows):
    with Path(path).open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def build_package(output, precision=100):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    ps = parameters()
    hashes = source_metadata()
    sources = {
        "128s": {"document": "FIPS 205", "status": "final / SHA2 and SHAKE parameter sets",
                 "pdf_page": 53, "printed_page": 43, "table": 2,
                 "url": "https://csrc.nist.gov/pubs/fips/205/final"},
        "128f": {"document": "FIPS 205", "status": "final / SHA2 and SHAKE parameter sets",
                 "pdf_page": 53, "printed_page": 43, "table": 2,
                 "url": "https://csrc.nist.gov/pubs/fips/205/final"},
        "128-24": {"document": "SP 800-230 ipd", "status": "initial public draft April 2026",
                   "pdf_page": 10, "printed_page": 2, "table": 1,
                   "url": "https://csrc.nist.gov/pubs/sp/800/230/ipd"},
    }
    calculations, r7, r8 = [], [], []
    cached = {}
    for base_pid, label, powers, limit_power in (
            (1, "128s", tuple(range(20, 65, 2)), 64),
            (2, "128f", tuple(range(20, 65, 2)), 64),
            (3, "128-24", tuple(range(20, 33)), 24)):
        p = ps[base_pid]
        for power in powers:
            value = fors_probability(p.h, p.a, p.k, 1 << power, precision=precision)
            cached[(base_pid, power)] = value
            evidence_id = f"R8/FORS/{label}/q2^{power}"
            calculations.append({"evidence_id": evidence_id, "parameter_structure": label,
                                 "input_source": sources[label], "source_hashes": hashes, **value})
            r8.append({"evidence_id": evidence_id, "parameter_structure": label,
                       "h": p.h, "a": p.a, "k": p.k, "q_power": power, "q": str(1 << power),
                       "scope": LABEL, "negative_log2_probability": value["negative_log2_probability"],
                       "exponent_lower": value["negative_log2_probability_lower"],
                       "exponent_upper": value["negative_log2_probability_upper"],
                       "gamma_terms": value["summed_gamma_through"],
                       "absolute_tail_upper": value["absolute_tail_upper"],
                       "relative_tail_upper": value["relative_tail_upper"],
                       "precision_decimal_digits": precision,
                       "operation_use_status": "within_stated_signature_limit" if power <= limit_power else
                                               "mathematical_extrapolation_beyond_strict_draft_limit",
                       "source_jsonl": "security-terms.jsonl", "source_line": len(calculations),
                       "full_security_claim": False, "final": False})
        for pid in (base_pid, base_pid + 100):
            instantiated = ps[pid]
            point = cached[(base_pid, limit_power)]
            r7.append({"evidence_id": f"R7/pid{pid}", "pid": pid,
                       "instance": ("SM3" if instantiated.sm3 else "SHA2") + "-" + label,
                       "n": p.n, "h": p.h, "d": p.d, "hp": p.hp, "a": p.a, "k": p.k,
                       "lgw": p.lgw, "wots_len": p.length, "m": p.m,
                       "public_key_bytes": 32, "secret_key_bytes": 64,
                       "signature_bytes": p.signature_bytes, "signature_limit_power": limit_power,
                       "signature_limit": str(1 << limit_power), "scope": LABEL,
                       "limit_point_negative_log2_probability": point["negative_log2_probability"],
                       "standard_parameter_category": 1,
                       "instantiated_scheme_category": "no NIST category assigned to experimental SM3 instance" if instantiated.sm3 else
                                                      "1 claimed by source parameter table",
                       "parameter_source_status": sources[label]["status"],
                       "instance_standard_status": "experimental SM3 adaptation" if instantiated.sm3 else sources[label]["status"],
                       "assumption_note": "SM3 adaptation is conditional on the required primitive-family properties" if instantiated.sm3 else
                                          "FIPS/IPD claims apply to the specified SHA2 construction",
                       "source_document": sources[label]["document"], "source_table": sources[label]["table"],
                       "source_pdf_page": sources[label]["pdf_page"],
                       "term_record": "security-terms.jsonl",
                       "term_line": next(i for i, r in enumerate(calculations, 1)
                                         if r["evidence_id"] == f"R8/FORS/{label}/q2^{limit_power}"),
                       "full_security_claim_from_probability_term": False, "final": False})
    with (output / "security-terms.jsonl").open("w", encoding="utf-8", newline="\n") as stream:
        for row in calculations:
            canonical = json.dumps(row, sort_keys=True, separators=(",", ":")).encode()
            row["record_sha256"] = hashlib.sha256(canonical).hexdigest()
            stream.write(json.dumps(row, sort_keys=True) + "\n")
    write_csv(output / "R7-security-parameters.csv", r7)
    write_csv(output / "R8-FORS-probability-term.csv", r8)
    markdown = ["# R7 / R8 解析数据", "",
                "范围：FORS目标覆盖概率项；不作完整EUF-CMA、量子安全位数或SM3类别认证。",
                "所有数据final=false；SP800-230 ipd仍按初稿与严格2^24签名限额解释。", "",
                "| 实例 | 参数来源 | 单密钥签名限额 | 签名B | 限额处概率项指数 | 实例类别状态 |",
                "|---|---|---:|---:|---:|---|"]
    for row in r7:
        markdown.append(f"| {row['instance']} | {row['source_document']} Table{row['source_table']} | "
                        f"2^{row['signature_limit_power']} | {row['signature_bytes']} | "
                        f"{float(row['limit_point_negative_log2_probability']):.9f} | {row['instantiated_scheme_category']} |")
    markdown.extend(["", "| 128-24签名观察量q | FORS概率项指数 | 运行限额状态 |",
                     "|---|---:|---|"])
    for row in r8:
        if row["parameter_structure"] == "128-24":
            markdown.append(f"| 2^{row['q_power']} | {float(row['negative_log2_probability']):.9f} | {row['operation_use_status']} |")
    markdown.extend(["", "完整区间、尾界与来源行见R7/R8 CSV及security-terms.jsonl。", ""])
    (output / "R7-R8-tables.md").write_text("\n".join(markdown), encoding="utf-8")
    generic = []
    for bits, scope in ((128, "n=16 truncated primitive output"), (256, "full underlying hash output")):
        generic.append({"output_bits": bits, "scope": scope,
                        "generic_classical_preimage_exponent": bits,
                        "generic_classical_collision_exponent": bits / 2,
                        "generic_quantum_preimage_query_exponent": bits / 2,
                        "generic_quantum_collision_query_exponent": bits / 3,
                        "model": "ideal generic oracle query asymptotics; not full scheme or circuit cost",
                        "certification_or_category_inference": False, "final": False})
    write_csv(output / "generic-output-bounds.csv", generic)
    metadata = {"schema_version": 1, "generated_utc": datetime.now(timezone.utc).isoformat(),
                "scope": LABEL, "security_records": len(calculations), "R7_rows": len(r7),
                "source_hashes": hashes, "parameters": sources,
                "strict_limit_interpretation": "2^24 is a strict per-key lifetime total across copies/devices; higher-q rows are analysis only",
                "numerical_method": "exact binomial; outward-rounded intervals; bounded positive tail",
                "no_Poisson_approximation": True, "not_full_EUF_CMA_or_category": True,
                "final": False,
                "files": {name: file_hash(output / name) for name in (
                    "security-terms.jsonl", "R7-security-parameters.csv", "R8-FORS-probability-term.csv", "R7-R8-tables.md", "generic-output-bounds.csv")}}
    (output / "security-terms.manifest.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "report-data/DP1-analysis")
    parser.add_argument("--precision", type=int, default=100)
    parser.add_argument("--h", type=int)
    parser.add_argument("--a", type=int)
    parser.add_argument("--k", type=int)
    parser.add_argument("--q", type=int)
    args = parser.parse_args()
    if any(x is not None for x in (args.h, args.a, args.k, args.q)):
        if not all(x is not None for x in (args.h, args.a, args.k, args.q)):
            parser.error("a single calculation requires --h --a --k --q")
        print(json.dumps(fors_probability(args.h, args.a, args.k, args.q, precision=args.precision), indent=2))
    else:
        result = build_package(args.output, args.precision)
        print(json.dumps({"output": str(args.output), "security_records": result["security_records"], "final": False}))


if __name__ == "__main__":
    main()
