"""Regenerate and independently audit the DP1 analytical evidence package."""

import argparse
from decimal import Decimal, localcontext
from fractions import Fraction
import hashlib
import json
from math import comb
from pathlib import Path
import sys


ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.count_model import (keygen_model, parameters, sign_model, signature_trace,
                               verify_model, FIELDS)
from tools.parameter_grid import (CONFIG, build_package as build_grid, candidate_constraints,
                                  pareto_ids, theoretical_cost, wots_distribution, wots_lengths)
from tools.security_terms import (build_package as build_security, file_hash,
                                  fors_probability, write_csv)


def exact_small_probability(h,a,k,q):
    p=Fraction(1,1<<h)
    s=Fraction(1,1<<a)
    return sum((comb(q,g)*p**g*(1-p)**(q-g)*(1-(1-s)**g)**k
                for g in range(1,q+1)),Fraction(0))


def rational_in_interval(value,result):
    return Fraction(Decimal(result["probability_lower"]))<=value<=Fraction(Decimal(result["probability_upper"]))


def positive_vector_inputs():
    """One complete existing seeded signing vector for each fixed engine pid."""
    from tools.external_vectors import load_acvp, encoded_message, xous_full_cases
    rows=[]
    toy_path=ROOT/"reference/evidence/toy-differential.jsonl"
    toy=json.loads(toy_path.read_text(encoding="utf-8").splitlines()[0])
    rows.append({"pid":201,"case_id":toy["case_id"],"source":str(toy_path.relative_to(ROOT)).replace("\\","/"),
                 "source_line":1,"source_sha256":file_hash(toy_path),
                 **{key:toy[key] for key in ("sk_seed","sk_prf","pk_seed","pk","sk","mp","sig","opt_rand")},
                 "randomization":toy["randomization"],"message_encoding":"pure independently encoded M'"})
    gp=ROOT/"vectors/external-gmsm.json"
    gmsm=json.loads(gp.read_text(encoding="utf-8"))["cases"]
    for pid in (1,2):
        c=next(x for x in gmsm if x["pid"]==pid)
        seeds=bytes.fromhex(c["seeds"])
        context=bytes.fromhex(c["context"])
        mp=b"\0"+bytes([len(context)])+context+bytes.fromhex(c["message"])
        rows.append({"pid":pid,"case_id":f"gmsm-pid{pid}-index{c['index']}-deterministic",
                     "source":"vectors/external-gmsm.json","source_json_pointer":f"/cases/{gmsm.index(c)}",
                     "source_sha256":file_hash(gp),"sk_seed":seeds[:16].hex(),"sk_prf":seeds[16:32].hex(),
                     "pk_seed":seeds[32:].hex(),"pk":c["pk"],"sk":c["sk"],"mp":mp.hex(),
                     "sig":c["deterministicSignature"],"opt_rand":seeds[32:].hex(),
                     "randomization":"deterministic","message_encoding":"pure independently encoded M'"})
    acvp,inputs=load_acvp()
    for pid in (101,102):
        c=next(x for x in acvp if x["pid"]==pid and x["operation"]=="sigGen")
        t=c["test"]
        sk=bytes.fromhex(t["sk"])
        rows.append({"pid":pid,"case_id":f"ACVP-pid{pid}-tg{c['group']['tgId']}-tc{t['tcId']}",
                     "source":"third_party/external_vectors/acvp/SLH-DSA-sigGen-FIPS205",
                     "source_hashes":inputs,"sk_seed":sk[:16].hex(),"sk_prf":sk[16:32].hex(),
                     "pk_seed":sk[32:48].hex(),"pk":sk[32:].hex(),"sk":t["sk"],
                     "mp":encoded_message(c["group"],t).hex(),"sig":t["signature"],
                     "opt_rand":sk[32:48].hex() if c["group"]["deterministic"] else t["additionalRandomness"],
                     "randomization":"deterministic" if c["group"]["deterministic"] else "explicit",
                     "message_encoding":c["group"]["signatureInterface"]+" / "+c["group"].get("preHash","internal")})
    pp=ROOT/"reference/evidence/python-sm3-128-24.jsonl"
    py=json.loads(pp.read_text(encoding="utf-8").splitlines()[0])
    rows.append({"pid":3,"case_id":py["case_id"],"source":str(pp.relative_to(ROOT)).replace("\\","/"),
                 "source_line":1,"source_sha256":file_hash(pp),
                 **{key:py[key] for key in ("sk_seed","sk_prf","pk_seed","pk","sk","mp","sig","opt_rand")},
                 "randomization":py["randomization"],"message_encoding":"pure independently encoded M'"})
    xous,xinputs=xous_full_cases()
    x=next(c for c in xous if c["operation"]=="sigGen")["test"]
    rows.append({"pid":103,"case_id":"xous-SHA2-128-24","source":"third_party/external_vectors/xous/vectors",
                 "source_hashes":xinputs,"sk_seed":x["sk"][:32],"sk_prf":x["sk"][32:64],
                 "pk_seed":x["sk"][64:96],"pk":x["pk"],"sk":x["sk"],"mp":x["message"],
                 "sig":x["signature"],"opt_rand":x["additionalRandomness"],
                 "randomization":"explicit","message_encoding":"internal SPHINCS+ input"})
    return sorted(rows,key=lambda row:row["pid"])


def export_existing_vector_predictions(output):
    ps=parameters()
    vector_rows=positive_vector_inputs()
    predictions=[]
    for vector in vector_rows:
        p=ps[vector["pid"]]
        trace=signature_trace(p,bytes.fromhex(vector["mp"]),bytes.fromhex(vector["sig"]),bytes.fromhex(vector["pk"]))
        vector["actual_trace"]=trace
        vector["source_operation_status"]="existing complete vector; predictions below not new native measurements"
        models=[keygen_model(p,1,min(12,p.hp)),verify_model(p,len(bytes.fromhex(vector["mp"])),trace["chain_sums"])]
        for t in (None,min(12,p.hp),0):
            models.append(sign_model(p,len(bytes.fromhex(vector["mp"])),trace["chain_sums"],t,1))
        for model in models:
            row={"pid":p.pid,"case_id":vector["case_id"],"operation":model["operation"],
                 "cache_t":model["metadata"].get("eligible_top_cache_t",model["metadata"].get("cache_t")),
                 "source":"count-replay-inputs.jsonl","source_line":vector_rows.index(vector)+1,
                 **model["counts"],"actual_chain_sums":";".join(map(str,trace["chain_sums"])),
                 "root_trace_matches":trace["public_root_matches"],
                 "observed":"pending native counter replay", "final":False}
            predictions.append(row)
    with (output/"count-replay-inputs.jsonl").open("w",encoding="utf-8",newline="\n") as stream:
        for row in vector_rows:
            row["record_sha256"]=hashlib.sha256(json.dumps(row,sort_keys=True,separators=(",",":")).encode()).hexdigest()
            stream.write(json.dumps(row,sort_keys=True)+"\n")
    write_csv(output/"R2-existing-vector-predictions.csv",predictions)
    summary_path=ROOT/"validation/stage1-20261004-0100/exact-counts.summary.json"
    current=json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.exists() else None
    return {"fixed_parameters_with_existing_vector_trace":sorted(vector["pid"] for vector in vector_rows),
            "all_existing_vector_roots_match":all(vector["actual_trace"]["public_root_matches"] for vector in vector_rows),
            "prediction_rows":len(predictions),
            "current_measured_pids":current["coverage"]["parameters"] if current else [],
            "missing_measured_pids":sorted(set(ps)-set(current["coverage"]["parameters"])) if current else sorted(ps),
            "low_cost_next_step":"verify_internal for all seven replay inputs; no tree generation, same seven-field compare",
            "small_tree_next_step":"keygen/sign pid1/101 seeded replay, no-cache versus t0 and resolved threads1/4",
            "large_tree_next_step":"pid3/103 keygen and sign remain full native workloads; use existing vectors to avoid creating new reference vectors",
            "shortcut_boundary":"signature reuse supplies exact S_i for model but does not measure native sign/keygen counts",
            "counts_build_scope":"global atomic counters need exclusive sequential operation reset/read",
            "final":False}


def run_checks(output):
    output=Path(output)
    output.mkdir(parents=True,exist_ok=True)
    build_security(output)
    build_grid(output)
    records=[]
    def check(name,passed,**data):
        records.append({"check":name,"passed":bool(passed),**data})
    for h,a,k,q in ((2,2,2,7),(3,1,4,9),(4,3,1,0),(4,3,1,1),(5,2,3,64)):
        exact=exact_small_probability(h,a,k,q)
        value=fors_probability(h,a,k,q,precision=100)
        check(f"exact-rational-h{h}-a{a}-k{k}-q{q}",rational_in_interval(exact,value),
              exact_probability=f"{exact.numerator}/{exact.denominator}",interval=value)
    ref=[(63,12,14,64,"133.7"),(66,6,33,64,"131.4")]
    old={20:"142.1",22:"136.3",24:"128.6",25:"124.0",26:"118.9",27:"113.4",28:"107.7",30:"95.9",32:"84.0"}
    ref.extend((22,24,6,power,expected) for power,expected in old.items())
    for h,a,k,power,expected in ref:
        value=fors_probability(h,a,k,1<<power,precision=100)
        refined=fors_probability(h,a,k,1<<power,precision=160,relative_tail="1e-60")
        a_lo,a_hi=Decimal(value["probability_lower"]),Decimal(value["probability_upper"])
        b_lo,b_hi=Decimal(refined["probability_lower"]),Decimal(refined["probability_upper"])
        mid=Decimal(value["negative_log2_probability"])
        check(f"reference-point-h{h}-q2^{power}",format(mid,".1f")==expected,
              expected_rounded=expected,actual_rounded=format(mid,".1f"),probability_exponent=str(mid))
        check(f"precision160-contained-h{h}-q2^{power}",a_lo<=b_lo<=b_hi<=a_hi,
              precision100_interval=[str(a_lo),str(a_hi)],precision160_interval=[str(b_lo),str(b_hi)])
        check(f"tail-tolerance-h{h}-q2^{power}",Decimal(value["relative_tail_upper"])<=Decimal("1e-40"),
              relative_tail_upper=value["relative_tail_upper"],gamma_terms=value["summed_gamma_through"])
    values=[fors_probability(22,24,6,1<<power) for power in range(20,33)]
    check("q-probability-monotonic",all(Decimal(x["probability_upper"])<Decimal(y["probability_lower"]) for x,y in zip(values,values[1:])))
    ks=[fors_probability(22,24,k,1<<24) for k in range(4,9)]
    check("k-probability-monotonic",all(Decimal(x["probability_lower"])>Decimal(y["probability_upper"]) for x,y in zip(ks,ks[1:])))
    for lgw in (2,3,4):
        distribution=wots_distribution(16,lgw)
        check(f"wots-population-lgw{lgw}",distribution["population"]==1<<128,
              len1=distribution["len1"],len2=distribution["len2"],length=distribution["length"],
              expectation_exact=str(distribution["expectation"]))
    check("lgw3-ceil-and-padding",wots_lengths(16,3)==(43,3,46))
    # Hand-sized expectation cross-check by exhaustively enumerating every byte.
    for lgw in (2,3,4):
        dist=wots_distribution(1,lgw)
        l1,l2,length=wots_lengths(1,lgw)
        totals=[]
        for value in range(256):
            bitstring=f"{value:08b}".ljust(l1*lgw,"0")
            ds=[int(bitstring[j*lgw:(j+1)*lgw],2) for j in range(l1)]
            checksum=l1*((1<<lgw)-1)-sum(ds)
            csum=0
            while checksum:
                csum+=checksum% (1<<lgw);checksum>>=lgw
            totals.append(sum(ds)+csum)
        check(f"wots-exhaustive-1byte-lgw{lgw}",dist["expectation"]==Fraction(sum(totals),256),
              exact_expectation=str(dist["expectation"]))
    ps=parameters()
    for p in ps.values():
        s=[int(wots_distribution(p.n,p.lgw)["expectation"])]*p.d
        for cache in (None,0,min(12,p.hp),p.hp):
            analytic=theoretical_cost(p.n,p.h,p.d,p.a,p.k,p.lgw,cache)
            actual=sign_model(p,64,s,cache)
            primitive=sum(actual["counts"][field] for field in FIELDS if field!="compress")
            predicted=analytic["sign_primitive_fixed_before_final_chain"]+s[-1]
            check(f"structural-count-match-pid{p.pid}-cache{cache}",primitive==predicted,
                  integer_chain_sums=s,model_calls=primitive,analytical_calls=predicted)
            # Removing the expected final chain from compression leaves the
            # exact fixed part; actual final-layer steps then substitute.
            comp=analytic["expected_sign_compressions"]-analytic["wots_uniform_chain_steps_expected"]+s[-1]
            check(f"compression-count-match-pid{p.pid}-cache{cache}",actual["counts"]["compress"]==comp)
        analytic=theoretical_cost(p.n,p.h,p.d,p.a,p.k,p.lgw)
        verify=verify_model(p,64,s)
        verify_calls=sum(verify["counts"][field] for field in FIELDS if field!="compress")
        expected=analytic["expected_verify_primitive_calls"]+p.d*analytic["wots_uniform_chain_steps_expected"]-sum(s)
        check(f"verify-count-match-pid{p.pid}",verify_calls==expected)
        keygen=keygen_model(p)
        check(f"keygen-count-match-pid{p.pid}",keygen["counts"]["compress"]==analytic["keygen_compressions"] and
              sum(keygen["counts"][f] for f in FIELDS if f!="compress")==analytic["keygen_primitive_calls"])
    fixtures=[{"candidate_id":"a","size":1,"cost":3}, {"candidate_id":"b","size":1,"cost":4},
              {"candidate_id":"c","size":2,"cost":3}, {"candidate_id":"d","size":2,"cost":2},
              {"candidate_id":"e","size":2,"cost":2}]
    check("Pareto-strictness-and-ties",pareto_ids(fixtures,"size","cost")=={"a","d","e"})
    check("grid-rejects-nonintegral-hp","h_not_divisible_by_d" in candidate_constraints(16,22,3,24,6,2))
    # Audit every preserved native record by recomputing the mathematical model
    # inputs and fields; this checks analysis linkage without executing native C.
    native_path=ROOT/"validation/stage1-20261004-0100/exact-counts.jsonl"
    audited=0; mismatches=[]
    if native_path.exists():
        for line_no,line in enumerate(native_path.read_text(encoding="utf-8").splitlines(),1):
            row=json.loads(line)
            if row["operation"] not in ("sign","verify"): continue
            trace=row["actual_signature_trace"]
            mp=bytes.fromhex(row["inputs"]["encoded_message_hex"])
            p=ps[row["pid"]]
            model=(verify_model(p,len(mp),trace["chain_sums"]) if row["operation"]=="verify" else
                   sign_model(p,len(mp),trace["chain_sums"],row.get("effective_cache_t"),row["native_threads"],row.get("verify_after_sign",False)))
            audited+=1
            if model["counts"]!=row["observed"]: mismatches.append(line_no)
        check("preserved-native-sign-verify-recomputed",not mismatches,records=audited,mismatch_lines=mismatches,
              source=str(native_path.relative_to(ROOT)).replace("\\","/"),source_sha256=file_hash(native_path))
    replay=export_existing_vector_predictions(output)
    check("all-fixed-parameter-existing-vector-traces",replay["all_existing_vector_roots_match"] and
          replay["fixed_parameters_with_existing_vector_trace"]==sorted(ps),details=replay)
    (output/"count-coverage-review.json").write_text(json.dumps(replay,indent=2)+"\n",encoding="utf-8")
    with (output/"analysis-checks.jsonl").open("w",encoding="utf-8",newline="\n") as stream:
        for record in records: stream.write(json.dumps(record,sort_keys=True)+"\n")
    summary={"schema_version":1,"passed":all(row["passed"] for row in records),"checks":len(records),
             "failed_checks":[row["check"] for row in records if not row["passed"]],
             "no_native_execution":True,"no_large_signature_generated":True,
             "scope":"numerical, structural-count and frozen-grid validation; analytical evidence",
             "source_hashes":{"tools/check_analysis.py":file_hash(Path(__file__)),
                              "tools/security_terms.py":file_hash(ROOT/"tools/security_terms.py"),
                              "tools/parameter_grid.py":file_hash(ROOT/"tools/parameter_grid.py"),
                              "tools/count_model.py":file_hash(ROOT/"tools/count_model.py"),
                              "tools/native.py":file_hash(ROOT/"tools/native.py"),
                              "tools/external_vectors.py":file_hash(ROOT/"tools/external_vectors.py"),
                              "reference/sm3.py":file_hash(ROOT/"reference/sm3.py"),
                              "docs/SECURITY_TERM_ANALYSIS.md":file_hash(ROOT/"docs/SECURITY_TERM_ANALYSIS.md")},
             "package_files":{str(path.relative_to(output)).replace("\\","/"):file_hash(path)
                              for path in sorted(output.rglob("*")) if path.is_file() and path.name not in
                              ("analysis-checks.summary.json","analysis-checks.log")},"final":False}
    (output/"analysis-checks.summary.json").write_text(json.dumps(summary,indent=2)+"\n",encoding="utf-8")
    (output/"analysis-checks.log").write_text("\n".join(f"{'PASS' if r['passed'] else 'FAIL'} {r['check']}" for r in records)+"\n",encoding="utf-8")
    return summary


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,default=ROOT/"report-data/DP1-analysis")
    args=parser.parse_args()
    result=run_checks(args.output)
    print(json.dumps({"passed":result["passed"],"checks":result["checks"],"failed_checks":result["failed_checks"],"output":str(args.output)}))
    return 0 if result["passed"] else 1


if __name__=="__main__":
    raise SystemExit(main())
