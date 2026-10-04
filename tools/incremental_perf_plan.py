"""Emit/check a closed performance plan. This tool has no sampling operation."""
import argparse
import csv
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def plan():
    configurations=[{"id":"K0","commit":"4ad41308ad537e0578f6dea6d85ebcd7535c46b1",
                     "mode":None,"b1":0,"v1":0,"role":"unchanged original comparator"}]
    for mode,name in enumerate(("generic","F8","A8","F1","AF")):
        for b1 in (0,1):
            configurations.append({"id":f"{name}-B{b1}","mode":mode,"b1":b1,"v1":0,
                "make_variables":{"INCREMENTAL_MODE":mode,"INCREMENTAL_B1":b1,"INCREMENTAL_V1":0,"COUNTERS":0},
                "role":"internal layout/expansion control"})
    configurations.append({"id":"AF-B1-V1","mode":4,"b1":1,"v1":1,
        "make_variables":{"INCREMENTAL_MODE":4,"INCREMENTAL_B1":1,"INCREMENTAL_V1":1,"COUNTERS":0},
        "role":"integrated candidate, not a speed-selected winner"})
    return {"schema":"a15-incremental-performance-preparation-v1","performance_enabled":False,
        "execution_permit":False,"new_performance_samples":0,"samples":[],
        "pid":3,"cache_t":12,"self_verify":True,"main_physical_threads":1,
        "configurations":configurations,"compiler_flags":"-O3; no test hooks, counters or global -mavx2",
        "comparisons":["A8/F8 at identical B1", "AF/F1 at identical B1",
                       "F1/F8 and AF/A8 representation tradeoff", "B1/B0 at identical mode",
                       "single-request V1/current AVX2 verifier", "final candidate/K0"],
        "external_comparators":["ISA-L SM3 x8 f22c49a", "GmSSL SM3 x8 24ae482", "OpenSSL supported SM3 4d25710"],
        "unknowns":{"pilot_N":None,"formal_N":None,"V1_practical_threshold":None,
                    "external_adapters":"must be accepted before external timed comparisons"},
        "excluded_current_stage":["timers","cycles","profiling","warmup","tuning","pilot","throughput","P99","network"],
        "source_sha256":{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in (
            "c/Makefile","c/src/engine.c","c/src/sm3_incremental.c","c/src/sm3_incremental.h","c/src/fors_verify_x8.inc")}}


def validate(value):
    if value.get("performance_enabled") is not False or value.get("execution_permit") is not False or value.get("samples")!=[] or value.get("new_performance_samples")!=0:
        raise ValueError("the pre-performance package must remain closed with empty samples")
    if value["source_sha256"]!=plan()["source_sha256"]:
        raise ValueError("plan source binding changed")
    for item in value["configurations"][1:]:
        fields=item["make_variables"]
        if fields["COUNTERS"]!=0 or fields["INCREMENTAL_MODE"] not in range(5) or fields["INCREMENTAL_B1"] not in (0,1) or fields["INCREMENTAL_V1"] not in (0,1):
            raise ValueError("invalid planned configuration")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,default=ROOT/"validation/incremental-20261005/performance")
    parser.add_argument("--check",action="store_true")
    args=parser.parse_args()
    if args.check:
        validate(json.loads((args.output/"plan.json").read_text()))
        with (args.output/"results.csv").open(newline="") as stream:
            if list(csv.DictReader(stream)):
                raise ValueError("results must contain no samples")
    else:
        args.output.mkdir(parents=True,exist_ok=True)
        if (args.output/"results.csv").exists():
            with (args.output/"results.csv").open(newline="") as stream:
                if list(csv.DictReader(stream)):
                    raise ValueError("preserve collected results; this tool only prepares an empty template")
        value=plan();validate(value)
        (args.output/"plan.json").write_text(json.dumps(value,indent=2)+"\n")
        with (args.output/"results.csv").open("w",newline="") as stream:
            csv.writer(stream).writerow(("phase","key_batch","configuration","operation","paired_input_sha256",
                "library_sha256","protocol_sha256","seconds","status","excluded_reason"))
    print(json.dumps({"plan_checked":True,"performance_enabled":False,"execution_permit":False,"new_performance_samples":0}))


if __name__=="__main__":
    main()
