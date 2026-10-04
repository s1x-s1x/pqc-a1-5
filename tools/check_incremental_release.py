"""Compile/preprocess guard checks only. No native kernel or timer invocation."""
import argparse
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library",type=Path,required=True)
    args=parser.parse_args()
    common=["gcc","-std=c11","-Ic/include","-Ic/src","-Ithird_party/slhdsa-c","-E","c/src/engine.c"]
    valid=subprocess.run([*common,"-DSLH_RELEASE_BUILD","-DA15_INCREMENTAL_MODE=4",
        "-DA15_INCREMENTAL_B1=1","-DA15_INCREMENTAL_V1=1"],cwd=ROOT,capture_output=True,text=True,check=True)
    if re.search(r"\b(?:a15_test_incremental_\w+|a15_test_v1_\w+|a15_sm3i_test_\w+)\b",valid.stdout):
        raise ValueError("private diagnostics remain in release preprocessing")
    cases=[("A15_INCREMENTAL_MODE",value) for value in (-1,5)]
    cases += [(name,value) for name in ("A15_INCREMENTAL_B1","A15_INCREMENTAL_V1") for value in (-1,2)]
    cases += [(name,1) for name in ("A15_TEST_INCREMENTAL_DIAGNOSTICS","A15_TEST_V1_DIAGNOSTICS","A15_TEST_V1_STAGE")]
    for name,value in cases:
        result=subprocess.run([*common,f"-D{name}={value}"],cwd=ROOT,capture_output=True,text=True)
        if result.returncode==0 or "error:" not in result.stderr:
            raise ValueError("invalid switch/hook compiled: "+name)
    symbols=subprocess.check_output(["nm","-D","--defined-only",str(args.library.resolve())],text=True)
    if re.search(r"\ba15_sm3i_|\ba15_test_|\bfors_from_sig_x8",symbols):
        raise ValueError("incremental internal interface leaked into public ABI")
    print(json.dumps({"release_private_code_erased":True,"invalid_builds_rejected":len(cases),
                      "incremental_ABI_exports":0,"performance_samples":0}))


if __name__=="__main__":
    main()
