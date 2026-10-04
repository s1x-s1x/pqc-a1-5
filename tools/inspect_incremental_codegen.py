"""Generate compiler resource and disassembly evidence without executing crypto."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--library",type=Path,required=True)
    args=parser.parse_args()
    out=args.output.resolve()
    if not out.is_relative_to(ROOT/"validation") or out.exists():
        parser.error("choose a fresh output under validation")
    out.mkdir(parents=True)
    command=["gcc","-std=c11","-O3","-Wall","-Wextra","-Werror","-Wpedantic",
             "-fstack-usage","-fPIC","-DSLH_RELEASE_BUILD","-Ic/src",
             "-c","c/src/sm3_incremental.c","-o",str(out/"sm3_incremental.o")]
    subprocess.run(command,cwd=ROOT,check=True)
    assembly=subprocess.check_output(["objdump","-d",str(out/"sm3_incremental.o")],text=True)
    (out/"sm3_incremental.asm").write_text(assembly)
    functions=dict(re.findall(r"^[0-9a-f]+ <([^>]+)>:\n(.*?)(?=^[0-9a-f]+ <|\Z)",assembly,re.M|re.S))
    if not any("vpxor" in body for name,body in functions.items() if name.startswith("rounds8")):
        raise ValueError("AVX2 round code is absent")
    baseline=functions.get("a15_sm3i_init","")
    if not baseline or re.search(r"\b(?:vpxor|vmov\w*|vpbroadcast\w*)\b",baseline):
        raise ValueError("baseline initializer contains unexpected AVX instructions")
    resources=[]
    for line in (out/"sm3_incremental.su").read_text().splitlines():
        function,size,kind=line.split("\t")
        resources.append({"function":function,"stack_bytes":int(size),"classification":kind})
    guards=subprocess.check_output(["python3","tools/check_incremental_release.py","--library",str(args.library.resolve())],cwd=ROOT,text=True)
    (out/"release-guards.json").write_text(guards)
    manifest={"compiler":subprocess.check_output(["gcc","--version"],text=True).splitlines()[0],
        "compile_command":command,"stack_usage":resources,"round_AVX2_present":True,
        "baseline_initializer_AVX_free":True,"performance_samples":0,
        "scope":"compiler stack frames and disassembly only; not RSS, physical leakage, or complete spill erasure",
        "source_sha256":{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
            for name in ("c/src/sm3_incremental.c","c/src/sm3_incremental.h","c/src/secure_zero.h","tools/check_incremental_release.py","tools/inspect_incremental_codegen.py")},
        "files_sha256":{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir() if p.is_file()}}
    (out/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
    print(json.dumps({"compiler_resource_check":"passed","functions":len(resources),"performance_samples":0}))


if __name__=="__main__":
    main()
