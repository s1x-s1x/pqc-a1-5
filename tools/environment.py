"""Record the server and select physical CPU cores from one NUMA node."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cores", type=int, default=32)
    parser.add_argument("--output", default="validation/environment.json")
    args = parser.parse_args()
    output = ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    cpu = json.loads(subprocess.check_output(["lscpu", "-J"], text=True))
    topology = subprocess.check_output(["lscpu", "-p=CPU,CORE,SOCKET,NODE"], text=True)
    available = set(os.sched_getaffinity(0))
    records = [tuple(map(int, line.split(","))) for line in topology.splitlines()
               if line and not line.startswith("#")]
    selected, seen = [], set()
    first_node = min(row[3] for row in records if row[0] in available)
    for processor, core, socket, node in records:
        if processor not in available or node != first_node or (socket, core) in seen:
            continue
        seen.add((socket, core))
        selected.append(processor)
        if len(selected) >= args.cores:
            break
    data = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "platform": platform.platform(), "python": platform.python_version(),
        "lscpu": cpu, "affinity": sorted(available),
        "selected_physical_cpus": selected, "selected_numa_node": first_node,
        "load_average": os.getloadavg(),
        "hashlib_sm3": "sm3" in hashlib.algorithms_available,
        "tools": {name: shutil.which(name) for name in ["gcc", "nvcc", "ip", "tc", "unshare"]},
    }
    for name, path in {
        "boost": "/sys/devices/system/cpu/cpufreq/boost",
        "governor": "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
    }.items():
        try:
            data[name] = Path(path).read_text().strip()
        except OSError:
            data[name] = None
    data["gcc"] = subprocess.check_output(["gcc", "--version"], text=True).splitlines()[0]
    if shutil.which("nvidia-smi"):
        data["gpu"] = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=index,name,memory.total,utilization.gpu", "--format=csv,noheader"],
            text=True,
        ).splitlines()
    output.write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps({"manifest": str(output), "physical_cpus": selected, "numa_node": first_node}))


if __name__ == "__main__":
    main()
