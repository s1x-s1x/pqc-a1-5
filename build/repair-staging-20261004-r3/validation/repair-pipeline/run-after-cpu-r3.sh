set -euo pipefail
cd /home/guest-experiment/pqc-a1-5/build/repair-staging-20261004-r3
export OMP_DYNAMIC=FALSE PYTHONUNBUFFERED=1 CUDA_VISIBLE_DEVICES=0
PY=/home/guest-experiment/pqc-a1-5/.venv/bin/python
$PY tools/run_cuda_native.py --run-dir validation/cuda-native-repair-r3
while ps -p 2309718 -o stat= | grep -q '^[^Z]'; do sleep 30; done
$PY -c 'import json; j=json.load(open("validation/cpu-full-repair-r3/summary.json")); assert j["passed"] and j["final"] and j["passed_planned"] == 3471'
$PY tools/check_cuda.py --library build/cuda-native-repair-r3/counters/libslhdsa_sm3.so --disabled-library build/cuda-native-repair-r3/disabled/libslhdsa_sm3.so --run-dir validation/cuda-full-repair-r3 --budget-db validation/repair-pipeline/correctness-budget.sqlite --suite full --cpu-run validation/cpu-full-repair-r3 --kernel-record validation/cuda-native-repair-r3/kernel.json --threads 1 4 64 --large-sign-all-levels --require-cuda-absent --fail-fast
$PY -c 'import json; j=json.load(open("validation/project-functional-repair-r3-final3/manifest.json")); assert j["passed"] and j["source_unchanged"] and j["real_timing_samples"] == 0'
echo completed > validation/repair-pipeline/completed.txt
