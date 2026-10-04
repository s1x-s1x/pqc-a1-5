set -eu
cd /home/guest-experiment/pqc-a1-5/build/repair-staging-20261004-r1
export OMP_DYNAMIC=FALSE PYTHONUNBUFFERED=1
PY=/home/guest-experiment/pqc-a1-5/.venv/bin/python
$PY tools/run_native_stage2.py --run-dir validation/native-repair-r1 --workers 24 --threads 32
$PY tools/check_optimization.py --library build/native-repair-r1/counters/libslhdsa_sm3.so --run-dir validation/cpu-full-repair-r1 --budget-db validation/repair-pipeline/correctness-budget.sqlite --suite full --full-sha2 --fail-fast
$PY tools/run_cuda_native.py --run-dir validation/cuda-native-repair-r1
$PY tools/check_cuda.py --library build/cuda-native-repair-r1/counters/libslhdsa_sm3.so --disabled-library build/cuda-native-repair-r1/disabled/libslhdsa_sm3.so --run-dir validation/cuda-full-repair-r1 --budget-db validation/repair-pipeline/correctness-budget.sqlite --suite full --cpu-run validation/cpu-full-repair-r1 --kernel-record validation/cuda-native-repair-r1/kernel.json --threads 1 4 64 --large-sign-all-levels --require-cuda-absent --fail-fast
$PY tools/alt_chain_fixtures.py generate --output validation/real-alt-fixtures-repair-r1 --library build/native-repair-r1/avx2/libslhdsa_sm3.so --threads 32 --handshake-signer falcon-512 --budget-db validation/repair-pipeline/ca-budget.sqlite
$PY tools/run_project_functional.py --run-dir validation/project-functional-repair-r1 --library build/native-repair-r1/avx2/libslhdsa_sm3.so --fixtures validation/real-alt-fixtures-repair-r1
echo completed > validation/repair-pipeline/completed.txt
