# Implementation Log

## 2026-10-03: stage 1 started

- Created an isolated A1-5 workspace; the existing `aoi` collection is separate.
- First user review will occur after the baseline correctness milestone, before
  SIMD/CUDA/TLS development expands the implementation surface.
- Initial corrections: SHA2-128s/128f ACVP coverage is 208 cases for the inspected
  upstream vector revision; WOTS chain counts depend on each message; FORS
  probability estimates are not the complete scheme's security strength.
- Server supports rootless user/network namespaces, veth, netem and packet
  sockets. Host boost/governor controls are read-only for this account.
- Available hardware: dual 48-core EPYC 7R32, AVX2, eight RTX 4090 devices.
  AVX-512 is absent. Formal measurements require a recorded CPU/GPU allocation.

## 2026-10-04: first scalar correctness review snapshot

- Resumed the interrupted development conversation and independently checked
  preserved external/Python evidence and the current report plan hashes.
- Added five calculation-stage fault sites in standalone test builds, release
  compile/preprocessor/symbol guards, cache/key binding regressions, subtree
  boundaries and output guards. Ordinary release libraries have no fault ABI.
- Added an exact implemented-path model and counter runner. Each message's
  WOTS/checksum digits are recovered from verification paths; cache checksums
  are separately identified because they use raw SM3 outside public counters.
- Added append-only execution and report-packaging tools. Input/source hashes
  are checked before/after execution; sanitizer failures halt the test process.
- All eight steps passed in `validation/stage1-20261004-0100`: native/extended/
  fault/release guards, counter build tests, ASan/UBSan, 351 external checks,
  three complete SM3-128-24 cases, 1000 toy and 1000 subtree cases, and 326
  seven-field exact-counter records for pid201/2/102.
- Current reference library SHA256:
  `7466b9e92ac09f6a5dd82cc928ebe1ea46d0e74c59f0dd6f937918d132a94618`.
  The historical b4ea1ead... library evidence is retained as its own snapshot.
- Exported `report-data/DP1-stage1-20261004-0100`: R1 summary and case index,
  R2 exact-count CSV/JSONL, vector/command/hash manifests and report availability.
  No correctness-run duration is treated as a final performance measurement.
- A post-freeze metadata-only variant of check_counts.py is preserved in
  `docs/archive/check_counts_6d39f3b8e2b4.py`; the active file matches the
  executed snapshot. The variant can be reviewed for a later run.
- Stopping at the previously selected user-review boundary. Complete DP1
  parameter/security analysis, SIMD/CUDA, formal benchmarks and new TLS work
  remain for subsequent stages.

## 2026-10-04: optimization checkpoint selected by user

- The user requested completing CPU optimization and stopping immediately
  before optimized performance testing. Formal timing and further TLS/network
  integration are held at this checkpoint.
- Current scope: midstate, adjustable cache, OpenMP, AVX2 FORS and the A5 WOTS
  x8/streaming T_len path. Correctness, counter equivalence, fallback, fault
  isolation and sanitizer checks precede benchmark preparation.
- AVX2 FORS and five prehash ABIs passed seeded local checks. A fresh Linux
  acceptance is running under `validation/native-stage2-20261004-0152`.
- Independent durable-budget check: 40 concurrent attempts, 8 workers, 17
  charged reservations, including simulated crashes; passed. Evidence:
  `validation/budget-20261004-status.json`.
- Frozen TLS work and resume instructions: `docs/ALT_CHAIN_DESIGN.md`.
  This partial integration is not part of the optimization completion claim.

## 2026-10-04: CUDA added to the optimization checkpoint

- The user explicitly selected completing CUDA during this checkpoint. The
  v3 B1 FORS subtree kernel is now required; formal performance remains held.
- WOTS native acceptance passed eleven steps and six untimed Linux RNG checks
  under `validation/native-wots-20261004-0216`. The full CPU cache/thread
  matrix remains in progress at `validation/optimization-full-20261004-0228`.
- A real CUDA toolchain probe compiled with system nvcc 11.5, gcc 11.4 and
  compute_86 PTX, and returned the expected device result on RTX 4090 (sm_89).
  The system CUDA 11 headers/runtime are used separately from /usr/local/cuda
  (CUDA 12.1). Probe output is a correctness check, not a timing sample.
- CUDA implementation, independent GPU correctness and benchmark preparation
  proceed in parallel. Older CPU evidence retains its tested source archive;
  the integrated final source must pass fresh CPU regression and GPU checks.

## 2026-10-04: integrated CPU and CUDA acceptance milestones

- The isolated `build/cuda-staging-20261004` project passed the current CPU
  eleven-step native run, 948-case REF/AVX2 regression and six real RNG checks.
- CUDA native acceptance passed five steps, including direct GPU SM3/FORS,
  complete signatures and 192 fault calls. The CUDA light matrix passed
  1670 cases; four hidden-device rejection cases passed separately.
- The no-counter CPU measurement library is byte-identical to the accepted
  current CPU release. The CUDA exact release passed fourteen untimed cases
  and eight committed signatures were independently checked in the shared SQL ledger.
- CPU and CUDA benchmark helpers each passed 22 Linux mock checks with no
  native benchmarking calls or real timing samples. Frozen evidence will
  retain SQL acceptance snapshots while future campaigns extend the live ledger.
- Full historical CPU correctness and the CUDA full matrix still precede
  canonical freeze publication. Formal performance samples remain zero.

## 2026-10-04: optimization checkpoint complete before formal performance

- Historical CPU full matrix passed 3471/3471 planned cases (4370 records);
  current integrated CPU regression passed 948/948 cases (1337 records).
- Current CUDA full matrix passed 1789/1789 planned cases (2541 records).
  GPU work covers FORS; WOTS, messages, cache and upper XMSS stay on CPU.
- Final CPU/CUDA freeze packages are published and passed the real server
  provenance gates without native loading or timing. Independent archive
  checks matched 71/68 source files and 21/186 correctness-evidence files.
- Final preparation mocks passed 26 CPU and 23 CUDA checks. Exact release
  builds and the 54/207/252/64-case normative plans remain hash-bound.
- Local delivery preserves all referenced evidence, including 50 additional
  original files and a 12-file Linux dependency mirror. Repeatable audit:
  ops/audit_optimization_delivery.py; result:
  validation/optimization-local-delivery.json. Frozen packages are unchanged.
- Formal performance has not started: zero real timing samples, no benchmark
  run/worker processes or performance sample files at the server audit.
  The user-selected stopping point is reached; continuation entry:
  docs/PERFORMANCE_START_READY.md. Whole-project TLS/network/report work
  remains for the later phase tracked in docs/PROJECT_COMPLETION.md.
