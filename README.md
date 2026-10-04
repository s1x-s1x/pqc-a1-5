# A1-5: limited-use SLH-DSA with SM3

The authoritative execution workspace is `/home/guest-experiment/pqc-a1-5`.
This directory is its development mirror. Original plans are preserved in
`docs/plans/`; corrections and implementation decisions are recorded in `SPEC.md`
and `LOG.md`. The prior TLS prototype is preserved in `base_tls/`.

The first review milestone is a reproducible scalar engine with external test
vectors, a separate Python reference, subtree parallelism and validated cache
loading. SIMD, CUDA and TLS integration follow this review.

Measurements before the first correctness gate are diagnostic timings only.
They are not final competition performance results.

## Current checkpoint: CPU and CUDA optimization before performance testing

The user selected completing CPU and CUDA optimization and their correctness acceptance,
then stopping immediately before optimized performance testing. Scope and
remaining checks are tracked in `docs/OPTIMIZATION_CHECKPOINT.md`.

The FORS/prehash Linux milestone passed all nine steps in
`validation/native-stage2-20261004-0152/manifest.json`. Its source archive and
artifact hashes have been independently checked. That run's older Python
replay scripts explicitly used REF; the direct native AVX2 tests establish
their own stated SIMD coverage. Replay tools now expose `--backend` and record
the selected backend so the WOTS follow-up can check complete AVX2 paths.

WOTS x8 passed the eleven-step native acceptance in
`validation/native-wots-20261004-0216/manifest.json`, including three complete
128-24 cases explicitly using AVX2. Full cache/thread coverage passed 3471/3471 cases in
`validation/optimization-full-20261004-0228`. CUDA FORS is implemented and its
five-step native GPU acceptance passed in `build/cuda-staging-20261004`.
The integrated CPU eleven-step acceptance, 948-case dispatch regression,
and real RNG checks passed in the same isolated project. Extended CUDA
light matrix passed 1670/1670 cases; the full 1789-case matrix also passed. Both
final freeze packages are published and their source archives, correctness
evidence, exact release builds and measurement plans passed independent checks.
Start at `validation/optimization-final-readiness.json` and
`docs/PERFORMANCE_START_READY.md`; the local delivery check is recorded in
`validation/optimization-local-delivery.json`. The selected optimization
checkpoint is complete. Formal timing has not started. TLS integration is saved
at `docs/ALT_CHAIN_DESIGN.md` for continuation after this checkpoint.

For a GitHub clone, see `docs/GITHUB_HANDOFF.md` for the evidence audit and
restoring the original system dependency bytes. Third-party origins and
licenses are described in `docs/THIRD_PARTY.md`.

## First review snapshot (2026-10-04)

The scalar correctness suite passed all eight execution steps in
`validation/stage1-20261004-0100/manifest.json`. Start review at
`report-data/DP1-stage1-20261004-0100/REVIEW.md`.
It exports R1 summaries and case/line references, R2 exact counters, an input
manifest and a report chapter availability list. The report mapping follows
the controlled 150-page design report plan.

Coverage: 351 external operation checks, three complete SM3-128-24 seeded
cases, 1,000 complete toy cases, 1,000 auxiliary subtree cases, native/cache
regressions, 96 fault-matrix signing calls, release guards and ASan/UBSan.
The 326 exact-counter records cover pid201/2/102 and compare all seven fields;
they do not measure full pid3/103 signing. Replays retain the same source
inputs and add no distinct external vectors.

Use a new run/build name to reproduce without overwriting evidence:

```sh
.venv/bin/python tools/run_stage1.py --run-dir validation/stage1-NEW --workers 24 --threads 32
.venv/bin/python tools/package_stage1.py --run-dir validation/stage1-NEW
```

At that first review snapshot, complete DP1 still needed parameter-grid and
security-term analysis, and SIMD/CUDA implementation was pending. These are
historical milestone statements; current optimization status is recorded
above and in `docs/OPTIMIZATION_CHECKPOINT.md`. Formal performance and new
TLS-chain experiments remain beyond the current stop boundary.

## Layout

- `c/`: native engine and public ABI.
- `reference/`: Python model based on a separately maintained upstream source.
- `tools/`: vector conversion, correctness runners and reproducibility tools.
- `third_party/`: pinned upstream sources and external vector inputs.
- `vectors/`: generated vectors and content hashes.
- `validation/`: command outputs and structured correctness summaries.
- `bench-out/`: diagnostic or final benchmark JSONL.
- `docs/`: original plans, design notes and review documents.
- `ops/`: local SSH/synchronization helper; excluded from anonymous submission.

No passwords are saved in the project. The SSH helper reads credentials from
`A15_JUMP_PASSWORD` and `A15_TARGET_PASSWORD` in the invoking process environment.
