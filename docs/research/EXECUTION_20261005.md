# Incremental Execution Record

Date: 2026-10-05. Goal: implement and accept the selected fixed-pid3 research
paths, then deliver preparation material before the first performance timer.

## Input Binding

Baseline commit: `4ad41308ad537e0578f6dea6d85ebcd7535c46b1`.
The baseline worktree was clean; the inherited V1 additions were untracked.
Existing engineering acceptance stays bound to that baseline and is not new
incremental-path evidence.

| Input | SHA-256 |
|---|---|
| Goal prompt 20261005 | 9312DD5899838C0AAACFD42D1C572F21766A6892D8C8E3E11489307FD7F3D26E |
| Executable plan v1.2 | 9090DB9D5648541578F6C2C47C2E6242A094313925E771ED91F2724CF1A5F683 |
| Technical plan v1.2 | E2236F7DD572ED6074721A28A363B6449F9EA7E861DB768DDBAF76271F13A212 |
| Extended analysis plan | 6BD91BE7523AFD59CD01036C458E6D26A09839A48320550217FF22E293AF0EB9 |
| Baseline engine.c | E9EF382C21EE8AE7576D524959A6D12808C848B00AD5D728CBB0BCC1EB5D227B |

Baseline GitHub correctness CI: run `37221485068`, completed/success for the
baseline SHA. Old host/CUDA/functional/container matrices remain historical.

## Stage Status

| Stage | State | Remaining evidence |
|---|---|---|
| G0 version handoff | Complete | Baseline and four input documents bound above |
| G1 contracts and neighbors | Complete | KERNEL/V1/NEIGHBORS notes and pinned licensed source excerpts |
| G2-K B1/A1 | Complete | kernel-r1: independent bytes, W/W', full256, boundaries, sanitizer |
| G2-V V1 | Complete | v1-r1 and current-engine release-r1 combined sanitizer fixtures |
| G3 A2 | Complete | F8/A8/F1/AF, same-layout controls, read-only consume and public deltas |
| G4 integration | Complete | integration-r2, full-af-r2, A8/fault evidence, isolation-r2 |
| P finite analysis | Complete | Eight parameter/cache configurations, 32 resource shapes, 168 boundaries |
| V2/W1 | Required design/simulation complete | 27 mock-clock tests; production integration deferred |
| G4-R delivery | Complete | Source/evidence archive and Chinese handoff; performance gates closed |

A2 is selected for its defined aligned-lane decomposition and continuation of
the technical plan. This is a mechanism decision, with no speed ranking.
B2 is deferred: A2 can consume its reconstructed PRF output through the existing
byte interface. B3, CPU task pool, GPU tiles, cross-key V2, W2, node deduplication,
new production parameters and M remain deferred.

V2/W1 production integration is deferred because this session specifies no
arrival/key distribution, queue budget or latency objective. The bounded design
and deterministic mock-clock simulation are required deliverables. They do not
change production verification or establish real latency guarantees.

## Fixed Boundaries

- Newly collected performance samples: **0**.
- No loop timing, cycles, profiling, pilot, benchmark warmup or network load.
- Correctness-only construction, counters, static resource analysis and mock
  scheduling are allowed. Process timestamps are diagnostic metadata only.
- Paper and LaTeX ZIP retain their current versions.
- Original encoding, budgets, fault sites and independent REF self-check stay.
- Historical full-session formal search remains the previously accepted open
  item; this does not discharge new implementation proof obligations.

## Acceptance Matrix

Minimum kernel configurations: original K0, F8/B0, F8/B1, A8/B0, A8/B1,
F1/B0, F1/B1, AF/B0, AF/B1. V1 is independently selectable. Layout uses a
separate byte constructor; expansion uses scalar recurrence; full256 checks
precede truncation. Trees compare root/auth/selected secret and absolute
addresses; whole signing compares fixed inputs to an existing independent
fixture and checks actual candidate hits. REF/other-parameter/CUDA fallback,
failure clearing, public state switching, memory/integer checks and concurrent
stream isolation are part of the new evidence, not inherited PASS claims.

## Accepted Evidence

All paths below start at `validation/`. Each manifest records commands, source
identity, zero new performance samples, return codes and log hashes.

| Evidence | Accepted scope |
|---|---|
| incremental-20261005-kernel-r1 | 5,159,276 checks in each normal/sanitizer run; 512 bases, 4,264 batches, 88 concurrent publication streams; portable fallback |
| incremental-20261005-v1-r1 | Three public independent fixtures, 36 three-path controls per fixture, normal and ASan/UBSan; V1 stage/address/padding controls |
| incremental-20261005-integration-r2 | Ten mode/layout combinations, 18 trees per configuration, exact logical counters, reversed tasks, sanitizer, fault sites 2/5 |
| incremental-20261005-full-af-r2 | Final AF+B1 full signature equals independent fixture; 96 threads, 3,072 streams, 12,582,912 PRF x8 packages, independent REF self-check |
| incremental-20261005-full-a8-r1 | Same production sources: complete A8+B1 signature and REF self-check |
| incremental-20261005-full-fault5-r1 | Same production sources: complete AF+B1 fault rejected by REF, length zero, 3,856 output bytes erased, budget consumed |
| incremental-20261005-release-r1 | Default/candidate/portable release guards and related existing checks; current-engine B1/V1 combined sanitizer fixtures |
| incremental-20261005-isolation-r2 | 64 full concurrent requests at 16 threads, REF per request, mixed validity/changed seeds; real CUDA candidate build with eight bounded FORS trees and two fixture verifies; candidate A/B/V1 excluded on CUDA; public JSON inputs extracted by the tool |
| incremental-20261005/codegen-r1 | GCC11 strict compile, 15 frame records, AVX2 round code, AVX-free baseline initializer, nine invalid configurations rejected, no added public ABI |

The latest integration/full-AF evidence binds the final runner and harness.
Earlier A8 and full-fault records bind an older test harness/runner; their
production engine/kernel/headers are identical to the final version. The final
harness adds logical-counter assertions to the small-tree phase, not a change
to the complete-signature or fault operation. Preserve that historical identity
rather than claim those added assertions ran in the earlier full cases.
Kernel/release records differ only in an unused engine test and the runner.
The earliest V1 record has an older engine; current-engine combined fixture
acceptance is supplied by release-r1, and concurrent isolation by isolation-r2.
Retained artifacts are hashed after the runs; the early runner did not record
binary hashes at invocation. The isolation artifacts are hashed immediately
after each accepted execution. This distinction is kept in its manifest.

Four signing attempts were newly budgeted: three successful signatures and one
fault failure. No attempt was refunded. All new full signatures use the existing
bound pid3/t12 cache and public independent test key; no performance dataset is
created. Parameter results are formulas/resource shapes, not measured memory or
time. Source wiping and compiler inspection support addressable-object cleanup;
register/spill erasure and physical leakage remain unproven.

Final analysis, performance-closed checks and package identity are recorded in
the handoff freeze. Next work requires explicit performance-phase authorization;
this Goal stops before its first timer. Paper/LaTeX identities remain unchanged.
