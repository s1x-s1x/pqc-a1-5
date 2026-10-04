# V2 / W1 bounded design and mock-clock simulation, 2026-10-05

## Decision and scope

The required bounded design and non-timing scheduling simulation are
implemented in `tools/incremental_scheduler.py` and independently exercised
by `tools/test_incremental_scheduler.py`. Production V2/W1 crypto integration
is deferred under the plan's stated condition: no target arrival workload,
same-key distribution, actual memory/queue budget, worker contract or latency
objective has been supplied. The simulator's illustrative limits do not
substitute for that deployment decision. V1 remains the implemented simple
production verifier route. Cross-key SIMD, W2, node deduplication, worker
pools and ABI changes stay deferred.

All clocks are monotonic integer ticks advanced explicitly by tests. No
time source, sleep, profiling, native crypto or performance samples occur.
The model returns mock task outcomes and a mock final-root comparison; it
does not validate signatures or claim an end-to-end crypto prototype.

The fixed SPHINCS+ source has now been read at `wots.c:gen_chains`, lines
47-66 and 71 onwards: it already uses stable counting sort by remaining
steps and writes through original-chain output pointers. W1 is therefore
an inherited strong baseline, not a new sorting method. See the source
bytes and SHA-256 in `validation/incremental-20261005/neighbors/` and the
bounded comparison in `docs/research/NEIGHBORS_20261005.md`.

## Request and task identities

A request owns a fixed slot and a uint64 generation. The slot's generation
increments on reuse and never wraps. A task stores that token, its bounded
task ID, original output slot, full 32-byte address, input bytes, key/seed
identity, shape, ready tick, deadline, remaining-service estimate and
dependencies. Only ready inputs whose parent IDs have completed are queued.

The first-stage key includes pid3, SM3, the complete 32-byte public key and
a 32-byte identity for the shared seed midstate. Production must construct
this identity from the trusted request context; the simulator does not
cryptographically prove key-to-midstate binding. Queue identity is exactly
`(key, shape)`. F and H are separate shapes with 16/32-byte inputs and the
original domain 3. PRF, T_k, T_len and multi-block hashes are excluded.
Different public keys or midstate identities never enter one packet.

Admission and task-resource results are `ACCEPTED`, `RESOURCE`, `STALE`,
`NOT_READY` or `BAD_INPUT`. `VALID`/`INVALID` are reserved for terminal
mock verification results. Queue exhaustion therefore does not report an
invalid signature. A mock task failure marks only its owning request; all
expected tasks and the final-root check must finish before terminal commit.
One invalid request does not cancel another valid request.

## Flush and fairness

For each ready task:

```text
flush = min(ready + delta_shape, deadline - estimated_remaining)
```

Negative flush ticks are allowed and mean already expired. An estimate
affects the waiting policy; it is not a promised deadline. If a compatible
queue has an expired task, it can emit a partial packet and fill unused
lanes with its own compatible queued tasks. Expired tasks precede fillers.
Within that queue, flush tick, ready tick and insertion sequence give a
deterministic order. With no expired queue, a full eight-task queue can emit
immediately. A smaller queue waits until its flush tick.

All expired compatible queues are selected by explicit round robin. Thus
one large expired queue does not starve another expired key/shape queue.
With a fixed set of eligible queues and available worker slots, each queue
is selected within one rotation. This is a dispatch-count property, not a
bound on real queueing time, P99 or end-to-end latency. Backpressure from
the running-packet limit stops dispatch while retaining bounded queued work.

Every packet has exactly eight descriptors. Partial packets use explicit
`None` inactive descriptors and never commit inactive output slots. A future
native worker must turn these descriptors into fully defined zero payloads
and public domain/address values under the packet's shared seed; this mock
does not execute the existing x8 kernel.

## Hard bounds and cancellation

Illustrative default limits:

| Resource | Bound |
|---|---:|
| Request slots | 64 |
| Active/reserved key identities | 4 |
| Queued plus physically running tasks | 512 |
| Running packets | 64 |
| Outstanding queued/running tasks per active request | 8 |
| Expected task identities per request | 256 |
| Lanes per packet | 8 |
| F/H waiting deltas | 10/20 mock ticks |

Configuration accepts only finite integer resource limits in 1..4096,
with consistency checks. Ready/deadline/remaining ticks fit signed 63-bit
nonnegative inputs. Request generations and task/packet sequence numbers
have checked uint64 maxima. Expected-task bookkeeping is bounded per slot.
Dependency/outcome iterators are consumed only up to their permitted lengths
plus one, preventing an oversized iterable from bypassing those checks.
Result state is retained only in fixed request slots; there is no unbounded
completion-history or event-log store.

A cancel removes queued descriptors and marks the current generation
cancelled. Already dispatched packets retain the old token and continue
reserving task/key capacity until they complete. A replacement generation
may use the slot, but a late old result is ignored and never writes the new
request's output. Retaining physical reservations prevents repeated
cancel/reuse from accumulating unbounded running tombstones. Successful
completion commits each generation once; duplicate packet completion is
stale. Malformed completion outcomes leave the packet reserved for a valid
retry rather than partially releasing it.

These are logical limits on objects and defined payload sizes, not measured
Python memory consumption. Per-task raw address plus input is at most
64 bytes; metadata, dependency IDs, interpreter allocation and native worker
workspace must be budgeted separately in a future implementation. The
single-thread simulator validates state transitions. Actual production
thread synchronization and races require a separate concurrent prototype.

## W0 / W1 structure

pid3 has 68 WOTS chains and public remaining counts 0..3. W0 retains original
chain groups of at most eight and executes each group's maximum remaining
count with shorter lanes masked. Its existing streaming T_len path uses one
group of endpoints (128 bytes at most), then absorbs the group in order.

W1 creates stable buckets for remaining counts 0, 1, 2 and 3. Equal-count
chains preserve original chain order. It uses fixed groups of at most eight
inside each positive bucket; this version performs no dynamic lane refill.
Zero-step chains copy their signature element directly and execute no F.
Each completed endpoint is restored to its original chain slot, and all
68 endpoints are absorbed by T_len in original chain order.

The W1 raw complete endpoint buffer is `68*16 = 1088` bytes, 960 bytes more
than W0's maximum raw group buffer. Bucket indices, task descriptors, output
copies and T_len state are additional metadata/workspace. The simulator
retains complete endpoints for both modes solely to compare correctness;
the stated raw-buffer numbers model the proposed production layouts and are
not a measurement of the Python implementation's storage.

The toy chain transition preserves each chain's number of steps and original
endpoint identity. Tests compare W0, W1 and independently calculated expected
endpoints, including original-order concatenation. This establishes the
modeled dependency/order behavior, not equivalence of a new native WOTS
implementation (none is added).

## Structural examples, not performance

Four simultaneously ready pid3 requests produce 24 paths per FORS stage.
Across 25 dependency stages, the simulator emits 75 full packets instead of
V1's 100 six-active-lane packets. Logical F/H tasks remain 600. This counts
packets under the simultaneous-readiness assumption; it excludes grouping,
queueing and native work and says nothing about speed or P99.

For one synthetic WOTS pattern `remaining[chain] = chain % 4`, W0 produces
27 packets and W1 18 packets; both perform 102 logical F calls. Their raw
endpoint storage models remain 128/1088 bytes. This is one deterministic
structure example, not an expected workload or a speed ranking.

## Tests and reproduction

Run the correctness-only command:

```sh
python -B tools/test_incremental_scheduler.py
```

The custom result path invokes test methods directly, avoiding both the
standard TestCase internal timer and text-runner duration reporting. The
current result is **27 tests passed**, `mock_clock_only=true`,
`native_crypto_calls=0`, `performance_samples=0`. Coverage includes:

- Request batches 1/2/4/7/8/9 and the finite default maximum 64.
- Full/partial eight-lane packets, deterministic inactive descriptors,
  deadline equation, overdue estimates, optional compatible fill and FIFO
  tie-breaking by insertion sequence.
- Three expired queues competing fairly, and expired partial work preceding
  a full unexpired queue.
- Same-key/same-shape partition, different key and midstate separation,
  mismatched key rejection and unsupported shape rejection.
- The 25-stage, four-request FORS dependency example; reverse packet
  completion; parent readiness; independent valid/invalid final results.
- Queue/task, request, active-key, packet and per-request limits; resource
  retry preserving task identity; generation saturation and clock bounds.
- Cancellation before/after dispatch, slot reuse, late result isolation,
  retained cancelled-work reservations, duplicate completion, commit once
  and malformed completion retry.
- W0/W1 endpoint equality, original-order commit, stable 0..3 buckets,
  zero-step no-F behavior, fixed packet counts and buffer formulas.

An additional guarded run replaced Python `time`, `monotonic`,
`perf_counter`, `process_time`, `thread_time` and `sleep` with functions
that raise on invocation. All 27 tests passed with those guards, confirming
that the documented execution path does not read a real clock or sleep.

Remaining production prerequisites are an explicit workload, deployment
budgets, worker/concurrency ownership and a latency objective. The next
performance phase must separately compare V1, fixed/FIFO grouping, simple
EDF and this candidate under the same arrival sequence and resource limits.
W2 remains conditional on actual endpoint-buffer or latency pressure.
No true timing, throughput, P99 or performance sample has been collected.
