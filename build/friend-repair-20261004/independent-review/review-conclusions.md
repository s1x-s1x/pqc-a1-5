# Independent repair review

## Ledger

Reviewed `tools/signing_budget.py` SQL schema and trigger matching, connection UDF guards, transactions, legacy identity/integrity migration, and constant-work hot-path checks.

- `_sql_normalized` splits quoted tokens and preserves their literal bytes. Its outside-token keyword/formatting normalization does not equate `'reserve'`, `'RESERVE'`, `' reserve'`, or `'reserve '`. The dedicated three-literal mutation regression exists.
- Each API connection registers its own write-mode and exact decimal arithmetic UDFs. Ordinary reads stay in `read` mode; writes occur only in the reserve/finish contexts. A normal external SQLite connection lacks these functions, and unconditional delete guards also reject deletion.
- Reserve/finish use `BEGIN IMMEDIATE`; schema/UUID verification, updates, trigger counters, and commit are in the same transaction. Receipt batches use one read transaction with one cached key invariant per key. Failures roll back the attempt, preserving previously consumed reservations.
- Unversioned migration audits complete historical records and ordinals before publishing `integrity_schema=3`. Identity migration retains receipts and consumed charges, merges aliases under the stricter limit, and does not refund even an overrun. Unsupported, malformed, or missing protected schema fails closed.
- Hot operations use guarded TEXT counters and indexed endpoint reads. `audit()` and opening a ledger still scan full history. Between those checkpoints, arbitrary file replacement or an attacker removing/reinstalling all guards and consistently rewriting counters lies outside the hot-path integrity claim. Copies and rollback need external authenticity/anti-rollback. No physical or global-monotonic guarantee follows from local SQLite counters.

No remaining specific defect was found in those reviewed mechanisms after the quoted-token normalization repair.

## Campaign evidence and crashes

Reviewed CPU/CUDA shared binding, campaign-wide receipt ownership, per-segment warmups, start/result pairing, live budget validation, complete-case metadata, immutable fixture checks, output ownership, and fsynced start records.

One additional defect was independently reproduced: a synthetic `case_complete` could close its own segment after an extra pending or failed operation while previous passed samples were present. Both CPU/CUDA initially accepted both mutations. The owner now checks the completing segment is ready, unstopped, and has no pending operation. Independent rerun rejects all four backend/mutation combinations. Evidence: `completion-review.json`; no native calls/timers.

The current receipt audit spans all preserved cases before selection or skip. The same receipt is legal for start/result of one operation and for immutable fixture input references, and is rejected for different operations or fixture-to-operation reuse. A fresh worker segment redoes all configured warmups before any missing sample. If all passed sample rows survived, completing only the summary adds no warmups/signatures.

Crash windows remain conservative: a committed reservation before JSON start is orphaned but consumed; a start before call remains reserved on interruption; a finish before result leaves a committed charge whose sample is absent. Resume creates a new segment/receipt for the missing sample and never treats those orphan attempts as passed samples or refunds them. A partial trailing JSONL line requires a new campaign while preserving the old file.

## CUDA owner cleanup

Persistent cleanup failure in the former destructor reached an unchecked `cudaFree` after ignored wipe/sync failures. This was a real ownership-policy defect, with no demonstrated disclosure evidence. Implemented fix and **17/17** deterministic fake-driver cases are in `cuda-cleanup-implementation.md` and `cuda-cleanup-host-results.json`. Production destructor and explicit cleanup now share one checked policy. Sticky failure blocks subsequent GPU work in this library process; failed allocations remain held until context/process teardown, and no device reset is issued. The main operation error keeps priority. Hardware erasure under a failing driver remains unverified.

The five-step real CUDA native runner must be rerun against the new source/library. Its first existing step now includes `cuda-cleanup-host-test`; the five step names are unchanged. The new helper must enter the CUDA benchmark build source closure before freezing.

## Evidence/freeze boundary

Historical CPU 3471/3471 with 4433 records and CUDA 1789/1789 with 2541 records retain their original summary, raw cases, manifest, source and library identity. Historical raw case hashes were checked locally. `historical-scope-review.json` records current source differences and `full_matrix_rerun=false`.

The current CPU translation units/ABI remain unchanged, but Makefile/native-wrapper/ledger files differ. Exact byte comparison of the newly built CPU library against the recorded historical library can strengthen inheritance; a matching C source subset alone does not label the entire new Python/TLS source matrix rerun. CUDA ownership code now differs, while the cryptographic device header and CPU engine remain unchanged. New real CUDA native acceptance and host cleanup policy evidence must be separately bound to the new source/library.

A new freeze should preserve old artifacts unchanged, record historical evidence identity/scope explicitly, collect current digest adapter, ledger, benchmark mock/resume, TLS and CUDA targeted evidence, and bind current source/plan/runner/schema/library/environment. Keep `formal_performance_started=false`, measured durations false for correctness checks, and formal samples 0. Do not silently overwrite old freeze identities or promote their complete-source claims to this new revision.
