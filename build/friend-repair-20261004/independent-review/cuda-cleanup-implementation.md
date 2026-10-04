# CUDA cleanup ownership fix — 2026-10-04

Changed `c/src/sm3_cuda.cu`, new `c/src/cuda_cleanup.h`, new `c/tests/test_cuda_cleanup_host.cpp`, `c/Makefile`, and `tools/run_cuda_native.py`.

The runtime and destructor now use the same checked wipe → synchronize → free policy. Free runs only after both wipe and synchronization succeed. Any cleanup error preserves the allocation and permanently poisons subsequent GPU availability, setup, statistics, and work in this library process. Other existing allocations still attempt cleanup. The destructor makes one checked retry; a persistent failure retains the allocation until context/process teardown. No device reset is issued. A primary operation error keeps precedence; an otherwise successful operation returns the cleanup error and zeroes the existing host output buffers.

This is an ownership/allocator reuse guarantee under callback semantics. It does not certify physical GPU erasure on arbitrary driver/hardware failure and supplies no demonstrated disclosure claim.

Local Windows g++14 validation:

```
g++ -std=c++14 -O2 -Wall -Wextra -Ic/src c/tests/test_cuda_cleanup_host.cpp -o build/friend-repair-20261004/independent-review/test_cuda_cleanup_host.exe
build/friend-repair-20261004/independent-review/test_cuda_cleanup_host.exe
```

Result: **17/17 policy cases**, compiler success without emitted warnings. Cases cover explicit/destructor cleanup, transient/persistent wipe/sync/free errors, sticky suppression of future allocations, allocation error, independent cleanup of other live owners, and preservation of the first operation error. Fake callbacks only; cryptographic ABI calls 0, CUDA events 0, performance samples 0.

New Linux target: `make -C c OUT=../build/cleanup-host cuda-cleanup-host-test`. The existing `run_cuda_native.py` release step now includes this target; its five step names remain stable. The native runner recursively hashes the new files, and `check_cuda.source_hashes()` glob includes both names. CUDA object/fault object dependencies include the helper.

Next required integration: update `bench_cuda.CUDA_FILES/BUILD_FILES` with `c/src/cuda_cleanup.h`, synchronize all changed files to a fresh Linux stage, rerun the five real CUDA native steps, and produce a new freeze. Historical CUDA 1789/1789 refers to the previous cleanup implementation; unchanged crypto kernels may be separately hash-compared, but the old complete native source identity is not the new one. Makefile text also changes CPU source manifests even though CPU C translation units and ABI remain unchanged.
