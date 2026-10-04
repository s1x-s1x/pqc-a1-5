# CUDA B1: GPU SM3 and FORS trees

This implementation completes B1 in the v3 plan. Backend 5 is an explicit
hybrid SM3 backend for pids 1, 2, 3 and 201. FORS secret derivation, leaf F and
every level of subtree H reduction execute on CUDA. WOTS/XMSS, message hashes,
FORS verification and cache operations retain CPU AVX2 when available, or REF.
The backend does not claim a complete GPU implementation of SLH-DSA. AUTO
remains the existing CPU selection. SHA2 explicitly rejects backend 5.

`sm3_cuda_device.cuh` implements SM3 compression, general raw-message SM3 and
the seeded PRF/F/H primitive. It preserves the 22-byte compressed address,
big-endian words, initial 64-byte PK.seed block, total message length and
padding. One CUDA thread generates one FORS leaf. Separate kernels reduce
adjacent children, preserving absolute parent indices and the keypair address.
Authentication nodes are copied before each reduction. z=0 and root-only
calls retain their original behavior. Inputs and base addresses stay immutable.

FORS storage uses two device buffers with capacities 16*2^z and 16*2^(z-1).
The largest a24 subtree therefore needs 384 MiB of node storage. Calls are
serialized with a process mutex. No other process or GPU allocation is changed.
CUDA_VISIBLE_DEVICES selects the visible device; the worker uses its ordinal
0 and reports its name, compute capability, runtime and driver versions.
Each call frees and clears its buffers. Missing CUDA builds use an explicit
stub; missing devices, runtime errors and failed kernels return
SLH_ERR_BACKEND. Allocation failures return SLH_ERR_ALLOC. No GPU failure is
relabelled as CPU execution.

The existing scalar counter contract is unchanged. A successful FORS subtree
with L=2^z leaves contributes PRF=L, F=L, H=L-1 and compression=3L-1; the
initial PK.seed compression remains charged by the existing host init_work.
GPU launch counts are kept separately. Fault point 5 is compiled into the
private CUDA fault objects and alters the selected F leaf before reduction.
Point 2 still affects the separately returned FORS secret on the CPU; digest
and WOTS fault sites retain their existing code. Ordinary CUDA shared objects
are compiled with the release guard and have no exported test worker.

Public diagnostics add slh_cuda_get_info and slh_cuda_stats_reset/get. The
statistics contain kernel_launches, h2d_bytes, d2h_bytes, device_hashes,
kernel_ns and timing_enabled, each uint64_t. Copy counts describe explicit
cudaMemcpy payloads; kernel parameter transfers and driver overhead are not
included. Timing defaults to disabled. Correctness tests call reset(0) and
assert kernel_ns=0. A future, separately authorized benchmark can call
reset(1): CUDA events then record device kernel time, excluding allocations,
copies and CPU work. ABI return always waits for completed kernels; a host
timer around the call measures the complete hybrid operation. An allocation
or transfer benchmark must use host timing and describe its scope separately.

## Build and untimed acceptance

The tested server toolchain is CUDA 11.5 with GCC/G++ 11.4. RTX 4090 can JIT
compute_86 PTX. Use the system CUDA 11.5 headers/runtime; the other installation
under /usr/local/cuda is not the selected runtime. All CUDA builds are explicit:

```sh
CUDA_VISIBLE_DEVICES=0 make -C c CUDA=1 NVCC=nvcc CUDA_ARCH=compute_86 OUT=../build/cuda-check all cuda-test cuda-fault-test guard-test
CUDA_VISIBLE_DEVICES=0 make -C c CUDA=1 NVCC=nvcc CUDA_ARCH=compute_86 COUNTERS=1 OUT=../build/cuda-counts all cuda-test
CUDA_VISIBLE_DEVICES='' ../build/cuda-check/test_cuda
make -C c CUDA=0 OUT=../build/cuda-absent all cuda-test
```

`cuda-test` compares raw GPU SM3 across padding boundaries, unaligned buffers
and partial launch blocks; FORS absolute addresses/authentication paths and
all seven counters across pids 201/1/2/3; hybrid WOTS; complete toy/128f
signatures, cached signatures, serialized caches, randomized inputs,
verification, self-check erasure and guards. Its JSONL output distinguishes
actual CUDA execution from a device-absent dispatch-only pass.
`cuda-fault-test` explicitly requests backend 5 at all six private fault sites.
`tools/check_cuda.py` owns larger independently sourced acceptance.

`test_cuda_kernel_host.cpp` checks exactly the same device arithmetic with a
host compiler. Its result is labelled host-only and never counts as evidence
of CUDA execution. Local Windows seeded native checks use the existing
unshipped RNG stub. Linux RNG, real kernels, .so symbols and fresh CPU native
regressions are independently accepted by the parent task.

This checkpoint contains no formal timings or measured speedup.
