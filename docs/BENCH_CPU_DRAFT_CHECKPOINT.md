# 性能测试准备交接

2026-10-04：停在正式性能测试之前，真实计时样本为 **0**。CPU 运行器通过 26 项 mock，CUDA 准备接口通过 23 项 mock；两份实际 self-test JSON 均包含 passed=true/native_calls=0/real_timing_samples=0，并绑定工具哈希。独立 SM3 harness 已在本地编译，执行 SM3 abc known answer 和 256 组 scalar/x8 对比，全部通过，sample 入口尚未调用。性能工具准备子任务当时没有连接服务器。

docs/bench_cpu/PREPARATION_READY.json 保存实际证据的路径、哈希、状态和计划，旧稿的 20 项 mock / SM3 pending / R5 全线程作为规范计划等字段已更新。CPU 和 CUDA 各自保留独立 freeze schema；真实 GPU 的完整正确性证据及最终库由主任务管理。

## 持久计划

| 文件 | Case | 计划计时调用 | 范围 |
|---|---:|---:|---|
| docs/bench_cpu/R3.plan.json | 54 | 92085 | SM3/SHA2 的 s、f、128-24；SM3 REF/AVX2 单线程配对 |
| docs/bench_cpu/R4.plan.json | 207 | 2760 | 128-24 每个 t=0..22 的 build/load/sign；SM3 REF/AVX2、SHA2 REF |
| docs/bench_cpu/R5.pow2.plan.json | 252 | 9765 | 规范 R5：1/2/4/8/16/32/64 物理线程；cached/uncached sign、seeded/RNG keygen |
| docs/bench_cpu/R5.plan.json | 2304 | 89280 | 扩展 R5：全部 1..64 物理线程，原计划保留 |
| docs/bench_cuda/CUDA_B1.v2.plan.json | 64 | 3155 | 42 项 SM3 sign + 22 项 FORS root/auth subtree；kernel 与 end-to-end 双范围 |

计划调用次数是 future workload，不是已采样数量。CPU REF/AVX2 比较保持 pid、输入、物理线程、缓存、operation 相同；REF p>1 对 REF p=1 是 OpenMP-only 对照。SHA2 固定 REF。CPU 不足物理核时记录 case_unavailable。

采样下限：verify=10000；s/f sign=100；128-24 cached sign=30、uncached sign=5、keygen=5；R4 build/load 各5。正式模式拒绝 --samples override 与 toy smoke。keygen 明确 requested t=12/effective min(12,hp)；RNG 获取包含在 ABI 时间内。warmup、夹具签名和 RNG keygen 的计时外验证签名均先预约签名预算。

## CPU 运行器验证范围

- JSONL 逐行 append/fsync；完成项保存 N、median、type-7 Q1/Q3/IQR/min/max 及样本行号。续跑检查输入哈希、唯一 sample index、合法 duration 和实际原始统计，只补缺少样本。损坏尾行保持原文件。
- 内核输出锁防同一 JSONL 并发，退出释放；JSON 原子硬链接发布，避免覆盖竞态 writer；build 要求全新目录。输出/预算与 immutable fixtures 分开，output 与 plan/library/build/freeze/ledger 路径分别校验。
- 父进程按计划顺序启动独立 worker，默认整项 timeout=7200 秒；超时保留证据。签名预算不退款，secondary finalize 错误附在原始错误上。
- CPU build 显式 COUNTERS=0/CUDA=0，仅接受 -O2/-O3/-DNDEBUG，清理继承 make flags，检查实际 release/OpenMP/C11/shared 编译命令及全部已哈希 C 源码，保存 compiler path/version/hash。计时前用 toy 一个 FORS 叶核验七个 counter 全零。
- 正式模式要求 Linux 物理核 affinity；同一 CPU 列表用于 parent/worker 的 OMP_PLACES。拒绝 SMT siblings 与重复 CPU，native 初始化前清理继承 OMP/GOMP/KMP 并设置显式线程数。
- source/library/input/build/freeze/plan 哈希及 host/CPU/affinity/governor/boost/OpenMP 稳定字段在续跑和结束时冻结。动态负载/频率逐样本观测；记录 first-touch/跨 NUMA，保持实际调频与 boost 策略。
- uncached sign 使用 fresh context+bind_key；cache build/load 在计时后 save+独立 REF load 重建检查根。cache_load 是 prepared-file warm page cache，包含 native 文件 I/O/摘要/重建。
- 预分配 ctypes ABI 调用的 perf_counter_ns 时间包括 libffi/ABI/native 内部工作，排除 Python 序列化、预算、setup 和 validation。MHz/TSC 没有用于推算 core cycles。

26 项 mock 覆盖计划/统计/核选择、实际编译命令/mock build、counter probe、cache roundtrip、文件锁/竞态/尾行、完整及部分续跑、环境变化、异常/timeout。freeze check 验证 build_record_sha256 与 parent/worker runtime plan 的 suite+digest 绑定，执行 gate 后才进行 native/affinity 工作。新增检查逐文件复核 CPU/CUDA correctness evidence、包内预算 DB/WAL 的缺失或篡改、路径与哈希映射身份及独立副本；live ledger 增长或移走通过，gate 从不读取 live 内容。mock 封锁真实 NativeSlhDsa 和真实 perf_counter_ns；真实 ABI/Linux placement/libgomp/dependencies 由性能阶段另行验收。

## 准备证据与后续命令

CPU/CUDA 最终冻结包现已发布并通过独立复核，真实计时样本仍为 0。
下列路径属于准备接口示例；正式已验收库、冻结包与启动命令以
`PERFORMANCE_START_READY.md` 为准。历史示例冻结记录保留其原始状态。

已运行的持久准备证据：

~~~text
python tools/bench_cpu.py self-test --output docs/bench_cpu/SELFTEST.v6.json
python tools/bench_cuda.py self-test --output docs/bench_cuda/SELFTEST.v7.json
~~~

两份文件是实际执行结果，重跑时使用新路径保留历史。以下 CPU 命令留给正式性能阶段：

~~~text
python tools/bench_cpu.py build --out build/bench-final --cc gcc --cflags=-O3
python tools/bench_cpu.py run --plan docs/bench_cpu/R3.plan.json --library build/bench-final/libslhdsa_sm3.so --build-record build/bench-final/build-record.json --freeze validation/cpu-final-freeze/freeze.json --output validation/perf/R3.jsonl --fixtures validation/perf-inputs --budget-db validation/perf-budget.sqlite --timeout-seconds 7200
python tools/bench_cpu.py inspect validation/perf/R3.jsonl
~~~

CPU freeze 示例保持 final=false/correctness_passed=false。正式 freeze 的 source_sha256 完整等于 hashes(BUILD_FILES + TOOL_FILES)，library_sha256/build_record_sha256 及 plans[suite].sha256 必须等于当前文件；root 依据独立正确性制作新 freeze。规范 R5 使用 R5.pow2.plan.json，扩展 R5 使用另外的 freeze 绑定。

CUDA B1 的 build/plan/mock/freeze/run/worker、结构体 ABI 和 GPU 身份/环境契约详见 docs/bench_cuda/PREPARATION.md。设备内核时间来自显式 events，CPU 墙钟覆盖整次混合 ABI 调用；计划只含产生设备 FORS 工作的操作。CUDA keygen/cache/verify 的 CPU 路径单独解释。run/worker 23 项 mock 已覆盖完整预算、raw/stat、续跑、timeout、物理放置和环境逻辑；真实 Linux/GPU 采样尚待正式阶段验证。

## 独立 SM3 与逻辑计数

tools/bench_sm3_harness.c 的 check 模式已运行，实际证据为 docs/bench_cpu/SM3_CORRECTNESS.v4.json。检查量是 1 个 known answer 加 256 个八路比较，native_calls=257 表示这些 native correctness work items，不计嵌套 C 函数调用。二进制位于 build/sm3-throughput-prep-v2-20261004/bench_sm3_harness.exe，来源哈希和编译命令保存在证据中。

独立 sample REF|AVX2 GROUPS dormant 入口在 C 内循环，相同 seed/state/block 输入；8 scalar compress 对一组 x8 final_blocks，每组 512 B compression blocks。计时包括 seed 拷贝、loop 和 volatile sink，排除输入准备。sample 的 block/byte 数量输出使用 uint64，避免 Windows unsigned long 的元数据溢出。本阶段仅执行 check，实际 SM3 throughput samples=0。该指标是 compression-block throughput；完整消息含 padding 的 SM3 MB/s 需要另一个 matched full-message 入口。

hash_calls/compressions 来自 count_model 的逻辑标量等价数，与无计数器计时库分离。x8 非活跃 lane 仍有物理计算；逻辑 count 与 SIMD 指令数、物理总工作分别说明。cache checksum 单列 model metadata，结果保留组成/源码位置/哈希，模型匹配由主任务独立计数验收保证。

本阶段没有正式性能结果或加速比结论；性能工具准备子任务修改 benchmark 与准备 docs/计划，C/native/ledger/count_model 由主任务和其他 agent 管理。

最终 formal gate 同时要求 canonical freeze.json 和 passed package.json 四件套；candidate 仅作内容兼容性检查，缺少完整 package 的文件不会授权采样。新增 mock 验证 candidate/缺失package/变动REVIEW 的 gate 行为。

CUDA candidate/public gate 还显式要求 freeze.formal_performance_started=false、real_timing_samples 为精确整数 0。SELFTEST.v7 的生命周期负例对两个 gate 分别覆盖 11 组缺失或异常值，布尔值与浮点数零也拒绝。

公开 gate 逐文件复核 CPU correctness_evidence / CUDA correctness_evidence_sha256 的非空绝对路径哈希映射。CUDA budget_snapshots 必须非空；每份 snapshot_database 位于该冻结包 budget-evidence 目录，files_sha256 精确列出 DB 与可选 DB-wal，且与 correctness evidence 同值。路径别名、SHM、包外副本、重复映射和硬链接副本均拒绝。live_database 及其 WAL/SHM 仅作历史身份，排除在不可变哈希依赖之外；后续正式实验继续使用 live ledger，包内 DB/WAL 保持独立只读。
