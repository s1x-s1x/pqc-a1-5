> 历史阶段文档：以下“当前/已就绪/未修改”均指本轮朋友复审修补之前的绑定版本。2026-10-04 最新工程状态见 [FRIEND_REPAIR_20261004.md](../FRIEND_REPAIR_20261004.md) 与最终 `validation/friend-repair-20261004/checkpoint.json`；旧冻结保持原身份。

# CUDA B1 性能准备接口

正式发布的 CPU/CUDA 冻结包已完成；当前启动路径与停止状态见
`../PERFORMANCE_START_READY.md` 和 `../OPTIMIZATION_CHECKPOINT.md`。
本页的构建与冻结路径属于接口示例，正式运行采用交接文档中的实际已验收路径。

本阶段采集的真实计时样本为 0。`tools/bench_cuda.py` 提供独立的 checked build、计划、mock 校验、freeze gate 及可运行的 run/worker。预算、夹具、JSONL、续跑、超时、亲和性和环境冻结已接入，实际持久证据 `SELFTEST.v7.json` 的 23 项 mock 通过；准备产物与真实 GPU 正确性由不同证据记录。

B1 使用明确的 backend 5：GPU 计算 FORS 的 PRF/F 叶节点及每层 H 归约；WOTS、消息哈希、缓存及上层 XMSS 仍由 CPU 处理。SM3 pid1/2/3 的 sign 和 FORS subtree 可产生设备工作。keygen、cache 和 verify 留在 CPU，计划只列出实际使用 FORS 设备工作的操作。

| 指标 | 范围 |
|---|---|
| end_to_end_ns | 预分配 ctypes ABI 调用的 CPU 墙钟时间；含 libffi、CPU 部分、设备分配、传输、同步及启用事件的开销 |
| kernel_ns | 显式启用 CUDA events 后记录的设备 kernel 时间之和；排除显式传输、分配、CPU 和 ABI |
| h2d_bytes / d2h_bytes | 显式 cudaMemcpy 的 payload bytes；不代表全部 PCIe 流量，kernel 参数与 runtime 元数据另有开销 |
| device_hashes | CUDA 路径报告的 device hash 数量，与 CPU 逻辑等价计数、指令数分别解释 |

CPU ABI 时间仅与 CUDA end_to_end_ns 作同输入、参数、缓存及物理线程的配对比较；kernel_ns 单列。多个 CUDA kernel 累计的时间采用设备 events，工具不会从 CPU 墙钟推算该值。统计量为进程全局，未来每项用独立顺序 worker，reset → operation → get 必须串行。

最新规范计划 `CUDA_B1.v2.plan.json` 含 64 项、3155 次计划计时调用：42 项 sign（3 参数 × cached/uncached × 7 个二次幂物理线程）和 22 项 root/auth FORS subtree。旧 `CUDA_B1.plan.json` 保留，其 cases 相同。sign 使用 CPU R3/R5 相同采样下限；FORS subtree 每项 5 次，GPU 对 pid3 高度 24 的内存开销应在正式阶段如实记录。输入/输出缓冲区在计时外准备；签名预算在调用前预约，签名与子树结果在计时后用独立 REF 验证。

## 实际构建记录

从项目根执行以下准备命令；`build` 会编译并执行无计时的 release/counter/device 小检查。选择新输出目录、实际 GPU 支持的 architecture。它采用显式 gcc/nvcc 命令数组，不依赖继承的 make flags。

```text
python tools/bench_cuda.py self-test --output docs/bench_cuda/SELFTEST.v7.json
python tools/bench_cuda.py plan --output docs/bench_cuda/CUDA_B1.v2.plan.json
python tools/bench_cuda.py build --out build/bench-cuda-prep-20261004 --arch sm_86
```

`build-record.json` schema=`a15-cuda-build-v1`，保存每条实际 compile/link argv 及退出结果、C/CUDA 源码前后哈希、cc/nvcc/host_cxx 的路径/版本/二进制哈希、architecture（native cubin 与 forward PTX）、library 哈希、ldd 输出与解析后的依赖文件哈希。C 与 CUDA 都定义 SLH_RELEASE_BUILD；没有 counter/fault/sanitizer 宏。CUDA 对象带 hidden visibility，公共 ABI 由 C 导出。环境移除 NVCC_PREPEND_FLAGS/NVCC_APPEND_FLAGS 及继承的编译 flags。

无计时 runtime probe 先用 REF toy 的一个 FORS 叶验证七个 core counter 为零，再用明确 CUDA toy 的一个 FORS 叶与 REF 比较。CUDA stats_reset(0)，要求 backend=5、device kernel_launches>0、timing_enabled=0、kernel_ns=0；设备字段包含 index、name、runtime/driver version、compute capability 和 total memory。probe 的 native_calls 统计三个 subtree work items，不计 context/info/stats ABI 调用，也不代替完整 CUDA 正确性验收。

## Freeze 契约

CPU 保持 `a15-cpu-freeze-v1`；CUDA 单独使用 `a15-cuda-freeze-v1`，示例见 `FREEZE.example.json`，final=false。主任务可把该对象作为 CPU freeze 的 `cuda_freeze` 引用并保留独立文件。正式 gate 要求 canonical 文件名 freeze.json 和同目录 passed package.json，完整核验 freeze.json/source.tar.gz/source-manifest.json/REVIEW.md 四件套的哈希及 source-manifest 覆盖当前 frozen sources。freeze 作者先写 candidate 与所有包文件，最后发布 canonical freeze.json；candidate、临时文件和缺少完整 package 的文件不会获得正式 timing permit。正式 CUDA gate 同时核验：

- library/build-record/current `BUILD_FILES + TOOL_FILES` 的哈希；实际编译命令仍等于 release 模板，编译器与 ldd 解析依赖保持一致。
- runtime plan 的 suite=cuda_b1 与完整文件 digest，参数/设备操作/采样下限通过检查。
- device_identity 与 build runtime probe 相同；worker 查询当前设备 identity 并传给 gate，以 nvidia-smi 记录全部 GPU UUID/PCI bus/name/driver/compute mode/power limit，冻结身份及策略；逐样本观测温度/时钟/功耗/占用和 CPU 环境。
- correctness evidence 的 passed=true/real_timing_samples=0，且 source_sha256/library_sha256/build_record_sha256/device_identity 与 checked build 一致；mock evidence 为 current TOOL_FILES，native_calls=0/real_timing_samples=0。
- freeze 自身显式包含 formal_performance_started=false 和精确整数 real_timing_samples=0；缺失、布尔值、浮点数、字符串和非零样本值均拒绝。
- correctness_evidence_sha256 列出的每个只读文件均复核 SHA256。budget_snapshots 非空，每份 DB 与可选 DB-wal 均为当前包 budget-evidence 目录中的独立副本，files_sha256 和 correctness evidence 同值且路径身份一致。live_database 及其 WAL/SHM 排除在哈希依赖之外；后续账本增长或移走不影响已发布包，门禁只读包内快照。

```text
python tools/bench_cuda.py validate --library build/bench-cuda-prep-20261004/libslhdsa_sm3.so --build-record build/bench-cuda-prep-20261004/build-record.json --plan docs/bench_cuda/CUDA_B1.v2.plan.json --freeze validation/cuda-final-freeze/freeze.json
python tools/bench_cuda.py run --library build/bench-cuda-prep-20261004/libslhdsa_sm3.so --build-record build/bench-cuda-prep-20261004/build-record.json --plan docs/bench_cuda/CUDA_B1.v2.plan.json --freeze validation/cuda-final-freeze/freeze.json --output validation/perf/CUDA_B1.jsonl --fixtures validation/perf-inputs --budget-db validation/perf-budget.sqlite --timeout-seconds 7200
```

`validate` 只读哈希和依赖，不加载库或采样。父进程和 worker 都在 native/affinity 操作前调用 gate；worker 在开始/结束检查同一组文件及稳定环境，逐样本核验 GPU UUID 与功耗策略。run 以独立顺序子进程运行每项，清理继承 OMP/GOMP/KMP，显式 OMP_PLACES 为同一物理 CPU 列表，CUDA_DEVICE_ORDER=PCI_BUS_ID，使用默认 visible devices，拒绝任意重新映射。worker 内部核验 backend5 和 ABI，所有 setup/warmup/validation 的 events 关闭。

freeze 作者用 `validate_freeze_content(args, device=...)` 校验 candidate 内容，其返回 content_gate_passed=true/formal_gate_passed=false，作为发布前兼容性检查。公开 `validate_freeze` 先校验 canonical 名称与完整 package，再调用内容检查；正式 permit 只在完整发布后成立。

`sample_once` 每次只围绕一个同步预分配 ABI 调用，显式 reset(1)，结束读 stats，随后 reset(0)；缺少设备工作或 kernel events 的样本报错，异常后关闭 events 并保留原始错误。预算在每次签名（含 warmup/夹具签名）之前预约，失败消耗不退款。REF 验证成功后 finalize，后续 model/stat 错误不会二次 finalize。

raw JSONL 逐行 append/fsync，使用独占 output lock；case_complete 同时保存 end-to-end 和 kernel 的 N/median/type-7 Q1/Q3/IQR、原始 samples 与行号。partial resume 验证唯一成功 index、双范围 duration、cuda stats、输入/环境/所有哈希，只补缺少项；completed skip 重算双范围统计、复核输入文件和当前 native device。超时保留记录及预算，默认7200秒；core 不足记录 unavailable，不计完成。`--case EXACT_ID` 可重复选择顺序子集，未提供时为完整计划。

23 项 mock 封锁 CDLL、NativeSlhDsa、subprocess 和真实 perf_counter_ns，用 fixed fake timer 实际走 sign100+warmup、FORS subtree、预算失败与续跑、raw/stat/skip、输入变化、GPU变化、parent顺序OMP/timeout、gate前无native/affinity、candidate/public 生命周期负例，以及 error 后关闭 events。生命周期负例对两个 gate 各覆盖 11 组缺失或异常字段；公开 gate 在内容检查之前拦截预算 DB/WAL 缺失或篡改，并允许 live ledger 增长。共享 CPU self-test 另覆盖两种 schema 的全部 evidence、快照路径与映射、独立副本及 live ledger 删除。Linux真实构建/启动/亲和性及 GPU timing ABI 的实际采样验证仍留给正式性能阶段。

本页性能接口准备子任务仅运行 self-test 和 plan；真实 GPU 构建、正确性验收与最终冻结另有独立证据，正式 campaign 尚未开始。任何吞吐、加速比或完成正式 campaign 的结论均需后续原始样本。

夹具 helper 显式接收调用方的 JSONL emitter。新增 mock 实际执行 helper 的 keygen/sign/持久文件路径，fake Native/预算生成 fixture+signature 两份文件，要求 setup_signature 与全部行均为 CUDA schema；102 次预约含夹具+warmup+100样本，复用已签夹具不增加预算，completed skip 再读不报 foreign schema。
