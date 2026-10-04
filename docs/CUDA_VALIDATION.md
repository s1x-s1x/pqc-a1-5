# CUDA B1 正确性验收计划

`tools/check_cuda.py` 为显式 backend 5 建立独立正确性证据，CPU 的
`tools/check_optimization.py` 保持冻结。当前 B1 是混合实现：GPU 计算 FORS
子树中的 PRF、F、父节点 H 及认证路径；WOTS、消息杂凑、上层 XMSS 和公共缓存
继续使用 CPU。工具检查实际后端及每次操作的 GPU kernel/device-hash 统计，
因此选中 backend 5 与实际发生 GPU 工作分别有证据。

## 范围与逻辑计数

light 覆盖七组既有向量验证、SM3 四参数的 REF/backend5 WOTS/FORS 子树、
首末绝对 offset、无目标/首/中/末认证路径、未对齐输出及参数错误 guards，
pid201/1/2 seeded keygen 与缓存/无缓存完整签名；toy 覆盖 t0..10 缓存
格式、save/load、根绑定、真实 build t0/t10。所有正常操作逐字段比较
`prf,prf_msg,h_msg,f,h,t,compress` 精确模型。逻辑计数表示相同标量计算，
kernel launch、传输字节和物理 device_hashes 是另一组统计，分别保存。

full 加入真实 pid3 t0 来源 keygen及独立父节点推导 t0..22，backend5/REF
全层 load/save 和 root binding；真实 backend5 cache_build t12 检查字节一致。
完整 GPU FORS 签名直接执行无缓存以及 t0/t12/t22。既有签名逐字节匹配，
还比较已完成 CPU full 中相同输入/缓存层的 REF 输出哈希与七字段。
CPU 重建大型 FORS 的记录经 manifest、逐行哈希、全计划和输入身份校验后复用，
不会伪装为本轮重新执行。每个新签名再分别由当前库 REF/backend5 验证。
`--large-sign-all-levels` 显式增加全部 23 层签名；默认保留未重复层的范围说明。

默认 1/4 个 CPU 工作线程。GPU 并行规模由 native kernel 实现和设备资源决定，
这里的线程数不当作 CUDA block/grid 配置。高 z 的 FORS 测试使用首/末合法树位置，
WOTS 子树在相应 hp 区间测试 CPU 混合路径；不声称 WOTS 在 GPU 执行。

错误 SK.root 的签后自验要求错误 `-5`、整个签名输出清零、外侧哨兵保持，
并在原始向量 PK 的持久预算中消耗失败 reservation。原生错误 guard 要求返回值、
输出保持和零逻辑计数。完整 CPU 故障注入与构建隔离由最终 native 验收另行覆盖。

## GPU 杂凑与环境证据

独立 C/CUDA `test_cuda` 使用内部 SM3 hook，检查 GPU 原始杂凑与标量结果。
其 JSON 通过 `--kernel-record` 提供，要求 `passed=true`、实际 backend5、
正的 kernel launch、精确源码哈希以及无性能计时标记。
这个内部 hook 保持在测试二进制，release 公共库只暴露后端、设备和统计 ABI。

`slh_cuda_get_info` 返回运行时设备、runtime/driver、compute capability、内存和名称。
工具额外保存 nvcc/gcc 版本、CUDA header 哈希、nvidia-smi 的设备 UUID/驱动/型号，
及 `CUDA_VISIBLE_DEVICES`/device order。完整执行以实际选定设备的记录为准。
CUDA 11.5 的 compute86 PTX 与 RTX4090 JIT 环境应通过独立 probe/构建记录追溯。
GPU 利用率高时保持单设备执行，不启动吞吐或时延测量。

每次测量前同时 reset 七字段和 `slh_cuda_stats_reset(0)`，之后保存六项
`kernel_launches,h2d_bytes,d2h_bytes,device_hashes,kernel_ns,timing_enabled`。
所有 `kernel_ns` 与 `timing_enabled` 必須为 0。计数区间串行，签名预算、
REF 基线、缓存准备和独立推导均分别记录。

## 运行及缺席检查

在源码冻结后构建独立 COUNTERS=1 CUDA 库与 CUDA=0 库，由父任务安排服务器验收。
在项目根目录执行，例如：

```sh
CUDA_VISIBLE_DEVICES=0 python3 tools/check_cuda.py \
  --library build/cuda/counters/libslhdsa_sm3.so \
  --disabled-library build/cuda/disabled/libslhdsa_sm3.so \
  --kernel-record validation/cuda-native-NEW_RUN_ID/kernel.json \
  --cpu-run validation/optimization-full-FINISHED_RUN_ID \
  --run-dir validation/cuda-full-NEW_RUN_ID \
  --budget-db validation/shared-signing-budget.sqlite \
  --suite full --fail-fast
```

CUDA=0 库必须对 SM3 参数显式 backend5 返回 `-2`、context 为 null、availability=0。
SHA2 参数同样要求显式 backend5 被拒绝。`--missing-library` 可检查旧版/portable
缺席库。实际运行 GPU 隐藏的情形在新的进程验证：

```sh
CUDA_VISIBLE_DEVICES='' python3 tools/check_cuda.py \
  --library build/cuda/counters/libslhdsa_sm3.so \
  --run-dir validation/cuda-runtime-absent-NEW_RUN_ID \
  --budget-db validation/shared-signing-budget.sqlite \
  --require-cuda-absent --fail-fast
```

普通验收请求 backend5 而设备或实现缺席时，记录显式拒绝后把相应用例标记
`unavailable`，请求范围保持待完成。absence 模式独立标记
`validation_kind=backend-absence`，用来证明拒绝行为，不作为 GPU 正确性通过证据。

## 产物与冻结审查

`manifest.json` 保存精确计划及源码/库/向量/预算路径/CPU reference/kernel record
身份；`cases.jsonl` 只追加，每条含 case/input/result/record 哈希、七字段、
逐字段匹配、actual_selected_backend、每操作 GPU stats 和预算 receipt。
辅助 REF、准备/load/save及生成签名验证失败也使全轮失败；fail-fast 在记录落盘后停止。

`summary.json` 提供 schema/final/passed/completed_requested_scope、计划与记录数量、
失败/缺席/待执行 case、源码与库哈希、cases.jsonl 哈希、GPU 环境、实际后端集合、
直接 GPU 操作计数、完整签名 pid/缓存层、预算核对、无计时标记和未重复的范围。
执行结束复核源码/库/向量及复用证据哈希；精确 `--resume` 继续同目录并保留旧记录。
正式性能工具、无计数器构建、计划及 mock 后续由独立冻结审查连接，
此工具自身不测量任何耗时，也不输出加速比。

## 独立冻结入口

`tools/freeze_cuda.py` 只读取证据、哈希和构建记录，不加载原生库。
它要求 full checker 的 CPU 工作线程为 1/4/64，`--large-sign-all-levels` 已开启，
显式计划每项及辅助记录都通过；检查逐行哈希、计划 case 身份、输入/结果指纹，
并独立重算七逻辑计数。大型 REF 引用按原 CPU manifest/records、受测源码归档，
以及 `--cpu-baseline-run` 的原生源码归档与旧计数器库验证，
签名 receipt 在同一个持久 SQLite 预算中核对状态、消息、PK、算法和签名摘要。

`--native-run` 指向 `tools/run_cuda_native.py` 的真实五步骤验收。
冻结入口核对当前 C/cu/cuh/cpp 源码、源码稳定标志、编译产物/日志哈希，
核对 GPU SM3/FORS/完整签名 raw 输出与 `kernel.json` 的一一绑定。
故障 0..5 要求 host/device 的 TEST_BUILD 编译旗标及显式 backend5 执行，
包含线程1/4、cache_t5/10、自验开/关、pure/internal/prehash/digest 所有组合。
同时核对 release guards、CUDA=0 与实际隐藏设备的拒绝记录。

精确无计数器的性能准备库由 `tools/check_cuda_release.py` 独立验收。
它的三条完整 Python pid3 向量及五种 toy prehash 共14条检查必须通过，
GPU 工作直接存在、事件关闭、公开逻辑计数为零，库/构建/设备/输入/工具哈希一致。
14个 case_id 必须精确匹配三条输入向量和 prehash1..5；八个签名均要求完整六字段
GPU 统计、输入/上下文/随机化/PK/签名摘要，以及同一持久 SQLite 账本的唯一 committed 收据。
JSON、JSONL、日志、源码归档及 SQLite/WAL 都从首次记录摘要的同一份字节解析，发布前复查原件。
账本的验收字节另存于冻结目录 `budget-evidence/`，`budget_snapshots` 连接运行时账本路径与
只读验收副本及其摘要。后续性能任务继续使用共享账本增加 reservation，验收副本保持原状。
benchmark mock 必須阻断真实原生调用与计时，规范计划必须逐项等于64项默认 CUDA B1
计划，CPU 与 GPU 时间指标的作用域保持独立。

```sh
python3 tools/freeze_cuda.py \
  --cuda-run validation/cuda-full-FINISHED_RUN_ID \
  --native-run validation/cuda-native-FINISHED_RUN_ID \
  --cpu-baseline-run validation/cpu-native-HISTORICAL_BASELINE_ID \
  --kernel-record validation/cuda-native-FINISHED_RUN_ID/kernel.json \
  --release-correctness validation/cuda-release-correctness-FINISHED_RUN_ID.json \
  --cli-correctness validation/cuda-cli-correctness-FINISHED_RUN_ID.json \
  --build-record build/cuda-benchmark-FINISHED_RUN_ID/build-record.json \
  --mock-record validation/cuda-preparation-mock-FINISHED_RUN_ID.json \
  --plan validation/cuda-benchmark-plan-FINISHED_RUN_ID.json \
  --output-dir validation/cuda-freeze-NEW_RUN_ID
```

产物为 `a15-cuda-freeze-v1` 的 freeze.json、source.tar.gz、逐文件源码清单、
REVIEW.md 和 package.json。候选内容通过 `bench_cuda.validate_freeze_content`，
其返回 `content_gate_passed=true`、`formal_gate_passed=false`。先完整写入包与哈希，
复核所有首次摘要后，最后发布规范名称 `freeze.json`；此时再通过 `bench_cuda.validate_freeze`。
候选文件或缺项包均不取得正式计时门禁。这个 gate 只证明性能准备的可追溯性，
本次仍保持正式性能样本数为0。

纯模拟负向检查可用 `python3 tools/freeze_cuda.py --self-test --self-test-output NEW_RECORD.json`，
覆盖缺项/重复 case、GPU 统计、错误收据、历史归档/库变动、WAL、输入变动和最后发布顺序。
