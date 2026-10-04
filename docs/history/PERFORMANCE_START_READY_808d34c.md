# 正式性能测试启动前的交接

用户当前要求完成 CPU 与 CUDA 优化及正确性验收，停在正式性能测试开始前。
本文只提供后续启动入口，当前不执行下列 `run` 命令，真实性能样本数为 0。

CPU/CUDA 两个冻结目录均已发布，`freeze.json` 与 `package.json` 的源码、
库、计划和证据哈希复核通过。最终准备记录为 `validation/optimization-final-readiness.json`；
本地副本复核记录为 `validation/optimization-local-delivery.json`。
当前已到达用户要求的停止点，下列正式运行入口留待后续开始性能测试的指令。

服务器项目为 `/home/guest-experiment/pqc-a1-5`。当前无计数器库和构建记录位于
`build/cuda-staging-20261004/build/bench-cpu-prep-20261004` 与
`build/cuda-staging-20261004/build/bench-cuda-prep-20261004`。
CPU 基准库与当前 CPU 原生验收库 SHA256 相同；CUDA 发布库另有 14 项无计时独立检查。

CPU 规范计划为 R3 54 项、R4 207 项、R5.pow2 252 项，覆盖 REF/AVX2、缓存与
1/2/4/8/16/32/64 个物理核。CUDA B1 计划为 64 项，另存端到端时长与设备 kernel 时长。
GPU 执行 FORS PRF/F/H 与认证路径，WOTS、消息、缓存和上层 XMSS 继续使用 CPU。

本地可用 `python ops/audit_optimization_delivery.py` 只读复核交付文件；
它检查冻结包、归档、全部引用证据、发布库和计划，不加载原生库或采集计时。
Linux 项目绝对路径映射至本地镜像；12 份系统依赖的原始字节保存在
`validation/optimization-external-evidence/`，映射由其中的 `manifest.json` 记录。
服务器的运行门禁结果见原始 readiness，本地校验结果只证明交付副本完整。
源码归档中的辅助说明保留冻结当时的版本，当前停止状态以本交接文档为准。

正式测试开始时，应先读取最终 checkpoint 中实际发布的冻结目录。
以下 shell 变量的路径须取自最终 checkpoint；不创建虚构的冻结记录。

```sh
cd /home/guest-experiment/pqc-a1-5
CPU_BUILD="$PWD/build/cuda-staging-20261004/build/bench-cpu-prep-20261004"
CUDA_BUILD="$PWD/build/cuda-staging-20261004/build/bench-cuda-prep-20261004"
CPU_FREEZE="$PWD/validation/optimization-cpu-final/freeze.json"
CUDA_FREEZE="$PWD/validation/optimization-cuda-final/freeze.json"
BUDGET="$PWD/validation/optimization-budget-20261004.sqlite"
```

使用下列只读入口核对 CUDA 冻结身份，不加载原生库、不计时：

```sh
.venv/bin/python tools/bench_cuda.py validate \
  --library "$CUDA_BUILD/libslhdsa_sm3.so" \
  --build-record "$CUDA_BUILD/build-record.json" \
  --plan docs/bench_cuda/CUDA_B1.v2.plan.json --freeze "$CUDA_FREEZE"
```

收到后续开始性能测试的指令后，CPU 逐轮执行，使用独立结果文件和夹具目录：

```sh
.venv/bin/python tools/bench_cpu.py run \
  --library "$CPU_BUILD/libslhdsa_sm3.so" \
  --build-record "$CPU_BUILD/build-record.json" --freeze "$CPU_FREEZE" \
  --plan docs/bench_cpu/R3.plan.json --output bench-out/final-r3.jsonl \
  --fixtures bench-out/final-fixtures-cpu --budget-db "$BUDGET"
```

R4 将计划换为 `docs/bench_cpu/R4.plan.json`，结果换为 `bench-out/final-r4.jsonl`；
R5 将计划换为 `docs/bench_cpu/R5.pow2.plan.json`，结果换为 `bench-out/final-r5.jsonl`。
父进程按环境中的物理核拓扑选择并绑定核；每个 case 独立子进程，正式输出只追加。

CUDA 正式运行采用默认可见设备与 PCI_BUS_ID 排序。开始前核对最终记录中的设备身份，
并检查 GPU 当前负载是否适合采样；本轮正确性时的高负载不构成性能基线。

```sh
env -u CUDA_VISIBLE_DEVICES CUDA_DEVICE_ORDER=PCI_BUS_ID \
  .venv/bin/python tools/bench_cuda.py run \
  --library "$CUDA_BUILD/libslhdsa_sm3.so" \
  --build-record "$CUDA_BUILD/build-record.json" --freeze "$CUDA_FREEZE" \
  --plan docs/bench_cuda/CUDA_B1.v2.plan.json --output bench-out/final-cuda.jsonl \
  --fixtures bench-out/final-fixtures-cuda --budget-db "$BUDGET"
```

续跑保留相同计划、库、构建、冻结包、结果文件、夹具和账本。工具检查已保存样本、
统计量、GPU/CPU 环境、预算和哈希；失败签名尝试也消耗 reservation。
不使用 correctness 日志中的诊断耗时计算加速比，不把计划样本量写成已执行样本量。
