# CPU 与 CUDA 优化阶段验收与停止边界

2026-10-04 用户调整当前阶段：先完成优化，停在准备开始测试优化性能的位置。
原“项目完成、停在写论文前”目标的其他工作保留，当前暂停推进 TLS、网络、正式性能与写作交接。

当前 CPU 范围包含 v3 的缓存/OpenMP/AVX2 FORS，以及 A5 的 WOTS x8 与 T_len 流式吸收。
用户随后明确选择“本次也完成 CUDA 优化”，因此 B1 CUDA FORS 子树核加入本次必做范围。
AVX-512、海光和 Windows DLL 仍按实施计划的可选条件处理。
当前主机支持 AVX2，未提供 AVX-512 能力。

| 项目 | 当前阶段要求 | 状态与证据 |
|---|---|---|
| midstate | 固定 PK.seed 前缀预压缩、REF 等价 | WOTS 版本 Linux 原生验收通过 |
| 缓存 | 128-24 t=0…22，保存/加载/root 绑定、签名字节一致 | 历史完整矩阵 3471 项及当前 CPU 948 项回归通过 |
| OpenMP | 1/2/4/8/16/32/64 线程与 REF 等价 | 历史完整矩阵 3471 项及当前 CPU 948 项回归通过 |
| AVX2 FORS | x8 PRF/F/H、绝对地址、认证路径、尾部与运行时回落 | WOTS 版本 Linux 原生验收通过 |
| AVX2 WOTS | x8 公钥链与流式 T_len、XMSS 子树/缓存/签名等价 | 实现完成；Linux 原生 11 步及完整 128-24 重放通过 |
| CUDA FORS | 实际 GPU SM3/叶/父节点/认证路径、REF 等价、故障边界 | 实现完成；五步原生验收与 light 1670 项通过；full 1789 项全部通过 |
| 原生接口 | release .so、ctypes、pure/prehash、CLI、预算账本 | 当前 CPU 11 步验收及 RNG 6 项通过；CUDA CLI/RNG 6 项通过 |
| 故障与内存 | 注入矩阵、自验清零、哨兵、ASan/UBSan、release 隔离 | 当前 CPU 原生验收通过；CUDA 192 次故障调用及设备缺席检查通过 |
| 测试准备 | 独立无计数器基准库、逐样本 JSONL、固定核、N/中位数/IQR、可运行入口 | CPU/CUDA 库、规范计划与 mock 已就绪；完整矩阵、最终冻结包与只读运行门禁均通过 |

正确性测试允许记录执行日志及诊断耗时；这些耗时不构成优化性能数据。
停止条件：当前优化代码冻结，以上正确性证据全部通过，性能测试工具和命令已就绪。
到达停止条件后汇报并等待用户下一步，不启动正式性能实验。

## 当前集成版本的验收

CUDA 集成在服务器隔离目录 `build/cuda-staging-20261004` 中验收，避免改变历史 CPU 完整矩阵所绑定的源码；
历史 CPU 完整矩阵与当前 CUDA 完整矩阵均已通过；当前集成版 CPU 另有原生验收与
1/64 线程 948 项回归。下列路径均相对于该隔离目录：

- `validation/native-cuda-cpu-regression-20261004-0344/manifest.json`：CPU 11 步通过，
  包括两构建各 351 项外部检查、3 组完整 AVX2 128-24、1000 toy、1000 subtree、
  精确计数、CLI/预算和 sanitizer；同目录 `rng.json` 的 6 项真实 RNG 检查通过。
- `validation/cpu-matrix-current-20261004-0350/summary.json`：948/948 项通过，
  七参数、REF/AVX2 与 CPU 工作线程 1/64 的当前版本回归。
- `validation/cuda-native-20261004-0330/manifest.json`：真实 GPU 五步验收通过，
  含 7294 项 SM3 对照、148 项子树/混合路径对照、12 项完整签名/缓存对照及 192 次故障调用。
- `validation/cuda-absent-20261004-0350/summary.json`：隐藏设备的 4 项显式拒绝检查通过。
- `validation/cuda-light-20261004-0354/summary.json`：1670/1670 项扩展检查通过，
  包含七参数验证、CPU 线程 1/4/64 的 SM3 REF/backend5 子树、小参数完整签名与缓存检查。
- `preparation/cuda-cli-rng.json`：显式 backend5 的 6 项真实 RNG/CLI 检查通过。

当前 CUDA B1 由 GPU 执行 FORS 的 PRF/F/H、子树归约与认证路径；WOTS、消息、
上层 XMSS 及缓存仍使用 CPU。正确性执行关闭 CUDA event 计时，正式性能样本数为 0。
历史 CPU 全矩阵 3471/3471 项、CUDA 全矩阵 1789/1789 项已通过；
最终冻结已绑定当前性能工具、release 证据与持久预算验收快照。
独立无计数器 CPU 基准库与本次 11 步原生验收的 release 库 SHA256 完全一致。
Linux 上的性能工具模拟检查覆盖冻结证据和预算副本校验；最终数量及工具哈希以冻结包所列 mock 记录为准，真实性能样本数均为 0。

最终交付目录为 `validation/optimization-cpu-final` 和 `validation/optimization-cuda-final`。
以两目录的 `freeze.json`、`package.json` 及 `REVIEW.md` 为最终验收依据；
后续启动入口见 `PERFORMANCE_START_READY.md`，该文档中的正式运行命令尚未执行。

## 最终停止点已到达（2026-10-04）

CPU 与 CUDA 的 `freeze.json` 均为 `final=true`、`correctness_passed=true`，
两个 `package.json` 均为 `passed=true`。服务器独立复核通过 71/68 份归档源码、
21/186 份正确性证据，以及精确发布库、构建记录和四份正式计划。
最终性能工具 mock 为 CPU 26 项、CUDA 23 项，均无真实原生计时调用。
只读 CPU/CUDA 门禁通过，详见 `validation/optimization-final-readiness.json`。

正式性能测试保持未启动：真实计时样本为 0，服务器无活动 benchmark run/worker，
性能输出目录无正式样本文件。当前停止于准备开始测试优化性能的位置。
本地交付副本的独立复核另记于 `validation/optimization-local-delivery.json`；
冻结文件中的 Linux 绝对路径保留原始来源，执行正式实验仍使用上述服务器项目。

## 已通过的 WOTS 原生里程碑

`validation/native-wots-20261004-0216/manifest.json` 的 11 步全部通过。
两种构建各有 351 外部 operation checks；显式 AVX2 的 3 组完整 SM3-128-24
与 Python 逐字节一致，另有 1000 toy、1000 subtree、326 七字段计数记录和 23 项 CLI/账本检查。
`rng.json` 的 6 项真实 Linux RNG 检查通过。这些记录均为正确性证据。

`validation/optimization-full-20261004-0228` 已通过 3471/3471 项，
覆盖七参数、两种 CPU backend、1/2/4/8/16/32/64 线程及 128-24 全缓存等级。
该版本源码以 `tested-source.tar.gz` 和 `tested-source.json` 保存；后续 CUDA 版本
须有自己的原生回归与 GPU 正确性证据，旧证据按其受测版本保留。

## 已冻结的 FORS/prehash 里程碑

`validation/native-stage2-20261004-0152/manifest.json` 的 9 个执行步骤全部通过。
53 份源码的归档内容哈希、18 个证据文件哈希、三份本地 .so 哈希独立复核通过；
CLI/预算包括 23 项检查。该 run 保留原样。

该 run 的 external/differential 旧脚本显式要求 REF；文件名中的 avx2 表示构建，
并不证明这些 Python 重放走了 SIMD。C 的 AVX2 专项测试已经直接比较 FORS 子树、
toy/128s/128f 完整签名、预哈希和计数。此历史里程碑之后，WOTS 和当前集成版本
已分别显式执行 AVX2 的完整 128-24 重放并通过；重放工具记录 `--backend` 与实际 backend 字段。
