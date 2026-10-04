# 第一轮审核包：标量正确性

审核日期：2026-10-04。服务器工作目录：`/home/guest-experiment/pqc-a1-5`。
本轮验收通过，源码与运行结果由 `validation/stage1-20261004-0100/manifest.json` 绑定。
共享库 SHA256：`7466b9e92ac09f6a5dd82cc928ebe1ea46d0e74c59f0dd6f937918d132a94618`。

| 证据 | 通过/执行 | 计数单位 |
|---|---:|---|
| ACVP/xous/gmsm | 351/351 | 操作或验签检查；208+3+140 |
| 完整 SM3-128-24 C/Python | 3/3 | 完整种子用例，含3,856字节签名 |
| 完整玩具参数 C/Python | 1000/1000 | 完整种子用例 |
| 辅助 subtree C/Python | 1000/1000 | 子树用例，单列辅助覆盖 |

本轮重新执行已有输入，重复执行不增加独立向量数量。
原生/扩展缓存与线程测试、计算故障注入矩阵、ASan/UBSan、精确计数的命令、退出码和日志位于 `execution-index.csv`。
故障测试使用专用编译宏，普通共享库不开放运行时注入接口；故障点和覆盖以原始fault日志为准。

`R1-summary.csv` 可用于表8-5；`R1-case-index.csv` 给出逐例来源文件、行号和哈希，支持表8-1、8-3。
`exact-counts.jsonl` 按实际消息和WOTS校验和比较理论预测与原生计数，覆盖参数/操作以摘要为准，供R2与表5-3/5-4使用。
参数尺寸与cache载荷/文件/节点内存来自 `DP1-preliminary/parameters.csv` 与 `cache-storage.csv`，属于按参数计算。
`report-availability.csv` 明确标识后续章节尚待实测的项目。

当前是标量正确性审核点，完整DP1还需参数网格与FORS攻击项等分析产物。报告中的正式性能数值、SIMD/CUDA、证书链/TCP和形式化模型结果留待后续实验。
全部耗时来自正确性运行，标为诊断耗时；旧TLS底座393项测试另列既有工作。
FORS攻击概率项、SM3适配假设与整个签名方案的安全结论分开写。该测试包提供功能一致性证据。

推荐审核入口：本文件 → `R1-summary.csv` → `execution-index.csv` → `package.json`。
