# CPU 正确性验收并行补齐

2026-10-04 的修复版验收在完整测试计划不变的前提下，采用“已完成串行前缀 + 独立进程补齐剩余用例”的执行方式。该调度只用于正确性验收，正式 CPU/CUDA/网络性能样本继续为 0；这里没有算法加速倍数或性能成绩。

## 保留的验收要求

- 完整 CPU 计划仍为 3471 项，七参数、REF/AVX2 和 1/2/4/8/16/32/64 线程档均保留。
- 受测引擎、原 Runner、签名预算工具、输入向量和 COUNTERS 库字节保持与原生验收一致。
- 各 worker 是独立操作系统进程，在自己的进程内顺序执行 reset/call/read，先执行本进程的计数器探针。
- 各 worker 使用私有输出与可写缓存。缓存输入必须与已保存的派生/加载记录和独立格式校验一致。
- 所有签名继续预约同一个真实 SQLite 账本；成功和失败尝试均收费。合并核对每份签名收据、消息、公钥、签名摘要和状态。

## 实际交接

原串行阶段保留 3359 项；其余 112 项分为 39 组。服务器为 96 个物理核、192 个逻辑 CPU，调度器仅使用每个物理核的一条逻辑线程，总分配量上限为 96 核。

原后台进程继承了 nohup 的 SIGINT 忽略设置。交接先暂停等待中的 CUDA/冻结流水线，再暂停 CPU 进程，核对完整 JSONL 行与校验和，随后终止原 CPU 进程。其原始 manifest、未完成 summary 和 cases 字节保存在 `cpu-full-repair-r3-serial-history`。另存的 `serial-snapshot` 是控制器生成的交接快照，明确记录外部终止，保持 `passed=false`；原 summary 的 `final=false` 状态保留。此次交接的在途签名预约列表为空。

最后一个单线程 worker 的初始核心存在资源争用，移至同一核预算内的空闲核心。线程档保持为 1，所有 TID 的前后亲和性、原始 handoff、资源诊断与调整工具字节单独保存。该操作属于操作系统资源调度，未生成密码算法性能样本。

## 合并与验收

[`ops/parallel_correctness.py`](../ops/parallel_correctness.py) 调用原 `Runner.run_case()` 执行分配项。merge 模式不调用原生库，逐行验证完整用例、源码/库身份、向量指纹、输入/结果摘要、七字段预测与实测计数、配套验算和收据。最终 JSONL 是各保留输入原始字节的拼接，标准 manifest 保留原身份与完整计划。

合并目录还保存每份原始来源、缓存输入和独立结算 SQLite 快照。快照核对 UUID、canonical key、连续收费序号、全部预约和零在途预约；后续 CUDA 使用原 live 账本，CPU 快照保持固定。

[`ops/audit_parallel_correctness.py`](../ops/audit_parallel_correctness.py) 是独立的只读交付复核，只打开结算快照，不打开 live 账本或加载原生库。它核对任务分区、原始行逐字节来源、进程日志/退码、核心分配及调整、全部收费和来源闭包。项目审计与离线包复核纳入该检查。

工具级验收为 55 个 worker/merge 正反例和 60 个并行交付审计正反例；这些隔离检查不代替真实完整矩阵。只有实际聚合通过后，控制器才恢复 CUDA 流水线，再执行原 CPU/CUDA 冻结与最终项目审计。

真实最终结果见 `PROJECT_REPAIR_CHECKPOINT.md` 及交付镜像中的 `validation/cpu-full-repair-r3/summary.json`、`provenance.json`、`settlement.json` 和 `validation/parallel-correctness-r3`。
