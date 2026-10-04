# B03 预算账本扩展性修补记录

日期：2026-10-04。仅 synthetic Python/SQLite 功能回归与 SQLite VM 指令计数；原生签名调用 0、计时样本 0、正式性能测试未开始。历史 `friend-audit-review-20261004` 证据保持原字节。

## 修改

- 新增 `integrity_schema=3` 和 `ledger_counts`，以十进制 TEXT 保存累计消耗及 reserved/committed/failed 数量，保留超过 SQLite int64 的 `2^64` 额度。
- `reserve()` 在 `BEGIN IMMEDIATE` 内先校验 UUID、schema、每密钥计数和两端 ordinal，再插入预留；触发器在同一事务中增加历史消耗。签名前扣账、失败和崩溃持续扣账、跨连接竞争遵守同一额度。
- `finish()` 仅允许 reserved 一次转为 committed/failed，事务内调整状态计数，累计消耗保持。
- 普通 `budget.connection()` 和外部 SQLite 连接的修改、删除、计数清零、序号修改、UUID 修改等写入由触发器拒绝。每次调用核验触发器定义，缺失/变更直接报错，既有 v3 账本不自动补装。schema 比较保留 SQL 字符串字面量的空格和大小写。
- 新增 `validate_receipts(requests)`：一个只读事务、一次 UUID/schema 检查，每个不同密钥核对一次计数，依请求顺序返回原 evidence 字典。单个 `validate_receipt()` 委托此 API，兼容既有字段。重复请求可以返回重复结果；操作回执重用由 benchmark 层拒绝。
- 旧 identity-v2 账本在启动事务内完整核对记录、状态、digest、canonical key、正整数序号连续性，初始化计数后装 guards；UUID 和回执不变。更早的大小写别名合并继续保留全部消耗，采取更严额度；历史超额保留并拒绝新增签名。
- 启动及 `audit()` 继续全历史 O(N) 核对；普通 reserve/finish/receipt 路径没有 COUNT 或完整历史扫描。`status()` 读取受保护的计数，完整 checkpoint 使用 `audit()`。

## 合成 VM 指令证据

SQLite 3.50.4；固定时钟 `2026-10-04T00:00:00+00:00`。通过 `progress_handler(..., 1)` 计数，不测实际时间。

| 同密钥已有记录 | 旧 reserve VM | 新 reserve VM | 旧单回执 VM | 新单回执 VM | 新 finish VM | 新完整 audit VM |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 144 | 782 | 60 | 534 | 697 | 510 |
| 10 | 171 | 795 | 87 | 534 | 697 | 600 |
| 100 | 441 | 795 | 357 | 534 | 697 | 1500 |
| 1000 | 3141 | 795 | 3057 | 534 | 697 | 10500 |
| 10000 | 30141 | 795 | 30057 | 534 | 697 | 100500 |

新路径增加固定 schema/guard 开销，消除了随同密钥历史线性增长的扫描。VM 指令数只证明执行工作量变化，不是签名速度、端到端耗时、吞吐或加速比结果。B-tree lookup 的理论开销仍随索引高度增长，不声明算法严格 O(1)。

同密钥 history=10000 时，批验 1/10/100/1000 份回执分别 534/714/2514/20514 VM 指令，仅按请求数量增长，不重扫 10000 条历史；reserve、finish、single/batch validate 均记录 COUNT 查询 0、完整历史扫描查询 0。

可复核脚本与原始 JSON：`probe_b03_repair.py`、`b03-repair-vm-results.json`。

## 回归

- `python tools/test_friend_budget_scalability.py`：15/15 通过。涵盖旧 v2 迁移、失败/崩溃持续收费、双实例 8 线程竞争精确消耗 17 份额度、普通修改/删除封锁、缺失/改变 guards、SQL literal 大小写/空格改变、used/state counter 损坏、内部删除/序号缺口的完整审计、端点缺失、批验顺序/重复/绑定/空批、2^64 TEXT 运算及无 COUNT/扫描的 VM 指令回归。
- `python tools/test_budget_repair.py`：12/12 通过。既有别名额度/迁移/失败收费/证据绑定/UUID/fixture 核对仍通过；手工 synthetic records 更新为 benchmark v2 所需完整绑定和预留开始记录，CPU/CUDA 完成检查都先核对 live receipt。
- 每个以上用例均使用合成 bytes；新专项没有 native 导入，既有测试 `NativeSlhDsa` 和 `perf_counter_ns` 以失败 guard 替代。

## 检测边界

触发器和逐次 schema/计数校验提供 SQLite 事务一致性及普通写入保护，不是数据库的密码学签名。主动删除 guards、伪造连接函数后重装相同 guards、以自洽数据改写全部计数/历史、复制或恢复同 UUID 的旧备份，仍需外部认证/反回滚。测试故意移除并原样重装 guards 制造不一致，再用启动/full audit 检出计数、状态或内部序号损坏。

内部回执损坏在主动绕过 guards 后由初始化/显式 full audit 检查，日常 API 仅核对本次回执、计数和两个序号端点。全历史检查按这个明确 checkpoint 执行，不对普通 API 宣称每次检查全部回执内容。
