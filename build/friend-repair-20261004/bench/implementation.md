# B01/B02 修复与本地验收

本轮只修改 `tools/bench_cpu.py`、`tools/bench_cuda.py`，新增 `tools/test_bench_resume_repair.py`。未修改 C、历史冻结和论文，未提交或推送。全部运算由 fake native 与 fake CUDA statistics 完成，时长来自固定合成时钟；使用真实临时 SQLite 检查收费与收据。禁止加载原生库、真实计时和启动子进程，正式性能样本 0。

## 行为

- CPU/CUDA JSONL schema 升级为 `a15-cpu-bench-v2` / `a15-cuda-bench-v2`。v1 与其它 schema 保留原文件并显式拒绝续跑，不自动转换。计划、构建与冻结 schema 保持各自原版本，最终新冻结须使用当前工具哈希。
- 每次 worker 的新执行段具有独立 segment UUID。仍有缺失样本时，新段执行全部配置预热，签名预热逐次预约并收费；已有通过样本按原索引保留。全部原始样本已齐而只缺汇总时不重新预热或执行运算。
- 每项预热或样本先持久化 `operation_start`，绑定 operation UUID、索引、执行段、输入、预约收据与 reserved 证据；结果匹配同一 start。进程在预约后或结算后丢失，原收费保留，后续新段使用新预约。失败操作记录非空异常类型/消息，不退款。
- 每个 case 的所有记录绑定完整计划 case、计划 SHA256、源码/库/构建/冻结 SHA256、分类、final、环境、账本 UUID。case key 来自整份绑定的规范编码哈希。各段 start/input/result/complete 逐条验证，拒绝同 case 多种执行身份、结果先于预约、重复结果、缺预热、重复通过索引和完成后新记录。
- `case_complete` 的当前段须输入就绪、无 pending 操作、未失败。旧段因进程丢失留下的 pending 预约继续计费，可由新段完成缺失样本。父代理独立审查发现的 pending/failed+complete 形状已加入专项负例。
- 在筛选 case 或 complete skip 之前审计整个 campaign，拒绝跨独立操作复用 receipt；允许同 operation 的 start/result 引用同收据。公共 fixture 签名收据可作多 case 输入，拒绝用作新的样本运算收据；RNG 验证收据同样参加独立操作去重。
- 绑定 campaign 元信息、setup signature 账本/实际夹具、setup cache 实际文件哈希、所有 partial/complete 输入文件与真实预算。预算逐条核对适配新 `validate_receipts` 批量 API，并兼容现有 mock 单条接口。
- CPU/CUDA 原始时长和汇总从原始行重新核对，CUDA 另外验证 device 计数、kernel/end-to-end 范围、scopes 与 kernel 汇总。当前 worker 开始前、完整 skip 前及父 runner 开始前的坏证据均拒绝。

父进程与 worker 的 CPU 亲和性/OpenMP 配置按计划不同，campaign 到 case 的稳定环境对照排除这两项；case 自身仍绑定其完整 OpenMP/亲和性身份。

## 最终本地结果

| 执行 | 结果 | 证据 |
|---|---|---|
| CPU 内置 fake self-test | 28/28 通过 | `cpu-selftest-final-r4.json` |
| CUDA 内置 fake self-test | 25/25 通过 | `cuda-selftest-final-r4.json` |
| B01/B02 真实 SQLite + fake worker 专项 | 42 个定义：41 通过、1 个 CUDA 不适用项跳过；零失败/错误 | `resume-regression-final-r4.json` / `.log` |
| 已更新预算兼容专项 | 12/12 通过（直接执行 `tools/test_budget_repair.py`） | 统一集成另保存运行日志 |
| 语法与补丁检查 | `py_compile`、`git diff --check` 通过 | 统一集成可再执行 |

专项包含 6 类 bound row 的逐字段 metadata 矩阵、计划/构建/环境/输入篡改、campaign/未选 case/部分样本提前拒绝、合法共享 fixture 引用、跨 case 独立 receipt 复用、预热/样本失败收费、reserved/committed 无结果恢复、只缺汇总、complete skip、KeyboardInterrupt、旧 v1 字节保留及 pending/failed/unready completion。

唯一跳过项是 CUDA 的 `setup_cache` 独立行检查：CUDA 本身不发出该行，使用 CPU 准备的缓存；CPU 对应检查已通过。不是跳过 CUDA 实际缓存代码或 GPU 验收。

最终专项记录 `sources_unchanged_during_run=true`。此前 r1 为测试夹具错误、r2 已通过当时版本；首个 final 在测试过程中继续加固导致源码漂移，明确标记 `passed=false`，保留历史，不用作最终证据。最终 r4 的三个 JSON 哈希与当前源码一致。

本轮未执行真实性能、密码或 GPU 运算；Linux/CUDA 当前版本统一验收及最终冻结由主代理继续。证据绑定和去重提供一致性核查，不构成对任意改写整套 JSONL/数据库的密码学认证。
