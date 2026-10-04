# CPU 优化的正确性与精确计数验收

`tools/check_optimization.py` 对冻结的 `COUNTERS=1` 原生库做正确性验收。
它记录输出一致性和 `prf, prf_msg, h_msg, f, h, t, compress` 七字段，
沿用 `tools/count_model.py` 的精确公式。全局原子计数器的 reset/read 区间串行执行，
参考运算、文件准备、签名预算记账都在相应原生操作的计数区间之外。

这里的签名、建树和文件操作都是正确性工作负载。工具不记录耗时、吞吐、加速比，
所有证据显式标记 `formal_performance=false`；汇总包含
`formal_performance_started=false, measured_durations=false`。

## 输入与公共检查

默认输入是 `report-data/DP1-analysis/count-replay-inputs.jsonl` 的七条完整既有向量：
pid1/2/3 是 SM3，pid101/102/103 是对应 SHA2，pid201 是 toy。
每条向量保留既有种子、密钥、编码消息 `M'`、随机化输入和完整签名。
工具检查输入记录哈希，用独立恢复路径确认签名根及各层实际 WOTS 数字，再验证既有签名。
完整签名用例必须逐字节等于这条既有签名，不生成新的参考签名。

各 suite 都验证七个 pid，并在配置的后端/线程下运行边界 subtree。
默认线程为 `1 2 4 8 16 32 64`，高度为 `0 1 2 3 4 5 6`。
每个高度覆盖无认证目标、首目标、末目标；高度 0 的首末是同一目标，合并成一个用例。
WOTS 子树位于可用叶区间的末端，FORS 子树位于最后一棵 FORS 树的末端，
地址同时包含最高层、最大可用 tree/keypair 域。
每个结果的根与认证路径比较显式单线程 REF 基线，七字段同时比较精确预测。

SM3 使用所选 REF/AVX2 后端。SHA2 使用 REF，并单独验证显式 AVX2 请求返回后端错误。
缺少请求的 AVX2 实现或 CPU 支持时记录 `unavailable`，保留待完成状态。
起始 toy 高度 0 计数探针用于发现误用了 `COUNTERS=0` 库的情况。

## 分层执行范围

| 选择 | 完整签名 | 全层级缓存与根绑定 | 真实 cache_build | 大参数的线程计数矩阵 |
|---|---|---|---|---|
| 默认 `--suite light` | pid201/2/102，无缓存和指定缓存；toy 每层 | toy t=0..10 | toy t=0/10 | 既有向量验证与有界 subtree |
| `--full-small` | 在 light/cache 中加入 pid1/101 | 同相应 suite | 同相应 suite | pid1/101 完整签名 |
| `--suite cache` | 同 light，可加 full-small | 加入真实 pid3 t=0..22 | 加入 pid3 t=0/12/22 | 既有向量验证与有界 subtree |
| `--suite full` | 加入 pid1/101/3；pid3 t=0..22 及无缓存/t12 线程矩阵 | toy 与 pid3 全层 | pid3 t=0/12/22；t12 线程矩阵 | pid3 keygen(t12)、cache_build(t12)、cache_load(t12)、缓存/无缓存签名 |
| `--suite full --full-sha2` | 再加入 pid103 的完整工作负载 | 再加入 pid103 t=0..22 | pid103 t=0/12/22；t12 线程矩阵 | 对 pid103 执行同类矩阵 |

全层缓存操作在最大配置线程数、每个所选有效后端下进行；完整签名缓存/无缓存矩阵
使用每个配置线程数。t0 来源 keygen 每个库/参数只执行一次。
全 suite 为大参数额外运行每个后端/线程的 t12 keygen，
验证缓存层级只改变存储而不改变完整建树的逻辑计数。
t12 的 load 计数在每个缓存签名的独立准备记录中保存。

`--full-sha2` 要求 `--suite full`，避免通过一个重工作负载标志得到部分隐含范围。
light 的完整通过只表示其请求范围完成；`deferred_scope` 明确列出大树/完整矩阵等后续范围。

## pid3 全层缓存的独立推导

每个库用一个明确后端的 seeded keygen 得到真实 t0 公共叶序列，
保存原生 `native-source-t0.cache`。工具独立解析 v1 格式，再逐层求 TREE 父节点，
输出 t=0..22 的 23 个文件，最后检查公共根等于既有 `PK.root`。
每层只包含公共节点。这种准备方式避免为了 23 个文件重复生成 23 次完整密钥。

格式检查包括 96 字节头、`A15CACHE`、版本、pid/t/hp/n、载荷字节数、PK 绑定、
固定 SM3 校验和、截断及尾随数据。载荷为 `n*2^(hp-t)` 字节。
父节点按参数选择 SM3/SHA256，使用 `PK.seed || zero[48]` 前缀、22 字节压缩地址、
对应 top layer、tree=0、TREE 类型、实际高度及索引，取摘要前 n 字节。

每层分别经原生 load/save 并检查字节完全一致；每个后端真实 build t0/t12/t22 的文件
必须等于独立推导层。根绑定测试修改文件内 `PK.root`，重新算正确 SM3 校验和，
并提供同样修改后的 PK；原生 load 仍须返回缓存错误 `-4`，且原有好缓存完整保留。
full 还逐层签名，与无缓存操作和既有完整签名逐字节比较。

缓存文件的固定 SM3 校验和不进入公开 compress 计数器。cache_save 七字段全零；
cache_load 为 `H=2^(hp-t)-1, compress=1+H`，其余全零。
keygen/cache_build 构造完整树，缓存层级不改变总计数。
细节与精确签名公式见 `docs/COUNT_MODEL.md`。

## 运行方式

先冻结源码和依赖，再在 Linux 构建独立计数库。例如：

```sh
make -C c OUT=../build/optimization/counters COUNTERS=1 all
python3 tools/check_optimization.py \
  --library build/optimization/counters/libslhdsa_sm3.so \
  --run-dir validation/optimization-NEW_RUN_ID \
  --budget-db validation/shared-signing-budget.sqlite \
  --suite light --full-small --fail-fast
```

真实 pid3 缓存层级验收选择 `--suite cache`。
明确执行完整大树正确性时使用下列命令，保留默认七组线程：

```sh
python3 tools/check_optimization.py \
  --library build/optimization/counters/libslhdsa_sm3.so \
  --run-dir validation/optimization-full-NEW_RUN_ID \
  --budget-db validation/shared-signing-budget.sqlite \
  --suite full --full-sha2 --cache-source-backend AVX2 --fail-fast
```

默认 `--cache-source-backend REF` 支持 portable 库；指定 AVX2 会明确使用 AVX2 生成
可复用的 t0 来源。portable 构建用 `AVX2=0`，独立运行时选 `--backends REF`。
同一次运行可重复传 `--library` 来比较多个支持同一请求后端集合的库；
portable 库中请求 AVX2 会真实留下 unavailable 状态。

Windows 的本地 seeded smoke 使用现有 getrandom 失败桩 DLL，
仅验证 seeded ABI，不作为生产随机源或正式 Linux 构建证据。
Python 加载 MinGW DLL 时需要先用 `os.add_dll_directory` 加入依赖目录。
缓存 C ABI 的 narrow fopen 路径通过临时进入文件所在目录、使用 ASCII 文件名调用；
进程目录随后恢复，原始证据保持在指定 run-dir。

## 预算、证据与续跑

每次原生签名进入 ABI 之前，先向同一个 `SigningBudget` SQLite 数据库 reserve，
正常完成后 finish(signature)。失败或中断已经消耗的 reservation 保留，重试消耗新条目。
toy 的错误 SK.root 自验用例也在原始向量 PK 下 reserve，要求返回 `-5` 并保留失败预算。
故障路径的实际七字段保存，但不套用正常成功路径的精确预测。

`manifest.json` 固定源码、库、既有向量文件、参数配置及解析后的预算数据库路径，
同时保存显式计划。`cases.jsonl` 只追加，逐行保存输入/结果/记录哈希、七字段、
逐字段匹配、输出检查、具体地址/缓存层及预算 receipt。辅助 REF、cache load/save、
新签名验证记录也参与最终失败判断。

`summary.json` 区分 passed、failed、unavailable、pending，列出实际执行 pid/后端/线程/
缓存层和直接 keygen/build/load 线程；全计划及辅助检查均通过时才报告请求范围完成。
进度 checkpoint 标记 `final=false`，结束后为 `final=true`。
`--fail-fast` 在失败检查落盘后立即停止进一步原生工作。
Windows 临时文件替换遇到短暂共享句柄时仅短重试，失败记录继续保留。

用完全相同参数加 `--resume` 可继续同一目录。它核对 manifest 身份和既有逐行记录哈希，
跳过已通过用例，重试失败/缺失用例。源码、库、向量或配置变动时采用新 run-dir；
保持同一个签名预算数据库。运行结束再次检查源码、库和向量文件哈希，
中途变动会令本轮证据失效。正式性能测试应在这些正确性记录验收后另行启动。

## 已保留的本地工具 smoke

`validation/optimization-tools-smoke-20261004-03/` 的 light 检查为 456 个计划用例全通过，
含辅助操作共 689 条记录：七 pid 验证，REF/AVX2 的线程 1/4，subtree 高度 0/3/5，
pid201/2/102 完整签名，toy t=0..10 缓存 load/save、根绑定和逐层签名。
输入、库和当轮脚本哈希均在该目录 manifest/records 中。
该轮工具 SHA-256 为 8ae573fbe952bcf117413b50e9936ba584abf4fee62b3aa8ec2fbf20ae449813，
包括落盘立即停止的 fail-fast 与解析后预算数据库路径身份检查。
早期 `...-01/` 保留路径编码失败，`...-02/` 保留 Windows 文件共享句柄失败，
两轮均按失败/待完成证据保存。
pid3/103 全树验收及最终冻结脚本与 Linux 编译产物的组合由独立完整运行补齐；
此本地 smoke 不代表这些范围已执行。
