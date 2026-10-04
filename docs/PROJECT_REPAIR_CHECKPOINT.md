# 项目修复验收与交付（论文修改之前）

用户授权的代码修复、正确性、功能验收及新版本冻结已完成；正式 CPU/CUDA/网络性能样本为 **0**，论文、LaTeX 和旧报告框架未修改。
完整会话形式化搜索仍未完成，用户已明确选择保留该未完成项后交付。下列工程通过结论不包含这项安全搜索结论。

## 本轮直接证据

| 范围 | 最终结果 | 当前修复版证据 |
|---|---|---|
| CPU 原生 | 11 步通过；独立向量、完整 128-24、AVX2/portable、故障与 ASan/UBSan | build/repair-staging-20261004-r3/validation/native-repair-r3 |
| CPU full | 3471/3471，4433 条记录；七参数、REF/AVX2、1/2/4/8/16/32/64 线程及完整缓存 | build/repair-staging-20261004-r3/validation/cpu-full-repair-r3 |
| CUDA 原生/full | 原生 5 步；1789/1789，2541 条记录；实际 backend5、1/4/64 线程与全部缓存等级 | build/repair-staging-20261004-r3/validation/cuda-native-repair-r3；cuda-full-repair-r3 |
| 发布准备 | CPU mock28、CUDA mock25、freeze mock31；CUDA release14、RNG6；新双冻结和 Linux readiness | build/repair-staging-20261004-r3/validation/repair-final-readiness-r3.json |
| 全项目功能 | 11 步通过；TLS 481 passed/1 Windows-only skip；live审计、依赖、强制真实CA双验、P0–P4 | build/repair-staging-20261004-r3/validation/project-functional-repair-r3-final3 |
| 干净复现 | 3 步通过；源码重建、真实五 profile/严格负例和 ABI边界 | build/repair-staging-20261004-r3/validation/clean-reproduction-repair-r3-final2 |
| 构建身份 | 同 OUT 的 A→B→A、重复 A、flags切换，7 检查通过 | build/repair-staging-20261004-r3/validation/build-config-repair-r3 |
| 分析/数据绑定 | 121 分析检查；当前 R1 case index/R2 exact counts；final=true仅指正确性/分析包 | build/repair-staging-20261004-r3/report-data/DP1-final-repair-r3 |
| 交付复核 | 项目证据审计 14 项及内含双冻结交付19项通过，原生调用/计时0 | validation/project-repair-final-audit-r3.json |
| 演示 | 四张真实证据展示图；32秒MP4内含中文字幕；已目视检查 | build/repair-staging-20261004-r3/validation/project-demo-repair-r3 |

CPU 验收保留串行阶段前缀，再用独立进程补齐剩余用例；各进程内部顺序 reset/call/read，原线程档和3471项完整计划均保留。工作进程采用私有缓存、共享真实预算账本，最多分配96个独立物理核；合并按原始行逐项校验，保存来源、调度记录及独立结算快照。串行运行的原始未完成状态与外部交接快照分开保存，详见当前CPU目录的 provenance.json 与 parallel-correctness-r3。

各 JSON 绑定受测源码、库和日志的 SHA256；历史冻结及 r1/r2/早期失败日志保留，历史通过数不挪用到修复版。
本轮历史修复记录清单为 `validation/repair-history-20261004.json`，保存失败、中断及被后续工具版本替代的原始状态。
演示视频是执行 JSON 的可视化展示，不是实时终端录屏。唯一 pytest skip 为 Windows 目录 DACL 测试。

## 合并清单关闭映射

| 编号 | 已落实行为与验收 |
|---|---|
| F01/F05/F06 | 算法 canonical pid/OID、旧账本事务合并、UUID、live receipt 对账、CA reserve/finish；成功签名摘要与失败收费，SQLite12项通过 |
| F02/F13 | 字节规范化后取长度、整数先检后分配、ABI1.1与checked容量入口；Python边界7项；legacy C容量责任保留 |
| F03/F04 | CPU/CUDA秘密cleanup、独立设备seed、库内私有候选；启用自验时以REF验证，再成功复制；故障/发布/清理与优化构建检查 |
| F07 | 编译配置身份戳；A→B→A实际重建与同配置复用通过 |
| F08/F09 | TLS记录16KiB边界、消息分片/重组、按Finished结束flight；17/21/22B口径分列，实际序列化验收 |
| F10/F11/F12 | 强制 native/Python真实夹具验链与逐边库哈希、live入口审计、经典P0不构造PQ provider |
| F14 | 同fd分配前尺寸检查、读取/EOF/摘要/根检查及提交前metadata复核；追加/截断拒绝、旧cache保留 |
| V01/V02 | 当前源码完整CPU/CUDA矩阵；224个full256 midstate/边界/并发对照，任务重排/发布/缓存变化/清零，CUDA编译资源记录 |
| D01–D09 | 项目事实与写作交接已整理；论文和旧设计文本后续再同步，保留原始审计结论 |

## 按用户选择保留的未完成项

CA v1 首次原始查询与反例保留，单签名来源查询不外推完整会话认证。v2八个完整场景共10次调用全部超时，600秒 honest复跑亦超时；完整模型已完成判决数为0。
两会话轻量控制 `a0a0f0` 只说明局部控制场景，不能替代完整模型。详情为 `CA_MODELS_V2_20261004.md` 与 `validation/ca-models-v2-summary-20261004.json`。

## 下一阶段

本轮停在论文修改之前。正式性能、能耗与网络分布继续未测，测试类型和待扩充入口见 `PERFORMANCE_SCOPE_REPAIR.md`。
Windows生产DLL、海光、AVX-512/NEON、额外RTT和生产CA治理保留后续范围。SM3参数/OID属于实验适配，私有TLS harness的功能验收不构成标准互通或完整安全证明。
数据库副本/备份回滚/直接C入口需要集中预算治理；UUID本身不提供抗回滚保证。

完整本地副本可只读复核：`python ops/audit_project_repair.py`。公开GitHub副本先按 `GITHUB_HANDOFF.md` 恢复匹配的系统依赖原字节。
