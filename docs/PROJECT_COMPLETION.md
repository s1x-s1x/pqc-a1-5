# 项目完成验收清单（报告开始撰写前）

当前阶段为用户另行指定的 CPU 与 CUDA 优化阶段：完成优化与正确性验收，停于正式性能测试之前。
此表仍保存全项目后续需求；当前阶段状态以 `OPTIMIZATION_CHECKPOINT.md` 为准。

目标：完成 v3 的核心软件、实验和可复现数据交付，停在开始撰写作品设计报告之前。
设计报告框架作为实验与产物的需求来源；正文、审批签字和竞赛网站提交属于后续写作/提交阶段。

历史标量证据基线保留在 `validation/stage1-20261004-0100/manifest.json` 与
`report-data/DP1-stage1-20261004-0100/package.json`，这些记录只覆盖各自受测源码。
当前 CUDA 集成版本在服务器隔离目录 `build/cuda-staging-20261004` 验收：
CPU 原生 11 步、当前 CPU light 948 项、CUDA 原生 5 步、CUDA light 1670 项及真实 RNG 已通过。
历史 CPU full 矩阵 3471/3471 项通过，保存 4370 条记录；当前 CUDA full 矩阵 1789/1789 项通过，保存 2541 条记录。
历史 CPU full 与当前集成版原生/light/CUDA full 证据按各自受测源码分版保留；最终 CPU/CUDA 优化冻结包已发布，
已绑定历史源码归档、当前构建、工具与验收快照，独立哈希复核及只读门禁均通过。
最终准备记录为 `validation/optimization-final-readiness.json`。正式性能样本数仍为 0，本阶段优化验收也不等于下表全部项目完成。

| 项 | 验收范围 | 状态 | 完成证据 |
|---|---|---|---|
| S01 | 环境、上游依赖、旧TLS 393测试 | 已有证据 | validation/environment.json;validation/baseline |
| S02 | 正式SPEC、参数/ABI/数据格式、gate0 | 进行中 | 待正式版本与标签 |
| S03–S09 | SM3、Python/C、ACVP/xous/gmsm/完整128-24/随机差分 | 当前原生回归与分版full验收通过 | 历史stage1/WOTS证据分版保留；当前CPU原生11步含外部向量、3组完整AVX2 128-24、toy/subtree差分；历史CPU full3471项/4370记录与当前CUDA full1789项/2541记录通过 |
| S10 | OpenMP子树、认证路径、线程等价 | 当前light回归与历史完整线程矩阵通过 | 当前CPU light948项覆盖七参数、REF/AVX2和1/64线程；历史CPU full3471项覆盖1/2/4/8/16/32/64；当前CUDA full1789项覆盖1/4/64，证据按源码分版 |
| S11 | 全参数计数理论/实测、消息依赖、grid/Pareto | 分析草稿与full计数通过，最终绑定待完成 | DP1-analysis有grid/Pareto、R7/R8及121项分析检查（final=false）；历史CPU full3471项与当前CUDA full1789项有七逻辑字段对照，最终源码/结果包绑定待完成 |
| S12 | 签后自验、计算故障矩阵、清零 | 当前原生专项通过 | 当前CPU原生11步含故障、自验清零、release隔离、ASan/UBSan；CUDA原生5步含192次故障调用与设备缺席检查 |
| S13 | 128-24 t=0…22缓存验收、完整字节一致 | 原生/light与分版full验收及优化冻结通过 | 历史CPU full3471项及当前CUDA full1789项含t0…22缓存载入、root绑定与完整签名字节对照；证据按受测源码保留，双冻结包已发布 |
| S14 | AVX2 x8 FORS、运行时检测、REF差分(F) | 实现、当前原生回归、历史full及优化冻结通过 | 当前CPU原生11步、完整128-24重放与948项light通过；历史CPU full3471项/4370记录通过，分版源码与最终CPU冻结包已保存 |
| A5/B1 | WOTS x8/T_len流式吸收、CUDA FORS混合后端 | 原生/light/full验收及优化冻结通过 | CUDA原生5步、light1670项与full1789项/2541记录通过；GPU负责FORS PRF/F/H，WOTS/消息/缓存/上层XMSS仍在CPU；最终CUDA冻结包已发布 |
| S15 | .so/ctypes/CLI、pure/prehash、ABI正式冻结 | 当前功能、真实RNG与优化构建冻结通过；全项目发布后续 | 当前CPU/CUDA原生专项和各6项真实CLI/RNG通过；精确无计数器release与当前工具已绑定最终freeze/package |
| S16 | R3–R5、正式JSONL、中位数/IQR、消融/E4 | CPU/CUDA测试工具准备完成；正式实验待完成 | 最终CPU26/CUDA23项mock、规范R3/R4/R5.pow2/CUDA64计划与双范围JSONL/续跑/预算工具已备；真实计时样本0，性能/消融/E4尚未开展 |
| S17 | 完整DP1/DP2/DP3、R1–R8、来源、图表数据 | 部分完成 | scalar审核包和DP1分析草稿已保存；最终R1/R2与全包源码绑定、DP2性能和DP3/TLS仍待完成 |
| S18 | 严格DER/preTBS、长度边界、规范依据 | 进行中 | 待往返/边界/独立编码对照 |
| S19 | TLS SlhDsaSm3、Python验签fallback、禁止128-24做在线CV | 进行中 | 待后端测试与live audit |
| S20 | alt链签发/验证、策略/负例、签发预算 | 进行中 | 待策略矩阵、preTBS不变、并发预算验收 |
| S21 | pid3/pid1/ML-DSA44真实fixtures、受控有效期与manifest | 待完成 | DER、密钥/签名、生成参数与哈希 |
| S22–S23 | P0–P4/E1字节、E2真实TCP分段ACK、E3 RTT10/100 N≥30 | 待完成 | 逐握手样本、抓包分析、真实netns记录 |
| E4–E5 | CA签发/验链、篡改与降级拒绝 | 待完成 | 成本样本、C/Python对照、负例记录 |
| M1/M2 | 经典CA泄露/双CA签名、原始首次结果与查询说明 | 待完成 | 模型/二进制/日志哈希、实际查询结果 |
| S24 | CA/握手/负例可运行演示、4截图、带字幕录屏 | 待完成 | 演示脚本、媒体与manifest |
| S25 | 旧393+新增测试、全部矩阵、verify_all等价、gate3 | 待完成 | 最终源码/构建freeze、全部检查记录 |
| S26 | README/SECURITY/CAPABILITIES/PROTOCOL/THIRD_PARTY、打包/匿名/复现 | 待完成 | 提交副本、许可证、干净目录构建与握手 |
| 写作交接 | 53图/64表/6算法框来源目录、事实修正、全部数据可追溯 | 待完成 | writer handoff、图表依赖/结果数据、未测项明确 |

用户已明确将 WOTS x8 与 B1 CUDA FORS 纳入当前阶段；Windows DLL、额外RTT、海光平台仍为后续可选项。
当前CPU无AVX-512。可选未启用项须在能力清单与图表目录标明，而不写成已实现。
正式CPU实验如主机时钟控制权限受限，记录真实boost/governor，固定核/NUMA/样本并报告分散度。
FORS概率项与整体方案安全结论分开；历史近似计数由实际模型替换，保留修正关系。

最终完成条件：以上核心条目均有当前版本直接执行证据，完整数据包与干净环境复现通过，写作交接可直接开始。
当前优化阶段的分版完整矩阵、无计数器release证据绑定、完整冻结包及独立复核均已通过，已到达正式性能开始前的停止点；
正式性能、TLS网络实验、全项目回归、报告图表交接与提交材料仍保留为后续范围。
