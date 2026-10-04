# 修复版项目事实交接（论文修改前）

2026-10-04。用户要求先补项目，停在论文修改之前；本次未编辑论文/LaTeX或旧设计框架。
冲突数值以源码、SPEC、实际日志和freeze为准。最终工程验收已完成，具体通过数与源码证据见 PROJECT_REPAIR_CHECKPOINT.md。
完整会话符号搜索按用户选择保留未完成，不沿用旧源码的通过计数。

后续论文需同步的事实：

- CPU midstate、AVX2 FORS/WOTS、流式T_len、OpenMP及CUDA FORS已有实现。
  CUDA范围是FORS混合后端；任务粒度采用实际自适应策略，计数使用全局atomic，
  无计数器发布构建擦除计数路径。报告固定任务数与thread-local描述按源码调整。
- 新ABI1.1 checked容量、私有签名候选→启用自验时REF验证→成功复制、秘密cleanup及cache尺寸
  前检/提交复核属于修复版保证。legacy入口容量责任和上下文并发约定继续写明。
- 预算case/fixtures绑定ledger UUID，并核验live receipts；aliases事务合并收费。
  UUID不等于数据库副本抗回滚方案。
- 真实CA夹具与强制C/Python验链、TLS分片、P0最小依赖和live audit须引用最终记录。
  17/21/22 B分别是bare保护、私有TCP、标准TLS模型；DER可变ECDSA长度用实际JSON。
- M1/M2查询需分别解释Binding、SignatureOrigin、完整flight/SessionAuth、Fresh、Secret；
  首轮a0针对单签名来源，不外推完整在线认证。场景A/B和双在线附加条件分别报告。
- FORS概率项负log2不等于完整安全强度；SM3是实验实例，测试OID/草案参数事实保留。

| 待引用产物 | 用途 | 当前状态 |
|---|---|---|
| native-repair-r3 manifest | CPU原生/独立差分/sanitizer/CLI | 11步通过 |
| cpu-full-repair-r3 summary/cases | 当前全参数、线程、cache/计数 | 通过；见最终checkpoint |
| cuda-native/full-repair-r3 | GPU实际执行/故障/资源/全矩阵 | 通过；见最终checkpoint |
| project-functional-repair-r3 | 真实夹具、pytest/live/负例 | 通过；见最终checkpoint |
| 新freeze/package/readiness | 当前版本及性能计划绑定 | 新双冻结及readiness通过 |
| ca-models首次日志与查询映射 | bounded符号检查 | v1原始结果保留；v2完整搜索超时，未完成 |
| DP1-analysis-repair | 数值/结构分析121检查 | 已通过；已生成当前版本最终绑定包 |
| project-demo | 执行证据图像/字幕视频 | 基于真实验收生成 |

正式CPU/CUDA/网络性能样本均0；DP2/性能表/能耗/网络分布保持未测。
后续性能类型包括R3完整操作、R4缓存/存储、R5线程/向量比较、CUDA B1内核与host范围、
阶段/自验消融、CA签发/验链、P0–P4网络条件；本轮只准备入口/计划，未提供这些结果。
Windows生产DLL、海光、AVX512/NEON、额外RTT和生产CA治理保留后续范围。
