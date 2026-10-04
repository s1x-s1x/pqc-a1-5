# 当前项目能力与验收边界

2026-10-04。本文描述当前代码，正式修复版工程验收已完成，状态以
`PROJECT_REPAIR_CHECKPOINT.md` 和绑定源码的实际 JSON 为准。

| 范围 | 当前实现 | 验收与限制 |
|---|---|---|
| SM3 SLH-DSA | 128s、128f、128-24、toy；pure/internal/prehash/digest | SM3 实例是实验适配，向量一致性不等于标准安全类别认证 |
| CPU | REF、运行时检测 AVX2 x8 FORS/WOTS、OpenMP子树、流式T_len | 上层H/T_len等仍有标量路径；当前3471项full通过 |
| 缓存 | t=0…hp 公共节点、PK绑定、摘要/根验证、失败保留旧缓存 | 同fd分配前尺寸及提交前元数据复核；文件无秘密seed |
| CUDA | 明确选择backend5，FORS叶/归约/认证路径 | WOTS、消息、cache、上层XMSS在CPU；AUTO选CPU |
| C/Python接口 | ABI1.1 checked容量、候选隔离、REF自验、异常清理 | legacy C仍要求调用者正确分配；Windows生产DLL后续 |
| 预算 | canonical pid/OID、事务迁移、UUID、成功/失败收费与凭据对账 | 数据库副本/备份回滚仍需外部治理 |
| CA | ECDSA root→intermediate→leaf并行alt签名/严格与兼容策略 | 测试OID、离线测试密钥；128-24仅用于CA |
| TLS | P0–P4、双在线签名、Finished、应用往返、分片/重组 | 私有harness，含私有码点/AAD/TCP前缀，非标准TLS互通 |
| 验签 | 显式native/Python模式、逐边实际后端与库哈希 | 缺库不得冒充native证据；普通运行可使用已披露fallback |
| 形式化 | v1 M1/M2及泄露控制已运行；v2完整会话搜索超时，未完成 | bounded理想原语搜索；不证明实现、DER或无限会话安全 |

正式CPU/CUDA/网络性能样本保持0。中位数/IQR、能耗、真实拥塞窗口/RTT/丢包分布
尚未测；AVX-512、NEON、海光、生产CA治理和Windows生产DLL属于后续范围。
项目已有具体测试不等于独立第三方审计。历史3471/1789等记录仅支持各自源码。
