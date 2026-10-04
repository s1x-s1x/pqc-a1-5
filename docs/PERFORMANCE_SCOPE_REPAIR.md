# 修复版性能测试范围（仅准备，尚未执行）

正式 CPU、CUDA 与网络计时样本均为 0。本轮只执行正确性、功能、编译资源与发布准备检查。
后续启动性能需新的用户指令，运行对象必须匹配修复版冻结包；旧优化包仅解释旧源码。

| 测试 | 已准备口径 | 正式样本状态 |
|---|---|---|
| R3 完整操作 | REF/AVX2 的 keygen、sign、verify，54 个计划 case | 0 |
| R4 缓存/存储 | 缓存等级、cache build/load 与签名，207 个计划 case；load 使用 warm page cache | 0 |
| R5 线程/向量 | 幂次线程、REF/AVX2 对比，R5.pow2 为 252 个计划 case | 0 |
| CUDA B1 | 完整签名与 FORS 子树；host 端到端与 CUDA event 内核范围分列，64 个计划 case | 0 |
| E1 字节 | P0–P4 已执行真实序列化功能；DER、握手消息、bare record、私有 TCP、标准 TLS 模型分列 | 仅字节，无耗时样本 |
| E2/E3 网络 | 真实 TCP 分段/ACK、initcwnd、RTT/丢包/拥塞与 N≥30 分布 | 未开展 |
| E4/E5 CA | 真实签发/验链功能与剥离/篡改负例已执行；成本分布未采集 | 0 |

四份规范计划合计 577 个 case。计划数量不代表执行数量；签名调用要在启动前按本轮持久账本、密钥预算和所选计划重新核对。
CPU 现有计时方案关闭签后自验。自验开销、冷启动/冷加载、缓存摊销、逐阶段时间、PRF/F/H/WOTS 微基准、独立消融、峰值内存及能耗属于评估扩充，启动前还需补对应采样入口与新计划绑定。

CUDA 只加速 FORS；WOTS、消息、缓存及上层 XMSS 在 CPU 执行。编译器寄存器/spill/shared-memory 信息属于静态资源证据，不能当作吞吐或时延结果。TSC tick、时间与核心周期分列，缺少实际核心周期计数时保持为空。

未来 campaign/case/fixture 使用 ledger UUID 和 live receipt 对账，失败预约继续计费。数据库副本、备份回滚与跨设备密钥集中治理仍需操作者统一核对。
Windows 生产 DLL、海光、AVX-512/NEON、额外 RTT 点和生产 CA 治理保留后续范围。
