# N01 / E01 / T01 修复及本地专项验收

本轮在朋友复审基线 `808d34c` 之上补齐三个已授权项。实现文件：`tools/native.py`、`tools/test_native_boundaries.py`、`base_tls/tls/alt_chain.py`、`base_tls/tls/handshake/client.py`，新增 `base_tls/tests/test_friend_native_tls_fixes.py`。主代理另行维护 `base_tls/tls/config.py` 的四项预算字段与配置输出。

## 实现

- N01：统一五算法 digest 字节长度为 SHA256/SHA512/SHAKE128/SHAKE256/SM3 的 32/64/32/64/32。若库提供可选 `slh_prehash_bytes`，digest 入口在签验调用前核对其与固定 ABI 契约一致；缺 query 时继续采用明示表，保留原有可选查询兼容。正确 SHAKE256 64 B 被接受，旧错误 32 B 在 Python 层拒绝。消息级 prehash 与 digest 入口继续分开。
- E01：签名、独立验签、组装或 preTBS 不变检查失败后，仍调用失败 finalizer 一次；若 finalizer 再抛普通 Exception，将其说明附到主异常 `add_note` 后重抛主异常。失败及崩溃消耗不退款，reserved 或已持久化 failed 状态不回滚。成功路径 finalizer 失败仍是发布失败。KeyboardInterrupt 主错误亦保留。
- T01：默认 authenticated server flight 上限为 4,096 条记录、4 MiB 累计 plaintext、5 MiB 累计 bare ciphertext、4,096 项审计记录。四项均由 `HybridTLSConfig` 严格正整数配置并记录到 profile。record/audit/ciphertext 限制与 16,640 B record 上限在解密前检查；plaintext 总预算在组装缓冲/audit 增长前检查。按 split header→长度检查→当前 body 的顺序拷贝，每消息仍上限 1 MiB，同记录多消息各自检查。不再先把未经检查的完整 body 放入 assembly。
- T01 失败状态：任意 record、解析、完整性、截断或超预算失败将该客户端 flight 置为终止；清空 assembly 和可用 record/application key 引用及 application/exporter/resumption secret，保留已消耗计数与有限审计。完整消息可能已入 transcript，record sequence 可能已推进，因此该实例不接受重试；后续 record、finish 与 client Finished 均拒绝。收到 Finished 后额外记录同样终止并收回已派生应用 key 引用。Python 清空引用不声明底层内存已物理擦除。

## 验收

正式性能样本始终为 0。下面 pytest 运行时间只是测试执行诊断，未形成 CPU/CUDA/网络性能采样。

| 专项 | 结果 | 范围 |
|---|---:|---|
| `tools/test_native_boundaries.py` | 10/10 | ctypes mock；五算法 × sign/verify × 字符串/整数 × 正确/相邻错误长度，另测 SHAKE256 错误32 B、typed memoryview、query 缺失/一致/冲突与 message prehash 控制 |
| `test_friend_native_tls_fixes.py` | 44/44 | CA普通mock + SQLite双失败前/后持久化不退款、success-finalizer失败、KeyboardInterrupt；四独立预算、默认4,096 tiny fragments、跨消息累计预算、exact边界、1 MiB message、header预检、失败终止、真实AEAD tag失败 |
| `test_merged_tls_fixes.py` | 18/18 | 既有实际40KB长DER/16KiB分片、split header、跨消息coalescing、Finished/transcript/exporter、AEAD record边界、P0可选依赖隔离及功能TCP重组；CA账本已有控制 |
| 源码静态 | 通过 | 五个改动文件AST语法与 `git diff --check` |

本机解释器采用 Codex bundled Python，pytest 纯Python包由 `base_tls/.deps` 提供，cryptography 使用该解释器可用的 Windows runtime。未加载SLH原生库；真实 native digest targeted、全TLS和整体集成由主代理在Linux验收。

证据：`adapter-results.json`、`mock-ca-flight.xml`（44项）、`streaming-functional.xml`（18项）。父任务交付前负责最终版本绑定、文档、提交与推送。本子任务未修改C、历史冻结包或论文，未提交。
