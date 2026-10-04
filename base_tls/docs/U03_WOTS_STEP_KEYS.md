# U-03 修复：按树、叶地址和链步派生 WOTS+ 密钥与掩码

状态：本修订已修复原始 v6 的全局固定链步密钥问题，并加入回归测试。原报告没有证明可实际利用的伪造攻击，本修订也不作此断言。

**并入主树后的补充（本仓库 v7）**：本目录的实现来自协作者的 `U03_FIX` 补丁（逐文件并入，见文末"并入记录"），并在此基础上补了一条不变量校验：`keygen_from_seed` 现在拒绝 secret seed 与 public_seed 重叠（相等或互为前缀）。第五轮审查的 V6-09/M1 正是这项缺失——它只校验长度，因此"同一个 32 字节串同时当两把种子"可以构造出可验证的伪造链。加固后该误用直接报错，`tests/test_audit_v6_fixes.py` 固定了这一点。

## 对原修复建议的校正

原附件把 RFC 8391 的 SEED 说成必须保密，并建议仅从私钥派生 tweak。这一说法不准确。SEED 是独立生成、随公钥提供的公开随机量；验签必须能从公开信息重建链函数。只在签名端引入私有 tweak，会使独立验签方缺少必要输入。

依据：[RFC 8391 §4.1.3](https://www.rfc-editor.org/rfc/rfc8391.html#section-4.1.3)、[§4.1.7](https://www.rfc-editor.org/rfc/rfc8391.html#section-4.1.7)、[§4.1.11](https://www.rfc-editor.org/rfc/rfc8391.html#section-4.1.11)。本修订采用两次独立 `os.urandom(n)` 调用生成秘密链种子与公开种子，不使用源码常量，也不把秘密种子发送给对端。

## 实现

删除 `_TWEAK_SEED`、`_step_key_prefixes()` 及其跨叶共享缓存。WOTS+ 的 keygen、sign、verify 都显式接收 `public_seed` 和叶地址；sign/verify 的地址为必传关键字参数。上下文只作为调用参数传递，不存在实例上的“当前种子”或“当前叶子”。

默认 SHA-256、n=32 的每步计算为：

```text
ADRS = layer:u32=0 || tree:u64=0 || type:u32=0
       || leaf:u32 || chain:u32 || step:u32 || keyAndMask:u32
KEY = SHA256(toByte(3,32) || public_seed || ADRS[keyAndMask=0])
BM  = SHA256(toByte(3,32) || public_seed || ADRS[keyAndMask=1])
next = SHA256(toByte(0,32) || KEY || (value XOR BM))
```

地址采用大端、固定 32 字节，包含绝对步号。独立 key/mask 角色避免二者复用；原实现没有 bitmask，此处一并补齐。
依据：[RFC 8391 §2.5](https://www.rfc-editor.org/rfc/rfc8391.html#section-2.5)、[§3.1.2](https://www.rfc-editor.org/rfc/rfc8391.html#section-3.1.2)、[§5.1](https://www.rfc-editor.org/rfc/rfc8391.html#section-5.1)。

XMSS 公钥编码改为 `root || public_seed`。整个公钥继续由模型证书的 CA 签名或 X.509 叶证书扩展认证；验签取公钥后半段的种子和签名中的 index 计算链，最后将认证路径折叠结果与公钥前半段比较。签名仍为：

```text
index:u32 || wots_signature || wots_public_key || auth_path
```

## 不兼容变更与迁移

| 项目 | 原始 v6 | 本修订 |
|---|---|---|
| 默认公钥 | 32 字节根 | 64 字节，根 + 公开种子 |
| h=10 签名 | 4612 字节 | 4612 字节 |
| WOTS+ 签名/端点数组 | 各 2144 字节 | 各 2144 字节，但内容改变 |
| 内部方案编号 | `0x0E00 + height` | `0xFE00 + height` |
| 私钥持久化 | seed、参数、next_index | 增加 public_seed |
| 重建接口 | `keygen_from_seed(seed)` | `keygen_from_seed(seed, public_seed=...)` |

公钥字段增加 32 字节，证书、握手字节数和哈希链耗时必须重新测量。X.509 DER 长度编码和 ECDSA 签名长度也可能影响总量，不能断言整个握手固定只增 32 字节。

双方同时升级；为旧密钥生成全新密钥对并重新签发证书。不要给旧根拼接种子，也不要把旧私钥的 next_index 重置为零继续使用。旧 32 字节公钥直接拒绝，旧签名即使拼接一个公开种子也不能通过新链函数验证。原方案编号无兼容回退。

已使用本修订的密钥恢复时，必须同时恢复秘密 seed、public_seed、参数和最新的 next_index。`keygen_from_seed` 是确定性重建工具，仍从 index=0 初始化，调用者必须在签名前恢复最新计数器。生产状态持久化、进程间互斥和抗回滚仍由调用者负责。

## 验证与证据

`tests/test_u03_wots_context.py` 独立用 `hashlib` 与 `struct.pack` 实现参考计算，不调用生产地址、PRF、链函数或校验和辅助函数。测试覆盖：

- 两个种子、不同叶/链/绝对步号、key/mask 角色的隔离；零步与最大 u32 叶地址。
- 完整 WOTS+ 端点和签名与独立参考计算逐字节一致。
- 修改种子、叶地址、根或公钥后拒绝验签；缺失/畸形上下文被拒绝。
- 独立随机取样、共享 backend 的并发跨树签名、独立新进程仅凭公钥验签。
- 原始 v6 生成的旧签名拒绝，以及模型证书和 X.509 两种完整握手。

`tests/test_wots_xmss.py` 保留原有 24 项测试，更新接口和参考链计算，继续检查签名篡改、认证路径、缓存重建、耗尽和默认 h=10 的 30 秒预算。旧版确定性签名见 `tests/vectors/u03_legacy_v1.json`，注明来源。新参考计算是本地独立实现，不冒称官方发布的 XMSS 向量。

最终结果和命令见 `validation/README.md`、`validation/final-pytest.txt`；补丁作者合并前的测量在 `.bench-u03/`。

> **并入主树后的口径（v7）**：`tools/verify_all.ps1` 已在合并后的树上重新运行，因此 `.bench-out/handshake.*` 等文件是**本修订当前**的测量（XMSS 行：公钥 64 字节、h=10 签名 4612 字节、握手 7610 字节）。`.bench-u03/` 保留为合并前、另一台机器上的对照记录。先前那句"`.bench-out/` 是修复前历史记录"只对合并前成立。

## 并入记录（本仓库补写）

- 来源：协作者的 `hybrid-tls13-review-package-v6-u03-fixed.zip`，其 `U03_FIX.patch` 相对 v6 基线。
- 并入方式：文件级三方比对（v6 基线 / 本仓库当前 / 补丁版本），冲突为 0——补丁只触及 `tls/pq/` 两个文件、`tests/` 两个文件、8 份文档与新增的 `validation/`、`.bench-u03/`，这些文件在本仓库自 v6 之后未改动。
- 逐行审读：ADRS 布局（layer/tree/type 共 16 零字节 ‖ leaf ‖ chain ‖ hash=step ‖ keyAndMask）、`toByte(3,32)` 的 PRF 域、`toByte(0,32)` 的 F 域与 RFC 8391 §2.5/§3.1.2/§5.1 一致；链秘密的前缀派生（每叶独立）保持不变。
- 本仓库补的校验：secret seed 与 public_seed 不得重叠（V6-09）；`Certificate`/`X509Chain` 两种证书体的空上下文规则、会话 ID 长度上限等与本补丁无关，属同一轮的其它修复。
- 本仓库独立复核的数据：`public_key_bytes = 64`、`signature_bytes(h=10) = 4612`、`scheme_id = 0xFE00 + h`、随机密钥对签名可验、旧签名拒绝（`tests/vectors/u03_legacy_v1.json` 场景）。
- **仍未独立审查**：这次并入、以及本轮全部修复，都没有经过本仓库之外的第三方复核。补丁作者自己的验证记录在 `validation/`，那是同一位作者的记录，不构成独立审查。

## 结论边界及论文可用表述

本补丁修复全局固定链步密钥与缺失叶地址的设计偏离，并使默认参数的链计算对齐 RFC 8391。原型仍保留自定义链秘密派生、无 L-tree 的公钥压缩、无随机化树哈希、自定义消息摘要和编码；未完成整个 XMSS 的标准互通或形式化安全归约。非默认参数的回归通过也不是对应 RFC 参数集认证。

论文可写：

> 本实现以每棵树独立生成的公开随机种子和包含叶地址、链编号、步编号及角色标识的地址，分别派生 WOTS+ 链步密钥与位掩码；公开种子随公钥认证传输，消除了原实现跨树、跨叶共享固定链步密钥的偏离。默认参数的链函数已通过独立参考计算与回归测试。完整 XMSS 仍为研究原型，不据此声称标准互通或获得完整安全证明。
