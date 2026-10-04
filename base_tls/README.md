> **v9 更新（第八轮红队审查）**：先读 [docs/AUDIT_V8_RESPONSE.md](docs/AUDIT_V8_RESPONSE.md) 与
> [docs/CAPABILITIES.md](docs/CAPABILITIES.md)；本轮验证与环境记录在 [`validation/README.md`](validation/README.md)
> 的「v9 验收与环境记录」一节，两套审计复跑（原用例兼容＋修订严格）在 `../02-审查记录/06-v8审计/audit_v9/`。

> v8 更新：先读 docs/AUDIT_V7_RESPONSE.md；v8 验证记录在上一级 `validation/`。

> **2026-09-21 U-03 修订 / 2026-09-22 第五轮审查修订**：WOTS+ 改用每树新生成的公开种子和完整链地址，加入独立 bitmask；XMSS 公钥为 64 字节，默认签名仍为 4612 字节，方案编号改为 `0xFE00 + height`。新旧密钥不兼容，需换钥、重签证书并同时升级双方。见 [修复说明](docs/U03_WOTS_STEP_KEYS.md) 和 [本轮验证](validation/README.md)。第五轮审查的十项修复见 [AUDIT_V6_RESPONSE.md](docs/AUDIT_V6_RESPONSE.md)；`tools\verify_all.ps1` 已在合并后的树上重跑，因此 `.bench-out/` 是**当前**测量，`.bench-u03/` 是补丁作者的合并前对照记录。

# hybrid-tls13

混合 TLS 1.3 握手实现：**ECDHE + 后量子 KEM 双路密钥协商**，**传统签名 + 后量子签名双路认证**，两者合入同一个 TLS 1.3 HKDF Key Schedule，**不增加握手往返**。

这个实现的目标是把那份设计笔记变成可运行、可测量、可证伪的代码：协议自洽（自带客户端与服务器），不做线格互通，也不假装解决了后量子 PKI 迁移。

## 文档地图

| 文档 | 内容 |
| --- | --- |
| `docs/PROTOCOL.md` | 字节级线格式规范，每个数字都能用 `tools\dump_wire.py` 复核 |
| `docs/CAPABILITIES.md` | **能力矩阵**：已实现且已验证／已实现未独立验证／明确未实现（引数字前先读） |
| `docs/SECURITY.md` | 声明 C1–C6、假设、**以及 15 条"未建立"**（含第五、第八轮审查后的残余项） |
| `docs/REDUCTION.md` | 归约骨架：定理陈述、9 条假设、game hops、**以及 §6 里 9 条未证事项** |
| `docs/HANDOVER.md` | **给外部复核者的任务书**：三项任务、各自验收标准、环境、汇报格式、不该继承的偏见 |
| `verification/tamarin/` | Tamarin 骨架（**从未被解析过**，且把 KEM 表示法的选择留给人来做） |
| `verification/verifpal/README.md` | 符号模型、结果码、对照组的含义与边界 |
| `rust-prototype/README.md` | 真实 rustls 内的混合密钥协商结果与环境说明 |
| `implement-stage/` | 假设账本（53 条）与构建记录（24 个 rung、全部失败根因） |

**一句话概括可靠性**：能跑的都在 `tools\verify_all.ps1` 里（35 项）；不能跑的都写明为什么不能跑（本机没有可用的 Tamarin/ProVerif、没有第二个模型族做独立复核）。

## 设计要点

| 位置 | 传统支路 | 后量子支路 | 合入方式 |
| --- | --- | --- | --- |
| 密钥协商 | X25519 ECDHE（`key_share`） | ML-KEM-768（`pq_key_share` 扩展） | `Z_hybrid = uint16(len)‖Z_ecdh‖uint16(len)‖ss_pq` 送入 `HKDF-Extract` 得 `handshake_secret` |
| 服务器认证 | ECDSA P-256（Certificate 中的经典公钥） | Falcon-512（或 ML-DSA / WOTS+/XMSS） | 两份签名覆盖**同一个** `M_CV`，客户端要求 `ok_classic && ok_pq` |
| 握手完整性 | Finished（`HMAC(finished_key, TH)`） | 同左 | transcript 覆盖 qpk、ct、双公钥、双签名，删掉任一 PQ 字段都会导致 Finished 失败 |

`M_CV = 0x20 × 64 ‖ "TLS 1.3, server CertificateVerify" ‖ 0x00 ‖ TH_S`，由传统的**和**后量子的签名同时覆盖——这正是"两份签名签同一条连接"的落地方式。

## 目录

```
tls/
  wire.py                     TLS 风格编解码（u8/u16/u24、vec8/16/24、握手帧）
  metrics.py                  计时与字节记账
  config.py                   配置：每个槽位选哪个后端
  credentials.py              测试 CA 与混合证书签发/验证
  key_schedule/hkdf.py        HKDF、HKDF-Expand-Label、Derive-Secret、混合密钥树
  classical/ecdh.py           X25519 / secp256r1 临时密钥交换
  classical/signature.py      ECDSA P-256、Ed25519
  pq/backends.py              KemBackend / PqSigner 协议
  pq/kem.py                   ML-KEM 512/768/1024、HQC、ECIES 占位 KEM
  pq/signature.py             Falcon 512/1024、ML-DSA 44/65/87、XMSS 包装
  pq/wots_xmss.py             纯 Python WOTS+ 与 XMSS（无第三方依赖）
  pq/providers.py             定位 .deps / .deps-falcon 依赖目录
  record/aead.py              AES-GCM 记录层（nonce = IV ⊕ seq，AAD = 记录头）
  transport/tcp.py            回环 TCP 传输：真实 socket + 在线数往返次数
  handshake/messages.py       六个握手消息的编解码
  handshake/transcript.py     transcript 哈希
  handshake/certificate_verify.py  M_CV 构造与混合验证负载
  handshake/state.py          两个角色共用的密钥派生与记录层状态
  handshake/client.py         客户端状态机（含 19 步验证顺序）
  handshake/server.py         服务器状态机
  handshake/connection.py     端到端驱动 + 字节记账
demo/run_handshake.py         跑一次握手并打印全部中间值；--tamper 演示拒绝路径
bench/measure_primitives.py   KEM 与签名原语计时、尺寸
bench/measure_handshake.py    握手字节数与延迟矩阵（进程内）
bench/measure_tcp.py          回环 TCP：往返次数观测 + 传输开销
tests/                        pytest 套件（393 项）
tools/verify_all.ps1          一键总验收：后端清单 / 5 个 profile / 4 条篡改 / pytest / 三个基准
tools/bootstrap_env.ps1       装 .deps
tools/install_falcon_provider.ps1  装 Falcon 提供方并重命名为 pqcrypto_pqclean
tools/probe_pq.py             枚举本机真正可导入的后量子算法与尺寸
tools/sandbox_pyfix/          沙箱兼容修补（见下）
```

## 快速开始
```powershell
cd D:\新建文件夹\TLS_deepseek实现\hybrid-tls13

# 一次握手 + 全部中间值
python demo\run_handshake.py

# 换后量子签名后端
python demo\run_handshake.py --pq xmss --xmss-height 10
python demo\run_handshake.py --pq ml-dsa-44
python demo\run_handshake.py --kem ml-kem-1024 --pq falcon-1024

# 列出本机可用的后端
python demo\run_handshake.py --list-backends

# 篡改任一字段，看在哪一步被拒
python demo\run_handshake.py --tamper pq-signature
python demo\run_handshake.py --tamper classic-signature
python demo\run_handshake.py --tamper certificate
python demo\run_handshake.py --tamper kem-ciphertext

# 测量
python bench\measure_primitives.py --iterations 50 --xmss-height 8
python bench\measure_handshake.py --repeats 10
python bench\measure_tcp.py --repeats 10

# 一键总验收（后端 / 握手 / 篡改 / 测试 / 三个基准）
powershell -File tools\verify_all.ps1
```

结果写到 `.bench-out/`（JSON + Markdown 表格）。

## 环境

依赖装在**项目内**（`.deps`、`.deps-falcon`），不写全局 site-packages：

| 依赖 | 用途 |
| --- | --- |
| `cryptography` | X25519/P-256 ECDHE、ECDSA/Ed25519、AES-GCM |
| `pqcrypto` 1.0.0 | ML-KEM 512/768/1024、HQC、ML-DSA 44/65/87 |
| `pqcrypto` 0.4.0（PQClean 版） | **Falcon 512/1024**（1.0.0 不含 Falcon） |
| `pytest` | 测试 |
| `numpy` / `matplotlib` | 可选，画图用 |

两个 `pqcrypto` 版本共享同一个顶层包名，因此 0.4.0 被重命名安装为 `pqcrypto_pqclean`，只按需追加到 `sys.path` 末尾，绝不会遮蔽 1.0.0 的 ML-KEM / ML-DSA。

```powershell
powershell -File tools\bootstrap_env.ps1            # 装 .deps
powershell -File tools\install_falcon_provider.ps1  # 装并重命名 Falcon 提供方
```

### 沙箱注意事项（本机特有）

本项目的开发环境由 DSH 文件沙箱保护：写入只允许落在工作区内，而沙箱通过 **capability SID**（`S-1-4-...`）授权。CPython 的 `os.mkdir(path, 0o700)`——也就是 `tempfile.mkdtemp` 内部用的模式——在 Windows 上会写一个**只授权 owner** 的 DACL，于是刚建出来的目录连列目录都失败，pip 和 pytest 因此全线报 `PermissionError`。

`tools/sandbox_pyfix/sitecustomize.py` 把 `os.mkdir` 的 mode 强制为默认值，让新目录继承父目录的 ACE。运行 pip / pytest 时把它放进 `PYTHONPATH`：

```powershell
$env:PYTHONPATH="D:\新建文件夹\TLS_deepseek实现\hybrid-tls13\tools\sandbox_pyfix"
```

在不受该沙箱约束的机器上，这个修补是惰性无害的（只会让临时目录权限更宽松），也可以整段删除。

留作证据：`.dsh\_tmp\probeB` 与同级的 `pip-build-tracker-*` / `pip-unpack-*` 等目录是在修补生效**之前**创建的，因此带着那份不可遍历的 DACL——沙箱下连 `rmdir` 都被拒绝。它们无法在沙箱内删除，正好是上述根因的物理证据；有管理员权限时执行
`takeown /f .dsh\_tmp /r` 后即可正常清理。

## 测量口径

- **原始操作**：KEM KeyGen/Encap/Decap、签名 Sign/Verify，各重复 N 次取中位数（首次调用作为预热，仅当 N>3 时剔除）。
- **握手字节**：按消息分别统计"握手帧字节"与"记录保护字节（tag + 5 字节记录头）"，不合并成一个总数。
- **后量子增量**：`ΔCH ≈ |qpk| + 扩展开销`、`ΔSH ≈ |ct| + 扩展开销`、`ΔCert ≈ |PK_PQ| + 帧开销`、`ΔCV ≈ |sig_PQ| + 帧开销`，从**实测消息**里分解出来，而不是再跑一遍经典握手。
- **延迟**：两个口径并列。`stage_ms.*` 与进程内 `handshake_ms` 只含密码学与 KDF，用于隔离后量子开销；`bench/measure_tcp.py` 走**真实回环 socket**，含内核拷贝、帧封装与线程切换，并**在线数出客户端阻塞等待次数**：`waits_to_authenticated = [1]` 就是"握手仍然只需 1 个往返"这一论断的观测证据（客户端只阻塞一次，就拿到了 ServerHello 与整个已认证的服务器 flight）。回环 TCP 的绝对毫秒数主要反映 harness（accept + 线程唤醒），不代表真实网络。

⚠️ **证书是极简结构**：只有一个身份串 + 两把公钥 + CA 签名，没有 X.509 链、没有扩展协商、没有中间 CA。所以**绝对总字节数不能与真实 TLS 栈对比**；可迁移的是每个字段的增量与逐消息分解。

## 后端支持矩阵

| 后端 | 类型 | 公钥 | 签名/密文 | 可用性 |
| --- | --- | --- | --- | --- |
| `ml-kem-512/768/1024` | KEM | 800/1184/1568 | 768/1088/1568 | ✅ |
| `hqc-128/192/256` | KEM（码基） | 2241/4514/7237 | 4433/8978/14421 | ✅ |
| `ecdh-kem-placeholder` | **非后量子**占位 | 32 | 32 | ✅（`post_quantum=False`） |
| `falcon-512/1024`, `falcon-padded-*` | 格签名 | 897/1793 | 652/1272 | ✅ 需 Falcon 提供方 |
| `ml-dsa-44/65/87` | 模格签名 | 1312/1952/2592 | 2420/3309/4627 | ✅ |
| `xmss`（WOTS+/Merkle） | 哈希签名 | 64 | ~4612（h=10） | ✅ 纯 Python |

**XMSS 是有状态的**：每次签名消耗一个叶子，叶子用尽抛错。`XmssSecretKey` 的秘密 `seed`、公开 `public_seed`、参数与最新 `next_index` 必须持久化，其中计数器必须原子持久化，回滚到旧状态会直接破坏 WOTS+ 的安全性——这是协议级属性，不隐藏在实现里。

## 已知边界

- **不做线格互通**：`pq_key_share` / `pq_ciphertext` 是私有扩展类型，没有对应的标准，因此无法与 OpenSSL/BoringSSL 对话。要互通需要把它落到某个 provider 与具体 draft。
- **PKI 迁移不在范围内**：CA 是测试 CA，只证明"服务器需要发布什么、客户端需要验证什么"，不涉及后量子 X.509 层级运营。
- **没有形式化安全证明**：只实现了设计笔记声明的性质（混合密钥协商、双签名合取、transcript 绑定、前向安全由临时密钥提供），并用篡改测试逐一验证其可观测后果。
- **`ecdh-kem-placeholder` 不是后量子后端**，仅用于在缺少 PQ 库时保持协议骨架可运行；它显式报告 `post_quantum = False`。
