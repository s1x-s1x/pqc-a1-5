# DP1：外部测试向量验收

服务器项目目录：`/home/guest-experiment/pqc-a1-5`。

本证据包服务于报告 §5.2–§5.4、§9.1 正确性汇总和附录 C。统一图表编号由项目 evidence contract 分配。

| 向量集 | 外部来源与覆盖 | 通过 | 失败 |
| --- | --- | ---: | ---: |
| A | NIST ACVP 固定镜像中的 SHA2-128s/128f：20 项密钥生成、104 项签名生成、84 项验签 | 208 | 0 |
| B | xous-core 的 SHA2-128-24 固定向量：完整公私钥、完整签名、验签各 1 项 | 3 | 0 |
| C | gmsm v0.44.1：每个 SM3-128s/128f 参数 10 组种子，完整密钥 10 项、确定性/随机化签名 20 项、正常验签 20 项、篡改拒绝 20 项 | 140 | 0 |
| 合计 | 原始逐例记录均已保留 | 351 | 0 |

向量集 A 的 208 项是两个 SHA2 参数的范围，区别于全部 12 个 FIPS 205 参数。包含 internal、external pure、external prehash，以及签名长度、消息、公钥等反例。预哈希 M′ 由独立的 Python 标准库按 FIPS 205 的 OID 与摘要规则编码，然后调用原生内部 API。A/B/C 这些校验不直接测试 C 的公共 pure-mode 包装函数。

向量集 B 原来的 verify-only 结果保留在 `validation/external-xous.json`。补充的完整复现在 `validation/external-xous-full.json`：从原始三个 16 字节种子得到完整 PK/SK，再使用原始 `opt_rand` 签名。输出签名的 SHA-256 与外部向量完全相同：`10975fa5d31e762cc437eaa13901603c2634453e8d655944d1aac103875c3772`。补充运行使用 reference backend、32 线程；记录中的耗时用于重现诊断，未按正式性能实验条件采集。

向量集 C 由未经修改的 gmsm 生成，其输入以固定命名域和 SHA-512 产生。每个种子有确定性签名和指定随机数的随机化签名；上下文覆盖 0、1、16、32、255 字节，随机数包含全 0、全 FF 和一般字节。比较完整的 32 字节 PK、64 字节 SK 和完整签名。gmsm 的公开接口拒绝空消息，因此 C 的消息至少 1 字节。每份外部签名还在 gmsm 内自验后输出。

来源固定为：

- ACVP 镜像 `mjosaarinen/py-acvp-pqc`：`1c859956c0217b04fa5ae76e338e5570aba622c5`。
- xous-core：`f239b847d9d864d7ee19651a7d29acd4f7104921`，与 PR #1002 的新增参数向量关联；固定此具体提交，并未把 PR 的最终 merge commit 当作此向量提交。
- gmsm v0.44.1：`84294d95666c7b628a45896b2ab068081591ef27`。

已对 A/B 所用 15 个来源文件核对固定提交的 Git blob ID。9 个 ACVP JSON 在本地检出时使用 CRLF，转为 LF 后与固定提交逐字节相同；6 个 xous 文件原始字节直接匹配。测试输入保持原样，没有通过更换预期值消除差异。源检查同时记录原始 SHA-256、LF 规范化 SHA-256、原始 Git blob ID 和期望 Git blob ID。gmsm 的归档、源树逐文件哈希、Go 运行时归档哈希另在 `third_party/external_vectors/GMSM_SOURCE.json` 保留。

全部结果对应原生共享库 SHA-256：`b4ea1ead5bd9db46d617a1a51071dc9eb675533ec102021ef1b85f1cf5685083`。本轮直接保存先前已经完成的 A/C/B 验签结果，仅对 B 新增完整密钥和签名复现；未重建共享库。

`validation/external-EVIDENCE.json` 是总清单，给出成功/失败数、源提交、共享库哈希和以下文件的哈希：

- `vectors/external-{acvp,xous,gmsm}-inputs.jsonl`：逐例原始输入与预期输出。
- `validation/external-{acvp,xous,gmsm}-results.jsonl`：逐例执行结果、时间、库哈希、唯一 case_id。
- `validation/external-{acvp,gmsm,xous-full}.json`：原始执行汇总。

JSONL 的执行时间来自原始结果，导出时间另在总清单记录。固定向量通过是功能一致性证据，其范围不包含完整安全证明、正式认证、CUDA/AVX2 加速路径或全部参数组。
