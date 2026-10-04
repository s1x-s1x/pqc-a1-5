# CA/TLS 当前协议与字节口径

2026-10-04。本项目是自包含私有TLS形状harness；既有逐字节说明见
`../base_tls/docs/PROTOCOL.md`。以下补充修复后的实际行为，不表示标准TLS互通。

握手转录按完整 `type:uint8 || length:uint24 || body` 消息更新。服务端先形成完整
消息，再按内容不超过16384 B分片成保护记录。客户端增量拼接，可跨记录握手头、
跨多记录证书和同记录多消息；按消息状态读到并认证Finished后切换应用密钥。
TCP依据Finished状态接收flight，记录序号随记录推进。超长内容/密文、截断、乱序、
篡改及额外记录有功能负例。

| 字节对象 | 定义 |
|---|---|
| DER | 实际证书DER文件字节与逐文件SHA256 |
| 握手消息 | 完整4 B握手头加body，各消息恰好一次 |
| bare harness record | 加密记录content+1 B内层类型+16 Btag，无标准5 B头 |
| 私有TCP framing | 每次发送的record/message额外4 B长度前缀 |
| 标准TLS模型 | 对应内容保护另加5 B标准record头，仅尺寸模型 |
| TCP/IP、initcwnd | 实测尚未开始，值保持null/未测 |

因此17 B是加密输出增量，21 B是私有TCP加密帧增量，22 B是无padding标准TLS
模型增量。分片后开销逐记录累计。E1 v2分列这些对象，实际字节不和模型混算。

CA alt扩展为2.5.29.72/73/74，实验SM3算法使用测试OID。preTBS移除外层TBS signature
及altSignatureValue，保留其余经严格DER编码的被绑定字段。客户端从已验链的证书
获取在线公钥，本地根与策略不从可替换网络项建立。严格策略要求完整alt材料；兼容
策略行为、降级拒绝和错误归属在功能测试记录。每边验签输出实际mode/backend/
库SHA256与消息/公钥/签名摘要；强制native缺库直接失败。

P0禁用PQ KEM及在线PQ签名，不创建这些provider；P1使用经典CA加混合握手；P2/P3/P4
分别使用128-24、128s、ML-DSA44离线alt CA夹具，在线算法单独固定。真实夹具生成
独立于普通握手回归，预算预约/完成及manifest保存后再使用，回归不重复签发128-24。
