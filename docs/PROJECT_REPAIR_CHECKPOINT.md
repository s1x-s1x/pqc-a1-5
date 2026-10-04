# 当前工程修补检查点

本轮修复朋友复审的 N01、B01/B02/B03、E01、T01，并补齐 CUDA 持续清理失败处置、CI、解析变异、环境重建配方及报告框架口径。实现与验收边界见 `FRIEND_REPAIR_20261004.md`。

正式 CPU/CUDA/网络性能样本为 **0**。用户已选择本轮先完成工程问题与验收；自验、冷热缓存、独立消融、峰值内存等额外性能入口留待下一阶段。完整会话形式化八场景十次超时、完成判决 0，继续按用户选择保留未完成。

## 验收范围

| 检查 | 结果与范围 |
|---|---|
| 当前 CPU 回归 | 21 步，含 fresh CPU build、故障、ASan/UBSan、adapter、账本、续跑、交付工具、TLS/live/锁与变异 |
| TLS 功能全集 | 524 passed、1 个 Windows DACL 专用 skip；1 个算法计时测试 deselected |
| CA/TLS 功能 | 11 步；两种 SLH 证书链各执行 native/Python 双验，ML-DSA provider 验链；P0–P4 实际序列化 |
| 续跑专项 | 42 个定义，41 通过、1 个 CUDA 不适用 setup_cache 行跳过；真实临时 SQLite、fake ABI、固定合成时钟 |
| 账本专项 | 扩展性15项、兼容12项通过；n=1..10000 的 VM 工作量控制，不测耗时 |
| Digest | 五算法 × 字符串/编号 = 10 个真实 toy 路径，消息/digest 签名相等、篡改及错误长度拒绝 |
| 输入变异 | 1008 个解析输入；1103 个真实 toy cache 损坏控制，原 live cache 保持 |
| CUDA | 新原生五步；7294个SM3比较、148个子树/WOTS比较、12个 pid201/pid2 完整签名/cache控制；backend5实际执行且event计时0 |
| CUDA 清理策略 | 17个host fake-driver控制；不声称真实driver持续故障已注入 |
| 新机器容器 | 固定基础镜像和系统快照下真实build/run通过；21步包含fresh CPU、fault、清理策略、ASan/UBSan、Falcon、TLS与交付工具；223份源码哈希与最终主机验收一致 |
| 历史继承 | 1048个历史受保护文件原字节保持；CPU release库与历史受验库SHA相同；GPU操作/kernel后缀原字节保持 |

本轮验收结果与最终字节闭包由 `validation/friend-repair-20261004/checkpoint.json` 和 `audit.json` 记录。只读复核：

```sh
python -B ops/audit_friend_repair.py --checkpoint validation/friend-repair-20261004/checkpoint.json --output review-fresh.json
```

该审计核对历史证据原字节、允许的源码差异、当前回归、真实 CUDA、CA/TLS 和新机器环境，不加载原生库、不产生性能样本。工程 delta checkpoint 不冒充新的完整 CPU/CUDA 矩阵或正式性能启动许可。

最终输入为主机回归 `friend-review-checks-20261004-r6`、CUDA `friend-cuda-native-20261004-r5`、功能验收 `friend-functional-20261004-r3`，以及 `build/friend-repair-20261004-r4/environment.json`。容器最终运行是 r6，r4 原失败记录保留；目录名仅是证据身份，不表示当前结论来自早期运行。

历史 `808d34c` 里 r3 的 CPU 3471/3471、CUDA 1789/1789 及原双冻结保持原身份，原检查点保存在 `history/PROJECT_REPAIR_CHECKPOINT_808d34c.md`。后续采样须新源码匹配的冻结包，旧包在当前入口哈希不匹配时继续拒绝。

此前独立 LaTeX 修订包已返还，基于 `808d34c`；本轮没有再次编辑该 ZIP。旧 Markdown 框架已同步并保留原稿。
