# 朋友复审修补与验收

基线为 `808d34c938725cf9b1edb7b2452d550afa396455`。本轮按用户授权修复工程问题并推送，正式 CPU、CUDA、网络性能样本保持 **0**。额外性能采样入口按用户最新选择留待下一阶段。完整会话形式化搜索继续保留此前接受的未完成状态：八个完整场景、十次调用超时、完整判决 0。

## 已落实的修改

| 编号 | 修改后的行为 | 验收方法 |
|---|---|---|
| N01 | 五种预哈希摘要长度统一为 32/64/32/64/32 字节；有 ABI 长度查询时核对契约 | 模拟 ABI 的字符串/编号及邻近长度控制；真实 toy 参数五算法十路径的消息/digest 签名对照、篡改拒绝 |
| B01 | 每个新执行段在剩余样本前重新完成计划预热并收费；已通过样本保留 | 真实临时 SQLite、假 ABI、固定合成时钟；预热/样本中断、失败、零预热与只缺汇总控制 |
| B02 | 整个 campaign 先审计收据归属；操作开始/结果/完成绑定计划、执行段、环境、库和源码；当前段有 pending/failed/unready 时拒绝完成 | CPU/CUDA 篡改矩阵、跨 case 复用、合法 fixture 引用、预约及结算后崩溃、KeyboardInterrupt；独立复现确认补强 |
| B03 | 事务内增量计数和写入 guards；启动/显式 audit 完整核对历史；单次/批次回执校验避免重复 COUNT 历史 | 迁移、失败收费、双实例并发、2^64 TEXT、直接写入及损坏拒绝；SQLite VM 指令计数 |
| E01 | CA 主异常保留，失败 finalizer 的次级异常附在 note；收费保留 | 主失败与 finalizer 同时失败、成功路径 finalizer 失败等控制 |
| T01 | 整轮握手限制记录数、明文/密文累计字节和审计条目；header 校验后复制 body；失败后终止 receiver 并撤下可用密钥 | 阈值边界、细碎/跨消息分片、长 DER 正例、错误后再次调用拒绝 |
| CUDA 清理 | explicit 与析构统一 checked wipe→sync→free；持续失败保留 allocation，进程内停用后续 GPU 操作；原主错误优先 | 17 个主机模拟驱动故障控制；修补后的真实 CUDA 构建、kernel、既有故障、禁用/隐藏设备与发布检查 |

默认 flight 上限为 4096 records、4 MiB 明文、5 MiB 密文、4096 audit entries；四个参数必须是正整数，拒绝 bool。原配置字段位置保持，新增字段位于既有 `extra` 后。阈值是原型资源目标，模拟驱动检查只证明清理策略，不构成真实驱动持续故障注入或硬件秘密擦除证明。

账本保留 UUID、回执与全部历史收费；schema 3 迁移在事务内执行。普通写连接缺少内部写入模式，触发器拒绝修改。完整 audit 检查内部历史，日常操作校验本次回执、计数和序号端点。主动重写整套数据库、备份回滚、独立副本和直接 C 入口仍需要外部一致性治理。

## 持续维护与材料

- 新增固定种子 DER/握手解析变异、receiver 状态检查和真实 toy cache 损坏拒绝入口；可选 Atheris。固定次数 smoke 不声称穷尽输入空间。
- 新增 Linux CPU CI，锁定 GitHub Action 提交、Python 主依赖/参考依赖/Falcon release artifacts，包含原生、回归及 sanitizer。远端 CI 状态以实际运行记录为准。
- 新增固定官方 Python 镜像 digest、Debian snapshot 与 Python hash locks 的新机器容器配方。基础镜像离线获取核验每层压缩 SHA256、解压 diff_id 和 config 身份，不改服务器 Docker 全局配置。
- 容器最终build/run与21步验收通过，包含实际sanitizer和Falcon检查；223份源码哈希与最终主机回归一致。registry、DNS和缺少git的首次失败记录保留，最终配方已安装交付检查需要的git。
- 旧报告框架同步当前安全、计数和未完成口径，原字节保存在 `docs/history/`。项目整体许可待作者选定，见 `LICENSE_STATUS.md`。
- NVCC 自动生成的 C++ 中间文件继续作为证据保留，并标注 `linguist-generated`，GitHub 语言比例据此重新统计。

## 版本与证据边界

历史 r3 完整 CPU 3471/3471、CUDA 1789/1789、库、向量、原始行、日志及冻结包保持原字节。本轮受影响工具、TLS 与 CUDA owner 有新验收；新结论以最终 checkpoint 的当前源码/库/日志哈希为准。旧完整矩阵没有被重新标为新版本完整矩阵。

CPU 密码 C translation units 未改，新构建 release 库与历史 r3 release 字节身份另行核对；CUDA 从 `struct kernel_clock` 到文件末尾的原操作/kernel 字节与归档相同，owner 前缀有本轮清理修补并执行新验收。这些比较用于界定继承范围，不把旧全源码 hash 改成新源码。

工程验收快照与正式采样冻结分列。旧正式冻结对新工具哈希不匹配是预期的拒绝行为，工程 checkpoint 不绕过它。后续正式采样前须针对最终源码重新发布所需采样冻结并只读核对，仍需新的启动指令。

此前返还的 LaTeX ZIP 基于 `808d34c`，SHA256 `cf44a97f5340ef916ceeb5f642cf578a32a61853be6e4606a6cf62e728785da1`；本轮工程修补未覆盖该历史 ZIP。生产 PKI/TLS、Windows 生产 DLL、多机限额治理和物理侧信道测量仍为已披露范围，不作为本轮新功能承诺。

最终结果、复核命令与证据入口见 `PROJECT_REPAIR_CHECKPOINT.md` 和 `GITHUB_HANDOFF.md`。上述通过结论限于版本绑定的检查范围。
