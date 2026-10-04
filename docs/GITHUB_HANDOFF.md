# 当前工程交付与复核

最新修补见 `FRIEND_REPAIR_20261004.md`，当前证据入口见 `PROJECT_REPAIR_CHECKPOINT.md`。正式 CPU/CUDA/网络性能样本为 0，完整会话形式化继续保留未完成；此前独立 LaTeX 修订包基于 `808d34c`，本轮不再覆盖。

## 新机器重建

`ops/repro/README.md` 提供固定镜像、系统快照、主依赖/参考/Falcon release hash locks 的新机器 CPU 正确性路线。它产生新的环境和构建证据，不要求重建历史 Linux/CUDA 原始二进制身份。CI 同样执行正确性与合成控制，不启动正式性能 worker。

```sh
git clone https://github.com/s1x-s1x/pqc-a1-5.git
cd pqc-a1-5
docker build -f ops/repro/Dockerfile -t a15-correctness .
docker run --rm a15-correctness
```

当前工程证据副本可只读核对：

```sh
python -B ops/audit_friend_repair.py --checkpoint validation/friend-repair-20261004/checkpoint.json --output review-fresh.json
```

该复核还校验历史证据保持。GitHub 只分发原验收环境 12 份系统文件的清单；全新机器恢复历史原字节时仍需以下入口，原字节缺失会明确失败。当前新机器构建验收与历史字节身份复核分开列结果。

```sh
python ops/restore_optimization_external_evidence.py --source-root / --manifest validation/repair-external-evidence-r3-manifest.json
```

匹配的系统原字节已保存于完整本地副本。可在原验收环境恢复，或用 `--ssh` 与当前进程 `A15_JUMP_*` / `A15_TARGET_*` 连接设置；真实连接数据仅在本地，未纳入交付。

旧源码完整复核应在 `808d34c` checkout 与原依赖身份下运行 `ops/audit_project_repair.py`。当前源码有新修补，旧冻结的 hash gate 保持生效，旧审计不代替最新 delta 审计；此前详细交接原字节保存在 `history/GITHUB_HANDOFF_808d34c.md`。

公开 CA 夹具的 test-key 与向量种子只用于回放测试。第三方来源和许可见 `THIRD_PARTY.md`，项目整体许可状态见 `LICENSE_STATUS.md`。新增工程证据保留第一次失败与重跑日志，当前通过只认最终 checkpoint 的版本绑定记录。
