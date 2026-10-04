# GitHub 优化阶段交付

本仓库保存 CPU 与 CUDA 优化完成、正式性能测试开始前的项目快照。
当前状态见 `OPTIMIZATION_CHECKPOINT.md`，后续服务器运行入口见
`PERFORMANCE_START_READY.md`。历史 TLS 原型保留在 `base_tls/`。

## 克隆与交付检查

```sh
git clone https://github.com/s1x-s1x/pqc-a1-5.git
cd pqc-a1-5
```

仓库保存项目证据与系统依赖哈希；12 份系统编译器、运行库和 CUDA 头文件的原始字节
保留在本地交付目录，未公开分发。完整离线交付副本可以直接运行：

```sh
python ops/audit_optimization_delivery.py
```

全新克隆需先从具有相同文件版本的原验收 Linux 环境恢复系统依赖字节：

```sh
python ops/restore_optimization_external_evidence.py --source-root /
python ops/audit_optimization_delivery.py
```

也可用 `--ssh` 从原验收主机取回，需安装 `paramiko` 并在当前进程设置
`A15_JUMP_HOST`、`A15_JUMP_USER`、`A15_JUMP_PASSWORD`、`A15_TARGET_HOST`、
`A15_TARGET_USER`、`A15_TARGET_PASSWORD`。真实部署值只在本地配置。
恢复入口逐文件核对清单 SHA256，版本不同会报错，保留原始冻结记录。

Python 3.10 或更新版本即可执行标准库审计。完整副本正常结果为 `passed=true`，
19 项检查通过，真实原生调用及计时样本均为 0。该入口只核验交付字节，
Linux/CUDA 运行门禁仍以原始服务器环境和 readiness 记录为依据。

`.gitattributes` 关闭自动换行转换，保留冻结源码及证据的原始 SHA256。
`build/` 默认忽略临时构建；最终冻结引用的验收文件与发布库单独纳入版本管理，
使克隆副本可以重跑上述校验。冻结记录中的 Linux 绝对路径保持原始来源身份；
本地检查将其映射到仓库，外部工具字节由 `validation/optimization-external-evidence/manifest.json` 映射。

## 已验收范围

- 历史 CPU 完整矩阵 3471/3471，当前集成版 CPU 回归 948/948。
- CUDA 完整矩阵 1789/1789；GPU 执行 FORS，WOTS、消息及上层树在 CPU 执行。
- 两份最终冻结包、无计数器发布库、规范测试计划及项目引用证据已保存；系统依赖另有哈希与恢复入口。
- 正式性能测试尚未启动，实际计时样本为 0。

上游来源与许可证见 `THIRD_PARTY.md`；本次提交未另行指定项目整体许可证。
