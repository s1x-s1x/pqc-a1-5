# GitHub 修复版交付

当前工程修复、当前源码完整正确性、CA/TLS功能、干净复现与新CPU/CUDA冻结已完成，详见 `PROJECT_REPAIR_CHECKPOINT.md`。
完整会话形式化搜索按用户选择保留未完成，原始模型/首次输出/超时记录随源码保存。正式CPU/CUDA/网络性能样本0，论文和LaTeX未修改。

## 克隆与只读复核

```sh
git clone https://github.com/s1x-s1x/pqc-a1-5.git
cd pqc-a1-5
python ops/restore_optimization_external_evidence.py --source-root / --manifest validation/repair-external-evidence-r3-manifest.json
python ops/audit_project_repair.py
```

第一条复核步骤应在原验收环境或具有逐字节匹配依赖的Linux环境执行。修复版清单包含 12 份系统编译器/运行库/CUDA头文件原字节，保存哈希、大小和原路径。
系统文件保留在完整本地交付副本，GitHub只分发其清单。全新克隆依赖版本不同会报错，不覆盖原冻结。
也可用 `--ssh --manifest validation/repair-external-evidence-r3-manifest.json` 从原验收主机恢复；安装paramiko，连接设置经当前进程的 `A15_JUMP_*`/`A15_TARGET_*`环境变量提供。
真实连接凭据只保存在本地，未提交。

完整本地副本可以直接执行 `python ops/audit_project_repair.py`。该入口只读当前源码、归档和证据，内含新双冻结19项交付审计；它不重新加载原生库、不跑GPU、不产生性能样本。
Linux执行能力仍由服务器 readiness及绑定版本日志证明。

## 功能重建

在匹配的Linux依赖环境中安装 `base_tls/requirements.lock.txt` 的锁定主依赖，Falcon使用匹配Python ABI的单独target：

```sh
/实际匹配解释器 tools/install_falcon_provider.py
/实际匹配解释器 tools/reproduce_project.py --fixtures build/repair-staging-20261004-r3/validation/real-alt-fixtures-repair-r3-parallel2 --output validation/fresh-clean-reproduction
```

复现脚本只做干净源码复制、fresh release build/repair专项、真实profile/严格负例与ABI边界。Python独立参考依赖 `third_party/py-acvp-pqc`，已纳入复制。
公开夹具中的 `*-test-key.pem` 与向量种子是这次新建的测试材料；用于重放演示，均不用于真实服务。Falcon provider是已锁定的独立依赖，不复用项目旧构建产物。

## 证据路径和历史

修复版镜像在 `build/repair-staging-20261004-r3`；只显式纳入新验收、新库、新冻结、公开测试夹具、演示与最终绑定数据，重建cache及本地连接adapter保持忽略。
CPU矩阵采用串行前缀及独立进程补齐，完整3471计划与七档线程保留。私有缓存、共享账本、原始工作进程记录、逐行合并来源和独立结算快照均随交付保存，原串行未完成记录单独留存；项目审计核对该并行证据闭包。
冻结里的Linux绝对路径保留原始来源身份；审计把它们映射到上述镜像，系统原字节映射到 `validation/optimization-external-evidence`。
`.gitattributes`保留原换行字节以保持SHA256。

历史双冻结、历史完整矩阵及 `validation/optimization-final-readiness.json` 保留原样。历史19项复核使用基线提交 `23947a2c9a336ece46ea7fae3dcd83e1fbbc6391` 的源码副本、默认 `ops/audit_optimization_delivery.py` 与默认系统manifest；当前源码已经修复，不能与旧冻结混配。
后续性能测试范围见 `PERFORMANCE_SCOPE_REPAIR.md`。论文修改和正式采样仍是后续阶段。
第三方来源/许可证见 `THIRD_PARTY.md`；项目整体未另行指定许可证。
