# 修复运行历史

原始记录保留在各自目录，逐文件 SHA256 清单见 `validation/repair-history-20261004.json`。这里的状态只描述对应运行，最终修复版验收引用 `PROJECT_REPAIR_CHECKPOINT.md` 中的 r3 证据。

| 记录 | 原始状态 | 最终交付的处理 |
|---|---|---|
| r1 native | `passed=false`；最后完整登记到 sanitizer，后续运行中断 | 保存 manifest、已生成日志和数据；不计作完整通过 |
| r1 functional-core | `bench_cpu-mock` 返回 2，命令参数与工具入口不匹配 | 保存首次失败；更正 runner 后采用 r3 final3 |
| r2 native | `passed=false`；最后完整登记到 portable，后续运行中断 | 保存 manifest 与日志；不计作完整通过 |
| r3 首次 clean reproduction | 真实 profile 步骤失败，日志表现为 alt 验证失败；干净源码复制遗漏 Python 独立参考依赖 | 保存错误日志；补齐 third_party 复制后采用 clean-final2 |
| r3 早期 functional 与 clean 重跑 | 部分检查已通过，但工具源码随后更新 | 保存各自受测哈希；最终版本使用 final3 与 clean-final2 |
| 离线打包工具新增正例 | Windows 临时解包路径过长，首次回归 18/19 通过 | 保留首次 JSON/log；改用短系统临时根后回归 19/19，通过记录在 `validation/repair-delivery-tools-20261004` |
| r3 CPU 串行验收交接 | 原 `summary.json` 保持 `final=false`；3359/3471 项通过，4128 条原始记录 | 保存串行历史，剩余 112 项分 39 组补跑；最终合并为 3471/3471，通过记录共 4433 条 |
| r3 CUDA 首次 full 启动参数 | 有 GPU 环境误带 `--require-cuda-absent`，运行的是 8 项缺席后端计划；首项失败，`passed=false` | 保存 `cuda-full-repair-r3-absence-flag-history` 原始 manifest、summary 与 cases；更正参数后 full 计划 1789/1789 通过 |
| r3 前两次本地交付复核 | CPU/CUDA 与功能检查通过，双冻结检查因本地镜像缺少计划、环境及受测源码附件失败 | 保存 `project-audit-first-mirror-incomplete.json` 与 `project-audit-second-mirror-incomplete.json`；按冻结闭包回收原件并核验 SHA256，再执行最终门禁 |
| 完整会话形式化 v2 | 八个完整场景、十次调用全部超时，完成安全判决为 0 | 按用户选择保留未完成项交付；详见 `CA_MODELS_V2_20261004.md` |

CPU 交接先使用 `SIGSTOP` 暂停原进程并保存完整 JSONL 行的稳定快照，再发送 `SIGTERM` 与 `SIGCONT` 完成外部中断；继承 `nohup` 的进程忽略 `SIGINT`。`cpu-full-repair-r3-serial-history` 的三份原始文件保留原始字节与 `final=false`，控制器生成的 `parallel-correctness-r3/serial-snapshot` 单独标记外部中断。中断时在途签名收据为空；分组输出、日志、调度、预算结算与原始来源副本均保留在 `parallel-correctness-r3` 和最终 CPU run 的 provenance 中。

旧记录中的 `diagnostic_seconds` 是验收流程的诊断字段，不属于正式 CPU/CUDA/网络性能样本。本轮正式性能样本保持 0，论文与 LaTeX 未修改。

r1/r2 路径为 `build/repair-staging-20261004-r1/validation` 与 `build/repair-staging-20261004-r2/validation`。r3 历史清单保存当时的 manifest、日志及结构化输出，不把已过时的源码哈希解释成当前源码验收。
