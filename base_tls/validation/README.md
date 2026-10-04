> 历史 U-03 记录，原样保留；v8 验证见 ../../validation/（上一级目录）。
>
> **v9 记录见本文件末尾的「v9 验收与环境记录」一节**：作者侧与"独立风格"两套环境清单、
> 两套审计复跑结果（原用例兼容＋修订严格）、生命周期测量与 Sweep 探针结果。

# U-03 验证记录（2026-09-21）

修复基于原始 v6 压缩包的独立副本，原附件未修改。

| 检查 | 结果 | 原始记录 |
|---|---|---|
| 原始 v6，主依赖已安装、Falcon 未安装 | 272 passed, 1 skipped，11.60 s | baseline-pytest.txt |
| 修复后完整测试，含 Falcon | **305 passed, 0 skipped，27.17 s** | final-pytest.txt |
| 新增 U-03 回归 | 31 个用例，含参数展开；已纳入完整测试 | tests/test_u03_wots_context.py |
| 原 WOTS+/XMSS 回归 | 原 24 项全部保留、更新后通过 | tests/test_wots_xmss.py |
| 检查函数可达性 | 85 个定义；0 tests-only、0 unattributed、0 dead；PASS | live-checks.txt |
| 原语尺寸与耗时 | 公钥 64 B，h=10 签名 4612 B | primitives.txt、../.bench-u03/primitives.json |
| X.509 完整握手测量 | 全部 ok=True；XMSS 2 次，另含经典基线及 Falcon 对照 | handshake.txt、../.bench-u03/handshake.json |

环境：Windows 11 x64、Python 3.12.10。主依赖按原 requirements.lock.txt 的版本和哈希安装；Falcon 用原 requirements-falcon.lock.txt 安装 pqcrypto 0.4.0 并按原项目方法复制为 pqcrypto_pqclean。

Falcon 单独安装时使用 `--no-deps`，因为其锁文件未锁传递依赖，而 cffi/pycparser 已由主锁文件安装。未修改锁文件、未跳过包哈希校验。测试基线和最终环境的 Falcon 可用性不同，因此总用例数变化不只来自新增用例。

## 复现命令

在 `project/` 下，用隔离虚拟环境执行（PowerShell）：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements.lock.txt
.\.venv\Scripts\python.exe -m pip install --no-deps --require-hashes --target .deps-falcon -r requirements-falcon.lock.txt
Copy-Item -LiteralPath .deps-falcon\pqcrypto -Destination .deps-falcon\pqcrypto_pqclean -Recurse
.\.venv\Scripts\python.exe -m pytest -q --tb=short
.\.venv\Scripts\python.exe tools/audit_live_checks.py
.\.venv\Scripts\python.exe bench/measure_primitives.py --iterations 10 --keygen-iterations 1 --kems ml-kem-768 --signers xmss --xmss-height 10 --xmss-keygen-iterations 1 --out .bench-u03
.\.venv\Scripts\python.exe bench/measure_handshake.py --repeats 2 --kems ml-kem-768 --signers xmss --xmss-height 10 --x509 --out .bench-u03
```

本轮实际使用修复工作目录上一级的 `.venv`，其他参数如上。虚拟环境、依赖二进制和缓存不进入交付 ZIP。

本机原语中位数：keygen 2282.1731 ms、sign 3.0819 ms、verify 1.2133 ms。X.509+ML-KEM-768+XMSS 的握手中位字节数 8391，握手阶段 7.080 ms；生成完整凭据的时间另计入 wall_ms。原语 keygen 仅 1 个请求样本，sign/verify 为 10 个请求样本，握手每配置 2 次；原语工具在请求次数大于 3 时去掉首个样本，因此 sign/verify 中位数各基于 9 个样本，keygen 保留 1 个；握手不剔除首样本。样本用于回归核对，不支持普遍性能结论。

本次未运行原攻击包（用户未提供）、未重新运行 Rust/Tamarin/Verifpal；其中原始结果仍是历史证据。本轮只对改动相关的 Python 实现、测试、可达性和测量负责。独立链参考实现并非官方 XMSS 向量或安全证明。

# v9 验收与环境记录（2026-09-22）

本轮按改进方案的 M0–M2 产出记录。原件冻结在 `02-审查记录/06-v8审计/`（含 21 个用例与
`EVIDENCE_MANIFEST.json`），审计侧修订放在 `audit_v9/`（`REVISION_DIFF.md` 给出完整差异）。

## 环境（两套，都是文件，不只是叙述）

| 文件 | 内容 |
|---|---|
| `environment.json` | 作者侧：解释器/平台/`sys.path`/锁文件哈希/已安装发行版样本哈希/`sandbox_pyfix` 是否在 `PYTHONPATH` 上及其哈希 |
| `environment-independent.json` | 独立风格：**`sandbox_pyfix` 不在 `PYTHONPATH` 上**（`on_pythonpath: false`），仅 `.deps`；补丁的 sha256 仍在清单里，便于在未导入它的进程里核对 |

两者都由 `tools/report_environment.py` 生成，只描述环境、不修改环境；`verify_all.ps1` 的 4d 检查会重新生成作者侧那一份。

## 测试与验收

| 检查 | 结果 | 原始记录 |
|---|---|---|
| pytest（作者侧，含沙箱补丁） | **393 passed** | `v9-pytest-author.txt` |
| pytest（独立风格，不含沙箱补丁） | **393 passed** | `v9-pytest-independent.txt` |
| 一键验收 | **35 checks, 35 passed**（新增 4c 锁关联、4d 环境清单、5c 生命周期） | `v9-acceptance.txt` |
| 可达性扫描 | 87 个定义；0 tests-only、0 unattributed、0 未声明 getattr、0 不可达；PASS | `v9-sweep.txt` |
| 依赖锁关联 | 2 个锁文件、11 个包，全部有 pin 与 hash；PASS | `v9-locks.txt` |
| 生命周期成本分解 | h=8/h=10，5 次冷初始化 + 30 次热握手，含墙钟与 CPU 时间与原始样本 | `v9-lifecycle.md`、`../.bench-lifecycle/` |
| 原用例兼容复跑（21 个脚本未改） | T1/T2 由 VULNERABLE 转 PASS；Q1/Q2/S=1、Q3=0；W2/W3 由 INFO-DEVIATION 转 PASS；T6 保持 INFO-DEVIATION | `../../02-审查记录/06-v8审计/audit_v9/compat_results.json` |
| 修订后严格复跑（11 条） | 11/11 PASS | `../../02-审查记录/06-v8审计/audit_v9/strict_results.json` |

### 关于独立环境里那 39 个 `tmp_path` 错误

在**未加载** `tools/sandbox_pyfix` 的进程里，pytest 自带的 `tmp_path` 会在本机沙箱中于 setup
阶段报 `PermissionError`：它用 `mode=0o700` 建基目录，而本沙箱通过 capability SID 授权，无法遍历
这样的 DACL。此前这被记成"21 项错误"，本轮实测是 **39 项 setup error（354 passed）**，如实记录，
不写成"已解决"。同一次实测还确认：把 `TEMP`/`TMP` 指到工作区内、或预先建好 `--basetemp` 目录，
**都不能**解决——pytest 会重建该目录。

因此本轮把 `tests/conftest.py` 的 `tmp_path` 换成同契约的本地实现（每个用例一个空目录，落在
检出目录的 `.tmp/pytest-work/` 下，用后删除），并在文件里写明放弃了 pytest 的编号保留目录这一
点。改前/改后两套记录都在上表：独立风格从 354 passed + 39 errors 变为 393 passed。

这仍然不是"环境安全"的结论：它只说明**本仓库的测试**在补丁缺席时能跑完；沙箱对目录 DACL 的
限制本身没有消失，pip 之类仍需要该补丁或等价手段。

## 本轮未做的事

* 未运行 Rust 原型、Tamarin、Verifpal 的**重新**验证（历史结果仍是历史证据，标注为未重跑）；
* 未实现 XMSS 状态的跨进程持久化与防回滚，因此**未启用**任何复用秘密状态的模式；
* 未做连接洪泛、握手中止、队列背压等网络触发实验，W1 仍是成本测量而不是远程 DoS 结论；
* 本轮全部修复仍**没有**第三方独立复核：探针是作者按审计脚本原样重跑的，这本身不构成独立审查。

