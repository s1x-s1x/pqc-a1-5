# v7 独立审查响应 — hybrid-tls13 v8

日期：2026-09-22。以攻击包内 v7 为基线，在独立副本完成五条修复及三条信息项。原始 ZIP、解包文件和攻击脚本保持字节不变；未修改攻击期望或 summarize.py。源代码补丁见 `../../validation/v7-to-v8.patch`。

| 发现 | 状态 | 修复文件与行号（包内相对路径） | 可执行回归与正向对照 | 原始攻击复跑 |
|---|---|---|---|---|
| V7-01 | 已修复 | `project/tls/pq/wots_xmss.py:612` | `project/tests/test_audit_v7_fixes.py:35`；正向：`test_v7_01_independent_seeds_sign_and_verify` | P1、P2：VULNERABLE → PASS |
| V7-02 | 已修复 | `project/tls/handshake/client.py:325`；`project/tls/handshake/client.py:362`；`project/tls/handshake/messages.py:479` | `project/tests/test_audit_v7_fixes.py:49`；正向：`test_v7_02_empty_entry_extensions_complete_handshake`；逐条编解码测试 | P4、P5：VULNERABLE → PASS；P6：INFO-DEVIATION → PASS |
| V7-03 | 已修复 | `project/tls/handshake/messages.py:220` | `project/tests/test_audit_v7_fixes.py:107`；正向：`test_v7_03_single_share_remains_accepted` | R1：VULNERABLE → PASS；R2、R4 仍 PASS |
| V7-04 | 已修复 | `project/tools/audit_live_checks.py:512`；`project/tools/audit_live_checks.py:544` | `project/tests/test_audit_v7_fixes.py:120`（含已声明接口正向对照、跨模块借用反例） | Q1 exit=1、PASS；Q3 exit=0、PASS |
| V7-05 | 已修复 | `project/tools/audit_live_checks.py:108`；`project/tools/audit_live_checks.py:382` | `project/tests/test_audit_v7_fixes.py:137`；正向：`test_v7_05_real_dispatch_with_valid_declaration_passes` | Q2 exit=1、PASS；S exit=1，拒绝借用；Q3 exit=0、PASS |
| 信息项 R3 | 已修复 | `project/tls/handshake/messages.py:90` | `project/tests/test_audit_v7_fixes.py:179` | INFO-DEVIATION → PASS |
| 信息项 K8 | 已修复 | `project/tls/config.py:62` | `project/tests/test_audit_v7_fixes.py:189` | INFO-DEVIATION → PASS |

## 完整验证

| 检查 | 结果 | 原始证据 |
|---|---|---|
| 修改前 pytest | 320 passed | `../../validation/baseline-pytest.log` |
| 修改后 pytest | 349 passed，新增 29 项参数展开用例 | `../../validation/acceptance.log` |
| 仓库验收 `tools/verify_all.ps1 -SkipBench` | 21/21；包含五种握手配置、四类篡改、完整 pytest、Sweep A | `../../validation/acceptance.log` |
| Sweep A | 87 个定义，0 tests-only、0 unattributed、0 dead；PASS | `../../validation/live-checks.log` |
| 原攻击包全部脚本 | 实际 17 个 case 脚本，加 summarize.py，共 18 个进程，全部 exit=0 | `../../validation/repaired/RUNS.json` |
| Q/S 专项退出码 | Q1=1、Q2=1、Q3=0、S=1 | 对应 `*.result.json` 与探针日志 |
| 原始文件完整性 | 原 v7 解包每个文件逐字节匹配 ZIP；三份输入 ZIP CRC 检查通过 | `../../validation/INPUT_PROVENANCE.json` |

复跑使用 Python 3.13.7、cryptography 47.0.0、pqcrypto 1.0.0、pytest 9.1.1，Falcon 为本地重命名的 pqcrypto 0.4.0 provider。pip 按锁安装首次失败（索引无可用版本）；本次实际复用了用户原目录中已存在的依赖副本，并记录版本，没有将其说成一次成功的干净锁文件安装。完整环境见 `../../validation/environment.json`。

Windows 沙箱首次运行遇到 pytest 的 0700 临时目录权限问题，使用仓库已有 `tools/sandbox_pyfix` 并显式设置 `DSH_SANDBOX_PYFIX=1` 后解决。中文路径的子进程统一 `PYTHONUTF8=1`。这些是测试进程环境设置，未改变协议代码。

## 原始汇总数字与例外

交接文字写“18 个 case / 118 项”。实际 ZIP 含 **17 个 case 脚本**，未改动的 summarize.py 汇总 **119 行**。原因是 S 的字典结果也被纳入通用 I 行；不是少跑或少统计。

| 判定 | 原 v7 同环境复跑 | v8 同环境复跑 |
|---|---:|---:|
| PASS | 89 | 99 |
| REJECTED | 6 | 6 |
| VULNERABLE | 12 | 5 |
| INFO-DEVIATION | 6 | 3 |
| INFO | 2 | 2 |
| HARNESS-BROKEN | 4 | 4 |

10 行预期变化为 P1、P2、P4、P5、P6、Q1、Q2、R1、R3、K8，详见 `../../validation/VERDICT_CHANGES.json`。其余原始判定全部不变。Q3 保持 PASS；S 实际 exit 从 0 变 1，但汇总器对未识别的字典结果无条件输出 `I/VULNERABLE` 并丢掉 exit，所以该行仍红。S 的原始 JSON 与日志证明拒绝，**没有修改汇总器消除这一红项**。

剩余 5 个 VULNERABLE 标签是 B7/B8/B10/D4（历史已驳回的期望，按要求保留）与上述 S/I 汇总缺陷。4 个 HARNESS-BROKEN 为 J1、J3、K4、M1 的旧装置在构造/解码阶段已被既有拒绝规则阻断，与基线相同；本轮没有为其更改用例。历史信息项也原样保留。

## 设计细节与兼容性

**种子守卫。** 双向子串检查覆盖完整包含、前缀、后缀和中段；这是误用防护，不能从字节值证明独立随机性，也不声称识别任意部分相关。正常 `keygen()` 仍取两次独立随机值，WOTS+ 链、签名格式和状态管理未改变。

**证书扩展。** 模型证书与 X.509 握手路径均拒绝非空 CertificateEntry 扩展，包含中间证书条目。X509Chain 新增 `entry_extensions`，完整保留每条扩展；原 `extensions` 参数现在只表示叶证书扩展，不再复制给每个条目。编码检查条目数和叶扩展冲突，解码逐条检查格式和重复类型。DER 证书内部的 X.509 扩展不受这条 TLS 消息规则影响。

**标准定位校正。** 扩展协商要求实际见 [RFC 8446 §4.4.2](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.2)：
> Extensions in the Certificate message from the server MUST correspond to ones from the ClientHello message.

本 profile 没有请求任何 CertificateEntry 扩展，因此非空即拒。交接中 §4.4.2.2 的定位不精确，该节是服务器证书选择。另见 [§4.2.8](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.8)：一般 TLS ClientHello 可包含不同组的多个 share；v8 的“只接受一个”是此研究 profile 的明确限制，并非声称 RFC 普遍禁止多个 share。

**Sweep A。** 唯一名字不再推定接收者类型，未归属变量调用失败并输出所在函数。现有 signer、Reader、连接驱动等真实接口改为经审阅的 `module::Class.method` 显式声明。主动态声明为 `DISPATCH_SITES["tls/a.py::validate_name"] = ("tls/driver.py", line, "getattr-call")`；验证确切 AST 行、立即调用和导入模块目标；该机制仅适用于模块级函数，类方法通过已审阅接口表管理。错误行、错误模块、仅提及、参数遮蔽、模块调用冒充类方法和同名借用均有回归。

为原始 Q3 保留 `GETATTR_DISPATCHED: dict[str, str] = {}` 旧注入入口。旧文本不直接豁免：仅当整个树有唯一目标定义，且存在通过导入模块别名的真实 getattr 立即调用时，才规范化为具体模块/行号证据。Q2 与 S 不满足这些条件而失败。这是语法调用清单，不是完整控制流分析；不证明代码运行时一定可达，不支持动态拼接名字或通用变量类型推断。

两个仓库内部旧测试随契约修订：唯一变量调用的旧“放行”测试改为断言失败；正向动态声明测试提供可验证的真实导入目标与精确行号。外部 audit_v7 脚本及其期望一字未改。

**范围。** 本次未重跑性能基准、Rust 原型和符号求解器，未改相关实现或模型；历史 `.bench-out/`、`.bench-u03/` 与 `project/validation/` 继续保存，不能当成本轮或跨机器性能比较。`SECURITY.md` 的未覆盖边界继续适用。这份响应是修复方实测记录，不是新的独立安全证明。

## 复现命令

在解包目录安装项目锁定依赖与 Falcon provider，然后执行：

```powershell
cd project
$env:PYTHONPATH = "$PWD\.deps;$PWD\tools\sandbox_pyfix"
$env:PYTHONUTF8 = "1"
$env:DSH_SANDBOX_PYFIX = "1"  # 仅受限 Windows 沙箱需要
python -m pytest tests -q --basetemp=../validation/local-pytest-tmp
./tools/verify_all.ps1 -SkipBench
cd ..
python validation/replay_audit_v7.py --attack-zip "原始攻击包路径.zip" --output "全新的复跑目录"
# 比较原版：同一命令增加 --baseline，另指定一个全新输出目录。
```

复跑器从原始 ZIP 复制脚本且校验 SHA-256，把目标副本放在旧版用例要求的 `hybrid-tls13-review-package-v7/project` 路径。这个名字是独立复跑目录中的路径兼容别名，实际代码来自当前 v8，不是修改原始 v7。输出目录必须全新，避免混入陈旧结果。
