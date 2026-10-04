# 原生收尾修复与验收入口

日期：2026-10-04。本记录描述源码修复，不修改论文/LaTeX和历史冻结证据。正式性能仍未执行。最终 Linux/GPU 正确性矩阵与新版本冻结由总任务统一生成；下文不把本地辅助验收冒充真实 CUDA/完整平台交付。

## 已实现

- Python 封装先以 buffer protocol 规范化为字节，再传规范化长度。消息/context/signature/digest 的多字节 memoryview 得到完整字节。整数先验证类型及 pid/backend/threads/cache/subtree 范围，子树地址、目标、对齐与跨树范围先于输出分配检查。
- ABI 1.1 (`0x00010001`) 增加版本查询、容量错误 `-8`、签名 pure/internal/prehash/digest 和子树 checked 入口。原 ABI 符号保留，旧入口仍要求调用者按尺寸查询分配。新版 Python 封装严格核验版本和尺寸，使用 checked 入口。加载历史 1.0 库会明确拒绝，历史验收应使用历史封装，而不是把新封装与旧库混配。
- 签名总在库内私有候选缓冲生成；启用自验时用 REF 完整恢复成功后复制输出，关闭自验时也保持候选隔离。候选生成/自验失败清输出，候选内存成功/失败均显式擦除后释放。子树同样先生成内部 root/auth，成功后一起发布。
- work 改为借用操作期间不可变的 SK.seed/SK.prf 指针，避免各线程、按值地址副本和 SIMD lanes 重复复制原始秘密；FORS 并行局部 context 只复制必要公开配置，不复制 context 中的 sk。
- HMAC pad/state/digest、PRF/F hash state、SIMD PRF/F blocks、WOTS 临时 next/endpoints、SM3 调度表等地址可见秘密工作区显式擦除。通用清除使用 memset 与编译器 memory barrier，固定大小可生成批量存储，不采用每字节 volatile 对所有工作区反复擦除。密钥生成缓存分配失败也清 tmp；getrandom 对 EINTR 重试。
- CUDA 种子改成一个受拥有关系控制的 16 B 设备分配，kernel 参数仅携带设备指针，host job 不持有原始种子。设备中 SM3 工作数组擦除；正常/错误路径调用清除+同步+释放，并将清除/同步/释放错误合并到返回状态。已有节点缓冲清除保留；GPU错误可能使底层设备失效，析构仍作 best-effort 重试，不能以错误返回宣称物理设备残留已被证明消除。
- 缓存加载在节点分配前对已打开文件描述符做 exact size 与普通文件检查；分配后仍核对完整读取、EOF、摘要和重建根，提交前再次核对描述符尺寸/身份/时间。轻量复现发现 stdio 预取可掩盖检查后截断，新增后验 metadata 检查与截断测试已拒绝该情形。错误保持旧缓存事务性。
- Makefile 对编译器、flags、CUDA/AVX2/counters 生成配置身份戳；相同 OUT 切换配置触发重建，旧戳移除使 A→B→A 也重建。既有独立目录和 `make -B` 仍可使用。相同 OUT 的并发异配置构建不在支持约定内。

## 专项测试

`python -m unittest tools.test_native_boundaries -v`：7 项通过，涵盖 ABI 拒绝、规范化、回绕、先检查后分配、context/digest边界和 native 秘密缓冲正常/失败及部分分配清理；使用 ctypes 回调，不加载业务原生库。

新增 `make -C c OUT=../build/repair-final repair-test`：独立私有 harness，包含 224 个完整 256 位 midstate/边界/4线程复制对照；容量不足先拒绝；外部签名缓冲在候选生成之后仍为原值；有效/强制无效候选均清除；错误长度为0；缓存分配失败清理；反向任务发出后根/路径一致；文件预检之后追加数据被拒绝；完整尺寸错误在分配前拒绝。所有 observer 仅编入 standalone SLH_TEST_BUILD，发行库没有设置器或测试 ABI。`sanitizer` 目标已包含 repair-test。

本机 MSYS2 GCC -O3 配合历史测试专用 sys/random 声明和拒绝随机生成 stub 运行 repair-test 通过，观察到 169647 次地址内存清除；辅助 deterministic TOY DLL 接入新 Python 封装后 pure/prehash/type-buffer/checked-subtree 通过；WOTS 8路组件 768 对照通过。这不是正式 Windows DLL 验收，也不覆盖系统随机生成。Linux/GPU验收必须使用真实运行环境重新生成日志。

CUDA 资源入口：`make -C c OUT=../build/repair-final/cuda CUDA=1 cuda-resource-report`，只编译目标 SM86 SASS，保存 `cuda-resources/ptxas.log`、保留的 PTX/生成文件和对象，记录寄存器/共享内存/spill资源。该入口不运行kernel、不创建计时事件、不采样性能。资源结论以本次编译输出为准。

## 复现与限制

建议最终环境运行：

```sh
python -m unittest tools.test_native_boundaries -v
make -C c OUT=../build/repair-final/avx2 all test review-test repair-test avx2-test wots-test prehash-test fault-test guard-test
make -C c OUT=../build/repair-final/portable AVX2=0 all test review-test repair-test prehash-test fault-test guard-test
make -C c OUT=../build/repair-final/avx2 sanitizer
make -C c OUT=../build/repair-final/cuda CUDA=1 all cuda-test cuda-fault-test guard-test cuda-resource-report
```

随后以本次源码、工具、库哈希重跑全量正确性矩阵和冻结启动门。构建清单需纳入新编译输入 `c/src/secure_zero.h`；测试源、脚本和本说明也应被源码/验收归档覆盖。性能计划继续停在准备状态。

清除保证针对本项目持有的可寻址工作区；Python 调用者原始不可变 bytes、C 调用者密钥、编译器自行生成的寄存器/溢出、设备物理存储与硬件侧信道并未由这些源码测试证明彻底消除。公开树节点和密钥指针无需按原始秘密重复全结构擦除；这一区分降低不必要存储和复制，不改变签名格式或向量结果。
