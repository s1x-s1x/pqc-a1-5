# 阶段一 C 标量实现与上游的差异清单

复核日期：2026-10-04。本文按当前本地源码逐模块、主要函数阅读整理；“源码已实现”描述代码状态，执行验收以本轮 `validation/<run>/manifest.json`、构建哈希及逐例结果为准。本文未连接服务器、未修改源码、未运行密码算法。

## 1 来源与复用边界

上游为 `slh-dsa/slhdsa-c`，项目登记提交 `2b111e076a3bf0b6041651cf8746acf5ade56cc7`。源码保存在 `third_party/slhdsa-c/`。该项目作者为 slhdsa-c project authors；LICENSE 说明代码原由 Markku-Juhani O. Saarinen 于2023–2025年编写并捐赠。

- 上游源码提供 `Apache-2.0 OR ISC OR MIT` 选择；本实现 `c/src/engine.c` 顶部明确选择 MIT，保留上游作者和A1-5贡献者署名。
- 保留原 `third_party/slhdsa-c/LICENSE`；第三方源码随提交材料保留原版权、许可通知。上游 README 标注 CC-BY-4.0，其文档许可与 C 源码许可分别处理。
- 当前 Makefile直接编译上游 `sha2_256.c`，并包含 `sha2_api.h`、`plat_local.h`。当前执行引擎没有直接编译上游 `slh_dsa.c`、`slh_sha2.c`、`slh_shake.c` 或 `slh_prehash.c`；这些文件提供算法骨架、实例化和地址布局的对照来源。
- `engine.c` 是基于上游算法骨架的重新组织和扩展，不宜描述为只改少量常量、上游全量功能原样继承或完全从零独立原创。`sm3.c` 是按 GB/T 32905 定义加入的项目标量实现。其文件当前没有单独 SPDX 声明，发布时应在项目许可证/组件清单中明确贡献代码的许可选择。

## 2 主要函数与模块映射

| 上游来源 | 当前函数/模块 | 复用、改动与新增 | 当前边界 |
|---|---|---|---|
| `slh_param.h`、`slh_sha2.c` 的参数与实例化结构；`slh_dsa.c:get_len1/gen_len2/get_len` | `parameters`、`lookup`、`slh_*_bytes` | 自有固定pid表：SM3 1/2/3、SHA2 101/102/103、玩具201；固定 n=16、最大WOTS len=68。加入草案128-24和玩具参数；长度按参数公式导出。SM3/SHA2对应参数目前是表中两条记录，须核值一致，不能说成共用同一个参数对象。 | 源码已实现七个pid；没有任意参数构造API，也未继承上游全部12组参数。 |
| `slh_adrs.h:slh_toint/slh_tobyte/adrs_*/adrsc_22` | `put32/get32/getint/set_type/set_type_kp/set_tree`、`work.adrs`、`thash` | 保留32 B大端地址和22 B压缩布局；以项目数组操作重写，类型切换分别清除下游字段或保留key-pair字段。FORS使用全局绝对索引。 | 源码已实现；布局/边界由独立向量与测试验收。 |
| `sha2_256.c`、`sha2_api.h`、`plat_local.h` | `hash_state`、`hi/hu/hf` 的SHA2分支 | 上游SHA-256核心直接编译；项目包装记录压缩次数。上游 `SLH_EXPERIMENTAL` 下的原计数代码不同于项目 `SLH_COUNTERS`，正式构建不启用该实验宏。 | SHA2仅用于n=16参数；未加入SHA-NI加速。构建绑定须含plat_local.h。 |
| 上游没有SM3核心 | `sm3.c:rot/rd/wr/compress/a15_sm3_init/update/final` | 新增SM3消息扩展、64轮压缩、流式吸收、大端填充和输出；旋转函数处理零位数；复制状态保留已吸收字节数。 | 便携标量代码；没有SM3硬件指令、SIMD或GPU内核。 |
| `slh_sha2.c:sha2_mk_var/sha2_256_adrsc/prf/f/h/tl` | `init_work/thash/hpair/prf` | 保留 `PK.seed || zero[48]` 的64 B前缀预压缩及状态复制，统一SM3/SHA2选择；ADRSc与输入在复制状态后吸收；PRF/F/H/T截取16 B。 | 不依赖OpenSSL或Python运行时；不把midstate收益当未测的性能数字。 |
| `slh_sha2.c:sha2_256_prf_msg/sha2_256_h_msg` | `prf_msg/h_msg` | 以通用hash包装重写HMAC、MGF1实例化并加入SM3；两者接受已经编码的M′。保留R、PK.seed、PK.root与消息的标准顺序。 | 纯模式编码由项目公共wrapper完成；外部prehash测试可经独立编码走internal，未新增公共prehash API。 |
| `slh_dsa.c:base_2b/wots_csum` | `digits/wots_digits` | 保留uint32累加器和base-2^b算法；支持b=2、4及FORS a=24；校验和移位用模8表达式，len从固定参数表读取。 | 仅表中lgw值；参数空间分析不能据此声称任意lgw均已实现。 |
| `slh_sha2.c:chain/wots_chain`；`slh_dsa.c:wots_sign/wots_pk_from_sig/xmss_node` | `chain/wots_secret/wots_leaf/xmss_sign/xmss_from_sig` | 保留WOTS秘密导出、链、压缩和从签名恢复公钥；整合到通用SM3/SHA2工作结构。XMSS认证兄弟子树由treehash计算，可从有效顶层缓存取高层节点。 | 链步数取实际消息与校验和；没有WOTS x8优化。 |
| `slh_dsa.c:xmss_node/fors_node` 的递归节点计算 | `serial_tree/treehash/record_node/node_offset` | 新增迭代栈treehash，O(height)局部栈；按实际线程数动态切分对齐子树，OpenMP计算chunks后按绝对高度/索引合并；可同时提取认证路径、记录公共缓存节点。 | 已有OpenMP；任务数动态选择，并非报告早期固定z=16/1536任务配置。 |
| 上游内部节点函数，没有本项目稳定子树API | `slh_ctx_bind_key/slh_subtree` | 新增绑定密钥的子树接口；检验pid/类型、高度、2^z对齐、范围、目标、认证路径缓冲；`UINT32_MAX`请求root-only。 | 上下文绑定/缓存状态不可并发修改；只读subtree调用按接口约束执行。 |
| `slh_dsa.c:fors_sign/fors_pk_from_sig/slh_sign_digest` | `fors_secret/fors_leaf/sign_fors_tree/sign_core` | 当前签名计算每棵完整FORS树及选中秘密，直接复用已算出的根压缩FORS公钥；大a森林逐树占用线程分配，小a森林按树并行、单树内部单线程。 | 计数与上游“认证兄弟子树后从签名重构根”的路径不同；须按实际实现模型核R2。 |
| `slh_dsa.c:split_digest/ht_sign/ht_verify/slh_verify_digest` | `split_digest/sign_core/verify_core` | 保留消息摘要分割、FORS→hypertree与逐层恢复；使用明确宽度，零treebits分支直接归零。验签先查完整签名长度，再重建root并累积比较差异。 | d=1/a=24/lgw=2新增路径已纳入设计；sanitizer执行结果由本轮manifest确认。 |
| `slh_dsa.c:slh_keygen_internal/slh_keygen` | `slh_keygen_internal/slh_keygen` | 保留SK.seed/SK.prf/PK.seed/PK.root顺序；keygen同时构建配置的顶层公共缓存；随机入口改为Linux getrandom并清理临时种子。 | Linux实现；没有生产密钥加密存储、跨设备签发预算账本。 |
| `slh_dsa.c:slh_sign/slh_verify/slh_sign_internal/slh_verify_internal` | 同名项目API、`encode_message`、`slh_ctx_*` | 改为不透明ctx、pid/backend标志、显式错误码与导出尺寸函数；公共纯模式编码 `0 || ctxlen || ctx || msg`，检查上下文长度及分配溢出；internal接受完整M′。 | ABI与上游不兼容；AUTO/REF支持，其余显式backend返回错误。 |
| 上游没有本项目签后自验和故障矩阵 | `slh_sign_internal`、`wipe`、`SLH_TEST_BUILD/SLH_TEST_FAULT_POINT` | 可选签后验签；失败返回SLH_ERR_FAULT并清零签名，公共wrapper长度为0。新增针对H_msg、FORS secret/leaf、WOTS链/认证叶的测试构建注入；双宏及release互斥保护。 | 注入仅测试可执行文件；不提供生产切换入口。当前测试源码存在，检测/清零结果由日志确认。 |
| 上游没有公共XMSS cache文件格式 | `allocate_cache/slh_cache_build/save/load/clear_cache/cache_digest` | 新增顶层tree0缓存；96 B A15CACHE头与height-t公共节点；SM3摘要、pid/尺寸/完整PK绑定；重算上层并验证root。失败保留旧缓存；不序列化秘密种子。 | t=12/hp22载荷16384 B、文件16480 B、节点32752 B；普通文件导出未提供并发事务或密钥库功能。 |
| 上游实验计数程序 `test/xcount.c` | `counts/COUNT/slh_counters_reset/get` | 新增7字段全局原子计数，区分原语与实际压缩；由SLH_COUNTERS构建开关控制。 | 计数版与计时版分离；不是线程局部计数，也不是每个ctx独立计数。 |

## 3 验收与后续设计的分界

本次主线是标量引擎、子树并行、缓存与签后自验的正确性。已保存的外部A/B/C、Python金向量和随机差分是功能证据；新增运行应保留旧文件，并把当前源码→编译命令→共享库→输入文件→逐例结果→汇总串起来。测试代码存在不自动代表执行通过。

AVX2 x8 FORS、AVX-512、NEON、CUDA、完整TLS alt链、生产CA预算和正式性能基准不属于本文“源码已实现”范围。现有backend枚举、旧TLS基座、硬件清单或报告算法框是接口/前期工作/设计材料，应分别标注。后续启用的功能需要新的差异清单及对应输出一致性证据。
