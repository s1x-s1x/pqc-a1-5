# 第一轮标量实现的精确计数口径

`tools/count_model.py` 预测当前 `c/src/engine.c` 的实际执行路径；
`tools/check_counts.py` 对独立 `COUNTERS=1` 构建逐操作比较
`prf, prf_msg, h_msg, f, h, t, compress` 七个字段。它们用于 R2 正确性证据，
不输出性能或整体安全结论。参数从实际 C 参数表读取，证据同时保存源码、脚本、
原生库及输入的 SHA-256，避免参数表与计数底稿各自演变。

## 1 压缩次数与 midstate

记 `B(x) = floor((x + 72)/64)`，即长度为 x 字节的 SM3/SHA-256 输入包含
填充后的 64 字节压缩块数。这里的两个算法采用相同块长与填充长度。
`M` 表示 internal API 实际接收的 `M'` 字节数；pure API 的长度是
`message_length + context_length + 2`。

`init_work` 对 `PK.seed || zero[48]` 压缩一次；随后 `thash` 复制已压缩的
状态，复制本身没有杂凑计算。线程内按值复制 `work` 也没有额外初始化。
每次 `thash` 只产生 `B(22 + input_length)` 次新压缩：

| 类别 | input_length | 新压缩次数 |
|---|---:|---:|
| PRF | n=16 | 1 |
| F | n=16 | 1 |
| H | 2n=32 | 1 |
| WOTS 公钥 T | len*n | `c_w = B(22+len*n)` |
| FORS 根 T | k*n | `c_f = B(22+k*n)` |

len=35 时 `c_w=10`；len=68 时 `c_w=18`。各参数的 `c_f` 分别为
pid1/101:4、pid2/102:9、pid3/103/201:2。`t` 只计函数调用总数，
模型的 component 保留 `t_wots` 与 `t_fors`，压缩预测分别加权。

一次 PRF_msg 计一次原语调用，实际压缩次数是
`C_PRFmsg(M) = B(64+n+M) + B(64+32)`。
一次 H_msg 也只计一次原语调用，其压缩次数是
`C_Hmsg(M) = B(3n+M) + ceil(m/32)*B(2n+32+4)`。
n=16 时分别为 `B(80+M)+2` 和 `B(48+M)+2*ceil(m/32)`。
PRF_msg 的内外 HMAC、H_msg 内部 digest 与 MGF1 迭代均包含在这些压缩数中。

因此 `compress` 不是 `PRF+F+H+T`，也不是每个原语都重复支付 PK.seed
前缀的一次压缩。完整有效签名包含一次 midstate 初始化、一次 PRF_msg 与
一次 H_msg；验证包含一次 midstate 初始化与一次 H_msg。签后自验把一次完整
验证加到签名计数上，包括第二次 midstate 与第二次 H_msg。

## 2 树、线程与认证路径

记 `L=2^z`、`u=len*(2^lgw-1)`。
一棵高 z 的 WOTS 树产生 `PRF=L*len, F=L*u, H=L-1, T=L`。
一棵 FORS 树产生 `PRF=L, F=L, H=L-1`。取得认证路径只是复制已算节点，
`target` 是否存在不改变这些计数。

公开 subtree API 在树成本上加一次 midstate。keygen 和 cache_build 都构造
完整 top XMSS 树，成本是高 hp 的 WOTS 树加一次 midstate；cache_t 只影响
写入缓存的节点，树仍完整计算。toy keygen 的精确预测为
`PRF=69632, F=208896, H=1023, T=1024, compress=297984`。

当前 treehash 在 `threads>1` 且 `z>=5` 时选择 split，满足
`split<=z, split<=10`，并使 `2^split` 达到 `4*threads` 或受到上述上限限制。
chunks 内部合计 `2^split*(2^(z-split)-1)` 次 H，合并 chunks 再产生
`2^split-1` 次 H，总数仍是 `2^z-1`。拆分没有额外 PRF、F、T 或 midstate。
小 FORS (`a<16`) 森林在树间并行，每棵内部线程数为 1；大 FORS 森林逐树
执行、每棵树内部并行。相同输入、缓存资格与 flags 下，线程数改变不改变计数。

XMSS 签名逐高度计算认证兄弟子树，没有合成一棵完整树后重复恢复路径。
若待计算的认证高度为 `0..b-1`，合计 WOTS 叶数为 `2^b-1`，内部 H 为
`2^b-1-b`。缓存只适用于 key 匹配、top layer 且 tree address=0 的 XMSS；
符合条件时 b=cache_t，其余层或不符合条件时 b=hp。
t=hp 只保存 root；签名认证路径仍全算，计数与完全无缓存一致。
t=0 缓存全部叶与上层，top XMSS 认证路径无需计算。

## 3 实际 WOTS 数字、FORS 根复用及完整公式

第 i 层的 `S_i` 是该层实际 n 字节消息的 WOTS 消息数字与校验和数字之和。
签名链步数为 `S_i`；从签名恢复公钥的链步数为 `u-S_i`。模型按 C 中的
MSB-first base-w 数字及 checksum 左移/编码规则求值，不使用近似均值。
`signature_trace` 用独立 full-hash 路径恢复 FORS 根与各层消息，记录所有数字、
层/树/叶地址以及恢复到的 root。它只走验证路径，不构造大树。
这份路径恢复是计数模型输入检查，不能单独代替完整签名实现的独立差分证据。

当前 FORS 签名每树先另生成选中秘密一次 PRF，再构造整棵树。合计
`PRF=k*(2^a+1), F=k*2^a, H=k*(2^a-1), T_fors=1`。
整棵树直接返回的根参与 T_k，没有再运行 fors_pkFromSig。
只相加这四类原语调用，得到 `3*k*2^a+1`；pid3/103 为 301,989,889。
这不包括消息原语、midstate、WOTS/XMSS；也没有把 T 的多块压缩误当一次。

XMSS 签名仅在非末层运行 xmss_from_sig，以得到下一层消息。
故非末层 `S_i + (u-S_i) = u` 精确抵消，总签名 F 对输入的剩余依赖是末层
`S_(d-1)`；验证 F 对所有 `S_i` 都有依赖。证据仍逐层保存实际数字与链步数。

令 `b_i` 为各层实际需计算的认证高度数，
`W=sum_i(2^b_i-1)`，`A=sum_i(2^b_i-1-b_i)`，普通签名精确为：

| 字段 | 预测 |
|---|---|
| prf | `k*(2^a+1) + len*(W+d)` |
| prf_msg | 1 |
| h_msg | 1 |
| f | `k*2^a + u*W + (d-1)*u + S_(d-1)` |
| h | `k*(2^a-1) + A + (d-1)*hp` |
| t | `1 + W + (d-1)` |
| compress | `1+C_PRFmsg(M)+C_Hmsg(M)+prf+f+h+c_f+c_w*(W+d-1)` |

验证精确为：

| 字段 | 预测 |
|---|---|
| prf / prf_msg | 0 / 0 |
| h_msg | 1 |
| f | `k + d*u - sum_i(S_i)` |
| h | `k*a + d*hp` |
| t | `1+d` |
| compress | `1+C_Hmsg(M)+f+h+c_f+d*c_w` |

上述针对正常结束的执行。签名长度错误在 init_work 前返回，七字段全零。
模型不把任意错误返回、部分故障路径与完整成功操作混在同一预测中。

## 4 缓存文件校验杂凑的特殊边界

cache_save/cache_load 的 checksum 直接调用 `a15_sm3_*`，没有经过 hu/hf，
因此实际执行 `B(64+payload_bytes)` 次 checksum 压缩却不进入公开 compress
计数器。文件杂凑固定为 SM3，SHA2 参数也如此。模型另列
`cache_checksum_compressions_uninstrumented`，保持公开计数与实际额外杂凑分开。

cache_save 的七字段都是 0。cache_load 的公开计数为
`H=2^(hp-t)-1, compress=1+H`，其他字段为 0；其中 1 是用于上层 H 的
midstate。t=hp 时没有上层 H，但当前源码仍初始化 midstate，因此 compress=1。
cache_build 与 keygen 的完整树成本相同，且不产生文件 checksum。

toy 的 t0/t5/t10 load 预测 `(H,compress)` 分别为 `(1023,1024)`、`(31,32)`、
`(0,1)`。磁盘载荷为 `n*2^(hp-t)`，完整文件为 `96+载荷`；缓存节点内存为
`n*(2^(hp-t+1)-1)`，尚未包含 context、分配器和线程工作区。

## 5 运行和输出

在项目根目录的 Linux 环境构建独立计数库，再执行：

```sh
make -C c OUT=../build/stage1/counters COUNTERS=1 all
python tools/check_counts.py \
  --library build/stage1/counters/libslhdsa_sm3.so \
  --output validation/stage1/exact-counts.jsonl
```

输出路径须为新文件，避免覆盖先前证据。摘要为
`validation/stage1/exact-counts.summary.json`。所有操作顺序执行；全局原子
计数器在 reset/read 区间内不应被另一客户端使用。脚本先以高0的 FORS subtree
检查计数构建，错误的普通库会留下失败记录/摘要并以非零退出码结束。

默认覆盖 toy 的 threads=1/4、无缓存/t0/t5/t10、key mismatch、build/save/load、
pure/internal、context0/255、确定性/显式随机化、签后自验、认证/无认证 subtree
及错误签名长度。internal M' 长度为
`0,1,7,8,39,40,47,48,55,56,63,64,257`，包含消息杂凑填充分界。
另外默认运行低成本 pid2/102 的多层样例，以验证 d−1 根恢复、每层实际数字与
m=34 的双 MGF1 迭代；不生成完整 pid3/103 签名。
可用 `--toy-only` 省略这些多层样例，用 `--threads 1 4` 和
`--message-lengths ...` 调整测试矩阵。此后摘要只声明实际执行的覆盖范围。

每条 JSONL 保存 predicted/observed 七字段、逐字段匹配、component 分解、实际
WOTS 数字、输入和输出、缓存/线程条件、库与源码哈希及记录哈希。所有字段
相等且相关正确性检查通过才标 passed，失败仍保留原始数据。counter-build
SHA-256 能绑定二进制；构建 flags/命令的来源应由统一阶段运行器再留档。

单独导出结构计数或根据已有二进制签名计算精确预测：

```sh
python tools/count_model.py --pid 201 --operation keygen --threads 4 --cache-t 5
python tools/count_model.py --pid 201 --operation cache_load --cache-t 10
python tools/count_model.py --pid 3 --operation sign --cache-t 12 \
  --signature EXISTING_SIGNATURE.bin --public-key-hex PK_HEX --message-hex MP_HEX
```

最后一条只读取已有签名并走验证路径，未运行完整高24 FORS 签名。

## 6 本地模型检查与尚待原生测量

新增脚本已通过 Python 语法检查。signature_trace 已读取现有 1,000 份 toy
差分签名，全部恢复到公开 root；观察到 13 个不同实际链步数，范围78..123。
另外读取现有 gmsm 的40份 SM3-128s/128f 确定性/随机化签名，7层和22层均
恢复到公开 root。此检查没有重生成签名，且不作为新原生计数实测宣称。

原生七字段是否一致以 `check_counts.py` 的实际输出为准。主要口径歧义已经
明确解决：threads 不增加原语数；FORS 直接复用完整树根；XMSS 仅重构非末层；
midstate 按入口初始化计数；消息杂凑按实际 M' 长度计压缩；缓存 checksum
是存在但未受公共计数器覆盖的工作。
