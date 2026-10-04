# 项目功能演示与证据展示

`tools/demo_project.py` 演示已签发夹具上的 P0–P4 成功路径、严格 alt 策略拒绝、真实序列化字节与长证书分片。它导出脱敏 JSON、四张 SVG（Pillow 可用时同时输出 PNG）和 32 秒带中文字幕的 MP4。

画面明确标为 **已执行 JSON 证据可视化**，录像属于证据演示，不伪装成实时终端录屏。画面上的 SHA-256 对应输出目录中的 `evidence.json`。演示不重新生成 SLH CA 密钥或签名，正式性能样本保持 0；不输出私钥、令牌、凭据路径或耗时。

## 使用预签发夹具执行功能演示

在已有真实 SLH/Falcon 夹具、对应原生库和可选依赖的 Linux 环境运行：

```sh
python tools/demo_project.py \
  --fixtures validation/post-audit-alt-fixtures \
  --library build/post-audit-final/libslhdsa_sm3.so \
  --output validation/project-demo \
  --video
```

路径使用实际验收产物替换；输出目录必须是新目录。原生库显式指定，不依赖默认查找。

执行内容：

1. P0–P4 加载已签发证书及测试叶子凭据，完成握手、应用数据与 exporter 验证。
2. SM3-128-24、128s 的两条 CA 边分别强制 C 与独立 Python 验签；记录实际后端和库哈希。ML-DSA 保留 provider 验签。
3. 对 SM3-128-24 叶证书删除 alt 签名对、修改 alt 签名字节，再用夹具测试中间 CA 的 ECDSA 密钥重签外层证书。经典链通过后，严格 alt 策略应在 `certificate_alt` 步拒绝；不生成新 SLH 签名。
4. 保存 DER 哈希、每条记录 content/ciphertext 长度、P0–P4 状态与拒绝阶段，生成四张展示图。

`--handshake-signer` 默认 `falcon-512`，应与既有夹具匹配。命令只用现存测试凭据，未修改原夹具和预算账本。

## 根据已经执行的 JSON 生成展示图

已有项目功能门禁产物时，可纯读证据渲染：

```sh
python tools/demo_project.py \
  --evidence-json validation/project-functional/manifest.json \
  --output validation/project-functional-visuals \
  --video
```

支持三种 schema：`a15-project-functional-v1`、`a15-tls-functional-acceptance-v1` 和演示脚本自身的 `a15-demo-evidence-v1`。项目功能 manifest 的日志、CA 验签 JSON 和 P0–P4 JSONL 必须与 manifest 中的哈希一致。输入未包含的 P0–P4、分片或负例结果，会在图和字幕中标为缺项，不补造成功结果。

也可同时指定 `--evidence-json` 与 `--fixtures --library`：读取原功能门禁摘要，再实际执行夹具演示，组成一份完整证据展示。

## 四个画面与输出

| 画面 | 内容 |
|---|---|
| 01 | 已执行功能门禁与强制 C/Python 验签摘要 |
| 02 | P0–P4 状态、握手与服务端实际记录字节 |
| 03 | P3 Certificate 分片数、各片明文/密文长度与边界 |
| 04 | alt 剥离/篡改拒绝阶段，性能和新 SLH CA 签发均为 0 |

输出 `evidence.json`、`slide-01` 至 `slide-04` 的 SVG/PNG、`captions.srt`、`slides.ffconcat`、`MAKE_VIDEO.txt`、`manifest.json`，以及成功编码时的 `evidence-demo.mp4`。manifest 给出每个产物哈希与真实 `video_status`。

SVG 无第三方绘图库依赖。PNG 优先使用 Pillow 和 TrueType 字体；默认尝试 Arial/DejaVu Sans/Liberation Sans，也可用 `--font /实际路径/font.ttf`。缺少 Pillow 时，`--video` 会尝试有 librsvg 的 ffmpeg 从 SVG 生成 PNG。画面英文便于跨平台字体稳定，MP4 内置默认启用的中文字幕轨道。

若当前环境缺少 ffmpeg，脚本仍完成证据与四张图，写出 `MAKE_VIDEO.txt`。在有 ffmpeg 的环境，将上述输出目录复制完整后，在该目录执行记录的命令即可编码；无需重跑握手或签发。MP4 编码需 `libx264`，字幕使用 `mov_text`。

字节统计属于本作品私有 TLS harness；标准 TLS 记录头与 TCP/IP 成本分开表示，展示不构成标准 TLS 互通或网络性能结论。论文、正式性能/网络采样继续留在后续用户确认阶段。
