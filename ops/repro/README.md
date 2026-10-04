# 新机器正确性复现

本配方建立新的 CPU 验收环境，不把它声称为历史 Linux/CUDA 原字节副本。Python 基础镜像固定到 Docker 官方 registry 的 manifest digest；Debian bookworm 软件源固定为 2026-10-03 UTC 快照；Python 主依赖、独立参考和 Falcon 使用 release artifact SHA256 锁。

```sh
docker build -f ops/repro/Dockerfile -t a15-correctness .
docker run --rm a15-correctness
```

验收服务器若配置的 registry mirror 拒绝 immutable manifest，可在可直连 Docker 官方 registry 的机器获取同一基础镜像：

```sh
python -B ops/repro/fetch_base_image.py --output .repro-artifacts/python-base.tar.gz
docker load -i .repro-artifacts/python-base.tar.gz
docker image inspect a15-python-base:locked-5024f48b --format '{{.Id}}'
docker build --build-arg BASE_IMAGE=a15-python-base:locked-5024f48b -f ops/repro/Dockerfile -t a15-correctness .
```

`image inspect` 的 Id 须与生成的 identity JSON 的 `image_config_digest` 相等。获取器先验证 pinned index、linux/amd64 manifest、config、压缩 layer 和解压 diff_id，再写 archive；不同 tar/gzip 封装的文件 SHA 可不同，基础 image 身份以这些固定 digest 为准。该途径不修改系统 daemon 设置。构建内部 DNS 出错时可对单次 build 追加 `--network=host`，保留原失败日志。

镜像构建执行原生正确性和 provider 功能检查；运行重新构建 CPU、执行 fault/清理策略/sanitizer，再检查 ABI/预算、mock 续跑、TLS 功能全集、交付工具及固定种子解析变异。命令中没有正式性能 worker。缺网络、registry 或快照时保留构建错误，新机器结果不填通过；成功必须由真实 build/run 和新日志证明。

在现有 Linux 主机同样可执行：

```sh
python -m pip install --require-hashes -r base_tls/requirements.lock.txt
python -m pip install --require-hashes -r reference/requirements.lock.txt
python tools/install_falcon_provider.py
OMP_NUM_THREADS=2 OMP_DYNAMIC=FALSE make -C c OUT=../build/fresh-review all test repair-test prehash-test guard-test
python -B ops/run_review_checks.py --native-library build/fresh-review/libslhdsa_sm3.so --output build/fresh-review-checks
```

选择新目录，保留首次失败。Falcon 安装目录已存在时先使用其既有匹配 ABI 安装记录，或在新的 checkout 安装，避免覆盖 provider。

历史冻结的 SHA256 复核仍使用 `docs/GITHUB_HANDOFF.md` 中的 12 份系统原字节清单。新机器验收应保存平台、编译器、包版本、源码、构建和日志哈希，不能更新历史冻结来消除环境差异。CUDA 后端只在专门的 NVIDIA 验收主机检查：`tools/run_cuda_native.py` 做 untimed kernel/fault/absence 功能，事件计时关闭；公共 CPU CI 不代表 GPU 通过。

`tools/fuzz_inputs.py` 提供固定种子、固定次数 smoke 和 `--atheris` 入口。可选 Atheris 长期 fuzz 在独立虚拟环境安装，传入 `-runs=N` 等边界；本轮 smoke 的成功不表示穷尽输入空间。解析、模拟 receiver 和真实 toy cache 的范围分别写入 JSON，避免把模拟语义回调视作真实握手验证。
