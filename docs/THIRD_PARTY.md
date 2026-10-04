# 第三方来源与证据说明

第三方代码保留原有版权、许可证及来源记录。

| 内容 | 来源/版本记录 | 许可证与用途 |
|---|---|---|
| SLH-DSA C 参考代码 | `https://github.com/slh-dsa/slhdsa-c`；原始提交 `2b111e076a3bf0b6041651cf8746acf5ade56cc7` | `third_party/slhdsa-c/LICENSE`，代码中的原始声明保留 |
| Python ACVP/FIPS205 参考代码 | `https://github.com/mjosaarinen/py-acvp-pqc`；原始提交 `1c859956c0217b04fa5ae76e338e5570aba622c5`；来源见 `reference/UPSTREAM.json` | `third_party/py-acvp-pqc/LICENSE`；本地受测修改随源码保存 |
| ACVP、xous、gmsm 外部向量 | `third_party/external_vectors/SOURCES.json`、`GMSM_SOURCE.json` 与 `reference/UPSTREAM.json` | 独立正确性输入，保留上游归档及声明 |
| 历史 TLS 原型 | `base_tls/README.md` 及该目录的能力、协议和验证文档 | 历史自有项目内容，按原始声明保存 |
| TLS Python/PQ provider | `base_tls/requirements.lock.txt` 与 `requirements-falcon.lock.txt`；Falcon 独立 provider 为 pqcrypto 0.4.0 | 安装的 wheel 保留各自 METADATA/许可证；独立重命名包不替换主 ML-KEM/ML-DSA provider |
| Verifpal 符号验证工具 | 官方 `symbolicsoft/verifpal` v1.4.12；安装来源与原二进制哈希见 `third_party/verifpal-tool/installation-windows-1.4.12.json` | GPL-3.0，原 LICENSE 保存在 `third_party/verifpal-tool/LICENSE`；只用于独立模型验证，GitHub 不分发工具二进制 |

`validation/optimization-external-evidence/manifest.json` 记录验收环境的 GCC、
glibc/GCC 运行库及 NVIDIA CUDA 头文件 SHA256、大小和来源路径。
这些系统文件的原始字节保留在本地，未纳入 GitHub 提交。
它们不是本项目源码，也没有采用项目代码的许可声明。
需要完整字节复核时，从已安装且版本匹配的原验收环境恢复，步骤见 `GITHUB_HANDOFF.md`。
修复版另保存 `validation/repair-external-evidence-r3-manifest.json`，两版证据分别核对，不覆盖历史清单。

参考源码和外部向量的具体 URL、提交及下载哈希以原始 JSON 来源记录为准。
