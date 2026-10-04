# DP1分析包：报告第5/7章

本包完成参数网格与FORS概率项分析；`final=false`，尚未绑定最终提交代码。
主说明为 `docs/SECURITY_TERM_ANALYSIS.md`。生成入口：

```sh
python tools/check_analysis.py --output report-data/DP1-analysis
```

本次121项复核全部通过。R7有6行，R8有59个概率点；有限网格保留25704个
组合，结构有效6822个、通过单项阈值4392个，无缓存/缓存前沿29/30点。
已实现128-24在这两条限定前沿之外；此结论只针对该有限网格与FORS单项筛选。

- `R7-security-parameters.csv`：NIST原参数来源/类别与实验SM3实例分列。
- `R8-FORS-probability-term.csv`：纵轴为FORS目标覆盖概率项的负二进制对数，
  不作完整EUF-CMA或量子安全位数声明；越过2^24的行是数学外推。
- `security-terms.jsonl`：100位Decimal向外舍入、精确二项递推及省略尾界。
- `grid-config.json`：冻结范围、约束、q、期望成本与配置哈希。
- `grid-all-candidates.csv`：原始全组合，包含失败原因与未实现状态。
- `grid-Pareto-*.csv`：两种成本口径各自的前沿。
- `R7-R8-tables.md` / `grid-tables.md`：带分析边界说明的Markdown表。
- `parameter-baselines.csv`：标准结构理论比较，包含均匀消息WOTS精确期望。
- `wots-uniform-chain-distribution.csv`：可复核的精确期望分布，lgw3使用ceil与补零。
- `analysis-checks.*`：小参数精确有理数、160位精度、旧参考值、结构计数、
  Pareto规则、已有268条原生签名/验证记录及7参数向量trace的复核。
- `count-replay-inputs.jsonl` / `R2-existing-vector-predictions.csv`：已有7参数
  向量及35条预测；用于后续计数库重放，尚未写入新observed。
- `sources/`：官方NIST原文、提取文本、哈希和Table1核对图。

完整方案安全、正式性能与新候选实现均不从本包单独推出。2^24草案限额始终
按单密钥跨全部副本/设备的严格总量约束解释。
