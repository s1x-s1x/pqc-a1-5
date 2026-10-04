# R7 / R8 解析数据

范围：FORS目标覆盖概率项；不作完整EUF-CMA、量子安全位数或SM3类别认证。
所有数据final=false；SP800-230 ipd仍按初稿与严格2^24签名限额解释。

| 实例 | 参数来源 | 单密钥签名限额 | 签名B | 限额处概率项指数 | 实例类别状态 |
|---|---|---:|---:|---:|---|
| SM3-128s | FIPS 205 Table2 | 2^64 | 7856 | 133.749299297 | no NIST category assigned to experimental SM3 instance |
| SHA2-128s | FIPS 205 Table2 | 2^64 | 7856 | 133.749299297 | 1 claimed by source parameter table |
| SM3-128f | FIPS 205 Table2 | 2^64 | 17088 | 131.364863183 | no NIST category assigned to experimental SM3 instance |
| SHA2-128f | FIPS 205 Table2 | 2^64 | 17088 | 131.364863183 | 1 claimed by source parameter table |
| SM3-128-24 | SP 800-230 ipd Table1 | 2^24 | 3856 | 128.629723853 | no NIST category assigned to experimental SM3 instance |
| SHA2-128-24 | SP 800-230 ipd Table1 | 2^24 | 3856 | 128.629723853 | 1 claimed by source parameter table |

| 128-24签名观察量q | FORS概率项指数 | 运行限额状态 |
|---|---:|---|
| 2^20 | 142.050450055 | within_stated_signature_limit |
| 2^21 | 139.412225114 | within_stated_signature_limit |
| 2^22 | 136.334666390 | within_stated_signature_limit |
| 2^23 | 132.753261663 | within_stated_signature_limit |
| 2^24 | 128.629723853 | within_stated_signature_limit |
| 2^25 | 123.973555701 | mathematical_extrapolation_beyond_strict_draft_limit |
| 2^26 | 118.853446140 | mathematical_extrapolation_beyond_strict_draft_limit |
| 2^27 | 113.381768355 | mathematical_extrapolation_beyond_strict_draft_limit |
| 2^28 | 107.677409727 | mathematical_extrapolation_beyond_strict_draft_limit |
| 2^29 | 101.834993481 | mathematical_extrapolation_beyond_strict_draft_limit |
| 2^30 | 95.916559919 | mathematical_extrapolation_beyond_strict_draft_limit |
| 2^31 | 89.958125783 | mathematical_extrapolation_beyond_strict_draft_limit |
| 2^32 | 83.979197260 | mathematical_extrapolation_beyond_strict_draft_limit |

完整区间、尾界与来源行见R7/R8 CSV及security-terms.jsonl。
