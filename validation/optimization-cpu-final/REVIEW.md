# CPU 优化验收完成，停于性能测试之前

实现：midstate、缓存、OpenMP、AVX2 FORS、WOTS x8 与流式 T_len。

原生验收 11 项；全矩阵 3471/3471 项、4370 条记录全部通过。七参数与 1/2/4/8/16/32/64 线程直接执行。

完整矩阵按其受测源码归档；集成 CUDA 后另有当前版本 CPU 原生回归和REF/AVX2 调度、计数、缓存矩阵证据。

128-24 t=0…22 缓存读写、root 绑定及完整签名对照通过；native cache-build 直接覆盖 t0/t12/t22 与 t12 全线程，其余文件由独立父节点计算生成。

REF/AVX2 字节与七字段计数一致，真实 Linux RNG、故障、自验清零、portable、release 隔离、ASan/UBSan 与独立 Python/外部输入检查通过。

独立无计数器基准库与 R3/R4/R5 最小样本计划已准备。正式计时样本数为 0，不报告加速比。此包覆盖 CPU；CUDA 有独立验收与冻结包。硬件 AVX-512 缺席，海光/Windows DLL 未包含。

追溯：freeze.json、source-manifest.json 以及所列 native/matrix/build/plan 证据。
