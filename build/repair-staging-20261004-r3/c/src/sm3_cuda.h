#ifndef A15_SM3_CUDA_H
#define A15_SM3_CUDA_H
#include <stdint.h>
#include <stddef.h>
#include "slhdsa_sm3.h"
#if (defined(__GNUC__) || defined(__clang__)) && !defined(_WIN32)
#define A15_CUDA_PRIVATE __attribute__((visibility("hidden")))
#else
#define A15_CUDA_PRIVATE
#endif
#ifdef __cplusplus
extern "C" {
#endif
/* Internal workers; no testing ABI is exported by the shared library. */
A15_CUDA_PRIVATE int a15_cuda_available(void);
A15_CUDA_PRIVATE int a15_cuda_info(slh_cuda_info *out);
A15_CUDA_PRIVATE int a15_cuda_stats_reset(int timing_enabled);
A15_CUDA_PRIVATE int a15_cuda_stats_get(slh_cuda_stats *out);
A15_CUDA_PRIVATE int a15_cuda_sm3(const uint8_t *messages,size_t stride,size_t length,size_t count,uint8_t *digests);
A15_CUDA_PRIVATE int a15_cuda_fors_tree(const uint32_t seed[8],const uint8_t skseed[16],
    const uint8_t adrs[32],uint32_t start,unsigned height,uint32_t target,
    uint8_t root[16],uint8_t *auth,unsigned fault_site,uint32_t fault_index);
#ifdef __cplusplus
}
#endif
#endif
