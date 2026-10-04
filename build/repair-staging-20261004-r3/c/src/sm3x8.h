#ifndef A15_SM3X8_H
#define A15_SM3X8_H
#include <stdint.h>
#if (defined(__GNUC__) || defined(__clang__)) && !defined(_WIN32)
#define A15_INTERNAL __attribute__((visibility("hidden")))
#else
#define A15_INTERNAL
#endif
/* The caller checks availability before dispatch. Both functions themselves
 * have baseline calling conventions, and the detector contains no AVX code. */
A15_INTERNAL int a15_sm3_avx2_available(void);
/* Eight final 64-byte blocks with a common previously compressed seed state.
 * blocks already include padding and the full message bit length. No pointer
 * alignment requirement exists. Outputs truncate the SM3 digest to 16 bytes. */
A15_INTERNAL void a15_sm3x8_final_blocks(const uint32_t seed[8],
    const uint8_t blocks[8][64],uint8_t out[8][16]);
#endif
