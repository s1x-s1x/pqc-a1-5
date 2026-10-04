#ifndef A15_SM3_INCREMENTAL_H
#define A15_SM3_INCREMENTAL_H
#include "sm3x8.h"
#include <stddef.h>
#include <stdint.h>

#ifndef A15_INCREMENTAL_B1
#define A15_INCREMENTAL_B1 0
#endif
#if A15_INCREMENTAL_B1 != 0 && A15_INCREMENTAL_B1 != 1
#error A15_INCREMENTAL_B1 must be 0 or 1
#endif
#ifndef A15_INCREMENTAL_MODE
#define A15_INCREMENTAL_MODE 0
#endif
#if A15_INCREMENTAL_MODE < 0 || A15_INCREMENTAL_MODE > 4
#error A15_INCREMENTAL_MODE must be 0, F8=1, A8=2, F1=3, or AF=4
#endif

enum a15_sm3i_mode { A15_SM3I_F8=1, A15_SM3I_A8=2,
    A15_SM3I_F1=3, A15_SM3I_AF=4 };

/* The union reserves 2176 B in every object. F1/AF use only its first 272 B
 * for secret U; the rest remains zero. Public offsets/deltas are shared. */
typedef struct {
    uint32_t seed[8];
    uint8_t adrs[32], skseed[16];
    uint32_t start, step, batches;
    unsigned q, mode, b1, ready;
    const uint32_t (*offsets)[8];
    const uint32_t (*deltas)[68];
    union { uint32_t w8[68][8]; uint32_t u[68]; } secret;
} a15_sm3i_stream;

/* Numeric big-endian words of ADRSc || input || padding || length. */
A15_INTERNAL int a15_sm3i_layout_words(const uint8_t adrs[32],
    const uint8_t *input,size_t input_bytes,uint32_t words[16]);
/* B1 changes layout only. Full expansion and the same read-only rounds follow.
 * Every lane has a defined 16/32-byte input and its own complete address. */
A15_INTERNAL int a15_sm3i_thash8(const uint32_t seed[8],
    const uint8_t adrs[8][32],const uint8_t *inputs[8],size_t input_bytes,
    unsigned b1,uint8_t out[8][16]);

/* Return 1=ready, 0=generic fallback (q=0 or no AVX2), -1=invalid.
 * pid3/a24/k6 only; adrs is copied and its type/height/index normalized to PRF.
 * The forest index is absolute, in [0,6*2^24). Inputs must not alias stream.
 * All shifts/bounds are widened before checking. Re-init clears old secrets. */
A15_INTERNAL int a15_sm3i_init(a15_sm3i_stream *stream,
    const uint32_t seed[8],const uint8_t adrs[32],const uint8_t skseed[16],
    uint32_t start,unsigned z,unsigned pid,unsigned a,unsigned k,
    unsigned mode,unsigned b1);
/* consume preserves the entire stream byte-for-byte. output must not alias it.
 * advance updates only the next schedule, or clears an exhausted stream.
 * next combines both and returns 1 for each emitted batch, including the last. */
A15_INTERNAL int a15_sm3i_consume(const a15_sm3i_stream *stream,
    uint8_t out[8][16]);
A15_INTERNAL int a15_sm3i_advance(a15_sm3i_stream *stream);
A15_INTERNAL int a15_sm3i_next(a15_sm3i_stream *stream,uint8_t out[8][16]);
A15_INTERNAL void a15_sm3i_clear(a15_sm3i_stream *stream);

#ifdef SLH_TEST_BUILD
/* Diagnostic interfaces are omitted from production builds. No timing hooks. */
A15_INTERNAL void a15_sm3i_test_expand8(const uint32_t words[16][8],
    uint32_t w[68][8]);
A15_INTERNAL void a15_sm3i_test_rounds8(const uint32_t seed[8],
    const uint32_t w[68][8],uint8_t out[8][32]);
A15_INTERNAL int a15_sm3i_test_consume256(const a15_sm3i_stream *stream,
    uint8_t out[8][32]);
A15_INTERNAL int a15_sm3i_test_snapshot(const a15_sm3i_stream *stream,
    uint32_t w[68][8],uint32_t wp[64][8]);
A15_INTERNAL int a15_sm3i_test_seek(a15_sm3i_stream *stream,uint32_t step);
A15_INTERNAL const uint32_t (*a15_sm3i_test_offsets(unsigned q))[8];
#endif
#endif
