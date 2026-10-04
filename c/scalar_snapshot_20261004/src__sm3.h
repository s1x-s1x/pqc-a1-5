#ifndef A15_SM3_H
#define A15_SM3_H
#include <stddef.h>
#include <stdint.h>
typedef struct { uint32_t h[8]; uint64_t bytes; size_t used; uint8_t buf[64]; } a15_sm3;
void a15_sm3_init(a15_sm3 *s);
void a15_sm3_update(a15_sm3 *s, const void *p, size_t n);
void a15_sm3_final(a15_sm3 *s, uint8_t out[32]);
#endif
