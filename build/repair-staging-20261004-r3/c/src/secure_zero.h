#ifndef A15_SECURE_ZERO_H
#define A15_SECURE_ZERO_H
#include <stddef.h>
#include <string.h>
/* The compiler barrier keeps memset stores even when the object is dead.
 * Unlike byte-at-a-time volatile stores, fixed-size buffers can use vector
 * stores. This clears addressable memory, not hardware register/stack spills. */
static inline void a15_secure_zero(void *p,size_t n) {
#ifdef A15_TEST_ZERO_OBSERVER
#ifndef SLH_TEST_BUILD
#error Zero observer requires a standalone SLH_TEST_BUILD
#endif
 A15_TEST_ZERO_OBSERVER(p,n,0);
#endif
#if defined(__GNUC__) || defined(__clang__)
 memset(p,0,n);__asm__ __volatile__("" : : "r"(p) : "memory");
#else
 volatile unsigned char *b=(volatile unsigned char *)p;while(n--)*b++=0;
#endif
#ifdef A15_TEST_ZERO_OBSERVER
 A15_TEST_ZERO_OBSERVER(p,n,1);
#endif
}
#endif
