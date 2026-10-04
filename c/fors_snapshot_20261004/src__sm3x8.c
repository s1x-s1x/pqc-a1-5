/* Eight independent SM3 instances in AVX2 32-bit lanes. GB/T 32905 rounds.
 * No global -mavx2 flag: only this worker is compiled for AVX2. */
#include "sm3x8.h"
#include "sm3.h"
#include <string.h>

#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__)) && !defined(SLH_DISABLE_AVX2)
#include <immintrin.h>
#define AVX2 __attribute__((target("avx2")))
int a15_sm3_avx2_available(void) { return !!__builtin_cpu_supports("avx2"); }
static AVX2 inline __m256i rv(__m256i x,unsigned n) {
 return _mm256_or_si256(_mm256_sll_epi32(x,_mm_cvtsi32_si128(n)),_mm256_srl_epi32(x,_mm_cvtsi32_si128(32-n)));
}
static uint32_t rs(uint32_t x,unsigned n) {n&=31;return n?(x<<n)|(x>>(32-n)):x;}
static void wr(uint8_t *p,uint32_t x) {p[0]=x>>24;p[1]=x>>16;p[2]=x>>8;p[3]=x;}
AVX2 void a15_sm3x8_final_blocks(const uint32_t seed[8],const uint8_t blocks[8][64],uint8_t out[8][16]) {
 __m256i w[68],initial[8],a,b,c,d,e,f,g,h;
 const __m256i offsets=_mm256_setr_epi32(0,64,128,192,256,320,384,448);
 const __m256i swap=_mm256_setr_epi8(3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12,3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12);
 for(unsigned j=0;j<8;j++)initial[j]=_mm256_set1_epi32((int)seed[j]);
 for(unsigned j=0;j<16;j++)w[j]=_mm256_shuffle_epi8(_mm256_i32gather_epi32((const int *)(const void *)(blocks[0]+4*j),offsets,1),swap);
 for(unsigned j=16;j<68;j++){
  __m256i x=_mm256_xor_si256(_mm256_xor_si256(w[j-16],w[j-9]),rv(w[j-3],15));
  w[j]=_mm256_xor_si256(_mm256_xor_si256(_mm256_xor_si256(x,rv(x,15)),rv(x,23)),_mm256_xor_si256(rv(w[j-13],7),w[j-6]));
 }
 a=initial[0];b=initial[1];c=initial[2];d=initial[3];e=initial[4];f=initial[5];g=initial[6];h=initial[7];
 for(unsigned j=0;j<64;j++){
  __m256i ar=rv(a,12),ss1=rv(_mm256_add_epi32(_mm256_add_epi32(ar,e),_mm256_set1_epi32((int)rs(j<16?0x79cc4519u:0x7a879d8au,j))),7);
  __m256i ff=j<16?_mm256_xor_si256(_mm256_xor_si256(a,b),c):_mm256_or_si256(_mm256_and_si256(a,b),_mm256_and_si256(c,_mm256_or_si256(a,b)));
  __m256i gg=j<16?_mm256_xor_si256(_mm256_xor_si256(e,f),g):_mm256_or_si256(_mm256_and_si256(e,f),_mm256_andnot_si256(e,g));
  __m256i t1=_mm256_add_epi32(_mm256_add_epi32(ff,d),_mm256_add_epi32(_mm256_xor_si256(ss1,ar),_mm256_xor_si256(w[j],w[j+4])));
  __m256i t2=_mm256_add_epi32(_mm256_add_epi32(gg,h),_mm256_add_epi32(ss1,w[j]));
  d=c;c=rv(b,9);b=a;a=t1;h=g;g=rv(f,19);f=e;e=_mm256_xor_si256(_mm256_xor_si256(t2,rv(t2,9)),rv(t2,17));
 }
 __m256i result[4]={a,b,c,d};for(unsigned j=0;j<4;j++){uint32_t lanes[8];_mm256_storeu_si256((__m256i *)(void *)lanes,_mm256_xor_si256(initial[j],result[j]));for(unsigned lane=0;lane<8;lane++)wr(out[lane]+4*j,lanes[lane]);}
}
#else
int a15_sm3_avx2_available(void) {return 0;}
void a15_sm3x8_final_blocks(const uint32_t seed[8],const uint8_t blocks[8][64],uint8_t out[8][16]) {
 for(unsigned lane=0;lane<8;lane++){uint32_t state[8];memcpy(state,seed,sizeof state);a15_sm3_compress_block(state,blocks[lane]);for(unsigned j=0;j<4;j++){uint32_t x=state[j];out[lane][j*4]=x>>24;out[lane][j*4+1]=x>>16;out[lane][j*4+2]=x>>8;out[lane][j*4+3]=x;}}
}
#endif
