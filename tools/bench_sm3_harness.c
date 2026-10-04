/* Separate SM3 compression-block microbenchmark, with an untimed check mode.
 * This reports 8 final compression blocks (512 B), not full-message SM3 MB/s.
 * Normal preparation runs only `check`; `sample` requires an explicit command.
 */
#define _POSIX_C_SOURCE 200809L
#include "sm3.h"
#include "sm3x8.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

static void wr(uint8_t *p,uint32_t x){p[0]=x>>24;p[1]=x>>16;p[2]=x>>8;p[3]=x;}
static uint32_t random32(uint32_t *s){*s=*s*1664525u+1013904223u;return *s;}
static volatile uint32_t sink;
static void scalar8(const uint32_t seed[8],const uint8_t blocks[8][64],uint8_t out[8][16]){
 for(unsigned lane=0;lane<8;lane++){uint32_t state[8];memcpy(state,seed,sizeof state);a15_sm3_compress_block(state,blocks[lane]);for(unsigned j=0;j<4;j++)wr(out[lane]+4*j,state[j]);}
}
static int check(void){
 static const uint8_t abc[32]={0x66,0xc7,0xf0,0xf4,0x62,0xee,0xed,0xd9,0xd1,0xf2,0xd4,0x6b,0xdc,0x10,0xe4,0xe2,0x41,0x67,0xc4,0x87,0x5c,0xf2,0xf7,0xa2,0x29,0x7d,0xa0,0x2b,0x8f,0x4b,0xa8,0xe0};
 a15_sm3 hash;uint8_t digest[32];a15_sm3_init(&hash);a15_sm3_update(&hash,"abc",3);a15_sm3_final(&hash,digest);if(memcmp(digest,abc,32))return 1;
 uint32_t rng=0x41513553u;unsigned comparisons=0;int avx=a15_sm3_avx2_available();
 for(unsigned test=0;test<256;test++){
  uint32_t seed[8];uint8_t blocks[8][64],ref[8][16],vector[8][16];
  for(unsigned j=0;j<8;j++)seed[j]=random32(&rng);
  for(unsigned lane=0;lane<8;lane++)for(unsigned j=0;j<64;j++)blocks[lane][j]=(uint8_t)random32(&rng);
  scalar8(seed,blocks,ref);a15_sm3x8_final_blocks(seed,blocks,vector);
  if(memcmp(ref,vector,sizeof ref))return 2;
  comparisons++;
 }
 printf("{\"schema\":\"a15-sm3-check-v1\",\"passed\":true,\"known_answer\":\"SM3 abc\",\"comparisons\":%u,\"avx2_available\":%s,\"x8_execution\":\"%s\",\"real_timing_samples\":0}\n",comparisons,avx?"true":"false",avx?"AVX2":"portable fallback");return 0;
}
static uint64_t now_ns(void){
#ifdef _WIN32
 LARGE_INTEGER value,frequency;QueryPerformanceCounter(&value);QueryPerformanceFrequency(&frequency);
 uint64_t ticks=(uint64_t)value.QuadPart,hz=(uint64_t)frequency.QuadPart;
 return (ticks/hz)*1000000000ull+(ticks%hz)*1000000000ull/hz;
#else
 struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))exit(3);return (uint64_t)t.tv_sec*1000000000ull+t.tv_nsec;
#endif
}
static int sample(const char *backend,const char *argument){
 errno=0;char *end=NULL;unsigned long groups=strtoul(argument,&end,10);
 if(errno||!end||*end||!groups||groups>100000000ul)return 4;
 int avx=strcmp(backend,"AVX2")==0;if(strcmp(backend,"REF")&& !avx)return 5;if(avx&&!a15_sm3_avx2_available())return 6;
 uint32_t rng=0x41513553u,seed[8];uint8_t blocks[8][64],out[8][16];for(unsigned j=0;j<8;j++)seed[j]=random32(&rng);
 for(unsigned lane=0;lane<8;lane++)for(unsigned j=0;j<64;j++)blocks[lane][j]=(uint8_t)random32(&rng);
 uint64_t start=now_ns();for(unsigned long i=0;i<groups;i++){if(avx)a15_sm3x8_final_blocks(seed,blocks,out);else scalar8(seed,blocks,out);sink^=out[0][i&15u];}uint64_t duration=now_ns()-start;
 if(!duration)return 7;
 printf("{\"schema\":\"a15-sm3-sample-v1\",\"backend\":\"%s\",\"duration_ns\":%llu,\"groups\":%lu,\"compression_blocks\":%llu,\"processed_block_bytes\":%llu,\"scope\":\"8 independent final compression blocks; seed copies and loop/sink included; no full-message claim\",\"checksum\":%u}\n",backend,(unsigned long long)duration,groups,(unsigned long long)groups*8ull,(unsigned long long)groups*512ull,sink);return 0;
}
int main(int argc,char **argv){
 if(argc==2&&!strcmp(argv[1],"check"))return check();
 if(argc==4&&!strcmp(argv[1],"sample"))return sample(argv[2],argv[3]);
 fputs("usage: harness check | harness sample REF|AVX2 GROUPS\n",stderr);return 8;
}
