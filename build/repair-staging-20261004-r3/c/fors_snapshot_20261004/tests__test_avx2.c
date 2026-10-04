#include "slhdsa_sm3.h"
#include "sm3.h"
#include "sm3x8.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define CHECK(x) do {if(!(x)){fprintf(stderr,"AVX2 FAIL line %d: %s\n",__LINE__,#x);exit(1);}} while(0)
static uint32_t random_state=0x31415926;
static uint32_t next(void){random_state^=random_state<<13;random_state^=random_state>>17;random_state^=random_state<<5;return random_state;}
static void put32(uint8_t *p,uint32_t x){p[0]=x>>24;p[1]=x>>16;p[2]=x>>8;p[3]=x;}
static void hash_tests(void){
 if(!a15_sm3_avx2_available()){puts("AVX2 worker unavailable: direct SIMD checks skipped; portable backend checks remain");return;}
 unsigned checks=0;for(unsigned batch=0;batch<256;batch++){
  uint8_t prefix[64],storage[513],output[130],expect[8][16];uint8_t (*blocks)[64]=(uint8_t (*)[64])(void *)(storage+1);uint8_t (*actual)[16]=(uint8_t (*)[16])(void *)(output+1);for(unsigned j=0;j<64;j++)prefix[j]=(uint8_t)next();a15_sm3 seeded;a15_sm3_init(&seeded);a15_sm3_update(&seeded,prefix,64);size_t len=batch&1?54:38;
  memset(output,0xa5,sizeof output);memset(storage,0x5a,sizeof storage);for(unsigned lane=0;lane<8;lane++){
   uint8_t input[54],digest[32];for(unsigned j=0;j<len;j++)input[j]=(uint8_t)next();memset(blocks[lane],0,64);memcpy(blocks[lane],input,len);blocks[lane][len]=0x80;uint64_t bits=(64+len)*8;for(unsigned j=0;j<8;j++)blocks[lane][63-j]=(uint8_t)(bits>>(8*j));
   a15_sm3 scalar=seeded;a15_sm3_update(&scalar,input,len);a15_sm3_final(&scalar,digest);memcpy(expect[lane],digest,16);
  }
  a15_sm3x8_final_blocks(seeded.h,blocks,actual);CHECK(!memcmp(actual,expect,sizeof expect));CHECK(output[0]==0xa5&&output[129]==0xa5&&storage[0]==0x5a);checks+=8;
  /* Arbitrary non-padding blocks stress all message schedule words and IVs. */
  uint32_t seed[8];for(unsigned j=0;j<8;j++)seed[j]=next();for(unsigned lane=0;lane<8;lane++){uint32_t state[8];for(unsigned j=0;j<64;j++)blocks[lane][j]=(uint8_t)next();memcpy(state,seed,sizeof state);a15_sm3_compress_block(state,blocks[lane]);for(unsigned j=0;j<4;j++)put32(expect[lane]+j*4,state[j]);}
  a15_sm3x8_final_blocks(seed,blocks,actual);CHECK(!memcmp(actual,expect,sizeof expect));checks+=8;
 }
 printf("SM3 AVX2 seeded PRF/F/H + arbitrary compression, unaligned buffers: %u lane comparisons PASS\n",checks);
}
#ifndef SLH_AVX2_HASH_ONLY
static void subtree_tests(void){
 const int pids[]={201,1,2,3};const unsigned heights[]={0,1,2,3,4,5,8,10,12};unsigned cases=0;
 for(unsigned parameter=0;parameter<4;parameter++){
  int pid=pids[parameter];unsigned a=pid==201?10:pid==1?12:pid==2?6:24,k=pid==201||pid==3?6:pid==1?14:33;slh_ctx *ref=NULL,*avx=NULL;uint8_t sk[64],base[32]={0};for(unsigned j=0;j<64;j++)sk[j]=(uint8_t)(j+parameter);CHECK(!slh_ctx_new(&ref,pid,SLH_BACKEND_REF));CHECK(!slh_ctx_new(&avx,pid,SLH_BACKEND_AVX2));CHECK(!slh_ctx_bind_key(ref,sk));CHECK(!slh_ctx_bind_key(avx,sk));put32(base+16,3);put32(base+20,0x112233);put32(base+8,0x01234567);put32(base+12,0x89abcdef);
  for(unsigned height=0;height<sizeof heights/sizeof *heights;height++){
   unsigned z=heights[height];if(z>a)continue;uint32_t start=((k-1)<<a)+(1u<<a)-(1u<<z);for(unsigned choice=0;choice<3;choice++){
    uint32_t target=start+(choice==0?0:choice==1?(1u<<z)-1:(1u<<z)/2);if(!z)target=start;uint8_t expected[16],expected_auth[24*16];slh_counters rc,vc;slh_counters_reset();CHECK(!slh_subtree(ref,SLH_LEAF_FORS,base,start,z,target,expected,expected_auth));slh_counters_get(&rc);
    const int threads[]={1,4};for(unsigned ti=0;ti<2;ti++){
     uint8_t root[18],auth[24*16+2],only[16],original[32];memcpy(original,base,32);memset(root,0xa5,sizeof root);memset(auth,0xa5,sizeof auth);CHECK(!slh_ctx_set_threads(avx,threads[ti]));slh_counters_reset();CHECK(!slh_subtree(avx,SLH_LEAF_FORS,base,start,z,target,root+1,auth+1));slh_counters_get(&vc);CHECK(!memcmp(&rc,&vc,sizeof rc));CHECK(!memcmp(root+1,expected,16)&&!memcmp(auth+1,expected_auth,z*16));CHECK(root[0]==0xa5&&root[17]==0xa5&&auth[0]==0xa5);for(size_t j=z*16+1;j<sizeof auth;j++)CHECK(auth[j]==0xa5);CHECK(!memcmp(original,base,32));CHECK(!slh_subtree(avx,SLH_LEAF_FORS,base,start,z,UINT32_MAX,only,NULL));CHECK(!memcmp(only,expected,16));cases++;
    }
   }
  }
  slh_ctx_free(ref);slh_ctx_free(avx);
 }
 printf("FORS AVX2 absolute addresses/heights/chunking/auth/root-only/guards/counters: %u comparisons PASS\n",cases);
}
static void signing_tests(void){
 const int pids[]={201,1,2};const int threads[]={1,4};uint8_t seed[48],msg[]={0x61,0,0xff,0x20},context[]={0,7,0x80},rnd[16];for(unsigned j=0;j<48;j++)seed[j]=(uint8_t)(j+33);for(unsigned j=0;j<16;j++)rnd[j]=(uint8_t)(j*17);unsigned cases=0;
 for(unsigned pi=0;pi<3;pi++){
  int pid=pids[pi];slh_ctx *ref=NULL,*avx=NULL;uint8_t pk[32],sk[64],pk2[32],sk2[64];size_t size=slh_sig_bytes(pid),len=0;uint8_t *expected=malloc(size),*actual=malloc(size);CHECK(expected&&actual);CHECK(!slh_ctx_new(&ref,pid,SLH_BACKEND_REF|SLH_FLAG_VERIFY_AFTER_SIGN));CHECK(!slh_ctx_new(&avx,pid,SLH_BACKEND_AVX2|SLH_FLAG_VERIFY_AFTER_SIGN));CHECK(!slh_ctx_set_threads(avx,4));CHECK(!slh_keygen_internal(ref,pk,sk,seed,seed+16,seed+32));CHECK(!slh_keygen_internal(avx,pk2,sk2,seed,seed+16,seed+32));CHECK(!memcmp(pk,pk2,32)&&!memcmp(sk,sk2,64));
  for(unsigned mode=0;mode<2;mode++){
   slh_counters scalar,vector;const uint8_t *randomizer=mode?rnd:NULL;slh_counters_reset();CHECK(!slh_sign(ref,expected,&len,msg,sizeof msg,context,sizeof context,sk,randomizer));CHECK(len==size);slh_counters_get(&scalar);
   for(unsigned ti=0;ti<2;ti++){
    CHECK(!slh_ctx_set_threads(avx,threads[ti]));slh_counters_reset();CHECK(!slh_sign(avx,actual,&len,msg,sizeof msg,context,sizeof context,sk,randomizer));slh_counters_get(&vector);CHECK(len==size&&!memcmp(actual,expected,size));CHECK(!memcmp(&scalar,&vector,sizeof scalar));CHECK(!slh_verify(ref,actual,len,msg,sizeof msg,context,sizeof context,pk));CHECK(!slh_verify(avx,expected,len,msg,sizeof msg,context,sizeof context,pk));actual[size/2]^=1;CHECK(slh_verify(avx,actual,len,msg,sizeof msg,context,sizeof context,pk)==SLH_ERR_VERIFY);cases++;
   }
  }
  free(expected);free(actual);slh_ctx_free(ref);slh_ctx_free(avx);printf("pid=%d AVX2 full signature/ref/counters/self-check/threads PASS\n",pid);
 }
 printf("AVX2 complete signing comparisons: %u PASS (128-24 uses bounded subtree tests only)\n",cases);
}
static void dispatch_tests(void){
 slh_ctx *c=NULL;CHECK(slh_backend_available(SLH_BACKEND_REF));CHECK(slh_backend_available(SLH_BACKEND_AUTO));CHECK(!slh_backend_available(999));CHECK(slh_ctx_backend(NULL)==SLH_ERR_PARAM);CHECK(!slh_ctx_new(&c,SLH_SHA2_128F,SLH_BACKEND_AUTO));CHECK(slh_ctx_backend(c)==SLH_BACKEND_REF);slh_ctx_free(c);c=NULL;CHECK(slh_ctx_new(&c,SLH_SHA2_128F,SLH_BACKEND_AVX2)==SLH_ERR_BACKEND&&c==NULL);CHECK(slh_ctx_new(&c,201,SLH_BACKEND_AVX512)==SLH_ERR_BACKEND&&c==NULL);
 CHECK(!slh_ctx_new(&c,201,SLH_BACKEND_AUTO));CHECK(slh_ctx_backend(c)==(slh_backend_available(SLH_BACKEND_AVX2)?SLH_BACKEND_AVX2:SLH_BACKEND_REF));slh_ctx_free(c);c=NULL;
 if(!slh_backend_available(SLH_BACKEND_AVX2))CHECK(slh_ctx_new(&c,201,SLH_BACKEND_AVX2)==SLH_ERR_BACKEND&&c==NULL);
 puts("runtime CPU/OS detection; SHA2 REF; unavailable explicit backend rejection PASS");
}
#endif
int main(void){hash_tests();
#ifndef SLH_AVX2_HASH_ONLY
 dispatch_tests();if(slh_backend_available(SLH_BACKEND_AVX2)){subtree_tests();signing_tests();}else puts("AVX2 engine execution skipped: runtime support absent");
#endif
 puts("AVX2 checks PASS");return 0;
}
