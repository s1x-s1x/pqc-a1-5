#include "slhdsa_sm3.h"
#include "sm3.h"
#include "sm3_cuda.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"CUDA FAIL line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
static void put32(uint8_t *p,uint32_t x){p[0]=x>>24;p[1]=x>>16;p[2]=x>>8;p[3]=x;}
static void count_equal(const slh_counters *a,const slh_counters *b){CHECK(!memcmp(a,b,sizeof *a));}
static void hash_tests(void){
 const unsigned lengths[]={0,1,16,38,54,55,56,63,64,65,127,128,129,1024};const unsigned batches[]={1,7,127,129,257};unsigned comparisons=0;
 for(unsigned i=0;i<sizeof lengths/sizeof *lengths;i++)for(unsigned b=0;b<sizeof batches/sizeof *batches;b++){
  size_t length=lengths[i],count=batches[b],stride=length+3,bytes=(count-1)*stride+length;uint8_t *in=malloc(bytes+2),*out=malloc(count*32+2);CHECK(in&&out);memset(in,0xa5,bytes+2);memset(out,0x5a,count*32+2);
  for(size_t j=0;j<bytes;j++)in[j+1]=(uint8_t)(j*31+(j>>7)+i);CHECK(!a15_cuda_sm3(in+1,stride,length,count,out+1));
  for(size_t j=0;j<count;j++){a15_sm3 s;uint8_t expected[32];a15_sm3_init(&s);a15_sm3_update(&s,in+1+j*stride,length);a15_sm3_final(&s,expected);CHECK(!memcmp(out+1+32*j,expected,32));comparisons++;}
  CHECK(in[0]==0xa5&&in[bytes+1]==0xa5&&out[0]==0x5a&&out[count*32+1]==0x5a);free(in);free(out);
 }
 printf("{\"case\":\"gpu-sm3\",\"comparisons\":%u,\"passed\":true,\"timed\":false}\n",comparisons);
}
static void subtree_tests(void){
 const int pids[]={201,1,2,3};const unsigned heights[]={0,1,3,6,8,10,12};unsigned comparisons=0;
 for(unsigned pi=0;pi<4;pi++){
  int pid=pids[pi];unsigned a=pid==201?10:pid==1?12:pid==2?6:24,k=pid==1?14:pid==2?33:6,hp=pid==201?10:pid==1?9:pid==2?3:22;slh_ctx *ref=NULL,*gpu=NULL;uint8_t sk[64],adrs[32]={0};for(unsigned j=0;j<64;j++)sk[j]=(uint8_t)(j+pi*11);put32(adrs,pi+5);put32(adrs+8,0x12345678);put32(adrs+12,0x9abcdef0);put32(adrs+20,0x11223344);
  CHECK(!slh_ctx_new(&ref,pid,SLH_BACKEND_REF));CHECK(!slh_ctx_new(&gpu,pid,SLH_BACKEND_CUDA));CHECK(slh_ctx_backend(gpu)==5);CHECK(!slh_ctx_bind_key(ref,sk));CHECK(!slh_ctx_bind_key(gpu,sk));
  for(unsigned hi=0;hi<sizeof heights/sizeof *heights;hi++){
   unsigned z=heights[hi];if(z>a)continue;uint32_t start=((k-1)<<a)+(1u<<a)-(1u<<z);put32(adrs+16,3);
   for(unsigned choice=0;choice<3;choice++){
    uint32_t target=choice==0?UINT32_MAX:start+(choice==1?0:(1u<<z)-1);uint8_t expected[16],ea[24*16],root[18],auth[24*16+2],base[32];memcpy(base,adrs,32);slh_counters rc,gc;slh_counters_reset();CHECK(!slh_subtree(ref,SLH_LEAF_FORS,adrs,start,z,target,expected,target==UINT32_MAX?NULL:ea));slh_counters_get(&rc);
    for(unsigned threads=1;threads<=4;threads*=4){CHECK(!slh_ctx_set_threads(gpu,threads));memset(root,0xa5,sizeof root);memset(auth,0x5a,sizeof auth);slh_counters_reset();CHECK(!slh_subtree(gpu,SLH_LEAF_FORS,adrs,start,z,target,root+1,target==UINT32_MAX?NULL:auth+1));slh_counters_get(&gc);count_equal(&rc,&gc);CHECK(!memcmp(expected,root+1,16));if(target!=UINT32_MAX)CHECK(!memcmp(ea,auth+1,z*16));CHECK(!memcmp(adrs,base,32)&&root[0]==0xa5&&root[17]==0xa5&&auth[0]==0x5a);for(size_t j=(target==UINT32_MAX?0:z*16)+1;j<sizeof auth;j++)CHECK(auth[j]==0x5a);comparisons++;}
   }
  }
  /* WOTS is deliberately the CPU part of CUDA B1; guards/counts still match. */
  unsigned z=hp<5?hp:5;uint32_t start=(1u<<hp)-(1u<<z),target=start;uint8_t expected[16],ea[80],actual[16],aa[80];slh_counters rc,gc;slh_cuda_stats before,after;put32(adrs+16,0);slh_counters_reset();CHECK(!slh_subtree(ref,SLH_LEAF_WOTS,adrs,start,z,target,expected,ea));slh_counters_get(&rc);CHECK(!slh_cuda_stats_get(&before));slh_counters_reset();CHECK(!slh_subtree(gpu,SLH_LEAF_WOTS,adrs,start,z,target,actual,aa));slh_counters_get(&gc);CHECK(!slh_cuda_stats_get(&after));CHECK(before.kernel_launches==after.kernel_launches&&before.device_hashes==after.device_hashes);CHECK(!memcmp(expected,actual,16)&&!memcmp(ea,aa,z*16));count_equal(&rc,&gc);comparisons++;
  slh_ctx_free(ref);slh_ctx_free(gpu);
 }
 printf("{\"case\":\"gpu-fors-subtrees-and-hybrid-wots\",\"comparisons\":%u,\"passed\":true,\"timed\":false}\n",comparisons);
}
static void compare_files(const char *x,const char *y){FILE *a=fopen(x,"rb"),*b=fopen(y,"rb");CHECK(a&&b);for(;;){int c=fgetc(a),d=fgetc(b);CHECK(c==d);if(c==EOF){CHECK(!ferror(a)&&!ferror(b));break;}}CHECK(!fclose(a)&&!fclose(b));}
static void signing_tests(void){
 const int pids[]={201,2};const char *folder=getenv("A15_TEST_CACHE_DIR");if(!folder)folder="../build";char left[512],right[512];CHECK(snprintf(left,sizeof left,"%s/cuda-ref.cache",folder)<(int)sizeof left);CHECK(snprintf(right,sizeof right,"%s/cuda-gpu.cache",folder)<(int)sizeof right);unsigned comparisons=0;
 for(unsigned pi=0;pi<2;pi++){
  int pid=pids[pi];slh_ctx *ref=NULL,*gpu=NULL,*loaded=NULL;uint8_t seed[48],rnd[16],pk[32],sk[64],p2[32],s2[64],msg[]={0,255,1,128},context[]={0,19};for(unsigned j=0;j<48;j++)seed[j]=(uint8_t)(j+pi*37);for(unsigned j=0;j<16;j++)rnd[j]=(uint8_t)(j*13);size_t size=slh_sig_bytes(pid),length=0;uint8_t *expected=malloc(size),*guarded=malloc(size+2);CHECK(expected&&guarded);slh_counters rc,gc;
  CHECK(!slh_ctx_new(&ref,pid,SLH_BACKEND_REF|SLH_FLAG_VERIFY_AFTER_SIGN));CHECK(!slh_ctx_new(&gpu,pid,SLH_BACKEND_CUDA|SLH_FLAG_VERIFY_AFTER_SIGN));CHECK(!slh_ctx_new(&loaded,pid,SLH_BACKEND_CUDA|SLH_FLAG_VERIFY_AFTER_SIGN));CHECK(!slh_ctx_set_threads(gpu,4));slh_counters_reset();CHECK(!slh_keygen_internal(ref,pk,sk,seed,seed+16,seed+32));slh_counters_get(&rc);slh_counters_reset();CHECK(!slh_keygen_internal(gpu,p2,s2,seed,seed+16,seed+32));slh_counters_get(&gc);CHECK(!memcmp(pk,p2,32)&&!memcmp(sk,s2,64));count_equal(&rc,&gc);
  unsigned hp=pid==201?10:3;const unsigned levels[]={0,hp/2,hp};
  for(unsigned li=0;li<3;li++){
   unsigned t=levels[li];slh_counters_reset();CHECK(!slh_cache_build(ref,sk,t));slh_counters_get(&rc);slh_counters_reset();CHECK(!slh_cache_build(gpu,sk,t));slh_counters_get(&gc);count_equal(&rc,&gc);CHECK(!slh_cache_save(ref,left)&&!slh_cache_save(gpu,right));compare_files(left,right);slh_counters_reset();CHECK(!slh_cache_load(ref,left,pk));slh_counters_get(&rc);slh_counters_reset();CHECK(!slh_cache_load(loaded,left,pk));slh_counters_get(&gc);count_equal(&rc,&gc);
   for(unsigned randomized=0;randomized<2;randomized++){
    slh_counters_reset();CHECK(!slh_sign(ref,expected,&length,msg,sizeof msg,context,sizeof context,sk,randomized?rnd:NULL));CHECK(length==size);slh_counters_get(&rc);memset(guarded,0xa5,size+2);slh_counters_reset();CHECK(!slh_sign(loaded,guarded+1,&length,msg,sizeof msg,context,sizeof context,sk,randomized?rnd:NULL));slh_counters_get(&gc);CHECK(length==size&&!memcmp(expected,guarded+1,size));CHECK(guarded[0]==0xa5&&guarded[size+1]==0xa5);count_equal(&rc,&gc);CHECK(!slh_verify(gpu,expected,size,msg,sizeof msg,context,sizeof context,pk));guarded[1+size/2]^=1;CHECK(slh_verify(gpu,guarded+1,size,msg,sizeof msg,context,sizeof context,pk)==SLH_ERR_VERIFY);comparisons++;
   }
  }
  if(pid==201){uint8_t wrong[64];memcpy(wrong,sk,64);wrong[63]^=1;memset(guarded,0xa5,size+2);length=1;CHECK(slh_sign(gpu,guarded+1,&length,msg,sizeof msg,context,sizeof context,wrong,NULL)==SLH_ERR_FAULT);CHECK(!length);for(size_t j=1;j<=size;j++)CHECK(!guarded[j]);CHECK(guarded[0]==0xa5&&guarded[size+1]==0xa5);}
  free(expected);free(guarded);slh_ctx_free(ref);slh_ctx_free(gpu);slh_ctx_free(loaded);
 }
 CHECK(!remove(left)&&!remove(right));printf("{\"case\":\"gpu-full-signatures-cache-randomized-inputs-and-guards\",\"comparisons\":%u,\"passed\":true,\"timed\":false}\n",comparisons);
}
int main(void){
 slh_ctx *context=NULL;CHECK(slh_ctx_new(&context,SLH_SHA2_128F,SLH_BACKEND_CUDA)==SLH_ERR_BACKEND&&context==NULL);CHECK(!slh_ctx_new(&context,201,SLH_BACKEND_AUTO));CHECK(slh_ctx_backend(context)!=(int)SLH_BACKEND_CUDA);slh_ctx_free(context);context=NULL;
 if(!slh_backend_available(SLH_BACKEND_CUDA)){CHECK(slh_ctx_new(&context,201,SLH_BACKEND_CUDA)==SLH_ERR_BACKEND&&context==NULL);slh_cuda_info info;slh_cuda_stats stats;CHECK(slh_cuda_get_info(&info)==SLH_ERR_BACKEND);CHECK(slh_cuda_stats_get(&stats)==SLH_ERR_BACKEND);puts("{\"passed\":true,\"cuda_available\":false,\"scope\":\"explicit-rejection-only\",\"timed\":false}");return 0;}
 slh_cuda_info info;slh_cuda_stats stats;CHECK(!slh_cuda_get_info(&info));CHECK(info.device==0&&info.compute_major>=1);CHECK(!slh_cuda_stats_reset(0));hash_tests();subtree_tests();signing_tests();CHECK(!slh_cuda_stats_get(&stats));CHECK(stats.kernel_launches>0&&stats.device_hashes>0&&!stats.timing_enabled&&!stats.kernel_ns);
 printf("{\"passed\":true,\"cuda_available\":true,\"actual_backend\":5,\"device\":%d,\"kernel_launches\":%llu,\"device_hashes\":%llu,\"timed\":false}\n",info.device,(unsigned long long)stats.kernel_launches,(unsigned long long)stats.device_hashes);return 0;
}
