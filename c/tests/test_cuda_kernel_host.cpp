/* Arithmetic-only local check; this is not evidence of CUDA execution. */
#include "sm3_cuda_device.cuh"
extern "C" {
#include "sm3.h"
#include "slhdsa_sm3.h"
}
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#define CHECK(x) do{if(!(x)){std::fprintf(stderr,"CUDA arithmetic FAIL line %d: %s\n",__LINE__,#x);std::exit(1);}}while(0)
int main(){
 unsigned comparisons=0;uint8_t input[1030],actual[32],expected[32];for(unsigned j=0;j<sizeof input;j++)input[j]=(uint8_t)(j*37+(j>>3));
 for(unsigned length=0;length<=1025;length++){a15_sm3 s;a15_sm3_init(&s);a15_sm3_update(&s,input+1,length);a15_sm3_final(&s,expected);cuda_sm3_hash(input+1,length,actual);CHECK(!std::memcmp(actual,expected,32));comparisons++;}
 const int pids[]={201,1,2,3};
 for(unsigned pi=0;pi<4;pi++){
  int pid=pids[pi];unsigned a=pid==201?10:pid==1?12:pid==2?6:24,k=pid==1?14:pid==2?33:6;uint8_t sk[64];for(unsigned j=0;j<64;j++)sk[j]=(uint8_t)(j+pi);slh_ctx *ref=nullptr;CHECK(!slh_ctx_new(&ref,pid,SLH_BACKEND_REF));CHECK(!slh_ctx_bind_key(ref,sk));
  a15_cuda_job job={};uint8_t prefix[64]={0};std::memcpy(prefix,sk+32,16);a15_sm3 seed;a15_sm3_init(&seed);a15_sm3_update(&seed,prefix,64);std::memcpy(job.seed,seed.h,32);std::memcpy(job.skseed,sk,16);cuda_put32(job.adrs,pi+5);cuda_put32(job.adrs+8,0x12345678);cuda_put32(job.adrs+12,0x9abcdef0);cuda_put32(job.adrs+20,0x11223344);
  for(unsigned height=0;height<=6;height++){
   if(height>a)continue;job.start=(k<<a)-(1u<<height);std::vector<uint8_t> nodes((1u<<height)*16),next(nodes.size());for(uint32_t i=0;i<(1u<<height);i++)cuda_fors_leaf(job,i,nodes.data()+16*i);
   for(unsigned h=1;h<=height;h++){for(uint32_t i=0;i<(1u<<(height-h));i++)cuda_fors_parent(job,h,i,nodes.data(),next.data()+16*i);nodes.swap(next);}
   CHECK(!slh_subtree(ref,SLH_LEAF_FORS,job.adrs,job.start,height,UINT32_MAX,expected,nullptr));CHECK(!std::memcmp(nodes.data(),expected,16));comparisons++;
  }slh_ctx_free(ref);
 }
 std::printf("CUDA arithmetic host-only: %u SM3/FORS comparisons PASS; real CUDA execution not claimed\n",comparisons);return 0;
}
