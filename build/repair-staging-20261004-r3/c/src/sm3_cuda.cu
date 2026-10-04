/* B1 CUDA SM3/FORS. Built only on explicit CUDA=1. No CPU fallback here. */
#include "sm3_cuda.h"
#include "sm3_cuda_device.cuh"
#include <cuda_runtime.h>
#include <mutex>
#include <cstring>
#include <limits>
#ifdef SLH_TEST_FAULT_POINT
#ifndef SLH_TEST_BUILD
#error SLH_TEST_FAULT_POINT requires SLH_TEST_BUILD
#endif
#endif
#if defined(SLH_RELEASE_BUILD) && defined(SLH_TEST_BUILD)
#error Release library must not include SLH_TEST_BUILD
#endif
#ifdef SLH_TEST_BUILD
#if SLH_TEST_FAULT_POINT < 0 || SLH_TEST_FAULT_POINT > 5
#error Invalid SLH_TEST_FAULT_POINT
#endif
#endif
static std::mutex cuda_mutex;
static slh_cuda_stats statistics={};
static int cuda_status(cudaError_t rc){return rc==cudaSuccess?SLH_OK:rc==cudaErrorMemoryAllocation?SLH_ERR_ALLOC:SLH_ERR_BACKEND;}
static int select_device(){int count=0;if(cudaGetDeviceCount(&count)!=cudaSuccess||!count)return SLH_ERR_BACKEND;return cuda_status(cudaSetDevice(0));}
struct cuda_buffer {
 uint8_t *p;size_t bytes;
 explicit cuda_buffer(size_t n):p(nullptr),bytes(n){}
 int allocate(){return bytes?cuda_status(cudaMalloc((void**)&p,bytes)):SLH_OK;}
 int clear_release(){if(!p)return 0;int rc=cuda_status(cudaMemset(p,0,bytes));if(!rc)rc=cuda_status(cudaDeviceSynchronize());
  /* If zeroing fails, keep ownership for destructor retry. Never turn a failed
   * cleanup into an operation success or silently free uncleared secret data. */
  if(rc)return rc;rc=cuda_status(cudaFree(p));if(!rc)p=nullptr;return rc;
 }
 ~cuda_buffer(){if(p){cudaMemset(p,0,bytes);cudaDeviceSynchronize();cudaFree(p);}}
};
struct kernel_clock {
 cudaEvent_t before=nullptr,after=nullptr;int rc=0;
 kernel_clock(){if(statistics.timing_enabled){rc=cuda_status(cudaEventCreate(&before));if(!rc)rc=cuda_status(cudaEventCreate(&after));if(!rc)rc=cuda_status(cudaEventRecord(before));}}
 int finish(){if(rc)return rc;int result=cuda_status(cudaGetLastError());if(result)return result;
  if(statistics.timing_enabled){result=cuda_status(cudaEventRecord(after));if(!result)result=cuda_status(cudaEventSynchronize(after));float ms=0;if(!result)result=cuda_status(cudaEventElapsedTime(&ms,before,after));if(!result)statistics.kernel_ns+=(uint64_t)(ms*1000000.0);}
  else result=cuda_status(cudaDeviceSynchronize());
  if(!result)statistics.kernel_launches++;return result;
 }
 ~kernel_clock(){if(before)cudaEventDestroy(before);if(after)cudaEventDestroy(after);}
};
static int download(void *out,const uint8_t *input,size_t bytes){int rc=cuda_status(cudaMemcpy(out,input,bytes,cudaMemcpyDeviceToHost));if(!rc)statistics.d2h_bytes+=bytes;return rc;}
__global__ void sm3_kernel(const uint8_t *messages,size_t stride,size_t length,size_t count,uint8_t *out){size_t i=(size_t)blockIdx.x*blockDim.x+threadIdx.x;if(i<count)cuda_sm3_hash(messages+i*stride,length,out+32*i);}
__global__ void fors_leaf_kernel(a15_cuda_job job,uint32_t count,uint8_t *nodes){uint32_t i=blockIdx.x*blockDim.x+threadIdx.x;if(i<count)cuda_fors_leaf(job,i,nodes+16*i);}
__global__ void fors_reduce_kernel(a15_cuda_job job,unsigned height,uint32_t count,const uint8_t *input,uint8_t *out){uint32_t i=blockIdx.x*blockDim.x+threadIdx.x;if(i<count)cuda_fors_parent(job,height,i,input,out+16*i);}
extern "C" int a15_cuda_available(void){std::lock_guard<std::mutex> hold(cuda_mutex);return select_device()==0;}
extern "C" int a15_cuda_info(slh_cuda_info *out){if(!out)return SLH_ERR_PARAM;std::lock_guard<std::mutex> hold(cuda_mutex);std::memset(out,0,sizeof *out);out->device=-1;int rc=select_device();if(rc)return rc;cudaDeviceProp properties;
 rc=cuda_status(cudaGetDeviceProperties(&properties,0));if(rc)return rc;out->device=0;out->compute_major=properties.major;out->compute_minor=properties.minor;out->total_memory=properties.totalGlobalMem;
 std::strncpy(out->name,properties.name,sizeof out->name-1);rc=cuda_status(cudaRuntimeGetVersion(&out->runtime_version));if(!rc)rc=cuda_status(cudaDriverGetVersion(&out->driver_version));return rc;
}
extern "C" int a15_cuda_stats_reset(int enabled){if(enabled!=0&&enabled!=1)return SLH_ERR_PARAM;std::lock_guard<std::mutex> hold(cuda_mutex);int rc=select_device();if(rc)return rc;std::memset(&statistics,0,sizeof statistics);statistics.timing_enabled=enabled;return 0;}
extern "C" int a15_cuda_stats_get(slh_cuda_stats *out){if(!out)return SLH_ERR_PARAM;std::lock_guard<std::mutex> hold(cuda_mutex);int rc=select_device();if(rc){std::memset(out,0,sizeof *out);return rc;}*out=statistics;return 0;}
extern "C" int a15_cuda_sm3(const uint8_t *messages,size_t stride,size_t length,size_t count,uint8_t *digests){
 if(!count||!digests||(!messages&&length)||stride<length||count>(size_t(1)<<20)||length>(size_t(1)<<24)||(count-1&&stride>(std::numeric_limits<size_t>::max()-length)/(count-1)))return SLH_ERR_PARAM;
 std::lock_guard<std::mutex> hold(cuda_mutex);int rc=select_device();if(rc)return rc;size_t input_bytes=(count-1)*stride+length;cuda_buffer input(input_bytes?input_bytes:1),output(count*32);
 rc=[&](){int result=input.allocate();if(!result)result=output.allocate();if(result)return result;
  if(input_bytes){result=cuda_status(cudaMemcpy(input.p,messages,input_bytes,cudaMemcpyHostToDevice));if(result)return result;statistics.h2d_bytes+=input_bytes;}
  {kernel_clock clock;if(clock.rc)return clock.rc;sm3_kernel<<<(unsigned)((count+127)/128),128>>>(input.p,stride,length,count,output.p);result=clock.finish();}if(result)return result;
  statistics.device_hashes+=count;return download(digests,output.p,count*32);
 }();int cleanup=input.clear_release();if(!rc)rc=cleanup;cleanup=output.clear_release();if(!rc)rc=cleanup;if(rc)std::memset(digests,0,count*32);return rc;
}
extern "C" int a15_cuda_fors_tree(const uint32_t seed[8],const uint8_t skseed[16],const uint8_t adrs[32],uint32_t start,unsigned height,uint32_t target,uint8_t root[16],uint8_t *auth,unsigned fault_site,uint32_t fault_index){
 if(!seed||!skseed||!adrs||!root||height>24||start&((1u<<height)-1)||(uint64_t)start+(uint64_t(1)<<height)>UINT64_C(0x100000000)||(target!=UINT32_MAX&&(target<start||(uint64_t)target>=(uint64_t)start+(uint64_t(1)<<height)||(height&&!auth))))return SLH_ERR_PARAM;
 std::lock_guard<std::mutex> hold(cuda_mutex);int rc=select_device();if(rc)return rc;const uint32_t leaves=1u<<height;cuda_buffer first((size_t)leaves*16),second((size_t)(leaves>1?leaves/2:1)*16),secret(16);
 /* A dedicated seed allocation owns its lifetime. Kernel parameters carry a
  * device pointer rather than copying the seed into the launch parameter area. */
 rc=[&](){int result=first.allocate();if(!result)result=second.allocate();if(!result)result=secret.allocate();if(result)return result;
 result=cuda_status(cudaMemcpy(secret.p,skseed,16,cudaMemcpyHostToDevice));if(result)return result;statistics.h2d_bytes+=16;
 a15_cuda_job job={};std::memcpy(job.seed,seed,sizeof job.seed);job.skseed=secret.p;std::memcpy(job.adrs,adrs,32);job.start=start;
#ifdef SLH_TEST_BUILD
 job.fault_site=fault_site;job.fault_index=fault_index;
#else
 (void)fault_site;(void)fault_index;
#endif
  {kernel_clock clock;if(clock.rc)return clock.rc;fors_leaf_kernel<<<(leaves+127)/128,128>>>(job,leaves,first.p);result=clock.finish();}if(result)return result;
 statistics.device_hashes+=(uint64_t)leaves*2;uint8_t *current=first.p,*next=second.p;uint32_t count=leaves;
 for(unsigned level=0;level<height;level++){
   if(target!=UINT32_MAX&&auth){uint32_t sibling=((target>>level)^1u)-(start>>level);result=download(auth+level*16,current+(size_t)sibling*16,16);if(result)return result;}
   count>>=1;{kernel_clock clock;if(clock.rc)return clock.rc;fors_reduce_kernel<<<(count+127)/128,128>>>(job,level+1,count,current,next);result=clock.finish();}if(result)return result;
  statistics.device_hashes+=count;uint8_t *temporary=current;current=next;next=temporary;
 }
  return download(root,current,16);
 }();int cleanup=secret.clear_release();if(!rc)rc=cleanup;cleanup=first.clear_release();if(!rc)rc=cleanup;cleanup=second.clear_release();if(!rc)rc=cleanup;
 if(rc){std::memset(root,0,16);if(target!=UINT32_MAX&&auth)std::memset(auth,0,(size_t)height*16);}return rc;
}
