/* Ordinary builds explicitly reject backend 5 rather than relabel CPU work. */
#include "sm3_cuda.h"
#include <string.h>
int a15_cuda_available(void){return 0;}
int a15_cuda_info(slh_cuda_info *out){if(!out)return SLH_ERR_PARAM;memset(out,0,sizeof *out);out->device=-1;return SLH_ERR_BACKEND;}
int a15_cuda_stats_reset(int timing_enabled){return timing_enabled==0||timing_enabled==1?SLH_ERR_BACKEND:SLH_ERR_PARAM;}
int a15_cuda_stats_get(slh_cuda_stats *out){if(!out)return SLH_ERR_PARAM;memset(out,0,sizeof *out);return SLH_ERR_BACKEND;}
int a15_cuda_sm3(const uint8_t *messages,size_t stride,size_t length,size_t count,uint8_t *digests){(void)messages;(void)stride;(void)length;(void)count;(void)digests;return SLH_ERR_BACKEND;}
int a15_cuda_fors_tree(const uint32_t seed[8],const uint8_t skseed[16],const uint8_t adrs[32],uint32_t start,unsigned height,uint32_t target,uint8_t root[16],uint8_t *auth,unsigned fault_site,uint32_t fault_index){(void)seed;(void)skseed;(void)adrs;(void)start;(void)height;(void)target;(void)root;(void)auth;(void)fault_site;(void)fault_index;return SLH_ERR_BACKEND;}
