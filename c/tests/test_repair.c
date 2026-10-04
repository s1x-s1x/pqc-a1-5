/* Private untimed correctness harness. No hooks are exported by release ABI. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdatomic.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"repair FAIL line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
static _Atomic unsigned wipes;static unsigned publications,allocations;
static unsigned candidate_wipes;static uint8_t *last_candidate;static int corrupt_candidate;
static size_t fail_size;
static uint8_t expected_output=0xa5;
static const char *changing_path;
static int truncate_cache;
static void zero_observer(void *p,size_t n,int after){if(after){const uint8_t *b=p;for(size_t j=0;j<n;j++)CHECK(!b[j]);wipes++;if(p==last_candidate&&n==2320)candidate_wipes++;}}
static void candidate_observer(uint8_t *out,uint8_t *candidate,size_t n){CHECK(out!=candidate);for(size_t j=0;j<n;j++)CHECK(out[j]==expected_output);last_candidate=candidate;if(corrupt_candidate)candidate[0]^=1;publications++;}
static void cache_prealloc(FILE *f){(void)f;if(changing_path){FILE *other=fopen(changing_path,truncate_cache?"wb":"ab");CHECK(other);CHECK(fputc(0x42,other)!=EOF);CHECK(!fclose(other));}}
static void *probe_malloc(size_t n){allocations++;if(n==fail_size)return NULL;return malloc(n);}
static void *probe_calloc(size_t n,size_t m){allocations++;if(n*m==fail_size)return NULL;return calloc(n,m);}
#define SLH_TEST_BUILD 1
#define SLH_TEST_REVERSE_TASKS 1
#define A15_TEST_ZERO_OBSERVER zero_observer
#define A15_TEST_CANDIDATE_OBSERVER candidate_observer
#define A15_TEST_CACHE_PREALLOC cache_prealloc
#define malloc probe_malloc
#define calloc probe_calloc
#include "../src/engine.c"
#undef malloc
#undef calloc

static void midstate(void){
 const size_t sizes[]={0,1,31,32,33,38,54,55,56,63,64,65,118,1110};uint8_t prefix[64]={0},suffix[1110];for(unsigned j=0;j<sizeof suffix;j++)suffix[j]=(uint8_t)(j*19);
 unsigned matches=0;for(unsigned seed_case=0;seed_case<2;seed_case++){
  for(unsigned j=0;j<16;j++)prefix[j]=(uint8_t)(seed_case*j);
  a15_sm3 shared;a15_sm3_init(&shared);a15_sm3_update(&shared,prefix,64);
  #pragma omp parallel for num_threads(4) reduction(+:matches)
  for(unsigned sample=0;sample<112;sample++){size_t size=sizes[sample%14];uint8_t expected[32],actual[32];a15_sm3 full,copy=shared;a15_sm3_init(&full);a15_sm3_update(&full,prefix,64);a15_sm3_update(&full,suffix,size);a15_sm3_final(&full,expected);a15_sm3_update(&copy,suffix,size);a15_sm3_final(&copy,actual);CHECK(!memcmp(expected,actual,32));matches++;}
  CHECK(shared.bytes==64&&shared.used==0);
 }printf("repair midstate full256/boundaries/thread-copy: %u comparisons PASS\n",matches);
}
int main(int argc,char **argv){
 CHECK(argc==2);CHECK(slh_abi_version()==SLH_ABI_VERSION);midstate();
 slh_ctx *c=NULL;uint8_t seed[48],pk[32],sk[64],sig[2322],msg[]={1,2,3};for(unsigned j=0;j<48;j++)seed[j]=(uint8_t)(j+7);
 CHECK(!slh_ctx_new(&c,201,SLH_FLAG_VERIFY_AFTER_SIGN));CHECK(!slh_ctx_set_cache_level(c,10));
 /* Fail the cache allocation after seeds have entered keygen tmp. */
 unsigned before=wipes;fail_size=16;CHECK(slh_keygen_internal(c,pk,sk,seed,seed+16,seed+32)==SLH_ERR_ALLOC);CHECK(wipes>before);fail_size=0;
 CHECK(!slh_keygen_internal(c,pk,sk,seed,seed+16,seed+32));size_t len=999;memset(sig,0xa5,sizeof sig);unsigned calls=allocations;
 CHECK(slh_sign_checked(c,sig+1,2319,&len,msg,sizeof msg,NULL,0,sk,NULL)==SLH_ERR_CAPACITY);CHECK(!len&&calls==allocations);for(unsigned j=0;j<sizeof sig;j++)CHECK(sig[j]==0xa5);
 CHECK(!slh_sign_checked(c,sig+1,2320,&len,msg,sizeof msg,NULL,0,sk,NULL));CHECK(len==2320&&publications==1);CHECK(sig[0]==0xa5&&sig[2321]==0xa5);CHECK(!slh_verify(c,sig+1,len,msg,sizeof msg,NULL,0,pk));
 CHECK(candidate_wipes==1);memset(sig,0xa5,sizeof sig);corrupt_candidate=1;CHECK(slh_sign_checked(c,sig+1,2320,&len,msg,sizeof msg,NULL,0,sk,NULL)==SLH_ERR_FAULT);CHECK(!len&&candidate_wipes==2);for(unsigned j=1;j<=2320;j++)CHECK(!sig[j]);corrupt_candidate=0;
 calls=allocations;CHECK(slh_sign_prehash_checked(c,sig+1,2319,&len,SLH_PREHASH_SM3,(const uint8_t *)1,SIZE_MAX,NULL,0,sk,NULL)==SLH_ERR_CAPACITY);CHECK(!len&&calls==allocations);
 memset(sig,0xa5,sizeof sig);fail_size=2320;CHECK(slh_sign_checked(c,sig+1,2320,&len,msg,sizeof msg,NULL,0,sk,NULL)==SLH_ERR_ALLOC);CHECK(!len);for(unsigned j=1;j<=2320;j++)CHECK(!sig[j]);fail_size=0;
 uint8_t address[32]={0},r1[16],r2[16],a1[64],a2[64];memset(r2,0xa5,16);calls=allocations;
 CHECK(slh_subtree_checked(c,SLH_LEAF_FORS,address,0,4,5,r2,15,a2,64)==SLH_ERR_CAPACITY);CHECK(calls==allocations);for(unsigned j=0;j<16;j++)CHECK(r2[j]==0xa5);
 CHECK(!slh_ctx_set_threads(c,1));CHECK(!slh_subtree_checked(c,SLH_LEAF_FORS,address,0,4,5,r1,16,a1,64));CHECK(!slh_ctx_set_threads(c,4));CHECK(!slh_subtree_checked(c,SLH_LEAF_FORS,address,0,4,5,r2,16,a2,64));CHECK(!memcmp(r1,r2,16)&&!memcmp(a1,a2,64));
 /* Use a larger task split to exercise reversed issue order. */
 CHECK(!slh_ctx_set_threads(c,1));CHECK(slh_subtree_checked(c,SLH_LEAF_FORS,address,0,8,5,r1,16,NULL,0)==SLH_ERR_PARAM);
 uint8_t path1[128],path2[128];CHECK(!slh_subtree_checked(c,SLH_LEAF_FORS,address,0,8,5,r1,16,path1,128));CHECK(!slh_ctx_set_threads(c,4));CHECK(!slh_subtree_checked(c,SLH_LEAF_FORS,address,0,8,5,r2,16,path2,128));CHECK(!memcmp(r1,r2,16)&&!memcmp(path1,path2,128));
 CHECK(!slh_cache_save(c,argv[1]));CHECK(!slh_cache_load(c,argv[1],pk));changing_path=argv[1];CHECK(slh_cache_load(c,argv[1],pk)==SLH_ERR_CACHE);changing_path=NULL;CHECK(!slh_cache_save(c,argv[1]));
 changing_path=argv[1];truncate_cache=1;CHECK(slh_cache_load(c,argv[1],pk)==SLH_ERR_CACHE);changing_path=NULL;truncate_cache=0;CHECK(!slh_cache_save(c,argv[1]));
 /* Wrong exact file size must be rejected before node allocation. */
 FILE *bad=fopen(argv[1],"ab");CHECK(bad);CHECK(fputc(0,bad)!=EOF);CHECK(!fclose(bad));calls=allocations;CHECK(slh_cache_load(c,argv[1],pk)==SLH_ERR_CACHE);CHECK(calls==allocations);unlink(argv[1]);
 slh_ctx_free(c);printf("repair capacities/private-publication/reordered-tasks/changing-cache/failure-wipes: PASS; %u observed wipes\n",wipes);return 0;
}
