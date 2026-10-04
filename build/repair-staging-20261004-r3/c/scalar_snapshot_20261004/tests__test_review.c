#include "slhdsa_sm3.h"
#include "sm3.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#define CHECK(x) do {if(!(x)){fprintf(stderr,"review FAIL line %d: %s\n",__LINE__,#x);exit(1);}} while(0)
static const uint8_t msg[]={0x61,0x62,0x63,0,0xff,0x80,0x20,0x11};
static const uint8_t context[]={0x78,0x79,0x7a};
static void put32(uint8_t *p,uint32_t x){p[0]=x>>24;p[1]=x>>16;p[2]=x>>8;p[3]=x;}
static uint8_t *read_file(const char *path,size_t *len){FILE *f=fopen(path,"rb");CHECK(f);CHECK(!fseek(f,0,SEEK_END));long n=ftell(f);CHECK(n>=0);rewind(f);uint8_t *p=malloc((size_t)n+1);CHECK(p);CHECK(fread(p,1,(size_t)n,f)==(size_t)n);CHECK(!fclose(f));*len=(size_t)n;return p;}
static void write_file(const char *path,const uint8_t *data,size_t len){FILE *f=fopen(path,"wb");CHECK(f);CHECK(fwrite(data,1,len,f)==len);CHECK(!fclose(f));}
static void digest(uint8_t *data,size_t len){a15_sm3 s;CHECK(len>=96);a15_sm3_init(&s);a15_sm3_update(&s,data,64);a15_sm3_update(&s,data+96,len-96);a15_sm3_final(&s,data+64);}
static void preserved(slh_ctx *c,const char *bad,const char *saved,const uint8_t *key,size_t goodlen,const uint8_t *good){
 CHECK(slh_cache_load(c,bad,key)==SLH_ERR_CACHE);CHECK(!slh_cache_save(c,saved));size_t n;uint8_t *actual=read_file(saved,&n);CHECK(n==goodlen&&!memcmp(actual,good,n));free(actual);
}
static void cache_tests(const char *dir,const uint8_t pk[32],const uint8_t sk[64],const uint8_t expected[2320]){
 char goodpath[512],badpath[512],savedpath[512];snprintf(goodpath,sizeof goodpath,"%s/review-good.cache",dir);snprintf(badpath,sizeof badpath,"%s/review-bad.cache",dir);snprintf(savedpath,sizeof savedpath,"%s/review-preserved.cache",dir);
 slh_ctx *c=NULL;CHECK(!slh_ctx_new(&c,201,SLH_FLAG_VERIFY_AFTER_SIGN));CHECK(!slh_ctx_set_threads(c,4));
 for(unsigned t=0;t<=10;t++){
  CHECK(!slh_cache_build(c,sk,t));CHECK(!slh_cache_save(c,goodpath));size_t n;uint8_t *data=read_file(goodpath,&n);CHECK(n==96+16*(1u<<(10-t)));free(data);
  slh_ctx *loaded=NULL;CHECK(!slh_ctx_new(&loaded,201,SLH_FLAG_VERIFY_AFTER_SIGN));CHECK(!slh_cache_load(loaded,goodpath,pk));uint8_t sig[2320];size_t len=0;CHECK(!slh_sign(loaded,sig,&len,msg,sizeof msg,context,sizeof context,sk,NULL));CHECK(len==2320&&!memcmp(sig,expected,2320));slh_ctx_free(loaded);
  /* Boundary cache levels must reject forged payloads even with a fresh
   * checksum. The root-only case performs no upper-layer reconstruction. */
  if(t==0||t==10){data=read_file(goodpath,&n);data[96]^=1;digest(data,n);write_file(badpath,data,n);CHECK(slh_cache_load(c,badpath,pk)==SLH_ERR_CACHE);free(data);}
  printf("toy cache t=%u size=%zu round-trip/signature-byte-equivalence PASS\n",t,n);
 }
 CHECK(!slh_cache_build(c,sk,5));CHECK(!slh_cache_save(c,goodpath));size_t n;uint8_t *good=read_file(goodpath,&n),*bad=malloc(n+1);CHECK(bad);
 const unsigned offsets[]={0,8,12,16,20,24,28,32,48,64};
 for(unsigned i=0;i<sizeof offsets/sizeof *offsets;i++){
  memcpy(bad,good,n);bad[offsets[i]]^=1;write_file(badpath,bad,n);preserved(c,badpath,savedpath,pk,n,good);printf("cache malformed offset %u old-cache-preserved PASS\n",offsets[i]);
 }
 memcpy(bad,good,n);bad[96]^=1;digest(bad,n);write_file(badpath,bad,n);preserved(c,badpath,savedpath,pk,n,good);puts("cache changed layer node + recomputed SM3 checksum rejected by root PASS");
 memcpy(bad,good,n);bad[48]^=1;digest(bad,n);uint8_t wrongroot[32];memcpy(wrongroot,pk,32);wrongroot[16]^=1;write_file(badpath,bad,n);preserved(c,badpath,savedpath,wrongroot,n,good);puts("cache changed claimed root + matching supplied key + recomputed checksum rejected by tree root PASS");
 uint8_t otherkey[32];memcpy(otherkey,pk,32);otherkey[0]^=1;write_file(badpath,good,n);preserved(c,badpath,savedpath,otherkey,n,good);memcpy(otherkey,pk,32);otherkey[16]^=1;preserved(c,badpath,savedpath,otherkey,n,good);puts("cache both public-key halves bound; old-cache-preserved PASS");
 memcpy(bad,good,n);put32(bad+12,101);digest(bad,n);write_file(badpath,bad,n);preserved(c,badpath,savedpath,pk,n,good);puts("cache cross-pid + recomputed checksum rejected PASS");
 const size_t truncations[]={0,8,63,95,96};for(unsigned i=0;i<sizeof truncations/sizeof *truncations;i++){write_file(badpath,good,truncations[i]);preserved(c,badpath,savedpath,pk,n,good);}
 write_file(badpath,good,n-1);preserved(c,badpath,savedpath,pk,n,good);memcpy(bad,good,n);bad[n]=0;write_file(badpath,bad,n+1);preserved(c,badpath,savedpath,pk,n,good);puts("cache truncation/extra-byte rejected old-cache-preserved PASS");
 memcpy(bad,good,n);put32(bad+16,0xffffffff);digest(bad,n);write_file(badpath,bad,n);preserved(c,badpath,savedpath,pk,n,good);puts("cache large t avoids underflow/overshift PASS");
 uint8_t sig[2320];size_t len;CHECK(!slh_sign(c,sig,&len,msg,sizeof msg,context,sizeof context,sk,NULL));CHECK(len==2320&&!memcmp(sig,expected,2320));
 free(good);free(bad);slh_ctx_free(c);
}
static void key_and_signature_tests(const char *dir,const uint8_t pk[32],const uint8_t sk[64],const uint8_t expected[2320]){
 slh_ctx *cached=NULL,*fresh=NULL,*loaded=NULL;uint8_t seed[48],pk2[32],sk2[64],sig[2320],other[2320];size_t len=0;char path[512];snprintf(path,sizeof path,"%s/review-key.cache",dir);
 CHECK(!slh_ctx_new(&cached,201,SLH_FLAG_VERIFY_AFTER_SIGN));CHECK(!slh_ctx_new(&fresh,201,SLH_FLAG_VERIFY_AFTER_SIGN));CHECK(!slh_ctx_new(&loaded,201,SLH_FLAG_VERIFY_AFTER_SIGN));
 for(unsigned j=0;j<48;j++)seed[j]=(uint8_t)(j+11);for(unsigned thread=1;thread<=8;thread*=8){slh_ctx *control=NULL;uint8_t actual_pk[32],actual_sk[64];CHECK(!slh_ctx_new(&control,201,0));CHECK(!slh_ctx_set_threads(control,thread));CHECK(!slh_keygen_internal(control,actual_pk,actual_sk,seed,seed+16,seed+32));CHECK(!memcmp(actual_pk,pk,32)&&!memcmp(actual_sk,sk,64));slh_ctx_free(control);printf("keygen threads=%u pk/sk byte-equivalence PASS\n",thread);}
 CHECK(!slh_cache_build(cached,sk,5));CHECK(!slh_cache_save(cached,path));CHECK(!slh_cache_load(loaded,path,pk));
 uint8_t base[32]={0},r1[16],r2[16];CHECK(slh_subtree(loaded,SLH_LEAF_WOTS,base,0,0,0,r1,NULL)==SLH_ERR_PARAM);CHECK(!slh_ctx_bind_key(loaded,sk));CHECK(!slh_subtree(loaded,SLH_LEAF_WOTS,base,0,0,0,r1,NULL));
 for(unsigned j=0;j<48;j++)seed[j]=(uint8_t)(j+91);CHECK(!slh_keygen_internal(fresh,pk2,sk2,seed,seed+16,seed+32));CHECK(memcmp(pk,pk2,32));CHECK(!slh_sign(fresh,other,&len,msg,sizeof msg,context,sizeof context,sk2,NULL));CHECK(len==sizeof other);
 CHECK(!slh_sign(cached,sig,&len,msg,sizeof msg,context,sizeof context,sk2,NULL));CHECK(len==sizeof sig&&!memcmp(sig,other,sizeof sig));CHECK(!slh_verify(fresh,sig,len,msg,sizeof msg,context,sizeof context,pk2));
 /* Binding changes the subtree key. An unrelated public cache never supplies
  * nodes for signing with another key, before or after a binding operation. */
 CHECK(!slh_ctx_bind_key(cached,sk2));CHECK(!slh_subtree(cached,SLH_LEAF_WOTS,base,0,0,0,r2,NULL));CHECK(memcmp(r1,r2,16));CHECK(!slh_subtree(fresh,SLH_LEAF_WOTS,base,0,0,0,r1,NULL));CHECK(!memcmp(r1,r2,16));
 CHECK(!slh_sign(cached,sig,&len,msg,sizeof msg,context,sizeof context,sk,NULL));CHECK(!memcmp(sig,expected,sizeof sig));
 unsigned threads[]={1,2,4,8};for(unsigned j=0;j<sizeof threads/sizeof *threads;j++){
  CHECK(!slh_ctx_set_threads(cached,threads[j]));CHECK(!slh_ctx_set_threads(loaded,threads[j]));CHECK(!slh_ctx_set_threads(fresh,threads[j]));
  CHECK(!slh_sign(cached,sig,&len,msg,sizeof msg,context,sizeof context,sk,NULL));CHECK(len==sizeof sig&&!memcmp(sig,expected,sizeof sig));CHECK(!slh_sign(loaded,sig,&len,msg,sizeof msg,context,sizeof context,sk,NULL));CHECK(!memcmp(sig,expected,sizeof sig));
  CHECK(!slh_sign(fresh,sig,&len,msg,sizeof msg,context,sizeof context,sk,NULL));CHECK(!memcmp(sig,expected,sizeof sig));printf("signature key binding/cached/loaded/cross-key threads=%u bytes=2320 PASS\n",threads[j]);
 }
 uint8_t malformed[64];memcpy(malformed,sk,64);malformed[0]^=1;memset(sig,0xa5,sizeof sig);len=999;CHECK(slh_sign(cached,sig,&len,msg,sizeof msg,context,sizeof context,malformed,NULL)==SLH_ERR_FAULT);CHECK(!len);for(size_t j=0;j<sizeof sig;j++)CHECK(!sig[j]);
 slh_ctx_free(cached);slh_ctx_free(fresh);slh_ctx_free(loaded);puts("cross-key cache fallback and malformed-secret self-check PASS");
}
static void subtree_case(slh_ctx *c,slh_leaf_type kind,uint8_t base[32],uint32_t start,unsigned z,uint32_t target){
 const unsigned threads[]={1,2,4,8,32};uint8_t root[16],auth[160],original[32];memcpy(original,base,32);CHECK(!slh_ctx_set_threads(c,1));CHECK(!slh_subtree(c,kind,base,start,z,target,root,auth));CHECK(!memcmp(base,original,32));
 for(unsigned i=0;i<sizeof threads/sizeof *threads;i++){
  uint8_t actual[18],path[162],only[18];memset(actual,0xa5,sizeof actual);memset(path,0xa5,sizeof path);memset(only,0xa5,sizeof only);CHECK(!slh_ctx_set_threads(c,threads[i]));
  CHECK(!slh_subtree(c,kind,base,start,z,target,actual+1,path+1));CHECK(!memcmp(actual+1,root,16)&&!memcmp(path+1,auth,z*16));CHECK(actual[0]==0xa5&&actual[17]==0xa5&&path[0]==0xa5);for(size_t j=1+z*16;j<sizeof path;j++)CHECK(path[j]==0xa5);
  CHECK(!slh_subtree(c,kind,base,start,z,UINT32_MAX,only+1,NULL));CHECK(!memcmp(only+1,root,16)&&only[0]==0xa5&&only[17]==0xa5);CHECK(!memcmp(base,original,32));
  if(!z){CHECK(!slh_subtree(c,kind,base,start,z,target,actual+1,NULL));CHECK(!memcmp(actual+1,root,16));}
  printf("%s z=%u start=%u target=%u threads=%u root/auth/root-only/guards PASS\n",kind==SLH_LEAF_FORS?"FORS":"WOTS",z,start,target,threads[i]);
 }
}
static void subtree_tests(const uint8_t sk[64]){
 slh_ctx *c=NULL;CHECK(!slh_ctx_new(&c,201,0));CHECK(!slh_ctx_bind_key(c,sk));uint8_t base[32]={0};
 /* Heights 5 and 8 trigger the chunked OpenMP branch, including subheight=0.
  * Nonzero starts and highest FORS global offset exercise absolute indices. */
 for(unsigned kind=0;kind<2;kind++)for(unsigned test=0;test<3;test++){
  unsigned z=test==2?5:8;uint32_t start=kind?((5u<<10)+(test==2?32u:256u)):(test==2?32u:256u);uint32_t target=start+(test==0?0:((1u<<z)-1));
  put32(base+16,kind?3:0);put32(base+20,kind?777:0);subtree_case(c,(slh_leaf_type)kind,base,start,z,target);
 }
 const unsigned boundary_z[]={0,1,4,10};for(unsigned kind=0;kind<2;kind++)for(unsigned j=0;j<sizeof boundary_z/sizeof *boundary_z;j++){
  unsigned z=boundary_z[j];uint32_t end=kind?6144:1024,start=end-(1u<<z);put32(base+16,kind?3:0);put32(base+20,kind?777:0);subtree_case(c,(slh_leaf_type)kind,base,start,z,end-1);
 }
 uint8_t root[16],auth[160];memset(root,0xa5,sizeof root);memset(auth,0xa5,sizeof auth);
 CHECK(slh_subtree(NULL,SLH_LEAF_WOTS,base,0,0,0,root,NULL)==SLH_ERR_PARAM);CHECK(slh_subtree(c,(slh_leaf_type)2,base,0,0,0,root,NULL)==SLH_ERR_PARAM);CHECK(slh_subtree(c,SLH_LEAF_WOTS,NULL,0,0,0,root,NULL)==SLH_ERR_PARAM);CHECK(slh_subtree(c,SLH_LEAF_WOTS,base,0,0,0,NULL,NULL)==SLH_ERR_PARAM);
 CHECK(slh_subtree(c,SLH_LEAF_WOTS,base,0,11,0,root,auth)==SLH_ERR_PARAM);CHECK(slh_subtree(c,SLH_LEAF_FORS,base,0,11,0,root,auth)==SLH_ERR_PARAM);CHECK(slh_subtree(c,SLH_LEAF_WOTS,base,0,UINT32_MAX,0,root,auth)==SLH_ERR_PARAM);
 CHECK(slh_subtree(c,SLH_LEAF_FORS,base,6144,0,6144,root,NULL)==SLH_ERR_PARAM);CHECK(slh_subtree(c,SLH_LEAF_WOTS,base,1024,0,1024,root,NULL)==SLH_ERR_PARAM);CHECK(slh_subtree(c,SLH_LEAF_FORS,base,UINT32_MAX,0,UINT32_MAX,root,NULL)==SLH_ERR_PARAM);
 CHECK(slh_subtree(c,SLH_LEAF_WOTS,base,1,5,1,root,auth)==SLH_ERR_PARAM);CHECK(slh_subtree(c,SLH_LEAF_WOTS,base,0,5,32,root,auth)==SLH_ERR_PARAM);CHECK(slh_subtree(c,SLH_LEAF_WOTS,base,32,5,31,root,auth)==SLH_ERR_PARAM);CHECK(slh_subtree(c,SLH_LEAF_WOTS,base,0,5,0,root,NULL)==SLH_ERR_PARAM);
 for(size_t j=0;j<sizeof root;j++)CHECK(root[j]==0xa5);for(size_t j=0;j<sizeof auth;j++)CHECK(auth[j]==0xa5);puts("subtree invalid inputs leave outputs untouched PASS");
 slh_ctx_free(c);
}
static void counters_test(const uint8_t sk[64],const uint8_t pk[32]){
 slh_ctx *c=NULL;CHECK(!slh_ctx_new(&c,201,0));CHECK(!slh_ctx_set_threads(c,4));uint8_t sig[2320];size_t len;slh_counters a,b;slh_counters_reset();CHECK(!slh_sign(c,sig,&len,msg,sizeof msg,context,sizeof context,sk,NULL));slh_counters_get(&a);slh_counters_reset();CHECK(!slh_verify(c,sig,len,msg,sizeof msg,context,sizeof context,pk));slh_counters_get(&b);
#ifdef SLH_COUNTERS
 uint64_t leaves=1024,lenw=68,k=6,hp=10;
 CHECK(a.prf==k*(leaves+1)+lenw*leaves);CHECK(a.prf_msg==1&&a.h_msg==1);CHECK(a.h==k*(leaves-1)+(leaves-1-hp));CHECK(a.t==leaves);
 uint64_t fixedf=k*leaves+lenw*3*(leaves-1);CHECK(a.f>=fixedf&&a.f<=fixedf+lenw*3);uint64_t steps=a.f-fixedf;
 CHECK(b.prf==0&&b.prf_msg==0&&b.h_msg==1&&b.f==k+lenw*3-steps&&b.h==k*10+hp&&b.t==2);
 CHECK(a.compress==1+a.prf+a.f+a.h+18*(leaves-1)+2+4+4);CHECK(b.compress==1+b.f+b.h+18+2+4);
 printf("exact counters sign prf=%llu f=%llu h=%llu t=%llu compress=%llu; WOTS steps=%llu verify f=%llu compress=%llu PASS\n",(unsigned long long)a.prf,(unsigned long long)a.f,(unsigned long long)a.h,(unsigned long long)a.t,(unsigned long long)a.compress,(unsigned long long)steps,(unsigned long long)b.f,(unsigned long long)b.compress);
#else
 slh_counters zero={0};CHECK(!memcmp(&a,&zero,sizeof a)&&!memcmp(&b,&zero,sizeof b));puts("timing-build counters disabled PASS");
#endif
 slh_ctx_free(c);
}
int main(int argc,char **argv){CHECK(argc==2);uint8_t seed[48],pk[32],sk[64],expected[2320];for(unsigned i=0;i<48;i++)seed[i]=(uint8_t)(i+11);slh_ctx *c=NULL;CHECK(!slh_ctx_new(&c,201,SLH_FLAG_VERIFY_AFTER_SIGN));CHECK(!slh_ctx_set_threads(c,4));CHECK(!slh_keygen_internal(c,pk,sk,seed,seed+16,seed+32));size_t len;CHECK(!slh_sign(c,expected,&len,msg,sizeof msg,context,sizeof context,sk,NULL));CHECK(len==sizeof expected);slh_ctx_free(c);cache_tests(argv[1],pk,sk,expected);key_and_signature_tests(argv[1],pk,sk,expected);subtree_tests(sk);counters_test(sk,pk);puts("native extended review PASS");return 0;}
