#include "slhdsa_sm3.h"
#include "sm3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define CHECK(x) do {if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);exit(1);}} while(0)
static void sm3_test(void) {
 a15_sm3 s;uint8_t d[32];char hex[65];
 a15_sm3_init(&s);a15_sm3_update(&s,"abc",3);a15_sm3_final(&s,d);
 for(unsigned i=0;i<32;i++)sprintf(hex+2*i,"%02x",d[i]);
 CHECK(!strcmp(hex,"66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"));
 a15_sm3_init(&s);for(unsigned i=0;i<16;i++)a15_sm3_update(&s,"abcd",4);a15_sm3_final(&s,d);
 for(unsigned i=0;i<32;i++)sprintf(hex+2*i,"%02x",d[i]);
 CHECK(!strcmp(hex,"debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"));
}
static void api_test(void) {
 slh_ctx *c=NULL;uint8_t sk[64]={0},base[32]={0},root[16],sig[2320];size_t len=123;
 CHECK(slh_ctx_new(NULL,201,0)==SLH_ERR_PARAM);CHECK(slh_ctx_new(&c,201,0x200u)==SLH_ERR_PARAM&&c==NULL);CHECK(slh_ctx_new(&c,201,0xffu)==SLH_ERR_BACKEND&&c==NULL);CHECK(!slh_ctx_new(&c,201,0));
 CHECK(slh_pk_bytes(999)==0&&slh_sk_bytes(999)==0&&slh_sig_bytes(999)==0);CHECK(slh_pk_bytes(201)==32&&slh_sk_bytes(201)==64);
 CHECK(slh_ctx_set_threads(c,-1)==SLH_ERR_PARAM);CHECK(slh_ctx_set_threads(c,1025)==SLH_ERR_PARAM);CHECK(!slh_ctx_set_threads(c,0));CHECK(!slh_ctx_set_threads(c,1));CHECK(slh_ctx_set_threads(NULL,1)==SLH_ERR_PARAM);
 CHECK(slh_ctx_set_cache_level(c,11)==SLH_ERR_PARAM);CHECK(slh_ctx_set_cache_level(c,UINT32_MAX)==SLH_ERR_PARAM);CHECK(slh_ctx_bind_key(c,NULL)==SLH_ERR_PARAM);CHECK(slh_ctx_bind_key(NULL,sk)==SLH_ERR_PARAM);CHECK(slh_subtree(c,SLH_LEAF_WOTS,base,0,0,0,root,NULL)==SLH_ERR_PARAM);
 CHECK(slh_sign(c,sig,&len,NULL,1,NULL,0,sk,NULL)==SLH_ERR_PARAM&&len==0);len=123;CHECK(slh_sign(c,sig,&len,NULL,0,NULL,1,sk,NULL)==SLH_ERR_PARAM&&len==0);len=123;CHECK(slh_sign(c,sig,&len,NULL,0,NULL,256,sk,NULL)==SLH_ERR_CTXLEN&&len==0);
 slh_ctx_free(c);puts("native argument guards PASS");
}
static void run(int pid) {
 const char *cache_file=getenv("A15_TEST_CACHE");if(!cache_file)cache_file="../build/test.cache";
 slh_ctx *c=NULL,*d=NULL;uint8_t seed[48],sk[64],pk[32],msg[]={0,1,2,3},context[]={9,8},base[32]={0};size_t size=slh_sig_bytes(pid),len=0;
 for(unsigned i=0;i<48;i++)seed[i]=(uint8_t)i;
 uint8_t *sig=malloc(size),*sig2=malloc(size);CHECK(sig&&sig2);CHECK(!slh_ctx_new(&c,pid,SLH_FLAG_VERIFY_AFTER_SIGN));CHECK(!slh_ctx_new(&d,pid,0));
 CHECK(!slh_ctx_set_threads(c,4));CHECK(!slh_ctx_set_cache_level(c,pid==201?5:3));
 CHECK(!slh_keygen_internal(c,pk,sk,seed,seed+16,seed+32));CHECK(!slh_sign(c,sig,&len,msg,sizeof msg,context,sizeof context,sk,NULL));CHECK(len==size);
 CHECK(!slh_verify(d,sig,len,msg,sizeof msg,context,sizeof context,pk));
 CHECK(slh_verify(d,sig,size-1,msg,sizeof msg,context,sizeof context,pk)==SLH_ERR_VERIFY);
 sig[size/2]^=1;CHECK(slh_verify(d,sig,size,msg,sizeof msg,context,sizeof context,pk)==SLH_ERR_VERIFY);sig[size/2]^=1;
 CHECK(slh_sign(c,sig2,&len,msg,sizeof msg,context,256,sk,NULL)==SLH_ERR_CTXLEN);
 if(pid==201){uint8_t corrupt[64];memcpy(corrupt,sk,64);corrupt[63]^=1;memset(sig2,0xa5,size);CHECK(slh_sign(c,sig2,&len,msg,sizeof msg,context,sizeof context,corrupt,NULL)==SLH_ERR_FAULT);CHECK(len==0);for(size_t i=0;i<size;i++)CHECK(sig2[i]==0);}
 CHECK(!slh_cache_save(c,cache_file));CHECK(!slh_cache_load(d,cache_file,pk));
 CHECK(!slh_sign(d,sig2,&len,msg,sizeof msg,context,sizeof context,sk,NULL));CHECK(!memcmp(sig,sig2,size));
 FILE *f=fopen(cache_file,"r+b");CHECK(f);CHECK(!fseek(f,97,SEEK_SET));int ch=fgetc(f);CHECK(!fseek(f,97,SEEK_SET));fputc(ch^1,f);fclose(f);CHECK(slh_cache_load(d,cache_file,pk)==SLH_ERR_CACHE);
 CHECK(!slh_ctx_bind_key(d,sk));uint8_t r1[16],r2[16],a1[48],a2[48];CHECK(!slh_subtree(c,SLH_LEAF_WOTS,base,0,3,5,r1,a1));CHECK(!slh_subtree(d,SLH_LEAF_WOTS,base,0,3,5,r2,a2));CHECK(!memcmp(r1,r2,16)&&!memcmp(a1,a2,48));
 CHECK(!slh_subtree(c,SLH_LEAF_WOTS,base,0,0,0,r1,NULL));
 CHECK(slh_subtree(c,SLH_LEAF_WOTS,base,1,3,UINT32_MAX,r1,NULL)==SLH_ERR_PARAM);
 free(sig);free(sig2);slh_ctx_free(c);slh_ctx_free(d);printf("pid %d native checks PASS\n",pid);
}
int main(void) {
 sm3_test();api_test();CHECK(slh_sig_bytes(3)==3856);CHECK(slh_sig_bytes(103)==3856);CHECK(slh_sig_bytes(201)==2320);slh_ctx *c=NULL;
 if(slh_backend_available(SLH_BACKEND_AVX2)){CHECK(!slh_ctx_new(&c,201,SLH_BACKEND_AVX2));CHECK(slh_ctx_backend(c)==SLH_BACKEND_AVX2);slh_ctx_free(c);c=NULL;}else CHECK(slh_ctx_new(&c,201,SLH_BACKEND_AVX2)==SLH_ERR_BACKEND);CHECK(c==NULL);CHECK(slh_ctx_new(&c,999,0)==SLH_ERR_PARAM);
 run(201);run(101);run(102);puts("native tests PASS");return 0;
}
