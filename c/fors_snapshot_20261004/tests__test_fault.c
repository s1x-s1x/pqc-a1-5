#include "slhdsa_sm3.h"
#include "sm3.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef SLH_TEST_BUILD
#error Fault executable requires SLH_TEST_BUILD
#endif
#ifndef SLH_TEST_FAULT_POINT
#error Fault executable requires SLH_TEST_FAULT_POINT
#endif
#define CHECK(x) do {if(!(x)){fprintf(stderr,"fault FAIL point %d line %d: %s\n",SLH_TEST_FAULT_POINT,__LINE__,#x);exit(1);}} while(0)
static void run(unsigned flags,int threads,unsigned cache_level) {
 slh_ctx *c=NULL,*verifier=NULL;uint8_t seed[48],pk[32],sk[64],output[2322],msg[]={0x31,0x41,0x59},mp[]={0,0,0x31,0x41,0x59},digest[32];uint8_t *sig=output+1;const size_t sigsize=2320;size_t len=123;
 for(unsigned j=0;j<48;j++)seed[j]=(uint8_t)(j+7);
 CHECK(!slh_ctx_new(&c,201,flags));CHECK(!slh_ctx_new(&verifier,201,0));CHECK(!slh_ctx_set_threads(c,threads));CHECK(!slh_ctx_set_cache_level(c,cache_level));CHECK(!slh_keygen_internal(c,pk,sk,seed,seed+16,seed+32));
 memset(output,0xa5,sizeof output);int rc=slh_sign(c,sig,&len,msg,sizeof msg,NULL,0,sk,NULL);
 if(SLH_TEST_FAULT_POINT==0){CHECK(rc==0);CHECK(len==sigsize);CHECK(slh_verify(verifier,sig,len,msg,sizeof msg,NULL,0,pk)==0);}
 else if(flags&SLH_FLAG_VERIFY_AFTER_SIGN){CHECK(rc==SLH_ERR_FAULT);CHECK(len==0);for(size_t j=0;j<sigsize;j++)CHECK(sig[j]==0);}
 else {CHECK(rc==0);CHECK(len==sigsize);CHECK(slh_verify(verifier,sig,len,msg,sizeof msg,NULL,0,pk)==SLH_ERR_VERIFY);}
 CHECK(output[0]==0xa5&&output[sizeof output-1]==0xa5);
 memset(output,0xa5,sizeof output);rc=slh_sign_internal(c,sig,mp,sizeof mp,sk,NULL);
 if(SLH_TEST_FAULT_POINT==0)CHECK(rc==0&&slh_verify_internal(verifier,sig,sigsize,mp,sizeof mp,pk)==0);
 else if(flags&SLH_FLAG_VERIFY_AFTER_SIGN){CHECK(rc==SLH_ERR_FAULT);for(size_t j=0;j<sigsize;j++)CHECK(sig[j]==0);}
 else CHECK(rc==0&&slh_verify_internal(verifier,sig,sigsize,mp,sizeof mp,pk)==SLH_ERR_VERIFY);
 CHECK(output[0]==0xa5&&output[sizeof output-1]==0xa5);
 a15_sm3 ph;a15_sm3_init(&ph);a15_sm3_update(&ph,msg,sizeof msg);a15_sm3_final(&ph,digest);for(unsigned mode=0;mode<2;mode++){
  memset(output,0xa5,sizeof output);len=123;rc=mode?slh_sign_digest(c,sig,&len,SLH_PREHASH_SM3,digest,32,NULL,0,sk,NULL):slh_sign_prehash(c,sig,&len,SLH_PREHASH_SM3,msg,sizeof msg,NULL,0,sk,NULL);
  if(SLH_TEST_FAULT_POINT==0){CHECK(rc==0&&len==sigsize);CHECK(!slh_verify_prehash(verifier,sig,len,SLH_PREHASH_SM3,msg,sizeof msg,NULL,0,pk));}
  else if(flags&SLH_FLAG_VERIFY_AFTER_SIGN){CHECK(rc==SLH_ERR_FAULT&&len==0);for(size_t j=0;j<sigsize;j++)CHECK(sig[j]==0);}
  else {CHECK(rc==0&&len==sigsize);CHECK(slh_verify_prehash(verifier,sig,len,SLH_PREHASH_SM3,msg,sizeof msg,NULL,0,pk)==SLH_ERR_VERIFY);}
  CHECK(output[0]==0xa5&&output[sizeof output-1]==0xa5);
 }
 printf("fault point=%d backend=%d threads=%d cache_t=%u self_verify=%u pure/internal/prehash/digest PASS\n",SLH_TEST_FAULT_POINT,slh_ctx_backend(c),threads,cache_level,!!(flags&SLH_FLAG_VERIFY_AFTER_SIGN));
 slh_ctx_free(c);slh_ctx_free(verifier);
}
int main(void){const int threads[]={1,4};const unsigned levels[]={5,10};for(unsigned t=0;t<2;t++)for(unsigned level=0;level<2;level++){run(0,threads[t],levels[level]);run(SLH_FLAG_VERIFY_AFTER_SIGN,threads[t],levels[level]);}if(SLH_TEST_FAULT_POINT==0)puts("fault point 0: 32 control signing calls, valid signatures+guards PASS");else printf("fault point %d: 32 signing calls, detection-off invalid signature, detection-on SLH_ERR_FAULT+2320-byte-clearing+guards PASS\n",SLH_TEST_FAULT_POINT);return 0;}
