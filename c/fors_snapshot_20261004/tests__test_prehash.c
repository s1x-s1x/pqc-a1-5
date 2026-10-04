#include "slhdsa_sm3.h"
#include "sm3.h"
#include "sha2_api.h"
#include "sha3_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do {if(!(x)){fprintf(stderr,"prehash FAIL line %d: %s\n",__LINE__,#x);exit(1);}} while(0)
static const uint8_t msg[]={0x61,0x62,0x63};
static const uint8_t oids[5][11]={
 {0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01},
 {0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03},
 {0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x0b},
 {0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x0c},
 {0x06,0x08,0x2a,0x81,0x1c,0xcf,0x55,0x01,0x83,0x11,0}
};
static const char *known[]={
 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
 "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
 "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
 "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4",
 "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
};
static void ph(int id,uint8_t out[64]){switch(id){case 1:sha2_256(out,msg,3);break;case 2:sha2_512(out,msg,3);break;case 3:shake128(out,32,msg,3);break;case 4:shake256(out,64,msg,3);break;case 5:{a15_sm3 s;a15_sm3_init(&s);a15_sm3_update(&s,msg,3);a15_sm3_final(&s,out);break;}default:CHECK(0);}}
static void check_hashes(void){for(int id=1;id<=5;id++){uint8_t digest[64];char hex[129];ph(id,digest);size_t n=slh_prehash_bytes(id);CHECK(n==(id==2||id==4?64u:32u));for(size_t j=0;j<n;j++)sprintf(hex+2*j,"%02x",digest[j]);CHECK(!strcmp(hex,known[id-1]));}CHECK(!slh_prehash_bytes(0)&&!slh_prehash_bytes(6));puts("five prehash abc known answers/lengths PASS");}
static void run(unsigned backend){
 slh_ctx *c=NULL;uint8_t seed[48],sk[64],pk[32],context[255],encoded[332],digest[64],pure[2320],sig[2320],actual[2320];size_t len=0;for(unsigned j=0;j<48;j++)seed[j]=(uint8_t)(j+17);for(unsigned j=0;j<255;j++)context[j]=(uint8_t)(j*13);
 CHECK(!slh_ctx_new(&c,201,backend|SLH_FLAG_VERIFY_AFTER_SIGN));CHECK(!slh_ctx_set_threads(c,4));CHECK(!slh_keygen_internal(c,pk,sk,seed,seed+16,seed+32));CHECK(!slh_sign(c,pure,&len,msg,sizeof msg,context,3,sk,NULL));CHECK(len==sizeof pure);
 for(int id=1;id<=5;id++){
  ph(id,digest);size_t dlen=slh_prehash_bytes(id),oidlen=id==5?10:11;slh_counters a,b;slh_counters_reset();CHECK(!slh_sign_prehash(c,sig,&len,id,msg,sizeof msg,context,3,sk,NULL));slh_counters_get(&a);CHECK(len==sizeof sig);slh_counters_reset();CHECK(!slh_sign_digest(c,actual,&len,id,digest,dlen,context,3,sk,NULL));slh_counters_get(&b);CHECK(!memcmp(sig,actual,sizeof sig)&&!memcmp(&a,&b,sizeof a));CHECK(memcmp(sig,pure,sizeof sig));
  CHECK(!slh_verify_prehash(c,sig,len,id,msg,sizeof msg,context,3,pk));CHECK(!slh_verify_digest(c,sig,len,id,digest,dlen,context,3,pk));CHECK(slh_verify(c,sig,len,msg,sizeof msg,context,3,pk)==SLH_ERR_VERIFY);CHECK(slh_verify_prehash(c,pure,len,id,msg,sizeof msg,context,3,pk)==SLH_ERR_VERIFY);
  encoded[0]=1;encoded[1]=3;memcpy(encoded+2,context,3);memcpy(encoded+5,oids[id-1],oidlen);memcpy(encoded+5+oidlen,digest,dlen);CHECK(!slh_sign_internal(c,actual,encoded,5+oidlen+dlen,sk,NULL));CHECK(!memcmp(sig,actual,sizeof sig));CHECK(!slh_verify_internal(c,sig,sizeof sig,encoded,5+oidlen+dlen,pk));
  encoded[0]=0;CHECK(slh_verify_internal(c,sig,sizeof sig,encoded,5+oidlen+dlen,pk)==SLH_ERR_VERIFY);encoded[0]=1;encoded[5+oidlen-1]^=1;CHECK(slh_verify_internal(c,sig,sizeof sig,encoded,5+oidlen+dlen,pk)==SLH_ERR_VERIFY);CHECK(slh_verify_digest(c,sig,sizeof sig,id,digest,dlen,context,2,pk)==SLH_ERR_VERIFY);
  int other=id==1?5:1;CHECK(slh_verify_prehash(c,sig,sizeof sig,other,msg,sizeof msg,context,3,pk)==SLH_ERR_VERIFY);digest[0]^=1;CHECK(slh_verify_digest(c,sig,sizeof sig,id,digest,dlen,context,3,pk)==SLH_ERR_VERIFY);digest[0]^=1;
  CHECK(!slh_sign_prehash(c,actual,&len,id,NULL,0,NULL,0,sk,NULL));CHECK(!slh_verify_prehash(c,actual,len,id,NULL,0,NULL,0,pk));CHECK(!slh_sign_digest(c,actual,&len,id,digest,dlen,context,255,sk,NULL));CHECK(!slh_verify_digest(c,actual,len,id,digest,dlen,context,255,pk));
  memset(actual,0xa5,sizeof actual);len=99;CHECK(slh_sign_digest(c,actual,&len,id,digest,dlen-1,context,3,sk,NULL)==SLH_ERR_PARAM&&!len);for(size_t j=0;j<sizeof actual;j++)CHECK(actual[j]==0xa5);CHECK(slh_verify_digest(c,sig,sizeof sig,id,digest,dlen+1,context,3,pk)==SLH_ERR_PARAM);
  len=99;CHECK(slh_sign_digest(c,actual,&len,id,digest,dlen,context,256,sk,NULL)==SLH_ERR_CTXLEN&&!len);CHECK(slh_sign_digest(c,actual,&len,id,NULL,dlen,NULL,0,sk,NULL)==SLH_ERR_PARAM);CHECK(slh_sign_prehash(c,actual,&len,id,NULL,1,NULL,0,sk,NULL)==SLH_ERR_PARAM);CHECK(slh_sign_prehash(c,actual,&len,id,msg,3,NULL,1,sk,NULL)==SLH_ERR_PARAM);
  printf("prehash id=%d backend=%u message/digest/DER/internal/mode/context/length/counters PASS\n",id,backend);
 }
 len=99;CHECK(slh_sign_prehash(c,actual,&len,999,msg,3,NULL,0,sk,NULL)==SLH_ERR_PARAM&&!len);CHECK(slh_sign_digest(c,actual,&len,999,digest,32,NULL,0,sk,NULL)==SLH_ERR_PARAM);slh_ctx_free(c);
}
int main(void){check_hashes();run(SLH_BACKEND_REF);if(slh_backend_available(SLH_BACKEND_AVX2))run(SLH_BACKEND_AVX2);puts("native prehash checks PASS");return 0;}
