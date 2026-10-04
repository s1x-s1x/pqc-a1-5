/* Bounded tree/fault/route acceptance. Optional whole signing has no timer. */
#define SLH_TEST_BUILD 1
#define A15_TEST_INCREMENTAL_DIAGNOSTICS 1
#include "../src/engine.c"
#define CHECK(x) do{if(!(x)){fprintf(stderr,"incremental engine FAIL %d: %s\n",__LINE__,#x);exit(1);}}while(0)

static void reset_routes(void){
 for(unsigned i=0;i<5;i++)atomic_store(&a15_test_incremental_streams[i],0);
 atomic_store(&a15_test_incremental_prf_packages,0);atomic_store(&a15_test_incremental_fallbacks,0);
 atomic_store(&a15_test_incremental_b1_packages,0);atomic_store(&a15_test_incremental_ref_verifications,0);
}
static unsigned cases;
static void trees(void){
 uint8_t sk[64],base[32]={0};for(unsigned i=0;i<64;i++)sk[i]=(uint8_t)(i*37+11);
 slh_ctx *ref=NULL,*simd=NULL;CHECK(!slh_ctx_new(&ref,3,SLH_BACKEND_REF));CHECK(!slh_ctx_new(&simd,3,SLH_BACKEND_AVX2));
 CHECK(!slh_ctx_bind_key(ref,sk));CHECK(!slh_ctx_bind_key(simd,sk));
 const unsigned heights[]={0,2,3,4,6,10};
 for(unsigned run=0;run<18;run++){
  unsigned z=heights[run%6],tree=run%6;uint32_t start=(tree<<24)+((UINT32_C(1)<<24)-(UINT32_C(1)<<z));
  uint32_t target=start+(run%3==0?0:run%3==1?(UINT32_C(1)<<z)-1:(UINT32_C(1)<<z)/2);
  uint8_t expected[16],actual[18],ea[24*16],aa[24*16+2];
  put32(base,run%4);put32(base+8,0x23456789+run);put32(base+12,0xabcdef01+run);
  put32(base+16,3);put32(base+20,0x3fffff-run);put32(base+24,19);put32(base+28,UINT32_MAX);
  CHECK(!slh_ctx_set_threads(simd,run<12?1:4));
  memset(actual,0xa5,sizeof actual);memset(aa,0xa5,sizeof aa);reset_routes();
  slh_counters ref_counts,simd_counts;slh_counters_reset();
  CHECK(!slh_subtree_checked(ref,SLH_LEAF_FORS,base,start,z,target,expected,16,ea,z*16));slh_counters_get(&ref_counts);slh_counters_reset();
  CHECK(!slh_subtree_checked(simd,SLH_LEAF_FORS,base,start,z,target,actual+1,16,aa+1,z*16));
  slh_counters_get(&simd_counts);CHECK(!memcmp(&ref_counts,&simd_counts,sizeof ref_counts));
  #ifdef SLH_COUNTERS
  CHECK(simd_counts.prf==(UINT64_C(1)<<z)&&simd_counts.f==(UINT64_C(1)<<z)&&simd_counts.h==(UINT64_C(1)<<z)-1);
  CHECK(simd_counts.compress==3*(UINT64_C(1)<<z)&&!simd_counts.t&&!simd_counts.h_msg&&!simd_counts.prf_msg);
  #endif
  CHECK(!memcmp(expected,actual+1,16)&&!memcmp(ea,aa+1,z*16));
  CHECK(actual[0]==0xa5&&actual[17]==0xa5&&aa[0]==0xa5&&aa[z*16+1]==0xa5);
  #if A15_INCREMENTAL_MODE
  if(z>=4&&run<12){CHECK(atomic_load(&a15_test_incremental_streams[A15_INCREMENTAL_MODE])==1);CHECK(atomic_load(&a15_test_incremental_prf_packages)==(UINT64_C(1)<<(z-3)));}
  else if(z==3){CHECK(!atomic_load(&a15_test_incremental_streams[A15_INCREMENTAL_MODE]));CHECK(atomic_load(&a15_test_incremental_fallbacks)>0);}
  #endif
  work w;init_work(&w,lookup(3),sk,NULL);memcpy(w.adrs,base,32);put32(w.adrs+28,target);uint8_t selected[16],independent[16];
  fors_secret(&w,selected);put32(w.adrs+16,6);thash(&w,independent,sk,16,C_PRF);CHECK(!memcmp(selected,independent,16));
  cases++;
 }
 uint8_t root[16],auth[64];CHECK(slh_subtree_checked(simd,SLH_LEAF_FORS,base,1,4,NO_TARGET,root,16,NULL,0)==SLH_ERR_PARAM);
 CHECK(slh_subtree_checked(simd,SLH_LEAF_FORS,base,6u<<24,4,NO_TARGET,root,16,NULL,0)==SLH_ERR_PARAM);
 CHECK(slh_subtree_checked(simd,SLH_LEAF_FORS,base,0,4,0,root,15,auth,64)==SLH_ERR_CAPACITY);
 #if A15_INCREMENTAL_B1
 reset_routes();CHECK(!slh_ctx_set_threads(simd,1));CHECK(!slh_subtree_checked(simd,SLH_LEAF_WOTS,base,0,0,NO_TARGET,root,16,NULL,0));CHECK(atomic_load(&a15_test_incremental_b1_packages)>0);
 #endif
 slh_ctx_free(ref);slh_ctx_free(simd);
 printf("{\"trees\":%u,\"mode\":%d,\"b1\":%d,\"v1\":%d,\"passed\":true,\"performance_samples\":0}\n",cases,A15_INCREMENTAL_MODE,A15_INCREMENTAL_B1,A15_INCREMENTAL_V1);
}
static void faults(void){
 #if A15_INCREMENTAL_MODE
 uint8_t sk[64],base[32]={0};for(unsigned i=0;i<64;i++)sk[i]=(uint8_t)(13*i+7);
 work w;init_work(&w,lookup(3),sk,NULL);w.backend=SLH_BACKEND_AVX2;memcpy(w.adrs,base,32);
 uint8_t expected[16],actual[16],ea[6*16],aa[6*16];
 const unsigned point=SLH_TEST_FAULT_POINT;
 TEST_SITE(w,point,3);
 CHECK(!fors_tree8(w,0,6,3,actual,aa));
 slh_ctx ref={0};ref.p=lookup(3);ref.backend=SLH_BACKEND_REF;ref.threads=1;
 CHECK(!serial_tree(w,SLH_LEAF_FORS,0,6,3,expected,ea,&ref,NULL));
 CHECK(!memcmp(expected,actual,16)&&!memcmp(ea,aa,sizeof ea));
 printf("{\"fault_point\":%u,\"tree_fault_matches_REF\":true}\n",point);
 #endif
}
static void read_exact(const char *path,uint8_t *out,size_t n){FILE *f=fopen(path,"rb");CHECK(f);CHECK(fread(out,1,n,f)==n&&fgetc(f)==EOF&&!ferror(f));CHECK(!fclose(f));}
static void full_signature(char **argv){
 uint8_t pk[32],sk[64],rnd[16],expected[3856],message[4096],context[255],output[3858];
 read_exact(argv[1],pk,32);read_exact(argv[2],sk,64);read_exact(argv[3],rnd,16);read_exact(argv[4],expected,3856);
 size_t lengths[2];for(unsigned field=0;field<2;field++){FILE *f=fopen(argv[5+field],"rb");CHECK(f);lengths[field]=fread(field?context:message,1,field?sizeof context:sizeof message,f);CHECK(fgetc(f)==EOF&&!ferror(f));CHECK(!fclose(f));}
 int threads=atoi(argv[8]);CHECK(threads>=1&&threads<=96);
 slh_ctx *signer=NULL,*verifier=NULL;CHECK(!slh_ctx_new(&signer,3,SLH_BACKEND_AVX2|SLH_FLAG_VERIFY_AFTER_SIGN));CHECK(!slh_ctx_new(&verifier,3,SLH_BACKEND_REF));CHECK(!slh_ctx_set_threads(signer,threads));
 CHECK(!slh_cache_load(signer,argv[7],pk));CHECK(!slh_ctx_bind_key(signer,sk));
 reset_routes();memset(output,0xa5,sizeof output);size_t size=17;
 int rc=slh_sign_checked(signer,output+1,3856,&size,message,lengths[0],context,lengths[1],sk,rnd);
 if(SLH_TEST_FAULT_POINT){CHECK(rc==SLH_ERR_FAULT&&size==0);for(unsigned i=1;i<=3856;i++)CHECK(output[i]==0);}
 else CHECK(rc==0&&size==3856&&!memcmp(output+1,expected,3856));
 CHECK(output[0]==0xa5&&output[3857]==0xa5);
 CHECK(atomic_load(&a15_test_incremental_ref_verifications)==1);
 #if A15_INCREMENTAL_MODE
 CHECK(atomic_load(&a15_test_incremental_streams[A15_INCREMENTAL_MODE])>0);CHECK(atomic_load(&a15_test_incremental_prf_packages)==(UINT64_C(6)<<21));
 #endif
 #if A15_INCREMENTAL_B1
 CHECK(atomic_load(&a15_test_incremental_b1_packages)>0);
 #endif
 if(!SLH_TEST_FAULT_POINT)CHECK(!slh_verify(verifier,output+1,size,message,lengths[0],context,lengths[1],pk));
 printf("{\"full_signature_equal\":%s,\"full_fault_detected_and_cleared\":%s,\"fault_point\":%d,\"independent_REF_self_verify\":true,\"mode\":%d,\"b1\":%d,\"streams\":%llu,\"PRF_x8_packages\":%llu,\"threads\":%d,\"performance_samples\":0}\n",SLH_TEST_FAULT_POINT?"false":"true",SLH_TEST_FAULT_POINT?"true":"false",SLH_TEST_FAULT_POINT,A15_INCREMENTAL_MODE,A15_INCREMENTAL_B1,(unsigned long long)atomic_load(&a15_test_incremental_streams[A15_INCREMENTAL_MODE]),(unsigned long long)atomic_load(&a15_test_incremental_prf_packages),threads);
 a15_secure_zero(sk,sizeof sk);a15_secure_zero(rnd,sizeof rnd);slh_ctx_free(signer);slh_ctx_free(verifier);
}
int main(int argc,char **argv){CHECK(a15_sm3_avx2_available());if(argc==9){full_signature(argv);return 0;}CHECK(argc==1);trees();faults();return 0;}
