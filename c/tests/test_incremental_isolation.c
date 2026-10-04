/* Bounded request isolation and real CUDA dispatch; no signing or timers. */
#define SLH_TEST_BUILD 1
#define A15_TEST_INCREMENTAL_DIAGNOSTICS 1
#define A15_TEST_V1_DIAGNOSTICS 1
#include "../src/engine.c"
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"isolation FAIL %d: %s\n",__LINE__,#x); exit(1); } } while (0)

static uint8_t *read_file(const char *path, size_t cap, size_t *size) {
    FILE *f=fopen(path,"rb"); CHECK(f);
    uint8_t *data=malloc(cap+1); CHECK(data);
    *size=fread(data,1,cap+1,f);
    CHECK(*size<=cap&&!ferror(f)&&fgetc(f)==EOF&&!fclose(f));
    return data;
}
static void reset_hits(void) {
    atomic_store(&a15_test_v1_calls,0);
    atomic_store(&a15_test_v1_f_packages,0);
    atomic_store(&a15_test_v1_h_packages,0);
    atomic_store(&a15_test_v1_padding_lanes,0);
    for(unsigned i=0;i<5;i++) atomic_store(&a15_test_incremental_streams[i],0);
    atomic_store(&a15_test_incremental_b1_packages,0);
}
static void concurrent(const uint8_t *pk,const uint8_t *sig,size_t slen,
                       const uint8_t *msg,size_t mlen,const uint8_t *ctx,size_t clen) {
    enum { REQUESTS=64 };
    slh_ctx *shared=NULL;
    CHECK(!slh_ctx_new(&shared,3,SLH_BACKEND_AVX2));
    reset_hits();
    #pragma omp parallel for num_threads(16) schedule(static)
    for(unsigned i=0;i<REQUESTS;i++) {
        uint8_t local[3856],local_pk[32]; memcpy(local,sig,slen); memcpy(local_pk,pk,32);
        const int expected=i%2?SLH_ERR_VERIFY:0;
        if(i%4==1) local[N+(i%6)*25*N+((i/6)%25)*N]^=1;
        if(i%4==3) local_pk[i%N]^=(uint8_t)(1u<<(i%8));
        slh_ctx *private_ctx=NULL,*reference=NULL;
        CHECK(!slh_ctx_new(&private_ctx,3,SLH_BACKEND_AVX2));
        CHECK(!slh_ctx_new(&reference,3,SLH_BACKEND_REF));
        slh_ctx *selected=i%4<2?shared:private_ctx;
        CHECK(slh_verify(reference,local,slen,msg,mlen,ctx,clen,local_pk)==expected);
        CHECK(slh_verify(selected,local,slen,msg,mlen,ctx,clen,local_pk)==expected);
        slh_ctx_free(private_ctx); slh_ctx_free(reference);
    }
    CHECK(atomic_load(&a15_test_v1_calls)==REQUESTS);
    CHECK(atomic_load(&a15_test_v1_f_packages)==REQUESTS);
    CHECK(atomic_load(&a15_test_v1_h_packages)==REQUESTS*24);
    CHECK(atomic_load(&a15_test_v1_padding_lanes)==REQUESTS*50);
    CHECK(atomic_load(&a15_test_incremental_streams[4])==0);
    slh_ctx_free(shared);
    puts("{\"concurrent_requests\":64,\"threads\":16,\"valid\":32,\"invalid\":32,\"changed_public_seeds\":16,\"REF_per_request\":true,\"shared_and_private_contexts\":true,\"V1_hits\":64,\"passed\":true,\"performance_samples\":0}");
}
static void cuda(const uint8_t *pk,const uint8_t *sig,size_t slen,
                 const uint8_t *msg,size_t mlen,const uint8_t *ctx,size_t clen) {
    CHECK(slh_backend_available(SLH_BACKEND_CUDA));
    slh_ctx *ref=NULL,*gpu=NULL;
    CHECK(!slh_ctx_new(&ref,3,SLH_BACKEND_REF));
    CHECK(!slh_ctx_new(&gpu,3,SLH_BACKEND_CUDA));
    CHECK(slh_ctx_backend(gpu)==SLH_BACKEND_CUDA);
    uint8_t sk[64],adrs[32]={0};
    for(unsigned i=0;i<64;i++) sk[i]=(uint8_t)(37*i+19);
    put32(adrs+16,3); put32(adrs+20,0x3fffff);
    CHECK(!slh_ctx_bind_key(ref,sk)&&!slh_ctx_bind_key(gpu,sk));
    CHECK(!slh_cuda_stats_reset(0)); reset_hits();
    const unsigned heights[]={0,3,6,10};
    unsigned trees=0;
    for(unsigned i=0;i<4;i++) for(unsigned edge=0;edge<2;edge++) {
        unsigned z=heights[i]; uint32_t start=(6u<<24)-(1u<<z);
        uint32_t target=start+(edge?(1u<<z)-1:0);
        uint8_t er[16],ea[160],ar[18],aa[162];
        memset(ar,0xa5,sizeof ar); memset(aa,0xa5,sizeof aa);
        CHECK(!slh_subtree_checked(ref,SLH_LEAF_FORS,adrs,start,z,target,er,16,ea,z*N));
        CHECK(!slh_subtree_checked(gpu,SLH_LEAF_FORS,adrs,start,z,target,ar+1,16,aa+1,z*N));
        CHECK(!memcmp(er,ar+1,N)&&!memcmp(ea,aa+1,z*N));
        CHECK(ar[0]==0xa5&&ar[17]==0xa5&&aa[0]==0xa5&&aa[z*N+1]==0xa5);
        trees++;
    }
    CHECK(atomic_load(&a15_test_incremental_streams[4])==0);
    CHECK(atomic_load(&a15_test_incremental_b1_packages)==0);
    CHECK(!slh_verify(gpu,sig,slen,msg,mlen,ctx,clen,pk));
    uint8_t mutation[3856]; memcpy(mutation,sig,slen); mutation[N]^=1;
    CHECK(slh_verify(gpu,mutation,slen,msg,mlen,ctx,clen,pk)==SLH_ERR_VERIFY);
    CHECK(atomic_load(&a15_test_v1_calls)==0);
    CHECK(atomic_load(&a15_test_incremental_streams[4])==0);
    CHECK(atomic_load(&a15_test_incremental_b1_packages)==0);
    slh_cuda_stats stats; CHECK(!slh_cuda_stats_get(&stats));
    CHECK(stats.kernel_launches>0&&stats.device_hashes>0);
    CHECK(!stats.timing_enabled&&!stats.kernel_ns);
    printf("{\"CUDA_subtrees\":%u,\"CUDA_verify_cases\":2,\"V1_hits\":0,\"AF_streams\":0,\"new_B1_hits\":%llu,\"kernel_launches\":%llu,\"device_hashes\":%llu,\"timed\":false,\"passed\":true,\"performance_samples\":0}\n",trees,(unsigned long long)atomic_load(&a15_test_incremental_b1_packages),(unsigned long long)stats.kernel_launches,(unsigned long long)stats.device_hashes);
    slh_ctx_free(ref); slh_ctx_free(gpu); a15_secure_zero(sk,sizeof sk);
}
int main(int argc,char **argv) {
    CHECK(argc==5||argc==6); CHECK(a15_sm3_avx2_available());
    size_t plen,slen,mlen,clen;
    uint8_t *pk=read_file(argv[1],32,&plen),*sig=read_file(argv[2],3856,&slen);
    uint8_t *msg=read_file(argv[3],4096,&mlen),*ctx=read_file(argv[4],255,&clen);
    CHECK(plen==32&&slen==3856);
    concurrent(pk,sig,slen,msg,mlen,ctx,clen);
    if(argc==6) { CHECK(!strcmp(argv[5],"cuda")); cuda(pk,sig,slen,msg,mlen,ctx,clen); }
    free(pk); free(sig); free(msg); free(ctx);
    return 0;
}
