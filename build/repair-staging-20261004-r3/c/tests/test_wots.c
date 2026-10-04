/* Private-algorithm correctness harness: compiled as a standalone executable.
 * It includes the engine to exercise precise chain/tail patterns without any
 * test hook in the production ABI. It performs no timing. */
#define SLH_TEST_BUILD 1
#include "../src/engine.c"
#define CHECK(x) do {if(!(x)){fprintf(stderr,"WOTS FAIL line %d: %s\n",__LINE__,#x);exit(1);}} while(0)
static uint32_t random_state=0x27182818;
static uint32_t next_random(void){random_state^=random_state<<13;random_state^=random_state>>17;random_state^=random_state<<5;return random_state;}
static void same_counts(const slh_counters *a,const slh_counters *b){CHECK(!memcmp(a,b,sizeof *a));}
static void work_at(work *w,int pid,uint32_t idx,unsigned salt){
 /* Work borrows immutable seed storage; this harness keeps it alive between
  * setup and component calls. Current comparisons share the same salt. */
 static uint8_t keys[16][64];static unsigned slot;uint8_t *sk=keys[slot++%16];for(unsigned j=0;j<64;j++)sk[j]=(uint8_t)(j*13+salt);init_work(w,lookup(pid),sk,NULL);put32(w->adrs,w->p->d-1);set_tree(w,UINT64_C(0x123456789abcdef0)+salt);set_type(w,0);put32(w->adrs+20,idx);
}
static void lane_tests(int pid){
 unsigned comparisons=0;for(unsigned count=1;count<=8;count++)for(unsigned pattern=0;pattern<6;pattern++){
  work w;work_at(&w,pid,UINT32_C(0x123456),count+pattern);uint32_t starts[8]={0},steps[8]={0};uint8_t expected[8][N],actual[8][N],signature[MAX_LEN*N];unsigned maximum=(1u<<w.p->lgw)-1,first=w.p->len-count;
  for(unsigned j=0;j<sizeof signature;j++)signature[j]=(uint8_t)next_random();for(unsigned lane=0;lane<count;lane++){
   unsigned value=pattern==0?0:pattern==1?maximum:pattern==2?(lane&1?maximum:0):pattern==3?lane%(maximum+1):pattern==4?next_random()%(maximum+1):(lane+1)%(maximum+1);
   starts[lane]=pattern==5?value:0;steps[lane]=pattern==5?maximum-value:value;
  }
  for(unsigned recovery=0;recovery<2;recovery++){
   slh_counters ref,simd;slh_counters_reset();for(unsigned lane=0;lane<count;lane++){
    work scalar=w;put32(scalar.adrs+24,first+lane);if(recovery)memcpy(expected[lane],signature+(first+lane)*N,N);else wots_secret(&scalar,expected[lane]);chain(&scalar,expected[lane],expected[lane],starts[lane],steps[lane]);
   }slh_counters_get(&ref);slh_counters_reset();wots_group8(w,first,count,actual,starts,steps,recovery?signature:NULL);slh_counters_get(&simd);CHECK(!memcmp(expected,actual,count*N));same_counts(&ref,&simd);comparisons++;
  }
 }printf("WOTS pid=%d lane masks/tails1..8/start/zero/max/divergent steps: %u comparisons PASS\n",pid,comparisons);
}
static void leaf_and_recovery_tests(int pid){
 unsigned comparisons=0;for(unsigned sample=0;sample<24;sample++){
  work scalar,vector;uint32_t idx=sample==0?0:sample==1?(1u<<lookup(pid)->hp)-1:next_random()%((1u<<lookup(pid)->hp));work_at(&scalar,pid,idx,sample);vector=scalar;vector.backend=SLH_BACKEND_AVX2;uint8_t expected[N],actual[N];slh_counters ref,simd;
  slh_counters_reset();wots_leaf(&scalar,idx,expected);slh_counters_get(&ref);slh_counters_reset();wots_leaf8(&vector,idx,actual);slh_counters_get(&simd);CHECK(!memcmp(expected,actual,N));same_counts(&ref,&simd);
  work w;work_at(&w,pid,idx,sample);uint8_t message[N],sig[MAX_LEN*N+MAX_HEIGHT*N];uint32_t values[MAX_LEN];for(unsigned j=0;j<N;j++)message[j]=sample==0?0:sample==1?0xff:(uint8_t)next_random();wots_digits(&w,values,message);uint8_t refsig[MAX_LEN*N],actualsig[MAX_LEN*N];
  slh_counters_reset();for(unsigned j=0;j<w.p->len;j++){work one=w;put32(one.adrs+24,j);wots_secret(&one,refsig+j*N);chain(&one,refsig+j*N,refsig+j*N,0,values[j]);}slh_counters_get(&ref);slh_counters_reset();wots_sign8(w,actualsig,values);slh_counters_get(&simd);CHECK(!memcmp(refsig,actualsig,w.p->len*N));same_counts(&ref,&simd);
  memcpy(sig,refsig,w.p->len*N);for(unsigned j=0;j<w.p->hp*N;j++)sig[w.p->len*N+j]=(uint8_t)next_random();work recovery=w;recovery.backend=SLH_BACKEND_REF;slh_counters_reset();xmss_from_sig(recovery,expected,sig,message,idx);slh_counters_get(&ref);recovery.backend=SLH_BACKEND_AVX2;slh_counters_reset();xmss_from_sig(recovery,actual,sig,message,idx);slh_counters_get(&simd);CHECK(!memcmp(expected,actual,N));same_counts(&ref,&simd);
  /* Direct T_len recovery must reproduce the independently generated leaf,
   * regardless of message and chain length distribution. */
  wots_from_sig8(w,actual,refsig,values);work leaf=w;wots_leaf(&leaf,idx,expected);CHECK(!memcmp(expected,actual,N));comparisons+=4;
 }printf("WOTS pid=%d lgw=%u len=%u leaf/sign/T_len/recovery/auth/counters: %u comparisons PASS\n",pid,lookup(pid)->lgw,lookup(pid)->len,comparisons);
}
int main(void){if(!a15_sm3_avx2_available()){puts("WOTS SIMD unavailable: runtime skip; no AVX2 worker invoked");return 0;}const int pids[]={201,1,2,3};for(unsigned i=0;i<sizeof pids/sizeof *pids;i++){lane_tests(pids[i]);leaf_and_recovery_tests(pids[i]);}puts("WOTS correctness PASS; no performance measured");return 0;}
