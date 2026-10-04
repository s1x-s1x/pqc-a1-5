#include "sm3_incremental.h"
#include "secure_zero.h"
#include <stdatomic.h>
#include <string.h>

static uint32_t rol(uint32_t x,unsigned n) {
    n &= 31; return n ? (x << n) | (x >> (32-n)) : x;
}
static uint32_t be32(const uint8_t *p) {
    return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 |
        (uint32_t)p[2]<<8 | p[3];
}
static void put32(uint8_t *p,uint32_t x) {
    p[0]=(uint8_t)(x>>24);p[1]=(uint8_t)(x>>16);
    p[2]=(uint8_t)(x>>8);p[3]=(uint8_t)x;
}
static void expand(uint32_t w[68]) {
    for(unsigned j=16;j<68;j++) {
        uint32_t x=w[j-16]^w[j-9]^rol(w[j-3],15);
        w[j]=x^rol(x,15)^rol(x,23)^rol(w[j-13],7)^w[j-6];
    }
}
static int valid_size(size_t n) { return n==16 || n==32; }

int a15_sm3i_layout_words(const uint8_t adrs[32],const uint8_t *input,
    size_t n,uint32_t w[16]) {
    if(!adrs || !input || !w || !valid_size(n)) return 0;
    memset(w,0,16*sizeof *w);
    w[0]=(uint32_t)adrs[3]<<24 | (uint32_t)adrs[8]<<16 |
        (uint32_t)adrs[9]<<8 | adrs[10];
    w[1]=be32(adrs+11);
    w[2]=(uint32_t)adrs[15]<<24 | (uint32_t)adrs[19]<<16 |
        (uint32_t)adrs[20]<<8 | adrs[21];
    w[3]=(uint32_t)adrs[22]<<24 | (uint32_t)adrs[23]<<16 |
        (uint32_t)adrs[24]<<8 | adrs[25];
    w[4]=(uint32_t)adrs[26]<<24 | (uint32_t)adrs[27]<<16 |
        (uint32_t)adrs[28]<<8 | adrs[29];
    w[5]=(uint32_t)adrs[30]<<24 | (uint32_t)adrs[31]<<16 |
        (uint32_t)input[0]<<8 | input[1];
    for(size_t j=0;j<n/4-1;j++) w[6+j]=be32(input+2+4*j);
    w[5+n/4]=(uint32_t)input[n-2]<<24 |
        (uint32_t)input[n-1]<<16 | UINT32_C(0x8000);
    w[15]=(uint32_t)((64+22+n)*8);
    return 1;
}
/* Separate byte construction preserves the pre-B1 representation as a control. */
static void layout_bytes(const uint8_t adrs[32],const uint8_t *input,
    size_t n,uint32_t w[16]) {
    uint8_t block[64]={0};
    block[0]=adrs[3];memcpy(block+1,adrs+8,8);
    memcpy(block+9,adrs+19,13);memcpy(block+22,input,n);
    block[22+n]=0x80;
    uint64_t bits=(64+22+n)*8;
    for(unsigned j=0;j<8;j++) block[63-j]=(uint8_t)(bits>>(8*j));
    for(unsigned j=0;j<16;j++) w[j]=be32(block+4*j);
    a15_secure_zero(block,sizeof block);
}
static void layout(const uint8_t adrs[32],const uint8_t *input,
    size_t n,unsigned b1,uint32_t w[16]) {
    if(b1) (void)a15_sm3i_layout_words(adrs,input,n,w);
    else layout_bytes(adrs,input,n,w);
}

/* Tables contain public index perturbations only. Each q is initialized once;
 * the acquire/release publication allows simultaneous streams without a lock. */
static uint32_t deltas[21][68], offsets[22][68][8];
static atomic_uint deltas_state=ATOMIC_VAR_INIT(0);
static atomic_uint offsets_state[22];
static void index_delta(uint32_t d,uint32_t w[68]) {
    memset(w,0,68*sizeof *w);w[4]=d>>16;w[5]=d<<16;expand(w);
}
static void prepare_deltas(void) {
    unsigned state=atomic_load_explicit(&deltas_state,memory_order_acquire);
    if(state==2) return;
    unsigned expected=0;
    if(atomic_compare_exchange_strong_explicit(&deltas_state,&expected,1,
            memory_order_acq_rel,memory_order_acquire)) {
        for(unsigned r=0;r<21;r++) index_delta((UINT32_C(1)<<(r+1))-1,deltas[r]);
        atomic_store_explicit(&deltas_state,2,memory_order_release);
    } else while(atomic_load_explicit(&deltas_state,memory_order_acquire)!=2) {}
}
static const uint32_t (*prepare_offsets(unsigned q))[8] {
    unsigned state=atomic_load_explicit(offsets_state+q,memory_order_acquire);
    if(state!=2) {
        unsigned expected=0;
        if(atomic_compare_exchange_strong_explicit(offsets_state+q,&expected,1,
                memory_order_acq_rel,memory_order_acquire)) {
            uint32_t basis[3][68];
            for(unsigned b=0;b<3;b++) index_delta(UINT32_C(1)<<(q+b),basis[b]);
            for(unsigned j=0;j<68;j++) for(unsigned lane=0;lane<8;lane++)
                offsets[q][j][lane]=((lane&1)?basis[0][j]:0)^
                    ((lane&2)?basis[1][j]:0)^((lane&4)?basis[2][j]:0);
            atomic_store_explicit(offsets_state+q,2,memory_order_release);
        } else while(atomic_load_explicit(offsets_state+q,memory_order_acquire)!=2) {}
    }
    return (const uint32_t (*)[8])offsets[q];
}

#if (defined(__x86_64__) || defined(__i386__)) && \
    (defined(__GNUC__) || defined(__clang__)) && !defined(SLH_DISABLE_AVX2)
#include <immintrin.h>
#define AVX2 __attribute__((target("avx2")))
static AVX2 inline __m256i rv(__m256i x,unsigned n) {
    return _mm256_or_si256(_mm256_sll_epi32(x,_mm_cvtsi32_si128((int)n)),
        _mm256_srl_epi32(x,_mm_cvtsi32_si128((int)(32-n))));
}
static AVX2 void expand8(const uint32_t input[16][8],uint32_t w[68][8]) {
    if((const void *)input!=(const void *)w) memcpy(w,input,16*8*sizeof(uint32_t));
    for(unsigned j=16;j<68;j++) {
        __m256i a=_mm256_loadu_si256((const __m256i *)(const void *)w[j-16]);
        __m256i b=_mm256_loadu_si256((const __m256i *)(const void *)w[j-9]);
        __m256i c=_mm256_loadu_si256((const __m256i *)(const void *)w[j-3]);
        __m256i x=_mm256_xor_si256(_mm256_xor_si256(a,b),rv(c,15));
        __m256i p=_mm256_xor_si256(_mm256_xor_si256(x,rv(x,15)),rv(x,23));
        __m256i d=_mm256_loadu_si256((const __m256i *)(const void *)w[j-13]);
        __m256i e=_mm256_loadu_si256((const __m256i *)(const void *)w[j-6]);
        _mm256_storeu_si256((__m256i *)(void *)w[j],
            _mm256_xor_si256(p,_mm256_xor_si256(rv(d,7),e)));
    }
}
typedef struct { __m256i initial[8],v[8],word[2],tmp[6];uint32_t lanes[8]; } round_workspace;
static AVX2 void rounds8(const uint32_t seed[8],const uint32_t w[68][8],
    const uint32_t u[68],const uint32_t p[68][8],uint8_t out[8][32]) {
    round_workspace s;
    for(unsigned j=0;j<8;j++) s.v[j]=s.initial[j]=_mm256_set1_epi32((int)seed[j]);
    for(unsigned j=0;j<64;j++) {
        if(u) {
            s.word[0]=_mm256_xor_si256(_mm256_set1_epi32((int)u[j]),
                _mm256_loadu_si256((const __m256i *)(const void *)p[j]));
            s.word[1]=_mm256_xor_si256(_mm256_set1_epi32((int)u[j+4]),
                _mm256_loadu_si256((const __m256i *)(const void *)p[j+4]));
        } else {
            s.word[0]=_mm256_loadu_si256((const __m256i *)(const void *)w[j]);
            s.word[1]=_mm256_loadu_si256((const __m256i *)(const void *)w[j+4]);
        }
        s.tmp[0]=rv(s.v[0],12);
        s.tmp[1]=rv(_mm256_add_epi32(_mm256_add_epi32(s.tmp[0],s.v[4]),
            _mm256_set1_epi32((int)rol(j<16?UINT32_C(0x79cc4519):UINT32_C(0x7a879d8a),j))),7);
        s.tmp[2]=j<16?_mm256_xor_si256(_mm256_xor_si256(s.v[0],s.v[1]),s.v[2]):
            _mm256_or_si256(_mm256_and_si256(s.v[0],s.v[1]),
            _mm256_and_si256(s.v[2],_mm256_or_si256(s.v[0],s.v[1])));
        s.tmp[3]=j<16?_mm256_xor_si256(_mm256_xor_si256(s.v[4],s.v[5]),s.v[6]):
            _mm256_or_si256(_mm256_and_si256(s.v[4],s.v[5]),_mm256_andnot_si256(s.v[4],s.v[6]));
        s.tmp[4]=_mm256_add_epi32(_mm256_add_epi32(s.tmp[2],s.v[3]),
            _mm256_add_epi32(_mm256_xor_si256(s.tmp[1],s.tmp[0]),
            _mm256_xor_si256(s.word[0],s.word[1])));
        s.tmp[5]=_mm256_add_epi32(_mm256_add_epi32(s.tmp[3],s.v[7]),
            _mm256_add_epi32(s.tmp[1],s.word[0]));
        s.v[3]=s.v[2];s.v[2]=rv(s.v[1],9);s.v[1]=s.v[0];s.v[0]=s.tmp[4];
        s.v[7]=s.v[6];s.v[6]=rv(s.v[5],19);s.v[5]=s.v[4];
        s.v[4]=_mm256_xor_si256(_mm256_xor_si256(s.tmp[5],rv(s.tmp[5],9)),rv(s.tmp[5],17));
    }
    for(unsigned j=0;j<8;j++) {
        _mm256_storeu_si256((__m256i *)(void *)s.lanes,_mm256_xor_si256(s.initial[j],s.v[j]));
        for(unsigned lane=0;lane<8;lane++) put32(out[lane]+4*j,s.lanes[lane]);
    }
    a15_secure_zero(&s,sizeof s);
}
static AVX2 void update8(uint32_t w[68][8],const uint32_t delta[68]) {
    for(unsigned j=0;j<68;j++) _mm256_storeu_si256((__m256i *)(void *)w[j],
        _mm256_xor_si256(_mm256_loadu_si256((const __m256i *)(const void *)w[j]),
        _mm256_set1_epi32((int)delta[j])));
}
#else
static void expand8(const uint32_t input[16][8],uint32_t w[68][8]) {
    uint32_t lane_words[68];
    for(unsigned lane=0;lane<8;lane++) {
        for(unsigned j=0;j<16;j++) lane_words[j]=input[j][lane];
        expand(lane_words);
        for(unsigned j=0;j<68;j++) w[j][lane]=lane_words[j];
    }
    a15_secure_zero(lane_words,sizeof lane_words);
}
static void rounds8(const uint32_t seed[8],const uint32_t w[68][8],
    const uint32_t u[68],const uint32_t p[68][8],uint8_t out[8][32]) {
    uint32_t v[8],ww[2];
    for(unsigned lane=0;lane<8;lane++) {
        memcpy(v,seed,sizeof v);
        for(unsigned j=0;j<64;j++) {
            ww[0]=u?u[j]^p[j][lane]:w[j][lane];
            ww[1]=u?u[j+4]^p[j+4][lane]:w[j+4][lane];
            uint32_t ar=rol(v[0],12),ss1=rol(ar+v[4]+rol(j<16?
                UINT32_C(0x79cc4519):UINT32_C(0x7a879d8a),j),7);
            uint32_t ff=j<16?v[0]^v[1]^v[2]:(v[0]&v[1])|(v[2]&(v[0]|v[1]));
            uint32_t gg=j<16?v[4]^v[5]^v[6]:(v[4]&v[5])|(~v[4]&v[6]);
            uint32_t t1=ff+v[3]+(ss1^ar)+(ww[0]^ww[1]);
            uint32_t t2=gg+v[7]+ss1+ww[0];
            v[3]=v[2];v[2]=rol(v[1],9);v[1]=v[0];v[0]=t1;
            v[7]=v[6];v[6]=rol(v[5],19);v[5]=v[4];
            v[4]=t2^rol(t2,9)^rol(t2,17);
        }
        for(unsigned j=0;j<8;j++) put32(out[lane]+4*j,seed[j]^v[j]);
    }
    a15_secure_zero(v,sizeof v);a15_secure_zero(ww,sizeof ww);
}
static void update8(uint32_t w[68][8],const uint32_t delta[68]) {
    for(unsigned j=0;j<68;j++) for(unsigned lane=0;lane<8;lane++) w[j][lane]^=delta[j];
}
#endif

int a15_sm3i_thash8(const uint32_t seed[8],const uint8_t adrs[8][32],
    const uint8_t *inputs[8],size_t n,unsigned b1,uint8_t out[8][16]) {
    if(!seed || !adrs || !inputs || !out || !valid_size(n) || b1>1 ||
        !a15_sm3_avx2_available()) return 0;
    for(unsigned lane=0;lane<8;lane++) if(!inputs[lane]) return 0;
    uint32_t words[16][8],one[16],w[68][8];uint8_t full[8][32];
    for(unsigned lane=0;lane<8;lane++) {
        layout(adrs[lane],inputs[lane],n,b1,one);
        for(unsigned j=0;j<16;j++) words[j][lane]=one[j];
    }
    expand8((const uint32_t (*)[8])words,w);
    rounds8(seed,(const uint32_t (*)[8])w,NULL,NULL,full);
    for(unsigned lane=0;lane<8;lane++) memcpy(out[lane],full[lane],16);
    a15_secure_zero(words,sizeof words);a15_secure_zero(one,sizeof one);
    a15_secure_zero(w,sizeof w);a15_secure_zero(full,sizeof full);return 1;
}
void a15_sm3i_clear(a15_sm3i_stream *s) { if(s) a15_secure_zero(s,sizeof *s); }
static int overlap(const void *a,size_t na,const void *b,size_t nb) {
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return x<=y?y-x<na:x-y<nb;
}
static void build_schedule(a15_sm3i_stream *s) {
    uint8_t adrs[32];uint32_t one[16];
    memcpy(adrs,s->adrs,sizeof adrs);
    if(s->mode==A15_SM3I_F1 || s->mode==A15_SM3I_AF) {
        put32(adrs+28,s->start+s->step);
        layout(adrs,s->skseed,16,s->b1,s->secret.u);expand(s->secret.u);
    } else {
        for(unsigned lane=0;lane<8;lane++) {
            put32(adrs+28,s->start+(lane<<s->q)+s->step);
            layout(adrs,s->skseed,16,s->b1,one);
            for(unsigned j=0;j<16;j++) s->secret.w8[j][lane]=one[j];
        }
        expand8((const uint32_t (*)[8])s->secret.w8,s->secret.w8);
    }
    a15_secure_zero(one,sizeof one);a15_secure_zero(adrs,sizeof adrs);
}
int a15_sm3i_init(a15_sm3i_stream *s,const uint32_t seed[8],
    const uint8_t adrs[32],const uint8_t skseed[16],uint32_t start,
    unsigned z,unsigned pid,unsigned a,unsigned k,unsigned mode,unsigned b1) {
    if(!s) return -1;
    if(!seed || !adrs || !skseed || overlap(s,sizeof *s,seed,32) ||
        overlap(s,sizeof *s,adrs,32) || overlap(s,sizeof *s,skseed,16)) {
        a15_sm3i_clear(s);return -1;
    }
    a15_sm3i_clear(s);
    if(pid!=3 || a!=24 || k!=6 || z<3 || z>24 ||
        mode<A15_SM3I_F8 || mode>A15_SM3I_AF || b1>1) return -1;
    uint64_t size=UINT64_C(1)<<z,end=(uint64_t)start+size;
    if(((uint64_t)start&(size-1)) || end>(UINT64_C(1)<<32) ||
        end>((uint64_t)k<<a)) return -1;
    if(z==3 || !a15_sm3_avx2_available()) return 0;
    memcpy(s->seed,seed,sizeof s->seed);memcpy(s->adrs,adrs,sizeof s->adrs);
    memcpy(s->skseed,skseed,sizeof s->skseed);
    put32(s->adrs+16,6);put32(s->adrs+24,0);put32(s->adrs+28,start);
    s->start=start;s->q=z-3;s->batches=UINT32_C(1)<<s->q;
    s->mode=mode;s->b1=b1;s->ready=1;
    if(mode==A15_SM3I_F1 || mode==A15_SM3I_AF) s->offsets=prepare_offsets(s->q);
    if(mode==A15_SM3I_A8 || mode==A15_SM3I_AF) {
        prepare_deltas();s->deltas=(const uint32_t (*)[68])deltas;
    }
    build_schedule(s);return 1;
}
int a15_sm3i_consume(const a15_sm3i_stream *s,uint8_t out[8][16]) {
    if(!s || !out || overlap(s,sizeof *s,out,8*16)) return 0;
    if(!s->ready || s->step>=s->batches) { memset(out,0,8*16);return 0; }
    uint8_t full[8][32];
    if(s->mode==A15_SM3I_F1 || s->mode==A15_SM3I_AF)
        rounds8(s->seed,NULL,s->secret.u,s->offsets,full);
    else rounds8(s->seed,s->secret.w8,NULL,NULL,full);
    for(unsigned lane=0;lane<8;lane++) memcpy(out[lane],full[lane],16);
    a15_secure_zero(full,sizeof full);return 1;
}
int a15_sm3i_advance(a15_sm3i_stream *s) {
    if(!s || !s->ready || s->step>=s->batches) {a15_sm3i_clear(s);return 0;}
    if(s->step+1==s->batches) {a15_sm3i_clear(s);return 0;}
    ++s->step;
    if(s->mode==A15_SM3I_A8 || s->mode==A15_SM3I_AF) {
        unsigned r=0;uint32_t value=s->step;
        while(!(value&1)) {++r;value>>=1;}
        if(s->mode==A15_SM3I_A8) update8(s->secret.w8,s->deltas[r]);
        else for(unsigned j=0;j<68;j++) s->secret.u[j]^=s->deltas[r][j];
    } else build_schedule(s);
    return 1;
}
int a15_sm3i_next(a15_sm3i_stream *s,uint8_t out[8][16]) {
    if(!a15_sm3i_consume(s,out)) {a15_sm3i_clear(s);return 0;}
    (void)a15_sm3i_advance(s);return 1;
}

#ifdef SLH_TEST_BUILD
void a15_sm3i_test_expand8(const uint32_t words[16][8],uint32_t w[68][8]) {expand8(words,w);}
void a15_sm3i_test_rounds8(const uint32_t seed[8],const uint32_t w[68][8],uint8_t out[8][32]) {rounds8(seed,w,NULL,NULL,out);}
int a15_sm3i_test_consume256(const a15_sm3i_stream *s,uint8_t out[8][32]) {
    if(!s || !s->ready || !out || overlap(s,sizeof *s,out,8*32)) return 0;
    if(s->mode==A15_SM3I_F1 || s->mode==A15_SM3I_AF)
        rounds8(s->seed,NULL,s->secret.u,s->offsets,out);
    else rounds8(s->seed,s->secret.w8,NULL,NULL,out);
    return 1;
}
int a15_sm3i_test_snapshot(const a15_sm3i_stream *s,uint32_t w[68][8],uint32_t wp[64][8]) {
    if(!s || !s->ready) return 0;
    for(unsigned j=0;j<68;j++) for(unsigned lane=0;lane<8;lane++)
        w[j][lane]=(s->mode==A15_SM3I_F1 || s->mode==A15_SM3I_AF)?
            s->secret.u[j]^s->offsets[j][lane]:s->secret.w8[j][lane];
    for(unsigned j=0;j<64;j++) for(unsigned lane=0;lane<8;lane++) wp[j][lane]=w[j][lane]^w[j+4][lane];
    return 1;
}
int a15_sm3i_test_seek(a15_sm3i_stream *s,uint32_t step) {
    if(!s || !s->ready || step>=s->batches) return 0;
    s->step=step;build_schedule(s);return 1;
}
const uint32_t (*a15_sm3i_test_offsets(unsigned q))[8] {
    return q<=21?prepare_offsets(q):NULL;
}
#endif
