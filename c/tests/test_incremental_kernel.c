#ifndef SLH_TEST_BUILD
#error Incremental kernel diagnostics require SLH_TEST_BUILD
#endif
#include "sm3_incremental.h"
#include "sm3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _OPENMP
#include <omp.h>
#define PARALLEL_ENABLED "true"
#else
#define PARALLEL_ENABLED "false"
#endif

static unsigned checks,basis_cases,stream_cases,thread_cases;
#define CHECK(x) do { ++checks; if(!(x)) { \
    fprintf(stderr,"incremental kernel failed line %u: %s\n",__LINE__,#x); \
    exit(1); } } while(0)
static uint32_t rng=UINT32_C(0xa15c2026);
static uint32_t random32(void) {
    rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;return rng;
}
static void random_bytes(uint8_t *p,size_t n) {
    for(size_t j=0;j<n;j++) p[j]=(uint8_t)random32();
}
static void write32(uint8_t *p,uint32_t x) {
    for(unsigned j=0;j<4;j++) p[j]=(uint8_t)(x>>(24-8*j));
}
static uint32_t read32(const uint8_t *p) {
    uint32_t x=0;for(unsigned j=0;j<4;j++) x=(x<<8)|p[j];return x;
}
static uint32_t rot(uint32_t x,unsigned n) {return (x<<n)|(x>>(32-n));}
/* Independently serialize the SPEC bytes. No candidate layout helper is used. */
static void reference_block(const uint8_t adrs[32],const uint8_t *input,
    size_t n,uint8_t block[64]) {
    memset(block,0,64);block[0]=adrs[3];
    for(unsigned j=0;j<8;j++) block[1+j]=adrs[8+j];
    for(unsigned j=0;j<13;j++) block[9+j]=adrs[19+j];
    for(size_t j=0;j<n;j++) block[22+j]=input[j];
    block[22+n]=128;
    uint64_t bits=((uint64_t)64+22+n)*8;
    for(unsigned j=0;j<8;j++) block[56+j]=(uint8_t)(bits>>(56-8*j));
}
static void reference_expand(const uint32_t input[16],uint32_t w[68]) {
    memcpy(w,input,16*sizeof *w);
    for(unsigned j=16;j<68;j++) {
        uint32_t t=w[j-16]^w[j-9]^rot(w[j-3],15);
        uint32_t p=t^rot(t,15)^rot(t,23);
        w[j]=p^rot(w[j-13],7)^w[j-6];
    }
}
static void reference_digest(const uint32_t seed[8],const uint8_t block[64],uint8_t out[32]) {
    uint32_t state[8];memcpy(state,seed,sizeof state);
    a15_sm3_compress_block(state,block);
    for(unsigned j=0;j<8;j++) write32(out+4*j,state[j]);
}
static int zero_object(const void *p,size_t n) {
    const unsigned char *b=p;unsigned x=0;
    for(size_t j=0;j<n;j++) x|=b[j];
    return x==0;
}

/* Run before any serial initialization to exercise concurrent table publication. */
static void check_thread_publication(void) {
    int errors=0;
#ifdef _OPENMP
#pragma omp parallel for num_threads(32) reduction(+:errors)
#endif
    for(unsigned worker=0;worker<88;worker++) {
        unsigned q=1+worker%21;uint32_t seed[8];uint8_t adrs[32],sk[16];
        for(unsigned j=0;j<8;j++) seed[j]=UINT32_C(0x76543210)+worker*123+j;
        for(unsigned j=0;j<32;j++) adrs[j]=(uint8_t)(worker+13*j);
        for(unsigned j=0;j<16;j++) sk[j]=(uint8_t)(worker+31*j);
        a15_sm3i_stream s;uint8_t out[8][16];
        if(a15_sm3i_init(&s,seed,adrs,sk,0,q+3,3,24,6,A15_SM3I_AF,worker%2)!=1)
            {++errors;continue;}
        if(!a15_sm3i_next(&s,out)) ++errors;
        for(unsigned lane=0;lane<8;lane++) {
            uint8_t block[64],expected[32];
            write32(adrs+16,6);write32(adrs+24,0);write32(adrs+28,lane<<q);
            reference_block(adrs,sk,16,block);reference_digest(seed,block,expected);
            if(memcmp(expected,out[lane],16)) ++errors;
        }
        a15_sm3i_clear(&s);if(!zero_object(&s,sizeof s)) ++errors;
    }
    thread_cases=88;CHECK(errors==0);
}
static void check_layouts(void) {
    uint32_t seed[8];for(unsigned j=0;j<8;j++) seed[j]=random32();
    for(unsigned trial=0;trial<64;trial++) {
        uint8_t adrs[8][32],input[8][32],b[64],out[8][16],full[8][32];
        const uint8_t *ptrs[8];uint32_t words[16][8],w[68][8];
        size_t n=(trial&1)?32:16;
        random_bytes((uint8_t *)adrs,sizeof adrs);random_bytes((uint8_t *)input,sizeof input);
        for(unsigned lane=0;lane<8;lane++) {
            uint32_t one[16];ptrs[lane]=input[lane];
            CHECK(a15_sm3i_layout_words(adrs[lane],input[lane],n,one));
            reference_block(adrs[lane],input[lane],n,b);
            for(unsigned j=0;j<16;j++) {CHECK(one[j]==read32(b+4*j));words[j][lane]=one[j];}
            CHECK(one[15]==(n==16?816u:944u));
        }
        a15_sm3i_test_expand8((const uint32_t (*)[8])words,w);
        a15_sm3i_test_rounds8(seed,(const uint32_t (*)[8])w,full);
        for(unsigned b1=0;b1<2;b1++) {
            CHECK(a15_sm3i_thash8(seed,(const uint8_t (*)[32])adrs,ptrs,n,b1,out));
            for(unsigned lane=0;lane<8;lane++) {
                uint8_t expected[32];reference_block(adrs[lane],input[lane],n,b);
                reference_digest(seed,b,expected);
                CHECK(!memcmp(expected,full[lane],32));CHECK(!memcmp(expected,out[lane],16));
            }
        }
    }
    uint8_t adrs[32]={0},in[32]={0};uint32_t one[16];
    CHECK(!a15_sm3i_layout_words(NULL,in,16,one));
    CHECK(!a15_sm3i_layout_words(adrs,NULL,16,one));
    CHECK(!a15_sm3i_layout_words(adrs,in,15,one));
    CHECK(!a15_sm3i_layout_words(adrs,in,33,one));
}
static void check_gf2_basis(void) {
    for(unsigned basis=0;basis<512;basis++) {
        uint32_t input[16][8]={{0}},w[68][8];
        for(unsigned lane=0;lane<8;lane++) {
            unsigned b=(basis+37*lane)%512;input[b/32][lane]=UINT32_C(1)<<(b%32);
        }
        a15_sm3i_test_expand8((const uint32_t (*)[8])input,w);
        for(unsigned lane=0;lane<8;lane++) {
            uint32_t one[16],expected[68];
            for(unsigned j=0;j<16;j++) one[j]=input[j][lane];
            reference_expand(one,expected);
            for(unsigned j=0;j<68;j++) CHECK(expected[j]==w[j][lane]);
            for(unsigned j=0;j<64;j++) CHECK((expected[j]^expected[j+4])==(w[j][lane]^w[j+4][lane]));
        }
        ++basis_cases;
    }
    /* Offset bases include q=0, and q14/15 straddle the two index words. */
    for(unsigned q=0;q<=21;q++) {
        const uint32_t (*p)[8]=a15_sm3i_test_offsets(q);CHECK(p!=NULL);
        for(unsigned lane=0;lane<8;lane++) {
            uint32_t one[16]={0},expected[68];uint8_t delta_bytes[64]={0};
            write32(delta_bytes+18,lane<<q);
            for(unsigned j=0;j<16;j++) one[j]=read32(delta_bytes+4*j);
            reference_expand(one,expected);
            for(unsigned j=0;j<68;j++) CHECK(expected[j]==p[j][lane]);
        }
    }
    CHECK(a15_sm3i_test_offsets(22)==NULL);
}
static void check_stream_batch(a15_sm3i_stream *s) {
    a15_sm3i_stream before=*s;uint32_t w[68][8],wp[64][8];
    uint8_t full[8][32],out[8][16];
    CHECK(a15_sm3i_test_snapshot(s,w,wp));
    CHECK(a15_sm3i_test_consume256(s,full));CHECK(a15_sm3i_consume(s,out));
    CHECK(!memcmp(&before,s,sizeof before));
    if(s->mode==A15_SM3I_F1 || s->mode==A15_SM3I_AF)
        CHECK(zero_object((const uint8_t *)&s->secret+272,sizeof s->secret-272));
    for(unsigned lane=0;lane<8;lane++) {
        uint8_t adrs[32],block[64],expected_digest[32];uint32_t one[16],expected[68];
        memcpy(adrs,s->adrs,32);write32(adrs+28,s->start+(lane<<s->q)+s->step);
        reference_block(adrs,s->skseed,16,block);
        for(unsigned j=0;j<16;j++) one[j]=read32(block+4*j);
        reference_expand(one,expected);reference_digest(s->seed,block,expected_digest);
        for(unsigned j=0;j<68;j++) CHECK(w[j][lane]==expected[j]);
        for(unsigned j=0;j<64;j++) CHECK(wp[j][lane]==(expected[j]^expected[j+4]));
        CHECK(!memcmp(expected_digest,full[lane],32));CHECK(!memcmp(expected_digest,out[lane],16));
    }
    ++stream_cases;
}
static void check_streams(void) {
    for(unsigned q=1;q<=21;q++) for(unsigned mode=1;mode<=4;mode++) for(unsigned b1=0;b1<2;b1++) {
        uint32_t seed[8];uint8_t adrs[32],sk[16];
        for(unsigned j=0;j<8;j++) seed[j]=random32();
        random_bytes(adrs,32);random_bytes(sk,16);
        uint32_t size=UINT32_C(1)<<(q+3),end=UINT32_C(6)<<24;
        uint32_t start=end-size;a15_sm3i_stream s;
        CHECK(a15_sm3i_init(&s,seed,adrs,sk,start,q+3,3,24,6,mode,b1)==1);
        /* Mutating caller addresses/seeds proves the fixed context is copied. */
        memset(seed,0,sizeof seed);memset(adrs,0,sizeof adrs);memset(sk,0,sizeof sk);
        if(q<=5) {
            for(uint32_t step=0;step<s.batches;step++) {
                check_stream_batch(&s);
                if(step+1==s.batches) break;
                CHECK(a15_sm3i_advance(&s));
            }
        } else {
            check_stream_batch(&s);
            for(unsigned carry=0;carry<q;carry++) {
                uint32_t step=(UINT32_C(1)<<carry)-1;
                CHECK(a15_sm3i_test_seek(&s,step));check_stream_batch(&s);
                CHECK(a15_sm3i_advance(&s));check_stream_batch(&s);
            }
        }
        CHECK(a15_sm3i_test_seek(&s,s.batches-1));check_stream_batch(&s);
        uint8_t last[8][16];CHECK(a15_sm3i_next(&s,last));CHECK(zero_object(&s,sizeof s));
        memset(last,1,sizeof last);CHECK(!a15_sm3i_next(&s,last));CHECK(zero_object(last,sizeof last));
    }
}
static void check_bounds_and_reuse(void) {
    uint32_t seed[8];uint8_t adrs[32],sk[16];
    for(unsigned j=0;j<8;j++) seed[j]=random32();
    random_bytes(adrs,32);random_bytes(sk,16);
    a15_sm3i_stream s;memset(&s,0xaa,sizeof s);
    CHECK(a15_sm3i_init(&s,seed,adrs,sk,0,3,3,24,6,4,1)==0);CHECK(zero_object(&s,sizeof s));
    const unsigned bad_z[]={0,2,25,32,64};
    for(unsigned j=0;j<sizeof bad_z/sizeof *bad_z;j++) {
        CHECK(a15_sm3i_init(&s,seed,adrs,sk,0,bad_z[j],3,24,6,4,1)==-1);CHECK(zero_object(&s,sizeof s));
    }
    const uint32_t bad_start[]={1,7,UINT32_MAX,UINT32_C(6)<<24,UINT32_C(0xfffffff0)};
    for(unsigned j=0;j<sizeof bad_start/sizeof *bad_start;j++) {
        CHECK(a15_sm3i_init(&s,seed,adrs,sk,bad_start[j],4,3,24,6,4,1)==-1);CHECK(zero_object(&s,sizeof s));
    }
    CHECK(a15_sm3i_init(&s,seed,adrs,sk,0,4,2,24,6,4,1)==-1);
    CHECK(a15_sm3i_init(&s,seed,adrs,sk,0,4,3,23,6,4,1)==-1);
    CHECK(a15_sm3i_init(&s,seed,adrs,sk,0,4,3,24,7,4,1)==-1);
    CHECK(a15_sm3i_init(&s,seed,adrs,sk,0,4,3,24,6,0,1)==-1);
    CHECK(a15_sm3i_init(&s,seed,adrs,sk,0,4,3,24,6,5,1)==-1);
    CHECK(a15_sm3i_init(&s,seed,adrs,sk,0,4,3,24,6,4,2)==-1);
    CHECK(a15_sm3i_init(&s,NULL,adrs,sk,0,4,3,24,6,4,1)==-1);
    for(unsigned reuse=0;reuse<16;reuse++) {
        random_bytes(adrs,32);random_bytes(sk,16);seed[0]=random32();
        CHECK(a15_sm3i_init(&s,seed,adrs,sk,(reuse%6)<<24,17,3,24,6,1+reuse%4,reuse%2)==1);
        check_stream_batch(&s);
        CHECK(!a15_sm3i_consume(&s,(uint8_t (*)[16])(void *)&s));
        a15_sm3i_clear(&s);CHECK(zero_object(&s,sizeof s));
    }
    CHECK(a15_sm3i_init(&s,seed,adrs,sk,0,4,3,24,6,4,1)==1);
    CHECK(!a15_sm3i_next(&s,NULL));CHECK(zero_object(&s,sizeof s));
    CHECK(a15_sm3i_init(&s,seed,adrs,sk,0,4,3,24,6,4,1)==1);
    CHECK(a15_sm3i_init(&s,s.seed,adrs,sk,0,4,3,24,6,4,1)==-1);CHECK(zero_object(&s,sizeof s));
    /* UINT32_MAX exceeds the real forest. Its layout/complete digest is tested
     * separately rather than admitting an invalid stream index. */
    write32(adrs+28,UINT32_MAX);uint8_t block[64];uint32_t words[16];
    CHECK(a15_sm3i_layout_words(adrs,sk,16,words));reference_block(adrs,sk,16,block);
    for(unsigned j=0;j<16;j++) CHECK(words[j]==read32(block+4*j));
}
int main(void) {
    if(!a15_sm3_avx2_available()) {
        uint32_t seed[8]={0};uint8_t adrs[32]={0},sk[16]={0};a15_sm3i_stream s;
        if(a15_sm3i_init(&s,seed,adrs,sk,0,4,3,24,6,4,1)!=0 || !zero_object(&s,sizeof s)) return 1;
        puts("{\"status\":\"fallback_checked\",\"avx2\":false,\"performance_samples\":0}");return 0;
    }
    check_thread_publication();check_layouts();check_gf2_basis();check_streams();check_bounds_and_reuse();
    printf("{\"status\":\"passed\",\"checks\":%u,\"basis_inputs\":%u,\"stream_batches\":%u,\"table_publication_streams\":%u,\"parallel_enabled\":%s,\"stream_object_bytes\":%u,\"secret_w8_bytes\":2176,\"secret_u_bytes\":272,\"public_delta_bytes\":5712,\"public_offsets_all_q_bytes\":47872,\"performance_samples\":0}\n",
        checks,basis_cases,stream_cases,thread_cases,PARALLEL_ENABLED,(unsigned)sizeof(a15_sm3i_stream));
    return 0;
}
