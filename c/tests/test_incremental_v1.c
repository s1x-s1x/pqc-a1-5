/* Standalone correctness only. Public fixture fields are supplied as binaries
 * by the Python JSON reader; this executable never signs or measures time. */
#define SLH_TEST_BUILD 1
#define A15_TEST_V1_DIAGNOSTICS 1
#ifndef A15_INCREMENTAL_V1
#define A15_INCREMENTAL_V1 1
#endif
#if !A15_INCREMENTAL_V1
#error This harness requires the V1 branch to be enabled
#endif
#ifndef SLH_COUNTERS
#error This harness requires SLH_COUNTERS for logical-count acceptance
#endif
#include <stddef.h>
static void observe_v1_stage(const void *, const unsigned char *const *,
                             size_t, int, unsigned);
#define A15_TEST_V1_STAGE(lanes, inputs, n, kind, mask) observe_v1_stage(lanes, inputs, n, kind, mask)
#include "../src/engine.c"

#define CHECK(x) do {if(!(x)){fprintf(stderr, "V1 FAIL line %d: %s\n", __LINE__, #x);exit(1);}} while(0)
static unsigned observed_stages;
static uint32_t random_state = UINT32_C(0x51f01234);
static uint32_t next_random(void) {
    random_state ^= random_state << 13;
    random_state ^= random_state >> 17;
    random_state ^= random_state << 5;
    return random_state;
}
static void reset_v1(void) {
    atomic_store(&a15_test_v1_calls, 0);
    atomic_store(&a15_test_v1_f_packages, 0);
    atomic_store(&a15_test_v1_h_packages, 0);
    atomic_store(&a15_test_v1_padding_lanes, 0);
    observed_stages = 0;
}
static void check_v1_hits(unsigned calls) {
    CHECK(atomic_load(&a15_test_v1_calls) == calls);
    CHECK(atomic_load(&a15_test_v1_f_packages) == calls);
    CHECK(atomic_load(&a15_test_v1_h_packages) == calls*24);
    CHECK(atomic_load(&a15_test_v1_padding_lanes) == calls*50);
    CHECK(observed_stages == calls*25);
}
static void observe_v1_stage(const void *opaque, const uint8_t *const *inputs,
                             size_t n, int kind, unsigned mask) {
    const work *lanes = opaque;
    const unsigned height = observed_stages%25;
    const uint8_t zero[32] = {0};
    CHECK(mask == 0x3fu);
    CHECK(kind == (height ? C_H : C_F));
    CHECK(n == (height ? 2*N : N));
    for(unsigned lane = 0; lane < 6; lane++) {
        CHECK(get32(lanes[lane].adrs+16) == 3);
        CHECK(get32(lanes[lane].adrs+24) == height);
        CHECK(get32(lanes[lane].adrs+28)/(UINT32_C(1) << (24-height)) == lane);
    }
    for(unsigned lane = 6; lane < 8; lane++) {
        CHECK(!memcmp(lanes[lane].adrs, zero, 32));
        CHECK(!memcmp(inputs[lane], zero, n));
        CHECK(!memcmp(lanes[lane].seed.sm3.h, lanes[0].seed.sm3.h, 32));
    }
    observed_stages++;
}

/* Independent byte construction and full scalar SM3, without thash/hpair or
 * the cached midstate final-block constructor under test. */
static void scalar_hash(const uint8_t pkseed[N], const uint8_t adrs[32],
                        const uint8_t *payload, size_t n, uint8_t out[N]) {
    uint8_t prefix[64] = {0}, address[22], digest[32];
    memcpy(prefix, pkseed, N);
    address[0] = adrs[3];
    for(unsigned i = 0; i < 8; i++) address[1+i] = adrs[8+i];
    for(unsigned i = 0; i < 13; i++) address[9+i] = adrs[19+i];
    a15_sm3 s;
    a15_sm3_init(&s);
    a15_sm3_update(&s, prefix, sizeof prefix);
    a15_sm3_update(&s, address, sizeof address);
    a15_sm3_update(&s, payload, n);
    a15_sm3_final(&s, digest);
    memcpy(out, digest, N);
    a15_secure_zero(&s, sizeof s);
    a15_secure_zero(digest, sizeof digest);
}
static void scalar_fors(work w, uint8_t roots[6*N], const uint8_t *sig,
                        const uint32_t indices[6]) {
    for(unsigned tree = 0; tree < 6; tree++) {
        uint8_t address[32], pair[2*N];
        const uint8_t *path = sig+tree*25*N;
        const uint32_t absolute = tree*UINT32_C(0x1000000)+indices[tree];
        memcpy(address, w.adrs, 32);
        put32(address+24, 0);
        put32(address+28, absolute);
        scalar_hash(w.pkseed, address, path, N, roots+tree*N);
        for(unsigned height = 0; height < 24; height++) {
            const unsigned offset = ((indices[tree] >> height)&1u)*N;
            memcpy(pair+offset, roots+tree*N, N);
            memcpy(pair+(N-offset), path+(height+1)*N, N);
            put32(address+24, height+1);
            put32(address+28, absolute >> (height+1));
            scalar_hash(w.pkseed, address, pair, sizeof pair, roots+tree*N);
        }
    }
}
static void component_tests(void) {
    uint8_t pk[2*N], sig[6*25*N], expected[6*N], actual[6*N+N];
    unsigned comparisons = 0;
    for(unsigned sample = 0; sample < 64; sample++) {
        for(unsigned i = 0; i < sizeof pk; i++) pk[i] = (uint8_t)next_random();
        for(unsigned i = 0; i < sizeof sig; i++) sig[i] = (uint8_t)next_random();
        uint32_t indices[6];
        for(unsigned lane = 0; lane < 6; lane++)
            indices[lane] = sample == 0 ? 0 : sample == 1 ? 0xffffffu :
                sample == 2 ? (lane&1 ? 0xaaaaaau : 0x555555u) :
                sample < 27 ? (1u << (sample-3)) : next_random()&0xffffffu;
        work w;
        init_work(&w, lookup(3), NULL, pk);
        w.backend = SLH_BACKEND_AVX2;
        put32(w.adrs, sample%23);
        set_tree(&w, sample&1 ? UINT64_MAX-sample : next_random());
        set_type_kp(&w, 3);
        put32(w.adrs+20, sample&1 ? 0x3fffffu : next_random()&0x3fffffu);
        uint8_t address_before[32];
        memcpy(address_before, w.adrs, 32);
        scalar_fors(w, expected, sig, indices);
        memset(actual, 0xa5, sizeof actual);
        reset_v1();
        slh_counters_reset();
        fors_from_sig_x8(w, actual, sig, indices);
        slh_counters counted;
        slh_counters_get(&counted);
        CHECK(!memcmp(expected, actual, 6*N));
        CHECK(!memcmp(w.adrs, address_before, 32));
        for(unsigned i = 6*N; i < sizeof actual; i++) CHECK(actual[i] == 0xa5);
        CHECK(counted.f == 6 && counted.h == 144 && counted.compress == 150);
        CHECK(!counted.prf && !counted.prf_msg && !counted.h_msg && !counted.t);
        check_v1_hits(1);
        comparisons++;
    }
    const int pids[] = {1, 2, 3, 101, 102, 103, 201};
    const int backends[] = {SLH_BACKEND_REF, SLH_BACKEND_AVX2, SLH_BACKEND_CUDA};
    for(unsigned i = 0; i < sizeof pids/sizeof *pids; i++)
        for(unsigned j = 0; j < sizeof backends/sizeof *backends; j++) {
            work w;
            init_work(&w, lookup(pids[i]), NULL, pk);
            w.backend = backends[j];
            CHECK(fors_verify_x8_eligible(&w) == (pids[i] == 3 && backends[j] == SLH_BACKEND_AVX2));
        }
    printf("V1 independent scalar roots: %u cases, logical F=6 H=144, physical F_x8=1 H_x8=24 padding=50 per case PASS\n", comparisons);
    puts("V1 eligibility: seven parameters x REF/AVX2/CUDA = 21 cases PASS");
}
static uint8_t *read_fixture(const char *path, size_t maximum, size_t *length) {
    FILE *file = fopen(path, "rb");
    CHECK(file != NULL);
    uint8_t *data = malloc(maximum+1);
    CHECK(data != NULL);
    *length = fread(data, 1, maximum+1, file);
    CHECK(!ferror(file) && *length <= maximum && fgetc(file) == EOF);
    CHECK(!fclose(file));
    return data;
}
static unsigned full_cases;
static void compare_verify(slh_ctx *reference, slh_ctx *vector, const uint8_t *sig,
                           size_t siglen, const uint8_t *message, size_t mlen,
                           const uint8_t *context, size_t clen, const uint8_t *pk,
                           int expected, unsigned expected_hit, const char *label) {
    slh_counters ref_counts, old_counts, new_counts;
    a15_test_v1_force_scalar = 0;
    reset_v1();
    slh_counters_reset();
    CHECK(slh_verify(reference, sig, siglen, message, mlen, context, clen, pk) == expected);
    slh_counters_get(&ref_counts);
    check_v1_hits(0);
    a15_test_v1_force_scalar = 1;
    reset_v1();
    slh_counters_reset();
    CHECK(slh_verify(vector, sig, siglen, message, mlen, context, clen, pk) == expected);
    slh_counters_get(&old_counts);
    check_v1_hits(0);
    a15_test_v1_force_scalar = 0;
    reset_v1();
    slh_counters_reset();
    CHECK(slh_verify(vector, sig, siglen, message, mlen, context, clen, pk) == expected);
    slh_counters_get(&new_counts);
    check_v1_hits(expected_hit);
    CHECK(!memcmp(&ref_counts, &old_counts, sizeof ref_counts));
    CHECK(!memcmp(&ref_counts, &new_counts, sizeof ref_counts));
    printf("V1 fixture %s REF/current-AVX2/new-V1 status=%d route_hits=%u logical counts identical PASS\n", label, expected, expected_hit);
    full_cases++;
}
static void fixture_tests(int argc, char **argv) {
    CHECK(argc == 5);
    size_t pklen, siglen, mlen, clen;
    uint8_t *pk = read_fixture(argv[1], 2*N, &pklen);
    uint8_t *sig = read_fixture(argv[2], slh_sig_bytes(3), &siglen);
    uint8_t *message = read_fixture(argv[3], 1u<<20, &mlen);
    uint8_t *context = read_fixture(argv[4], 255, &clen);
    CHECK(pklen == 2*N && siglen == slh_sig_bytes(3));
    slh_ctx *reference = NULL, *vector = NULL;
    CHECK(!slh_ctx_new(&reference, 3, SLH_BACKEND_REF));
    CHECK(!slh_ctx_new(&vector, 3, SLH_BACKEND_AVX2));
    compare_verify(reference, vector, sig, siglen, message, mlen, context, clen, pk, 0, 1, "valid");
    const size_t mutations[] = {0, N+6*25*N, N+6*25*N+68*N-1, siglen-1};
    for(unsigned i = 0; i < sizeof mutations/sizeof *mutations; i++) {
        sig[mutations[i]] ^= (uint8_t)(1u << (i%8));
        compare_verify(reference, vector, sig, siglen, message, mlen, context, clen, pk, SLH_ERR_VERIFY, 1, "signature-mutation");
        sig[mutations[i]] ^= (uint8_t)(1u << (i%8));
    }
    for(unsigned tree = 0; tree < 6; tree++) {
        const size_t offsets[] = {N+tree*25*N, N+tree*25*N+N,
                                   N+tree*25*N+24*N+N-1};
        for(unsigned element = 0; element < 3; element++) {
            sig[offsets[element]] ^= 1;
            compare_verify(reference, vector, sig, siglen, message, mlen, context, clen, pk, SLH_ERR_VERIFY, 1, "each-tree-secret-auth");
            sig[offsets[element]] ^= 1;
        }
    }
    for(unsigned i = 0; i < 2; i++) {
        pk[i*N] ^= 1;
        compare_verify(reference, vector, sig, siglen, message, mlen, context, clen, pk, SLH_ERR_VERIFY, 1, i ? "pk-root" : "pk-seed");
        pk[i*N] ^= 1;
    }
    if(mlen) {
        message[mlen/2] ^= 1;
        compare_verify(reference, vector, sig, siglen, message, mlen, context, clen, pk, SLH_ERR_VERIFY, 1, "message");
        message[mlen/2] ^= 1;
    }
    if(clen) {
        context[clen/2] ^= 1;
        compare_verify(reference, vector, sig, siglen, message, mlen, context, clen, pk, SLH_ERR_VERIFY, 1, "context");
        context[clen/2] ^= 1;
    }
    compare_verify(reference, vector, sig, siglen-1, message, mlen, context, clen, pk, SLH_ERR_VERIFY, 0, "signature-short");
    compare_verify(reference, vector, sig, siglen+1, message, mlen, context, clen, pk, SLH_ERR_VERIFY, 0, "signature-long");
    compare_verify(reference, vector, sig, siglen, message, mlen, context, 256, pk, SLH_ERR_CTXLEN, 0, "context-long");
    compare_verify(reference, vector, sig, siglen, message, mlen, NULL, 1, pk, SLH_ERR_PARAM, 0, "context-null");
    compare_verify(reference, vector, sig, siglen, NULL, 1, context, clen, pk, SLH_ERR_PARAM, 0, "message-null");
    compare_verify(reference, vector, sig, siglen, message, mlen, context, clen, NULL, SLH_ERR_PARAM, 0, "pk-null");
    compare_verify(reference, vector, NULL, siglen, message, mlen, context, clen, pk, SLH_ERR_PARAM, 0, "signature-null");
    slh_ctx *wrong = NULL;
    CHECK(!slh_ctx_new(&wrong, 103, SLH_BACKEND_REF));
    reset_v1();
    CHECK(slh_verify(wrong, sig, siglen, message, mlen, context, clen, pk) == SLH_ERR_VERIFY);
    check_v1_hits(0);
    slh_ctx_free(wrong);
    for(unsigned pid = 1; pid <= 2; pid++) {
        slh_ctx *wrong_ref = NULL, *wrong_vector = NULL;
        CHECK(!slh_ctx_new(&wrong_ref, pid, SLH_BACKEND_REF));
        CHECK(!slh_ctx_new(&wrong_vector, pid, SLH_BACKEND_AVX2));
        compare_verify(wrong_ref, wrong_vector, sig, siglen, message, mlen, context, clen, pk, SLH_ERR_VERIFY, 0, "parameter-length");
        slh_ctx_free(wrong_ref);
        slh_ctx_free(wrong_vector);
    }
    CHECK(slh_ctx_new(&wrong, 103, SLH_BACKEND_AVX2) == SLH_ERR_BACKEND && wrong == NULL);
    slh_ctx_free(reference);
    slh_ctx_free(vector);
    free(pk);free(sig);free(message);free(context);
    printf("V1 full fixture: %u three-path cases plus SHA2 parameter rejection PASS\n", full_cases);
}
int main(int argc, char **argv) {
    if(argc != 5) {
        fprintf(stderr, "Usage: %s pk.bin sig.bin message.bin context.bin\n", argv[0]);
        return 2;
    }
    if(!a15_sm3_avx2_available()) {
        puts("V1 AVX2 unavailable; no candidate-path correctness claim");
        return 77;
    }
    component_tests();
    fixture_tests(argc, argv);
    puts("V1 correctness PASS; no signing, timing or performance samples");
    return 0;
}
