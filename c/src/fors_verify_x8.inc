/* Fixed pid3 single-request FORS recovery. Included after thash8_mask. */
#ifndef A15_INCREMENTAL_V1
#define A15_INCREMENTAL_V1 0
#endif
#if A15_INCREMENTAL_V1 != 0 && A15_INCREMENTAL_V1 != 1
#error A15_INCREMENTAL_V1 must be zero or one
#endif
#if (defined(A15_TEST_V1_DIAGNOSTICS) || defined(A15_TEST_V1_STAGE)) && !defined(SLH_TEST_BUILD)
#error Private V1 hooks require SLH_TEST_BUILD
#endif

#if A15_INCREMENTAL_V1
#ifdef A15_TEST_V1_DIAGNOSTICS
static _Thread_local unsigned a15_test_v1_force_scalar;
static _Atomic uint64_t a15_test_v1_calls;
static _Atomic uint64_t a15_test_v1_f_packages;
static _Atomic uint64_t a15_test_v1_h_packages;
static _Atomic uint64_t a15_test_v1_padding_lanes;
#define V1_DIAGNOSTIC(counter, value) atomic_fetch_add_explicit(&(counter), (value), memory_order_relaxed)
#else
#define V1_DIAGNOSTIC(counter, value) ((void)0)
#endif

static int fors_verify_x8_eligible(const work *w) {
    if(w->p->pid != SLH_SM3_128_24 || !w->p->sm3 ||
       w->p->a != 24 || w->p->k != 6 || w->backend != SLH_BACKEND_AVX2)
        return 0;
#ifdef A15_TEST_V1_DIAGNOSTICS
    if(a15_test_v1_force_scalar) return 0;
#endif
    return 1;
}

static void fors_from_sig_x8(work w, uint8_t *roots,
                             const uint8_t *fors_signature,
                             const uint32_t *indices) {
    work lanes[8];
    uint8_t nodes[8][N], pairs[8][2*N], filler[2*N] = {0};
    const uint8_t *inputs[8];
    uint32_t absolute[6];
    const size_t stride = 25*N;
    V1_DIAGNOSTIC(a15_test_v1_calls, 1);
    for(unsigned lane = 0; lane < 8; lane++) {
        lanes[lane] = w;
        /* Empty lanes use a fixed public address and fully defined zero input. */
        if(lane >= 6) {
            memset(lanes[lane].adrs, 0, sizeof lanes[lane].adrs);
            inputs[lane] = filler;
            continue;
        }
        absolute[lane] = (lane << 24) + indices[lane];
        put32(lanes[lane].adrs+24, 0);
        put32(lanes[lane].adrs+28, absolute[lane]);
        inputs[lane] = fors_signature + lane*stride;
    }
#ifdef A15_TEST_V1_STAGE
    A15_TEST_V1_STAGE(lanes, inputs, N, C_F, 0x3fu);
#endif
    thash8_mask(lanes, nodes, inputs, N, C_F, 0x3fu);
    V1_DIAGNOSTIC(a15_test_v1_f_packages, 1);
    V1_DIAGNOSTIC(a15_test_v1_padding_lanes, 2);
    for(unsigned height = 0; height < 24; height++) {
        for(unsigned lane = 0; lane < 6; lane++) {
            const uint8_t *auth = fors_signature + lane*stride + (height+1)*N;
            const unsigned right = (indices[lane] >> height) & 1u;
            memcpy(pairs[lane] + right*N, nodes[lane], N);
            memcpy(pairs[lane] + (right^1u)*N, auth, N);
            inputs[lane] = pairs[lane];
            put32(lanes[lane].adrs+24, height+1);
            put32(lanes[lane].adrs+28, absolute[lane] >> (height+1));
        }
#ifdef A15_TEST_V1_STAGE
        A15_TEST_V1_STAGE(lanes, inputs, 2*N, C_H, 0x3fu);
#endif
        thash8_mask(lanes, nodes, inputs, 2*N, C_H, 0x3fu);
        V1_DIAGNOSTIC(a15_test_v1_h_packages, 1);
        V1_DIAGNOSTIC(a15_test_v1_padding_lanes, 2);
    }
    memcpy(roots, nodes, 6*N);
    a15_secure_zero(nodes, sizeof nodes);
    a15_secure_zero(pairs, sizeof pairs);
}
#undef V1_DIAGNOSTIC
#endif
