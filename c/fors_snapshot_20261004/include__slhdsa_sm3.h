#ifndef SLHDSA_SM3_H
#define SLHDSA_SM3_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#define SLH_API __declspec(dllexport)
#else
#define SLH_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum {
    SLH_SM3_128S = 1, SLH_SM3_128F = 2, SLH_SM3_128_24 = 3,
    SLH_SHA2_128S = 101, SLH_SHA2_128F = 102, SLH_SHA2_128_24 = 103,
    SLH_TOY_SM3 = 201
};
enum {
    SLH_BACKEND_AUTO = 0, SLH_BACKEND_REF = 1, SLH_BACKEND_AVX2 = 2,
    SLH_BACKEND_AVX512 = 3, SLH_BACKEND_NEON = 4, SLH_BACKEND_CUDA = 5
};
enum {
    SLH_PREHASH_SHA256 = 1, SLH_PREHASH_SHA512 = 2,
    SLH_PREHASH_SHAKE128 = 3, SLH_PREHASH_SHAKE256 = 4,
    SLH_PREHASH_SM3 = 5
};
/* Verify the computed signature before returning it. A failed self-check
 * returns SLH_ERR_FAULT and wipes all slh_sig_bytes(pid) output bytes. The
 * public slh_sign wrapper also leaves *siglen == 0 on failure. */
#define SLH_FLAG_VERIFY_AFTER_SIGN 0x100u
#define SLH_OK 0
#define SLH_ERR_PARAM (-1)
#define SLH_ERR_BACKEND (-2)
#define SLH_ERR_VERIFY (-3)
#define SLH_ERR_CACHE (-4)
#define SLH_ERR_FAULT (-5)
#define SLH_ERR_ALLOC (-6)
#define SLH_ERR_CTXLEN (-7)

typedef struct slh_ctx slh_ctx;
typedef enum { SLH_LEAF_WOTS = 0, SLH_LEAF_FORS = 1 } slh_leaf_type;
typedef struct {
    uint64_t prf, prf_msg, h_msg, f, h, t, compress;
} slh_counters;

SLH_API int slh_ctx_new(slh_ctx **ctx, int pid, unsigned flags);
/* AUTO picks AVX2 for SM3/FORS on capable CPUs and REF otherwise. Explicit
 * AVX2 requires SM3 and runtime CPU/OS support; SHA2 contexts remain REF.
 * WOTS and verification currently retain the scalar implementation. */
SLH_API int slh_backend_available(int backend);
SLH_API int slh_ctx_backend(const slh_ctx *ctx);
SLH_API int slh_ctx_set_threads(slh_ctx *ctx, int nthreads);
SLH_API int slh_ctx_set_cache_level(slh_ctx *ctx, unsigned t);
SLH_API void slh_ctx_free(slh_ctx *ctx);
SLH_API size_t slh_pk_bytes(int pid);
SLH_API size_t slh_sk_bytes(int pid);
SLH_API size_t slh_sig_bytes(int pid);

SLH_API int slh_keygen_internal(slh_ctx *ctx, uint8_t *pk, uint8_t *sk,
    const uint8_t *sk_seed, const uint8_t *sk_prf, const uint8_t *pk_seed);
SLH_API int slh_keygen(slh_ctx *ctx, uint8_t *pk, uint8_t *sk);
SLH_API int slh_sign(slh_ctx *ctx, uint8_t *sig, size_t *siglen,
    const uint8_t *msg, size_t mlen, const uint8_t *ctxstr, size_t ctxlen,
    const uint8_t *sk, const uint8_t *addrnd);
SLH_API int slh_verify(slh_ctx *ctx, const uint8_t *sig, size_t siglen,
    const uint8_t *msg, size_t mlen, const uint8_t *ctxstr, size_t ctxlen,
    const uint8_t *pk);
SLH_API int slh_sign_internal(slh_ctx *ctx, uint8_t *sig,
    const uint8_t *mp, size_t mplen, const uint8_t *sk, const uint8_t *addrnd);
SLH_API int slh_verify_internal(slh_ctx *ctx, const uint8_t *sig, size_t siglen,
    const uint8_t *mp, size_t mplen, const uint8_t *pk);
/* HashSLH-DSA encoding is 01 || ctxlen || ctx || DER_OID || PH(M), distinct
 * from the pure entry point's 00 prefix. SHA256/SHA512/SHAKE128/SHAKE256 use
 * the FIPS 205 OIDs and output lengths 32/64/32/64. SM3 uses its standard
 * 1.2.156.10197.1.401 OID and 32 bytes as an experimental SM3 profile.
 * This SM3 profile is not a FIPS-approved prehash instantiation.
 * Digest entry points require exactly slh_prehash_bytes(hash_alg) bytes.
 * Counters cover the SLH core, excluding computation of the message prehash. */
SLH_API size_t slh_prehash_bytes(int hash_alg);
SLH_API int slh_sign_prehash(slh_ctx *ctx, uint8_t *sig, size_t *siglen,
    int hash_alg, const uint8_t *msg, size_t mlen,
    const uint8_t *ctxstr, size_t ctxlen, const uint8_t *sk, const uint8_t *addrnd);
SLH_API int slh_verify_prehash(slh_ctx *ctx, const uint8_t *sig, size_t siglen,
    int hash_alg, const uint8_t *msg, size_t mlen,
    const uint8_t *ctxstr, size_t ctxlen, const uint8_t *pk);
SLH_API int slh_sign_digest(slh_ctx *ctx, uint8_t *sig, size_t *siglen,
    int hash_alg, const uint8_t *digest, size_t digestlen,
    const uint8_t *ctxstr, size_t ctxlen, const uint8_t *sk, const uint8_t *addrnd);
SLH_API int slh_verify_digest(slh_ctx *ctx, const uint8_t *sig, size_t siglen,
    int hash_alg, const uint8_t *digest, size_t digestlen,
    const uint8_t *ctxstr, size_t ctxlen, const uint8_t *pk);

SLH_API int slh_cache_build(slh_ctx *ctx, const uint8_t *sk, unsigned t);
SLH_API int slh_cache_save(const slh_ctx *ctx, const char *path);
/* Loading is transactional and bound to pid and the full supplied public key.
 * It reconstructs upper nodes and checks PK.root. Loading a public cache does
 * not bind a secret key; bind a key explicitly before calling slh_subtree. */
SLH_API int slh_cache_load(slh_ctx *ctx, const char *path, const uint8_t *pk);
SLH_API void slh_counters_reset(void);
SLH_API void slh_counters_get(slh_counters *out);
/* Context mutation requires caller synchronization. Binding selects the key
 * used by subtree calls. Signing always uses its explicit sk argument and
 * applies a cache only when both PK.seed and PK.root match that argument. */
SLH_API int slh_ctx_bind_key(slh_ctx *ctx, const uint8_t *sk);
/* leaf_start must be aligned to 2^z. A FORS subtree stays within one FORS tree.
 * target == UINT32_MAX requests a root only; otherwise target lies in the
 * subtree and auth has z*16 bytes (auth may be NULL only when z == 0).
 * root has 16 bytes. Base address is copied and never modified. */
SLH_API int slh_subtree(const slh_ctx *ctx, slh_leaf_type leaf_type,
    const uint8_t base_adrs[32], uint32_t leaf_start, unsigned z,
    uint32_t target, uint8_t *root, uint8_t *auth);

#ifdef __cplusplus
}
#endif
#endif
