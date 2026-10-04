# Bounded Mechanism Neighbors

The fixed source bytes, commits, URLs, SHA-256 and matching line positions are
bound in `validation/incremental-20261005/neighbors/manifest.json`. This review
supports only the named functions at those versions. It is not a global novelty
or patent search and assigns no first-invention claim.

| Source and position | Existing mechanism | Selected project difference |
|---|---|---|
| ISA-L Crypto f22c49a, SM3 x8 asm lines 300-311, 322/345, 366 onwards | Input transpose; complete per-block expansion; documented pre-expansion versus in-round memory tradeoff | A8 applies public carry deltas across successive fixed-context inputs; AF consumes a common secret schedule plus public aligned-lane offsets |
| GmSSL 24ae482, `sm3_x8_compress_blocks`, lines 79, 90, 126-155 | Gather/endian shuffle and full W[68][8] expansion for each block | B1 directly constructs the fixed 38/54-byte SLH final block words; A8/AF change schedule construction, with full rounds retained |
| OpenSSL 4d25710, `sm3_local.h`, P1/EXPAND/RND macros | Standard linear message expansion and non-linear/modular compression | Linear XOR decomposition applies only to W, with all 64 rounds and feed-forward rerun from the correct midstate |
| SPHINCS+ 7ec789a, `fors_sign`, `fors_pk_from_sig` | Signing x8 subtree generation; verification recovers each tree sequentially via `compute_root` | V1 maps the fixed six pid3 verification paths to lanes at the same height; it retains original root order |
| SPHINCS+ 7ec789a, `wots.c:gen_chains`, lines 47-66 and 71 onwards | Stable counting sort by remaining steps, x8 groups, output pointers restored to original chain positions | W1 sorting is an inherited simple baseline. Only its bounded pid3/mock scheduling analysis is delivered here; no sorting novelty is claimed |
| Vendored slhdsa-c `slh_sha2.c:442`, `sha2_256_fors_hash` | Combination of FORS PRF and F already exists | B2 is deferred because A2 uses the existing byte boundary; no combined-API novelty claim |
| slh-dsa-rls 375c69e, README and parameter.go | Existing finite-use parameter choices, work weights and caching | P uses the project's finite cache set, exact counter model, resource reservations and REF self-check; parameters belong to the upstream work |

General SIMD, XOR linearity, rolling schedules, common-subexpression reuse,
sorting, EDF and bounded queues are established techniques. The candidate
research question is the specific fixed SLH layout/address stream/lane
decomposition/lifetime combination. None of the bounded reads establishes its
global novelty. ParaSM2 full-text comparison, AsicBoost mechanism comparison
and broader patent coverage retain their documented gaps; no unsupported
mechanism was filled in. S-F is not the selected route, so its generator is
not implemented in this iteration.

External performance comparators: ISA-L x8, GmSSL x8 and OpenSSL's actually
supported SM3 path must receive the same fixed-prefix/short-block adaptation,
input batches, output truncation and lifecycle conditions. Their general APIs
and adapted kernels must be reported separately. These source reads are not
external speed measurements or completed adapter acceptance. AVX-512/SM3-NI
paths are excluded unless later hardware evidence supports execution.

The K0 comparator is the unchanged baseline commit
`4ad41308ad537e0578f6dea6d85ebcd7535c46b1`, not the new default build. K1 F8
and A8 share the persistent schedule and readonly consumer; F1 and AF share
the same public offsets and readonly reconstruction consumer. B1 is selectable
in all four modes. No speed ranking is selected in this iteration.
