/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * GHASH using ARMv8 PMULL.  NEON port of the PCLMUL backend:
 * BSWAP representation, 8-block aggregation, Karatsuba, same reduction.
 */

#include <sdcrypt/config.h>

#if SDC_ENABLE_GCM && defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))

#include <string.h>
#include <arm_neon.h>
#include "ghash_impl.h"

#define SDC_PMULL_TARGET __attribute__((target("+crypto")))

static const uint8_t bswap_idx[16] = {15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0};

typedef struct {
    uint8x16_t H;
    uint8x16_t H2, H3, H4, H5, H6, H7, H8;
    uint8x16_t Hx, H2x, H3x, H4x, H5x, H6x, H7x, H8x;
    uint8x16_t state;
    uint8_t buf[128];
    size_t buf_len;
    uint64_t aad_len;
    uint64_t data_len;
    int phase;
} ghash_pmull_ctx;

SDC_PMULL_TARGET
static inline uint8x16_t bswap16(uint8x16_t v) {
    return vqtbl1q_u8(v, vld1q_u8(bswap_idx));
}

/* Swap the two 64-bit halves (== _mm_shuffle_epi32(a, 0x0E)). */
SDC_PMULL_TARGET
static inline uint64x2_t swap_halves(uint64x2_t v) {
    return vextq_u64(v, v, 1);
}

/* 64x64 -> 128 carry-less multiply. */
SDC_PMULL_TARGET
static inline uint64x2_t clmul64(uint64_t x, uint64_t y) {
    poly64_t px, py;
    __builtin_memcpy(&px, &x, sizeof(px));
    __builtin_memcpy(&py, &y, sizeof(py));
    return vreinterpretq_u64_p128(vmull_p64(px, py));
}

SDC_PMULL_TARGET
static inline uint64x2_t gf128_reduce(uint64x2_t T0, uint64x2_t T1,
                                      uint64x2_t T2, uint64x2_t T3) {
    T0 = vorrq_u64(vshlq_n_u64(T0, 1), vshrq_n_u64(T1, 63));
    T1 = vorrq_u64(vshlq_n_u64(T1, 1), vshrq_n_u64(T2, 63));
    T2 = vorrq_u64(vshlq_n_u64(T2, 1), vshrq_n_u64(T3, 63));
    T3 = vshlq_n_u64(T3, 1);

    T1 = veorq_u64(T1, veorq_u64(veorq_u64(T3, vshrq_n_u64(T3, 1)),
                                 veorq_u64(vshrq_n_u64(T3, 2), vshrq_n_u64(T3, 7))));
    T2 = veorq_u64(veorq_u64(T2, vshlq_n_u64(T3, 63)),
                   veorq_u64(vshlq_n_u64(T3, 62), vshlq_n_u64(T3, 57)));
    T0 = veorq_u64(T0, veorq_u64(veorq_u64(T2, vshrq_n_u64(T2, 1)),
                                 veorq_u64(vshrq_n_u64(T2, 2), vshrq_n_u64(T2, 7))));
    T1 = veorq_u64(veorq_u64(T1, vshlq_n_u64(T2, 63)),
                   veorq_u64(vshlq_n_u64(T2, 62), vshlq_n_u64(T2, 57)));

    return vcombine_u64(vget_low_u64(T1), vget_low_u64(T0));
}

SDC_PMULL_TARGET
static inline uint64x2_t gf128_mul(uint64x2_t a, uint64x2_t b) {
    uint64_t alo = vgetq_lane_u64(a, 0), ahi = vgetq_lane_u64(a, 1);
    uint64_t blo = vgetq_lane_u64(b, 0), bhi = vgetq_lane_u64(b, 1);

    uint64x2_t t1 = clmul64(ahi, bhi);
    uint64x2_t t3 = clmul64(alo, blo);
    uint64x2_t t2 = clmul64(alo ^ ahi, blo ^ bhi);
    t2 = veorq_u64(t2, veorq_u64(t1, t3));

    uint64x2_t t0 = swap_halves(t1);
    t1 = veorq_u64(t1, swap_halves(t2));
    t2 = veorq_u64(t2, swap_halves(t3));

    return gf128_reduce(t0, t1, t2, t3);
}

#define HX8(dst, src) do { \
    uint64x2_t _s = vreinterpretq_u64_u8(src); \
    dst = vreinterpretq_u8_u64(veorq_u64(_s, swap_halves(_s))); \
} while (0)

SDC_PMULL_TARGET
static void pmull_precompute(ghash_pmull_ctx *c) {
    uint64x2_t H = vreinterpretq_u64_u8(c->H);
    c->H2 = vreinterpretq_u8_u64(gf128_mul(H, H));
    c->H3 = vreinterpretq_u8_u64(gf128_mul(H, vreinterpretq_u64_u8(c->H2)));
    c->H4 = vreinterpretq_u8_u64(gf128_mul(H, vreinterpretq_u64_u8(c->H3)));
    c->H5 = vreinterpretq_u8_u64(gf128_mul(H, vreinterpretq_u64_u8(c->H4)));
    c->H6 = vreinterpretq_u8_u64(gf128_mul(H, vreinterpretq_u64_u8(c->H5)));
    c->H7 = vreinterpretq_u8_u64(gf128_mul(H, vreinterpretq_u64_u8(c->H6)));
    c->H8 = vreinterpretq_u8_u64(gf128_mul(H, vreinterpretq_u64_u8(c->H7)));
    HX8(c->Hx,  c->H);  HX8(c->H2x, c->H2); HX8(c->H3x, c->H3); HX8(c->H4x, c->H4);
    HX8(c->H5x, c->H5); HX8(c->H6x, c->H6); HX8(c->H7x, c->H7); HX8(c->H8x, c->H8);
}

#define CLM(a, b, sel) clmul64(vgetq_lane_u64(a, sel), vgetq_lane_u64(b, sel))

SDC_PMULL_TARGET
static void pmull_1block(ghash_pmull_ctx *c, const uint8_t *blk) {
    uint64x2_t H = vreinterpretq_u64_u8(c->H);
    uint64x2_t d = vreinterpretq_u64_u8(bswap16(vld1q_u8(blk)));
    d = veorq_u64(d, vreinterpretq_u64_u8(c->state));
    uint64x2_t dx = veorq_u64(d, swap_halves(d));
    uint64x2_t Hx = veorq_u64(H, swap_halves(H));

    uint64x2_t t1 = CLM(d, H, 1);
    uint64x2_t t3 = CLM(d, H, 0);
    uint64x2_t t2 = CLM(dx, Hx, 0);
    t2 = veorq_u64(t2, veorq_u64(t1, t3));

    uint64x2_t t0 = swap_halves(t1);
    t1 = veorq_u64(t1, swap_halves(t2));
    t2 = veorq_u64(t2, swap_halves(t3));

    c->state = vreinterpretq_u8_u64(gf128_reduce(t0, t1, t2, t3));
}

SDC_PMULL_TARGET
static void pmull_8blocks(ghash_pmull_ctx *c, const uint8_t *data) {
    uint64x2_t H1 = vreinterpretq_u64_u8(c->H),  H2 = vreinterpretq_u64_u8(c->H2);
    uint64x2_t H3 = vreinterpretq_u64_u8(c->H3), H4 = vreinterpretq_u64_u8(c->H4);
    uint64x2_t H5 = vreinterpretq_u64_u8(c->H5), H6 = vreinterpretq_u64_u8(c->H6);
    uint64x2_t H7 = vreinterpretq_u64_u8(c->H7), H8 = vreinterpretq_u64_u8(c->H8);
    uint64x2_t H1x = vreinterpretq_u64_u8(c->Hx),  H2x = vreinterpretq_u64_u8(c->H2x);
    uint64x2_t H3x = vreinterpretq_u64_u8(c->H3x), H4x = vreinterpretq_u64_u8(c->H4x);
    uint64x2_t H5x = vreinterpretq_u64_u8(c->H5x), H6x = vreinterpretq_u64_u8(c->H6x);
    uint64x2_t H7x = vreinterpretq_u64_u8(c->H7x), H8x = vreinterpretq_u64_u8(c->H8x);

    uint64x2_t d0 = veorq_u64(vreinterpretq_u64_u8(bswap16(vld1q_u8(data))),      vreinterpretq_u64_u8(c->state));
    uint64x2_t d1 = vreinterpretq_u64_u8(bswap16(vld1q_u8(data + 16)));
    uint64x2_t d2 = vreinterpretq_u64_u8(bswap16(vld1q_u8(data + 32)));
    uint64x2_t d3 = vreinterpretq_u64_u8(bswap16(vld1q_u8(data + 48)));
    uint64x2_t d4 = vreinterpretq_u64_u8(bswap16(vld1q_u8(data + 64)));
    uint64x2_t d5 = vreinterpretq_u64_u8(bswap16(vld1q_u8(data + 80)));
    uint64x2_t d6 = vreinterpretq_u64_u8(bswap16(vld1q_u8(data + 96)));
    uint64x2_t d7 = vreinterpretq_u64_u8(bswap16(vld1q_u8(data + 112)));

    uint64x2_t d0x = veorq_u64(d0, swap_halves(d0));
    uint64x2_t d1x = veorq_u64(d1, swap_halves(d1));
    uint64x2_t d2x = veorq_u64(d2, swap_halves(d2));
    uint64x2_t d3x = veorq_u64(d3, swap_halves(d3));
    uint64x2_t d4x = veorq_u64(d4, swap_halves(d4));
    uint64x2_t d5x = veorq_u64(d5, swap_halves(d5));
    uint64x2_t d6x = veorq_u64(d6, swap_halves(d6));
    uint64x2_t d7x = veorq_u64(d7, swap_halves(d7));

    uint64x2_t t1 = veorq_u64(
        veorq_u64(veorq_u64(CLM(d0, H8, 1), CLM(d1, H7, 1)), veorq_u64(CLM(d2, H6, 1), CLM(d3, H5, 1))),
        veorq_u64(veorq_u64(CLM(d4, H4, 1), CLM(d5, H3, 1)), veorq_u64(CLM(d6, H2, 1), CLM(d7, H1, 1))));
    uint64x2_t t3 = veorq_u64(
        veorq_u64(veorq_u64(CLM(d0, H8, 0), CLM(d1, H7, 0)), veorq_u64(CLM(d2, H6, 0), CLM(d3, H5, 0))),
        veorq_u64(veorq_u64(CLM(d4, H4, 0), CLM(d5, H3, 0)), veorq_u64(CLM(d6, H2, 0), CLM(d7, H1, 0))));
    uint64x2_t t2 = veorq_u64(
        veorq_u64(veorq_u64(CLM(d0x, H8x, 0), CLM(d1x, H7x, 0)), veorq_u64(CLM(d2x, H6x, 0), CLM(d3x, H5x, 0))),
        veorq_u64(veorq_u64(CLM(d4x, H4x, 0), CLM(d5x, H3x, 0)), veorq_u64(CLM(d6x, H2x, 0), CLM(d7x, H1x, 0))));
    t2 = veorq_u64(t2, veorq_u64(t1, t3));

    uint64x2_t t0 = swap_halves(t1);
    t1 = veorq_u64(t1, swap_halves(t2));
    t2 = veorq_u64(t2, swap_halves(t3));

    c->state = vreinterpretq_u8_u64(gf128_reduce(t0, t1, t2, t3));
}

SDC_PMULL_TARGET
static void pmull_process(ghash_pmull_ctx *c, const uint8_t *data, size_t len) {
    while (len >= 128) { pmull_8blocks(c, data); data += 128; len -= 128; }
    while (len >= 16)  { pmull_1block(c, data);  data += 16;  len -= 16;  }
    if (len > 0) { memcpy(c->buf + c->buf_len, data, len); c->buf_len += len; }
}

SDC_PMULL_TARGET
static void p_init(void *ctx, const uint8_t H[16]) {
    ghash_pmull_ctx *c = (ghash_pmull_ctx *)ctx;
    memset(c, 0, sizeof(*c));
    c->H = bswap16(vld1q_u8(H));
    c->state = vdupq_n_u8(0);
    pmull_precompute(c);
}

SDC_PMULL_TARGET
static void p_aad(void *ctx, const uint8_t *aad, size_t len) {
    ghash_pmull_ctx *c = (ghash_pmull_ctx *)ctx;
    if (c->phase != 0 || len == 0) return;
    c->aad_len += (uint64_t)len * 8;
    pmull_process(c, aad, len);
}

SDC_PMULL_TARGET
static void p_update(void *ctx, const uint8_t *data, size_t len) {
    ghash_pmull_ctx *c = (ghash_pmull_ctx *)ctx;
    if (c->phase == 0) {
        if (c->buf_len > 0) {
            uint8_t blk[16] = {0};
            memcpy(blk, c->buf, c->buf_len);
            pmull_1block(c, blk);
            c->buf_len = 0;
        }
        c->phase = 1;
    }
    if (len == 0) return;
    c->data_len += (uint64_t)len * 8;
    if (c->buf_len > 0) {
        size_t need = 16 - c->buf_len;
        size_t want = (need < len) ? need : len;
        memcpy(c->buf + c->buf_len, data, want);
        c->buf_len += want;
        data += want; len -= want;
        if (c->buf_len == 16) { pmull_1block(c, c->buf); c->buf_len = 0; }
    }
    pmull_process(c, data, len);
}

SDC_PMULL_TARGET
static void p_final(void *ctx, uint8_t out[16]) {
    ghash_pmull_ctx *c = (ghash_pmull_ctx *)ctx;
    if (c->phase == 0) c->phase = 1;
    if (c->buf_len > 0) {
        uint8_t blk[16] = {0};
        memcpy(blk, c->buf, c->buf_len);
        pmull_1block(c, blk);
        c->buf_len = 0;
    }
    uint8_t lb[16] = {0};
    for (int i = 0; i < 8; i++) lb[i] = (uint8_t)(c->aad_len >> (56 - 8 * i));
    for (int i = 0; i < 8; i++) lb[8 + i] = (uint8_t)(c->data_len >> (56 - 8 * i));
    pmull_1block(c, lb);

    vst1q_u8(out, bswap16(c->state));
}

const sdc_ghash_vtable sdc_ghash_pmull_vtable = {
    p_init, p_aad, p_update, p_final
};

#endif /* aarch64 */
