/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Chacha20 DBRG table definition.
 */

#include <string.h>
#include <sdcrypt/rng.h>
#include <sdcrypt/config.h>
#include <sdcrypt/chacha20.h>
#include <sdcrypt/platform.h>
#include <sdcrypt/utils.h>
#include <sdcrypt/errcode.h>
 
#if SDC_ENABLE_CHACHA20_RNG
#  if !SDC_ENABLE_CHACHA20RAW
#    error "Chacha20 raw mode is not enabled."
#  endif /* !SDC_ENABLE_CHACHA20RAW */

static int chacha20_rng_init(sdc_rng_ctx *ctx, const uint8_t *seed) {
    if (!ctx || !seed) return SDC_ERR_INVALID_PARAM;
    uint8_t nonce[8];
    int ret = sdc_rng_get_seed(nonce, sizeof(nonce));
    if (ret != SDC_ERR_OK) return ret;
    sdc_chacha20raw_init((sdc_chacha20_ctx *)ctx->inner_state, seed, nonce, 0);
    return SDC_ERR_OK;
}

#if defined(__ARM_NEON) || defined(__ARM_NEON__)

static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

#define QR_SCALAR(a, b, c, d) \
    do { \
        a += b; d ^= a; d = rotl32(d, 16); \
        c += d; b ^= c; b = rotl32(b, 12); \
        a += b; d ^= a; d = rotl32(d, 8);  \
        c += d; b ^= c; b = rotl32(b, 7);  \
    } while (0)

#define QR_MIXED(an, bn, cn, dn, as, bs, cs, ds) \
    do { \
        an = vaddq_u32(an, bn);  as += bs; \
        dn = veorq_u32(dn, an);  ds ^= as; \
        dn = vorrq_u32(vshlq_n_u32(dn, 16), vshrq_n_u32(dn, 16)); \
        ds = rotl32(ds, 16); \
        cn = vaddq_u32(cn, dn);  cs += ds; \
        bn = veorq_u32(bn, cn);  bs ^= cs; \
        bn = vorrq_u32(vshlq_n_u32(bn, 12), vshrq_n_u32(bn, 20)); \
        bs = rotl32(bs, 12); \
        an = vaddq_u32(an, bn);  as += bs; \
        dn = veorq_u32(dn, an);  ds ^= as; \
        dn = vorrq_u32(vshlq_n_u32(dn, 8), vshrq_n_u32(dn, 24)); \
        ds = rotl32(ds, 8); \
        cn = vaddq_u32(cn, dn);  cs += ds; \
        bn = veorq_u32(bn, cn);  bs ^= cs; \
        bn = vorrq_u32(vshlq_n_u32(bn, 7), vshrq_n_u32(bn, 25)); \
        bs = rotl32(bs, 7); \
    } while (0)

static inline void transpose_4x4_u32(uint32x4_t *out, uint32x4_t v0, uint32x4_t v1, uint32x4_t v2, uint32x4_t v3) {
#if SDC_64BIT  // ARM64, ARMv8.0 neon is always available
    uint32x4_t t0 = vzip1q_u32(v0, v1);  // [a0,b0,a1,b1]
    uint32x4_t t1 = vzip2q_u32(v0, v1);  // [a2,b2,a3,b3]
    uint32x4_t t2 = vzip1q_u32(v2, v3);  // [c0,d0,c1,d1]
    uint32x4_t t3 = vzip2q_u32(v2, v3);  // [c2,d2,c3,d3]

    out[0] = vreinterpretq_u32_u64(vzip1q_u64(vreinterpretq_u64_u32(t0), vreinterpretq_u64_u32(t2)));  // [a0,b0,c0,d0]
    out[1] = vreinterpretq_u32_u64(vzip2q_u64(vreinterpretq_u64_u32(t0), vreinterpretq_u64_u32(t2)));  // [a1,b1,c1,d1]
    out[2] = vreinterpretq_u32_u64(vzip1q_u64(vreinterpretq_u64_u32(t1), vreinterpretq_u64_u32(t3)));  // [a2,b2,c2,d2]
    out[3] = vreinterpretq_u32_u64(vzip2q_u64(vreinterpretq_u64_u32(t1), vreinterpretq_u64_u32(t3)));  // [a3,b3,c3,d3]
#elif SDC_32BIT  // ARM32, normally ARMv7l neon
    uint32_t d[16];
    d[0]  = vgetq_lane_u32(v0, 0); d[1]  = vgetq_lane_u32(v1, 0);
    d[2]  = vgetq_lane_u32(v2, 0); d[3]  = vgetq_lane_u32(v3, 0);
    d[4]  = vgetq_lane_u32(v0, 1); d[5]  = vgetq_lane_u32(v1, 1);
    d[6]  = vgetq_lane_u32(v2, 1); d[7]  = vgetq_lane_u32(v3, 1);
    d[8]  = vgetq_lane_u32(v0, 2); d[9]  = vgetq_lane_u32(v1, 2);
    d[10] = vgetq_lane_u32(v2, 2); d[11] = vgetq_lane_u32(v3, 2);
    d[12] = vgetq_lane_u32(v0, 3); d[13] = vgetq_lane_u32(v1, 3);
    d[14] = vgetq_lane_u32(v2, 3); d[15] = vgetq_lane_u32(v3, 3);

    out[0] = vld1q_u32(d + 0);   // [a0, b0, c0, d0]
    out[1] = vld1q_u32(d + 4);   // [a1, b1, c1, d1]
    out[2] = vld1q_u32(d + 8);   // [a2, b2, c2, d2]
    out[3] = vld1q_u32(d + 12);  // [a3, b3, c3, d3]
#endif
}

static void transpose_and_store(uint8_t buf[256], const uint32x4_t ne[16]) {
    uint32x4_t out[4][4];  // out[block][group]
    
    transpose_4x4_u32(out[0], ne[0], ne[1], ne[2], ne[3]);
    transpose_4x4_u32(out[1], ne[4], ne[5], ne[6], ne[7]);
    transpose_4x4_u32(out[2], ne[8], ne[9], ne[10], ne[11]);
    transpose_4x4_u32(out[3], ne[12], ne[13], ne[14], ne[15]);
    
    for (int block = 0; block < 4; block++) {
        for (int group = 0; group < 4; group++) {
            vst1q_u32((uint32_t*)(buf + block * 64 + group * 16), out[group][block]);
        }
    }
}

/* ---------------------------------------------------------------------
 * next_block - generate 320 bytes of keystream (5 blocks) into ctx->buf
 * --------------------------------------------------------------------- */
static void next_block(sdc_chacha20_ctx *ctx) {
    uint32x4_t i0 = ctx->state1[0],  i1 = ctx->state1[1];
    uint32x4_t i2 = ctx->state1[2],  i3 = ctx->state1[3];
    uint32x4_t i4 = ctx->state1[4],  i5 = ctx->state1[5];
    uint32x4_t i6 = ctx->state1[6],  i7 = ctx->state1[7];
    uint32x4_t i8 = ctx->state1[8],  i9 = ctx->state1[9];
    uint32x4_t i10 = ctx->state1[10], i11 = ctx->state1[11];
    uint32x4_t i12 = ctx->state1[12], i13 = ctx->state1[13];
    uint32x4_t i14 = ctx->state1[14], i15 = ctx->state1[15];

    uint32_t j0 = ctx->state2[0],  j1 = ctx->state2[1];
    uint32_t j2 = ctx->state2[2],  j3 = ctx->state2[3];
    uint32_t j4 = ctx->state2[4],  j5 = ctx->state2[5];
    uint32_t j6 = ctx->state2[6],  j7 = ctx->state2[7];
    uint32_t j8 = ctx->state2[8],  j9 = ctx->state2[9];
    uint32_t j10 = ctx->state2[10], j11 = ctx->state2[11];
    uint32_t j12 = ctx->state2[12], j13 = ctx->state2[13];
    uint32_t j14 = ctx->state2[14], j15 = ctx->state2[15];

    uint32x4_t n0 = i0,  n1 = i1,  n2 = i2,  n3 = i3;
    uint32x4_t n4 = i4,  n5 = i5,  n6 = i6,  n7 = i7;
    uint32x4_t n8 = i8,  n9 = i9,  n10 = i10, n11 = i11;
    uint32x4_t n12 = i12, n13 = i13, n14 = i14, n15 = i15;

    uint32_t s0 = j0,  s1 = j1,  s2 = j2,  s3 = j3;
    uint32_t s4 = j4,  s5 = j5,  s6 = j6,  s7 = j7;
    uint32_t s8 = j8,  s9 = j9,  s10 = j10, s11 = j11;
    uint32_t s12 = j12, s13 = j13, s14 = j14, s15 = j15;

    for (int round = 0; round < 10; round++) {
        /* Column rounds */
        QR_MIXED(n0, n4,  n8, n12, s0, s4,  s8, s12);
        QR_MIXED(n1, n5,  n9, n13, s1, s5,  s9, s13);
        QR_MIXED(n2, n6, n10, n14, s2, s6, s10, s14);
        QR_MIXED(n3, n7, n11, n15, s3, s7, s11, s15);
        /* Diagonal rounds */
        QR_MIXED(n0, n5, n10, n15, s0, s5, s10, s15);
        QR_MIXED(n1, n6, n11, n12, s1, s6, s11, s12);
        QR_MIXED(n2, n7,  n8, n13, s2, s7,  s8, s13);
        QR_MIXED(n3, n4,  n9, n14, s3, s4,  s9, s14);
    }

    n0 = vaddq_u32(n0, i0);   n1 = vaddq_u32(n1, i1);
    n2 = vaddq_u32(n2, i2);   n3 = vaddq_u32(n3, i3);
    n4 = vaddq_u32(n4, i4);   n5 = vaddq_u32(n5, i5);
    n6 = vaddq_u32(n6, i6);   n7 = vaddq_u32(n7, i7);
    n8 = vaddq_u32(n8, i8);   n9 = vaddq_u32(n9, i9);
    n10 = vaddq_u32(n10, i10); n11 = vaddq_u32(n11, i11);
    n12 = vaddq_u32(n12, i12); n13 = vaddq_u32(n13, i13);
    n14 = vaddq_u32(n14, i14); n15 = vaddq_u32(n15, i15);

    s0 += j0;   s1 += j1;   s2 += j2;   s3 += j3;
    s4 += j4;   s5 += j5;   s6 += j6;   s7 += j7;
    s8 += j8;   s9 += j9;   s10 += j10; s11 += j11;
    s12 += j12; s13 += j13; s14 += j14; s15 += j15;

    /* Transpose NEON SoA -> 4 separate 64-byte AoS blocks in buf[0..255] */
    uint32x4_t ne[16] = { n0, n1, n2,  n3,  n4,  n5,  n6,  n7,
                           n8, n9, n10, n11, n12, n13, n14, n15 };
    transpose_and_store(ctx->buf, ne);

    /* Scalar block -> buf[256..319] */
    uint32_t sc[16] = { s0, s1, s2,  s3,  s4,  s5,  s6,  s7,
                         s8, s9, s10, s11, s12, s13, s14, s15 };
    for (int w = 0; w < 16; w++) {
        store32_le(ctx->buf + 256 + w * 4, sc[w]);
    }

    /* Advance both counters by 5 (4 NEON blocks + 1 scalar block consumed),
       with correct 64-bit wraparound via unsigned-overflow detection. */
    uint32x4_t newlow = vaddq_u32(ctx->state1[12], vdupq_n_u32(5));
    uint32x4_t carry = vshrq_n_u32(vcltq_u32(newlow, ctx->state1[12]), 31);
    ctx->state1[13] = vaddq_u32(ctx->state1[13], carry);
    ctx->state1[12] = newlow;

    uint32_t old12 = ctx->state2[12];
    ctx->state2[12] = old12 + 5;
    if (ctx->state2[12] < old12) ctx->state2[13]++;
    ctx->buf_used = 0;
}

#else
#warning "Compiling without NEON support, fallback to scalar implementation"

#define ROTL32(x, n) ((x << (n)) | (x >> (32 - (n))))
#define QR(a, b, c, d) \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8);  \
    c += d; b ^= c; b = ROTL32(b, 7);

static void chacha20_block(uint32_t out[16], const uint32_t in[16]) {
    uint32_t x[16];
    int i;
    memcpy(x, in, sizeof(uint32_t) * 16);
    for (i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8],  x[12]);
        QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]);
        QR(x[3], x[4], x[9],  x[14]);
    }
    for (i = 0; i < 16; i++) {
        out[i] = x[i] + in[i];
    }
}

static void next_block(sdc_chacha20_ctx *ctx) {
    uint32_t out[16];
    chacha20_block(out, ctx->state);
    for (int i = 0; i < 16; i++) {
        store32_le(ctx->buf + 4 * i, out[i]);
    }
    ctx->buf_used = 0;
    ctx->state[12]++;
    if (ctx->state[12] == 0) {
        ctx->state[13]++;
    }
}

#endif

static int chacha20_rng_generate(sdc_rng_ctx *ctx, uint8_t *out, size_t len) {
    if (!ctx || !out || len == 0) return SDC_ERR_INVALID_PARAM;
    sdc_chacha20_ctx *chacha20 = (sdc_chacha20_ctx *)ctx->inner_state;
    size_t i = 0;

#if defined(__ARM_NEON) || defined(__ARM_NEON__)
    while (i < len) {
        if (chacha20->buf_used == 320) next_block(chacha20);
        size_t available = 320 - chacha20->buf_used;
        size_t remaining = len - i;
        size_t n = (available < remaining) ? available : remaining;

        while (n >= 64) {
            if (i + 128 < len) {
                __builtin_prefetch(chacha20->buf + chacha20->buf_used + 64, 0, 3);
            }
            uint8x16x4_t ks = vld1q_u8_x4(chacha20->buf + chacha20->buf_used);
            vst1q_u8_x4(out + i, ks);
            i += 64; chacha20->buf_used += 64; n -= 64;
        }
        while (n >= 16) {
            uint8x16_t ks = vld1q_u8(chacha20->buf + chacha20->buf_used);
            vst1q_u8(out + i, ks);
            i += 16; chacha20->buf_used += 16; n -= 16;
        }
        while (n > 0) {
            out[i] = chacha20->buf[chacha20->buf_used];
            i++; chacha20->buf_used++; n--;
        }
    }
#else
    while (i < len) {
        if (chacha20->buf_used == 64) {
            next_block(chacha20);
        }
        size_t n = len - i;
        if (n > 64 - chacha20->buf_used) n = 64 - chacha20->buf_used;
        memcpy(out + i, chacha20->buf + chacha20->buf_used, n);
        chacha20->buf_used += n;
        i += n;
    }
#endif
    return SDC_ERR_OK;
}

const sdc_rng_ops_t sdc_chacha20_rng_ops = {
    .init = chacha20_rng_init,
    .generate = chacha20_rng_generate,
    .seed_len = 32
};

#endif /* SDC_ENABLE_CHACHA20_RNG */
