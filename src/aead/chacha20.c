/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 * 
 * ChaCha20 IETF - 5-block-per-call keystream generation:
 *   - 4 blocks (counter+0..+3) computed in parallel with NEON (SoA state)
 *   - 1 block  (counter+4)     computed with plain scalar code
 *
 * Every quarter round touches both the NEON lanes and the scalar lane in
 * the same macro invocation (QR_MIXED). The scalar chain has no data
 * dependency on the NEON chain, so the compiler can schedule integer ops
 * into pipeline slots that would otherwise stall waiting on NEON
 * add/xor/rotate latency - this is what buys the extra throughput over a
 * pure 4-block implementation, at the cost of one extra independent
 * dependency chain to carry.
 */

#include <string.h>
#include <sdcrypt/chacha20.h>
#include <sdcrypt/platform.h>
#include <sdcrypt/utils.h>
#include <sdcrypt/config.h>

#if SDC_ENABLE_CHACHA20
#if defined(__ARM_NEON) || defined(__ARM_NEON__)

static inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

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
    uint32x4_t t0 = vzip1q_u32(v0, v2);  // [a0,c0,a1,c1]
    uint32x4_t t1 = vzip1q_u32(v1, v3);  // [b0,d0,b1,d1]
    uint32x4_t t2 = vzip2q_u32(v0, v2);  // [a2,c2,a3,c3]
    uint32x4_t t3 = vzip2q_u32(v1, v3);  // [b2,d2,b3,d3]

    out[0] = vzip1q_u32(t0, t1);          // [a0,b0,c0,d0]
    out[1] = vzip2q_u32(t0, t1);          // [a1,b1,c1,d1]
    out[2] = vzip1q_u32(t2, t3);          // [a2,b2,c2,d2]
    out[3] = vzip2q_u32(t2, t3);          // [a3,b3,c3,d3]
#elif SDC_32BIT  // ARM32, ARMv7l neon is always available
    uint32x2_t v0_lo = vget_low_u32(v0), v0_hi = vget_high_u32(v0);
    uint32x2_t v1_lo = vget_low_u32(v1), v1_hi = vget_high_u32(v1);
    uint32x2_t v2_lo = vget_low_u32(v2), v2_hi = vget_high_u32(v2);
    uint32x2_t v3_lo = vget_low_u32(v3), v3_hi = vget_high_u32(v3);

    uint32x2x2_t t01_lo = vzip_u32(v0_lo, v1_lo);
    uint32x2x2_t t01_hi = vzip_u32(v0_hi, v1_hi);
    uint32x2x2_t t23_lo = vzip_u32(v2_lo, v3_lo);
    uint32x2x2_t t23_hi = vzip_u32(v2_hi, v3_hi);

    out[0] = vcombine_u32(t01_lo.val[0], t23_lo.val[0]);  // [a0,b0,c0,d0]
    out[1] = vcombine_u32(t01_lo.val[1], t23_lo.val[1]);  // [a1,b1,c1,d1]
    out[2] = vcombine_u32(t01_hi.val[0], t23_hi.val[0]);  // [a2,b2,c2,d2]
    out[3] = vcombine_u32(t01_hi.val[1], t23_hi.val[1]);  // [a3,b3,c3,d3]
#endif
}

static void transpose_and_store(uint8_t buf[256], const uint32x4_t ne[16]) {
    uint32x4_t out[4][4];  // out[block][word_group]
    
    transpose_4x4_u32(out[0], ne[0], ne[1], ne[2], ne[3]);
    transpose_4x4_u32(out[1], ne[4], ne[5], ne[6], ne[7]);
    transpose_4x4_u32(out[2], ne[8], ne[9], ne[10], ne[11]);
    transpose_4x4_u32(out[3], ne[12], ne[13], ne[14], ne[15]);

#if SDC_64BIT  // vst1q_u32_x4 is available on ARMv8 and later
    vst1q_u32_x4((uint32_t*)(buf + 0),   ((uint32x4x4_t){out[0][0], out[1][0], out[2][0], out[3][0]}));
    vst1q_u32_x4((uint32_t*)(buf + 64),  ((uint32x4x4_t){out[0][1], out[1][1], out[2][1], out[3][1]}));
    vst1q_u32_x4((uint32_t*)(buf + 128), ((uint32x4x4_t){out[0][2], out[1][2], out[2][2], out[3][2]}));
    vst1q_u32_x4((uint32_t*)(buf + 192), ((uint32x4x4_t){out[0][3], out[1][3], out[2][3], out[3][3]}));
#elif SDC_32BIT  // ARM32, ARMv7l neon is always available
    for (int block = 0; block < 4; block++) {
        for (int group = 0; group < 4; group++) {
            vst1q_u32((uint32_t*)(buf + block * 64 + group * 16), out[group][block]);
        }
    }
#endif
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
    ctx->state1[12] = vaddq_u32(ctx->state1[12], vdupq_n_u32(5));
    ctx->state2[12] += 5;
    ctx->buf_used = 0;
}

void sdc_chacha20_init(sdc_chacha20_ctx *ctx, const uint8_t key[32],
                        const uint8_t nonce[12], uint32_t counter) {
    if (!ctx || !key || !nonce) return;

    /* NEON state: 4 parallel blocks, counters c+0, c+1, c+2, c+3 */
    ctx->state1[0] = vdupq_n_u32(0x61707865);
    ctx->state1[1] = vdupq_n_u32(0x3320646e);
    ctx->state1[2] = vdupq_n_u32(0x79622d32);
    ctx->state1[3] = vdupq_n_u32(0x6b206574);

    uint32_t ctr[4] = {
        (uint32_t)(counter + 0), (uint32_t)(counter + 1),
        (uint32_t)(counter + 2), (uint32_t)(counter + 3)
    };
    for (int i = 0; i < 8; i++) {
        ctx->state1[4 + i] = vdupq_n_u32(load32_le(key + 4 * i));
    }
    ctx->state1[12] = vld1q_u32(ctr);
    ctx->state1[13] = vdupq_n_u32(load32_le(nonce));
    ctx->state1[14] = vdupq_n_u32(load32_le(nonce + 4));
    ctx->state1[15] = vdupq_n_u32(load32_le(nonce + 8));

    /* Scalar state: 5th block, counter c+4 */
    ctx->state2[0] = 0x61707865;
    ctx->state2[1] = 0x3320646e;
    ctx->state2[2] = 0x79622d32;
    ctx->state2[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) {
        ctx->state2[4 + i] = load32_le(key + 4 * i);
    }
    ctx->state2[12] = counter + 4;
    ctx->state2[13] = load32_le(nonce);
    ctx->state2[14] = load32_le(nonce + 4);
    ctx->state2[15] = load32_le(nonce + 8);
    ctx->buf_used = 320; /* forces next_block() on the first crypt() call */
}

void sdc_chacha20_crypt(sdc_chacha20_ctx *ctx, const uint8_t *in,
                        uint8_t *out, size_t len) {
    if (!ctx || !in || !out || len == 0) return;

    size_t i = 0;
    while (i < len) {
        if (ctx->buf_used >= 320) next_block(ctx);

        size_t available = 320 - ctx->buf_used;
        size_t remaining = len - i;
        size_t n = (available < remaining) ? available : remaining;
    #if SDC_64BIT  // vld1q_u8_x4 is available on ARMv8 and later
        while (n >= 64) {
            if (i + 128 < len) {
                __builtin_prefetch(in + i + 64, 0, 3);
                __builtin_prefetch(ctx->buf + ctx->buf_used + 64, 0, 3);
            }
            uint8x16x4_t ks = vld1q_u8_x4(ctx->buf + ctx->buf_used);
            uint8x16x4_t pt = vld1q_u8_x4(in + i);
            uint8x16x4_t ct;
            ct.val[0] = veorq_u8(ks.val[0], pt.val[0]);
            ct.val[1] = veorq_u8(ks.val[1], pt.val[1]);
            ct.val[2] = veorq_u8(ks.val[2], pt.val[2]);
            ct.val[3] = veorq_u8(ks.val[3], pt.val[3]);
            vst1q_u8_x4(out + i, ct);
            i += 64; ctx->buf_used += 64; n -= 64;
        }
    #endif
        while (n >= 16) {
            uint8x16_t ks = vld1q_u8(ctx->buf + ctx->buf_used);
            uint8x16_t pt = vld1q_u8(in + i);
            vst1q_u8(out + i, veorq_u8(ks, pt));
            i += 16; ctx->buf_used += 16; n -= 16;
        }
        while (n > 0) {
            out[i] = in[i] ^ ctx->buf[ctx->buf_used];
            i++; ctx->buf_used++; n--;
        }
    }
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
}

void sdc_chacha20_init(sdc_chacha20_ctx *ctx, const uint8_t key[32],
                       const uint8_t nonce[12], uint32_t counter) {
    if (!ctx || !key || !nonce) return;
    ctx->state[0] = 0x61707865;
    ctx->state[1] = 0x3320646e;
    ctx->state[2] = 0x79622d32;
    ctx->state[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) {
        ctx->state[i + 4] = load32_le(key + 4 * i);
    }
    ctx->state[12] = (uint32_t)counter;
    ctx->state[13] = load32_le(nonce);
    ctx->state[14] = load32_le(nonce + 4);
    ctx->state[15] = load32_le(nonce + 8);
    ctx->buf_used = 64;
}

void sdc_chacha20_crypt(sdc_chacha20_ctx *ctx, const uint8_t *in,
                        uint8_t *out, size_t len) {
    if (!ctx || !in || !out) return;
    size_t i = 0;
    while (i < len) {
        if (ctx->buf_used == 64) {
            next_block(ctx);
        }
        size_t n = len - i;
        if (n > 64 - ctx->buf_used) n = 64 - ctx->buf_used;
        for (size_t j = 0; j < n; j++) {
            out[i + j] = in[i + j] ^ ctx->buf[ctx->buf_used + j];
        }
        ctx->buf_used += n;
        i += n;
    }
}

#endif /* __ARM_NEON || __ARM_NEON__ */
#endif /* SDC_ENABLE_CHACHA20 */