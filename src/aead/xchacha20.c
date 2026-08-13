/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 * 
 * XChaCha20 - 5-block-per-call keystream generation:
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
#include <sdcrypt/utils.h>
#include <sdcrypt/config.h>

#if SDC_ENABLE_XCHACHA20

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

/* ---------------------------------------------------------------------
 * HChaCha20 - subkey derivation, done once per init(), kept scalar for
 * simplicity/clarity (it's off the hot path).
 * --------------------------------------------------------------------- */

static void hchacha20_scalar(uint32_t out[8], const uint32_t key[8],
                             const uint32_t nonce16[4]) {
    uint32_t x[16] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        key[0], key[1], key[2], key[3],
        key[4], key[5], key[6], key[7],
        nonce16[0], nonce16[1], nonce16[2], nonce16[3]
    };

    for (int round = 0; round < 10; round++) {
        QR_SCALAR(x[0], x[4], x[8],  x[12]);
        QR_SCALAR(x[1], x[5], x[9],  x[13]);
        QR_SCALAR(x[2], x[6], x[10], x[14]);
        QR_SCALAR(x[3], x[7], x[11], x[15]);
        QR_SCALAR(x[0], x[5], x[10], x[15]);
        QR_SCALAR(x[1], x[6], x[11], x[12]);
        QR_SCALAR(x[2], x[7], x[8],  x[13]);
        QR_SCALAR(x[3], x[4], x[9],  x[14]);
    }
    out[0] = x[0];  out[1] = x[1];  out[2] = x[2];  out[3] = x[3];
    out[4] = x[12]; out[5] = x[13]; out[6] = x[14]; out[7] = x[15];
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
    for (int w = 0; w < 16; w++) {
        store32_le(ctx->buf + 0 * 64 + w * 4, vgetq_lane_u32(ne[w], 0));
        store32_le(ctx->buf + 1 * 64 + w * 4, vgetq_lane_u32(ne[w], 1));
        store32_le(ctx->buf + 2 * 64 + w * 4, vgetq_lane_u32(ne[w], 2));
        store32_le(ctx->buf + 3 * 64 + w * 4, vgetq_lane_u32(ne[w], 3));
    }

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

/* ---------------------------------------------------------------------
 * sdc_xchacha20_init
 * --------------------------------------------------------------------- */

void sdc_xchacha20_init(sdc_chacha20_ctx *ctx, const uint8_t key[32],
                        const uint8_t nonce[24], uint64_t counter) {
    if (!ctx || !key || !nonce) return;

    uint32_t key_w[8];
    for (int i = 0; i < 8; i++) key_w[i] = load32_le(key + 4 * i);

    uint32_t nonce16[4];
    for (int i = 0; i < 4; i++) nonce16[i] = load32_le(nonce + 4 * i);

    uint32_t subkey[8];
    hchacha20_scalar(subkey, key_w, nonce16);

    const uint32_t n16 = load32_le(nonce + 16);
    const uint32_t n20 = load32_le(nonce + 20);

    /* NEON state: 4 parallel blocks, counters c+0, c+1, c+2, c+3 */
    ctx->state1[0] = vdupq_n_u32(0x61707865);
    ctx->state1[1] = vdupq_n_u32(0x3320646e);
    ctx->state1[2] = vdupq_n_u32(0x79622d32);
    ctx->state1[3] = vdupq_n_u32(0x6b206574);
    for (int i = 0; i < 8; i++) ctx->state1[i + 4] = vdupq_n_u32(subkey[i]);

    uint32_t ctr_lo[4] = {
        (uint32_t)(counter + 0), (uint32_t)(counter + 1),
        (uint32_t)(counter + 2), (uint32_t)(counter + 3)
    };
    uint32_t ctr_hi[4] = {
        (uint32_t)((counter + 0) >> 32), (uint32_t)((counter + 1) >> 32),
        (uint32_t)((counter + 2) >> 32), (uint32_t)((counter + 3) >> 32)
    };
    ctx->state1[12] = vld1q_u32(ctr_lo);
    ctx->state1[13] = vld1q_u32(ctr_hi);
    ctx->state1[14] = vdupq_n_u32(n16);
    ctx->state1[15] = vdupq_n_u32(n20);

    /* Scalar state: 5th block, counter c+4 */
    ctx->state2[0] = 0x61707865;
    ctx->state2[1] = 0x3320646e;
    ctx->state2[2] = 0x79622d32;
    ctx->state2[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) ctx->state2[i + 4] = subkey[i];
    ctx->state2[12] = (uint32_t)(counter + 4);
    ctx->state2[13] = (uint32_t)((counter + 4) >> 32);
    ctx->state2[14] = n16;
    ctx->state2[15] = n20;
    ctx->buf_used = 320; /* forces next_block() on the first crypt() call */
}

void sdc_xchacha20_crypt(sdc_chacha20_ctx *ctx, const uint8_t *in,
                         uint8_t *out, size_t len) {
    if (!ctx || !in || !out || len == 0) return;

    size_t i = 0;
    while (i < len) {
        if (ctx->buf_used >= 320) next_block(ctx);

        size_t available = 320 - ctx->buf_used;
        size_t remaining = len - i;
        size_t n = (available < remaining) ? available : remaining;

        while (n >= 64) {
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

#endif /* SDC_ENABLE_XCHACHA20 */