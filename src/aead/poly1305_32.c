/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2013-2024 Frank Denis <github@pureftpd.org>
 *
 * Ported from libsodium's poly1305_ref implementation.
 */

#include "config.h"
#include <string.h>
#include "poly1305.h"
#include "utils.h"

#if SDC_ENABLE_POLY1305 && SDC_32BIT

void sdc_poly1305_init(sdc_poly1305_ctx *ctx, const uint8_t key[32]) {
    /* r &= 0xffffffc0ffffffc0ffffffc0fffffff - wiped after finalization */
    ctx->r[0] = (load32_le(&key[0])) & 0x3ffffff;
    ctx->r[1] = (load32_le(&key[3]) >> 2) & 0x3ffff03;
    ctx->r[2] = (load32_le(&key[6]) >> 4) & 0x3ffc0ff;
    ctx->r[3] = (load32_le(&key[9]) >> 6) & 0x3f03fff;
    ctx->r[4] = (load32_le(&key[12]) >> 8) & 0x00fffff;

    /* h = 0 */
    ctx->h[0] = 0;
    ctx->h[1] = 0;
    ctx->h[2] = 0;
    ctx->h[3] = 0;
    ctx->h[4] = 0;

    /* save pad for later */
    ctx->pad[0] = load32_le(&key[16]);
    ctx->pad[1] = load32_le(&key[20]);
    ctx->pad[2] = load32_le(&key[24]);
    ctx->pad[3] = load32_le(&key[28]);

    ctx->leftover = 0;
    ctx->is_final = 0;
}

static void poly1305_blocks(sdc_poly1305_ctx *ctx, const uint8_t *m, size_t bytes) {
    const uint32_t hibit = (ctx->is_final) ? 0UL : (1UL << 24); /* 1 << 128 */
    uint32_t  r0, r1, r2, r3, r4;
    uint32_t  s1, s2, s3, s4;
    uint32_t  h0, h1, h2, h3, h4;
    uint64_t  d0, d1, d2, d3, d4;
    uint32_t  c;

    r0 = ctx->r[0];
    r1 = ctx->r[1];
    r2 = ctx->r[2];
    r3 = ctx->r[3];
    r4 = ctx->r[4];

    s1 = r1 * 5;
    s2 = r2 * 5;
    s3 = r3 * 5;
    s4 = r4 * 5;

    h0 = ctx->h[0];
    h1 = ctx->h[1];
    h2 = ctx->h[2];
    h3 = ctx->h[3];
    h4 = ctx->h[4];

    while (bytes >= 16) {
        /* h += m[i] */
        h0 += (load32_le(m + 0)) & 0x3ffffff;
        h1 += (load32_le(m + 3) >> 2) & 0x3ffffff;
        h2 += (load32_le(m + 6) >> 4) & 0x3ffffff;
        h3 += (load32_le(m + 9) >> 6) & 0x3ffffff;
        h4 += (load32_le(m + 12) >> 8) | hibit;

        /* h *= r */
        d0 = ((uint64_t)h0 * r0) + ((uint64_t)h1 * s4) +
             ((uint64_t)h2 * s3) + ((uint64_t)h3 * s2) +
             ((uint64_t)h4 * s1);
        d1 = ((uint64_t)h0 * r1) + ((uint64_t)h1 * r0) +
             ((uint64_t)h2 * s4) + ((uint64_t)h3 * s3) +
             ((uint64_t)h4 * s2);
        d2 = ((uint64_t)h0 * r2) + ((uint64_t)h1 * r1) +
             ((uint64_t)h2 * r0) + ((uint64_t)h3 * s4) +
             ((uint64_t)h4 * s3);
        d3 = ((uint64_t)h0 * r3) + ((uint64_t)h1 * r2) +
             ((uint64_t)h2 * r1) + ((uint64_t)h3 * r0) +
             ((uint64_t)h4 * s4);
        d4 = ((uint64_t)h0 * r4) + ((uint64_t)h1 * r3) +
             ((uint64_t)h2 * r2) + ((uint64_t)h3 * r1) +
             ((uint64_t)h4 * r0);

        /* (partial) h %= p */
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff; d1 += c;
        c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff; d2 += c;
        c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff; d3 += c;
        c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff; d4 += c;
        c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff; h0 += c * 5;
        c = (uint32_t)(h0 >> 26); h0 &= 0x3ffffff; h1 += c;

        m += 16;
        bytes -= 16;
    }

    ctx->h[0] = h0;
    ctx->h[1] = h1;
    ctx->h[2] = h2;
    ctx->h[3] = h3;
    ctx->h[4] = h4;
}

void sdc_poly1305_update(sdc_poly1305_ctx *ctx, const uint8_t *in, size_t len) {
    if (ctx->is_final) return;

    if (ctx->leftover) {
        size_t want = 16 - ctx->leftover;
        if (len < want) {
            memcpy(ctx->buffer + ctx->leftover, in, len);
            ctx->leftover += len;
            return;
        }
        memcpy(ctx->buffer + ctx->leftover, in, want);
        poly1305_blocks(ctx, ctx->buffer, 16);
        in += want;
        len -= want;
        ctx->leftover = 0;
    }

    if (len >= 16) {
        size_t blocks = len / 16;
        poly1305_blocks(ctx, in, blocks * 16);
        in += blocks * 16;
        len -= blocks * 16;
    }

    if (len) {
        memcpy(ctx->buffer, in, len);
        ctx->leftover = len;
    }
}

void sdc_poly1305_final(sdc_poly1305_ctx *ctx, uint8_t mac[16]) {
    uint32_t  h0, h1, h2, h3, h4, c;
    uint32_t  g0, g1, g2, g3, g4;
    uint32_t  mask;
    uint64_t  f;

    /* process the remaining block */
    if (ctx->leftover) {
        uint64_t i = ctx->leftover;
        ctx->buffer[i++] = 1;
        for (; i < 16; i++) {
            ctx->buffer[i] = 0;
        }
        ctx->is_final = 1;
        poly1305_blocks(ctx, ctx->buffer, 16);
    }

    /* fully carry h */
    h0 = ctx->h[0];
    h1 = ctx->h[1];
    h2 = ctx->h[2];
    h3 = ctx->h[3];
    h4 = ctx->h[4];

    c = h1 >> 26; h1 = h1 & 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 = h2 & 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 = h3 & 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 = h4 & 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 = h0 & 0x3ffffff; h1 += c;

    /* compute h + -p */
    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c - (1UL << 26);

    /* select h if h < p, or h + -p if h >= p */
    mask = (g4 >> ((sizeof(uint32_t) * 8) - 1)) - 1;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;

    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* h = h % (2^128) */
    h0 = ((h0) | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

    /* mac = (h + pad) % (2^128) */
    f  = (uint64_t)h0 + ctx->pad[0];
    h0 = (uint32_t)f;
    f  = (uint64_t)h1 + ctx->pad[1] + (f >> 32);
    h1 = (uint32_t)f;
    f  = (uint64_t)h2 + ctx->pad[2] + (f >> 32);
    h2 = (uint32_t)f;
    f  = (uint64_t)h3 + ctx->pad[3] + (f >> 32);
    h3 = (uint32_t)f;

    store32_le(mac + 0, (uint32_t) h0);
    store32_le(mac + 4, (uint32_t) h1);
    store32_le(mac + 8, (uint32_t) h2);
    store32_le(mac + 12, (uint32_t) h3);
    sdc_secure_memzero(ctx, sizeof(sdc_poly1305_ctx));
}

void sdc_poly1305_mac(uint8_t mac[16], const uint8_t *in, size_t len, const uint8_t key[32]) {
    sdc_poly1305_ctx ctx;
    sdc_poly1305_init(&ctx, key);
    sdc_poly1305_update(&ctx, in, len);
    sdc_poly1305_final(&ctx, mac);
}

#endif /* SDC_ENABLE_POLY1305 && SDC_32BIT */