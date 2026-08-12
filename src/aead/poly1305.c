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

#if SDC_ENABLE_POLY1305

void sdc_poly1305_init(sdc_poly1305_ctx *ctx, const uint8_t key[32]) {
    uint64_t t0 = load64_le(key);
    uint64_t t1 = load64_le(key + 8);

    ctx->r[0] = (t0) & 0xffc0fffffffULL;
    ctx->r[1] = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffffULL;
    ctx->r[2] = ((t1 >> 24)) & 0x00ffffffc0fULL;

    ctx->h[0] = 0;
    ctx->h[1] = 0;
    ctx->h[2] = 0;

    ctx->pad[0] = load64_le(key + 16);
    ctx->pad[1] = load64_le(key + 24);

    ctx->leftover = 0;
    ctx->final = 0;
}

static void sdc_poly1305_blocks(sdc_poly1305_ctx *ctx, const uint8_t *m, size_t bytes) {
    const uint64_t hibit = ctx->final ? 0 : (1ULL << 40);
    uint64_t r0 = ctx->r[0];
    uint64_t r1 = ctx->r[1];
    uint64_t r2 = ctx->r[2];
    uint64_t s1 = r1 * 20;
    uint64_t s2 = r2 * 20;
    uint64_t h0 = ctx->h[0];
    uint64_t h1 = ctx->h[1];
    uint64_t h2 = ctx->h[2];

    while (bytes >= 16) {
        uint64_t t0 = load64_le(m);
        uint64_t t1 = load64_le(m + 8);

        h0 += t0 & 0xfffffffffffULL;
        h1 += ((t0 >> 44) | (t1 << 20)) & 0xfffffffffffULL;
        h2 += (((t1 >> 24)) & 0x3ffffffffffULL) | hibit;

        u128 d0 = (u128)h0 * r0;
        u128 d1 = (u128)h0 * r1;
        u128 d2 = (u128)h0 * r2;

        d0 += (u128)h1 * s2;
        d1 += (u128)h1 * r0;
        d2 += (u128)h1 * r1;

        d0 += (u128)h2 * s1;
        d1 += (u128)h2 * s2;
        d2 += (u128)h2 * r0;

        uint64_t c;
        c = (uint64_t)(d0 >> 44);
        h0 = (uint64_t)d0 & 0xfffffffffffULL;
        d1 += c;

        c = (uint64_t)(d1 >> 44);
        h1 = (uint64_t)d1 & 0xfffffffffffULL;
        d2 += c;

        c = (uint64_t)(d2 >> 42);
        h2 = (uint64_t)d2 & 0x3ffffffffffULL;
        h0 += c * 5;

        c = h0 >> 44;
        h0 &= 0xfffffffffffULL;
        h1 += c;

        m += 16;
        bytes -= 16;
    }

    ctx->h[0] = h0;
    ctx->h[1] = h1;
    ctx->h[2] = h2;
}

void sdc_poly1305_update(sdc_poly1305_ctx *ctx, const uint8_t *in, size_t len) {
    if (ctx->final) return;

    if (ctx->leftover) {
        size_t want = 16 - ctx->leftover;
        if (len < want) {
            memcpy(ctx->buffer + ctx->leftover, in, len);
            ctx->leftover += len;
            return;
        }
        memcpy(ctx->buffer + ctx->leftover, in, want);
        sdc_poly1305_blocks(ctx, ctx->buffer, 16);
        in += want;
        len -= want;
        ctx->leftover = 0;
    }

    if (len >= 16) {
        size_t blocks = len / 16;
        sdc_poly1305_blocks(ctx, in, blocks * 16);
        in += blocks * 16;
        len -= blocks * 16;
    }

    if (len) {
        memcpy(ctx->buffer, in, len);
        ctx->leftover = len;
    }
}

void sdc_poly1305_final(sdc_poly1305_ctx *ctx, uint8_t mac[16]) {
    uint64_t h0, h1, h2, c;
    uint64_t g0, g1, g2;
    uint64_t t0, t1;
    uint64_t mask;

    if (ctx->leftover) {
        size_t i = ctx->leftover;

        ctx->buffer[i++] = 1;
        for (; i < 16; i++) {
            ctx->buffer[i] = 0;
        }
        ctx->final = 1;
        sdc_poly1305_blocks(ctx, ctx->buffer, 16);
    }

    h0 = ctx->h[0];
    h1 = ctx->h[1];
    h2 = ctx->h[2];

    c = h1 >> 44;
    h1 &= 0xfffffffffffULL;
    h2 += c;
    c = h2 >> 42;
    h2 &= 0x3ffffffffffULL;
    h0 += c * 5;
    c = h0 >> 44;
    h0 &= 0xfffffffffffULL;
    h1 += c;
    c = h1 >> 44;
    h1 &= 0xfffffffffffULL;
    h2 += c;
    c = h2 >> 42;
    h2 &= 0x3ffffffffffULL;
    h0 += c * 5;
    c = h0 >> 44;
    h0 &= 0xfffffffffffULL;
    h1 += c;

    g0 = h0 + 5;
    c = g0 >> 44;
    g0 &= 0xfffffffffffULL;
    g1 = h1 + c;
    c = g1 >> 44;
    g1 &= 0xfffffffffffULL;
    g2 = h2 + c - (1ULL << 42);

    mask = (g2 >> 63) - 1;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;

    t0 = ctx->pad[0];
    t1 = ctx->pad[1];

    h0 += t0 & 0xfffffffffffULL;
    c = h0 >> 44;
    h0 &= 0xfffffffffffULL;
    h1 += ((t0 >> 44) | (t1 << 20)) & 0xfffffffffffULL;
    h1 += c;
    c = h1 >> 44;
    h1 &= 0xfffffffffffULL;
    h2 += ((t1 >> 24)) & 0x3ffffffffffULL;
    h2 += c;
    h2 &= 0x3ffffffffffULL;

    h0 = h0 | (h1 << 44);
    h1 = (h1 >> 20) | (h2 << 24);
    store64_le(&mac[0], h0);
    store64_le(&mac[8], h1);
    sdc_secure_memzero(ctx, sizeof(sdc_poly1305_ctx));  
}

void sdc_poly1305_mac(uint8_t mac[16], const uint8_t *in, size_t len, const uint8_t key[32]) {
    sdc_poly1305_ctx ctx;
    sdc_poly1305_init(&ctx, key);
    sdc_poly1305_update(&ctx, in, len);
    sdc_poly1305_final(&ctx, mac);
}

#endif /* SDC_ENABLE_POLY1305 */
