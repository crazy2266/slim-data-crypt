/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * GHASH scalar backend (BearSSL ctmul64 style, constant time).
 */

#include <string.h>
#include <sdcrypt/config.h>
#include "ghash_impl.h"

#if SDC_ENABLE_GCM

typedef struct {
    uint8_t H[16];
    uint8_t state[16];
    uint8_t buf[16];
    size_t buf_len;
    uint64_t aad_len;
    uint64_t data_len;
    int phase;
} ghash_scalar_ctx;

static uint64_t rev64(uint64_t x) {
#define RMS(m, s) do { x = ((x & (uint64_t)(m)) << (s)) | ((x >> (s)) & (uint64_t)(m)); } while (0)
    RMS(0x5555555555555555ULL, 1);
    RMS(0x3333333333333333ULL, 2);
    RMS(0x0F0F0F0F0F0F0F0FULL, 4);
    RMS(0x00FF00FF00FF00FFULL, 8);
    RMS(0x0000FFFF0000FFFFULL, 16);
#undef RMS
    return (x << 32) | (x >> 32);
}

static uint64_t bmul64(uint64_t x, uint64_t y) {
    uint64_t x0 = x & 0x1111111111111111ULL, x1 = x & 0x2222222222222222ULL;
    uint64_t x2 = x & 0x4444444444444444ULL, x3 = x & 0x8888888888888888ULL;
    uint64_t y0 = y & 0x1111111111111111ULL, y1 = y & 0x2222222222222222ULL;
    uint64_t y2 = y & 0x4444444444444444ULL, y3 = y & 0x8888888888888888ULL;
    uint64_t z0 = (x0*y0) ^ (x1*y3) ^ (x2*y2) ^ (x3*y1);
    uint64_t z1 = (x0*y1) ^ (x1*y0) ^ (x2*y3) ^ (x3*y2);
    uint64_t z2 = (x0*y2) ^ (x1*y1) ^ (x2*y0) ^ (x3*y3);
    uint64_t z3 = (x0*y3) ^ (x1*y2) ^ (x2*y1) ^ (x3*y0);
    return (z0 & 0x1111111111111111ULL) | (z1 & 0x2222222222222222ULL)
         | (z2 & 0x4444444444444444ULL) | (z3 & 0x8888888888888888ULL);
}

static uint64_t load64_be_(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}
static void store64_be_(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[7 - i] = (uint8_t)(v >> (8 * i));
}

/* One block: y = (y xor x) * H, all in BearSSL byte order. */
static void ghash_scalar_block(ghash_scalar_ctx *c, const uint8_t *blk) {
    uint64_t y1 = load64_be_(c->state);
    uint64_t y0 = load64_be_(c->state + 8);
    uint64_t h1 = load64_be_(c->H);
    uint64_t h0 = load64_be_(c->H + 8);
    uint64_t h0r = rev64(h0), h1r = rev64(h1);
    uint64_t h2 = h0 ^ h1, h2r = h0r ^ h1r;

    y1 ^= load64_be_(blk);
    y0 ^= load64_be_(blk + 8);

    uint64_t y0r = rev64(y0), y1r = rev64(y1);
    uint64_t y2 = y0 ^ y1, y2r = y0r ^ y1r;

    uint64_t z0 = bmul64(y0, h0), z1 = bmul64(y1, h1), z2 = bmul64(y2, h2);
    uint64_t z0h = bmul64(y0r, h0r), z1h = bmul64(y1r, h1r), z2h = bmul64(y2r, h2r);

    z2 ^= z0 ^ z1;
    z2h ^= z0h ^ z1h;
    z0h = rev64(z0h) >> 1;
    z1h = rev64(z1h) >> 1;
    z2h = rev64(z2h) >> 1;

    uint64_t v0 = z0;
    uint64_t v1 = z0h ^ z2;
    uint64_t v2 = z1 ^ z2h;
    uint64_t v3 = z1h;

    v3 = (v3 << 1) | (v2 >> 63);
    v2 = (v2 << 1) | (v1 >> 63);
    v1 = (v1 << 1) | (v0 >> 63);
    v0 = (v0 << 1);

    v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
    v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
    v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
    v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);

    store64_be_(c->state, v3);
    store64_be_(c->state + 8, v2);
}

static void scalar_process(ghash_scalar_ctx *c, const uint8_t *data, size_t len) {
    while (len >= 16) { ghash_scalar_block(c, data); data += 16; len -= 16; }
    if (len > 0) {
        memcpy(c->buf + c->buf_len, data, len);
        c->buf_len += len;
    }
}

static void s_init(void *ctx, const uint8_t H[16]) {
    ghash_scalar_ctx *c = (ghash_scalar_ctx *)ctx;
    memset(c, 0, sizeof(*c));
    memcpy(c->H, H, 16);
}

static void s_aad(void *ctx, const uint8_t *aad, size_t len) {
    ghash_scalar_ctx *c = (ghash_scalar_ctx *)ctx;
    if (c->phase != 0 || len == 0) return;
    c->aad_len += (uint64_t)len * 8;
    scalar_process(c, aad, len);
}

static void s_update(void *ctx, const uint8_t *data, size_t len) {
    ghash_scalar_ctx *c = (ghash_scalar_ctx *)ctx;
    if (c->phase == 0) {
        if (c->buf_len > 0) {
            uint8_t blk[16] = {0};
            memcpy(blk, c->buf, c->buf_len);
            ghash_scalar_block(c, blk);
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
        if (c->buf_len == 16) {
            ghash_scalar_block(c, c->buf);
            c->buf_len = 0;
        }
    }
    scalar_process(c, data, len);
}

static void s_final(void *ctx, uint8_t out[16]) {
    ghash_scalar_ctx *c = (ghash_scalar_ctx *)ctx;
    if (c->phase == 0) c->phase = 1;

    if (c->buf_len > 0) {
        uint8_t blk[16] = {0};
        memcpy(blk, c->buf, c->buf_len);
        ghash_scalar_block(c, blk);
        c->buf_len = 0;
    }
    uint8_t lb[16] = {0};
    store64_be_(lb, c->aad_len);
    store64_be_(lb + 8, c->data_len);
    ghash_scalar_block(c, lb);
    memcpy(out, c->state, 16);
}

const sdc_ghash_vtable sdc_ghash_scalar_vtable = {
    s_init, s_aad, s_update, s_final
};

#endif /* SDC_ENABLE_GCM */
