/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * SHA-2 (Secure Hash Algorithm 2) family implementation.
 *
 * References:
 *   - FIPS PUB 180-4: Secure Hash Standard (SHS)
 *     (https://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf)
 *   - NIST SP 800-107: Recommendation for Applications Using Approved
 *     Hash Algorithms
 *
 * Implementation conforms to FIPS 180-4 for SHA-256.
 */

#include "config.h"
#include <string.h>
#include "sha2.h"
#include "utils.h"

#if SDC_ENABLE_SHA256

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define Ch(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x)    (ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define Sigma1(x)    (ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define sigma0(x)    (ROTR32(x, 7) ^ ROTR32(x, 18) ^ ((x) >> 3))
#define sigma1(x)    (ROTR32(x, 17) ^ ROTR32(x, 19) ^ ((x) >> 10))

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sdc_sha256_transform(sdc_sha256_ctx *ctx, const uint8_t* block) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t T1, T2;

    for (int i = 0; i < 16; i++) {
        W[i] = load32_be(block + 4 * i);
    }
    for (int i = 16; i < 64; i++) {
        W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (int i = 0; i < 64; i++) {
        T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
        T2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sdc_sha256_init(sdc_sha256_ctx *ctx) {
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
    ctx->len = 0;
}

void sdc_sha256_update(sdc_sha256_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->count += (uint64_t)len * 8;

    if (ctx->len) {
        size_t want = 64 - ctx->len;
        if (want > len) want = len;
        memcpy(ctx->buffer + ctx->len, data, want);
        ctx->len += want;
        data += want;
        len -= want;
        if (ctx->len == 64) {
            sdc_sha256_transform(ctx, ctx->buffer);
            ctx->len = 0;
        }
    }

    while (len >= 64) {
        sdc_sha256_transform(ctx, data);
        data += 64;
        len -= 64;
    }

    if (len) {
        memcpy(ctx->buffer, data, len);
        ctx->len = len;
    }
}

void sdc_sha256_final(sdc_sha256_ctx *ctx, uint8_t out[32]) {
    size_t i = ctx->len;
    ctx->buffer[i++] = 0x80;
    
    if (ctx->len > 55) {
        memset(ctx->buffer + i, 0, 64 - i);
        sdc_sha256_transform(ctx, ctx->buffer);
        i = 0;
    }
    memset(ctx->buffer + i, 0, 56 - i);
    store64_be(ctx->buffer + 56, ctx->count);
    sdc_sha256_transform(ctx, ctx->buffer);

    for (int j = 0; j < 8; j++) {
        store32_be(out + 4 * j, ctx->state[j]);
    }
}

void sdc_sha256_hash(uint8_t out[32], const uint8_t *in, size_t len) {
    sdc_sha256_ctx ctx;
    sdc_sha256_init(&ctx);
    sdc_sha256_update(&ctx, in, len);
    sdc_sha256_final(&ctx, out);
}

#endif /* SDC_ENABLE_SHA256 */