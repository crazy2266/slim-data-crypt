/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * SHA-3 (Secure Hash Algorithm 3) family implementation.
 *
 * Implementation conforms to FIPS 180-4 for SHA-3 family.
 */

#include <string.h>
#include <sdcrypt/config.h>
#include <sdcrypt/hash.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/sha.h>
#include <sdcrypt/oid.h>
#include <sdcrypt/utils.h>

#if SDC_ENABLE_SHA3

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL,
};

static const int RHO[25] = {
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
};

static void keccak_f1600(uint64_t a[25]) {
    uint64_t b[25];
    uint64_t c[5];
    uint64_t d;
    int round, x, y;

    for (round = 0; round < 24; round++) {
        // θ
        for (x = 0; x < 5; x++) {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for (x = 0; x < 5; x++) {
            d = c[(x + 4) % 5] ^ ROTL64(c[(x + 1) % 5], 1);
            for (y = 0; y < 5; y++) {
                a[x + 5 * y] ^= d;
            }
        }

        // ρ + π
        for (x = 0; x < 5; x++) {
            for (y = 0; y < 5; y++) {
                b[y + 5 * ((2 * x + 3 * y) % 5)] =
                    ROTL64(a[x + 5 * y], RHO[x + 5 * y]);
            }
        }

        // χ
        for (x = 0; x < 5; x++) {
            for (y = 0; y < 5; y++) {
                a[x + 5 * y] = b[x + 5 * y]
                    ^ ((~b[((x + 1) % 5) + 5 * y])
                    & b[((x + 2) % 5) + 5 * y]);
            }
        }

        // ι
        a[0] ^= RC[round];
    }
}

static void keccak_absorb(sdc_sha3_ctx *ctx, const uint8_t *data, size_t len) {
    size_t rate = ctx->rate;
    size_t i;

    while (len) {
        size_t chunk = rate - ctx->buf_len;
        if (chunk > len) chunk = len;
        memcpy(ctx->buffer + ctx->buf_len, data, chunk);
        ctx->buf_len += chunk;
        data += chunk;
        len -= chunk;

        if (ctx->buf_len == rate) {
            for (i = 0; i < rate / 8; i++) {
                ctx->state[i] ^= load64_le(ctx->buffer + 8 * i);
            }
            keccak_f1600(ctx->state);
            ctx->buf_len = 0;
        }
    }
}

static void keccak_finalize(sdc_sha3_ctx *ctx, uint8_t pad) {
    size_t rate = ctx->rate;

    memset(ctx->buffer + ctx->buf_len, 0, rate - ctx->buf_len);
    ctx->buffer[ctx->buf_len] ^= pad;
    ctx->buffer[rate - 1] ^= 0x80;

    for (size_t i = 0; i < rate / 8; i++) {
        ctx->state[i] ^= load64_le(ctx->buffer + 8 * i);
    }
    keccak_f1600(ctx->state);

    for (size_t i = 0; i < rate / 8; i++) {
        store64_le(ctx->buffer + 8 * i, ctx->state[i]);
    }
    ctx->buf_len = 0;
}

static void keccak_squeeze(sdc_sha3_ctx *ctx, uint8_t *out, size_t len) {
    size_t rate = ctx->rate;

    while (len) {
        if (ctx->buf_len == rate) {
            keccak_f1600(ctx->state);
            for (size_t i = 0; i < rate / 8; i++) {
                store64_le(ctx->buffer + 8 * i, ctx->state[i]);
            }
            ctx->buf_len = 0;
        }

        size_t chunk = rate - ctx->buf_len;
        if (chunk > len) chunk = len;
        memcpy(out, ctx->buffer + ctx->buf_len, chunk);
        ctx->buf_len += chunk;
        out += chunk;
        len -= chunk;
    }
}

// ---- SHA3-224 ----
void sdc_sha3_224_init(sdc_sha3_ctx *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->rate = 144;
    ctx->out_len = 28;
}

void sdc_sha3_224_update(sdc_sha3_ctx *ctx, const uint8_t *data, size_t len) {
    keccak_absorb(ctx, data, len);
}

void sdc_sha3_224_final(sdc_sha3_ctx *ctx, uint8_t out[28]) {
    keccak_finalize(ctx, 0x06);
    memcpy(out, ctx->buffer, 28);
}

void sdc_sha3_224_hash(uint8_t out[28], const uint8_t *in, size_t len) {
    sdc_sha3_ctx ctx;
    sdc_sha3_224_init(&ctx);
    sdc_sha3_224_update(&ctx, in, len);
    sdc_sha3_224_final(&ctx, out);
}

// ---- SHA3-256 ----
void sdc_sha3_256_init(sdc_sha3_ctx *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->rate = 136;
    ctx->out_len = 32;
}

void sdc_sha3_256_update(sdc_sha3_ctx *ctx, const uint8_t *data, size_t len) {
    keccak_absorb(ctx, data, len);
}

void sdc_sha3_256_final(sdc_sha3_ctx *ctx, uint8_t out[32]) {
    keccak_finalize(ctx, 0x06);
    memcpy(out, ctx->buffer, 32);
}

void sdc_sha3_256_hash(uint8_t out[32], const uint8_t *in, size_t len) {
    sdc_sha3_ctx ctx;
    sdc_sha3_256_init(&ctx);
    sdc_sha3_256_update(&ctx, in, len);
    sdc_sha3_256_final(&ctx, out);
}

// ---- SHA3-384 ----
void sdc_sha3_384_init(sdc_sha3_ctx *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->rate = 104;
    ctx->out_len = 48;
}

void sdc_sha3_384_update(sdc_sha3_ctx *ctx, const uint8_t *data, size_t len) {
    keccak_absorb(ctx, data, len);
}

void sdc_sha3_384_final(sdc_sha3_ctx *ctx, uint8_t out[48]) {
    keccak_finalize(ctx, 0x06);
    memcpy(out, ctx->buffer, 48);
}

void sdc_sha3_384_hash(uint8_t out[48], const uint8_t *in, size_t len) {
    sdc_sha3_ctx ctx;
    sdc_sha3_384_init(&ctx);
    sdc_sha3_384_update(&ctx, in, len);
    sdc_sha3_384_final(&ctx, out);
}

// ---- SHA3-512 ----
void sdc_sha3_512_init(sdc_sha3_ctx *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->rate = 72;
    ctx->out_len = 64;
}

void sdc_sha3_512_update(sdc_sha3_ctx *ctx, const uint8_t *data, size_t len) {
    keccak_absorb(ctx, data, len);
}

void sdc_sha3_512_final(sdc_sha3_ctx *ctx, uint8_t out[64]) {
    keccak_finalize(ctx, 0x06);
    memcpy(out, ctx->buffer, 64);
}

void sdc_sha3_512_hash(uint8_t out[64], const uint8_t *in, size_t len) {
    sdc_sha3_ctx ctx;
    sdc_sha3_512_init(&ctx);
    sdc_sha3_512_update(&ctx, in, len);
    sdc_sha3_512_final(&ctx, out);
}

// ---- SHAKE128 ----
void sdc_shake128_init(sdc_sha3_ctx *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->rate = 168;
}

void sdc_shake128_update(sdc_sha3_ctx *ctx, const uint8_t *data, size_t len) {
    keccak_absorb(ctx, data, len);
}

void sdc_shake128_final(sdc_sha3_ctx *ctx) {
    keccak_finalize(ctx, 0x1F);
}

void sdc_shake128_squeeze(sdc_sha3_ctx *ctx, uint8_t *out, size_t len) {
    keccak_squeeze(ctx, out, len);
}

void sdc_shake128_hash(uint8_t *out, const uint8_t *in, size_t len, size_t out_len) {
    sdc_sha3_ctx ctx;
    sdc_shake128_init(&ctx);
    sdc_shake128_update(&ctx, in, len);
    sdc_shake128_final(&ctx);
    sdc_shake128_squeeze(&ctx, out, out_len);
}

// ---- SHAKE256 ----
void sdc_shake256_init(sdc_sha3_ctx *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->rate = 136;
}

void sdc_shake256_update(sdc_sha3_ctx *ctx, const uint8_t *data, size_t len) {
    keccak_absorb(ctx, data, len);
}

void sdc_shake256_final(sdc_sha3_ctx *ctx) {
    keccak_finalize(ctx, 0x1F);
}

void sdc_shake256_squeeze(sdc_sha3_ctx *ctx, uint8_t *out, size_t len) {
    keccak_squeeze(ctx, out, len);
}

void sdc_shake256_hash(uint8_t *out, const uint8_t *in, size_t len, size_t out_len) {
    sdc_sha3_ctx ctx;
    sdc_shake256_init(&ctx);
    sdc_shake256_update(&ctx, in, len);
    sdc_shake256_final(&ctx);
    sdc_shake256_squeeze(&ctx, out, out_len);
}

/* ---- SHA3-224 ---- */

static int sha3_224_init_wrapper(sdc_hash_ctx *ctx) {
    if (!ctx) return SDC_ERR_INVALID_PARAM;
    sdc_sha3_ctx *state = (sdc_sha3_ctx *)ctx->inner_state;
    sdc_sha3_224_init(state);
    return SDC_ERR_OK;
}

static int sha3_224_update_wrapper(sdc_hash_ctx *ctx, const uint8_t *in, size_t len) {
    if (!ctx) return SDC_ERR_INVALID_PARAM;
    sdc_sha3_ctx *state = (sdc_sha3_ctx *)ctx->inner_state;
    sdc_sha3_224_update(state, in, len);
    return SDC_ERR_OK;
}

static int sha3_224_final_wrapper(sdc_hash_ctx *ctx, uint8_t *out, size_t *out_len) {
    if (!ctx || !out || !out_len) return SDC_ERR_INVALID_PARAM;
    if (*out_len < 28) {
        *out_len = 28;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }
    sdc_sha3_ctx *state = (sdc_sha3_ctx *)ctx->inner_state;
    sdc_sha3_224_final(state, out);
    *out_len = 28;
    return SDC_ERR_OK;
}

static int sha3_224_hash_wrapper(uint8_t *out, const uint8_t *in, size_t len, size_t *out_len) {
    if (!out || !out_len) return SDC_ERR_INVALID_PARAM;
    if (*out_len < 28) {
        *out_len = 28;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }
    sdc_sha3_224_hash(out, in, len);
    *out_len = 28;
    return SDC_ERR_OK;
}


const sdc_hash_ops_t sdc_sha3_224_ops = {
    .init = sha3_224_init_wrapper,
    .update = sha3_224_update_wrapper,
    .final = sha3_224_final_wrapper,
    .hash = sha3_224_hash_wrapper,
    .hash_len = 28,
    .name = "SHA3-224",
    .oid = SDC_OID_SHA3_224,
    .oid_len = SDC_OID_SHA3_224_LEN
};

/* ---- SHA3-256 ---- */

static int sha3_256_init_wrapper(sdc_hash_ctx *ctx) {
    if (!ctx) return SDC_ERR_INVALID_PARAM;
    sdc_sha3_ctx *state = (sdc_sha3_ctx *)ctx->inner_state;
    sdc_sha3_256_init(state);
    return SDC_ERR_OK;
}

static int sha3_256_update_wrapper(sdc_hash_ctx *ctx, const uint8_t *in, size_t len) {
    if (!ctx) return SDC_ERR_INVALID_PARAM;
    sdc_sha3_ctx *state = (sdc_sha3_ctx *)ctx->inner_state;
    sdc_sha3_256_update(state, in, len);
    return SDC_ERR_OK;
}

static int sha3_256_final_wrapper(sdc_hash_ctx *ctx, uint8_t *out, size_t *out_len) {
    if (!ctx || !out || !out_len) return SDC_ERR_INVALID_PARAM;
    if (*out_len < 32) {
        *out_len = 32;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }
    sdc_sha3_ctx *state = (sdc_sha3_ctx *)ctx->inner_state;
    sdc_sha3_256_final(state, out);
    *out_len = 32;
    return SDC_ERR_OK;
}

static int sha3_256_hash_wrapper(uint8_t *out, const uint8_t *in, size_t len, size_t *out_len) {
    if (!out || !out_len) return SDC_ERR_INVALID_PARAM;
    if (*out_len < 32) {
        *out_len = 32;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }
    sdc_sha3_256_hash(out, in, len);
    *out_len = 32;
    return SDC_ERR_OK;
}

const sdc_hash_ops_t sdc_sha3_256_ops = {
    .init = sha3_256_init_wrapper,
    .update = sha3_256_update_wrapper,
    .final = sha3_256_final_wrapper,
    .hash = sha3_256_hash_wrapper,
    .hash_len = 32,
    .name = "SHA3-256",
    .oid = SDC_OID_SHA3_256,
    .oid_len = SDC_OID_SHA3_256_LEN
};

/* ---- SHA3-384 ---- */

static int sha3_384_init_wrapper(sdc_hash_ctx *ctx) {
    if (!ctx) return SDC_ERR_INVALID_PARAM;
    sdc_sha3_ctx *state = (sdc_sha3_ctx *)ctx->inner_state;
    sdc_sha3_384_init(state);
    return SDC_ERR_OK;
}

static int sha3_384_update_wrapper(sdc_hash_ctx *ctx, const uint8_t *in, size_t len) {
    if (!ctx) return SDC_ERR_INVALID_PARAM;
    sdc_sha3_ctx *state = (sdc_sha3_ctx *)ctx->inner_state;
    sdc_sha3_384_update(state, in, len);
    return SDC_ERR_OK;
}

static int sha3_384_final_wrapper(sdc_hash_ctx *ctx, uint8_t *out, size_t *out_len) {
    if (!ctx || !out || !out_len) return SDC_ERR_INVALID_PARAM;
    if (*out_len < 48) {
        *out_len = 48;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }
    sdc_sha3_ctx *state = (sdc_sha3_ctx *)ctx->inner_state;
    sdc_sha3_384_final(state, out);
    *out_len = 48;
    return SDC_ERR_OK;
}

static int sha3_384_hash_wrapper(uint8_t *out, const uint8_t *in, size_t len, size_t *out_len) {
    if (!out || !out_len) return SDC_ERR_INVALID_PARAM;
    if (*out_len < 48) {
        *out_len = 48;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }
    sdc_sha3_384_hash(out, in, len);
    *out_len = 48;
    return SDC_ERR_OK;
}

const sdc_hash_ops_t sdc_sha3_384_ops = {
    .init = sha3_384_init_wrapper,
    .update = sha3_384_update_wrapper,
    .final = sha3_384_final_wrapper,
    .hash = sha3_384_hash_wrapper,
    .hash_len = 48,
    .name = "SHA3-384",
    .oid = SDC_OID_SHA3_384,
    .oid_len = SDC_OID_SHA3_384_LEN
};

/* ---- SHA3-512 ---- */

static int sha3_512_init_wrapper(sdc_hash_ctx *ctx) {
    if (!ctx) return SDC_ERR_INVALID_PARAM;
    sdc_sha3_ctx *state = (sdc_sha3_ctx *)ctx->inner_state;
    sdc_sha3_512_init(state);
    return SDC_ERR_OK;
}

static int sha3_512_update_wrapper(sdc_hash_ctx *ctx, const uint8_t *in, size_t len) {
    if (!ctx) return SDC_ERR_INVALID_PARAM;
    sdc_sha3_ctx *state = (sdc_sha3_ctx *)ctx->inner_state;
    sdc_sha3_512_update(state, in, len);
    return SDC_ERR_OK;
}

static int sha3_512_final_wrapper(sdc_hash_ctx *ctx, uint8_t *out, size_t *out_len) {
    if (!ctx || !out || !out_len) return SDC_ERR_INVALID_PARAM;
    if (*out_len < 64) {
        *out_len = 64;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }
    sdc_sha3_ctx *state = (sdc_sha3_ctx *)ctx->inner_state;
    sdc_sha3_512_final(state, out);
    *out_len = 64;
    return SDC_ERR_OK;
}

static int sha3_512_hash_wrapper(uint8_t *out, const uint8_t *in, size_t len, size_t *out_len) {
    if (!out || !out_len) return SDC_ERR_INVALID_PARAM;
    if (*out_len < 64) {
        *out_len = 64;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }
    sdc_sha3_512_hash(out, in, len);
    *out_len = 64;
    return SDC_ERR_OK;
}

const sdc_hash_ops_t sdc_sha3_512_ops = {
    .init = sha3_512_init_wrapper,
    .update = sha3_512_update_wrapper,
    .final = sha3_512_final_wrapper,
    .hash = sha3_512_hash_wrapper,
    .hash_len = 64,
    .name = "SHA3-512",
    .oid = SDC_OID_SHA3_512,
    .oid_len = SDC_OID_SHA3_512_LEN
};

#endif  /* SDC_ENABLE_SHA3 */