#include <string.h>
#include <sdcrypt/config.h>
#include <sdcrypt/hash.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/sm3.h>
#include <sdcrypt/oid.h>
#include <sdcrypt/utils.h>

#if SDC_ENABLE_SM3

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define FF0(x, y, z) ((x) ^ (y) ^ (z))                          // 0 <= j <= 15
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))  // 16 <= j <= 63
#define GG0(x, y, z) ((x) ^ (y) ^ (z))                          // 0 <= j <= 15
#define GG1(x, y, z) (((x) & (y)) | (~(x) & (z)))               // 16 <= j <= 63
#define P0(x) ((x) ^ ROTL32(x, 9) ^ ROTL32(x, 17))
#define P1(x) ((x) ^ ROTL32(x, 15) ^ ROTL32(x, 23))

static const uint32_t T[64] = {
    0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb,
    0x9cc45197, 0x3988a32f, 0x7311465e, 0xe6228cbc,
    0xcc451979, 0x988a32f3, 0x311465e7, 0x6228cbce,
    0xc451979c, 0x88a32f39, 0x11465e73, 0x228cbce6,
    0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c,
    0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
    0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec,
    0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5,
    0x7a879d8a, 0xf50f3b14, 0xea1e7629, 0xd43cec53,
    0xa879d8a7, 0x50f3b14f, 0xa1e7629e, 0x43cec53d,
    0x879d8a7a, 0x0f3b14f5, 0x1e7629ea, 0x3cec53d4,
    0x79d8a7a8, 0xf3b14f50, 0xe7629ea1, 0xcec53d43,
    0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c,
    0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
    0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec,
    0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5
};

static void sm3_transform(sdc_sm3_ctx *ctx, const uint8_t *block) {
    uint32_t W[68];
    uint32_t W1[64];
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;

    for (int i = 0; i < 16; i++) {
        W[i] = load32_be(block + 4 * i);
    }
    for (int i = 16; i < 68; i++) {
        W[i] = P1(W[i-16] ^ W[i-9] ^ ROTL32(W[i-3], 15)) ^ ROTL32(W[i-13], 7) ^ W[i-6];
    }
    for (int i = 0; i < 64; i++) {
        W1[i] = W[i] ^ W[i+4];
    }

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];

    for (int i = 0; i < 64; i++) {
        SS1 = ROTL32((ROTL32(A, 12) + E + T[i]), 7);
        SS2 = SS1 ^ ROTL32(A, 12);

        if (i < 16) {
            TT1 = FF0(A, B, C) + D + SS2 + W1[i];
            TT2 = GG0(E, F, G) + H + SS1 + W[i];
        } else {
            TT1 = FF1(A, B, C) + D + SS2 + W1[i];
            TT2 = GG1(E, F, G) + H + SS1 + W[i];
        }

        D = C;
        C = ROTL32(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL32(F, 19);
        F = E;
        E = P0(TT2);
    }

    ctx->state[0] ^= A;
    ctx->state[1] ^= B;
    ctx->state[2] ^= C;
    ctx->state[3] ^= D;
    ctx->state[4] ^= E;
    ctx->state[5] ^= F;
    ctx->state[6] ^= G;
    ctx->state[7] ^= H;
}

void sdc_sm3_init(sdc_sm3_ctx *ctx) {
    ctx->state[0] = 0x7380166f;
    ctx->state[1] = 0x4914b2b9;
    ctx->state[2] = 0x172442d7;
    ctx->state[3] = 0xda8a0600;
    ctx->state[4] = 0xa96f30bc;
    ctx->state[5] = 0x163138aa;
    ctx->state[6] = 0xe38dee4d;
    ctx->state[7] = 0xb0fb0e4e;
    ctx->count = 0;
    ctx->len = 0;
}

void sdc_sm3_update(sdc_sm3_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->count += (uint64_t)len * 8;

    if (ctx->len) {
        size_t want = 64 - ctx->len;
        if (want > len) want = len;
        memcpy(ctx->buffer + ctx->len, data, want);
        ctx->len += want;
        data += want;
        len -= want;

        if (ctx->len == 64) {
            sm3_transform(ctx, ctx->buffer);
            ctx->len = 0;
        }
    }

    while (len >= 64) {
        sm3_transform(ctx, data);
        data += 64;
        len -= 64;
    }

    if (len) {
        memcpy(ctx->buffer, data, len);
        ctx->len = len;
    }
}

void sdc_sm3_final(sdc_sm3_ctx *ctx, uint8_t out[32]) {
    size_t i = ctx->len;
    ctx->buffer[i++] = 0x80;

    if (i > 56) {
        memset(ctx->buffer + i, 0, 64 - i);
        sm3_transform(ctx, ctx->buffer);
        i = 0;
    }
    memset(ctx->buffer + i, 0, 56 - i);
    store64_be(ctx->buffer + 56, ctx->count);
    sm3_transform(ctx, ctx->buffer);

    for (int j = 0; j < 8; j++) {
        store32_be(out + 4 * j, ctx->state[j]);
    }
}

void sdc_sm3_hash(uint8_t out[32], const uint8_t *in, size_t len) {
    sdc_sm3_ctx ctx;
    sdc_sm3_init(&ctx);
    sdc_sm3_update(&ctx, in, len);
    sdc_sm3_final(&ctx, out);
}

static int sm3_init_wrapper(sdc_hash_ctx *ctx) {
    if (!ctx) return SDC_ERR_INVALID_PARAM;
    sdc_sm3_ctx *state = (sdc_sm3_ctx *)ctx->inner_state;
    sdc_sm3_init(state);
    return SDC_ERR_OK;
}

static int sm3_update_wrapper(sdc_hash_ctx *ctx, const uint8_t *in, size_t len) {
    if (!ctx) return SDC_ERR_INVALID_PARAM;
    sdc_sm3_ctx *state = (sdc_sm3_ctx *)ctx->inner_state;
    sdc_sm3_update(state, in, len);
    return SDC_ERR_OK;
}

static int sm3_final_wrapper(sdc_hash_ctx *ctx, uint8_t *out, size_t *out_len) {
    if (!ctx || !out || !out_len) return SDC_ERR_INVALID_PARAM;
    if (*out_len < 32) {
        *out_len = 32;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }
    sdc_sm3_ctx *state = (sdc_sm3_ctx *)ctx->inner_state;
    sdc_sm3_final(state, out);
    *out_len = 32;
    return SDC_ERR_OK;
}

static int sm3_hash_wrapper(uint8_t *out, const uint8_t *in, size_t len, size_t *out_len) {
    if (!out || !out_len) return SDC_ERR_INVALID_PARAM;
    if (*out_len < 32) {
        *out_len = 32;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }
    sdc_sm3_hash(out, in, len);
    *out_len = 32;
    return SDC_ERR_OK;
}

const sdc_hash_ops_t sdc_sm3_ops = {
    .init = sm3_init_wrapper,
    .update = sm3_update_wrapper,
    .final = sm3_final_wrapper,
    .hash = sm3_hash_wrapper,
    .hash_len = 32,
    .name = "SM3",
    .oid = SDC_OID_SM3,
    .oid_len = SDC_OID_SM3_LEN
};

#endif /* SDC_ENABLE_SM3 */