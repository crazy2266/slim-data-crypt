/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Constant-time SM4 backend (no table lookups, no secret-dependent
 * branches or memory accesses).  Exposed only through sdc_sm4_ct_ops;
 * the native sdc_sm4_* API is table-driven.
 *
 * The S-box is a pure boolean circuit over 4 bytes packed in a uint32_t
 * (byte j in bits [8j, 8j+7]); each bit plane is (x>>k)&0x01010101.
 * It was derived from a GF(2^8) field-tower construction and verified
 * bit-exactly against the official SM4 S-box (GB/T 32907-2016).
 */

#include <string.h>
#include <sdcrypt/config.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/sm4.h>
#include <sdcrypt/block_cipher.h>
#include <sdcrypt/utils.h>

#if SDC_ENABLE_SM4 && SDC_ENABLE_SM4_CT

#define ROTL32_CT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static const uint32_t CT_FK[4] = {
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};

static const uint32_t CT_CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

/*
 * S-box over 4 parallel bytes packed in a uint32_t.
 * Byte j lives in bits [8j, 8j+7]; a bit-plane is (x>>k)&0x01010101.
 */
static uint32_t sm4_sbox_word(uint32_t x) {
    uint32_t p0, p1, p2, p3, p4, p5, p6, p7;
    uint32_t c0, c1, c2, c3, c4, c5, c6, c7;
    uint32_t h0, h1, h2, h3, l0, l1, l2, l3;
    uint32_t hh0, hh1, hh2, hh3, ll0, ll1, ll2, ll3;
    uint32_t hhlam0, hhlam1, hhlam2, hhlam3;
    uint32_t hl0, hl1, hl2, hl3, d0, d1, d2, d3;
    uint32_t dinv0, dinv1, dinv2, dinv3;
    uint32_t nh0, nh1, nh2, nh3, hxl0, hxl1, hxl2, hxl3;
    uint32_t nl0, nl1, nl2, nl3, o0, o1, o2, o3, o4, o5, o6, o7;
    uint32_t q0, q1, q2, q3, q4, q5, q6, q7;

    p0 = x & 0x01010101;
    p1 = (x >> 1) & 0x01010101;
    p2 = (x >> 2) & 0x01010101;
    p3 = (x >> 3) & 0x01010101;
    p4 = (x >> 4) & 0x01010101;
    p5 = (x >> 5) & 0x01010101;
    p6 = (x >> 6) & 0x01010101;
    p7 = (x >> 7) & 0x01010101;

    c0 = ~(p3 ^ p4 ^ p7) & 0x01010101;
    c1 = ~(p0 ^ p5 ^ p6 ^ p7) & 0x01010101;
    c2 = p0 ^ p2;
    c3 = p0 ^ p1 ^ p2 ^ p3;
    c4 = p0 ^ p1 ^ p4 ^ p7;
    c5 = ~(p6) & 0x01010101;
    c6 = p2 ^ p6 ^ p7;
    c7 = ~(p0 ^ p1 ^ p2 ^ p3 ^ p4 ^ p5 ^ p6) & 0x01010101;

    h0 = c4; h1 = c5; h2 = c6; h3 = c7;
    l0 = c0; l1 = c1; l2 = c2; l3 = c3;

    hh0 = h0 ^ h2; hh1 = h2; hh2 = h1 ^ h3; hh3 = h3;
    ll0 = l0 ^ l2; ll1 = l2; ll2 = l1 ^ l3; ll3 = l3;

    hhlam0 = hh1 ^ hh2;
    hhlam1 = hh1 ^ hh3;
    hhlam2 = hh0 ^ hh2;
    hhlam3 = hh0 ^ hh1 ^ hh3;

    hl0 = (h0 & l0) ^ (h1 & l3) ^ (h2 & l2) ^ (h3 & l1);
    hl1 = (h0 & l1) ^ (h1 & l0) ^ (h1 & l3) ^ (h2 & l2) ^ (h2 & l3) ^ (h3 & l1) ^ (h3 & l2);
    hl2 = (h0 & l2) ^ (h1 & l1) ^ (h2 & l0) ^ (h2 & l3) ^ (h3 & l2) ^ (h3 & l3);
    hl3 = (h0 & l3) ^ (h1 & l2) ^ (h2 & l1) ^ (h3 & l0) ^ (h3 & l3);

    d0 = hhlam0 ^ hl0 ^ ll0;
    d1 = hhlam1 ^ hl1 ^ ll1;
    d2 = hhlam2 ^ hl2 ^ ll2;
    d3 = hhlam3 ^ hl3 ^ ll3;

    dinv0 = d0 ^ d1 ^ d2 ^ (d0 & d2) ^ (d1 & d2) ^ (d0 & d1 & d2) ^ d3 ^ (d1 & d2 & d3);
    dinv1 = (d0 & d1) ^ (d0 & d2) ^ (d1 & d2) ^ d3 ^ (d1 & d3) ^ (d0 & d1 & d3);
    dinv2 = (d0 & d1) ^ d2 ^ (d0 & d2) ^ d3 ^ (d0 & d3) ^ (d0 & d2 & d3);
    dinv3 = d1 ^ d2 ^ d3 ^ (d0 & d3) ^ (d1 & d3) ^ (d2 & d3) ^ (d1 & d2 & d3);

    nh0 = (h0 & dinv0) ^ (h1 & dinv3) ^ (h2 & dinv2) ^ (h3 & dinv1);
    nh1 = (h0 & dinv1) ^ (h1 & dinv0) ^ (h1 & dinv3) ^ (h2 & dinv2) ^ (h2 & dinv3) ^ (h3 & dinv1) ^ (h3 & dinv2);
    nh2 = (h0 & dinv2) ^ (h1 & dinv1) ^ (h2 & dinv0) ^ (h2 & dinv3) ^ (h3 & dinv2) ^ (h3 & dinv3);
    nh3 = (h0 & dinv3) ^ (h1 & dinv2) ^ (h2 & dinv1) ^ (h3 & dinv0) ^ (h3 & dinv3);

    hxl0 = h0 ^ l0; hxl1 = h1 ^ l1; hxl2 = h2 ^ l2; hxl3 = h3 ^ l3;

    nl0 = (hxl0 & dinv0) ^ (hxl1 & dinv3) ^ (hxl2 & dinv2) ^ (hxl3 & dinv1);
    nl1 = (hxl0 & dinv1) ^ (hxl1 & dinv0) ^ (hxl1 & dinv3) ^ (hxl2 & dinv2) ^ (hxl2 & dinv3) ^ (hxl3 & dinv1) ^ (hxl3 & dinv2);
    nl2 = (hxl0 & dinv2) ^ (hxl1 & dinv1) ^ (hxl2 & dinv0) ^ (hxl2 & dinv3) ^ (hxl3 & dinv2) ^ (hxl3 & dinv3);
    nl3 = (hxl0 & dinv3) ^ (hxl1 & dinv2) ^ (hxl2 & dinv1) ^ (hxl3 & dinv0) ^ (hxl3 & dinv3);

    o0 = nl0; o1 = nl1; o2 = nl2; o3 = nl3;
    o4 = nh0; o5 = nh1; o6 = nh2; o7 = nh3;

    q0 = ~(o0 ^ o1 ^ o4 ^ o6 ^ o7) & 0x01010101;
    q1 = ~(o0 ^ o2 ^ o5 ^ o7) & 0x01010101;
    q2 = o2 ^ o5;
    q3 = o0 ^ o2 ^ o4 ^ o5 ^ o6;
    q4 = ~(o1 ^ o3 ^ o5 ^ o6 ^ o7) & 0x01010101;
    q5 = o1 ^ o3 ^ o6;
    q6 = ~(o0 ^ o1 ^ o2 ^ o4 ^ o6 ^ o7) & 0x01010101;
    q7 = ~(o0 ^ o3 ^ o5 ^ o7) & 0x01010101;

    return (q7 << 7) | (q6 << 6) | (q5 << 5) | (q4 << 4)
         | (q3 << 3) | (q2 << 2) | (q1 << 1) |  q0;
}

/* T (single block): tau + linear layer L */
static uint32_t sm4_T_ct(uint32_t x) {
    uint32_t b = sm4_sbox_word(x);
    return b ^ ROTL32_CT(b, 2) ^ ROTL32_CT(b, 10)
             ^ ROTL32_CT(b, 18) ^ ROTL32_CT(b, 24);
}

/* T' for key schedule: tau + linear layer L' */
static uint32_t sm4_Tp_ct(uint32_t x) {
    uint32_t b = sm4_sbox_word(x);
    return b ^ ROTL32_CT(b, 13) ^ ROTL32_CT(b, 23);
}

static void sm4_crypt_block_ct(const sdc_sm4_ctx *ctx,
                               const uint8_t in[16], uint8_t out[16]) {
    uint32_t X0, X1, X2, X3, X4;

    X0 = load32_be(in);
    X1 = load32_be(in + 4);
    X2 = load32_be(in + 8);
    X3 = load32_be(in + 12);

    for (int i = 0; i < 32; i++) {
        X4 = X0 ^ sm4_T_ct(X1 ^ X2 ^ X3 ^ ctx->rk[i]);
        X0 = X1;
        X1 = X2;
        X2 = X3;
        X3 = X4;
    }

    store32_be(out,      X3);
    store32_be(out + 4,  X2);
    store32_be(out + 8,  X1);
    store32_be(out + 12, X0);
}

/* Constant-time key schedule (T' via the table-free S-box). */
static int sm4_set_encrypt_key_ct(sdc_sm4_ctx *ctx, const uint8_t user_key[16]) {
    uint32_t X[36];

    if (!ctx || !user_key) return SDC_ERR_INVALID_PARAM;

    for (int i = 0; i < 4; i++) X[i] = load32_be(user_key + 4 * i) ^ CT_FK[i];
    for (int i = 0; i < 32; i++)
        X[i + 4] = X[i] ^ sm4_Tp_ct(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ CT_CK[i]);
    for (int i = 0; i < 32; i++) ctx->rk[i] = X[i + 4];

    sdc_secure_memzero(X, sizeof(X));
    return SDC_ERR_OK;
}

static int sm4_set_decrypt_key_ct(sdc_sm4_ctx *ctx, const uint8_t user_key[16]) {
    int rc = sm4_set_encrypt_key_ct(ctx, user_key);
    if (rc != SDC_ERR_OK) return rc;
    for (int i = 0; i < 16; i++) {
        uint32_t t = ctx->rk[i];
        ctx->rk[i] = ctx->rk[31 - i];
        ctx->rk[31 - i] = t;
    }
    return SDC_ERR_OK;
}

/* ---------------- ops layer (wrappers) ---------------- */

static int sm4_set_encrypt_key_ct_wrapper(sdc_block_cipher_ctx *ctx, const uint8_t *user_key) {
    return sm4_set_encrypt_key_ct((sdc_sm4_ctx *)ctx->inner_state, user_key);
}

static int sm4_set_decrypt_key_ct_wrapper(sdc_block_cipher_ctx *ctx, const uint8_t *user_key) {
    return sm4_set_decrypt_key_ct((sdc_sm4_ctx *)ctx->inner_state, user_key);
}

static void sm4_encrypt_block_ct_wrapper(const sdc_block_cipher_ctx *ctx,
                                         const uint8_t in[16], uint8_t out[16]) {
    sm4_crypt_block_ct((const sdc_sm4_ctx *)ctx->inner_state, in, out);
}

static void sm4_encrypt_blocks_ct_wrapper(const sdc_block_cipher_ctx *ctx,
                                          const uint8_t *in, size_t nblocks, uint8_t *out) {
    for (size_t i = 0; i < nblocks; i++) {
        sm4_crypt_block_ct((const sdc_sm4_ctx *)ctx->inner_state, in + 16 * i, out + 16 * i);
    }
}

const sdc_block_cipher_ops_t sdc_sm4_ct_ops = {
    sm4_set_encrypt_key_ct_wrapper,
    sm4_set_decrypt_key_ct_wrapper,
    sm4_encrypt_block_ct_wrapper,
    sm4_encrypt_block_ct_wrapper,   /* SM4 encrypt == decrypt with reversed key */
    sm4_encrypt_blocks_ct_wrapper,
    SDC_SM4_KEY_SIZE,
    "SM4 constant-time"
};

#endif /* SDC_ENABLE_SM4 && SDC_ENABLE_SM4_CT */
