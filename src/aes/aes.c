/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * AES block cipher, scalar implementation (FIPS-197).
 */

#include <string.h>
#include <sdcrypt/config.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/aes.h>
#include <sdcrypt/utils.h>
#include "aes_backend.h"
#include "../cpu.h"

#if SDC_ENABLE_AES

/* ---------------- S-boxes ---------------- */

static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t rsbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const uint32_t rcon[11] = {
    0x00000000,0x01000000,0x02000000,0x04000000,0x08000000,
    0x10000000,0x20000000,0x40000000,0x80000000,0x1b000000,0x36000000
};

/* ---------------- GF(2^8) helpers ---------------- */

static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

/* ---------------- key expansion ---------------- */

static uint32_t sub_word(uint32_t w) {
    return ((uint32_t)sbox[(w >> 24) & 0xff] << 24) |
           ((uint32_t)sbox[(w >> 16) & 0xff] << 16) |
           ((uint32_t)sbox[(w >> 8) & 0xff] << 8) |
           ((uint32_t)sbox[w & 0xff]);
}

static void key_expansion(uint8_t *rk, const uint8_t *key, int nk, int nr) {
    uint32_t w[60];
    int total = 4 * (nr + 1);

    for (int i = 0; i < nk; i++) {
        w[i] = ((uint32_t)key[4*i] << 24) | ((uint32_t)key[4*i+1] << 16) |
               ((uint32_t)key[4*i+2] << 8) | (uint32_t)key[4*i+3];
    }
    for (int i = nk; i < total; i++) {
        uint32_t t = w[i-1];
        if (i % nk == 0) {
            t = sub_word((t << 8) | (t >> 24));   /* RotWord + SubWord */
            t ^= rcon[i / nk];
        } else if (nk > 6 && i % nk == 4) {
            t = sub_word(t);
        }
        w[i] = w[i-nk] ^ t;
    }
    for (int i = 0; i < total; i++) {
        rk[4*i+0] = (uint8_t)(w[i] >> 24);
        rk[4*i+1] = (uint8_t)(w[i] >> 16);
        rk[4*i+2] = (uint8_t)(w[i] >> 8);
        rk[4*i+3] = (uint8_t)(w[i]);
    }
}

/* ---------------- block cipher ---------------- */

static void add_round_key(uint8_t *s, const uint8_t *rk) {
    for (int i = 0; i < 16; i++) s[i] ^= rk[i];
}

static void sub_bytes(uint8_t *s) {
    for (int i = 0; i < 16; i++) s[i] = sbox[s[i]];
}
static void inv_sub_bytes(uint8_t *s) {
    for (int i = 0; i < 16; i++) s[i] = rsbox[s[i]];
}

static void shift_rows(uint8_t *s) {
    uint8_t t;
    /* row 1: left by 1 */
    t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    /* row 2: left by 2 */
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    /* row 3: left by 3 (= right by 1) */
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}

static void inv_shift_rows(uint8_t *s) {
    uint8_t t;
    /* row 1: right by 1 */
    t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    /* row 2: same as shift (self-inverse) */
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    /* row 3: right by 3 (= left by 1) */
    t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
}

static void mix_columns(uint8_t *s) {
    for (int c = 0; c < 4; c++) {
        uint8_t *col = s + 4*c;
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        col[0] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
        col[1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
        col[2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
        col[3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
    }
}

static void inv_mix_columns(uint8_t *s) {
    for (int c = 0; c < 4; c++) {
        uint8_t *col = s + 4*c;
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        col[0] = gmul(a0,14) ^ gmul(a1,11) ^ gmul(a2,13) ^ gmul(a3,9);
        col[1] = gmul(a0,9)  ^ gmul(a1,14) ^ gmul(a2,11) ^ gmul(a3,13);
        col[2] = gmul(a0,13) ^ gmul(a1,9)  ^ gmul(a2,14) ^ gmul(a3,11);
        col[3] = gmul(a0,11) ^ gmul(a1,13) ^ gmul(a2,9)  ^ gmul(a3,14);
    }
}

void sdc_aes_scalar_encrypt(const sdc_aes_key *key, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    memcpy(s, in, 16);

    add_round_key(s, key->rk);
    for (int r = 1; r < key->nr; r++) {
        sub_bytes(s);
        shift_rows(s);
        mix_columns(s);
        add_round_key(s, key->rk + 16*r);
    }
    sub_bytes(s);
    shift_rows(s);
    add_round_key(s, key->rk + 16*key->nr);

    memcpy(out, s, 16);
    sdc_secure_memzero(s, sizeof(s));
}

void sdc_aes_scalar_decrypt(const sdc_aes_key *key, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    memcpy(s, in, 16);

    add_round_key(s, key->rk + 16*key->nr);
    for (int r = key->nr - 1; r >= 1; r--) {
        inv_shift_rows(s);
        inv_sub_bytes(s);
        add_round_key(s, key->rk + 16*r);
        inv_mix_columns(s);
    }
    inv_shift_rows(s);
    inv_sub_bytes(s);
    add_round_key(s, key->rk);

    memcpy(out, s, 16);
    sdc_secure_memzero(s, sizeof(s));
}

/* ---------------- public API ---------------- */

void sdc_aes_init(void) {
    (void)sdc_cpu_get();   /* warm the cache */
}

int sdc_aes_set_encrypt_key(sdc_aes_key *key, const uint8_t *user_key, size_t key_len) {
    int nk, nr;
    switch (key_len) {
        case 16: nk = 4; nr = 10; break;
        case 24: nk = 6; nr = 12; break;
        case 32: nk = 8; nr = 14; break;
        default: return SDC_ERR_KEY_SIZE_INVALID;
    }
    if (!key || !user_key) return SDC_ERR_INVALID_PARAM;

    key->nr = nr;
    key_expansion(key->rk, user_key, nk, nr);   /* portable round keys */

    const sdc_cpu_features *f = sdc_cpu_get();
#if defined(SDC_HAVE_AESNI)
    if (f->aes) {
        key->impl = SDC_AES_IMPL_AESNI;
        sdc_aes_aesni_set_key(key);
        return SDC_ERR_OK;
    }
#endif
#if defined(SDC_HAVE_ARMCE)
    if (f->aes) {
        key->impl = SDC_AES_IMPL_ARMCE;
        sdc_aes_armce_set_key(key);
        return SDC_ERR_OK;
    }
#endif
    (void)f;
    key->impl = SDC_AES_IMPL_SCALAR;
    return SDC_ERR_OK;
}

int sdc_aes_set_decrypt_key(sdc_aes_key *key, const uint8_t *user_key, size_t key_len) {
    return sdc_aes_set_encrypt_key(key, user_key, key_len);
}

void sdc_aes_encrypt_block(const sdc_aes_key *key, const uint8_t in[16], uint8_t out[16]) {
#if defined(SDC_HAVE_AESNI)
    if (key->impl == SDC_AES_IMPL_AESNI) { sdc_aes_aesni_encrypt(key, in, out); return; }
#endif
#if defined(SDC_HAVE_ARMCE)
    if (key->impl == SDC_AES_IMPL_ARMCE) { sdc_aes_armce_encrypt(key, in, out); return; }
#endif
    sdc_aes_scalar_encrypt(key, in, out);
}

void sdc_aes_decrypt_block(const sdc_aes_key *key, const uint8_t in[16], uint8_t out[16]) {
#if defined(SDC_HAVE_AESNI)
    if (key->impl == SDC_AES_IMPL_AESNI) { sdc_aes_aesni_decrypt(key, in, out); return; }
#endif
#if defined(SDC_HAVE_ARMCE)
    if (key->impl == SDC_AES_IMPL_ARMCE) { sdc_aes_armce_decrypt(key, in, out); return; }
#endif
    sdc_aes_scalar_decrypt(key, in, out);
}

void sdc_aes_encrypt_blocks(const sdc_aes_key *key, const uint8_t *in, size_t nblocks, uint8_t *out) {
    if (nblocks == 0) return;
#if defined(SDC_HAVE_AESNI)
    if (key->impl == SDC_AES_IMPL_AESNI) { sdc_aes_aesni_encrypt_blocks(key, in, nblocks, out); return; }
#endif
#if defined(SDC_HAVE_ARMCE)
    if (key->impl == SDC_AES_IMPL_ARMCE) { sdc_aes_armce_encrypt_blocks(key, in, nblocks, out); return; }
#endif
    for (size_t i = 0; i < nblocks; i++)
        sdc_aes_scalar_encrypt(key, in + 16 * i, out + 16 * i);
}

/* ---------------- ops layer (for the generic block-cipher layer) ---------------- */

static int aes_set_encrypt_key_wrapper(sdc_block_cipher_ctx *ctx, const uint8_t *user_key) {
    return sdc_aes_set_encrypt_key((sdc_aes_key *)ctx->inner_state, user_key, ctx->ops->key_len);
}

static int aes_set_decrypt_key_wrapper(sdc_block_cipher_ctx *ctx, const uint8_t *user_key) {
    return sdc_aes_set_decrypt_key((sdc_aes_key *)ctx->inner_state, user_key, ctx->ops->key_len);
}

static void aes_encrypt_block_wrapper(const sdc_block_cipher_ctx *ctx,
                                      const uint8_t in[16], uint8_t out[16]) {
    sdc_aes_encrypt_block((const sdc_aes_key *)ctx->inner_state, in, out);
}

static void aes_decrypt_block_wrapper(const sdc_block_cipher_ctx *ctx,
                                      const uint8_t in[16], uint8_t out[16]) {
    sdc_aes_decrypt_block((const sdc_aes_key *)ctx->inner_state, in, out);
}

static void aes_encrypt_blocks_wrapper(const sdc_block_cipher_ctx *ctx,
                                       const uint8_t *in, size_t nblocks, uint8_t *out) {
    sdc_aes_encrypt_blocks((const sdc_aes_key *)ctx->inner_state, in, nblocks, out);
}

const sdc_block_cipher_ops_t sdc_aes128_ops = {
    aes_set_encrypt_key_wrapper, aes_set_decrypt_key_wrapper,
    aes_encrypt_block_wrapper, aes_decrypt_block_wrapper,
    aes_encrypt_blocks_wrapper, 16, "AES-128"
};

const sdc_block_cipher_ops_t sdc_aes192_ops = {
    aes_set_encrypt_key_wrapper, aes_set_decrypt_key_wrapper,
    aes_encrypt_block_wrapper, aes_decrypt_block_wrapper,
    aes_encrypt_blocks_wrapper, 24, "AES-192"
};

const sdc_block_cipher_ops_t sdc_aes256_ops = {
    aes_set_encrypt_key_wrapper, aes_set_decrypt_key_wrapper,
    aes_encrypt_block_wrapper, aes_decrypt_block_wrapper,
    aes_encrypt_blocks_wrapper, 32, "AES-256"
};

#endif /* SDC_ENABLE_AES */
