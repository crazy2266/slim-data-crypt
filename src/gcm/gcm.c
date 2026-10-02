/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Generic GCM (NIST SP 800-38D), parameterized over a 128-bit block cipher.
 * GHASH is delegated to the sdc_ghash_* module (backend-dispatched).
 */

#include <string.h>
#include <sdcrypt/config.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/gcm.h>
#include <sdcrypt/ghash.h>
#include <sdcrypt/utils.h>

#if SDC_ENABLE_GCM

static void inc32(uint8_t ctr[16]) {
    for (int i = 15; i >= 12; i--) {
        if (++ctr[i] != 0) break;
    }
}

void sdc_gcm_init(sdc_gcm_ctx *ctx, sdc_gcm_block_fn enc, const void *key,
                  const uint8_t *iv, size_t iv_len) {
    sdc_gcm_init_ex(ctx, enc, NULL, key, iv, iv_len);
}

void sdc_gcm_init_ex(sdc_gcm_ctx *ctx, sdc_gcm_block_fn enc, sdc_gcm_blocks_fn enc_blocks,
                     const void *key, const uint8_t *iv, size_t iv_len) {
    uint8_t h[16];
    (void)iv_len;   /* 12-byte IV only */

    memset(ctx, 0, sizeof(*ctx));
    ctx->enc = enc;
    ctx->enc_blocks = enc_blocks;
    ctx->key = key;
    ctx->phase = 0;

    /* H = E_K(0^128) */
    {
        uint8_t zero[16] = {0};
        enc(key, h, zero);
    }
    sdc_ghash_init(&ctx->gh, h);

    /* J0 (12-byte IV only; other lengths are rejected by the caller). */
    memcpy(ctx->j0, iv, 12);
    ctx->j0[12] = 0; ctx->j0[13] = 0; ctx->j0[14] = 0; ctx->j0[15] = 1;
    memcpy(ctx->ctr, ctx->j0, 16);

    /* tag_mask = E_K(J0) */
    enc(key, ctx->tag_mask, ctx->j0);
}

void sdc_gcm_aad_update(sdc_gcm_ctx *ctx, const uint8_t *aad, size_t len) {
    if (ctx->phase != 0 || len == 0) return;
    ctx->aad_len += len;
    sdc_ghash_aad(&ctx->gh, aad, len);
}

void sdc_gcm_encrypt_update(sdc_gcm_ctx *ctx, const uint8_t *in, size_t len, uint8_t *out) {
    if (ctx->phase == 0) ctx->phase = 1;
    while (len > 0) {
        if (ctx->enc_blocks && ctx->ks_pos == 0 && len >= 64) {
            uint8_t ctrblk[64], ks[64], c[16];
            memcpy(c, ctx->ctr, 16);
            for (int i = 0; i < 4; i++) { inc32(c); memcpy(ctrblk + 16 * i, c, 16); }
            memcpy(ctx->ctr, c, 16);
            ctx->enc_blocks(ctx->key, ctrblk, 4, ks);
            for (int i = 0; i < 64; i++) out[i] = in[i] ^ ks[i];
            sdc_ghash_update(&ctx->gh, out, 64);
            ctx->msg_len += 64;
            in += 64; out += 64; len -= 64;
            continue;
        }
        if (ctx->ks_pos == 0) {
            inc32(ctx->ctr);
            ctx->enc(ctx->key, ctx->ks, ctx->ctr);
            ctx->ks_pos = 16;
        }
        size_t ks_off = 16 - ctx->ks_pos;
        size_t n = len;
        if (n > ctx->ks_pos) n = ctx->ks_pos;
        for (size_t i = 0; i < n; i++) out[i] = in[i] ^ ctx->ks[ks_off + i];
        sdc_ghash_update(&ctx->gh, out, n);
        ctx->ks_pos -= n;
        ctx->msg_len += n;
        in += n; out += n; len -= n;
    }
}

void sdc_gcm_encrypt_final(sdc_gcm_ctx *ctx, uint8_t tag[SDC_GCM_TAG_SIZE]) {
    uint8_t s[16];
    if (ctx->phase == 0) ctx->phase = 1;
    sdc_ghash_final(&ctx->gh, s);
    for (int i = 0; i < 16; i++) tag[i] = ctx->tag_mask[i] ^ s[i];
    sdc_secure_memzero(s, sizeof(s));
}

void sdc_gcm_decrypt_update(sdc_gcm_ctx *ctx, const uint8_t *in, size_t len, uint8_t *out) {
    if (ctx->phase == 0) ctx->phase = 1;
    while (len > 0) {
        if (ctx->enc_blocks && ctx->ks_pos == 0 && len >= 64) {
            uint8_t ctrblk[64], ks[64], c[16];
            memcpy(c, ctx->ctr, 16);
            for (int i = 0; i < 4; i++) { inc32(c); memcpy(ctrblk + 16 * i, c, 16); }
            memcpy(ctx->ctr, c, 16);
            ctx->enc_blocks(ctx->key, ctrblk, 4, ks);
            sdc_ghash_update(&ctx->gh, in, 64);
            for (int i = 0; i < 64; i++) out[i] = in[i] ^ ks[i];
            ctx->msg_len += 64;
            in += 64; out += 64; len -= 64;
            continue;
        }
        if (ctx->ks_pos == 0) {
            inc32(ctx->ctr);
            ctx->enc(ctx->key, ctx->ks, ctx->ctr);
            ctx->ks_pos = 16;
        }
        size_t ks_off = 16 - ctx->ks_pos;
        size_t n = len;
        if (n > ctx->ks_pos) n = ctx->ks_pos;
        sdc_ghash_update(&ctx->gh, in, n);
        for (size_t i = 0; i < n; i++) out[i] = in[i] ^ ctx->ks[ks_off + i];
        ctx->ks_pos -= n;
        ctx->msg_len += n;
        in += n; out += n; len -= n;
    }
}

int sdc_gcm_decrypt_final(sdc_gcm_ctx *ctx, const uint8_t tag[SDC_GCM_TAG_SIZE]) {
    uint8_t s[16], computed[16];
    int rc;
    if (ctx->phase == 0) ctx->phase = 1;
    sdc_ghash_final(&ctx->gh, s);
    for (int i = 0; i < 16; i++) computed[i] = ctx->tag_mask[i] ^ s[i];
    rc = sdc_secure_memcmp(computed, tag, 16) ? SDC_ERR_VERIFY_FAIL : SDC_ERR_OK;
    sdc_secure_memzero(s, sizeof(s));
    sdc_secure_memzero(computed, sizeof(computed));
    return rc;
}

void sdc_gcm_encrypt(sdc_gcm_block_fn enc, const void *key,
                     const uint8_t *iv, size_t iv_len,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *in, size_t len,
                     uint8_t *out, uint8_t tag[SDC_GCM_TAG_SIZE]) {
    sdc_gcm_ctx ctx;
    sdc_gcm_init(&ctx, enc, key, iv, iv_len);
    if (aad_len) sdc_gcm_aad_update(&ctx, aad, aad_len);
    if (len) sdc_gcm_encrypt_update(&ctx, in, len, out);
    sdc_gcm_encrypt_final(&ctx, tag);
    sdc_secure_memzero(&ctx, sizeof(ctx));
}

int sdc_gcm_decrypt(sdc_gcm_block_fn enc, const void *key,
                    const uint8_t *iv, size_t iv_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *in, size_t len,
                    const uint8_t tag[SDC_GCM_TAG_SIZE],
                    uint8_t *out) {
    sdc_gcm_ctx ctx;
    int rc;
    sdc_gcm_init(&ctx, enc, key, iv, iv_len);
    if (aad_len) sdc_gcm_aad_update(&ctx, aad, aad_len);
    if (len) sdc_gcm_decrypt_update(&ctx, in, len, out);
    rc = sdc_gcm_decrypt_final(&ctx, tag);
    sdc_secure_memzero(&ctx, sizeof(ctx));
    return rc;
}

#endif /* SDC_ENABLE_GCM */
