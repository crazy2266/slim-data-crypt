/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * AEAD (Authenticated Encryption with Associated Data)
 * ChaCha20-Poly1305 (RFC 8439) and XChaCha20-Poly1305.
 */

#include <string.h>
#include "aead.h"
#include "utils.h"
#include "config.h"

#if SDC_ENABLE_CHACHA20POLY1305_AEAD || SDC_ENABLE_XCHACHA20POLY1305_AEAD

#if SDC_ENABLE_CHACHA20POLY1305_AEAD
#  if !SDC_ENABLE_CHACHA20 || !SDC_ENABLE_POLY1305
#    error "ChaCha20 and Poly1305 must be enabled to use ChaCha20-Poly1305 AEAD"
#  endif
#endif
#if SDC_ENABLE_XCHACHA20POLY1305_AEAD
#  if !SDC_ENABLE_XCHACHA20 || !SDC_ENABLE_POLY1305
#    error "XChaCha20 and Poly1305 must be enabled to use XChaCha20-Poly1305 AEAD"
#  endif
#endif

static void poly1305_pad16(sdc_poly1305_ctx *ctx, uint64_t len) {
    static const uint8_t zero[16] = {0};
    size_t rem = (size_t)(len & 15u);
    if (rem != 0) {
        sdc_poly1305_update(ctx, zero, 16 - rem);
    }
}

/* ============================================================
   XChaCha20-Poly1305 (24-byte nonce)
   ============================================================ */

#if SDC_ENABLE_XCHACHA20POLY1305_AEAD

void sdc_xchacha20poly1305_init(sdc_chacha20poly1305_ctx *ctx,
                                const uint8_t key[32],
                                const uint8_t nonce[24],
                                const uint8_t *aad,
                                size_t aad_len) {
    uint8_t block0[64] = {0};
    uint8_t subkey[32];

    sdc_xchacha20_init(&ctx->chacha, key, nonce, 0);
    sdc_xchacha20_crypt(&ctx->chacha, block0, block0, 64);
    memcpy(subkey, block0, 32);
    sdc_secure_memzero(block0, sizeof(block0));
    sdc_xchacha20_init(&ctx->chacha, key, nonce, 1);
    sdc_poly1305_init(&ctx->poly, subkey);
    sdc_secure_memzero(subkey, sizeof(subkey));
    if (aad && aad_len) sdc_poly1305_update(&ctx->poly, aad, aad_len);
    poly1305_pad16(&ctx->poly, aad_len);

    ctx->aad_len = aad_len;
    ctx->total_len = 0;
    ctx->verified = 0;
}

void sdc_xchacha20poly1305_encrypt_update(sdc_chacha20poly1305_ctx *ctx,
                                          const uint8_t *in,
                                          uint8_t *out,
                                          size_t len) {
    if (len == 0) return;
    sdc_xchacha20_crypt(&ctx->chacha, in, out, len);
    sdc_poly1305_update(&ctx->poly, out, len);
    ctx->total_len += len;
}

void sdc_xchacha20poly1305_encrypt_final(sdc_chacha20poly1305_ctx *ctx,
                                         uint8_t tag[16]) {
    poly1305_pad16(&ctx->poly, ctx->total_len);

    uint8_t len_buf[16] = {0};
    uint64_t aad_len = ctx->aad_len;
    uint64_t msg_len = ctx->total_len;

    for (int i = 0; i < 8; i++) {
        len_buf[i]     = (uint8_t)(aad_len & 0xff);
        aad_len >>= 8;
        len_buf[i + 8] = (uint8_t)(msg_len & 0xff);
        msg_len >>= 8;
    }
    sdc_poly1305_update(&ctx->poly, len_buf, 16);
    sdc_poly1305_final(&ctx->poly, tag);
    sdc_secure_memzero(ctx, sizeof(sdc_chacha20poly1305_ctx));
}

void sdc_xchacha20poly1305_auth_update(sdc_chacha20poly1305_ctx *ctx,
                                       const uint8_t *in,
                                       size_t len) {
    if (len == 0) return;
    sdc_poly1305_update(&ctx->poly, in, len);
    ctx->total_len += len;
}

int sdc_xchacha20poly1305_auth_final(sdc_chacha20poly1305_ctx *ctx,
                                     const uint8_t tag[16]) {
    poly1305_pad16(&ctx->poly, ctx->total_len);

    uint8_t expected[16];
    uint8_t len_buf[16] = {0};
    uint64_t aad_len = ctx->aad_len;
    uint64_t msg_len = ctx->total_len;

    for (int i = 0; i < 8; i++) {
        len_buf[i]     = (uint8_t)(aad_len & 0xff);
        aad_len >>= 8;
        len_buf[i + 8] = (uint8_t)(msg_len & 0xff);
        msg_len >>= 8;
    }
    sdc_poly1305_update(&ctx->poly, len_buf, 16);
    sdc_poly1305_final(&ctx->poly, expected);

    ctx->verified = (sdc_secure_memcmp(tag, expected, 16) == 0) ? 1 : 0;
    return ctx->verified ? 0 : -1;
}

void sdc_xchacha20poly1305_decrypt_update(sdc_chacha20poly1305_ctx *ctx,
                                          const uint8_t *in,
                                          uint8_t *out,
                                          size_t len) {
    if (!ctx->verified || len == 0) return;
    sdc_xchacha20_crypt(&ctx->chacha, in, out, len);
}

void sdc_xchacha20poly1305_decrypt_final(sdc_chacha20poly1305_ctx *ctx) {
    sdc_secure_memzero(ctx, sizeof(sdc_chacha20poly1305_ctx));
}

void sdc_xchacha20poly1305_encrypt(const uint8_t key[32],
                                   const uint8_t nonce[24],
                                   const uint8_t *aad,
                                   size_t aad_len,
                                   const uint8_t *plaintext,
                                   size_t msg_len,
                                   uint8_t *ciphertext,
                                   uint8_t tag[16]) {
    sdc_chacha20poly1305_ctx ctx;
    sdc_xchacha20poly1305_init(&ctx, key, nonce, aad, aad_len);
    sdc_xchacha20poly1305_encrypt_update(&ctx, plaintext, ciphertext, msg_len);
    sdc_xchacha20poly1305_encrypt_final(&ctx, tag);
}

int sdc_xchacha20poly1305_decrypt(const uint8_t key[32],
                                  const uint8_t nonce[24],
                                  const uint8_t *aad,
                                  size_t aad_len,
                                  const uint8_t *ciphertext,
                                  size_t msg_len,
                                  const uint8_t tag[16],
                                  uint8_t *plaintext) {
    sdc_chacha20poly1305_ctx ctx;
    sdc_xchacha20poly1305_init(&ctx, key, nonce, aad, aad_len);
    sdc_xchacha20poly1305_auth_update(&ctx, ciphertext, msg_len);
    int ret = sdc_xchacha20poly1305_auth_final(&ctx, tag);
    if (ret == 0) sdc_xchacha20poly1305_decrypt_update(&ctx, ciphertext, plaintext, msg_len);
    sdc_xchacha20poly1305_decrypt_final(&ctx);
    return ret;
}

#endif /* SDC_ENABLE_XCHACHA20POLY1305_AEAD */

/* ============================================================
   ChaCha20-Poly1305 (IETF, RFC 8439, 12-byte nonce)
   ============================================================ */

#if SDC_ENABLE_CHACHA20POLY1305_AEAD

void sdc_chacha20poly1305_init(sdc_chacha20poly1305_ctx *ctx,
                               const uint8_t key[32],
                               const uint8_t nonce[12],
                               const uint8_t *aad,
                               size_t aad_len) {
    uint8_t block0[64] = {0};
    uint8_t subkey[32];

    sdc_chacha20_init(&ctx->chacha, key, nonce, 0);
    sdc_chacha20_crypt(&ctx->chacha, block0, block0, 64);
    memcpy(subkey, block0, 32);
    sdc_secure_memzero(block0, sizeof(block0));
    sdc_chacha20_init(&ctx->chacha, key, nonce, 1);
    sdc_poly1305_init(&ctx->poly, subkey);
    sdc_secure_memzero(subkey, sizeof(subkey));
    if (aad && aad_len) sdc_poly1305_update(&ctx->poly, aad, aad_len);
    poly1305_pad16(&ctx->poly, aad_len);

    ctx->aad_len = aad_len;
    ctx->total_len = 0;
    ctx->verified = 0;
}

void sdc_chacha20poly1305_encrypt_update(sdc_chacha20poly1305_ctx *ctx,
                                         const uint8_t *in,
                                         uint8_t *out,
                                         size_t len) {
    if (len == 0) return;
    sdc_chacha20_crypt(&ctx->chacha, in, out, len);
    sdc_poly1305_update(&ctx->poly, out, len);
    ctx->total_len += len;
}

void sdc_chacha20poly1305_encrypt_final(sdc_chacha20poly1305_ctx *ctx,
                                         uint8_t tag[16]) {
    poly1305_pad16(&ctx->poly, ctx->total_len);

    uint8_t len_buf[16] = {0};
    uint64_t aad_len = ctx->aad_len;
    uint64_t msg_len = ctx->total_len;

    for (int i = 0; i < 8; i++) {
        len_buf[i]     = (uint8_t)(aad_len & 0xff);
        aad_len >>= 8;
        len_buf[i + 8] = (uint8_t)(msg_len & 0xff);
        msg_len >>= 8;
    }
    sdc_poly1305_update(&ctx->poly, len_buf, 16);
    sdc_poly1305_final(&ctx->poly, tag);
    sdc_secure_memzero(ctx, sizeof(sdc_chacha20poly1305_ctx));
}

void sdc_chacha20poly1305_auth_update(sdc_chacha20poly1305_ctx *ctx,
                                       const uint8_t *in,
                                       size_t len) {
    if (len == 0) return;
    sdc_poly1305_update(&ctx->poly, in, len);
    ctx->total_len += len;
}

int sdc_chacha20poly1305_auth_final(sdc_chacha20poly1305_ctx *ctx,
                                     const uint8_t tag[16]) {
    poly1305_pad16(&ctx->poly, ctx->total_len);

    uint8_t expected[16];
    uint8_t len_buf[16] = {0};
    uint64_t aad_len = ctx->aad_len;
    uint64_t msg_len = ctx->total_len;

    for (int i = 0; i < 8; i++) {
        len_buf[i]     = (uint8_t)(aad_len & 0xff);
        aad_len >>= 8;
        len_buf[i + 8] = (uint8_t)(msg_len & 0xff);
        msg_len >>= 8;
    }
    sdc_poly1305_update(&ctx->poly, len_buf, 16);
    sdc_poly1305_final(&ctx->poly, expected);

    ctx->verified = (sdc_secure_memcmp(tag, expected, 16) == 0) ? 1 : 0;
    return ctx->verified ? 0 : -1;
}

void sdc_chacha20poly1305_decrypt_update(sdc_chacha20poly1305_ctx *ctx,
                                          const uint8_t *in,
                                          uint8_t *out,
                                          size_t len) {
    if (!ctx->verified || len == 0) return;
    sdc_chacha20_crypt(&ctx->chacha, in, out, len);
}

void sdc_chacha20poly1305_decrypt_final(sdc_chacha20poly1305_ctx *ctx) {
    sdc_secure_memzero(ctx, sizeof(sdc_chacha20poly1305_ctx));
}

void sdc_chacha20poly1305_encrypt(const uint8_t key[32],
                                   const uint8_t nonce[12],
                                   const uint8_t *aad,
                                   size_t aad_len,
                                   const uint8_t *plaintext,
                                   size_t msg_len,
                                   uint8_t *ciphertext,
                                   uint8_t tag[16]) {
    sdc_chacha20poly1305_ctx ctx;
    sdc_chacha20poly1305_init(&ctx, key, nonce, aad, aad_len);
    sdc_chacha20poly1305_encrypt_update(&ctx, plaintext, ciphertext, msg_len);
    sdc_chacha20poly1305_encrypt_final(&ctx, tag);
}

int sdc_chacha20poly1305_decrypt(const uint8_t key[32],
                                  const uint8_t nonce[12],
                                  const uint8_t *aad,
                                  size_t aad_len,
                                  const uint8_t *ciphertext,
                                  size_t msg_len,
                                  const uint8_t tag[16],
                                  uint8_t *plaintext) {
    sdc_chacha20poly1305_ctx ctx;
    sdc_chacha20poly1305_init(&ctx, key, nonce, aad, aad_len);
    sdc_chacha20poly1305_auth_update(&ctx, ciphertext, msg_len);
    int ret = sdc_chacha20poly1305_auth_final(&ctx, tag);
    if (ret == 0) sdc_chacha20poly1305_decrypt_update(&ctx, ciphertext, plaintext, msg_len);
    sdc_chacha20poly1305_decrypt_final(&ctx);
    return ret;
}

#endif /* SDC_ENABLE_CHACHA20POLY1305_AEAD */

#endif /* SDC_ENABLE_CHACHA20POLY1305_AEAD || SDC_ENABLE_XCHACHA20POLY1305_AEAD */
