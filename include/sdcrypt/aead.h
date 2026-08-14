/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * ChaCha20-Poly1305 (RFC 8439) and XChaCha20-Poly1305 AEAD cipher.
 */

#ifndef SDC_AEAD_H
#define SDC_AEAD_H

#include <stdint.h>
#include <stddef.h>
#include "./chacha20.h"
#include "./poly1305.h"
#include "./config.h"

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

/* ============================================================
   Public ctx for ChaCha20-Poly1305 and XChaCha20-Poly1305
   ============================================================ */
typedef struct {
    sdc_chacha20_ctx chacha;
    sdc_poly1305_ctx poly;
    uint64_t aad_len;
    uint64_t total_len;
    uint8_t verified;
} sdc_chacha20poly1305_ctx;

/* ============================================================
   XChaCha20-Poly1305 (24-byte nonce)
   ============================================================ */

#if SDC_ENABLE_XCHACHA20POLY1305_AEAD

/* Initialize */
void sdc_xchacha20poly1305_init(
    sdc_chacha20poly1305_ctx *ctx,
    const uint8_t key[32],
    const uint8_t nonce[24],
    const uint8_t *aad,
    size_t aad_len
);

/* Encrypt and compute tag */
void sdc_xchacha20poly1305_encrypt_update(
    sdc_chacha20poly1305_ctx *ctx,
    const uint8_t *in,
    uint8_t *out,
    size_t len
);

void sdc_xchacha20poly1305_encrypt_final(
    sdc_chacha20poly1305_ctx *ctx,
    uint8_t tag[16]
);

/* Authenticate and decrypt */
void sdc_xchacha20poly1305_auth_update(
    sdc_chacha20poly1305_ctx *ctx,
    const uint8_t *in,
    size_t len
);

int sdc_xchacha20poly1305_auth_final(
    sdc_chacha20poly1305_ctx *ctx,
    const uint8_t tag[16]
);

void sdc_xchacha20poly1305_decrypt_update(
    sdc_chacha20poly1305_ctx *ctx,
    const uint8_t *in,
    uint8_t *out,
    size_t len
);

void sdc_xchacha20poly1305_decrypt_final(
    sdc_chacha20poly1305_ctx *ctx
);

/* One-time interface */
void sdc_xchacha20poly1305_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[24],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    size_t msg_len,
    uint8_t *ciphertext,
    uint8_t tag[16]
);

int sdc_xchacha20poly1305_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[24],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ciphertext,
    size_t msg_len,
    const uint8_t tag[16],
    uint8_t *plaintext
);

#endif /* SDC_ENABLE_XCHACHA20POLY1305_AEAD */

/* ============================================================
   ChaCha20-Poly1305 (IETF, RFC 8439, 12-byte nonce)
   ============================================================ */

#if SDC_ENABLE_CHACHA20POLY1305_AEAD

/* Initialize */
void sdc_chacha20poly1305_init(
    sdc_chacha20poly1305_ctx *ctx,
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *aad,
    size_t aad_len
);

/* Encrypt and compute tag */
void sdc_chacha20poly1305_encrypt_update(
    sdc_chacha20poly1305_ctx *ctx,
    const uint8_t *in,
    uint8_t *out,
    size_t len
);

void sdc_chacha20poly1305_encrypt_final(
    sdc_chacha20poly1305_ctx *ctx,
    uint8_t tag[16]
);

/* Authenticate and decrypt */
void sdc_chacha20poly1305_auth_update(
    sdc_chacha20poly1305_ctx *ctx,
    const uint8_t *in,
    size_t len
);

int sdc_chacha20poly1305_auth_final(
    sdc_chacha20poly1305_ctx *ctx,
    const uint8_t tag[16]
);

void sdc_chacha20poly1305_decrypt_update(
    sdc_chacha20poly1305_ctx *ctx,
    const uint8_t *in,
    uint8_t *out,
    size_t len
);

void sdc_chacha20poly1305_decrypt_final(
    sdc_chacha20poly1305_ctx *ctx
);

/* One-time interface */
void sdc_chacha20poly1305_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    size_t msg_len,
    uint8_t *ciphertext,
    uint8_t tag[16]
);

int sdc_chacha20poly1305_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ciphertext,
    size_t msg_len,
    const uint8_t tag[16],
    uint8_t *plaintext
);

#endif /* SDC_ENABLE_CHACHA20POLY1305_AEAD */

#endif /* SDC_ENABLE_CHACHA20POLY1305_AEAD || SDC_ENABLE_XCHACHA20POLY1305_AEAD */

#endif /* SDC_AEAD_H */