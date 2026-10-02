/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * AES block cipher (FIPS-197), with ECB/CBC/CTR modes.
 * Runtime-dispatched to AES-NI / ARM Crypto Extensions when available.
 */

#ifndef SDC_AES_H
#define SDC_AES_H

#include <stdint.h>
#include <stddef.h>
#include <sdcrypt/config.h>
#ifndef __cplusplus
#  include <stdalign.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if SDC_ENABLE_AES

#define SDC_AES_BLOCK_SIZE   16
#define SDC_AES_MAX_ROUNDS   14
#define SDC_AES_MAX_RK_BYTES (16 * (SDC_AES_MAX_ROUNDS + 1))  /* 240 */

/* Backend implementations (selected at runtime by sdc_aes_init). */
#define SDC_AES_IMPL_SCALAR 0
#define SDC_AES_IMPL_AESNI  1
#define SDC_AES_IMPL_ARMCE  2

typedef struct {
    int     nr;                                   /* rounds: 10 / 12 / 14 */
    uint8_t impl;                                 /* SDC_AES_IMPL_* */
    alignas(16) uint8_t rk[SDC_AES_MAX_RK_BYTES]; /* portable round keys */
    alignas(16) uint8_t be[SDC_AES_MAX_RK_BYTES]; /* backend round keys  */
} sdc_aes_key;

/* Detect CPU features once (idempotent). */
void sdc_aes_init(void);

/* key_len must be 16, 24, or 32. */
int sdc_aes_set_encrypt_key(sdc_aes_key *key, const uint8_t *user_key, size_t key_len);
int sdc_aes_set_decrypt_key(sdc_aes_key *key, const uint8_t *user_key, size_t key_len);

void sdc_aes_encrypt_block(const sdc_aes_key *key, const uint8_t in[16], uint8_t out[16]);
void sdc_aes_decrypt_block(const sdc_aes_key *key, const uint8_t in[16], uint8_t out[16]);

/* Encrypt nblocks independent blocks (used by CTR and bulk ECB). */
void sdc_aes_encrypt_blocks(const sdc_aes_key *key, const uint8_t *in, size_t nblocks, uint8_t *out);

/* CBC (len must be a multiple of 16). */
void sdc_aes_cbc_encrypt(const sdc_aes_key *key, const uint8_t iv[16],
                         const uint8_t *in, size_t len, uint8_t *out);
void sdc_aes_cbc_decrypt(const sdc_aes_key *key, const uint8_t iv[16],
                         const uint8_t *in, size_t len, uint8_t *out);

/* CTR (12-byte nonce + 32-bit counter, big-endian). */
void sdc_aes_ctr(const sdc_aes_key *key, const uint8_t nonce[12],
                 const uint8_t *in, size_t len, uint8_t *out);

#endif /* SDC_ENABLE_AES */

#ifdef __cplusplus
}
#endif

#endif /* SDC_AES_H */
