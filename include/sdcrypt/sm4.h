/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * SM4 block cipher (GB/T 32907-2016).
 */

#ifndef SDC_SM4_H
#define SDC_SM4_H

#include <stdint.h>
#include <stddef.h>
#include <sdcrypt/config.h>

#ifdef __cplusplus
extern "C" {
#endif

#if SDC_ENABLE_SM4

#define SDC_SM4_BLOCK_SIZE  16
#define SDC_SM4_KEY_SIZE    16

typedef struct {
    uint32_t rk[32];    // round keys
} sdc_sm4_key;

// Set encryption key.
int sdc_sm4_set_encrypt_key(sdc_sm4_key *key, const uint8_t user_key[SDC_SM4_KEY_SIZE]);
// Set decryption key (round keys in reverse order).
int sdc_sm4_set_decrypt_key(sdc_sm4_key *key, const uint8_t user_key[SDC_SM4_KEY_SIZE]);

// Encrypt one block (ECB).
void sdc_sm4_encrypt_block(const sdc_sm4_key *key, const uint8_t in[SDC_SM4_BLOCK_SIZE],
                           uint8_t out[SDC_SM4_BLOCK_SIZE]);
// Decrypt one block (ECB).
void sdc_sm4_decrypt_block(const sdc_sm4_key *key, const uint8_t in[SDC_SM4_BLOCK_SIZE],
                           uint8_t out[SDC_SM4_BLOCK_SIZE]);

// Encrypt multiple blocks.
void sdc_sm4_encrypt_blocks(const sdc_sm4_key *key, const uint8_t *in, size_t nblocks,
                            uint8_t *out);

// CTR mode (12-byte nonce, 32-bit counter).
void sdc_sm4_ctr(const sdc_sm4_key *key, const uint8_t nonce[12],
                 const uint8_t *in, size_t len, uint8_t *out);

#endif /* SDC_ENABLE_SM4 */

#ifdef __cplusplus
}
#endif

#endif /* SDC_SM4_H */
