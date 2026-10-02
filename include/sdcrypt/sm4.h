/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * SM4 block cipher (GB/T 32907-2016).
 *
 * The native API uses sdc_sm4_ctx (table-driven).  A table-free
 * constant-time backend is available through the block-cipher ops layer:
 * select sdc_sm4_ct_ops with sdc_block_cipher_init().
 */

#ifndef SDC_SM4_H
#define SDC_SM4_H

#include <stdint.h>
#include <stddef.h>
#include <sdcrypt/config.h>
#include <sdcrypt/block_cipher.h>

#ifdef __cplusplus
extern "C" {
#endif

#if SDC_ENABLE_SM4

#define SDC_SM4_BLOCK_SIZE  16
#define SDC_SM4_KEY_SIZE    16

typedef struct {
    uint32_t rk[32];    /* round keys */
} sdc_sm4_ctx;

/* Set encryption key. */
int sdc_sm4_set_encrypt_key(sdc_sm4_ctx *ctx, const uint8_t user_key[SDC_SM4_KEY_SIZE]);
/* Set decryption key (round keys in reverse order). */
int sdc_sm4_set_decrypt_key(sdc_sm4_ctx *ctx, const uint8_t user_key[SDC_SM4_KEY_SIZE]);

/* Encrypt one block (ECB). */
void sdc_sm4_encrypt_block(const sdc_sm4_ctx *ctx, const uint8_t in[SDC_SM4_BLOCK_SIZE],
                           uint8_t out[SDC_SM4_BLOCK_SIZE]);
/* Decrypt one block (ECB). */
void sdc_sm4_decrypt_block(const sdc_sm4_ctx *ctx, const uint8_t in[SDC_SM4_BLOCK_SIZE],
                           uint8_t out[SDC_SM4_BLOCK_SIZE]);

/* Encrypt multiple blocks. */
void sdc_sm4_encrypt_blocks(const sdc_sm4_ctx *ctx, const uint8_t *in, size_t nblocks,
                            uint8_t *out);

/* Backend operation tables (for the generic block-cipher layer). */
extern const sdc_block_cipher_ops_t sdc_sm4_table_ops;
#if SDC_ENABLE_SM4_CT
extern const sdc_block_cipher_ops_t sdc_sm4_ct_ops;
#endif

#endif /* SDC_ENABLE_SM4 */

#ifdef __cplusplus
}
#endif

#endif /* SDC_SM4_H */
