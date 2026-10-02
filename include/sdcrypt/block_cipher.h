/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Block-cipher operation table (vtable), in the same spirit as
 * sdc_hash_ops_t / sdc_rng_ops_t.
 *
 * A concrete cipher implementation exports a global const ops instance and
 * stores its key state inside sdc_block_cipher_ctx.inner_state.
 */

#ifndef SDC_BLOCK_CIPHER_H
#define SDC_BLOCK_CIPHER_H

#include <stdint.h>
#include <stddef.h>
#include <sdcrypt/config.h>
#ifndef __cplusplus
#  include <stdalign.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SDC_BLOCK_CIPHER_BLOCK_SIZE      16
#define SDC_BLOCK_CIPHER_STATE_MAX_SIZE 512

typedef struct sdc_block_cipher_ops_t sdc_block_cipher_ops_t;

typedef struct {
    const sdc_block_cipher_ops_t *ops;
    alignas(8) uint8_t inner_state[SDC_BLOCK_CIPHER_STATE_MAX_SIZE];
} sdc_block_cipher_ctx;

struct sdc_block_cipher_ops_t {
    int  (*set_encrypt_key)(sdc_block_cipher_ctx *ctx, const uint8_t *user_key);
    int  (*set_decrypt_key)(sdc_block_cipher_ctx *ctx, const uint8_t *user_key);
    void (*encrypt_block)(const sdc_block_cipher_ctx *ctx,
                          const uint8_t in[16], uint8_t out[16]);
    void (*decrypt_block)(const sdc_block_cipher_ctx *ctx,
                          const uint8_t in[16], uint8_t out[16]);
    void (*encrypt_blocks)(const sdc_block_cipher_ctx *ctx,
                           const uint8_t *in, size_t nblocks, uint8_t *out);
    size_t key_len;         /* expected key size in bytes */
    const char *name;
};

/* Initialize a context with a backend (ops must not be NULL). */
static inline void sdc_block_cipher_init(sdc_block_cipher_ctx *ctx,
                                         const sdc_block_cipher_ops_t *ops) {
    if (ctx) ctx->ops = ops;
}

/* Expected key size (bytes) of a backend, or 0 if ops is NULL. */
static inline size_t sdc_block_cipher_get_key_len(const sdc_block_cipher_ops_t *ops) {
    return ops ? ops->key_len : 0;
}

/* Generic CTR (12-byte nonce + 32-bit big-endian counter). */
void sdc_block_cipher_ctr(const sdc_block_cipher_ctx *ctx, const uint8_t nonce[12],
                          const uint8_t *in, size_t len, uint8_t *out);

/* Generic CBC (len must be a multiple of 16). */
void sdc_block_cipher_cbc_encrypt(const sdc_block_cipher_ctx *ctx, const uint8_t iv[16],
                                  const uint8_t *in, size_t len, uint8_t *out);
void sdc_block_cipher_cbc_decrypt(const sdc_block_cipher_ctx *ctx, const uint8_t iv[16],
                                  const uint8_t *in, size_t len, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SDC_BLOCK_CIPHER_H */
