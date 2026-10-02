/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Generic GCM (NIST SP 800-38D).
 *
 * GCM is parameterized over a 128-bit block cipher (single-block encrypt).
 * This lets AES-GCM and SM4-GCM share the same GCM/GHASH core.
 */

#ifndef SDC_GCM_H
#define SDC_GCM_H

#include <stdint.h>
#include <stddef.h>
#include <sdcrypt/config.h>

#ifdef __cplusplus
extern "C" {
#endif

#if SDC_ENABLE_GCM

#define SDC_GCM_BLOCK_SIZE 16
#define SDC_GCM_TAG_SIZE   16

/*
 * Block-cipher single-block encryptor.
 *   key  : pointer to the cipher key context
 *   out  : 16-byte output
 *   in   : 16-byte input
 */
typedef void (*sdc_gcm_block_fn)(const void *key, uint8_t out[16], const uint8_t in[16]);

/*
 * Optional bulk block encryptor: encrypts nblocks independent 16-byte blocks.
 * When supplied, GCM uses it for the CTR keystream (much faster on AES-NI/CE).
 */
typedef void (*sdc_gcm_blocks_fn)(const void *key, const uint8_t *in, size_t nblocks, uint8_t *out);

#include <sdcrypt/ghash.h>

/* Incremental context. */
typedef struct {
    sdc_gcm_block_fn enc;
    sdc_gcm_blocks_fn enc_blocks;   /* optional; NULL = per-block */
    const void *key;
    sdc_ghash_ctx gh;       /* GHASH state (backend-dispatched) */
    uint8_t  j0[16];        /* initial counter block J0 */
    uint8_t  ctr[16];       /* running counter (inc32 per block) */
    uint8_t  tag_mask[16];  /* E_K(J0) */
    uint64_t aad_len;       /* total AAD bytes */
    uint64_t msg_len;       /* total message bytes */
    uint8_t  ks[16];        /* current keystream block */
    size_t   ks_pos;        /* bytes left in ks (0 => need new block) */
    int      phase;         /* 0 = AAD, 1 = message */
} sdc_gcm_ctx;

/* Initialize with IV (any length). */
void sdc_gcm_init(sdc_gcm_ctx *ctx, sdc_gcm_block_fn enc, const void *key,
                  const uint8_t *iv, size_t iv_len);

/* As sdc_gcm_init, but also supplies a bulk block encryptor (may be NULL). */
void sdc_gcm_init_ex(sdc_gcm_ctx *ctx, sdc_gcm_block_fn enc, sdc_gcm_blocks_fn enc_blocks,
                     const void *key, const uint8_t *iv, size_t iv_len);

/* Feed additional authenticated data. */
void sdc_gcm_aad_update(sdc_gcm_ctx *ctx, const uint8_t *aad, size_t len);

/* Encrypt in place / out of place; out may equal in. */
void sdc_gcm_encrypt_update(sdc_gcm_ctx *ctx, const uint8_t *in, size_t len, uint8_t *out);
/* Produce the tag. */
void sdc_gcm_encrypt_final(sdc_gcm_ctx *ctx, uint8_t tag[SDC_GCM_TAG_SIZE]);

/* Authenticate ciphertext (for decryption). */
void sdc_gcm_decrypt_update(sdc_gcm_ctx *ctx, const uint8_t *in, size_t len, uint8_t *out);
/* Verify tag. Returns SDC_ERR_OK or SDC_ERR_VERIFY_FAIL. */
int sdc_gcm_decrypt_final(sdc_gcm_ctx *ctx, const uint8_t tag[SDC_GCM_TAG_SIZE]);

/* One-shot helpers. */
void sdc_gcm_encrypt(sdc_gcm_block_fn enc, const void *key,
                     const uint8_t *iv, size_t iv_len,
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *in, size_t len,
                     uint8_t *out, uint8_t tag[SDC_GCM_TAG_SIZE]);

int sdc_gcm_decrypt(sdc_gcm_block_fn enc, const void *key,
                    const uint8_t *iv, size_t iv_len,
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *in, size_t len,
                    const uint8_t tag[SDC_GCM_TAG_SIZE],
                    uint8_t *out);

#endif /* SDC_ENABLE_GCM */

#ifdef __cplusplus
}
#endif

#endif /* SDC_GCM_H */
