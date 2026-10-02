/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * AES-GCM convenience API.
 */

#include <sdcrypt/config.h>
#include <sdcrypt/aes.h>
#include <sdcrypt/gcm.h>
#include <sdcrypt/aes_gcm.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/utils.h>

#if SDC_ENABLE_AES_GCM

static void aeg_block(const void *key, uint8_t out[16], const uint8_t in[16]) {
    sdc_aes_encrypt_block((const sdc_aes_key *)key, in, out);
}

static void aeg_blocks(const void *key, const uint8_t *in, size_t n, uint8_t *out) {
    sdc_aes_encrypt_blocks((const sdc_aes_key *)key, in, n, out);
}

void sdc_aes_gcm_encrypt(const uint8_t *key, size_t key_len,
                         const uint8_t *iv, size_t iv_len,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *in, size_t len,
                         uint8_t *out, uint8_t tag[16]) {
    sdc_aes_key k;
    sdc_gcm_ctx ctx;
    sdc_aes_set_encrypt_key(&k, key, key_len);
    sdc_gcm_init_ex(&ctx, aeg_block, aeg_blocks, &k, iv, iv_len);
    if (aad_len) sdc_gcm_aad_update(&ctx, aad, aad_len);
    if (len) sdc_gcm_encrypt_update(&ctx, in, len, out);
    sdc_gcm_encrypt_final(&ctx, tag);
    sdc_secure_memzero(&k, sizeof(k));
    sdc_secure_memzero(&ctx, sizeof(ctx));
}

int sdc_aes_gcm_decrypt(const uint8_t *key, size_t key_len,
                        const uint8_t *iv, size_t iv_len,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *in, size_t len,
                        const uint8_t tag[16], uint8_t *out) {
    sdc_aes_key k;
    sdc_gcm_ctx ctx;
    int rc;
    sdc_aes_set_encrypt_key(&k, key, key_len);
    sdc_gcm_init_ex(&ctx, aeg_block, aeg_blocks, &k, iv, iv_len);
    if (aad_len) sdc_gcm_aad_update(&ctx, aad, aad_len);
    if (len) sdc_gcm_decrypt_update(&ctx, in, len, out);
    rc = sdc_gcm_decrypt_final(&ctx, tag);
    sdc_secure_memzero(&k, sizeof(k));
    sdc_secure_memzero(&ctx, sizeof(ctx));
    return rc;
}

#endif /* SDC_ENABLE_AES_GCM */
