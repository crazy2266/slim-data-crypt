/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * SM4-GCM AEAD, built on the generic GCM core.
 */

#include <sdcrypt/config.h>
#include <sdcrypt/sm4.h>
#include <sdcrypt/sm4_gcm.h>
#include <sdcrypt/gcm.h>
#include <sdcrypt/utils.h>

#if SDC_ENABLE_SM4_GCM

#if !SDC_ENABLE_SM4
#error "SM4 must be enabled for SM4-GCM (set SDC_ENABLE_SM4 to 1)"
#endif
#if !SDC_ENABLE_GCM
#error "GCM must be enabled for SM4-GCM (set SDC_ENABLE_GCM to 1)"
#endif

static void sm4_gcm_block(const void *key, uint8_t out[16], const uint8_t in[16]) {
    sdc_sm4_encrypt_block((const sdc_sm4_key *)key, in, out);
}

void sdc_sm4_gcm_encrypt(const uint8_t key[16], const uint8_t nonce[12],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *in, size_t len,
                         uint8_t *out, uint8_t tag[16]) {
    sdc_sm4_key k;
    sdc_sm4_set_encrypt_key(&k, key);
    sdc_gcm_encrypt(sm4_gcm_block, &k, nonce, 12, aad, aad_len, in, len, out, tag);
    sdc_secure_memzero(&k, sizeof(k));
}

int sdc_sm4_gcm_decrypt(const uint8_t key[16], const uint8_t nonce[12],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *in, size_t len,
                        const uint8_t tag[16], uint8_t *out) {
    sdc_sm4_key k;
    int rc;
    sdc_sm4_set_encrypt_key(&k, key);
    rc = sdc_gcm_decrypt(sm4_gcm_block, &k, nonce, 12, aad, aad_len, in, len, tag, out);
    sdc_secure_memzero(&k, sizeof(k));
    return rc;
}

#endif /* SDC_ENABLE_SM4_GCM */
