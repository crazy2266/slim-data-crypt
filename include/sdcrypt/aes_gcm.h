/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * AES-GCM convenience API (uses bulk AES when the backend supports it).
 */

#ifndef SDC_AES_GCM_H
#define SDC_AES_GCM_H

#include <stdint.h>
#include <stddef.h>
#include <sdcrypt/config.h>

#ifdef __cplusplus
extern "C" {
#endif

#if SDC_ENABLE_AES_GCM

#define SDC_AES_GCM_KEY_MIN  16
#define SDC_AES_GCM_KEY_MAX  32
#define SDC_AES_GCM_NONCE    12
#define SDC_AES_GCM_TAG      16

void sdc_aes_gcm_encrypt(const uint8_t *key, size_t key_len,
                         const uint8_t *iv, size_t iv_len,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *in, size_t len,
                         uint8_t *out, uint8_t tag[SDC_AES_GCM_TAG]);

int sdc_aes_gcm_decrypt(const uint8_t *key, size_t key_len,
                        const uint8_t *iv, size_t iv_len,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *in, size_t len,
                        const uint8_t tag[SDC_AES_GCM_TAG],
                        uint8_t *out);

#endif /* SDC_ENABLE_AES_GCM */

#ifdef __cplusplus
}
#endif

#endif /* SDC_AES_GCM_H */
