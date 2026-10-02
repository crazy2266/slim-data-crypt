/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * SM4-GCM AEAD, built on the generic GCM core.
 */

#ifndef SDC_SM4_GCM_H
#define SDC_SM4_GCM_H

#include <stdint.h>
#include <stddef.h>
#include <sdcrypt/config.h>
#include <sdcrypt/sm4.h>
#include <sdcrypt/gcm.h>

#ifdef __cplusplus
extern "C" {
#endif

#if SDC_ENABLE_SM4_GCM

#define SDC_SM4_GCM_KEY_SIZE  16
#define SDC_SM4_GCM_NONCE_SIZE 12
#define SDC_SM4_GCM_TAG_SIZE  16

void sdc_sm4_gcm_encrypt(const uint8_t key[16], const uint8_t nonce[12],
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *in, size_t len,
                         uint8_t *out, uint8_t tag[16]);

int sdc_sm4_gcm_decrypt(const uint8_t key[16], const uint8_t nonce[12],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *in, size_t len,
                        const uint8_t tag[16], uint8_t *out);

#endif /* SDC_ENABLE_SM4_GCM */

#ifdef __cplusplus
}
#endif

#endif /* SDC_SM4_GCM_H */
