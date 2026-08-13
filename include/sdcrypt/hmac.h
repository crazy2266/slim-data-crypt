/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * HMAC-SHA256 functions.
 */

#ifndef SDC_HMAC_H
#define SDC_HMAC_H

#include <stdint.h>
#include <stddef.h>
#include "./sha2.h"
#include "./config.h"

#if SDC_ENABLE_HMAC

#if !SDC_ENABLE_SHA256
    #error "HMAC-SHA256 requires SHA256 support"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    sdc_sha256_ctx inner;
    sdc_sha256_ctx outer;
    uint8_t ipad[64];
    uint8_t opad[64];
} sdc_hmac_sha256_ctx;

void sdc_hmac_sha256_init(sdc_hmac_sha256_ctx *ctx, const uint8_t *key, size_t key_len);
void sdc_hmac_sha256_update(sdc_hmac_sha256_ctx *ctx, const uint8_t *data, size_t len);
void sdc_hmac_sha256_final(sdc_hmac_sha256_ctx *ctx, uint8_t out[32]);
void sdc_hmac_sha256(uint8_t out[32], const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len);

#ifdef __cplusplus
}
#endif

#endif /* SDC_ENABLE_HMAC */

#endif /* SDC_HMAC_H */