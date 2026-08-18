/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * SM3 hash functions.
 */

#ifndef SDC_SM3_H
#define SDC_SM3_H

#include <stdint.h>
#include <stddef.h>
#include <sdcrypt/config.h>

#ifdef __cplusplus
extern "C" {
#endif

#if SDC_ENABLE_SM3
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buffer[64];
    size_t   len;
} sdc_sm3_ctx;

void sdc_sm3_init(sdc_sm3_ctx *ctx);
void sdc_sm3_update(sdc_sm3_ctx *ctx, const uint8_t *data, size_t len);
void sdc_sm3_final(sdc_sm3_ctx *ctx, uint8_t out[32]);
void sdc_sm3_hash(uint8_t out[32], const uint8_t *in, size_t len);
extern const sdc_hash_ops_t sdc_sm3_ops;
#endif /* SDC_ENABLE_SM3 */

#ifdef __cplusplus
}
#endif

#endif /* SDC_SM3_H */