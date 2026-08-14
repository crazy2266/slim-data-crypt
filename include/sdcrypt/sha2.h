/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * SHA2 hash functions.
 */

#ifndef SDC_SHA2_H
#define SDC_SHA2_H

#include <stdint.h>
#include <stddef.h>
#include "./config.h"

#ifdef __cplusplus
extern "C" {
#endif

#if SDC_ENABLE_SHA224 || SDC_ENABLE_SHA256

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buffer[64];
    size_t   len;
} sdc_sha256_ctx;

#if SDC_ENABLE_SHA224
/* SHA-224 */
void sdc_sha224_init(sdc_sha256_ctx *ctx);
void sdc_sha224_update(sdc_sha256_ctx *ctx, const uint8_t *data, size_t len);
void sdc_sha224_final(sdc_sha256_ctx *ctx, uint8_t out[28]);
void sdc_sha224_hash(uint8_t out[28], const uint8_t *in, size_t len);
#endif /* SDC_ENABLE_SHA224 */

#if SDC_ENABLE_SHA256
/* SHA-256 */
void sdc_sha256_init(sdc_sha256_ctx *ctx);
void sdc_sha256_update(sdc_sha256_ctx *ctx, const uint8_t *data, size_t len);
void sdc_sha256_final(sdc_sha256_ctx *ctx, uint8_t out[32]);
void sdc_sha256_hash(uint8_t out[32], const uint8_t *in, size_t len);
#endif /* SDC_ENABLE_SHA256 */

#endif /* SDC_ENABLE_SHA224 || SDC_ENABLE_SHA256 */

#if SDC_ENABLE_SHA384 || SDC_ENABLE_SHA512

typedef struct {
    uint64_t state[8];
    uint64_t count[2];
    uint8_t  buffer[128];
    size_t   len;
} sdc_sha512_ctx;

#if SDC_ENABLE_SHA384
/* SHA-384 */
void sdc_sha384_init(sdc_sha512_ctx *ctx);
void sdc_sha384_update(sdc_sha512_ctx *ctx, const uint8_t *data, size_t len);
void sdc_sha384_final(sdc_sha512_ctx *ctx, uint8_t out[48]);
void sdc_sha384_hash(uint8_t out[48], const uint8_t *in, size_t len);
#endif /* SDC_ENABLE_SHA384 */

#if SDC_ENABLE_SHA512
/* SHA-512 */
void sdc_sha512_init(sdc_sha512_ctx *ctx);
void sdc_sha512_update(sdc_sha512_ctx *ctx, const uint8_t *data, size_t len);
void sdc_sha512_final(sdc_sha512_ctx *ctx, uint8_t out[64]);
void sdc_sha512_hash(uint8_t out[64], const uint8_t *in, size_t len);
#endif /* SDC_ENABLE_SHA512 */

#endif /* SDC_ENABLE_SHA384 || SDC_ENABLE_SHA512 */

#ifdef __cplusplus
}
#endif

#endif /* SDC_SHA2_H */