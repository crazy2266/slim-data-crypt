/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * ChaCha20 and XChaCha20 cipher functions.
 */

#ifndef SDC_CHACHA20_H
#define SDC_CHACHA20_H

#include <stdint.h>
#include <stddef.h>
#include <sdcrypt/config.h>
#ifndef __cplusplus
#  include <stdalign.h>
#endif
#if defined(__ARM_NEON) || defined(__ARM_NEON__)
#  include <arm_neon.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if SDC_ENABLE_CHACHA20 || SDC_ENABLE_XCHACHA20
typedef struct {
#if defined(__ARM_NEON) || defined(__ARM_NEON__)
    uint32x4_t state1[16];        /* NEON 4-block parallel (SoA) */
    uint32_t state2[16];          /* Scalar 5th block (AoS) */
    alignas(16) uint8_t buf[320]; /* 5 blocks x 64 bytes */
#else
    uint32_t state[16];
    uint8_t buf[64];
#endif
    size_t buf_used;
} sdc_chacha20_ctx;
#endif

#if SDC_ENABLE_CHACHA20
void sdc_chacha20_init(sdc_chacha20_ctx *ctx, const uint8_t key[32],
                       const uint8_t nonce[12], uint32_t counter);
void sdc_chacha20_crypt(sdc_chacha20_ctx *ctx, const uint8_t *in,
                        uint8_t *out, size_t len);
#endif /* SDC_ENABLE_CHACHA20 */

#if SDC_ENABLE_CHACHA20RAW
void sdc_chacha20raw_init(sdc_chacha20_ctx *ctx, const uint8_t key[32],
                          const uint8_t nonce[8], uint64_t counter);
void sdc_chacha20raw_crypt(sdc_chacha20_ctx *ctx, const uint8_t *in,
                           uint8_t *out, size_t len);
#endif /* SDC_ENABLE_CHACHA20RAW */

#if SDC_ENABLE_XCHACHA20
void sdc_xchacha20_init(sdc_chacha20_ctx *ctx, const uint8_t key[32],
                        const uint8_t nonce[24], uint64_t counter);
void sdc_xchacha20_crypt(sdc_chacha20_ctx *ctx, const uint8_t *in,
                         uint8_t *out, size_t len);
#endif /* SDC_ENABLE_XCHACHA20 */

#ifdef __cplusplus
}
#endif

#endif /* SDC_CHACHA20_H */