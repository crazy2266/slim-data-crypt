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
#include <stdalign.h>
#include "./config.h"

#if defined(__ARM_NEON) || defined(__ARM_NEON__)
#  include <arm_neon.h>
#else
#  error "NEON support is required for this project."
#endif

#if SDC_ENABLE_CHACHA20 || SDC_ENABLE_XCHACHA20
typedef struct {
    uint32x4_t state1[16];        /* NEON 4-block parallel (SoA) */
    uint32_t state2[16];          /* Scalar 5th block (AoS) */
    alignas(16) uint8_t buf[320]; /* 5 blocks x 64 bytes */
    size_t buf_used;
} sdc_chacha20_ctx;
#endif

#if SDC_ENABLE_CHACHA20
void sdc_chacha20_init(sdc_chacha20_ctx *ctx, const uint8_t key[32],
                       const uint8_t nonce[12], uint32_t counter);
void sdc_chacha20_crypt(sdc_chacha20_ctx *ctx, const uint8_t *in,
                        uint8_t *out, size_t len);
#endif

#if SDC_ENABLE_XCHACHA20
void sdc_xchacha20_init(sdc_chacha20_ctx *ctx, const uint8_t key[32],
                        const uint8_t nonce[24], uint64_t counter);
void sdc_xchacha20_crypt(sdc_chacha20_ctx *ctx, const uint8_t *in,
                         uint8_t *out, size_t len);
#endif

#endif /* SDC_CHACHA20_H */
