/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * XChaCha20 cipher - 5-block parallel (4 NEON + 1 scalar)
 */

#ifndef SDC_XCHACHA20_H
#define SDC_XCHACHA20_H

#include <stdint.h>
#include <stddef.h>
#include <stdalign.h>

#if defined(__ARM_NEON) || defined(__ARM_NEON__)
#  include <arm_neon.h>
#else
#  error "NEON support is required for this project."
#endif

typedef struct {
    uint32x4_t state1[16];     /* NEON 4-block parallel (SoA) */
    uint32_t state2[16];     /* Scalar 5th block (AoS) */
    alignas(16) uint8_t buf[320]; /* 5 blocks x 64 bytes */
    size_t buf_used;
} sdc_xchacha20_ctx;

void sdc_xchacha20_init(sdc_xchacha20_ctx *ctx, const uint8_t key[32],
                        const uint8_t nonce[24], uint64_t counter);
void sdc_xchacha20_crypt(sdc_xchacha20_ctx *ctx, const uint8_t *in,
                         uint8_t *out, size_t len);

#endif
