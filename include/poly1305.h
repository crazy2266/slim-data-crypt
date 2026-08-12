/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Poly1305 MAC functions.
 */

#ifndef SDC_POLY1305_H
#define SDC_POLY1305_H

#include <stdint.h>
#include <stddef.h>
#include "platform.h"
#include "config.h"

#if SDC_ENABLE_POLY1305

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
#if SDC_64BIT
    uint64_t r[3];
    uint64_t h[3];
    uint64_t pad[2];
#else
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
#endif
    uint8_t  buffer[16];
    size_t   leftover;
    uint8_t  is_final;
} sdc_poly1305_ctx;


void sdc_poly1305_init(sdc_poly1305_ctx *ctx, const uint8_t key[32]);
void sdc_poly1305_update(sdc_poly1305_ctx *ctx, const uint8_t *in, size_t len);
void sdc_poly1305_final(sdc_poly1305_ctx *ctx, uint8_t mac[16]);
void sdc_poly1305_mac(uint8_t mac[16], const uint8_t *in, size_t len, const uint8_t key[32]);

#ifdef __cplusplus
}
#endif

#endif /* SDC_ENABLE_POLY1305 */

#endif /* SDC_POLY1305_H */