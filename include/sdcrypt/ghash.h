/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * GHASH (GF(2^128), GCM polynomial x^128 + x^7 + x^2 + x + 1).
 *
 * Backend-dispatched (scalar / PCLMULQDQ / PMULL) and 8-block aggregated.
 */

#ifndef SDC_GHASH_H
#define SDC_GHASH_H

#include <stdint.h>
#include <stddef.h>
#include <sdcrypt/config.h>
#ifndef __cplusplus
#  include <stdalign.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if SDC_ENABLE_GCM

/* Opaque; large enough for any backend context. */
#define SDC_GHASH_CTX_BYTES 512
typedef struct {
    alignas(16) uint8_t opaque[SDC_GHASH_CTX_BYTES];
} sdc_ghash_ctx;

/* Initialize with subkey H (= E_K(0^128)). */
void sdc_ghash_init(sdc_ghash_ctx *ctx, const uint8_t H[16]);
/* Feed additional authenticated data (must precede the ciphertext). */
void sdc_ghash_aad(sdc_ghash_ctx *ctx, const uint8_t *aad, size_t len);
/* Feed ciphertext. */
void sdc_ghash_update(sdc_ghash_ctx *ctx, const uint8_t *data, size_t len);
/* Produce the 16-byte GHASH result. */
void sdc_ghash_final(sdc_ghash_ctx *ctx, uint8_t out[16]);

/* Name of the active GHASH backend: "scalar", "pclmul" or "pmull". */
const char *sdc_ghash_backend(void);

#endif /* SDC_ENABLE_GCM */

#ifdef __cplusplus
}
#endif

#endif /* SDC_GHASH_H */
