/*
 * SPDX-License-Identifier: MIT
 * Internal GHASH backend interface.
 */

#ifndef SDC_GHASH_IMPL_H
#define SDC_GHASH_IMPL_H

#include <sdcrypt/ghash.h>

typedef struct {
    void (*init)(void *ctx, const uint8_t H[16]);
    void (*aad)(void *ctx, const uint8_t *aad, size_t len);
    void (*update)(void *ctx, const uint8_t *data, size_t len);
    void (*final)(void *ctx, uint8_t out[16]);
} sdc_ghash_vtable;

extern const sdc_ghash_vtable sdc_ghash_scalar_vtable;

#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
extern const sdc_ghash_vtable sdc_ghash_pclmul_vtable;
#endif
#if defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))
extern const sdc_ghash_vtable sdc_ghash_pmull_vtable;
#endif

#endif /* SDC_GHASH_IMPL_H */
