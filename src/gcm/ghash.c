/*
 * SPDX-License-Identifier: MIT
 * GHASH dispatch (runtime CPU selection).
 */

#include <sdcrypt/config.h>
#include "ghash_impl.h"
#include "../cpu.h"

#if SDC_ENABLE_GCM

static const sdc_ghash_vtable *g_vt = 0;

static const sdc_ghash_vtable *resolve_vt(void) {
    const sdc_cpu_features *f = sdc_cpu_get();
#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
    if (f->pclmul) return &sdc_ghash_pclmul_vtable;
#endif
#if defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))
    if (f->pclmul) return &sdc_ghash_pmull_vtable;
#endif
    (void)f;
    return &sdc_ghash_scalar_vtable;
}

void sdc_ghash_init(sdc_ghash_ctx *ctx, const uint8_t H[16]) {
    if (!g_vt) g_vt = resolve_vt();
    g_vt->init(ctx->opaque, H);
}

void sdc_ghash_aad(sdc_ghash_ctx *ctx, const uint8_t *aad, size_t len) {
    g_vt->aad(ctx->opaque, aad, len);
}

void sdc_ghash_update(sdc_ghash_ctx *ctx, const uint8_t *data, size_t len) {
    g_vt->update(ctx->opaque, data, len);
}

void sdc_ghash_final(sdc_ghash_ctx *ctx, uint8_t out[16]) {
    g_vt->final(ctx->opaque, out);
}

const char *sdc_ghash_backend(void) {
    if (!g_vt) g_vt = resolve_vt();
#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
    if (g_vt == &sdc_ghash_pclmul_vtable) return "pclmul";
#endif
#if defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))
    if (g_vt == &sdc_ghash_pmull_vtable) return "pmull";
#endif
    return "scalar";
}

#endif /* SDC_ENABLE_GCM */
