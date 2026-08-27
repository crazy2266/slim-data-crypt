/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * RNG table definition.
 */

#ifndef SDC_RNG_H
#define SDC_RNG_H

#include <stdint.h>
#include <stddef.h>
#include <sdcrypt/config.h>

typedef struct sdc_rng_ops_t sdc_rng_ops_t;

typedef struct {
    const sdc_rng_ops_t *ops;
    uint8_t inner_state[SDC_RNG_STATE_MAX_SIZE];
} sdc_rng_ctx;

struct sdc_rng_ops_t {
    int (*init)(sdc_rng_ctx *ctx, const uint8_t *seed, size_t seed_len);
    int (*generate)(sdc_rng_ctx *ctx, uint8_t *out, size_t len);
};

static inline int sdc_rng_init(sdc_rng_ctx *ctx, const uint8_t *seed, size_t seed_len) {
    return ctx->ops->init(ctx, seed, seed_len);
}

static inline int sdc_rng_generate(sdc_rng_ctx *ctx, uint8_t *out, size_t len) {
    return ctx->ops->generate(ctx, out, len);
}

#if SDC_ENABLE_SYSTEM_RNG
extern const sdc_rng_ops_t sdc_system_rng_ops;
#endif

#if SDC_ENABLE_CHACHA20_RNG
extern const sdc_rng_ops_t sdc_chacha20_rng_ops;
#endif

#endif /* SDC_RNG_H */
