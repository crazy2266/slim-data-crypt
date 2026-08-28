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
#include <sdcrypt/errcode.h>
#include <sdcrypt/config.h>

typedef struct sdc_rng_ops_t sdc_rng_ops_t;

typedef struct {
    const sdc_rng_ops_t *ops;
    uint8_t inner_state[SDC_RNG_STATE_MAX_SIZE];
} sdc_rng_ctx;

struct sdc_rng_ops_t {
    int (*init)(sdc_rng_ctx *ctx, const uint8_t *seed);
    int (*generate)(sdc_rng_ctx *ctx, uint8_t *out, size_t len);
    size_t seed_len;
};

static inline int sdc_rng_init(sdc_rng_ctx *ctx, const uint8_t *seed) {
    if (!ctx) return SDC_ERR_INVALID_PARAM;
    return ctx->ops->init(ctx, seed);
}

static inline int sdc_rng_generate(sdc_rng_ctx *ctx, uint8_t *out, size_t len) {
    if (!ctx || !out || len == 0) return SDC_ERR_INVALID_PARAM;
    return ctx->ops->generate(ctx, out, len);
}

static inline size_t sdc_rng_get_seed_len(const sdc_rng_ctx *ctx) {
    if (!ctx) return SDC_ERR_INVALID_PARAM;
    return ctx->ops->seed_len;
}

// Get seed by default rng.
int sdc_rng_default_seed(uint8_t *seed, size_t len);
// Get seed by custom rng. If user did not set seed generator, then use default rng.
int sdc_rng_get_seed(uint8_t *seed, size_t len);
#if SDC_SWAPPABLE_RNG_SEED
void sdc_rng_set_seed_generator(int (*generator)(uint8_t *seed, size_t len));
void sdc_rng_set_seed_generator_to_default(void);
#endif

#if SDC_ENABLE_SYSTEM_RNG
extern const sdc_rng_ops_t sdc_system_rng_ops;
#endif
#if SDC_ENABLE_CHACHA20_RNG
extern const sdc_rng_ops_t sdc_chacha20_rng_ops;
#endif

#endif /* SDC_RNG_H */
