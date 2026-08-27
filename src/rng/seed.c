/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * DBRG seed generator.
 */

#include <sdcrypt/rng.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/config.h>

static int default_seed_generator(uint8_t *seed, size_t len) {
#if SDC_ENABLE_SYSTEM_RNG
    return sdc_system_rng_ops.generate(NULL, seed, len);
#else
    return SDC_ERR_NOT_IMPLEMENTED;
#endif
}

static int (*g_seed_generator)(uint8_t *seed, size_t len) = default_seed_generator;

int sdc_rng_default_seed(uint8_t *seed, size_t len) {
    return default_seed_generator(seed, len);
}

int sdc_rng_get_seed(uint8_t *seed, size_t len) {
    return g_seed_generator(seed, len);
}

void sdc_rng_set_seed_generator(int (*generator)(uint8_t *seed, size_t len)) {
    if (generator) g_seed_generator = generator;
}

void sdc_rng_set_seed_generator_to_default(void) {
    g_seed_generator = default_seed_generator;
}