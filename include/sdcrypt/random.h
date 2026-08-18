/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Random number generation functions.
 */

#ifndef SDC_RANDOM_H
#define SDC_RANDOM_H

#include <stdint.h>
#include <stddef.h>
#include <sdcrypt/config.h>

#if SDC_SWAPPABLE_RANDOM_RNG
typedef int (*sdc_random_rng_t)(uint8_t *out, size_t len);
void sdc_random_set_rng(sdc_random_rng_t rng);
void sdc_random_set_rng_to_default(void);
#endif

// return SDC_ERR_OK on success, SDC_ERR_RANDOM_FAIL on error
int sdc_random_bytes(uint8_t *out, size_t len);

#endif /* SDC_RANDOM_H */