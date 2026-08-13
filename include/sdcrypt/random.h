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

// return SDC_ERR_OK on success, SDC_ERR_RANDOM_FAIL on error
int sdc_random_bytes(uint8_t *out, size_t len);

#endif /* SDC_RANDOM_H */