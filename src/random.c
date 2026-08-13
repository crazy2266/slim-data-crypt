/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * A simple system random number generation function.
 */

#include <stdio.h>
#include <sdcrypt/random.h>
#include <sdcrypt/errcode.h>

int sdc_random_bytes(uint8_t *out, size_t len) {
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp) return SDC_ERR_RANDOM_FAIL;
    size_t n = fread(out, 1, len, fp);
    fclose(fp);
    return (n == len) ? SDC_ERR_OK : SDC_ERR_RANDOM_FAIL;
}