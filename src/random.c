/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * A simple system random number generation function.
 */

#include "random.h"
#include <stdio.h>

int sdc_random_bytes(uint8_t *out, size_t len) {
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp) return -1;
    size_t n = fread(out, 1, len, fp);
    fclose(fp);
    return (n == len) ? 0 : -1;
}