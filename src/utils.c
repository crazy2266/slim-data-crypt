/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Some helper functions.
 */

#include <sdcrypt/utils.h>

void sdc_secure_memzero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}

int sdc_secure_memcmp(const void *a, const void *b, size_t len) {
    const volatile uint8_t *pa = (const volatile uint8_t *)a;
    const volatile uint8_t *pb = (const volatile uint8_t *)b;
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= pa[i] ^ pb[i];
    }
    return (int)diff;
}