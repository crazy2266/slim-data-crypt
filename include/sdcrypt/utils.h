/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Some helper functions.
 */

#ifndef SDC_UTILS_H
#define SDC_UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sdcrypt/platform.h>

// Securely memset a buffer to 0.
void sdc_secure_memzero(void *ptr, size_t len);
// return 0 if a == b, non-zero if a != b.
int sdc_secure_memcmp(const void *a, const void *b, size_t len);

/* ================ load/store functions ================ */

static inline uint32_t load32_le(const uint8_t in[4]) {
    uint32_t result;
    result = (uint32_t)in[0];
    result |= (uint32_t)in[1] << 8;
    result |= (uint32_t)in[2] << 16;
    result |= (uint32_t)in[3] << 24;
    return result;
}

static inline void store32_le(uint8_t out[4], uint32_t in) {
    out[0] = (uint8_t)in;
    out[1] = (uint8_t)(in >> 8);
    out[2] = (uint8_t)(in >> 16);
    out[3] = (uint8_t)(in >> 24);
}

static inline uint64_t load64_le(const uint8_t in[8]) {
    uint64_t result;
    result = (uint64_t)in[0];
    result |= (uint64_t)in[1] << 8;
    result |= (uint64_t)in[2] << 16;
    result |= (uint64_t)in[3] << 24;
    result |= (uint64_t)in[4] << 32;
    result |= (uint64_t)in[5] << 40;
    result |= (uint64_t)in[6] << 48;
    result |= (uint64_t)in[7] << 56;
    return result;
}

static inline void store64_le(uint8_t out[8], uint64_t in) {
    out[0] = (uint8_t)in;
    out[1] = (uint8_t)(in >> 8);
    out[2] = (uint8_t)(in >> 16);
    out[3] = (uint8_t)(in >> 24);
    out[4] = (uint8_t)(in >> 32);
    out[5] = (uint8_t)(in >> 40);
    out[6] = (uint8_t)(in >> 48);
    out[7] = (uint8_t)(in >> 56);
}

static inline uint32_t load32_be(const uint8_t in[4]) {
    uint32_t result;
    result = (uint32_t)in[3];
    result |= (uint32_t)in[2] << 8;
    result |= (uint32_t)in[1] << 16;
    result |= (uint32_t)in[0] << 24;
    return result;
}

static inline void store32_be(uint8_t out[4], uint32_t in) {
    out[3] = (uint8_t)in;
    out[2] = (uint8_t)(in >> 8);
    out[1] = (uint8_t)(in >> 16);
    out[0] = (uint8_t)(in >> 24);
}

static inline uint64_t load64_be(const uint8_t in[8]) {
    uint64_t result;
    result = (uint64_t)in[7];
    result |= (uint64_t)in[6] << 8;
    result |= (uint64_t)in[5] << 16;
    result |= (uint64_t)in[4] << 24;
    result |= (uint64_t)in[3] << 32;
    result |= (uint64_t)in[2] << 40;
    result |= (uint64_t)in[1] << 48;
    result |= (uint64_t)in[0] << 56;
    return result;
}

static inline void store64_be(uint8_t out[8], uint64_t in) {
    out[7] = (uint8_t)in;
    out[6] = (uint8_t)(in >> 8);
    out[5] = (uint8_t)(in >> 16);
    out[4] = (uint8_t)(in >> 24);
    out[3] = (uint8_t)(in >> 32);
    out[2] = (uint8_t)(in >> 40);
    out[1] = (uint8_t)(in >> 48);
    out[0] = (uint8_t)(in >> 56);
}

#if SDC_64BIT
#  define load_word_le load64_le
#  define load_word_be load64_be
#  define store_word_le store64_le
#  define store_word_be store64_be
#elif SDC_32BIT
#  define load_word_le load32_le
#  define load_word_be load32_be
#  define store_word_le store32_le
#  define store_word_be store32_be
#endif

#endif /* SDC_UTILS_H */