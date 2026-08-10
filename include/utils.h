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

typedef unsigned __int128 u128;

void sdc_secure_memzero(void *ptr, size_t len);
int sdc_secure_memcmp(const void *a, const void *b, size_t len);

static inline uint32_t load32_le(const uint8_t src[4]) {
    uint32_t result;
    memcpy(&result, src, sizeof(result));
    return result;
}

static inline void store32_le(uint8_t dst[4], uint32_t value) {
    memcpy(dst, &value, sizeof(value));
}

static inline uint64_t load64_le(const uint8_t src[8]) {
    uint64_t result;
    memcpy(&result, src, sizeof(result));
    return result;
}

static inline void store64_le(uint8_t dst[8], uint64_t value) {
    memcpy(dst, &value, sizeof(value));
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

static inline uint64_t is_nonzero64(uint64_t x) {
    return (x | (0ULL - x)) >> 63;
}

static inline uint64_t GTE128(u128 a, u128 b) {
    u128 ah = a >> 64;
    u128 bh = b >> 64;
    u128 al = a & 0xFFFFFFFFFFFFFFFFULL;
    u128 bl = b & 0xFFFFFFFFFFFFFFFFULL;

    u128 hgt = (bh - ah) >> 127;
    u128 lgt = (bl - al) >> 127;
    u128 heq = is_nonzero64(ah ^ bh) ^ 1;
    u128 leq = is_nonzero64(al ^ bl) ^ 1;
    uint64_t result = hgt | (heq & (lgt | leq));
    return result;
}

#endif /* SDC_UTILS_H */