/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Wang Yi <godspeed_china@yeah.net>
 * Ported to slim-data-crypt by crazy2266.
 * 
 * WyHash 32-bit hash function.
 * Oringinal address: https://github.com/wangyi-fudan/wyhash/blob/master/wyhash32.h
 */

#include <stdint.h>
#include <sdcrypt/utils.h>

#define _wyr32 load32_le
static inline uint32_t _wyr24(const uint8_t *p, uint32_t k) {
    return (((uint32_t)p[0]) << 16) | (((uint32_t)p[k >> 1]) << 8) | p[k - 1];
}

static inline void _wymix32(uint32_t *A,  uint32_t *B){
    uint64_t c = *A ^ 0x53c5ca59u;
    c *= *B ^ 0x74743c1bu;
    *A = (uint32_t)c;
    *B = (uint32_t)(c >> 32);
}

// This version is vulnerable when used with a few bad seeds, which should be skipped beforehand:
// 0x429dacdd, 0xd637dbf3
static inline uint32_t wyhash32(const void *key, uint64_t len, uint32_t seed) {
    const uint8_t *p = (const uint8_t *)key; uint64_t i = len;
    uint32_t see1 = (uint32_t)len; seed ^= (uint32_t)(len >> 32); _wymix32(&seed, &see1);
    for (; i > 8; i -= 8, p += 8) { seed ^= _wyr32(p); see1 ^= _wyr32(p + 4); _wymix32(&seed, &see1); }
    if (i >= 4) { seed ^= _wyr32(p); see1 ^= _wyr32(p + i - 4); } else if (i) seed ^= _wyr24(p, (uint32_t)i);
    _wymix32(&seed, &see1); _wymix32(&seed, &see1); return seed ^ see1;
}