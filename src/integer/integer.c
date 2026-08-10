/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Parts of this implementation are based on BearSSL's
 * Montgomery multiplication implementation.
 * BearSSL: https://bearssl.org/
 * Copyright (c) 2016 Thomas Pornin <thomas.pornin@nccgroup.com>
 * 
 * The implementation of integer arithmetic functions.
 */

#include "integer.h"
#include "utils.h"

typedef unsigned __int128 u128;

static uint64_t is_nonzero(uint64_t x) {
    return (x | (0ULL - x)) >> 63;
}

/* p1 = p1, p2 = p2 if ctl = 0
   p1 = p2, p2 = p1 if ctl = 1 */
static void ptr_cswap(uint64_t **p1, uint64_t **p2, uint64_t ctl) {
    uintptr_t mask = -(uintptr_t)(ctl & 1);
    uintptr_t val1 = (uintptr_t)*p1;
    uintptr_t val2 = (uintptr_t)*p2;
    uintptr_t diff = (val1 ^ val2) & mask;
    *p1 = (uint64_t *)(val1 ^ diff);
    *p2 = (uint64_t *)(val2 ^ diff);
}

void sdc_int_set_word(uint64_t *r, uint64_t val, size_t len) {
    r[0] = val;
    for (size_t i = 1; i < len; i++) {
        r[i] = 0;
    }
}

void sdc_int_copy(uint64_t *r, const uint64_t *a, size_t len) {
    while (len--) {
        r[len] = a[len];
    }
}

void sdc_int_ccopy(uint64_t *dst, const uint64_t *src, size_t len, uint64_t ctl) {
    uint64_t mask = 0ULL - ctl;
    size_t i;
    for (i = 0; i < len; i++) {
        dst[i] = (dst[i] & ~mask) | (src[i] & mask);
    }
}

void sdc_int_cswap(uint64_t *a, uint64_t *b, size_t len, uint64_t ctl) {
    uint64_t mask = 0ULL - ctl;
    size_t i;
    for (i = 0; i < len; i++) {
        uint64_t diff = (a[i] ^ b[i]) & mask;
        a[i] ^= diff;
        b[i] ^= diff;
    }
}

uint64_t sdc_int_eq_word(const uint64_t *a, uint64_t word, size_t len) {
    uint64_t result = 0;
    result = a[0] ^ word;
    for (size_t i = 1; i < len; i++) {
        result |= a[i];
    }
    return is_nonzero(result) ^ 1;
}

uint64_t sdc_int_is_odd(const uint64_t *a, size_t len) {
    (void)len;
    return a[0] & 1;
}

uint64_t sdc_int_is_even(const uint64_t *a, size_t len) {
    (void)len;
    return (a[0] & 1) ^ 1;
}

uint64_t sdc_int_lt(const uint64_t *a, const uint64_t *b, size_t len) {
    u128 borrow = 0;
    for (size_t i = 0; i < len; i++) {
        u128 diff = (u128)a[i] - (u128)b[i] - borrow;
        borrow = diff >> 127;
    }
    return (uint64_t)borrow;
}

uint64_t sdc_int_gte(const uint64_t *a, const uint64_t *b, size_t len) {
    return sdc_int_lt(a, b, len) ^ 1;
}

uint64_t sdc_int_eq(const uint64_t *a, const uint64_t *b, size_t len) {
    uint64_t diff = 0;
    while (len--) {
        diff |= a[len] ^ b[len];
    }
    return is_nonzero(diff) ^ 1;
}

uint64_t sdc_int_add(uint64_t *r, const uint64_t *a, const uint64_t *b, size_t len) {
    u128 tmp = 0;
    for (size_t i = 0; i < len; i++) {
        tmp += (u128)a[i] + b[i];
        r[i] = (uint64_t)tmp;
        tmp >>= 64;
    }
    return (uint64_t)tmp;
}

uint64_t sdc_int_sub(uint64_t *r, const uint64_t *a, const uint64_t *b, size_t len) {
    u128 borrow = 0;
    for (size_t i = 0; i < len; i++) {
        u128 diff = (u128)a[i] - (u128)b[i] - borrow;
        r[i] = (uint64_t)diff;
        borrow = (diff >> 64) & 1;
    }
    return (uint64_t)borrow;
}

uint64_t sdc_int_add_ctl(uint64_t *a, const uint64_t *b,
                       size_t len, uint64_t ctl) {
    uint64_t mask = 0ULL - ctl;
    u128 tmp = 0;
    for (size_t i = 0; i < len; i++) {
        uint64_t bi = b[i] & mask;
        tmp += (u128)a[i] + bi;
        a[i] = (uint64_t)tmp;
        tmp >>= 64;
    }
    return (uint64_t)tmp;
}

uint64_t sdc_int_sub_ctl(uint64_t *a, const uint64_t *b,
                       size_t len, uint64_t ctl) {
    uint64_t mask = 0ULL - ctl;
    u128 borrow = 0;
    for (size_t i = 0; i < len; i++) {
        uint64_t bi = b[i] & mask;
        u128 diff = (u128)a[i] - (u128)bi - borrow;
        a[i] = (uint64_t)diff;
        borrow = (diff >> 64) & 1;
    }
    return (uint64_t)borrow;
}

void sdc_int_mul(uint64_t *r, const uint64_t *a, const uint64_t *b, size_t len) {
	u128 tmp;
	size_t i, j;
	sdc_int_set_word(r, 0, len * 2);
	for (i = 0; i < len; i++) {
		tmp = 0;
		for (j = 0; j < len; j++) {
			tmp += (u128)r[i + j] + (u128)a[i] * (u128)b[j];
			r[i + j] = (uint64_t)tmp;
			tmp >>= 64;
		}
		r[i + len] = (uint64_t)tmp;
	}
}

uint64_t sdc_int_add_word(uint64_t *r, const uint64_t *a, uint64_t word, size_t len) {
    u128 tmp;
    uint64_t carry;
    size_t i;
    
    tmp = (u128)a[0] + word;
    r[0] = (uint64_t)tmp;
    carry = (uint64_t)(tmp >> 64);
    for (i = 1; i < len; i++) {
        tmp = (u128)a[i] + carry;
        r[i] = (uint64_t)tmp;
        carry = (uint64_t)(tmp >> 64);
    }
    return carry;
}

uint64_t sdc_int_sub_word(uint64_t *r, const uint64_t *a, uint64_t word, size_t len) {
    u128 tmp;
    uint64_t borrow;
    size_t i;

    tmp = (u128)a[0] - word;
    r[0] = (uint64_t)tmp;
    borrow = (tmp >> 64) & 1;
    for (i = 1; i < len; i++) {
        tmp = (u128)a[i] - borrow;
        r[i] = (uint64_t)tmp;
        borrow = (tmp >> 64) & 1;
    }
    return borrow;
}

void sdc_int_mul_word(uint64_t *r, const uint64_t *a, uint64_t b, size_t len) {
    u128 tmp;
    size_t i;
    tmp = 0;
    sdc_int_set_word(r, 0, len + 1);
    for (i = 0; i < len; i++) {
        tmp += (u128)r[i] + (u128)a[i] * b;
        r[i] = (uint64_t)tmp;
        tmp >>= 64;
    }
    r[len] = (uint64_t)tmp;
}

void sdc_int_to_mont(uint64_t *x, const uint64_t *n, size_t len) {
    size_t i, k;
    uint64_t c;
    k = len * 64;
    for (i = 0; i < k; i++) {
        c = sdc_int_add(x, x, x, len);
        sdc_int_sub_ctl(x, n, len, sdc_int_gte(x, n, len) | c);
    }
}

void sdc_int_mont_mul(uint64_t *r, const uint64_t *a, const uint64_t *b,
        const uint64_t *n, size_t len, uint64_t ninv) {
    size_t i, j;
    u128 dh, r1, r2, z, zh;
    uint64_t f, ai, t;

    sdc_int_set_word(r, 0, len);
    dh = 0;
    for (i = 0; i < len; i++) {
        ai = a[i];
        f = (r[0] + ai * b[0]) * ninv;
        r1 = r2 = 0;
        for (j = 0; j < len; j++) {
            z = (u128)r[j] + (u128)ai * b[j] + r1;
            r1 = z >> 64;
            t = (uint64_t)z;
            z = (u128)t + (u128)f * n[j] + r2;
            r2 = z >> 64;
            if (j != 0) r[j - 1] = (uint64_t)z;
        }
        zh = dh + r1 + r2;
        r[len - 1] = (uint64_t)zh;
        dh = zh >> 64;
    }
    sdc_int_sub_ctl(r, n, len, is_nonzero(dh) | sdc_int_gte(r, n, len));
}

void sdc_int_from_mont(uint64_t *x, const uint64_t *n, size_t len, uint64_t ninv) {
    size_t i, j;
    uint64_t f;
    u128 cc, z;

    for (i = 0; i < len; i++) {
        f = x[0] * ninv;
        cc = 0;
        for (j = 0; j < len; j++) {
            z = (u128)x[j] + (u128)f * n[j] + cc;
            cc = z >> 64;
            if (j != 0) x[j - 1] = (uint64_t)z;
        }
        x[len - 1] = (uint64_t)cc;
    }
    sdc_int_sub_ctl(x, n, len, sdc_int_gte(x, n, len));
}

void sdc_int_mont_modexp_u8(uint64_t *r, const uint64_t *a, const uint8_t *e, size_t elen,
            const uint64_t *n, uint64_t *tmp, size_t len, uint64_t ninv) {
    size_t i, bit_idx;
    uint64_t *buf1, *buf2, *buf3, *a_mont;
    uint64_t *res, *base, *scratch;
    uint64_t bit;
    
    buf1 = tmp;                   /* len words */
    buf2 = tmp + len;             /* len words */
    buf3 = tmp + len * 2;         /* len words */
    a_mont = tmp + len * 3;       /* len words */
    
    sdc_int_copy(a_mont, a, len);
    sdc_int_to_mont(a_mont, n, len);
    sdc_int_set_word(buf1, 1, len);
    sdc_int_to_mont(buf1, n, len);
    sdc_int_copy(buf2, a_mont, len);
    
    res = buf1;
    base = buf2;
    scratch = buf3;
    
    for (i = 0; i < elen; i++) {
        uint8_t byte = e[elen - 1 - i];
        for (bit_idx = 0; bit_idx < 8; bit_idx++) {
            bit = (byte >> bit_idx) & 1;
            sdc_int_mont_mul(scratch, res, base, n, len, ninv);
            ptr_cswap(&res, &scratch, bit);
            sdc_int_mont_mul(scratch, base, base, n, len, ninv);
            ptr_cswap(&base, &scratch, 1);
        }
    }
    sdc_int_from_mont(res, n, len, ninv);
    sdc_int_copy(r, res, len);
}

void sdc_int_mont_modexp_u64(uint64_t *r, const uint64_t *a, const uint64_t *e, size_t elen,
            const uint64_t *n, uint64_t *tmp, size_t len, uint64_t ninv) {
    size_t i, bit_idx;
    uint64_t *buf1, *buf2, *buf3, *a_mont;
    uint64_t *res, *base, *scratch;
    uint64_t bit;

    buf1 = tmp;                   /* len words */
    buf2 = tmp + len;             /* len words */
    buf3 = tmp + len * 2;         /* len words */
    a_mont = tmp + len * 3;       /* len words */

    sdc_int_copy(a_mont, a, len);
    sdc_int_to_mont(a_mont, n, len);
    sdc_int_set_word(buf1, 1, len);
    sdc_int_to_mont(buf1, n, len);
    sdc_int_copy(buf2, a_mont, len);

    res = buf1;
    base = buf2;
    scratch = buf3;

    for (i = 0; i < elen; i++) {
        uint64_t word = e[i];
        for (bit_idx = 0; bit_idx < 64; bit_idx++) {
            bit = (word >> bit_idx) & 1;
            sdc_int_mont_mul(scratch, res, base, n, len, ninv);
            ptr_cswap(&res, &scratch, bit);
            sdc_int_mont_mul(scratch, base, base, n, len, ninv);
            ptr_cswap(&base, &scratch, 1);
        }
    }
    sdc_int_from_mont(res, n, len, ninv);
    sdc_int_copy(r, res, len);
}

void sdc_int_mont_modexp_u64_vartime(uint64_t *r, const uint64_t *a, const uint64_t *e, size_t elen,
            const uint64_t *n, uint64_t *tmp, size_t len, uint64_t ninv) {
    size_t i, bit_idx;
    uint64_t *base, *scratch;
    uint64_t bit;

    base = tmp;           // uint64_t base[len];
    scratch = tmp + len;  // uint64_t scratch[len];

    sdc_int_copy(base, a, len);
    sdc_int_to_mont(base, n, len);
    sdc_int_set_word(r, 1, len);
    sdc_int_to_mont(r, n, len);

    for (i = 0; i < elen; i++) {
        uint64_t word = e[elen - 1 - i];
        for (bit_idx = 0; bit_idx < 64; bit_idx++) {
            bit = (word >> (63 - bit_idx)) & 1;
            /* r = r^2 mod n (用 scratch 做临时) */
            sdc_int_mont_mul(scratch, r, r, n, len, ninv);
            sdc_int_copy(r, scratch, len);
            if (bit) {
                /* r = r * base mod n */
                sdc_int_mont_mul(scratch, r, base, n, len, ninv);
                sdc_int_copy(r, scratch, len);
            }
        }
    }
    sdc_int_from_mont(r, n, len, ninv);
}

uint64_t sdc_int_calculate_ninv(uint64_t x) {
    uint64_t inv = 1;
    for (int i = 0; i < 6; i++) {
        inv = inv * (2 - x * inv);
    }
    return 0 - inv;
}

static u128 div128_64(u128 dividend, uint64_t divisor, uint64_t *rem) {
    u128 q = 0;
    u128 r = 0;
    u128 d = divisor;
    
    for (int i = 127; i >= 0; i--) {
        r <<= 1;
        r |= (dividend >> i) & 1;
        uint64_t cond = (r >= d);
        u128 mask = -(u128)cond;
        r -= d & mask;
        q |= (u128)cond << i;
    }
    *rem = (uint64_t)r;
    return q;
}

/* 大数除以单字：quo = a / word, rem = a % word */
void sdc_int_div_word(uint64_t *quo, const uint64_t *a, uint64_t word, size_t len, uint64_t *rem) {
    u128 remainder = 0;
    for (size_t i = len; i > 0; i--) {
        u128 val = (remainder << 64) | a[i - 1];
        uint64_t tmp;
        quo[i - 1] = (uint64_t)div128_64(val, word, &tmp);
        remainder = tmp;
    }
    if (rem) *rem = (uint64_t)remainder;
}

void sdc_int_frombytes_le(uint64_t *a, size_t len, const uint8_t *in) {
    for (size_t i = 0; i < len; i++) {
        uint64_t word = load64_le(in + i * 8);
        a[i] = word;
    }
}

void sdc_int_tobytes_le(const uint64_t *a, size_t len, uint8_t *out) {
    for (size_t i = 0; i < len; i++) {
        uint64_t word = a[i];
        store64_le(out + i * 8, word);
    }
}

void sdc_int_frombytes_be(uint64_t *a, size_t len, const uint8_t *in) {
    for (size_t i = 0; i < len; i++) {
        uint64_t word = load64_be(in + i * 8);
        a[len - 1 - i] = word;
    }
}

void sdc_int_tobytes_be(const uint64_t *a, size_t len, uint8_t *out) {
    for (size_t i = 0; i < len; i++) {
        uint64_t word = a[len - 1 - i];
        store64_be(out + i * 8, word);
    }
}

void sdc_int_modinv(uint64_t *d, const uint64_t *phi, uint64_t e, uint64_t *tmp, size_t len) {
    uint64_t *q, *r, *k_phi;
    uint64_t k = 0;
    uint64_t rem;

    q = tmp;                // uint64_t q[len];
    r = tmp + len;          // uint64_t r[len];
    k_phi = tmp + 2 * len;  // uint64_t k_phi[len + 1];

    sdc_int_div_word(q, phi, e, len, &rem);
    sdc_int_set_word(r, 0, len);
    r[0] = rem;

    for (uint64_t i = 1; i < e; i++) {
        if ((i * rem + 1) % e == 0) {
            k = i;
            break;
        }
    }

    sdc_int_mul_word(k_phi, phi, k, len);
    k_phi[0]++;  // We can directly add 1 because k*phi is always even.
    sdc_int_div_word(k_phi, k_phi, e, len + 1, NULL);
    sdc_int_copy(d, k_phi, len);
}