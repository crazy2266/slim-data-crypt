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

#include "config.h"
#include "integer.h"
#include "utils.h"

#if SDC_ENABLE_INTEGER

/* ================ Inner helper functions ================ */

static inline sdc_word_t is_nonzero_word(sdc_word_t x) {
    return (x | ((sdc_word_t)0 - x)) >> (SDC_WORD_BITS - 1);
}

static inline sdc_word_t GTE_DWORD(sdc_dword_t a, sdc_dword_t b) {
    // Get the high word and low word of a and b.
    sdc_dword_t ah = a >> SDC_WORD_BITS;
    sdc_dword_t bh = b >> SDC_WORD_BITS;
    sdc_dword_t al = a & SDC_WORD_MASK;
    sdc_dword_t bl = b & SDC_WORD_MASK;
    // Compare the high word and low word by subtraction.
    sdc_dword_t hgt = (bh - ah) >> (SDC_DWORD_BITS - 1);
    sdc_dword_t lgt = (bl - al) >> (SDC_DWORD_BITS - 1);
    sdc_dword_t heq = is_nonzero_word(ah ^ bh) ^ 1;
    sdc_dword_t leq = is_nonzero_word(al ^ bl) ^ 1;
    sdc_word_t result = hgt | (heq & (lgt | leq));
    return result;
}

/* p1 = p1, p2 = p2 if ctl = 0
   p1 = p2, p2 = p1 if ctl = 1 */
static void ptr_cswap(sdc_word_t **p1, sdc_word_t **p2, sdc_word_t ctl) {
    uintptr_t mask = -(uintptr_t)(ctl & 1);
    uintptr_t val1 = (uintptr_t)*p1;
    uintptr_t val2 = (uintptr_t)*p2;
    uintptr_t diff = (val1 ^ val2) & mask;
    *p1 = (sdc_word_t *)(val1 ^ diff);
    *p2 = (sdc_word_t *)(val2 ^ diff);
}

static inline sdc_word_t gen_mask_word(sdc_word_t boolval) {
    return (sdc_word_t)0 - boolval;
}

static inline sdc_word_t select_word(sdc_word_t mask, sdc_word_t a, sdc_word_t b) {
    return (a & mask) | (b & ~mask);
}

static inline sdc_word_t gte_word_mask(sdc_word_t a, sdc_word_t b) {
    sdc_dword_t diff = (sdc_dword_t)a - (sdc_dword_t)b;
    return ~(sdc_word_t)(diff >> SDC_WORD_BITS);
}

/* ================ Public functions ================ */

void sdc_int_set_word(sdc_word_t *r, sdc_word_t val, size_t len) {
    r[0] = val;
    for (size_t i = 1; i < len; i++) {
        r[i] = 0;
    }
}

void sdc_int_copy(sdc_word_t *r, const sdc_word_t *a, size_t len) {
    while (len--) {
        r[len] = a[len];
    }
}

void sdc_int_ccopy(sdc_word_t *dst, const sdc_word_t *src, size_t len, sdc_word_t ctl) {
    sdc_word_t mask = 0ULL - ctl;
    size_t i;
    for (i = 0; i < len; i++) {
        dst[i] = (dst[i] & ~mask) | (src[i] & mask);
    }
}

void sdc_int_cswap(sdc_word_t *a, sdc_word_t *b, size_t len, sdc_word_t ctl) {
    sdc_word_t mask = 0ULL - ctl;
    size_t i;
    for (i = 0; i < len; i++) {
        sdc_word_t diff = (a[i] ^ b[i]) & mask;
        a[i] ^= diff;
        b[i] ^= diff;
    }
}

sdc_word_t sdc_int_eq_word(const sdc_word_t *a, sdc_word_t word, size_t len) {
    sdc_word_t result = 0;
    result = a[0] ^ word;
    for (size_t i = 1; i < len; i++) {
        result |= a[i];
    }
    return is_nonzero_word(result) ^ 1;
}

sdc_word_t sdc_int_is_odd(const sdc_word_t *a, size_t len) {
    (void)len;
    return a[0] & 1;
}

sdc_word_t sdc_int_is_even(const sdc_word_t *a, size_t len) {
    (void)len;
    return (a[0] & 1) ^ 1;
}

sdc_word_t sdc_int_lt(const sdc_word_t *a, const sdc_word_t *b, size_t len) {
    sdc_dword_t borrow = 0;
    for (size_t i = 0; i < len; i++) {
        sdc_dword_t diff = (sdc_dword_t)a[i] - (sdc_dword_t)b[i] - borrow;
        borrow = diff >> (SDC_DWORD_BITS - 1);
    }
    return (sdc_word_t)borrow;
}

sdc_word_t sdc_int_gte(const sdc_word_t *a, const sdc_word_t *b, size_t len) {
    return sdc_int_lt(a, b, len) ^ 1;
}

sdc_word_t sdc_int_eq(const sdc_word_t *a, const sdc_word_t *b, size_t len) {
    sdc_word_t diff = 0;
    while (len--) {
        diff |= a[len] ^ b[len];
    }
    return is_nonzero_word(diff) ^ 1;
}

sdc_word_t sdc_int_add(sdc_word_t *r, const sdc_word_t *a, const sdc_word_t *b, size_t len) {
    sdc_dword_t tmp = 0;
    for (size_t i = 0; i < len; i++) {
        tmp += (sdc_dword_t)a[i] + b[i];
        r[i] = (sdc_word_t)tmp;
        tmp >>= SDC_WORD_BITS;
    }
    return (sdc_word_t)tmp;
}

sdc_word_t sdc_int_sub(sdc_word_t *r, const sdc_word_t *a, const sdc_word_t *b, size_t len) {
    sdc_dword_t borrow = 0;
    for (size_t i = 0; i < len; i++) {
        sdc_dword_t diff = (sdc_dword_t)a[i] - (sdc_dword_t)b[i] - borrow;
        r[i] = (sdc_word_t)diff;
        borrow = diff >> (SDC_DWORD_BITS - 1);
    }
    return (sdc_word_t)borrow;
}

sdc_word_t sdc_int_add_ctl(sdc_word_t *a, const sdc_word_t *b,
                       size_t len, sdc_word_t ctl) {
    sdc_word_t mask = 0ULL - ctl;
    sdc_dword_t tmp = 0;
    for (size_t i = 0; i < len; i++) {
        sdc_word_t bi = b[i] & mask;
        tmp += (sdc_dword_t)a[i] + bi;
        a[i] = (sdc_word_t)tmp;
        tmp >>= SDC_WORD_BITS;
    }
    return (sdc_word_t)tmp;
}

sdc_word_t sdc_int_sub_ctl(sdc_word_t *a, const sdc_word_t *b,
                       size_t len, sdc_word_t ctl) {
    sdc_word_t mask = 0ULL - ctl;
    sdc_dword_t borrow = 0;
    for (size_t i = 0; i < len; i++) {
        sdc_word_t bi = b[i] & mask;
        sdc_dword_t diff = (sdc_dword_t)a[i] - (sdc_dword_t)bi - borrow;
        a[i] = (sdc_word_t)diff;
        borrow = diff >> (SDC_DWORD_BITS - 1);
    }
    return (sdc_word_t)borrow;
}

void sdc_int_mul(sdc_word_t *r, const sdc_word_t *a, const sdc_word_t *b, size_t len) {
	sdc_dword_t tmp;
	size_t i, j;
	sdc_int_set_word(r, 0, len * 2);
	for (i = 0; i < len; i++) {
		tmp = 0;
		for (j = 0; j < len; j++) {
			tmp += (sdc_dword_t)r[i + j] + (sdc_dword_t)a[i] * (sdc_dword_t)b[j];
			r[i + j] = (sdc_word_t)tmp;
			tmp >>= SDC_WORD_BITS;
		}
		r[i + len] = (sdc_word_t)tmp;
	}
}

sdc_word_t sdc_int_add_word(sdc_word_t *r, const sdc_word_t *a, sdc_word_t word, size_t len) {
    sdc_dword_t tmp;
    sdc_word_t carry;
    size_t i;
    
    tmp = (sdc_dword_t)a[0] + word;
    r[0] = (sdc_word_t)tmp;
    carry = (sdc_word_t)(tmp >> SDC_WORD_BITS);
    for (i = 1; i < len; i++) {
        tmp = (sdc_dword_t)a[i] + carry;
        r[i] = (sdc_word_t)tmp;
        carry = (sdc_word_t)(tmp >> SDC_WORD_BITS);
    }
    return carry;
}

sdc_word_t sdc_int_sub_word(sdc_word_t *r, const sdc_word_t *a, sdc_word_t word, size_t len) {
    sdc_dword_t tmp;
    sdc_word_t borrow;
    size_t i;

    tmp = (sdc_dword_t)a[0] - word;
    r[0] = (sdc_word_t)tmp;
    borrow = (tmp >> SDC_WORD_BITS) & 1;
    for (i = 1; i < len; i++) {
        tmp = (sdc_dword_t)a[i] - borrow;
        r[i] = (sdc_word_t)tmp;
        borrow = (tmp >> SDC_WORD_BITS) & 1;
    }
    return borrow;
}

void sdc_int_shr(sdc_word_t *x, size_t bits, size_t len) {
    if (bits == 0) return;
    if (bits >= SDC_WORD_BITS * len) {
        sdc_int_set_word(x, 0, len);
        return;
    }
    size_t shr_limb = bits / SDC_WORD_BITS;
    size_t shr_bits = bits % SDC_WORD_BITS;
    size_t i;
    
    if (shr_bits == 0) {
        for (i = 0; i < len - shr_limb; i++) {
            x[i] = x[i + shr_limb];
        }
    } else {
        for (i = 0; i < len - shr_limb - 1; i++) {
            x[i] = (x[i + shr_limb] >> shr_bits) | 
                   (x[i + shr_limb + 1] << (SDC_WORD_BITS - shr_bits));
        }
        x[len - shr_limb - 1] = x[len - 1] >> shr_bits;
    }
    for (i = len - shr_limb; i < len; i++) {
        x[i] = 0;
    }
}

size_t sdc_int_ctz(const sdc_word_t *x, size_t len) {
    if (len == 0) return 0;
    size_t i;
    for (i = 0; i < len; i++) {
        if (x[i] != 0) return i * SDC_WORD_BITS + sdc_word_ctz(x[i]);
    }
    return len * SDC_WORD_BITS;
}

void sdc_int_mul_word(sdc_word_t *r, const sdc_word_t *a, sdc_word_t b, size_t len) {
    sdc_dword_t tmp;
    size_t i;
    tmp = 0;
    sdc_int_set_word(r, 0, len + 1);
    for (i = 0; i < len; i++) {
        tmp += (sdc_dword_t)r[i] + (sdc_dword_t)a[i] * b;
        r[i] = (sdc_word_t)tmp;
        tmp >>= SDC_WORD_BITS;
    }
    r[len] = (sdc_word_t)tmp;
}

void sdc_int_to_mont(sdc_word_t *x, const sdc_word_t *n, size_t len) {
    size_t i, k;
    sdc_word_t c;
    k = len * SDC_WORD_BITS;
    for (i = 0; i < k; i++) {
        c = sdc_int_add(x, x, x, len);
        sdc_int_sub_ctl(x, n, len, sdc_int_gte(x, n, len) | c);
    }
}

void sdc_int_mont_mul(sdc_word_t *r, const sdc_word_t *a, const sdc_word_t *b,
        const sdc_word_t *n, size_t len, sdc_word_t ninv) {
    size_t i, j;
    sdc_dword_t dh, r1, r2, z, zh;
    sdc_word_t f, ai, t;

    sdc_int_set_word(r, 0, len);
    dh = 0;
    for (i = 0; i < len; i++) {
        ai = a[i];
        f = (r[0] + ai * b[0]) * ninv;
        r1 = r2 = 0;
        for (j = 0; j < len; j++) {
            z = (sdc_dword_t)r[j] + (sdc_dword_t)ai * b[j] + r1;
            r1 = z >> SDC_WORD_BITS;
            t = (sdc_word_t)z;
            z = (sdc_dword_t)t + (sdc_dword_t)f * n[j] + r2;
            r2 = z >> SDC_WORD_BITS;
            if (j != 0) r[j - 1] = (sdc_word_t)z;
        }
        zh = dh + r1 + r2;
        r[len - 1] = (sdc_word_t)zh;
        dh = zh >> SDC_WORD_BITS;
    }
    sdc_int_sub_ctl(r, n, len, is_nonzero_word(dh) | sdc_int_gte(r, n, len));
}

void sdc_int_from_mont(sdc_word_t *x, const sdc_word_t *n, size_t len, sdc_word_t ninv) {
    size_t i, j;
    sdc_word_t f;
    sdc_dword_t cc, z;

    for (i = 0; i < len; i++) {
        f = x[0] * ninv;
        cc = 0;
        for (j = 0; j < len; j++) {
            z = (sdc_dword_t)x[j] + (sdc_dword_t)f * n[j] + cc;
            cc = z >> SDC_WORD_BITS;
            if (j != 0) x[j - 1] = (sdc_word_t)z;
        }
        x[len - 1] = (sdc_word_t)cc;
    }
    sdc_int_sub_ctl(x, n, len, sdc_int_gte(x, n, len));
}

void sdc_int_mont_modexp_u8(sdc_word_t *r, const sdc_word_t *a, const uint8_t *e, size_t elen,
            const sdc_word_t *n, sdc_word_t *tmp, size_t len, sdc_word_t ninv) {
    size_t i, bit_idx;
    sdc_word_t *buf1, *buf2, *buf3, *a_mont;
    sdc_word_t *res, *base, *scratch;
    sdc_word_t bit;
    
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

void sdc_int_mont_modexp_word(sdc_word_t *r, const sdc_word_t *a, const sdc_word_t *e, size_t elen,
            const sdc_word_t *n, sdc_word_t *tmp, size_t len, sdc_word_t ninv) {
    size_t i, bit_idx;
    sdc_word_t *buf1, *buf2, *buf3, *a_mont;
    sdc_word_t *res, *base, *scratch;
    sdc_word_t bit;

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
        sdc_word_t word = e[i];
        for (bit_idx = 0; bit_idx < SDC_WORD_BITS; bit_idx++) {
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

void sdc_int_mont_modexp_word_vartime(sdc_word_t *r, const sdc_word_t *a, const sdc_word_t *e, size_t elen,
            const sdc_word_t *n, sdc_word_t *tmp, size_t len, sdc_word_t ninv) {
    size_t i, bit_idx;
    sdc_word_t *base, *scratch;
    sdc_word_t bit;

    base = tmp;           // sdc_word_t base[len];
    scratch = tmp + len;  // sdc_word_t scratch[len];

    sdc_int_copy(base, a, len);
    sdc_int_to_mont(base, n, len);
    sdc_int_set_word(r, 1, len);
    sdc_int_to_mont(r, n, len);

    for (i = 0; i < elen; i++) {
        sdc_word_t word = e[elen - 1 - i];
        for (bit_idx = 0; bit_idx < SDC_WORD_BITS; bit_idx++) {
            bit = (word >> (SDC_WORD_BITS - 1 - bit_idx)) & 1;
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

sdc_word_t sdc_int_calculate_ninv(sdc_word_t x) {
    sdc_word_t inv = 2 - x;
    inv = inv * (2 - x * inv);
    inv = inv * (2 - x * inv);
    inv = inv * (2 - x * inv);
    inv = inv * (2 - x * inv);
#if SDC_64BIT
    inv = inv * (2 - x * inv);
#endif
    return 0 - inv;
}

static sdc_dword_t div_word(sdc_dword_t dividend, sdc_word_t divisor, sdc_word_t *rem) {
    sdc_dword_t q = 0;
    sdc_dword_t r = 0;
    sdc_dword_t d = divisor;
    
    for (int i = (SDC_DWORD_BITS - 1); i >= 0; i--) {
        r <<= 1;
        r |= (dividend >> i) & 1;
        sdc_word_t cond = GTE_DWORD(r, d);
        sdc_dword_t mask = -(sdc_dword_t)cond;
        r -= d & mask;
        q |= (sdc_dword_t)cond << i;
    }
    *rem = (sdc_word_t)r;
    return q;
}

static sdc_word_t rem_word(sdc_dword_t dividend, sdc_word_t divisor) {
    sdc_dword_t r = 0;
    sdc_dword_t d = divisor;
    
    for (int i = (SDC_DWORD_BITS - 1); i >= 0; i--) {
        r = (r << 1) | ((dividend >> i) & 1);
        sdc_dword_t mask = -(sdc_dword_t)GTE_DWORD(r, d);
        r -= d & mask;
    }
    return r;
}

/* 大数除以单字：quo = a / word, rem = a % word */
void sdc_int_div_word(sdc_word_t *quo, const sdc_word_t *a, sdc_word_t word, size_t len, sdc_word_t *rem) {
    sdc_dword_t remainder = 0;
    for (size_t i = len; i > 0; i--) {
        sdc_dword_t val = (remainder << SDC_WORD_BITS) | a[i - 1];
        sdc_word_t tmp;
        quo[i - 1] = (sdc_word_t)div_word(val, word, &tmp);
        remainder = tmp;
    }
    if (rem) *rem = (sdc_word_t)remainder;
}

sdc_word_t sdc_int_mod_word(const sdc_word_t *a, sdc_word_t word, size_t len) {
    sdc_dword_t rem = 0;
    for (size_t i = len; i > 0; i--) {
        sdc_dword_t val = (rem << SDC_WORD_BITS) | a[i - 1];
        rem = rem_word(val, word);
    }
    return rem;
}

void sdc_int_frombytes_le(sdc_word_t *a, size_t len, const uint8_t *in) {
    for (size_t i = 0; i < len; i++) {
        sdc_word_t word = load_word_le(in + i * SDC_WORD_SIZE);
        a[i] = word;
    }
}

void sdc_int_tobytes_le(const sdc_word_t *a, size_t len, uint8_t *out) {
    for (size_t i = 0; i < len; i++) {
        sdc_word_t word = a[i];
        store_word_le(out + i * SDC_WORD_SIZE, word);
    }
}

void sdc_int_frombytes_be(sdc_word_t *a, size_t len, const uint8_t *in) {
    for (size_t i = 0; i < len; i++) {
        sdc_word_t word = load_word_be(in + i * SDC_WORD_SIZE);
        a[len - 1 - i] = word;
    }
}

void sdc_int_tobytes_be(const sdc_word_t *a, size_t len, uint8_t *out) {
    for (size_t i = 0; i < len; i++) {
        sdc_word_t word = a[len - 1 - i];
        store_word_be(out + i * SDC_WORD_SIZE, word);
    }
}

/*
* Binary extended GCD, constant time w.r.t. the number of iterations
* (fixed at 4*SDC_WORD_BITS rounds) and control flow (branchless updates).
*
* Invariants maintained (classic binary xgcd):
*   u, v : current remainders (start: u = a mod m, v = m)
*   x1, x2: coefficients such that u = a*x1 mod m, v = a*x2 mod m
*
* We track everything modulo m using SDC_DWORD_BITS-bit intermediate arithmetic
* to avoid overflow, and use branchless conditional swaps/updates.
*/
static sdc_word_t modinv_word(sdc_word_t a, sdc_word_t m) {
    if (m == 1) return 0;

    sdc_word_t u = a; // We assume a < m.
    sdc_word_t v = m;
    sdc_word_t x1 = 1;
    sdc_word_t x2 = 0;
    const int ITERS = SDC_WORD_BITS * 4;

    for (int i = 0; i < ITERS; i++) {
        sdc_word_t u_odd_mask = gen_mask_word(u & 1);      /* all-ones if u odd */
        sdc_word_t v_odd_mask = gen_mask_word(v & 1);      /* all-ones if v odd */
        sdc_word_t both_odd_mask = u_odd_mask & v_odd_mask;

        sdc_word_t u_even_mask = ~u_odd_mask;
        sdc_word_t v_even_mask = ~v_odd_mask;

        /* Step A: if u is even -> u/=2, x1 = (x1 even ? x1/2 : (x1+m)/2)
           if v is even -> v/=2, x2 similarly
           We compute both possibilities and select. */

        /* --- handle u even --- */
        {
            sdc_word_t x1_odd_mask = gen_mask_word(x1 & 1);
            sdc_word_t x1_half_even = x1 >> 1;
            sdc_word_t x1_half_odd = (sdc_word_t)(((sdc_dword_t)x1 + (sdc_dword_t)m) >> 1);
            sdc_word_t x1_half = select_word(x1_odd_mask, x1_half_odd, x1_half_even);
            sdc_word_t new_u = u >> 1;

            u  = select_word(u_even_mask, new_u, u);
            x1 = select_word(u_even_mask, x1_half, x1);
        }

        /* --- handle v even (only relevant if u was NOT selected this round in a mutually
               exclusive binary-gcd variant; here we do the "both may shrink" variant below) --- */
        {
            sdc_word_t x2_odd_mask = gen_mask_word(x2 & 1);
            sdc_word_t x2_half_even = x2 >> 1;
            sdc_word_t x2_half_odd = (sdc_word_t)(((sdc_dword_t)x2 + (sdc_dword_t)m) >> 1);
            sdc_word_t x2_half = select_word(x2_odd_mask, x2_half_odd, x2_half_even);
            sdc_word_t new_v = v >> 1;

            v  = select_word(v_even_mask, new_v, v);
            x2 = select_word(v_even_mask, x2_half, x2);
        }

        /* --- handle both odd: subtract smaller from larger --- */
        {
            sdc_word_t u_ge_v_mask = gte_word_mask(u, v);
            /* candidate values if u >= v: u -= v, x1 -= x2 (mod m) */
            sdc_word_t new_u_sub = u - v;
            sdc_word_t new_x1_sub;
            {
                /* x1 - x2 mod m */
                sdc_word_t diff_mask = gte_word_mask(x1, x2);
                sdc_word_t d1 = x1 - x2;
                sdc_word_t d2 = x1 + m - x2;
                new_x1_sub = select_word(diff_mask, d1, d2);
            }

            /* candidate values if v > u: v -= u, x2 -= x1 (mod m) */
            sdc_word_t new_v_sub = v - u;
            sdc_word_t new_x2_sub;
            {
                sdc_word_t diff_mask = gte_word_mask(x2, x1);
                sdc_word_t d1 = x2 - x1;
                sdc_word_t d2 = x2 + m - x1;
                new_x2_sub = select_word(diff_mask, d1, d2);
            }

            sdc_word_t apply_mask = both_odd_mask; /* only when both odd do we subtract */
            sdc_word_t take_u_branch = apply_mask & u_ge_v_mask;
            sdc_word_t take_v_branch = apply_mask & ~u_ge_v_mask;

            u  = select_word(take_u_branch, new_u_sub, u);
            x1 = select_word(take_u_branch, new_x1_sub, x1);
            v  = select_word(take_v_branch, new_v_sub, v);
            x2 = select_word(take_v_branch, new_x2_sub, x2);
        }
    }

    /* At termination (v == gcd == 1 assumed), x2 holds a*x2 ≡ v(final) ... 
       Standard binary xgcd converges with u -> gcd, and x1 the corresponding
       coefficient for u. Since we assume gcd(a,m)=1, u should reach 1 (or v reaches 1
       depending on parity path); take whichever of u/v equals... */

    /* To keep this fully branch-free and correct regardless of which variable
       ended up holding 1, select based on (u == 1). */
    sdc_word_t u_is_one_mask = gen_mask_word(is_nonzero_word(u ^ 1) ^ 1);
    sdc_word_t result = select_word(u_is_one_mask, rem_word(x1, m), rem_word(x2, m));
    return result;
}

/*
 * Mathematical Derivation (independently discovered by the author):
 *
 * We want d such that d * e ≡ 1 (mod φ).
 * This means d * e = k * φ + 1 for some integer k.
 * Rearranging: d = (k * φ + 1) / e.
 *
 * For this to yield an integer, we need:
 *     k * φ ≡ -1 (mod e)
 *     k ≡ -φ⁻¹ (mod e)
 *
 * Since e is a small public exponent (typically 65537), φ⁻¹ mod e
 * can be computed with a SDC_WORD_BITS-bit constant-time modular inverse.
 *
 * This avoids a full big-integer extended GCD, which is both
 * slower and significantly harder to implement in constant time.
 *
 * Note: This technique was independently derived during the
 * development of slim-data-crypt and is specific to RSA key
 * generation with small public exponents.
 */
void sdc_int_modinv(sdc_word_t *d, const sdc_word_t *phi, sdc_word_t e, sdc_word_t *tmp, size_t len) {
    sdc_word_t k = 0;
    sdc_word_t rem;

    rem = sdc_int_mod_word(phi, e, len);
    // k = -phi^{-1} (mod e)
    k = e - modinv_word(rem, e);
    // tmp = k * phi + 1
    sdc_int_mul_word(tmp, phi, k, len);
    tmp[0]++;  // We can directly add 1 because k*phi is always even.
    sdc_int_div_word(tmp, tmp, e, len + 1, NULL);
    // d = tmp / e = (k * phi + 1) / e
    sdc_int_copy(d, tmp, len);
}

#endif /* SDC_ENABLE_INTEGER */