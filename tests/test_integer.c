/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Big-integer arithmetic tests.
 * Covers basic ops, reference comparison, modular inverse,
 * modular exponentiation (Fermat), and long division.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>
#include <sdcrypt/integer.h>
#include <sdcrypt/config.h>
#include "test_common.h"

#if SDC_ENABLE_INTEGER

static int eq_words(const sdc_word_t *a, const sdc_word_t *b, size_t len) {
    sdc_word_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

static void print_words(const char *label, const sdc_word_t *a, size_t len) {
    printf("  %s: ", label);
    int started = 0;
    for (size_t i = len; i > 0; i--) {
        if (started || a[i - 1] != 0) {
#if SDC_64BIT
            printf("%016" PRIx64, (uint64_t)a[i - 1]);
#else
            printf("%08" PRIx32, (uint32_t)a[i - 1]);
#endif
            started = 1;
        }
    }
    if (!started) printf("0");
    printf("\n");
}

static uint64_t test_rng_state = UINT64_C(0x6a09e667f3bcc909);

static uint64_t test_rand64(void) {
    uint64_t x = test_rng_state;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    test_rng_state = x;
    return x * UINT64_C(0x2545f4914f6cdd1d);
}

static void random_fill(sdc_word_t *a, size_t len) {
    for (size_t i = 0; i < len; i++) {
#if SDC_64BIT
        a[i] = (sdc_word_t)test_rand64();
#else
        a[i] = (sdc_word_t)(test_rand64() & 0xFFFFFFFF);
#endif
    }
}

/* ------------------------------------------------------------------ */
/* Section 1: basic operations                                         */
/* ------------------------------------------------------------------ */
static void test_basic_ops(void) {
    T_SECTION("Basic operations");

#if SDC_64BIT
    sdc_word_t test_word = UINT64_C(0x123456789abcdef0);
#else
    sdc_word_t test_word = UINT32_C(0x12345678);
#endif

    {
        sdc_word_t x[4];
        sdc_int_set_word(x, test_word, 4);
        T_CHECK(x[0] == test_word && x[1] == 0 && x[2] == 0 && x[3] == 0,
                "set_word places value in word 0");
    }
    {
        sdc_word_t a[4] = {1,2,3,4}, b[4] = {0};
        sdc_int_copy(b, a, 4);
        T_CHECK(eq_words(a, b, 4), "copy produces identical words");
    }
    {
        sdc_word_t a[2] = {1,0}, b[2] = {2,0};
        T_CHECK(sdc_int_lt(a, b, 2) && !sdc_int_lt(b, a, 2) &&
                !sdc_int_eq(a, b, 2) && sdc_int_gte(b, a, 2),
                "comparison operators are consistent");
    }
    {
        sdc_word_t a[2] = {0, 1}, b[2] = {1,0}, r[2];
        sdc_word_t carry = sdc_int_add(r, a, b, 2);
        T_CHECK(r[0] == 1 && r[1] == 1 && carry == 0,
                "add handles multi-word without carry-out");
        sdc_word_t borrow = sdc_int_sub(r, r, b, 2);
        T_CHECK(r[0] == 0 && r[1] == 1 && borrow == 0,
                "sub reverses add (round-trip)");
    }
    {
        sdc_word_t x[3] = {0,0,0};
#if SDC_64BIT
        x[2] = UINT64_C(0x8000000000000000);
        size_t expected_ctz = 191;
#else
        x[2] = UINT32_C(0x80000000);
        size_t expected_ctz = 95;
#endif
        T_CHECK(sdc_int_ctz(x, 3) == expected_ctz, "ctz locates top set bit");
        sdc_int_shr(x, 1, 3);
#if SDC_64BIT
        T_CHECK(x[0] == 0 && x[1] == 0 && x[2] == UINT64_C(0x4000000000000000),
                "shr shifts across words");
#else
        T_CHECK(x[0] == 0 && x[1] == 0 && x[2] == UINT32_C(0x40000000),
                "shr shifts across words");
#endif
    }
}

/* ------------------------------------------------------------------ */
/* Section 2: reference comparison vs native sdc_dword_t               */
/* ------------------------------------------------------------------ */
static void test_word_reference(void) {
    T_SECTION("Reference comparison (10000 random cases)");

    for (unsigned i = 0; i < 10000; i++) {
        sdc_word_t a = (sdc_word_t)test_rand64();
        sdc_word_t b = (sdc_word_t)test_rand64();
        sdc_word_t aa[1] = {a}, bb[1] = {b}, r[2] = {0,0};

        sdc_dword_t sum = (sdc_dword_t)a + b;
        sdc_word_t carry = sdc_int_add(r, aa, bb, 1);
        if (r[0] != (sdc_word_t)sum || carry != (sdc_word_t)(sum >> SDC_WORD_BITS)) {
            T_CHECK(0, "add matches native reference");
            return;
        }

        sdc_dword_t product = (sdc_dword_t)a * b;
        sdc_int_mul(r, aa, bb, 1);
        if (r[0] != (sdc_word_t)product || r[1] != (sdc_word_t)(product >> SDC_WORD_BITS)) {
            T_CHECK(0, "mul matches native reference");
            return;
        }

        sdc_word_t divisor = (sdc_word_t)(test_rand64() | 1);
        sdc_word_t q[1], rem = 0;
        sdc_word_t ref_q = a / divisor, ref_r = a % divisor;
        sdc_int_div_word(q, aa, divisor, 1, &rem);
        if (q[0] != ref_q || rem != ref_r) {
            T_CHECK(0, "div_word matches native reference");
            return;
        }
        if (sdc_int_mod_word(aa, divisor, 1) != ref_r) {
            T_CHECK(0, "mod_word matches native reference");
            return;
        }
    }
    T_CHECK(1, "add/mul/div/mod match native reference across 10000 cases");
}

/* ------------------------------------------------------------------ */
/* Section 3: modular inverse                                          */
/* ------------------------------------------------------------------ */
static void test_modinv(void) {
    T_SECTION("Modular inverse (phi=3120, e=17)");

    size_t len = 4;
    sdc_word_t phi[4] = {0x00000c30, 0, 0, 0};
    sdc_word_t d[4];
    sdc_word_t expected[4] = {0x00000ac1, 0, 0, 0};
    sdc_word_t e = 17;

    sdc_int_modinv(d, phi, e, len);
    print_words("computed d", d, len);
    print_words("expected d", expected, len);
    T_CHECK(eq_words(d, expected, len), "modinv(3120, 17) == 0xac1");
}

/* ------------------------------------------------------------------ */
/* Section 4: modular exponentiation (Fermat little theorem)           */
/* ------------------------------------------------------------------ */
static void test_modexp(void) {
    T_SECTION("Modular exponentiation (Fermat: a^(p-1) mod p == 1)");

#if SDC_64BIT
    size_t len = 4;
    sdc_word_t n[4] = {
        0xFFFFFFFFFFFFFFEDULL, 0xFFFFFFFFFFFFFFFFULL,
        0xFFFFFFFFFFFFFFFFULL, 0x7FFFFFFFFFFFFFFFULL
    };
#else
    size_t len = 8;
    sdc_word_t n[8] = {
        0xFFFFFFEDU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU,
        0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0x7FFFFFFFU
    };
#endif
    sdc_word_t a[len], exp[len], result[len];
    sdc_word_t tmp[len * 4];
    sdc_word_t ninv;

    print_words("p (2^255 - 19)", n, len);

    srand((unsigned)time(NULL));
    random_fill(a, len);
    sdc_int_sub_ctl(a, n, len, sdc_int_gte(a, n, len));
    if (sdc_int_eq_word(a, 0, len)) a[0] = 2;
    print_words("a", a, len);

    sdc_int_copy(exp, n, len);
    sdc_int_sub_word(exp, exp, 1, len);

    ninv = sdc_int_calculate_ninv(n[0]);
    sdc_int_mont_modexp_word(result, a, exp, len, n, tmp, len, ninv);
    print_words("a^(p-1) mod p", result, len);

    sdc_word_t one[len];
    sdc_int_set_word(one, 1, len);
    T_CHECK(eq_words(result, one, len), "a^(p-1) mod p == 1");
}

/* ------------------------------------------------------------------ */
/* Section 5: long division                                            */
/* ------------------------------------------------------------------ */
static void test_division(void) {
    T_SECTION("Long division");

    size_t len = 4;
    sdc_word_t a[4], b[4], q[4], r[4], zero[4], one[4];
    sdc_int_set_word(zero, 0, len);
    sdc_int_set_word(one, 1, len);

    sdc_int_set_word(a, 0, len);
    sdc_int_set_word(b, 123, len);
    sdc_int_div(q, r, a, len, b, len);
    T_CHECK(eq_words(q, zero, len) && eq_words(r, zero, len), "0 / b == 0");

    sdc_int_set_word(b, 1, len);
    random_fill(a, len);
    sdc_int_div(q, r, a, len, b, len);
    T_CHECK(eq_words(q, a, len) && eq_words(r, zero, len), "a / 1 == a");

    sdc_int_set_word(a, 123, len);
    sdc_int_set_word(b, 456, len);
    sdc_int_div(q, r, a, len, b, len);
    T_CHECK(eq_words(q, zero, len) && eq_words(r, a, len), "a < b -> q=0, r=a");

    random_fill(b, len);
    if (sdc_int_eq_word(b, 0, len)) b[0] = 1;
    sdc_int_copy(a, b, len);
    sdc_int_div(q, r, a, len, b, len);
    T_CHECK(eq_words(q, one, len) && eq_words(r, zero, len), "a == b -> q=1, r=0");

    {
        sdc_int_set_word(a, 0, len);
        sdc_int_set_word(b, 0, len);
#if SDC_64BIT
        a[0] = UINT64_MAX;
        b[0] = UINT64_C(2);
        sdc_word_t eq[4] = {UINT64_C(0x7FFFFFFFFFFFFFFF), 0, 0, 0};
        sdc_word_t er[4] = {UINT64_C(1), 0, 0, 0};
#else
        a[0] = UINT32_MAX;
        b[0] = UINT32_C(2);
        sdc_word_t eq[4] = {UINT32_C(0x7FFFFFFF), 0, 0, 0};
        sdc_word_t er[4] = {UINT32_C(1), 0, 0, 0};
#endif
        sdc_int_div(q, r, a, len, b, len);
        T_CHECK(eq_words(q, eq, len) && eq_words(r, er, len),
                "word-boundary division (MAX / 2)");
    }

    {
        int ok = 1;
        for (unsigned t = 0; t < 10000 && ok; t++) {
            random_fill(a, len);
            random_fill(b, len);
            if (sdc_int_eq_word(b, 0, len)) b[0] = 1;
            sdc_int_div(q, r, a, len, b, len);
            if (!sdc_int_lt(r, b, len)) { ok = 0; break; }
            sdc_word_t product[8];
            sdc_int_mul(product, q, b, len);
            sdc_word_t carry = sdc_int_add(product, product, r, len);
            for (size_t i = len; i < len * 2; i++) {
                if (product[i] != 0) { ok = 0; break; }
            }
            if (!ok) break;
            if (!eq_words(product, a, len) || carry != 0) { ok = 0; break; }
        }
        T_CHECK(ok, "random division (10000 cases): a == q*b + r and r < b");
    }
}

int main(void) {
    T_SUITE("Slim Data Crypt - Integer Library Tests");

    test_basic_ops();
    test_word_reference();
    test_modinv();
    test_modexp();
    test_division();

    T_SUMMARY();
}

#else

int main(void) {
    printf("[SKIP] INTEGER disabled in config.h\n");
    return 0;
}

#endif /* SDC_ENABLE_INTEGER */
