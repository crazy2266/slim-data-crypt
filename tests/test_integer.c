/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Integer arithmetic library tests.
 * 
 * This test covers basic integer operations: set, copy, comparison,
 * add/sub, ctz/shr, and the 64-bit reference tests.
 */

#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>
#include "integer.h"

#if SDC_ENABLE_INTEGER

static unsigned g_failures = 0;

static void test_ok(const char *name) {
    printf("  [PASS] %s\n", name);
}

static int test_fail(const char *name, const char *reason) {
    printf("  [FAIL] %s: %s\n", name, reason);
    g_failures++;
    return -1;
}

static int eq_words(const sdc_word_t *a, const sdc_word_t *b, size_t len) {
    sdc_word_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

static void print_hex(const char *label, const sdc_word_t *a, size_t len) {
    printf("%s: ", label);
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

/* ============================================================
   测试 1: 基础操作
   ============================================================ */

static int test_basic_ops(void) {
    printf("\n=== 基础操作测试 ===\n");

#if SDC_64BIT
    sdc_word_t test_word = UINT64_C(0x123456789abcdef0);
#else
    sdc_word_t test_word = UINT32_C(0x12345678);
#endif

    /* set_word */
    {
        sdc_word_t x[4];
        sdc_int_set_word(x, test_word, 4);
        if (x[0] != test_word || x[1] != 0 || x[2] != 0 || x[3] != 0)
            return test_fail("set_word", "unexpected result");
        test_ok("set_word");
    }

    /* copy */
    {
        sdc_word_t a[4] = {1,2,3,4}, b[4] = {0};
        sdc_int_copy(b, a, 4);
        if (!eq_words(a, b, 4)) return test_fail("copy", "copy mismatch");
        test_ok("copy");
    }

    /* comparison */
    {
        sdc_word_t a[2] = {1,0}, b[2] = {2,0};
        if (!sdc_int_lt(a, b, 2) || sdc_int_lt(b, a, 2) ||
            sdc_int_eq(a, b, 2) || !sdc_int_gte(b, a, 2))
            return test_fail("comparison", "comparison mismatch");
        test_ok("comparison");
    }

    /* add/sub */
    {
        sdc_word_t a[2] = {0, 1}, b[2] = {1,0}, r[2];
        sdc_word_t carry = sdc_int_add(r, a, b, 2);
        if (r[0] != 1 || r[1] != 1 || carry != 0)
            return test_fail("add", "overflow case mismatch");
        sdc_word_t borrow = sdc_int_sub(r, r, b, 2);
        if (r[0] != 0 || r[1] != 1 || borrow != 0)
            return test_fail("sub", "round-trip mismatch");
        test_ok("add/sub");
    }

    /* ctz/shr */
    {
        sdc_word_t x[3] = {0,0,0};
#if SDC_64BIT
        x[2] = UINT64_C(0x8000000000000000);
        size_t expected_ctz = 191;
#else
        x[2] = UINT32_C(0x80000000);
        size_t expected_ctz = 95;
#endif
        if (sdc_int_ctz(x, 3) != expected_ctz)
            return test_fail("ctz", "expected trailing zeros mismatch");
        sdc_int_shr(x, 1, 3);
#if SDC_64BIT
        if (x[0] != 0 || x[1] != 0 || x[2] != 0x4000000000000000)
#else
        if (x[0] != 0 || x[1] != 0 || x[2] != 0x40000000)
#endif
            return test_fail("shr", "shift mismatch");
        test_ok("ctz/shr");
    }
    return 0;
}

/* ============================================================
   测试 2: 参考值测试 (与 sdc_dword_t 对比)
   ============================================================ */

static int test_word_reference(void) {
    printf("\n=== 参考值测试 (sdc_dword_t 对比) ===\n");

    for (unsigned i = 0; i < 10000; i++) {
        sdc_word_t a = (sdc_word_t)test_rand64();
        sdc_word_t b = (sdc_word_t)test_rand64();
        sdc_word_t aa[1] = {a}, bb[1] = {b}, r[2] = {0,0};

        /* add */
        sdc_dword_t sum = (sdc_dword_t)a + b;
        sdc_word_t carry = sdc_int_add(r, aa, bb, 1);
        if (r[0] != (sdc_word_t)sum || carry != (sdc_word_t)(sum >> SDC_WORD_BITS))
            return test_fail("add/reference", "random mismatch");

        /* mul */
        sdc_dword_t product = (sdc_dword_t)a * b;
        sdc_int_mul(r, aa, bb, 1);
        if (r[0] != (sdc_word_t)product || r[1] != (sdc_word_t)(product >> SDC_WORD_BITS))
            return test_fail("mul/reference", "random mismatch");

        /* div_word / mod_word */
        sdc_word_t divisor = (sdc_word_t)(test_rand64() | 1);
        sdc_word_t q[1], rem = 0;
        sdc_word_t ref_q = a / divisor, ref_r = a % divisor;
        sdc_int_div_word(q, aa, divisor, 1, &rem);
        if (q[0] != ref_q || rem != ref_r)
            return test_fail("div_word/reference", "random mismatch");
        if (sdc_int_mod_word(aa, divisor, 1) != ref_r)
            return test_fail("mod_word/reference", "random mismatch");
    }

    test_ok("add/mul/div/mod against sdc_dword_t reference");
    return 0;
}

/* ============================================================
   测试 3: 模逆 (小数字)
   ============================================================ */

static int test_modinv(void) {
    printf("\n=== 模逆测试 (phi=3120, e=17) ===\n");

    size_t len = 4;
    sdc_word_t phi[4] = {0x00000c30, 0, 0, 0};
    sdc_word_t d[4];
    sdc_word_t tmp[9];
    sdc_word_t expected[4] = {0x00000ac1, 0, 0, 0};
    sdc_word_t e = 17;

    sdc_int_modinv(d, phi, e, tmp, len);
    print_hex("计算出的 d", d, len);
    print_hex("期望的 d", expected, len);

    if (!eq_words(d, expected, len)) {
        test_fail("模逆", "d 不匹配");
        return -1;
    }
    test_ok("模逆正确");
    return 0;
}

/* ============================================================
   测试 4: 蒙哥马利模幂 (费马小定理)
   ============================================================ */

static int test_modexp(void) {
    printf("\n=== 蒙哥马利模幂测试 (费马小定理) ===\n");
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

    print_hex("p (2^255 - 19)", n, len);

    srand((unsigned)time(NULL));
    random_fill(a, len);
    sdc_int_sub_ctl(a, n, len, sdc_int_gte(a, n, len));
    if (sdc_int_eq_word(a, 0, len)) a[0] = 2;
    print_hex("a", a, len);

    /* exp = n - 2 */
    sdc_int_copy(exp, n, len);
    sdc_int_sub_word(exp, exp, 1, len);

    ninv = sdc_int_calculate_ninv(n[0]);
    sdc_int_mont_modexp_word(result, a, exp, len, n, tmp, len, ninv);

    print_hex("a^(p-1) mod p", result, len);

    sdc_word_t one[len];
    sdc_int_set_word(one, 1, len);
    if (eq_words(result, one, len)) {
        test_ok("费马小定理验证通过");
        return 0;
    } else {
        return test_fail("费马小定理", "a^(p-1) mod p != 1");
    }
}

/* ============================================================
   main
   ============================================================ */

int main(void) {
    printf("========================================\n");
    printf("Slim Data Crypt - Integer Library Test\n");
    printf("========================================\n");

    if (test_basic_ops() != 0) return 1;
    if (test_word_reference() != 0) return 1;
    if (test_modinv() != 0) return 1;
    if (test_modexp() != 0) return 1;

    printf("\n========================================\n");
    if (g_failures == 0) {
        printf("ALL TESTS PASSED\n");
        printf("========================================\n");
        return 0;
    }
    printf("TEST FAILURES: %u\n", g_failures);
    printf("========================================\n");
    return 1;
}

#else

int main(void) {
    printf("[SKIP] Integer 测试未启用\n");
    return 0;
}

#endif /* SDC_ENABLE_INTEGER */