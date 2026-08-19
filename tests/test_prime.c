/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Prime generation + RSA key generation test.
 * 
 * This test generates random primes p and q, builds an RSA key pair,
 * and verifies that encryption/decryption works correctly.
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sdcrypt/config.h>
#include <sdcrypt/integer.h>
#include <sdcrypt/random.h>

#if SDC_ENABLE_INTEGER

#define RSA_PUB_EXP UINT64_C(65537)

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
    printf("%s = 0x", label);
    int started = 0;
    for (size_t i = len; i != 0; i--) {
        sdc_word_t w = a[i - 1];
        if (started || w != 0) {
#if SDC_64BIT
            printf("%016" PRIx64, (uint64_t)w);
#else
            printf("%08" PRIx32, (uint32_t)w);
#endif
            started = 1;
        }
    }
    if (!started) printf("0");
    putchar('\n');
}

/* ============================================================
   High-resolution timer
   ============================================================ */
#if defined(_WIN32) || defined(_WIN64)
#  include <windows.h>
static LARGE_INTEGER timer_freq;
static int timer_initialized = 0;

static double get_time_ms(void) {
    if (!timer_initialized) {
        QueryPerformanceFrequency(&timer_freq);
        timer_initialized = 1;
    }
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    return (double)now.QuadPart * 1000.0 / (double)timer_freq.QuadPart;
}
#else
#  include <time.h>
static double get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}
#endif

static void print_time(const char *label, double ms) {
    if (ms >= 1000.0) printf("%s: %.3f s\n", label, ms / 1000.0);
    else if (ms >= 1.0) printf("%s: %.3f ms\n", label, ms);
    else if (ms >= 0.001) printf("%s: %.3f us\n", label, ms * 1000.0);
    else printf("%s: %.3f ns\n", label, ms * 1000000.0);
}

static int test_rsa_keygen(size_t rsa_len, int do_perf) {
    const size_t prime_len = rsa_len / 2;
    const size_t rsa_bits = rsa_len * SDC_WORD_BITS;
    const size_t prime_bits = prime_len * SDC_WORD_BITS;
    double t_start, t_end;
    double t_total = 0.0;
    double t_enc = 0.0, t_dec = 0.0;

    printf("\n============================================================\n");
    printf("RSA-%zu KEY GENERATION TEST\n", rsa_bits);
    printf("============================================================\n");

    if (rsa_len == 0 || (rsa_len & 1) != 0)
        return test_fail("rsa_keygen", "invalid rsa_len (must be even)");

    sdc_word_t p[prime_len], q[prime_len];
    sdc_word_t n[rsa_len], phi[rsa_len];
    sdc_word_t p1[rsa_len], q1[rsa_len];
    sdc_word_t d[rsa_len];
    sdc_word_t m[rsa_len], c[rsa_len], m_dec[rsa_len];
    sdc_word_t pq_full[2 * prime_len], phi_full[2 * rsa_len];
    sdc_word_t e = RSA_PUB_EXP;
    size_t e_bits = SDC_WORD_BITS - sdc_word_clz(e);
    sdc_word_t *tmp = (sdc_word_t *)calloc(5 * rsa_len, sizeof(sdc_word_t));
    if (tmp == NULL) return test_fail("rsa_keygen", "scratch allocation failed");

    int ret;

    printf("\nGenerating %zu-bit prime p...\n", prime_bits);
    if (do_perf) t_start = get_time_ms();
    ret = sdc_int_gen_prime(p, tmp, prime_len);
    if (do_perf) { t_end = get_time_ms(); t_total += t_end - t_start; }
    if (ret != 0) { free(tmp); return test_fail("p generation", "sdc_int_gen_prime failed"); }
    print_hex("p", p, prime_len);

    printf("\nGenerating %zu-bit prime q...\n", prime_bits);
    if (do_perf) t_start = get_time_ms();
    do { ret = sdc_int_gen_prime(q, tmp, prime_len); } while (ret == 0 && eq_words(p, q, prime_len));
    if (do_perf) { t_end = get_time_ms(); t_total += t_end - t_start; }
    if (ret != 0) { free(tmp); return test_fail("q generation", "sdc_int_gen_prime failed"); }
    print_hex("q", q, prime_len);
    test_ok("p and q generated (p != q)");

    printf("\nCalculating n = p * q...\n");
    if (do_perf) t_start = get_time_ms();
    memset(pq_full, 0, sizeof(pq_full));
    sdc_int_mul(pq_full, p, q, prime_len);
    memcpy(n, pq_full, sizeof(n));
    if (do_perf) { t_end = get_time_ms(); t_total += t_end - t_start; }
    print_hex("n", n, rsa_len);

    sdc_word_t top_bit_mask = 0;
#if SDC_64BIT
    top_bit_mask = UINT64_C(0x8000000000000000);
#else
    top_bit_mask = UINT32_C(0x80000000);
#endif
    if ((n[rsa_len - 1] & top_bit_mask) == 0) {
        free(tmp);
        return test_fail("n", "modulus lost its top bit");
    }
    test_ok("n has expected bit length");

    memset(p1, 0, sizeof(p1)); memset(q1, 0, sizeof(q1));
    memcpy(p1, p, prime_len * sizeof(sdc_word_t));
    memcpy(q1, q, prime_len * sizeof(sdc_word_t));
    sdc_int_sub_word(p1, p1, 1, rsa_len);
    sdc_int_sub_word(q1, q1, 1, rsa_len);
    memset(phi_full, 0, sizeof(phi_full));

    printf("\nCalculating phi = (p-1) * (q-1)...\n");
    if (do_perf) t_start = get_time_ms();
    sdc_int_mul(phi_full, p1, q1, rsa_len);
    if (do_perf) { t_end = get_time_ms(); t_total += t_end - t_start; }

    for (size_t i = rsa_len; i < 2 * rsa_len; i++) {
        if (phi_full[i] != 0) {
            free(tmp);
            return test_fail("phi", "phi exceeds RSA modulus width");
        }
    }
    memcpy(phi, phi_full, sizeof(phi));
    print_hex("phi", phi, rsa_len);

    printf("\nChecking gcd(65537, phi)...\n");
    if (sdc_int_mod_word(phi, RSA_PUB_EXP, rsa_len) == 0) {
        free(tmp);
        return test_fail("gcd", "gcd(e, phi) != 1, try a different prime pair");
    }
    test_ok("gcd(65537, phi) == 1");

    printf("\nCalculating d = e^-1 mod phi...\n");
    if (do_perf) t_start = get_time_ms();
    memset(d, 0, sizeof(d));
    sdc_int_modinv(d, phi, RSA_PUB_EXP, rsa_len);
    if (do_perf) { t_end = get_time_ms(); t_total += t_end - t_start; }
    if (sdc_int_eq_word(d, 0, rsa_len)) {
        free(tmp);
        return test_fail("d", "modinv returned zero");
    }
    print_hex("d", d, rsa_len);
    test_ok("d = e^-1 mod phi computed");

    printf("\nGenerating random message m < n...\n");
    for (;;) {
        ret = sdc_random_bytes((uint8_t *)m, rsa_len * sizeof(sdc_word_t));
        if (ret != 0) { free(tmp); return test_fail("message", "random generation failed"); }
        if (!sdc_int_gte(m, n, rsa_len)) break;
    }
    if (sdc_int_eq_word(m, 0, rsa_len)) m[0] = 2;
    print_hex("m", m, rsa_len);

    sdc_word_t ninv = sdc_int_calculate_ninv(n[0]);
    printf("\nninv = ");
#if SDC_64BIT
    printf("%016" PRIx64, (uint64_t)ninv);
#else
    printf("%08" PRIx32, (uint32_t)ninv);
#endif
    printf("\n");

    printf("\nEncrypting with e=65537...\n");
    if (do_perf) t_start = get_time_ms();
    memset(c, 0, sizeof(c));
    sdc_int_mont_modexp_with_ebits_vartime(c, m, e, e_bits, n, tmp, rsa_len, ninv);
    if (do_perf) { t_end = get_time_ms(); t_enc = t_end - t_start; }
    print_hex("c (ciphertext)", c, rsa_len);

    printf("\nDecrypting with d...\n");
    if (do_perf) t_start = get_time_ms();
    memset(m_dec, 0, sizeof(m_dec));
    sdc_int_mont_modexp_word(m_dec, c, d, rsa_len, n, tmp, rsa_len, ninv);
    if (do_perf) { t_end = get_time_ms(); t_dec = t_end - t_start; }
    print_hex("m_dec (decrypted)", m_dec, rsa_len);

    if (!eq_words(m, m_dec, rsa_len)) {
        free(tmp);
        return test_fail("decrypt", "decrypted message != original");
    }
    test_ok("RSA encryption/decryption successful");

    printf("\nVariable-time decrypt cross-check...\n");
    memset(m_dec, 0, sizeof(m_dec));
    sdc_int_mont_modexp_word_vartime(m_dec, c, d, rsa_len, n, tmp, rsa_len, ninv);
    if (!eq_words(m, m_dec, rsa_len)) {
        free(tmp);
        return test_fail("vartime_decrypt", "vartime result != original");
    }
    test_ok("variable-time RSA decrypt matches");

    free(tmp);

    if (do_perf) {
        printf("\n--- Performance ---\n");
        print_time("Total key generation (p+q+phi+d)", t_total);
        print_time("Encrypt (m^e mod n)", t_enc);
        print_time("Decrypt (c^d mod n)", t_dec);
    }

    printf("\n============================================================\n");
    printf("RSA-%zu KEY GENERATION TEST PASSED\n", rsa_bits);
    printf("============================================================\n");

    return 0;
}

int main(void) {
    printf("============================================================\n");
    printf("Slim Data Crypt - Prime Generation & RSA Test\n");
    printf("============================================================\n");

    size_t rsa2048_len = sdc_get_len_by_bits(2048);
    size_t rsa4096_len = sdc_get_len_by_bits(4096);

    if (test_rsa_keygen(rsa2048_len, 1) != 0) return 1;
    if (test_rsa_keygen(rsa4096_len, 1) != 0) return 1;

    printf("\n============================================================\n");
    if (g_failures == 0) {
        printf("ALL TESTS PASSED\n");
        printf("============================================================\n");
        return 0;
    }
    printf("TEST FAILURES: %u\n", g_failures);
    printf("============================================================\n");
    return 1;
}

#else

int main(void) {
    printf("[SKIP] Integer module is disabled\n");
    return 0;
}

#endif