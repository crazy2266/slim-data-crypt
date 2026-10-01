/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Prime generation + RSA key generation test.
 * Generates random primes p and q, builds an RSA key pair,
 * and verifies that encrypt/decrypt round-trips correctly.
 */

#ifdef _WIN32
#  include <windows.h>
#else
#  define _POSIX_C_SOURCE 200809L
#endif
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sdcrypt/config.h>
#include <sdcrypt/integer.h>
#include <sdcrypt/rng.h>
#include "test_common.h"

#if SDC_ENABLE_INTEGER

#define RSA_PUB_EXP UINT64_C(65537)

static sdc_rng_ctx rng_ctx = {&sdc_system_rng_ops, {0}};

static int eq_words(const sdc_word_t *a, const sdc_word_t *b, size_t len) {
    sdc_word_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

static void print_words(const char *label, const sdc_word_t *a, size_t len) {
    printf("  %s = 0x", label);
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

static double get_time_ms(void) {
#ifdef _WIN32
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart * 1000.0 / freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
#endif
}

static void print_time(const char *label, double ms) {
    if (ms >= 1000.0) printf("  %s: %.3f s\n", label, ms / 1000.0);
    else if (ms >= 1.0) printf("  %s: %.3f ms\n", label, ms);
    else if (ms >= 0.001) printf("  %s: %.3f us\n", label, ms * 1000.0);
    else printf("  %s: %.3f ns\n", label, ms * 1000000.0);
}

static void test_rsa_keygen(size_t rsa_len) {
    const size_t prime_len = rsa_len / 2;
    const size_t rsa_bits = rsa_len * SDC_WORD_BITS;
    const size_t prime_bits = prime_len * SDC_WORD_BITS;

    T_SECTION("RSA key generation");
    printf("  target: RSA-%zu (%zu-bit primes)\n", rsa_bits, prime_bits);

    if (rsa_len == 0 || (rsa_len & 1) != 0) {
        T_CHECK(0, "rsa_len must be even and non-zero");
        return;
    }

    sdc_word_t p[prime_len], q[prime_len];
    sdc_word_t n[rsa_len], phi[rsa_len];
    sdc_word_t p1[rsa_len], q1[rsa_len];
    sdc_word_t d[rsa_len];
    sdc_word_t m[rsa_len], c[rsa_len], m_dec[rsa_len];
    sdc_word_t pq_full[2 * prime_len], phi_full[2 * rsa_len];
    sdc_word_t e[1] = { RSA_PUB_EXP };
    sdc_word_t *tmp = (sdc_word_t *)calloc(5 * rsa_len, sizeof(sdc_word_t));
    if (tmp == NULL) { T_CHECK(0, "scratch allocation"); return; }

    int ret;
    double t0, t1, t_gen = 0.0, t_mul = 0.0, t_inv = 0.0, t_enc = 0.0, t_dec = 0.0;

    t0 = get_time_ms();
    ret = sdc_int_gen_prime(p, tmp, prime_len, &rng_ctx);
    t1 = get_time_ms(); t_gen += t1 - t0;
    if (ret != 0) { free(tmp); T_CHECK(0, "prime p generation"); return; }
    print_words("p", p, prime_len);

    t0 = get_time_ms();
    do { ret = sdc_int_gen_prime(q, tmp, prime_len, &rng_ctx); }
    while (ret == 0 && eq_words(p, q, prime_len));
    t1 = get_time_ms(); t_gen += t1 - t0;
    if (ret != 0) { free(tmp); T_CHECK(0, "prime q generation"); return; }
    print_words("q", q, prime_len);
    T_CHECK(!eq_words(p, q, prime_len), "p and q are distinct");

    t0 = get_time_ms();
    memset(pq_full, 0, sizeof(pq_full));
    sdc_int_mul(pq_full, p, q, prime_len);
    memcpy(n, pq_full, sizeof(n));
    t1 = get_time_ms(); t_mul += t1 - t0;
    print_words("n", n, rsa_len);

    sdc_word_t top = 0;
#if SDC_64BIT
    top = UINT64_C(0x8000000000000000);
#else
    top = UINT32_C(0x80000000);
#endif
    T_CHECK((n[rsa_len - 1] & top) != 0, "modulus n keeps its top bit");

    memset(p1, 0, sizeof(p1)); memset(q1, 0, sizeof(q1));
    memcpy(p1, p, prime_len * sizeof(sdc_word_t));
    memcpy(q1, q, prime_len * sizeof(sdc_word_t));
    sdc_int_sub_word(p1, p1, 1, rsa_len);
    sdc_int_sub_word(q1, q1, 1, rsa_len);
    memset(phi_full, 0, sizeof(phi_full));

    t0 = get_time_ms();
    sdc_int_mul(phi_full, p1, q1, rsa_len);
    t1 = get_time_ms(); t_mul += t1 - t0;

    int phi_ok = 1;
    for (size_t i = rsa_len; i < 2 * rsa_len; i++)
        if (phi_full[i] != 0) phi_ok = 0;
    T_CHECK(phi_ok, "phi = (p-1)(q-1) fits modulus width");
    memcpy(phi, phi_full, sizeof(phi));
    print_words("phi", phi, rsa_len);

    T_CHECK(sdc_int_mod_word(phi, RSA_PUB_EXP, rsa_len) != 0,
            "gcd(65537, phi) == 1");

    t0 = get_time_ms();
    memset(d, 0, sizeof(d));
    sdc_int_modinv(d, phi, RSA_PUB_EXP, rsa_len);
    t1 = get_time_ms(); t_inv += t1 - t0;
    T_CHECK(!sdc_int_eq_word(d, 0, rsa_len), "d = e^-1 mod phi is non-zero");
    print_words("d", d, rsa_len);

    for (;;) {
        ret = sdc_rng_generate(&rng_ctx, (uint8_t *)m, rsa_len * sizeof(sdc_word_t));
        if (ret != 0) { free(tmp); T_CHECK(0, "random message generation"); return; }
        if (!sdc_int_gte(m, n, rsa_len)) break;
    }
    if (sdc_int_eq_word(m, 0, rsa_len)) m[0] = 2;
    print_words("m", m, rsa_len);

    sdc_word_t ninv = sdc_int_calculate_ninv(n[0]);
    sdc_word_t mont[5 * rsa_len];
    memcpy(mont, tmp, sizeof(mont));

    t0 = get_time_ms();
    sdc_int_mont_modexp_word(c, m, e, 1, n, tmp, rsa_len, ninv);
    t1 = get_time_ms(); t_enc += t1 - t0;
    print_words("c = m^e mod n", c, rsa_len);

    t0 = get_time_ms();
    sdc_int_mont_modexp_word(m_dec, c, d, rsa_len, n, tmp, rsa_len, ninv);
    t1 = get_time_ms(); t_dec += t1 - t0;
    print_words("m_dec", m_dec, rsa_len);

    T_CHECK(eq_words(m, m_dec, rsa_len), "decrypt(encrypt(m)) == m");

    (void)mont;
    print_time("prime generation", t_gen);
    print_time("modular multiply", t_mul);
    print_time("modular inverse", t_inv);
    print_time("encrypt", t_enc);
    print_time("decrypt", t_dec);

    free(tmp);
}

int main(void) {
    T_SUITE("Prime Generation & RSA Key Generation Tests");

#if SDC_64BIT
    test_rsa_keygen(64);   /* RSA-4096 */
#else
    test_rsa_keygen(128);  /* RSA-4096 */
#endif

    T_SUMMARY();
}

#else

int main(void) {
    printf("[SKIP] INTEGER disabled in config.h\n");
    return 0;
}

#endif /* SDC_ENABLE_INTEGER */


