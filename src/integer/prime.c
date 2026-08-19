/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 * 
 * The implementation of integer prime number functions.
 */

#include <sdcrypt/config.h>
#include <sdcrypt/integer.h>
#include <sdcrypt/platform.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/random.h>
#include <sdcrypt/utils.h>

#if SDC_ENABLE_INTEGER

#define GEN_PRIME_MAX_ATTEMPT 10000

static const uint32_t SMALL_PRIMES[168] = {
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
    31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
    127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
    179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
    283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
    353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
    419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
    467, 479, 487, 491, 499, 503, 509, 521, 523, 541,
    547, 557, 563, 569, 571, 577, 587, 593, 599, 601,
    607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
    661, 673, 677, 683, 691, 701, 709, 719, 727, 733,
    739, 743, 751, 757, 761, 769, 773, 787, 797, 809,
    811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
    877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
    947, 953, 967, 971, 977, 983, 991, 997
};
#define SMALL_PRIMES_COUNT 168

/*
 * Generate a random odd number with the highest two bits set to 1.
 * This ensures that the number has exactly `SDC_WORD_BITS * len` bits and is large enough
 * that `n = p * q` will have the desired bit length.
 */
static int int_gen_random_odd(sdc_word_t *x, size_t len) {
    if (len == 0) return SDC_ERR_INVALID_PARAM;
    int ret = sdc_random_bytes((uint8_t *)x, len * SDC_WORD_SIZE);
    if (ret != 0) return ret;
    x[0] |= 1;                           /* Set the least significant bit to 1 */
#if SDC_64BIT
    x[len - 1] |= 0xC000000000000000ULL;
#elif SDC_32BIT
    x[len - 1] |= 0xC0000000U;
#endif
    return SDC_ERR_OK;
}

/*
 * Check if a number is divisible by any of the small primes.
 * This is a fast pre-screening step before Miller-Rabin.
 */
static int is_divisible_by_small_prime(const sdc_word_t *x, size_t len) {
    for (size_t i = 0; i < SMALL_PRIMES_COUNT; i++) {
        sdc_word_t rem = sdc_int_mod_word(x, SMALL_PRIMES[i], len);
        if (rem == 0) return 1;
    }
    return 0;
}

/*
 * Miller-Rabin primality test using deterministic bases.
 * 
 * For numbers that fit in a single word, the bases {2, 3, 5, 7, 11, 13, 17} are sufficient.
 * For larger numbers, we use a wider set of bases to reduce error probability.
 */
static int is_prime(const sdc_word_t *x, size_t len, sdc_word_t *tmp) {
    /*
     * tmp layout:
     *   tmp[0 .. len-1]     = d, where x - 1 = d * 2^s
     *   tmp[len .. 2*len-1] = scratch for modular exponentiation
     *   tmp[3*len .. 4*len-1] = result for Miller-Rabin test
     *   tmp[4*len .. 5*len-1] = minus_one for Miller-Rabin test
     */
    static const sdc_word_t bases_small[] = { 2, 3, 5, 7, 11, 13, 17 };
    static const sdc_word_t bases_large[] = {
        2, 3, 5, 7, 11, 13, 17, 19,
        23, 29, 31, 37, 41, 43, 47, 53,
        59, 61, 67, 71, 73, 79, 83, 89,
        97, 101, 103, 107, 109, 113, 127, 131
    };
    size_t base_count, s, i, j;
    sdc_word_t *d = tmp;
    sdc_word_t *scratch = tmp + len;
    sdc_word_t *result = tmp + 3 * len;
    sdc_word_t *minus_one = tmp + 4 * len;
    sdc_word_t ninv;
    const sdc_word_t *bases;

    if (len == 0) return 0;

    /* 0 and 1 are not prime. */
    if (sdc_int_eq_word(x, 0, len) || sdc_int_eq_word(x, 1, len)) return 0;

    /* Even numbers are composite, except for 2. */
    if (sdc_int_is_even(x, len)) return sdc_int_eq_word(x, 2, len) ? 1 : 0;

    /* Write x - 1 = d * 2^s, with d odd. */
    sdc_int_sub_word(d, x, 1, len);
    s = sdc_int_ctz(d, len);
    sdc_int_shr(d, s, len);

    /* x is odd, so its low word is invertible modulo 2^SDC_WORD_BITS. */
    ninv = sdc_int_calculate_ninv(x[0]);

    if (len == 1) {
        bases = bases_small;
        base_count = sizeof(bases_small) / sizeof(bases_small[0]);
    } else {
        bases = bases_large;
        base_count = sizeof(bases_large) / sizeof(bases_large[0]);
    }

    sdc_int_copy(minus_one, x, len);
    sdc_int_sub_word(minus_one, minus_one, 1, len);

    for (i = 0; i < base_count; i++) {
        sdc_word_t base = bases[i];
        int witness_passed = 0;

        /* For tiny standalone inputs, reduce a base that is >= x. */
        if (len == 1 && base >= x[0]) base %= x[0];
        if (base == 0) continue;

        sdc_int_set_word(result, base, len);
        sdc_int_mont_modexp_word_vartime(
            result, result, d, len, x, scratch, len, ninv);

        if (sdc_int_eq_word(result, 1, len) ||
            sdc_int_eq(result, minus_one, len)) {
            witness_passed = 1;
            continue;
        }

        for (j = 1; j < s; j++) {
            sdc_int_mont_modexp_with_ebits_vartime(
                result, result, 2, 2, x, scratch, len, ninv);
            if (sdc_int_eq(result, minus_one, len)) {
                witness_passed = 1;
                break;
            }
            if (sdc_int_eq_word(result, 1, len)) return 0;
        }
        if (!witness_passed) return 0;
    }
    return 1;
}

int sdc_int_gen_prime(sdc_word_t *x, sdc_word_t *tmp, size_t len) {
    if (x == NULL || tmp == NULL || len == 0) return SDC_ERR_INVALID_PARAM;
    int attempt = 0;
    while (attempt < GEN_PRIME_MAX_ATTEMPT) {
        attempt++;
        int ret = int_gen_random_odd(x, len);
        if (ret != 0) return ret;
        /* Fast rejection before the expensive Miller-Rabin test. */
        if (is_divisible_by_small_prime(x, len)) continue;
        if (is_prime(x, len, tmp)) return 0;
    }
    /* Failed to find a prime within the maximum attempts. */
    return SDC_ERR_INTEGER_GENPRIME_TIMEOUT;
}

#endif /* SDC_ENABLE_INTEGER */