/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 * 
 * The implementation of integer prime number functions.
 */

#include "config.h"
#include "integer.h"
#include "random.h"
#include "utils.h"

#if SDC_ENABLE_INTEGER

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
 * This ensures that the number has exactly `64 * len` bits and is large enough
 * that `n = p * q` will have the desired bit length.
 */
static int int_gen_random_odd(uint64_t *x, size_t len) {
    if (len == 0) return -1;
    int ret = sdc_random_bytes((uint8_t *)x, len * sizeof(uint64_t));
    if (ret != 0) return ret;
    x[0] |= 1;                           /* Set the least significant bit to 1 */
    x[len - 1] |= 0xC000000000000000ULL; /* Set the highest two bits to 1 */
    return 0;
}

/*
 * Check if a number is divisible by any of the small primes.
 * This is a fast pre-screening step before Miller-Rabin.
 */
static int is_divisible_by_small_prime(const uint64_t *x, size_t len) {
    for (size_t i = 0; i < SMALL_PRIMES_COUNT; i++) {
        uint64_t rem = sdc_int_mod_word(x, SMALL_PRIMES[i], len);
        if (rem == 0) return 1;
    }
    return 0;
}

/*
 * Miller-Rabin primality test using deterministic bases.
 * 
 * For numbers < 2^64, the bases {2, 3, 5, 7, 11, 13, 17} are sufficient.
 * For larger numbers, we use a wider set of bases to reduce error probability.
 */
static int is_prime(const uint64_t *x, size_t len, uint64_t *tmp) {
    
}

int sdc_int_gen_prime(uint64_t *x, uint64_t *tmp, size_t len) {
    
}

#endif /* SDC_ENABLE_INTEGER */