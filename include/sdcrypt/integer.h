/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Unsigned large integer arithmetic section.
 * All functions are constant-time unless explicitly noted in the comments.
 * 
 * ============================================================
 * !!! IMPORTANT PRECONDITIONS FOR ALL FUNCTIONS !!!
 * ============================================================
 * - All functions assume len > 0 unless explicitly noted.
 * - All pointer arguments (r, a, b, n, tmp, etc.) must be non-NULL (except for rem in sdc_int_div_word).
 * - Montgomery functions assume n is odd and ninv is correctly precomputed.
 * - The tmp buffer must be large enough for the specific operation.
 * - No dynamic memory allocation is performed; all buffers are caller-provided.
 *
 * Violation of these preconditions leads to undefined behavior.
 * ============================================================
 */

#ifndef SDC_INTEGER_H
#define SDC_INTEGER_H

#include <stdint.h>
#include <stddef.h>
#include <sdcrypt/platform.h>
#include <sdcrypt/config.h>

#if SDC_ENABLE_INTEGER

#ifdef __cplusplus
extern "C" {
#endif

// These basic functions have no comment because the author is lazy. :)
// If you want to know more, please check the source code.

void sdc_int_set_word(sdc_word_t *r, sdc_word_t val, size_t len);
void sdc_int_copy(sdc_word_t *r, const sdc_word_t *a, size_t len);
void sdc_int_ccopy(sdc_word_t *dst, const sdc_word_t *src, size_t len, sdc_word_t ctl);
void sdc_int_cswap(sdc_word_t *a, sdc_word_t *b, size_t len, sdc_word_t ctl);
sdc_word_t sdc_int_eq_word(const sdc_word_t *a, sdc_word_t word, size_t len);
sdc_word_t sdc_int_is_odd(const sdc_word_t *a, size_t len);
sdc_word_t sdc_int_is_even(const sdc_word_t *a, size_t len);
sdc_word_t sdc_int_lt(const sdc_word_t *a, const sdc_word_t *b, size_t len);
sdc_word_t sdc_int_eq(const sdc_word_t *a, const sdc_word_t *b, size_t len);
sdc_word_t sdc_int_gte(const sdc_word_t *a, const sdc_word_t *b, size_t len);
sdc_word_t sdc_int_add(sdc_word_t *r, const sdc_word_t *a, const sdc_word_t *b, size_t len);
sdc_word_t sdc_int_sub(sdc_word_t *r, const sdc_word_t *a, const sdc_word_t *b, size_t len);
sdc_word_t sdc_int_add_ctl(sdc_word_t *a, const sdc_word_t *b, size_t len, sdc_word_t ctl);
sdc_word_t sdc_int_sub_ctl(sdc_word_t *a, const sdc_word_t *b, size_t len, sdc_word_t ctl);
sdc_word_t sdc_int_add_word(sdc_word_t *r, const sdc_word_t *a, sdc_word_t word, size_t len);
sdc_word_t sdc_int_sub_word(sdc_word_t *r, const sdc_word_t *a, sdc_word_t word, size_t len);
sdc_word_t sdc_int_add_word_vartime(sdc_word_t *r, const sdc_word_t *a, sdc_word_t word, size_t len);
sdc_word_t sdc_int_sub_word_vartime(sdc_word_t *r, const sdc_word_t *a, sdc_word_t word, size_t len);
void sdc_int_shr1(sdc_word_t *x, size_t len);
// WARNING: This function has branches, please use it cautiously.
void sdc_int_shr(sdc_word_t *x, size_t bits, size_t len);
// WARNING: This function is not constant-time.
size_t sdc_int_ctz(const sdc_word_t *x, size_t len);

/*
 * Multiply two unsigned integers.
 * r should be at least 2*len words long.
 * a,b should be at least len words long.
 * WARNING: r must be distinct from a and b.
 */
void sdc_int_mul(sdc_word_t *r, const sdc_word_t *a, const sdc_word_t *b, size_t len);

/*
 * Constant-time divide two unsigned integers.
 * q should be at least alen words long.
 * r should be at least blen words long.
 * a,b should be at least alen words long.
 * WARNING: q,r must be distinct from a and b, and b shouldn't be zero.
 */
void sdc_int_div(sdc_word_t *q, sdc_word_t *r, const sdc_word_t *a, size_t alen, 
                 const sdc_word_t *b, size_t blen);

/*
 * Return r = x mod n.
 * r,n should be at least n_len words long.
 * x should be at least x_len words long.
 * WARNING: r must be distinct from x and n.
 */
void sdc_int_reduce(sdc_word_t *r, const sdc_word_t *x, size_t x_len, const sdc_word_t *n, size_t n_len);

/*
 * Multiply an unsigned integer by a word.
 * r should be at least (len+1) words long.
 * a should be at least len words long.
 */
void sdc_int_mul_word(sdc_word_t *r, const sdc_word_t *a, sdc_word_t word, size_t len);

/*
 * Precompute R2 for Montgomery reduction.
 * R2, n should be at least len words long.
 * R2 = 2^(2 * len * SDC_WORD_BITS) mod n.
 */
void sdc_int_precompute_R2(sdc_word_t *R2, const sdc_word_t *n, size_t len);

/*
 * Convert x (normal field) to Montgomery field.
 * x,n should be at least len words long.
 */
void sdc_int_to_mont(sdc_word_t *x, const sdc_word_t *n, size_t len);

/*
 * Convert a (normal field) to Montgomery field with R2.
 * x = Montmul(a, R2) = aR mod n.
 * x,a,R2,n should be at least len words long.
 * WARNING: x must be distinct from a,n and R2.
 */
void sdc_int_to_mont_with_R2(sdc_word_t *x, const sdc_word_t *a, const sdc_word_t *R2, const sdc_word_t *n, size_t len, sdc_word_t ninv);

/*
 * Multiply two Montgomery numbers in the field Z_n.
 * r,a,b,n should be at least len words long.
 * ninv should be precomputed by sdc_int_calculate_ninv.
 * WARNING: r must be distinct from a and b.
 */
void sdc_int_mont_mul(sdc_word_t *r, const sdc_word_t *a, const sdc_word_t *b, const sdc_word_t *n, size_t len, sdc_word_t ninv);

/*
 * Convert x (Montgomery field) to normal field.
 * x,n should be at least len words long.
 * ninv should be precomputed by sdc_int_calculate_ninv.
 */
void sdc_int_from_mont(sdc_word_t *x, const sdc_word_t *n, size_t len, sdc_word_t ninv);

/*
 * Compute a^e mod n in the field Z_n.
 * r,a,n should be at least len words long.
 * a should be in normal field, and r will be in normal field after the operation.
 * tmp should be at least 4*len words long.
 * ninv should be precomputed by sdc_int_calculate_ninv.
 * ATTENTION: e must be in big-endian format.
 */
void sdc_int_mont_modexp_u8(sdc_word_t *r, const sdc_word_t *a, const uint8_t *e, size_t elen,
                            const sdc_word_t *n, sdc_word_t *tmp, size_t len, sdc_word_t ninv);

/*
 * Compute a^e mod n in the field Z_n.
 * r,a,n should be at least len words long.
 * a should be in normal field, and r will be in normal field after the operation.
 * tmp should be at least 4*len words long.
 * ninv should be precomputed by sdc_int_calculate_ninv.
 * ATTENTION: e must be in little-endian format.
 */
void sdc_int_mont_modexp_word(sdc_word_t *r, const sdc_word_t *a, const sdc_word_t *e, size_t elen,
                              const sdc_word_t *n, sdc_word_t *tmp, size_t len, sdc_word_t ninv);

/*
 * Compute a^e mod n in the field Z_n.
 * r,a,n should be at least len words long.
 * a should be in normal field, and r will be in normal field after the operation.
 * tmp should be at least 2*len words long.
 * ninv should be precomputed by sdc_int_calculate_ninv.
 */
void sdc_int_mont_modexp_with_ebits_vartime(sdc_word_t *r, const sdc_word_t *a, const sdc_word_t e, size_t e_bits,
            const sdc_word_t *n, sdc_word_t *tmp, size_t len, sdc_word_t ninv);

/*
 * Compute a^e mod n in the field Z_n.
 * r,a,n should be at least len words long.
 * a should be in normal field, and r will be in normal field after the operation.
 * tmp should be at least 2*len words long.
 * ninv should be precomputed by sdc_int_calculate_ninv.
 * ATTENTION: e must be in little-endian format.
 * WARNING: This function is not constant-time,
 *   do not use it in decryption and signing operations.
 */
void sdc_int_mont_modexp_word_vartime(sdc_word_t *r, const sdc_word_t *a, const sdc_word_t *e, size_t elen,
                                      const sdc_word_t *n, sdc_word_t *tmp, size_t len, sdc_word_t ninv);

// return ninv. (ninv = -x^{-1} mod n)
sdc_word_t sdc_int_calculate_ninv(sdc_word_t x);

/*
 * Divide an unsigned integer by a word.
 * quo,a should be at least len words long.
 * rem is just a word, and it can be NULL if you don't need it.
 * WARNING: word cannot be zero, or the function will return immediately without setting quo or rem.
 */
void sdc_int_div_word(sdc_word_t *quo, const sdc_word_t *a, sdc_word_t word, size_t len, sdc_word_t *rem);

/*
 * Compute the remainder of dividing an unsigned integer by a word.
 * a should be at least len words long.
 * WARNING: word cannot be zero, or the function will return immediately without setting rem.
 */
sdc_word_t sdc_int_mod_word(const sdc_word_t *a, sdc_word_t word, size_t len);

/*
 * Convert a byte array to an unsigned integer in little-endian order.
 * a should be at least len words long, and in should be 8*len bytes long.
 */
void sdc_int_frombytes_le(sdc_word_t *a, size_t len, const uint8_t *in);

/*
 * Convert a byte array to an unsigned integer in big-endian order.
 * a should be at least len words long, and in should be 8*len bytes long.
 */
void sdc_int_frombytes_be(sdc_word_t *a, size_t len, const uint8_t *in);

/*
 * Convert an unsigned integer to a byte array in little-endian order.
 * a should be at least len words long, and out should be at least 8*len bytes long.
 */
void sdc_int_tobytes_le(const sdc_word_t *a, size_t len, uint8_t *out);

/*
 * Convert an unsigned integer to a byte array in big-endian order.
 * a should be at least len words long, and out should be at least 8*len bytes long.
 */
void sdc_int_tobytes_be(const sdc_word_t *a, size_t len, uint8_t *out);

/*
 * d = e^{-1} mod phi
 * d,phi should be at least len words long.
 */
void sdc_int_modinv(sdc_word_t *d, const sdc_word_t *phi, sdc_word_t e, size_t len);

/*
 * Generate a random prime number with len words long.
 * The highest 2 bits of x will be set to 1 to ensure n (n = p * q) is
 *   actually 2048,3072,4096,etc. bits long.
 * tmp should be at least 5*len words long.
 * WARNING: x will be (SDC_WORD_BITS * len) bits long.
 *   This is a design choice to keep the implementation simple and efficient.
 *   If you need arbitrary bit lengths, consider using a higher-level wrapper.
 * 
 * return values:
 *   SDC_ERR_OK: success
 *   SDC_ERR_RANDOM_FAIL: random number generation failed
 *   SDC_ERR_INVALID_PARAM: invalid input
 *   SDC_ERR_INTEGER_GENPRIME_TIMEOUT: failed to find a prime within the maximum attempts.
 */
int sdc_int_gen_prime(sdc_word_t *x, sdc_word_t *tmp, size_t len);

// A helper function to calculate the length of an unsigned integer in words.
static inline size_t sdc_get_len_by_bits(size_t bits) {
    if (bits == 0) return 0;
    return (bits + SDC_WORD_BITS - 1) / SDC_WORD_BITS;
}

#ifdef __cplusplus
}
#endif

#endif /* SDC_ENABLE_INTEGER */

#endif /* SDC_INTEGER_H */