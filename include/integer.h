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

// These basic functions have no comment because the author is lazy. :)
// If you want to know more, please check the source code.

void sdc_int_set_word(uint64_t *r, uint64_t val, size_t len);
void sdc_int_copy(uint64_t *r, const uint64_t *a, size_t len);
void sdc_int_ccopy(uint64_t *dst, const uint64_t *src, size_t len, uint64_t ctl);
void sdc_int_cswap(uint64_t *a, uint64_t *b, size_t len, uint64_t ctl);
uint64_t sdc_int_eq_word(const uint64_t *a, uint64_t word, size_t len);
uint64_t sdc_int_is_odd(const uint64_t *a, size_t len);
uint64_t sdc_int_is_even(const uint64_t *a, size_t len);
uint64_t sdc_int_lt(const uint64_t *a, const uint64_t *b, size_t len);
uint64_t sdc_int_eq(const uint64_t *a, const uint64_t *b, size_t len);
uint64_t sdc_int_gte(const uint64_t *a, const uint64_t *b, size_t len);
uint64_t sdc_int_add(uint64_t *r, const uint64_t *a, const uint64_t *b, size_t len);
uint64_t sdc_int_sub(uint64_t *r, const uint64_t *a, const uint64_t *b, size_t len);
uint64_t sdc_int_add_ctl(uint64_t *a, const uint64_t *b, size_t len, uint64_t ctl);
uint64_t sdc_int_sub_ctl(uint64_t *a, const uint64_t *b, size_t len, uint64_t ctl);
uint64_t sdc_int_add_word(uint64_t *r, const uint64_t *a, uint64_t word, size_t len);
uint64_t sdc_int_sub_word(uint64_t *r, const uint64_t *a, uint64_t word, size_t len);
/*
 * Multiply two unsigned integers.
 * r should be at least 2 * len words long.
 * WARNING: r must be distinct from a and b.
 */
void sdc_int_mul(uint64_t *r, const uint64_t *a, const uint64_t *b, size_t len);

/*
 * Multiply an unsigned integer by a word.
 * r should be at least len + 1 words long.
 */
void sdc_int_mul_word(uint64_t *r, const uint64_t *a, uint64_t word, size_t len);

// Convert x (normal field) to Montgomery field.
void sdc_int_to_mont(uint64_t *x, const uint64_t *n, size_t len);

/*
 * Multiply two Montgomery numbers in the field Z_n.
 * r should be at least len words long.
 * WARNING: r must be distinct from a and b.
 */
void sdc_int_mont_mul(uint64_t *r, const uint64_t *a, const uint64_t *b, const uint64_t *n, size_t len, uint64_t ninv);

// Convert x (Montgomery field) to normal field.
void sdc_int_from_mont(uint64_t *x, const uint64_t *n, size_t len, uint64_t ninv);

/*
 * Compute a^e mod n in the field Z_n.
 * r should be at least len words long.
 * a should be in normal field, and r will be in normal field after the operation.
 * tmp should be at least 4*len words long.
 */
void sdc_int_mont_modexp_u8(uint64_t *r, const uint64_t *a, const uint8_t *e, size_t elen,
                            const uint64_t *n, uint64_t *tmp, size_t len, uint64_t ninv);

/*
 * Compute a^e mod n in the field Z_n.
 * r should be at least len words long.
 * a should be in normal field, and r will be in normal field after the operation.
 * tmp should be at least 4*len words long.
 */
void sdc_int_mont_modexp_u64(uint64_t *r, const uint64_t *a, const uint64_t *e, size_t elen,
                             const uint64_t *n, uint64_t *tmp, size_t len, uint64_t ninv);

/*
 * Compute a^e mod n in the field Z_n.
 * r should be at least len words long.
 * a should be in normal field, and r will be in normal field after the operation.
 * tmp should be at least 2*len words long.
 * WARNING: This function is not constant-time,
 *   do not use it in decryption and signing operations.
 */
void sdc_int_mont_modexp_u64_vartime(uint64_t *r, const uint64_t *a, const uint64_t *e, size_t elen,
                                     const uint64_t *n, uint64_t *tmp, size_t len, uint64_t ninv);

// return ninv. (ninv = -x^{-1} mod n)
uint64_t sdc_int_calculate_ninv(uint64_t x);

/*
 * Divide an unsigned integer by a word.
 * quo should be at least len words long.
 * rem is just a word, and it can be NULL if you don't need it.
 * WARNING: word cannot be zero, or it will cause undefined behavior.
 */
void sdc_int_div_word(uint64_t *quo, const uint64_t *a, uint64_t word, size_t len, uint64_t *rem);

/*
 * Convert a byte array to an unsigned integer in little-endian order.
 * a should be at least len words long, and in should be 8*len bytes long.
 */
void sdc_int_frombytes_le(uint64_t *a, size_t len, const uint8_t *in);

/*
 * Convert a byte array to an unsigned integer in big-endian order.
 * a should be at least len words long, and in should be 8*len bytes long.
 */
void sdc_int_frombytes_be(uint64_t *a, size_t len, const uint8_t *in);

/*
 * Convert an unsigned integer to a byte array in little-endian order.
 * a should be at least len words long, and out should be at least 8*len bytes long.
 */
void sdc_int_tobytes_le(const uint64_t *a, size_t len, uint8_t *out);

/*
 * Convert an unsigned integer to a byte array in big-endian order.
 * a should be at least len words long, and out should be at least 8*len bytes long.
 */
void sdc_int_tobytes_be(const uint64_t *a, size_t len, uint8_t *out);

/*
 * d = e^{-1} mod phi
 * phi should be at least len words long.
 * tmp should be at least (3*len+1) words long.
 * WARNING: This function is not constant-time,
 *   do not use it in high-frequency scenarios.
 */
void sdc_int_modinv(uint64_t *d, const uint64_t *phi, uint64_t e, uint64_t *tmp, size_t len);

#endif /* SDC_INTEGER_H */