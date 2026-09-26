/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * RSA core internal operations (public/private).
 * These are low-level primitives used by the upper-layer RSA functions.
 */

#ifndef SDC_RSA_INNER_H
#define SDC_RSA_INNER_H

#include <sdcrypt/rsa.h>
#include <sdcrypt/platform.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Temporary buffer size for _sdc_rsa_private(), in words.
 *
 * Layout (len1 = key->len1):
 *
 *   Shared (all modes), 8 * len1:
 *     [0  .. 1*len1)  m1
 *     [1  .. 2*len1)  m2
 *     [2  .. 3*len1)  s1
 *     [3  .. 4*len1)  s2
 *     [4  .. 8*len1)  scratch (4*len1, for mont_modexp_word)
 *
 *   Blinding-only, additional 12 * len1:
 *     [8  .. 10*len1) dp_blind  (2*len1, full-width exponent)
 *     [10 .. 12*len1) dq_blind  (2*len1, full-width exponent)
 *     [12 .. 13*len1) rp_raw
 *     [13 .. 14*len1) rq_raw
 *     [14 .. 15*len1) p_minus_1
 *     [15 .. 16*len1) q_minus_1
 *     [16 .. 17*len1) base1
 *     [17 .. 18*len1) base2
 */
#if SDC_RSA_ENABLE_BLINDING
#  define SDC_RSA_PRIVATE_TMP_SIZE(len1) ((len1) * 18)
#else
#  define SDC_RSA_PRIVATE_TMP_SIZE(len1) ((len1) * 8)
#endif

/**
 * RSA public key operation: c = m^e mod n
 *
 * @param out   Output buffer, must have at least pub->nlen words
 * @param m     Input data (must be < n), pub->nlen words
 * @param pub   RSA public key
 * @param tmp   Temporary buffer, must be at least (4 * pub->nlen) words
 * @return      0 on success, negative error code otherwise
 */
int _sdc_rsa_public(sdc_word_t *out, const sdc_word_t *m,
                    const sdc_rsa_pubkey_t *pub, sdc_word_t *tmp);

/**
 * RSA private key operation: m = c^d mod n (CRT-accelerated)
 *
 * @param out     Output buffer, must have at least key->len2 words
 * @param c       Input ciphertext (must be < n), key->len2 words
 * @param key     RSA private key (CRT form)
 * @param tmp     Temporary buffer, must be at least
 *                SDC_RSA_PRIVATE_TMP_SIZE(key->len1) words
 * @param rng_ctx Random number generator context (required when
 *                SDC_RSA_ENABLE_BLINDING is enabled)
 * @return        0 on success, negative error code otherwise
 */
int _sdc_rsa_private(sdc_word_t *out, const sdc_word_t *c,
                     const sdc_rsa_privkey_t *key, sdc_word_t *tmp,
                     sdc_rng_ctx *rng_ctx);

#ifdef __cplusplus
}
#endif

#endif /* SDC_RSA_INNER_H */
