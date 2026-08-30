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

#if SDC_RSA_ENABLE_BLINDING
#  define SDC_RSA_PRIVATE_TMP_SIZE(len1) ((len1) * 12)
#else
#  define SDC_RSA_PRIVATE_TMP_SIZE(len1) ((len1) * 8)
#endif

/**
 * RSA public key operation: c = m^e mod n
 *
 * This is the core mathematical primitive for encryption and signature
 * verification. No padding is applied or removed.
 *
 * @param out   Output buffer (ciphertext or recovered data), must have at
 *              least pub->nlen words
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
 * This is the core mathematical primitive for decryption and signing.
 * No padding is applied or removed.
 *
 * @param out     Output buffer (plaintext or signature), must have at least key->len2 words
 * @param c       Input ciphertext (must be < n), key->len2 words
 * @param key     RSA private key (CRT form)
 * @param tmp     Temporary buffer, must be at least SDC_RSA_PRIVATE_TMP_SIZE(key->len1) words
 * @param rng_ctx Random number generator context
 * @return        0 on success, negative error code otherwise
 */
int _sdc_rsa_private(sdc_word_t *out, const sdc_word_t *c,
                     const sdc_rsa_privkey_t *key, sdc_word_t *tmp,
                     sdc_rng_ctx *rng_ctx);

#ifdef __cplusplus
}
#endif

#endif /* SDC_RSA_INNER_H */