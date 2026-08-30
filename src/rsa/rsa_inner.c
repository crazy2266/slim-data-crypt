/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * RSA core internal operations (public/private).
 */

#include <sdcrypt/rsa.h>
#include <sdcrypt/rng.h>
#include <sdcrypt/integer.h>
#include <sdcrypt/errcode.h>
#include "./rsa_inner.h"

#if SDC_ENABLE_RSA
#define SDC_RSA_BLINDING_WORDS (SDC_RSA_BLINDING_BITS / SDC_WORD_BITS)

/*
 * _sdc_rsa_public
 * 
 * RSA public key operation: c = m^e mod n
 * 
 * This is the core mathematical primitive for encryption and signature verification.
 * No padding is applied or removed.
 * 
 * This implementation uses a variable-time exponentiation, which is acceptable for
 * public key operations where the exponent (e) is known and not secret.
 * 
 * Parameters:
 *   out   - Output buffer (ciphertext or recovered data), must have at least pub->nlen words
 *   m     - Input data (must be < n), pub->nlen words
 *   pub   - RSA public key
 *   tmp   - Temporary buffer, must be at least 4 * pub->nlen words
 * 
 * Returns: 0 on success, negative on error
 */
int _sdc_rsa_public(sdc_word_t *out, const sdc_word_t *m,
                    const sdc_rsa_pubkey_t *pub, sdc_word_t *tmp) {
    if (!out || !m || !pub || !tmp) return SDC_ERR_INVALID_PARAM;
    size_t n_len = pub->nlen;
    if (n_len == 0) return SDC_ERR_INVALID_PARAM;
    /* Ensure m < n */
    if (sdc_int_gte(m, pub->n, n_len)) return SDC_ERR_KEY_INVALID;
    sdc_word_t ninv = sdc_int_calculate_ninv(pub->n[0]);
    sdc_int_mont_modexp_with_ebits_vartime(out, m, pub->e, pub->e_bits, pub->n, tmp, n_len, ninv);
    return SDC_ERR_OK;
}

/*
 * _sdc_rsa_private
 *
 * RSA private key operation: m = c^d mod n (CRT-accelerated)
 *
 * Parameters:
 *   out     - Output buffer, must have at least key->len2 words
 *   c       - Input ciphertext, must be < n, key->len2 words
 *   key     - RSA private key (CRT form)
 *   tmp     - Temporary buffer, must be at least (key->len1 * 12) words
 *   rng_ctx - RNG context (required when blinding is enabled)
 *
 * Returns: 0 on success, negative error code otherwise
 *
 * tmp layout ((8 or 12) * len1 words total):
 *   [0 .. len1-1]         = m1 (reused as dp_blind in blinding mode)
 *   [len1 .. 2*len1-1]    = m2 (reused as dq_blind in blinding mode)
 *   [2*len1 .. 3*len1-1]  = s1
 *   [3*len1 .. 4*len1-1]  = s2
 *   [4*len1 .. 8*len1-1]  = scratch (4*len1 words)
 *   [8*len1 .. 12*len1-1] = extra (4*len1 words, for blinding temp)
 */
int _sdc_rsa_private(sdc_word_t *out, const sdc_word_t *c,
                     const sdc_rsa_privkey_t *key, sdc_word_t *tmp,
                     sdc_rng_ctx *rng_ctx)
{
    if (!out || !c || !key || !tmp) return SDC_ERR_INVALID_PARAM;

    size_t len1 = key->len1;
    size_t len2 = key->len2;

    if (len1 == 0 || len2 == 0) return SDC_ERR_INVALID_PARAM;
    if (sdc_int_gte(c, key->n, len2)) return SDC_ERR_KEY_INVALID;

    sdc_word_t *m1 = tmp;
    sdc_word_t *m2 = m1 + len1;
    sdc_word_t *s1 = m2 + len1;
    sdc_word_t *s2 = s1 + len1;
    sdc_word_t *scratch = s2 + len1;        /* 4 * len1 words */
#if SDC_RSA_ENABLE_BLINDING
    sdc_word_t *extra = scratch + 4 * len1; /* 4 * len1 words */
#endif

    sdc_int_reduce(m1, c, len2, key->p, len1);
    sdc_int_reduce(m2, c, len2, key->q, len1);

    sdc_word_t pinv = sdc_int_calculate_ninv(key->p[0]);
    sdc_word_t qinv_n = sdc_int_calculate_ninv(key->q[0]);

#if SDC_RSA_ENABLE_BLINDING
    if (!rng_ctx) return SDC_ERR_INVALID_PARAM;

    sdc_word_t *p_minus_1 = scratch;
    sdc_word_t *q_minus_1 = scratch + len1;
    sdc_word_t *rp = q_minus_1 + len1;
    sdc_word_t *rq = rp + SDC_RSA_BLINDING_WORDS;
    sdc_word_t *rp_raw = extra;
    sdc_word_t *rq_raw = rp_raw + len1;
    sdc_word_t *base1 = rq_raw + len1;
    sdc_word_t *base2 = base1 + len1;

    sdc_int_copy(base1, m1, len1);
    sdc_int_copy(base2, m2, len1);

    sdc_int_sub_word(p_minus_1, key->p, 1, len1);
    sdc_int_sub_word(q_minus_1, key->q, 1, len1);

    int ret = SDC_ERR_OK;
    do {
        ret = sdc_rng_generate(rng_ctx, (uint8_t *)rp_raw, SDC_RSA_BLINDING_WORDS * SDC_WORD_SIZE);
        if (ret != SDC_ERR_OK) return ret;
        sdc_int_reduce(rp, rp_raw, SDC_RSA_BLINDING_WORDS, key->p, len1);
    } while (sdc_int_eq_word(rp, 0, len1));

    do {
        ret = sdc_rng_generate(rng_ctx, (uint8_t *)rq_raw, SDC_RSA_BLINDING_WORDS * SDC_WORD_SIZE);
        if (ret != SDC_ERR_OK) return ret;
        sdc_int_reduce(rq, rq_raw, SDC_RSA_BLINDING_WORDS, key->q, len1);
    } while (sdc_int_eq_word(rq, 0, len1));

    /* dp_blind = dp + rp * (p - 1), reuse m1 */
    sdc_int_mul(scratch, rp, p_minus_1, len1);
    sdc_int_add(m1, key->dp, scratch, len1);

    /* dq_blind = dq + rq * (q - 1), reuse m2 */
    sdc_int_mul(scratch, rq, q_minus_1, len1);
    sdc_int_add(m2, key->dq, scratch, len1);

    sdc_int_mont_modexp_word(s1, base1, m1, len1, key->p, scratch, len1, pinv);
    sdc_int_mont_modexp_word(s2, base2, m2, len1, key->q, scratch, len1, qinv_n);
#else
    sdc_int_mont_modexp_word(s1, m1, key->dp, len1, key->p, scratch, len1, pinv);
    sdc_int_mont_modexp_word(s2, m2, key->dq, len1, key->q, scratch, len1, qinv_n);
#endif

    sdc_word_t *t = scratch;
    sdc_word_t *prod = scratch + len1;

    sdc_int_sub(t, s1, s2, len1);
    sdc_int_add_ctl(t, key->p, len1, sdc_int_lt(s1, s2, len1));

    sdc_int_mul(prod, t, key->qinv, len1);
    sdc_int_reduce(t, prod, len1 * 2, key->p, len1);

    sdc_int_set_word(out, 0, len2);
    sdc_int_copy(out, s2, len1);
    sdc_int_mul(prod, key->q, t, len1);
    sdc_int_add(out, out, prod, len2);

    return SDC_ERR_OK;
}

#endif /* SDC_ENABLE_RSA */