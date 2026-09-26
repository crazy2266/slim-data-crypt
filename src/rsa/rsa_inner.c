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
 * Core mathematical primitive for encryption and signature verification.
 * No padding is applied or removed.
 *
 * Uses variable-time exponentiation, which is acceptable for public key
 * operations where the exponent (e) is public.
 *
 * Parameters:
 *   out   - Output buffer (ciphertext or recovered data), >= pub->nlen words
 *   m     - Input data (must be < n), pub->nlen words
 *   pub   - RSA public key
 *   tmp   - Temporary buffer, must be at least 4 * pub->nlen words
 *
 * Returns: SDC_ERR_OK on success, negative on error
 */
int _sdc_rsa_public(sdc_word_t *out, const sdc_word_t *m,
                    const sdc_rsa_pubkey_t *pub, sdc_word_t *tmp)
{
    if (!out || !m || !pub || !tmp) return SDC_ERR_INVALID_PARAM;

    size_t n_len = pub->nlen;
    if (n_len == 0) return SDC_ERR_INVALID_PARAM;

    /* Ensure m < n */
    if (sdc_int_gte(m, pub->n, n_len)) return SDC_ERR_KEY_INVALID;

    sdc_word_t ninv = sdc_int_calculate_ninv(pub->n[0]);
    sdc_int_mont_modexp_with_ebits_vartime(out, m, pub->e, pub->e_bits,
                                           pub->n, tmp, n_len, ninv);
    return SDC_ERR_OK;
}

/*
 * _sdc_rsa_private
 *
 * RSA private key operation: m = c^d mod n (CRT-accelerated).
 *
 * When blinding is enabled, the exponents are randomized as follows:
 *
 *   dp_blind = dp + rp * (p - 1)
 *   dq_blind = dq + rq * (q - 1)
 *
 * where rp, rq are random integers in [1, p) and [1, q) respectively.
 * By Fermat's little theorem, for c coprime to p:
 *
 *   c^dp_blind ≡ c^dp * (c^(p-1))^rp ≡ c^dp * 1^rp ≡ c^dp  (mod p)
 *
 * so the result is unchanged, but the exponentiation path is randomized.
 *
 * IMPORTANT: dp_blind / dq_blind MUST be full (2*len1)-word values.
 * Truncating them to len1 words would change the exponent modulo the
 * group order and yield a wrong result. mont_modexp_word() accepts an
 * exponent whose length differs from the modulus length, so we pass
 * 2*len1 as elen.
 *
 * Parameters:
 *   out     - Output buffer, must have at least key->len2 words
 *   c       - Input ciphertext, must be < n, key->len2 words
 *   key     - RSA private key (CRT form)
 *   tmp     - Temporary buffer, must be at least
 *             SDC_RSA_PRIVATE_TMP_SIZE(key->len1) words
 *   rng_ctx - RNG context (required when blinding is enabled)
 *
 * Returns: SDC_ERR_OK on success, negative error code otherwise
 *
 * tmp layout (len1 = key->len1):
 *
 *   Shared (all modes):
 *     [0  .. 1*len1)  m1      (also holds rp in blinding mode)
 *     [1  .. 2*len1)  m2      (also holds rq in blinding mode)
 *     [2  .. 3*len1)  s1
 *     [3  .. 4*len1)  s2
 *     [4  .. 8*len1)  scratch (4*len1, for mont_modexp_word)
 *
 *   Blinding only:
 *     [8  .. 10*len1) dp_blind (2*len1)
 *     [10 .. 12*len1) dq_blind (2*len1)
 *     [12 .. 13*len1) rp_raw
 *     [13 .. 14*len1) rq_raw
 *     [14 .. 15*len1) p_minus_1
 *     [15 .. 16*len1) q_minus_1
 *     [16 .. 17*len1) base1   (c mod p)
 *     [17 .. 18*len1) base2   (c mod q)
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

    /* ---- Shared layout ---- */
    sdc_word_t *m1      = tmp;                 /* [0  .. 1*len1) */
    sdc_word_t *m2      = m1 + len1;           /* [1  .. 2*len1) */
    sdc_word_t *s1      = m2 + len1;           /* [2  .. 3*len1) */
    sdc_word_t *s2      = s1 + len1;           /* [3  .. 4*len1) */
    sdc_word_t *scratch = s2 + len1;           /* [4  .. 8*len1) */

    /* c mod p, c mod q */
    sdc_int_reduce(m1, c, len2, key->p, len1);
    sdc_int_reduce(m2, c, len2, key->q, len1);

    sdc_word_t pinv   = sdc_int_calculate_ninv(key->p[0]);
    sdc_word_t qinv_n = sdc_int_calculate_ninv(key->q[0]);

#if SDC_RSA_ENABLE_BLINDING
    if (!rng_ctx) return SDC_ERR_INVALID_PARAM;

    /* ---- Blinding-only regions ---- */
    sdc_word_t *dp_blind  = scratch + 4 * len1;  /* [8  .. 10*len1) */
    sdc_word_t *dq_blind  = dp_blind + 2 * len1; /* [10 .. 12*len1) */
    sdc_word_t *rp_raw    = dq_blind + 2 * len1; /* [12 .. 13*len1) */
    sdc_word_t *rq_raw    = rp_raw + len1;       /* [13 .. 14*len1) */
    sdc_word_t *p_minus_1 = rq_raw + len1;       /* [14 .. 15*len1) */
    sdc_word_t *q_minus_1 = p_minus_1 + len1;    /* [15 .. 16*len1) */
    sdc_word_t *base1     = q_minus_1 + len1;    /* [16 .. 17*len1) */
    sdc_word_t *base2     = base1 + len1;        /* [17 .. 18*len1) */

    /* Save c mod p and c mod q before m1/m2 are reused for rp/rq. */
    sdc_int_copy(base1, m1, len1);
    sdc_int_copy(base2, m2, len1);

    /* p - 1, q - 1 */
    sdc_int_sub_word(p_minus_1, key->p, 1, len1);
    sdc_int_sub_word(q_minus_1, key->q, 1, len1);

    /* rp = random in [1, p), rq = random in [1, q) */
    int ret;
    do {
        ret = sdc_rng_generate(rng_ctx, (uint8_t *)rp_raw,
                               SDC_RSA_BLINDING_WORDS * SDC_WORD_SIZE);
        if (ret != SDC_ERR_OK) return ret;
        sdc_int_reduce(m1, rp_raw, SDC_RSA_BLINDING_WORDS, key->p, len1);
    } while (sdc_int_eq_word(m1, 0, len1));

    do {
        ret = sdc_rng_generate(rng_ctx, (uint8_t *)rq_raw,
                               SDC_RSA_BLINDING_WORDS * SDC_WORD_SIZE);
        if (ret != SDC_ERR_OK) return ret;
        sdc_int_reduce(m2, rq_raw, SDC_RSA_BLINDING_WORDS, key->q, len1);
    } while (sdc_int_eq_word(m2, 0, len1));

    /*
     * dp_blind = dp + rp * (p - 1)   (full 2*len1 words)
     * dq_blind = dq + rq * (q - 1)   (full 2*len1 words)
     *
     * sdc_int_mul writes 2*len1 words and must not alias its inputs.
     * dp_blind / dq_blind are dedicated output buffers, disjoint from
     * rp/m1, rq/m2, p_minus_1, q_minus_1.
     */

    /* dp_blind = rp * (p-1), then += dp */
    sdc_int_mul(dp_blind, m1, p_minus_1, len1);
    {
        sdc_word_t carry = sdc_int_add(dp_blind, dp_blind, key->dp, len1);
        dp_blind[len1] += carry;   /* propagate carry into high half */
    }

    /* dq_blind = rq * (q-1), then += dq */
    sdc_int_mul(dq_blind, m2, q_minus_1, len1);
    {
        sdc_word_t carry = sdc_int_add(dq_blind, dq_blind, key->dq, len1);
        dq_blind[len1] += carry;
    }

    /* Modular exponentiation with full 2*len1-word exponents. */
    sdc_int_mont_modexp_word(s1, base1, dp_blind, 2 * len1,
                             key->p, scratch, len1, pinv);
    sdc_int_mont_modexp_word(s2, base2, dq_blind, 2 * len1,
                             key->q, scratch, len1, qinv_n);
#else
    sdc_int_mont_modexp_word(s1, m1, key->dp, len1,
                             key->p, scratch, len1, pinv);
    sdc_int_mont_modexp_word(s2, m2, key->dq, len1,
                             key->q, scratch, len1, qinv_n);
#endif

    /*
     * CRT recombination (Garner):
     *   t    = (s1 - s2) mod p
     *   prod = t * qinv
     *   t    = prod mod p
     *   out  = s2 + q * t
     */
    sdc_word_t *t    = scratch;              /* reuse scratch */
    sdc_word_t *prod = scratch + len1;

    sdc_int_sub(t, s1, s2, len1);
    sdc_int_add_ctl(t, key->p, len1, sdc_int_lt(s1, s2, len1));

    sdc_int_mul(prod, t, key->qinv, len1);   /* prod and t are disjoint */
    sdc_int_reduce(t, prod, len1 * 2, key->p, len1);

    sdc_int_set_word(out, 0, len2);
    sdc_int_copy(out, s2, len1);
    sdc_int_mul(prod, key->q, t, len1);      /* prod and t are disjoint */
    sdc_int_add(out, out, prod, len2);

    return SDC_ERR_OK;
}

#endif /* SDC_ENABLE_RSA */
