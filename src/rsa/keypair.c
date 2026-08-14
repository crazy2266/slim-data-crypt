/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * RSA key generation functions.
 */

#include <sdcrypt/rsa.h>
#include <sdcrypt/mem.h>
#include <sdcrypt/integer.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/platform.h>
#include <sdcrypt/config.h>

#if SDC_ENABLE_RSA

int sdc_rsa_pubkey_init(sdc_rsa_pubkey_t *pubkey, sdc_word_t e, const uint8_t *n, size_t nlen) {
    size_t n_words = nlen / SDC_WORD_SIZE;
    if (!pubkey || !n || e == 0 || n_words == 0 || nlen % SDC_WORD_SIZE != 0) return SDC_ERR_INVALID_PARAM;
    uint8_t acc = 0;
    for (size_t i = 0; i < nlen; i++) acc |= n[i];
    if (acc == 0) return SDC_ERR_KEY_INVALID;
    sdc_word_t *N = sdc_malloc(nlen);
    if (!N) return SDC_ERR_MEM_ALLOCATE_FAIL;
    sdc_int_frombytes_be(N, n_words, n);
    pubkey->n = N;
    pubkey->nlen = n_words;
    pubkey->e = e;
    return SDC_ERR_OK;
}

static void ptr_cswap(sdc_word_t **p1, sdc_word_t **p2, sdc_word_t ctl) {
    uintptr_t mask = -(uintptr_t)(ctl & 1);
    uintptr_t val1 = (uintptr_t)*p1;
    uintptr_t val2 = (uintptr_t)*p2;
    uintptr_t diff = (val1 ^ val2) & mask;
    *p1 = (sdc_word_t *)(val1 ^ diff);
    *p2 = (sdc_word_t *)(val2 ^ diff);
}

int sdc_rsa_privkey_init(sdc_rsa_privkey_t *privkey, const uint8_t *p, const uint8_t *q, const uint8_t *dp, const uint8_t *dq, const uint8_t *qinv, size_t len1, const uint8_t *d, const uint8_t *n, size_t len2) {
    int ret = SDC_ERR_OK;
    size_t len1_words = len1 / SDC_WORD_SIZE;
    size_t len2_words = len2 / SDC_WORD_SIZE;
    if (!privkey || !p || !q || !d || !n ||
        len1_words == 0 || len2_words == 0) return SDC_ERR_INVALID_PARAM;
    sdc_word_t *P = sdc_malloc(len1);
    sdc_word_t *Q = sdc_malloc(len1);
    sdc_word_t *DP = sdc_malloc(len1);
    sdc_word_t *DQ = sdc_malloc(len1);
    sdc_word_t *QINV = sdc_malloc(len1);
    sdc_word_t *D = sdc_malloc(len2);
    sdc_word_t *N = sdc_malloc(len2);
    if (!P || !Q || !DP || !DQ || !QINV || !D || !N) {
        ret = SDC_ERR_MEM_ALLOCATE_FAIL;
        goto err_free;
    }
    sdc_int_frombytes_be(P, len1_words, p);
    sdc_int_frombytes_be(Q, len1_words, q);
    if (sdc_int_eq(P, Q, len1_words)) {
        ret = SDC_ERR_KEY_INVALID;
        goto err_free;
    }
    ptr_cswap(&P, &Q, sdc_int_lt(P, Q, len1_words));
    sdc_int_frombytes_be(D, len2_words, d);
    sdc_int_frombytes_be(N, len2_words, n);
    if (dp && dq && qinv) {
        sdc_int_frombytes_be(DP, len1_words, dp);
        sdc_int_frombytes_be(DQ, len1_words, dq);
        sdc_int_frombytes_be(QINV, len1_words, qinv);
    } else if (!dp && !dq && !qinv) {
        P[0]--; Q[0]--;
        sdc_int_reduce(DP, D, len2_words, P, len1_words);  // dp = d mod (p-1)
        sdc_int_reduce(DQ, D, len2_words, Q, len1_words);  // dq = d mod (q-1)
        P[0]++; Q[0]++;
        sdc_word_t *t = sdc_malloc(len1 * 5);
        if (!t) {
            ret = SDC_ERR_MEM_ALLOCATE_FAIL;
            goto err_free;
        }
        sdc_int_sub_word(t, P, 2, len1_words);
        sdc_word_t pinv = sdc_int_calculate_ninv(P[0]);
        sdc_int_mont_modexp_word(QINV, Q, t, len1_words, P, t + len1_words, len1_words, pinv);
        sdc_free(t);
    } else {
        ret = SDC_ERR_KEY_INVALID;
        goto err_free;
    }
    privkey->p = P;
    privkey->q = Q;
    privkey->dp = DP;
    privkey->dq = DQ;
    privkey->qinv = QINV;
    privkey->d = D;
    privkey->n = N;
    privkey->len1 = len1_words;
    privkey->len2 = len2_words;
    return SDC_ERR_OK;
err_free:
    sdc_free(P);
    sdc_free(Q);
    sdc_free(DP);
    sdc_free(DQ);
    sdc_free(QINV);
    sdc_free(D);
    sdc_free(N);
    return ret;
}

#if SDC_ENABLE_RSA_KEYGEN
int sdc_rsa_keypair(sdc_rsa_pubkey_t *pubkey, sdc_rsa_privkey_t *privkey, sdc_word_t e, size_t bits) {
    if (!pubkey || !privkey || bits == 0 || bits % SDC_WORD_BITS != 0) return SDC_ERR_INVALID_PARAM;
    int ret = SDC_ERR_OK;
    size_t len2 = bits / SDC_WORD_BITS;
    size_t len1 = len2 / 2;

    privkey->p = sdc_malloc(len1 * SDC_WORD_SIZE);
    privkey->q = sdc_malloc(len1 * SDC_WORD_SIZE);
    privkey->dp = sdc_malloc(len1 * SDC_WORD_SIZE);
    privkey->dq = sdc_malloc(len1 * SDC_WORD_SIZE);
    privkey->qinv = sdc_malloc(len1 * SDC_WORD_SIZE);
    privkey->d = sdc_malloc(len2 * SDC_WORD_SIZE);
    privkey->n = sdc_malloc(len2 * SDC_WORD_SIZE);
    if (!privkey->p || !privkey->q || !privkey->dp || !privkey->dq ||
        !privkey->qinv || !privkey->d || !privkey->n) {
        ret = SDC_ERR_MEM_ALLOCATE_FAIL;
        goto err_free_privkey;
    }

    sdc_word_t *tmp = sdc_malloc(len1 * 4 * SDC_WORD_SIZE);
    sdc_word_t *phi = sdc_malloc(len2 * SDC_WORD_SIZE);
    if (!tmp || !phi) {
        ret = SDC_ERR_MEM_ALLOCATE_FAIL;
        goto err_free_all;
    }

    /* Generate p and q (p > q) */
    ret = sdc_int_gen_prime(privkey->p, tmp, len1);
    if (ret != SDC_ERR_OK) goto err_free_all;
    do {
        ret = sdc_int_gen_prime(privkey->q, tmp, len1);
        if (ret != SDC_ERR_OK) goto err_free_all;
    } while (sdc_int_eq(privkey->p, privkey->q, len1) == 1);
    ptr_cswap(&privkey->p, &privkey->q, sdc_int_lt(privkey->p, privkey->q, len1));

    /* Calculate n = p * q */
    sdc_int_mul(privkey->n, privkey->p, privkey->q, len1);

    /* Calculate phi = (p-1)*(q-1) */
    sdc_int_sub_word(phi, privkey->p, 1, len1);
    sdc_int_sub_word(phi + len1, privkey->q, 1, len1);
    sdc_int_mul(phi, phi, phi + len1, len1);

    /* Calculate d = e^{-1} mod phi */
    sdc_int_modinv(privkey->d, phi, e, tmp, len2);

    /* Calculate CRT parameters (using phi as temporary buffer) */
    sdc_int_sub_word(phi, privkey->p, 1, len1);      // phi = p-1
    sdc_int_reduce(privkey->dp, privkey->d, len2, phi, len1);
    sdc_int_sub_word(phi, privkey->q, 1, len1);      // phi = q-1
    sdc_int_reduce(privkey->dq, privkey->d, len2, phi, len1);
    sdc_int_sub_word(phi, privkey->p, 2, len1);      // phi = p-2
    sdc_word_t pinv = sdc_int_calculate_ninv(privkey->p[0]);
    sdc_int_mont_modexp_word(privkey->qinv, privkey->q, phi, len1, privkey->p, tmp, len1, pinv);

    privkey->len1 = len1;
    privkey->len2 = len2;

    pubkey->e = e;
    pubkey->n = sdc_malloc(len2 * SDC_WORD_SIZE);
    if (!pubkey->n) {
        ret = SDC_ERR_MEM_ALLOCATE_FAIL;
        goto err_free_all;
    }
    sdc_int_copy(pubkey->n, privkey->n, len2);
    pubkey->nlen = len2;

    sdc_free(tmp);
    sdc_free(phi);
    return SDC_ERR_OK;

err_free_all:
    sdc_free(tmp);
    sdc_free(phi);
    sdc_free(pubkey->n);
err_free_privkey:
    sdc_free(privkey->p);
    sdc_free(privkey->q);
    sdc_free(privkey->dp);
    sdc_free(privkey->dq);
    sdc_free(privkey->qinv);
    sdc_free(privkey->d);
    sdc_free(privkey->n);
    return ret;
}
#endif /* SDC_ENABLE_RSA_KEYGEN */

#endif /* SDC_ENABLE_RSA */