/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * RSA key pair generation and initialization.
 */

#include <sdcrypt/rsa.h>
#include <sdcrypt/mem.h>
#include <sdcrypt/utils.h>
#include <sdcrypt/integer.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/platform.h>
#include <sdcrypt/config.h>

#if SDC_ENABLE_RSA

/* ============================================================
   Pointer swap
   ============================================================ */
static void ptr_cswap(sdc_word_t **p1, sdc_word_t **p2, sdc_word_t ctl) {
    uintptr_t mask = (uintptr_t)(0 - (ctl & 1));
    uintptr_t val1 = (uintptr_t)*p1;
    uintptr_t val2 = (uintptr_t)*p2;
    uintptr_t diff = (val1 ^ val2) & mask;
    *p1 = (sdc_word_t *)(val1 ^ diff);
    *p2 = (sdc_word_t *)(val2 ^ diff);
}

/* ============================================================
   Public key initialization
   ============================================================ */
int sdc_rsa_pubkey_init(sdc_rsa_pubkey_t *pubkey,
                        const uint8_t *n, size_t nlen,
                        sdc_word_t e) {
    size_t n_words = nlen / SDC_WORD_SIZE;
    size_t left_n  = nlen % SDC_WORD_SIZE;
    if (!pubkey || !n || (e & 1) == 0 || n_words == 0 || left_n != 0) {
        return SDC_ERR_INVALID_PARAM;
    }

    uint8_t acc = 0;
    for (size_t i = 0; i < nlen; i++) acc |= n[i];
    if (acc == 0) return SDC_ERR_KEY_INVALID;

    sdc_word_t *N = sdc_malloc(nlen);
    if (!N) return SDC_ERR_MEM_ALLOCATE_FAIL;

    sdc_int_frombytes_be(N, n_words, n);
    pubkey->n = N;
    pubkey->nlen = n_words;
    pubkey->e = e;
    pubkey->e_bits = SDC_WORD_BITS - sdc_word_clz(e);
    return SDC_ERR_OK;
}

/* ============================================================
   Private key initialization
   ============================================================ */
int sdc_rsa_privkey_init(sdc_rsa_privkey_t *privkey,
                         const uint8_t *p, const uint8_t *q,
                         const uint8_t *dp, const uint8_t *dq,
                         const uint8_t *qinv, size_t len1,
                         const uint8_t *d, const uint8_t *n,
                         size_t len2) {
    if (!privkey) return SDC_ERR_INVALID_PARAM;
    memset(privkey, 0, sizeof(sdc_rsa_privkey_t));

    size_t len1_words = len1 / SDC_WORD_SIZE;
    size_t left1      = len1 % SDC_WORD_SIZE;
    size_t len2_words = len2 / SDC_WORD_SIZE;
    size_t left2      = len2 % SDC_WORD_SIZE;

    if (!p || !q || !d || !n ||
        len1_words == 0 || len2_words == 0 ||
        (d[0] & 1) == 0 ||
        left1 != 0 || left2 != 0 ||
        len2 != len1 * 2) {
        return SDC_ERR_INVALID_PARAM;
    }

    size_t total_words = len1_words * 5 + len2_words * 2;
    sdc_word_t *block = sdc_malloc(total_words * SDC_WORD_SIZE);
    if (!block) return SDC_ERR_MEM_ALLOCATE_FAIL;

    privkey->_block_start = block;
    privkey->p    = block;
    privkey->q    = block + len1_words;
    privkey->dp   = block + len1_words * 2;
    privkey->dq   = block + len1_words * 3;
    privkey->qinv = block + len1_words * 4;
    privkey->d    = block + len1_words * 5;
    privkey->n    = block + len1_words * 5 + len2_words;
    privkey->len1 = len1_words;
    privkey->len2 = len2_words;

    sdc_int_frombytes_be(privkey->p, len1_words, p);
    sdc_int_frombytes_be(privkey->q, len1_words, q);

    if (sdc_int_eq(privkey->p, privkey->q, len1_words)) {
        sdc_free(block);
        privkey->_block_start = NULL;
        return SDC_ERR_KEY_INVALID;
    }

    ptr_cswap(&privkey->p, &privkey->q,
              sdc_int_lt(privkey->p, privkey->q, len1_words));

    sdc_int_frombytes_be(privkey->d, len2_words, d);
    sdc_int_frombytes_be(privkey->n, len2_words, n);

    if (dp && dq && qinv) {
        sdc_int_frombytes_be(privkey->dp, len1_words, dp);
        sdc_int_frombytes_be(privkey->dq, len1_words, dq);
        sdc_int_frombytes_be(privkey->qinv, len1_words, qinv);
    } else if (!dp && !dq && !qinv) {
        sdc_word_t *P = privkey->p;
        sdc_word_t *Q = privkey->q;
        sdc_word_t *DP = privkey->dp;
        sdc_word_t *DQ = privkey->dq;
        sdc_word_t *QINV = privkey->qinv;
        sdc_word_t *D = privkey->d;

        P[0]--; Q[0]--;
        sdc_int_reduce(DP, D, len2_words, P, len1_words);
        sdc_int_reduce(DQ, D, len2_words, Q, len1_words);
        P[0]++; Q[0]++;

        sdc_word_t *tmp = sdc_malloc(len1_words * 2 * SDC_WORD_SIZE);
        if (!tmp) {
            sdc_free(block);
            privkey->_block_start = NULL;
            return SDC_ERR_MEM_ALLOCATE_FAIL;
        }

        sdc_int_sub_word(tmp, P, 2, len1_words);
        sdc_word_t pinv = sdc_int_calculate_ninv(P[0]);
        sdc_int_mont_modexp_word(QINV, Q, tmp, len1_words,
                                 P, tmp + len1_words, len1_words, pinv);
        sdc_free(tmp);
    } else {
        sdc_free(block);
        privkey->_block_start = NULL;
        return SDC_ERR_KEY_INVALID;
    }
    return SDC_ERR_OK;
}

/* ============================================================
   Key pair cleanup
   ============================================================ */
void sdc_rsa_free_keypair(sdc_rsa_pubkey_t *pubkey,
                          sdc_rsa_privkey_t *privkey) {
    if (pubkey) {
        if (pubkey->n) sdc_free(pubkey->n);
        sdc_secure_memzero(pubkey, sizeof(sdc_rsa_pubkey_t));
    }
    if (privkey) {
        if (privkey->_block_start) sdc_free(privkey->_block_start);
        sdc_secure_memzero(privkey, sizeof(sdc_rsa_privkey_t));
    }
}

/* ============================================================
   RSA key pair generation
   ============================================================ */
#if SDC_ENABLE_RSA_KEYGEN
int sdc_rsa_keypair(sdc_rsa_pubkey_t *pubkey,
                    sdc_rsa_privkey_t *privkey,
                    sdc_word_t e,
                    size_t bits) {
    if (!pubkey || !privkey || bits == 0 || (e & 1) == 0 ||
        bits % SDC_WORD_BITS != 0) {
        return SDC_ERR_INVALID_PARAM;
    }

    memset(privkey, 0, sizeof(sdc_rsa_privkey_t));
    memset(pubkey, 0, sizeof(sdc_rsa_pubkey_t));

    int ret = SDC_ERR_OK;
    size_t len2 = bits / SDC_WORD_BITS;
    size_t len1 = len2 / 2;

    if (len1 == 0 || len2 == 0) return SDC_ERR_INVALID_PARAM;

    /* Allocate private key block */
    size_t total_words = len1 * 5 + len2 * 2;
    sdc_word_t *block = sdc_malloc(total_words * SDC_WORD_SIZE);
    if (!block) return SDC_ERR_MEM_ALLOCATE_FAIL;

    privkey->_block_start = block;
    privkey->p    = block;
    privkey->q    = block + len1;
    privkey->dp   = block + len1 * 2;
    privkey->dq   = block + len1 * 3;
    privkey->qinv = block + len1 * 4;
    privkey->d    = block + len1 * 5;
    privkey->n    = block + len1 * 5 + len2;
    privkey->len1 = len1;
    privkey->len2 = len2;

    /*
     * Temporary workspace:
     *   p_minus_1, q_minus_1 (len1 each)
     *   phi (len2)
     *   scratch (len1 * 5, enough for gen_prime and mont_exp)
     */
    size_t scratch_words = len1 * 5;
    size_t total_tmp_words = len1 * 2 + len2 + scratch_words;
    sdc_word_t *tmp_block = sdc_malloc(total_tmp_words * SDC_WORD_SIZE);
    if (!tmp_block) {
        ret = SDC_ERR_MEM_ALLOCATE_FAIL;
        goto err_free_privkey;
    }

    sdc_word_t *p_minus_1 = tmp_block;
    sdc_word_t *q_minus_1 = p_minus_1 + len1;
    sdc_word_t *phi = q_minus_1 + len1;
    sdc_word_t *scratch = phi + len2;

    /* Generate p */
    ret = sdc_int_gen_prime(privkey->p, scratch, len1);
    if (ret != SDC_ERR_OK) goto err_free_all;

    /* Generate q, ensure q != p */
    do {
        ret = sdc_int_gen_prime(privkey->q, scratch, len1);
        if (ret != SDC_ERR_OK) goto err_free_all;
    } while (sdc_int_eq(privkey->p, privkey->q, len1) == 1);

    /* Ensure p > q */
    ptr_cswap(&privkey->p, &privkey->q, sdc_int_lt(privkey->p, privkey->q, len1));

    /* n = p * q */
    sdc_int_mul(privkey->n, privkey->p, privkey->q, len1);

    /* phi = (p - 1) * (q - 1) */
    sdc_int_sub_word(p_minus_1, privkey->p, 1, len1);
    sdc_int_sub_word(q_minus_1, privkey->q, 1, len1);
    sdc_int_mul(phi, p_minus_1, q_minus_1, len1);

    /* d = e^{-1} mod phi */
    sdc_int_modinv(privkey->d, phi, e, scratch, len2);

    /* CRT parameters */
    /* dp = d mod (p - 1) */
    sdc_int_reduce(privkey->dp, privkey->d, len2, p_minus_1, len1);
    /* dq = d mod (q - 1) */
    sdc_int_reduce(privkey->dq, privkey->d, len2, q_minus_1, len1);

    /* qinv = q^{-1} mod p = q^{p-2} mod p */
    sdc_int_sub_word(p_minus_1, privkey->p, 2, len1);
    sdc_word_t pinv = sdc_int_calculate_ninv(privkey->p[0]);
    sdc_int_mont_modexp_word(privkey->qinv, privkey->q, p_minus_1, len1,
                             privkey->p, scratch, len1, pinv);

    /* Public key */
    pubkey->n = sdc_malloc(len2 * SDC_WORD_SIZE);
    if (!pubkey->n) {
        ret = SDC_ERR_MEM_ALLOCATE_FAIL;
        goto err_free_all;
    }
    sdc_int_copy(pubkey->n, privkey->n, len2);
    pubkey->nlen = len2;
    pubkey->e = e;
    pubkey->e_bits = SDC_WORD_BITS - sdc_word_clz(e);

    sdc_free(tmp_block);
    return SDC_ERR_OK;

err_free_all:
    sdc_free(tmp_block);
    if (pubkey->n) {
        sdc_free(pubkey->n);
        pubkey->n = NULL;
    }

err_free_privkey:
    if (privkey->_block_start) {
        sdc_free(privkey->_block_start);
        privkey->_block_start = NULL;
        privkey->p = NULL;
        privkey->q = NULL;
        privkey->dp = NULL;
        privkey->dq = NULL;
        privkey->qinv = NULL;
        privkey->d = NULL;
        privkey->n = NULL;
        privkey->len1 = 0;
        privkey->len2 = 0;
    }
    return ret;
}
#endif /* SDC_ENABLE_RSA_KEYGEN */

#endif /* SDC_ENABLE_RSA */