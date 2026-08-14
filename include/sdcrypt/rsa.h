/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * RSA encryption/decryption and signing/verification functions.
 * Encryption/decryption supports:
 * - RSAES-PKCS#1 v1.5
 * - RSAES-OAEP
 * Signing/verification supports:
 * - RSASSA-PKCS#1 v1.5
 * - RSASSA-PSS
 */

#ifndef SDC_RSA_H
#define SDC_RSA_H

#include <stdint.h>
#include <stddef.h>
#include <sdcrypt/platform.h>
#include <sdcrypt/config.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SDC_ENABLE_RSA SDC_ENABLE_RSAES_PKCS1V15 || SDC_ENABLE_RSASSA_PKCS1V15 || \
                       SDC_ENABLE_RSAES_OAEP || SDC_ENABLE_RSASSA_PSS

#if SDC_ENABLE_RSA

typedef struct {
    sdc_word_t e;  // Only support e is a single word
    sdc_word_t *n;
    size_t nlen;
} sdc_rsa_pubkey_t;

typedef struct {
    sdc_word_t *p;
    sdc_word_t *q;
    sdc_word_t *dp;
    sdc_word_t *dq;
    sdc_word_t *qinv;
    size_t len1;  // The params above have the same length
    sdc_word_t *d;
    sdc_word_t *n;
    size_t len2;  // d,n have the same length and len2 = len1 * 2
} sdc_rsa_privkey_t;

// nlen must be a multiple of SDC_WORD_SIZE
int sdc_rsa_pubkey_init(sdc_rsa_pubkey_t *pubkey, sdc_word_t e, const uint8_t *n, size_t nlen);
// len1,len2 must be a multiple of SDC_WORD_SIZE
int sdc_rsa_privkey_init(sdc_rsa_privkey_t *privkey, const uint8_t *p, const uint8_t *q, const uint8_t *dp, const uint8_t *dq, const uint8_t *qinv, size_t len1, const uint8_t *d, const uint8_t *n, size_t len2);
#if SDC_ENABLE_RSA_KEYGEN
int sdc_rsa_keypair(sdc_rsa_pubkey_t *pubkey, sdc_rsa_privkey_t *privkey, sdc_word_t e, size_t bits);
#endif
void sdc_rsa_free_keypair(sdc_rsa_pubkey_t *pubkey, sdc_rsa_privkey_t *privkey);
#if SDC_ENABLE_RSAES_PKCS1V15
int sdc_rsaes_pkcs1v15_encrypt(const sdc_rsa_pubkey_t *pubkey, const uint8_t *plain, size_t plain_len, uint8_t *cipher, size_t *cipher_len);
int sdc_rsaes_pkcs1v15_decrypt(const sdc_rsa_privkey_t *privkey, const uint8_t *cipher, size_t cipher_len, uint8_t *plain, size_t *plain_len);
#endif
#if SDC_ENABLE_RSASSA_PKCS1V15
int sdc_rsassa_pkcs1v15_sign(const sdc_rsa_privkey_t *privkey, const uint8_t *hash, size_t hash_len, uint8_t *sig, size_t *sig_len);
int sdc_rsassa_pkcs1v15_verify(const sdc_rsa_pubkey_t *pubkey, const uint8_t *hash, size_t hash_len, const uint8_t *sig, size_t sig_len);
#endif
#if SDC_ENABLE_RSAES_OAEP
int sdc_rsaes_oaep_encrypt(const sdc_rsa_pubkey_t *pubkey, const uint8_t *plain, size_t plain_len, uint8_t *cipher, size_t *cipher_len);
int sdc_rsaes_oaep_decrypt(const sdc_rsa_privkey_t *privkey, const uint8_t *cipher, size_t cipher_len, uint8_t *plain, size_t *plain_len);
#endif
#if SDC_ENABLE_RSASSA_PSS
int sdc_rsassa_pss_sign(const sdc_rsa_privkey_t *privkey, const uint8_t *hash, size_t hash_len, uint8_t *sig, size_t *sig_len);
int sdc_rsassa_pss_verify(const sdc_rsa_pubkey_t *pubkey, const uint8_t *hash, size_t hash_len, const uint8_t *sig, size_t sig_len);
#endif

#endif /* SDC_ENABLE_RSA */
#ifdef __cplusplus
}
#endif

#endif /* SDC_RSA_H */