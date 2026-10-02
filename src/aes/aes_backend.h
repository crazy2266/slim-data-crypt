/*
 * SPDX-License-Identifier: MIT
 * Internal AES backend interface (not installed).
 */

#ifndef SDC_AES_BACKEND_H
#define SDC_AES_BACKEND_H

#include <sdcrypt/config.h>
#include <sdcrypt/aes.h>

/* Scalar backend (always available). */
void sdc_aes_scalar_encrypt(const sdc_aes_key *key, const uint8_t in[16], uint8_t out[16]);
void sdc_aes_scalar_decrypt(const sdc_aes_key *key, const uint8_t in[16], uint8_t out[16]);

#if SDC_ENABLE_AES && (defined(__x86_64__) || defined(__i386__)) \
    && (defined(__GNUC__) || defined(__clang__))
#  define SDC_HAVE_AESNI 1
void sdc_aes_aesni_set_key(sdc_aes_key *key);
void sdc_aes_aesni_encrypt(const sdc_aes_key *key, const uint8_t in[16], uint8_t out[16]);
void sdc_aes_aesni_decrypt(const sdc_aes_key *key, const uint8_t in[16], uint8_t out[16]);
void sdc_aes_aesni_encrypt_blocks(const sdc_aes_key *key, const uint8_t *in, size_t nblocks, uint8_t *out);
#endif

#if SDC_ENABLE_AES && defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))
#  define SDC_HAVE_ARMCE 1
void sdc_aes_armce_set_key(sdc_aes_key *key);
void sdc_aes_armce_encrypt(const sdc_aes_key *key, const uint8_t in[16], uint8_t out[16]);
void sdc_aes_armce_decrypt(const sdc_aes_key *key, const uint8_t in[16], uint8_t out[16]);
void sdc_aes_armce_encrypt_blocks(const sdc_aes_key *key, const uint8_t *in, size_t nblocks, uint8_t *out);
#endif

#endif /* SDC_AES_BACKEND_H */
