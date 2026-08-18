/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * RSA public-key cryptography.
 *
 * Supported schemes:
 *   - RSAES-PKCS#1 v1.5 (encryption/decryption)
 *   - RSAES-OAEP       (encryption/decryption)
 *   - RSASSA-PKCS#1 v1.5 (sign/verify)
 *   - RSASSA-PSS       (sign/verify)
 *
 * ============================================================
 * Hash function dependency:
 * ============================================================
 * All signing/verification functions in this module require a
 * hash algorithm to be provided via sdc_hash_ops_t.
 *
 * Example:
 *   int ret = sdc_rsassa_pkcs1v15_sign(&sdc_sha256_ops, key,
 *                                       msg, msg_len,
 *                                       sig, &sig_len);
 *
 * For RSASSA-PSS, the hash algorithm specified in ops is used
 * for both the message digest and the MGF1 mask generation.
 *
 * ============================================================
 * out_len parameter convention:
 * ============================================================
 * All functions that accept a size_t* out_len follow the same
 * convention as the hash module:
 *
 *   - INPUT:  Caller MUST initialize *out_len to the size of
 *             the output buffer (in bytes).
 *   - OUTPUT: On success, *out_len is updated to the actual
 *             output length.
 *   - ERROR:  If *out_len is too small, the function returns
 *             SDC_ERR_BUFFER_TOO_SMALL and sets *out_len to the
 *             required size.
 */

#ifndef SDC_RSA_H
#define SDC_RSA_H

#include <stdint.h>
#include <stddef.h>
#include <sdcrypt/config.h>
#include <sdcrypt/hash.h>
#include <sdcrypt/platform.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SDC_ENABLE_RSA (SDC_ENABLE_RSA_KEYGEN || SDC_ENABLE_RSAES_PKCS1V15 || SDC_ENABLE_RSAES_OAEP || \
                        SDC_ENABLE_RSASSA_PKCS1V15 || SDC_ENABLE_RSASSA_PSS)

/* ============================================================
   Key structures
   ============================================================ */

/**
 * RSA public key.
 *
 * n:  modulus, stored as an array of sdc_word_t (big-endian limbs)
 * nlen: number of limbs in n
 * e:   public exponent (limited to a single word, typically 65537)
 */
typedef struct {
    sdc_word_t *n;
    size_t nlen;
    sdc_word_t e;
} sdc_rsa_pubkey_t;

/**
 * RSA private key (CRT form).
 *
 * p, q:       the two prime factors (len1 limbs each)
 * dp, dq, qinv: CRT coefficients (len1 limbs each)
 * d:          private exponent (len2 limbs)
 * n:          modulus (len2 limbs)
 *
 * len2 is the key length in limbs (nlen), len1 = len2 / 2.
 */
typedef struct {
    sdc_word_t *p;
    sdc_word_t *q;
    sdc_word_t *dp;
    sdc_word_t *dq;
    sdc_word_t *qinv;
    sdc_word_t *d;
    sdc_word_t *n;
    size_t len1;   // limbs for p, q, dp, dq, qinv
    size_t len2;   // limbs for d, n (len2 = len1 * 2)
    sdc_word_t *_block_start;
} sdc_rsa_privkey_t;

/* ============================================================
   Key management
   ============================================================ */

/**
 * Initialize a public key from byte arrays.
 *
 * @param pubkey  Pointer to public key structure
 * @param n       Modulus bytes (big-endian)
 * @param nlen    Length of n in bytes (must be multiple of SDC_WORD_SIZE)
 * @param e       Public exponent (single word)
 * @return        SDC_ERR_OK on success, error code otherwise
 */
int sdc_rsa_pubkey_init(sdc_rsa_pubkey_t *pubkey,
                        const uint8_t *n, size_t nlen,
                        sdc_word_t e);

/**
 * Initialize a private key from byte arrays.
 *
 * All byte arrays are big-endian. len1 and len2 must be multiples of
 * SDC_WORD_SIZE. len2 must be exactly len1 * 2.
 *
 * @param privkey Pointer to private key structure
 * @param p       Prime p bytes
 * @param q       Prime q bytes
 * @param dp      CRT coefficient d mod (p-1)
 * @param dq      CRT coefficient d mod (q-1)
 * @param qinv    CRT coefficient q^{-1} mod p
 * @param len1    Length of p, q, dp, dq, qinv in bytes
 * @param d       Private exponent d bytes
 * @param n       Modulus n bytes
 * @param len2    Length of d and n in bytes (len2 = len1 * 2)
 * @return        SDC_ERR_OK on success, error code otherwise
 */
int sdc_rsa_privkey_init(sdc_rsa_privkey_t *privkey,
                         const uint8_t *p, const uint8_t *q,
                         const uint8_t *dp, const uint8_t *dq,
                         const uint8_t *qinv, size_t len1,
                         const uint8_t *d, const uint8_t *n, size_t len2);

/**
 * Generate an RSA key pair.
 *
 * @param pubkey  Output public key (must be initialized)
 * @param privkey Output private key (must be initialized)
 * @param e       Public exponent (single word, typically 0x10001)
 * @param bits    Key size in bits (must be multiple of SDC_WORD_BITS)
 * @return        SDC_ERR_OK on success, error code otherwise
 */
#if SDC_ENABLE_RSA_KEYGEN
int sdc_rsa_keypair(sdc_rsa_pubkey_t *pubkey,
                    sdc_rsa_privkey_t *privkey,
                    sdc_word_t e,
                    size_t bits);
#endif

/**
 * Free memory used by an RSA key pair.
 *
 * This function frees the internal buffers of both keys and
 * zeroes the structures.
 *
 * @param pubkey  Public key (can be NULL)
 * @param privkey Private key (can be NULL)
 */
void sdc_rsa_free_keypair(sdc_rsa_pubkey_t *pubkey,
                          sdc_rsa_privkey_t *privkey);

/* ============================================================
   RSAES-PKCS#1 v1.5
   ============================================================ */

#if SDC_ENABLE_RSAES_PKCS1V15

/**
 * Encrypt a message using RSAES-PKCS#1 v1.5.
 *
 * @param pubkey       Public key
 * @param msg          Message to encrypt
 * @param msg_len      Length of message in bytes
 * @param out          Output buffer for ciphertext
 * @param out_len      Input: buffer size; Output: ciphertext length
 * @return             SDC_ERR_OK on success, error code otherwise
 */
int sdc_rsaes_pkcs1v15_encrypt(const sdc_rsa_pubkey_t *pubkey,
                               const uint8_t *msg, size_t msg_len,
                               uint8_t *out, size_t *out_len);

/**
 * Decrypt a ciphertext using RSAES-PKCS#1 v1.5.
 *
 * @param privkey      Private key
 * @param cipher       Ciphertext
 * @param cipher_len   Length of ciphertext in bytes
 * @param out          Output buffer for plaintext
 * @param out_len      Input: buffer size; Output: plaintext length
 * @return             SDC_ERR_OK on success, error code otherwise
 */
int sdc_rsaes_pkcs1v15_decrypt(const sdc_rsa_privkey_t *privkey,
                               const uint8_t *cipher, size_t cipher_len,
                               uint8_t *out, size_t *out_len);

#endif /* SDC_ENABLE_RSAES_PKCS1V15 */

/* ============================================================
   RSAES-OAEP
   ============================================================ */

#if SDC_ENABLE_RSAES_OAEP

/**
 * Encrypt a message using RSAES-OAEP.
 *
 * Uses the hash algorithm specified by the caller for both the
 * message digest and the MGF1 mask generation.
 *
 * @param hash_ops     Hash algorithm for OAEP
 * @param pubkey       Public key
 * @param msg          Message to encrypt
 * @param msg_len      Length of message in bytes
 * @param label        Optional label (can be NULL)
 * @param label_len    Length of label in bytes
 * @param out          Output buffer for ciphertext
 * @param out_len      Input: buffer size; Output: ciphertext length
 * @return             SDC_ERR_OK on success, error code otherwise
 */
int sdc_rsaes_oaep_encrypt(const sdc_hash_ops_t *hash_ops,
                           const sdc_rsa_pubkey_t *pubkey,
                           const uint8_t *msg, size_t msg_len,
                           const uint8_t *label, size_t label_len,
                           uint8_t *out, size_t *out_len);

/**
 * Decrypt a ciphertext using RSAES-OAEP.
 *
 * @param hash_ops     Hash algorithm for OAEP (must match encryption)
 * @param privkey      Private key
 * @param cipher       Ciphertext
 * @param cipher_len   Length of ciphertext in bytes
 * @param label        Optional label (can be NULL)
 * @param label_len    Length of label in bytes
 * @param out          Output buffer for plaintext
 * @param out_len      Input: buffer size; Output: plaintext length
 * @return             SDC_ERR_OK on success, error code otherwise
 */
int sdc_rsaes_oaep_decrypt(const sdc_hash_ops_t *hash_ops,
                           const sdc_rsa_privkey_t *privkey,
                           const uint8_t *cipher, size_t cipher_len,
                           const uint8_t *label, size_t label_len,
                           uint8_t *out, size_t *out_len);

#endif /* SDC_ENABLE_RSAES_OAEP */

/* ============================================================
   RSASSA-PKCS#1 v1.5
   ============================================================ */

#if SDC_ENABLE_RSASSA_PKCS1V15

/**
 * Sign a message using RSASSA-PKCS#1 v1.5.
 *
 * @param hash_ops     Hash algorithm to use
 * @param privkey      Private key
 * @param msg          Message to sign
 * @param msg_len      Length of message in bytes
 * @param out          Output buffer for signature
 * @param out_len      Input: buffer size; Output: signature length
 * @return             SDC_ERR_OK on success, error code otherwise
 */
int sdc_rsassa_pkcs1v15_sign(const sdc_hash_ops_t *hash_ops,
                             const sdc_rsa_privkey_t *privkey,
                             const uint8_t *msg, size_t msg_len,
                             uint8_t *out, size_t *out_len);

/**
 * Sign a pre-computed hash using RSASSA-PKCS#1 v1.5.
 *
 * This is useful when the hash has been computed externally
 * (e.g., using a streaming hash or hardware accelerator).
 *
 * @param hash_ops     Hash algorithm (used to determine DigestInfo)
 * @param privkey      Private key
 * @param digest       Pre-computed message digest
 * @param digest_len   Length of digest (must match hash_ops->hash_len)
 * @param out          Output buffer for signature
 * @param out_len      Input: buffer size; Output: signature length
 * @return             SDC_ERR_OK on success, error code otherwise
 */
int sdc_rsassa_pkcs1v15_sign_hash(const sdc_hash_ops_t *hash_ops,
                                  const sdc_rsa_privkey_t *privkey,
                                  const uint8_t *digest, size_t digest_len,
                                  uint8_t *out, size_t *out_len);

/**
 * Verify a signature using RSASSA-PKCS#1 v1.5.
 *
 * @param hash_ops     Hash algorithm to use
 * @param pubkey       Public key
 * @param msg          Message that was signed
 * @param msg_len      Length of message in bytes
 * @param sig          Signature to verify
 * @param sig_len      Length of signature in bytes
 * @return             SDC_ERR_OK on success, error code otherwise
 */
int sdc_rsassa_pkcs1v15_verify(const sdc_hash_ops_t *hash_ops,
                               const sdc_rsa_pubkey_t *pubkey,
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t *sig, size_t sig_len);

/**
 * Verify a signature against a pre-computed hash using RSASSA-PKCS#1 v1.5.
 *
 * @param hash_ops     Hash algorithm (used to determine DigestInfo)
 * @param pubkey       Public key
 * @param digest       Pre-computed message digest
 * @param digest_len   Length of digest (must match hash_ops->hash_len)
 * @param sig          Signature to verify
 * @param sig_len      Length of signature in bytes
 * @return             SDC_ERR_OK on success, error code otherwise
 */
int sdc_rsassa_pkcs1v15_verify_hash(const sdc_hash_ops_t *hash_ops,
                                    const sdc_rsa_pubkey_t *pubkey,
                                    const uint8_t *digest, size_t digest_len,
                                    const uint8_t *sig, size_t sig_len);

#endif /* SDC_ENABLE_RSASSA_PKCS1V15 */

/* ============================================================
   RSASSA-PSS
   ============================================================ */

#if SDC_ENABLE_RSASSA_PSS

/**
 * Sign a message using RSASSA-PSS.
 *
 * Uses the same hash algorithm for both the message digest and
 * the MGF1 mask generation. Salt length is set to hash_len.
 *
 * @param hash_ops     Hash algorithm to use
 * @param privkey      Private key
 * @param msg          Message to sign
 * @param msg_len      Length of message in bytes
 * @param out          Output buffer for signature
 * @param out_len      Input: buffer size; Output: signature length
 * @return             SDC_ERR_OK on success, error code otherwise
 */
int sdc_rsassa_pss_sign(const sdc_hash_ops_t *hash_ops,
                        const sdc_rsa_privkey_t *privkey,
                        const uint8_t *msg, size_t msg_len,
                        uint8_t *out, size_t *out_len);

/**
 * Sign a pre-computed hash using RSASSA-PSS.
 *
 * @param hash_ops     Hash algorithm to use
 * @param privkey      Private key
 * @param digest       Pre-computed message digest
 * @param digest_len   Length of digest (must match hash_ops->hash_len)
 * @param out          Output buffer for signature
 * @param out_len      Input: buffer size; Output: signature length
 * @return             SDC_ERR_OK on success, error code otherwise
 */
int sdc_rsassa_pss_sign_hash(const sdc_hash_ops_t *hash_ops,
                             const sdc_rsa_privkey_t *privkey,
                             const uint8_t *digest, size_t digest_len,
                             uint8_t *out, size_t *out_len);

/**
 * Verify a signature using RSASSA-PSS.
 *
 * @param hash_ops     Hash algorithm to use
 * @param pubkey       Public key
 * @param msg          Message that was signed
 * @param msg_len      Length of message in bytes
 * @param sig          Signature to verify
 * @param sig_len      Length of signature in bytes
 * @return             SDC_ERR_OK on success, error code otherwise
 */
int sdc_rsassa_pss_verify(const sdc_hash_ops_t *hash_ops,
                          const sdc_rsa_pubkey_t *pubkey,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *sig, size_t sig_len);

/**
 * Verify a signature against a pre-computed hash using RSASSA-PSS.
 *
 * @param hash_ops     Hash algorithm to use
 * @param pubkey       Public key
 * @param digest       Pre-computed message digest
 * @param digest_len   Length of digest (must match hash_ops->hash_len)
 * @param sig          Signature to verify
 * @param sig_len      Length of signature in bytes
 * @return             SDC_ERR_OK on success, error code otherwise
 */
int sdc_rsassa_pss_verify_hash(const sdc_hash_ops_t *hash_ops,
                               const sdc_rsa_pubkey_t *pubkey,
                               const uint8_t *digest, size_t digest_len,
                               const uint8_t *sig, size_t sig_len);

#endif /* SDC_ENABLE_RSASSA_PSS */

#ifdef __cplusplus
}
#endif

#endif /* SDC_RSA_H */