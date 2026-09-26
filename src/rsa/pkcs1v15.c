/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * RSA-PKCS#1 v1.5 implementation.
 *
 * References:
 *   - RFC 8017: PKCS #1: RSA Cryptography Specifications Version 2.2
 *     (https://www.rfc-editor.org/rfc/rfc8017)
 *   - PKCS #1 v2.1: RSA Cryptography Standard
 *     (https://www.emc.com/collateral/white-papers/h11300-pkcs-1v2-1-rsa-cryptography-standard-wp.pdf)
 *
 * Implements:
 *   - RSAES-PKCS1-v1_5  (encryption/decryption, Section 7.2)
 *   - RSASSA-PKCS1-v1_5 (sign/verify, Section 8.2)
 */

#include <string.h>
#include <sdcrypt/rsa.h>
#include <sdcrypt/mem.h>
#include <sdcrypt/rng.h>
#include <sdcrypt/config.h>
#include <sdcrypt/integer.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/hash.h>
#include "rsa_inner.h"
#if SDC_ENABLE_RSASSA_PKCS1V15
#  include <sdcrypt/asn1.h>
#endif

#if SDC_ENABLE_RSAES_PKCS1V15 || SDC_ENABLE_RSASSA_PKCS1V15

static uint8_t NEQ(uint8_t a, uint8_t b) {
    uint8_t diff = a ^ b;
    return (diff | (uint8_t)(-(int8_t)diff)) >> 7;
}

static uint8_t EQ(uint8_t a, uint8_t b) {
    return NEQ(a, b) ^ 1;
}

/*
 * PKCS#1 v1.5 padding.
 *
 * Output: 0x00 || type || PS || 0x00 || (DigestInfo or PlainText)
 * type = 0x01 for signing, 0x02 for encryption.
 */
static int pad_pkcs1v15(uint8_t *out, size_t out_len, const uint8_t *di,
                        size_t di_len, uint8_t type, sdc_rng_ctx *rng) {
    if (!out || !di || out_len < 11 + di_len) return SDC_ERR_INVALID_PARAM;
    if (type != 0x01 && type != 0x02) return SDC_ERR_INVALID_PARAM;
    if (type == 0x02 && !rng) return SDC_ERR_INVALID_PARAM;

    size_t ps_len = out_len - 3 - di_len;
    if (ps_len < 8) return SDC_ERR_INVALID_PARAM;

    out[0] = 0x00;
    out[1] = type;

    if (type == 0x01) {
        memset(out + 2, 0xFF, ps_len);
    } else {
        for (size_t i = 0; i < ps_len; i++) {
            uint8_t b;
            do {
                int ret = sdc_rng_generate(rng, &b, 1);
                if (ret != SDC_ERR_OK) return ret;
            } while (b == 0);
            out[2 + i] = b;
        }
    }

    out[2 + ps_len] = 0x00;
    memcpy(out + 2 + ps_len + 1, di, di_len);
    return SDC_ERR_OK;
}

/*
 * PKCS#1 v1.5 unpadding.
 *
 * type = 0x01: verify that em contains the expected DigestInfo in `out`.
 * type = 0x02: extract plaintext from em into `out`.
 */
static int unpad_pkcs1v15(const uint8_t *em, size_t em_len,
                          uint8_t *out, size_t *out_len, uint8_t type) {
    if (!em || !out_len || em_len < 11) return SDC_ERR_INVALID_PARAM;
    if (type != 0x01 && type != 0x02) return SDC_ERR_INVALID_PARAM;

    uint8_t ok = EQ(em[0], 0x00);
    ok &= EQ(em[1], type);

    size_t ps_start = 2;
    size_t ps_end = em_len - 1;

    if (type == 0x01) {
        if (!out) return SDC_ERR_INVALID_PARAM;
        size_t di_len = *out_len;
        if (em_len < 11 + di_len) return SDC_ERR_INVALID_PARAM;
        ps_end = em_len - di_len - 1;
    } else {
        size_t i;
        for (i = ps_start; i < em_len; i++) {
            if (em[i] == 0x00) break;
        }
        if (i == em_len) return SDC_ERR_INVALID_PARAM;
        ps_end = i;
    }

    /* Check PS: 0xFF for signing, non-zero for encryption */
    uint8_t ps_ok = 1, t1 = 0, t2 = 0;
    t1 -= (type & 1);
    t2 = (type & 1);
    for (size_t i = ps_start; i < ps_end; i++) {
        ps_ok &= NEQ(em[i], t1) ^ t2;
    }

    ok &= EQ(em[ps_end], 0x00);

    size_t ps_len = ps_end - ps_start;
    uint16_t t = (uint16_t)ps_len - 8;
    uint8_t ps_len_ok = (t >> 15) ^ 1;

    uint8_t di_ok = 1;
    size_t di_start = ps_end + 1;
    size_t di_len = em_len - di_start;

    if (type == 0x01) {
        size_t expected_len = *out_len;
        if (di_len != expected_len) return SDC_ERR_KEY_INVALID;
        for (size_t i = 0; i < di_len; i++) {
            di_ok &= EQ(em[di_start + i], out[i]);
        }
    } else {
        if (out) {
            if (*out_len < di_len) {
                *out_len = di_len;
                return SDC_ERR_BUFFER_TOO_SMALL;
            }
            for (size_t i = 0; i < di_len; i++) {
                out[i] = em[di_start + i];
            }
        }
        *out_len = di_len;
    }

    ok &= ps_ok & ps_len_ok & di_ok;
    return (int)ok - 1;
}

#if SDC_ENABLE_RSAES_PKCS1V15

int sdc_rsaes_pkcs1v15_encrypt(const sdc_rsa_pubkey_t *pubkey,
                               const uint8_t *msg, size_t msg_len,
                               uint8_t *out, size_t *out_len,
                               sdc_rng_ctx *rng_ctx) {
    if (!pubkey || !msg || !out || !out_len || !rng_ctx) return SDC_ERR_INVALID_PARAM;

    size_t mod_bytes = pubkey->nlen * SDC_WORD_SIZE;
    if (msg_len > mod_bytes - 11) return SDC_ERR_INVALID_PARAM;
    if (*out_len < mod_bytes) {
        *out_len = mod_bytes;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }

    int ret = pad_pkcs1v15(out, mod_bytes, msg, msg_len, 0x02, rng_ctx);
    if (ret != SDC_ERR_OK) return ret;

    size_t n_words = pubkey->nlen;
    size_t tmp_words = n_words * 4;
    sdc_word_t *scratch = (sdc_word_t *)sdc_malloc((n_words * 2 + tmp_words) * SDC_WORD_SIZE);
    if (!scratch) return SDC_ERR_MEM_ALLOCATE_FAIL;

    sdc_word_t *em_w = scratch;
    sdc_word_t *c_w = scratch + n_words;
    sdc_word_t *tmp = scratch + n_words * 2;

    sdc_int_frombytes_be(em_w, n_words, out);
    ret = _sdc_rsa_public(c_w, em_w, pubkey, tmp);
    if (ret == SDC_ERR_OK) {
        sdc_int_tobytes_be(c_w, n_words, out);
        *out_len = mod_bytes;
    }

    sdc_free(scratch);
    return ret;
}

int sdc_rsaes_pkcs1v15_decrypt(const sdc_rsa_privkey_t *privkey,
                               const uint8_t *cipher, size_t cipher_len,
                               uint8_t *out, size_t *out_len,
                               sdc_rng_ctx *rng_ctx) {
    if (!privkey || !cipher || !out || !out_len) return SDC_ERR_INVALID_PARAM;
#if SDC_RSA_ENABLE_BLINDING
    if (!rng_ctx) return SDC_ERR_INVALID_PARAM;
#endif
    size_t mod_bytes = privkey->len2 * SDC_WORD_SIZE;
    if (cipher_len != mod_bytes) return SDC_ERR_INVALID_PARAM;

    size_t n_words = privkey->len2;
    size_t tmp_words = SDC_RSA_PRIVATE_TMP_SIZE(privkey->len1);
    sdc_word_t *scratch = (sdc_word_t *)sdc_malloc(
        (n_words * 2 + tmp_words) * SDC_WORD_SIZE + mod_bytes);
    if (!scratch) return SDC_ERR_MEM_ALLOCATE_FAIL;

    sdc_word_t *c_w = scratch;
    sdc_word_t *em_w = scratch + n_words;
    sdc_word_t *tmp = scratch + n_words * 2;
    uint8_t *em = (uint8_t *)(tmp + tmp_words);

    sdc_int_frombytes_be(c_w, n_words, cipher);
    int ret = _sdc_rsa_private(em_w, c_w, privkey, tmp, rng_ctx);
    if (ret != SDC_ERR_OK) {
        sdc_free(scratch);
        return ret;
    }

    sdc_int_tobytes_be(em_w, n_words, em);

    size_t plaintext_len = *out_len;
    ret = unpad_pkcs1v15(em, mod_bytes, out, &plaintext_len, 0x02);
    sdc_free(scratch);

    if (ret == SDC_ERR_BUFFER_TOO_SMALL) {
        *out_len = plaintext_len;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }
    if (ret != SDC_ERR_OK) return SDC_ERR_KEY_INVALID;

    *out_len = plaintext_len;
    return SDC_ERR_OK;
}

#endif /* SDC_ENABLE_RSAES_PKCS1V15 */

#if SDC_ENABLE_RSASSA_PKCS1V15

/*
 * Build DigestInfo: SEQUENCE { SEQUENCE { OID, NULL }, OCTET STRING }
 */
static size_t build_digestinfo(const sdc_hash_ops_t *ops,
                               const uint8_t *digest, size_t digest_len,
                               uint8_t *out, size_t out_len) {
    if (!ops || !digest || !out) return 0;

    sdc_asn1_writer_t writer;
    sdc_asn1_writer_init(&writer, out, out_len);

    sdc_asn1_writer_t seq, algo;
    sdc_asn1_write_sequence_begin(&writer, &seq);
    sdc_asn1_write_sequence_begin(&writer, &algo);
    sdc_asn1_write_oid(&writer, ops->oid, ops->oid_len);
    sdc_asn1_write_null(&writer);
    sdc_asn1_write_sequence_end(&writer, &algo);
    sdc_asn1_write_octet_string(&writer, digest, digest_len);
    sdc_asn1_write_sequence_end(&writer, &seq);

    if (sdc_asn1_writer_has_error(&writer)) return 0;
    return sdc_asn1_writer_length(&writer);
}

/*
 * Maximum DER-encoded DigestInfo size for PKCS#1 v1.5.
 *
 * Layout:
 *   SEQUENCE {
 *       SEQUENCE { OID, NULL }
 *       OCTET STRING
 *   }
 *
 * Exact size = oid_len + hash_len + 10.
 * We add 6 bytes of headroom to cover:
 *   - ASN.1 writer's 4-byte length placeholders (for nested SEQUENCEs)
 *   - Future hash algorithms with slightly longer OIDs
 *
 * The ASN.1 writer temporarily uses 4-byte length fields during
 * construction and compacts them on *_end(), so the working buffer
 * must be larger than the final DER size.
 */
static inline size_t digestinfo_der_len(const sdc_hash_ops_t *ops) {
    return ops->oid_len + ops->hash_len + 14;
}

int sdc_rsassa_pkcs1v15_sign_hash(const sdc_hash_ops_t *hash_ops,
                                  const sdc_rsa_privkey_t *privkey,
                                  const uint8_t *digest, size_t digest_len,
                                  uint8_t *sig, size_t *sig_len,
                                  sdc_rng_ctx *rng_ctx) {
    if (!hash_ops || !privkey || !digest || !sig || !sig_len) return SDC_ERR_INVALID_PARAM;
#if SDC_RSA_ENABLE_BLINDING
    if (!rng_ctx) return SDC_ERR_INVALID_PARAM;
#endif
    if (digest_len != hash_ops->hash_len) return SDC_ERR_INVALID_PARAM;

    size_t mod_bytes = privkey->len2 * SDC_WORD_SIZE;
    if (*sig_len < mod_bytes) {
        *sig_len = mod_bytes;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }

    size_t n_words = privkey->len2;
    size_t tmp_words = SDC_RSA_PRIVATE_TMP_SIZE(privkey->len1);
    size_t di_bytes = digestinfo_der_len(hash_ops);

    sdc_word_t *scratch = (sdc_word_t *)sdc_malloc(
        (n_words * 2 + tmp_words) * SDC_WORD_SIZE + mod_bytes + di_bytes);
    if (!scratch) return SDC_ERR_MEM_ALLOCATE_FAIL;

    sdc_word_t *em_w = scratch;
    sdc_word_t *sig_w = em_w + n_words;
    sdc_word_t *tmp = sig_w + n_words;
    uint8_t *em = (uint8_t *)(tmp + tmp_words);
    uint8_t *di = em + mod_bytes;

    size_t di_len = build_digestinfo(hash_ops, digest, digest_len, di, di_bytes);
    if (di_len == 0) {
        sdc_free(scratch);
        return SDC_ERR_INVALID_PARAM;
    }

    int ret = pad_pkcs1v15(em, mod_bytes, di, di_len, 0x01, NULL);
    if (ret != SDC_ERR_OK) {
        sdc_free(scratch);
        return ret;
    }

    sdc_int_frombytes_be(em_w, n_words, em);
    ret = _sdc_rsa_private(sig_w, em_w, privkey, tmp, rng_ctx);
    if (ret == SDC_ERR_OK) {
        sdc_int_tobytes_be(sig_w, n_words, sig);
        *sig_len = mod_bytes;
    }

    sdc_free(scratch);
    return ret;
}

int sdc_rsassa_pkcs1v15_sign(const sdc_hash_ops_t *hash_ops,
                             const sdc_rsa_privkey_t *privkey,
                             const uint8_t *msg, size_t msg_len,
                             uint8_t *sig, size_t *sig_len,
                             sdc_rng_ctx *rng_ctx) {
    if (!hash_ops || !privkey || !msg || !sig || !sig_len) return SDC_ERR_INVALID_PARAM;

    uint8_t digest[64];
    size_t digest_len = sizeof(digest);
    int ret = sdc_hash_once(hash_ops, digest, msg, msg_len, &digest_len);
    if (ret != SDC_ERR_OK) return ret;

    return sdc_rsassa_pkcs1v15_sign_hash(hash_ops, privkey,
                                         digest, digest_len,
                                         sig, sig_len, rng_ctx);
}

int sdc_rsassa_pkcs1v15_verify_hash(const sdc_hash_ops_t *hash_ops,
                                    const sdc_rsa_pubkey_t *pubkey,
                                    const uint8_t *digest, size_t digest_len,
                                    const uint8_t *sig, size_t sig_len) {
    if (!hash_ops || !pubkey || !digest || !sig) return SDC_ERR_INVALID_PARAM;
    if (digest_len != hash_ops->hash_len) return SDC_ERR_INVALID_PARAM;

    size_t mod_bytes = pubkey->nlen * SDC_WORD_SIZE;
    if (sig_len != mod_bytes) return SDC_ERR_INVALID_PARAM;

    size_t n_words = pubkey->nlen;
    size_t tmp_words = n_words * 4;
    size_t di_bytes = digestinfo_der_len(hash_ops);

    sdc_word_t *scratch = (sdc_word_t *)sdc_malloc(
        (n_words * 2 + tmp_words) * SDC_WORD_SIZE + mod_bytes + di_bytes);
    if (!scratch) return SDC_ERR_MEM_ALLOCATE_FAIL;

    sdc_word_t *sig_w = scratch;
    sdc_word_t *em_w = scratch + n_words;
    sdc_word_t *tmp = em_w + n_words;
    uint8_t *em = (uint8_t *)(tmp + tmp_words);
    uint8_t *di = em + mod_bytes;

    size_t di_len = build_digestinfo(hash_ops, digest, digest_len, di, di_bytes);
    if (di_len == 0) {
        sdc_free(scratch);
        return SDC_ERR_INVALID_PARAM;
    }

    sdc_int_frombytes_be(sig_w, n_words, sig);
    int ret = _sdc_rsa_public(em_w, sig_w, pubkey, tmp);
    if (ret != SDC_ERR_OK) {
        sdc_free(scratch);
        return ret;
    }

    sdc_int_tobytes_be(em_w, n_words, em);
    ret = unpad_pkcs1v15(em, mod_bytes, di, &di_len, 0x01);
    sdc_free(scratch);

    return (ret == 0) ? SDC_ERR_OK : SDC_ERR_KEY_INVALID;
}

int sdc_rsassa_pkcs1v15_verify(const sdc_hash_ops_t *hash_ops,
                               const sdc_rsa_pubkey_t *pubkey,
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t *sig, size_t sig_len) {
    if (!hash_ops || !pubkey || !msg || !sig) return SDC_ERR_INVALID_PARAM;

    uint8_t digest[64];
    size_t digest_len = sizeof(digest);
    int ret = sdc_hash_once(hash_ops, digest, msg, msg_len, &digest_len);
    if (ret != SDC_ERR_OK) return ret;

    return sdc_rsassa_pkcs1v15_verify_hash(hash_ops, pubkey,
                                           digest, digest_len,
                                           sig, sig_len);
}

#endif /* SDC_ENABLE_RSASSA_PKCS1V15 */

#endif /* SDC_ENABLE_RSAES_PKCS1V15 || SDC_ENABLE_RSASSA_PKCS1V15 */
