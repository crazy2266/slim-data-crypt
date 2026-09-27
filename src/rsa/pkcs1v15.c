/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * RSA-PKCS#1 v1.5 implementation.
 *
 * References:
 *   - RFC 8017: PKCS #1: RSA Cryptography Specifications Version 2.2
 *     (https://www.rfc-editor.org/rfc/rfc8017)
 *
 * Implements:
 *   - RSAES-PKCS1-v1_5  (encryption/decryption, Section 7.2)
 *   - RSASSA-PKCS1-v1_5 (sign/verify, Section 8.2)
 *
 * Note: The decryption path of unpad_pkcs1v15() is written to resist
 * Bleichenbacher-style padding-oracle attacks. See the comment above
 * that function for details.
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
 *              (Signature verification - `em` is public, see note above.)
 * type = 0x02: extract plaintext from em into `out`.
 *              (Decryption - `em` is secret-derived, must be handled in
 *              constant time w.r.t. padding validity; see note above.)
 *
 * Return value convention:
 *   0  -> success
 *   -1 -> generic padding/verification failure (type 0x01 path)
 *   For type 0x02, SDC_ERR_OK / SDC_ERR_KEY_INVALID are returned
 *   directly instead (see below).
 */
static int unpad_pkcs1v15(const uint8_t *em, size_t em_len,
                          uint8_t *out, size_t *out_len, uint8_t type) {
    if (!em || !out_len || em_len < 11) return SDC_ERR_INVALID_PARAM;
    if (type != 0x01 && type != 0x02) return SDC_ERR_INVALID_PARAM;
    if (type == 0x01 && !out) return SDC_ERR_INVALID_PARAM;

    uint8_t ok = EQ(em[0], 0x00);
    ok &= EQ(em[1], type);

    size_t ps_start = 2;
    size_t ps_end;

    if (type == 0x01) {
        /*
         * Verification: `em` is derived from a public-key operation on
         * public data (the signature under test). The expected digest
         * length is a caller-supplied, public parameter. Nothing here
         * is secret, so ordinary branches/early returns are fine.
         */
        size_t di_len_expected = *out_len;
        if (em_len < 11 + di_len_expected) return SDC_ERR_INVALID_PARAM;
        ps_end = em_len - di_len_expected - 1;
        ok &= EQ(em[ps_end], 0x00);
    } else {
        /*
         * Decryption: the delimiter position is secret. Scan the whole
         * remaining buffer unconditionally; never stop early and never
         * branch on the byte value. `found` and `ps_end` are derived
         * purely from bitwise masks.
         */
        uint8_t found = 0;
        size_t scan_end = ps_start;
        for (size_t i = ps_start; i < em_len; i++) {
            uint8_t is_zero = EQ(em[i], 0x00);
            uint8_t take = (uint8_t)(is_zero & (uint8_t)(found ^ 1));
            size_t mask = (size_t)0 - (size_t)take; /* all-1s if take, else 0 */
            scan_end = (scan_end & ~mask) | (i & mask);
            found = (uint8_t)(found | is_zero);
        }
        ps_end = scan_end;
        /* em[ps_end] == 0x00 is guaranteed whenever found == 1, by
         * construction of the scan above - no separate indexed check
         * needed (and none is done, to avoid a secret-indexed read). */
        ok &= found;
    }

    /*
     * Verify PS (the padding string):
     *   type 0x01 (signing):    every PS byte must be 0xFF
     *   type 0x02 (encryption): every PS byte must be non-zero
     *
     * The loop always covers the full [ps_start, em_len) range. For
     * type 0x02, ps_end is secret, so we never use it as a loop bound;
     * whether byte i is "inside PS" is decided with a mask instead.
     */
    uint8_t ps_ok = 1;
    uint8_t t1 = (uint8_t)(0 - (type & 1)); /* 0xFF for type 1, 0x00 for type 2 */
    uint8_t t2 = (uint8_t)(type & 1);       /* 1 => require em[i] != t1 */
    for (size_t i = ps_start; i < em_len; i++) {
        uint8_t in_range = (uint8_t)((i < ps_end) ? 1u : 0u);
        uint8_t byte_ok = (uint8_t)(NEQ(em[i], t1) ^ t2);
        ps_ok = (uint8_t)(ps_ok & (uint8_t)(byte_ok | (uint8_t)(in_range ^ 1)));
    }

    size_t ps_len = ps_end - ps_start;
    uint16_t t = (uint16_t)ps_len - 8;
    uint8_t ps_len_ok = (uint8_t)((t >> 15) ^ 1);

    size_t di_start = ps_end + 1;
    size_t di_len = em_len - di_start;

    if (type == 0x01) {
        size_t expected_len = *out_len;
        /* Public lengths only - safe to branch/return here. */
        if (di_len != expected_len) return SDC_ERR_KEY_INVALID;

        uint8_t di_ok = 1;
        for (size_t i = 0; i < di_len; i++) {
            di_ok &= EQ(em[di_start + i], out[i]);
        }

        ok &= ps_ok & ps_len_ok & di_ok;
        return (int)ok - 1;
    }

    /*
     * type == 0x02 (decryption).
     *
     * Fold "output buffer big enough" into the same uniform pass/fail
     * decision instead of returning SDC_ERR_BUFFER_TOO_SMALL early:
     * that would be a third, distinguishable outcome (alongside
     * "padding valid" / "padding invalid") that a Bleichenbacher-style
     * attacker could use as an additional oracle. Callers should size
     * their output buffer to at least (mod_bytes - 11) bytes so this
     * never triggers in practice for legitimately-padded messages.
     */
    uint8_t fits = 1;
    if (out) {
        fits = (uint8_t)((*out_len >= di_len) ? 1u : 0u);
    }
    ok &= ps_ok & ps_len_ok & fits;

    if (ok) {
        /*
         * Reached only when padding was valid AND the buffer was large
         * enough. di_len is safe to use/reveal here: disclosing the
         * plaintext length on success is exactly what the API is
         * supposed to do.
         */
        if (out) {
            memcpy(out, em + di_start, di_len);
        }
        *out_len = di_len;
        return SDC_ERR_OK;
    }

    /*
     * Uniform failure: never touch *out_len here (that would leak the
     * secret plaintext length even on failure), and never distinguish
     * "bad padding" from "buffer too small" - both must be
     * indistinguishable to an external observer.
     */
    return SDC_ERR_KEY_INVALID;
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

    /*
     * unpad_pkcs1v15 now reports exactly two outcomes for the
     * decryption path: SDC_ERR_OK or SDC_ERR_KEY_INVALID. Any
     * "buffer too small" condition is intentionally folded into the
     * generic SDC_ERR_KEY_INVALID result (see the security note at the
     * top of this file) - it is not surfaced separately, to avoid
     * giving an attacker a distinguishable third outcome.
     */
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
                               uint8_t *out, size_t out_len,
                               uint8_t **out_data) {
    if (!ops || !digest || !out || !out_data) return 0;

    sdc_asn1_writer_t writer;
    sdc_asn1_writer_init(&writer, out, out_len);

    sdc_asn1_writer_t seq, algo;
    sdc_asn1_write_sequence_begin(&writer, &seq);
    sdc_asn1_write_sequence_begin(&writer, &algo);

    /*
     * The ASN.1 writer is reverse-writing, so fields are emitted
     * in reverse order and appear in normal DER order in the result.
     *
     * AlgorithmIdentifier = SEQUENCE { OID, NULL }
     */
    sdc_asn1_write_null(&writer);
    sdc_asn1_write_oid(&writer, ops->oid, ops->oid_len);
    sdc_asn1_write_sequence_end(&writer, &algo);

    /* DigestInfo = SEQUENCE { AlgorithmIdentifier, OCTET STRING } */
    sdc_asn1_write_octet_string(&writer, digest, digest_len);
    sdc_asn1_write_sequence_end(&writer, &seq);

    if (sdc_asn1_writer_has_error(&writer)) return 0;

    *out_data = sdc_asn1_writer_data(&writer);
    return sdc_asn1_writer_length(&writer);
}

/*
 * DigestInfo DER length (all length fields < 128):
 *   SEQUENCE tag+len        : 2
 *     SEQUENCE tag+len      : 2
 *       OID tag+len+oid     : 2 + oid_len
 *       NULL tag+len        : 2
 *     OCTET STRING tag+len  : 2
 *       hash                : hash_len
 *   Total = oid_len + hash_len + 10
 */
static inline size_t digestinfo_der_len(const sdc_hash_ops_t *ops) {
    return ops->oid_len + ops->hash_len + 10;
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

    uint8_t *di_data = NULL;
    size_t di_len = build_digestinfo(hash_ops, digest, digest_len,
                                     di, di_bytes, &di_data);
    if (di_len == 0) {
        sdc_free(scratch);
        return SDC_ERR_INVALID_PARAM;
    }

    int ret = pad_pkcs1v15(em, mod_bytes, di_data, di_len, 0x01, NULL);
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

    uint8_t *di_data = NULL;
    size_t di_len = build_digestinfo(hash_ops, digest, digest_len,
                                     di, di_bytes, &di_data);
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
    ret = unpad_pkcs1v15(em, mod_bytes, di_data, &di_len, 0x01);
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
