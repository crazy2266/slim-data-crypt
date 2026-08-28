/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * RSA-PKCS#1 v1.5 implementation.
 * Include:
 *   - encrypt/decrypt
 *   - sign/verify
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
 * pad_pkcs1v15
 * 
 * PKCS#1 v1.5 padding (for encryption/signing)
 * 
 * Output format：0x00 || type || PS || 0x00 || (DigestInfo or PlainText)
 * 
 * @param out       Output buffer pointer
 * @param out_len   Output buffer length
 * @param di        Encoded DigestInfo (ASN.1 structure) or PlainText
 * @param di_len    length of di
 * @param type      Padding type (0x01 for signing, 0x02 for encryption)
 * @return          0 on success, -1 on error
 */
static int pad_pkcs1v15(uint8_t *out, size_t out_len, const uint8_t *di,
                        size_t di_len, uint8_t type, sdc_rng_ctx *rng) {
    if (!out || !di || out_len < 11 + di_len) return SDC_ERR_INVALID_PARAM;
    if (type != 0x01 && type != 0x02) return SDC_ERR_INVALID_PARAM;
    int ret = SDC_ERR_OK;
    size_t ps_len = out_len - 3 - di_len;
    if (ps_len < 8) return SDC_ERR_INVALID_PARAM;
    out[0] = 0x00;
    out[1] = type;
    if (type == 0x01) {
        memset(out + 2, 0xFF, ps_len);
    } else if (type == 0x02) {
        for (size_t i = 0; i < ps_len; i++) {
            uint8_t b;
            do {
                ret = sdc_rng_generate(rng, &b, 1);
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
 * unpad_pkcs1v15
 * 
 * PKCS#1 v1.5 type 1 padding verification (for decryption/verification)
 * 
 * @param em        encoded message
 * @param em_len    em length
 * @param di        Expected DigestInfo or PlainText
 * @param di_len    length of di
 * @param type      Padding type (0x01 for signing, 0x02 for encryption)
 * @return          0 on success, -1 on error
 */
static int unpad_pkcs1v15(const uint8_t *em, size_t em_len,
                          const uint8_t *di, size_t di_len, uint8_t type) {
    if (!em || !di || em_len < 11 + di_len) return SDC_ERR_INVALID_PARAM;
    if (type != 0x01 && type != 0x02) return SDC_ERR_INVALID_PARAM;
    
    /* Check padding type and 0x00 type */
    uint8_t ok = EQ(em[0], 0x00);
    ok &= EQ(em[1], type);

    /* Check PS part */
    size_t ps_start = 2;
    size_t ps_end = em_len - di_len - 1;
    uint8_t ps_ok = 1, t1 = 0, t2 = 0;
    t1 -= (type & 1);  // type == 0x01 => 0xFF, type == 0x02 => 0x00
    t2 = (type & 1);   // type == 0x01 => 0x01, type == 0x02 => 0x00
    // if type == 0x01, then ps_ok &= EQ(em[i], 0xFF);
    // if type == 0x02, then ps_ok &= NEQ(em[i], 0x00);
    for (size_t i = ps_start; i < ps_end; i++) {
        ps_ok &= NEQ(em[i], t1) ^ t2;
    }

    /* Check separator 0x00 */
    ok &= EQ(em[ps_end], 0x00);

    /* Check PS length */
    size_t ps_len = ps_end - ps_start;
    uint16_t t = (uint16_t)ps_len - 8;
    uint8_t ps_len_ok = (t >> 15) ^ 1;

    /* Check di match */
    size_t di_start = ps_end + 1;
    uint8_t di_ok = 1;
    for (size_t i = 0; i < di_len; i++) {
        di_ok &= EQ(em[di_start + i], di[i]);
    }
    ok &= ps_ok & ps_len_ok & di_ok;
    return (int)ok - 1;  // if ok == 1, return 0, else return -1
}

#if SDC_ENABLE_RSASSA_PKCS1V15
static size_t build_digestinfo(const sdc_hash_ops_t *ops,
                                   const uint8_t *digest, size_t digest_len,
                                   uint8_t *out, size_t out_len) {
    if (!ops || !digest || !out) return 0;
    if (out_len < 128) return 0;

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

int sdc_rsassa_pkcs1v15_sign(const sdc_hash_ops_t *hash_ops,
                             const sdc_rsa_privkey_t *privkey,
                             const uint8_t *msg, size_t msg_len,
                             uint8_t *sig, size_t *sig_len) {
    if (!hash_ops || !privkey || !msg || !sig || !sig_len) {
        return SDC_ERR_INVALID_PARAM;
    }

    size_t mod_bytes = privkey->len2 * SDC_WORD_SIZE;
    if (*sig_len < mod_bytes) {
        *sig_len = mod_bytes;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }

    /* Calculate hash */
    uint8_t digest[64];
    size_t digest_len = sizeof(digest);
    int ret = sdc_hash_once(hash_ops, digest, msg, msg_len, &digest_len);
    if (ret != SDC_ERR_OK) return ret;

    /* Build DigestInfo */
    uint8_t di[128];
    size_t di_len = build_digestinfo(hash_ops, digest, digest_len, di, sizeof(di));
    if (di_len == 0) return SDC_ERR_INVALID_PARAM;

    /* Padding */
    uint8_t *em = sig;  /* Use sig buffer directly */
    ret = pad_pkcs1v15(em, mod_bytes, di, di_len, 0x01, NULL);
    if (ret != SDC_ERR_OK) return ret;

    /* Private key modular exponentiation */
    size_t n_words = privkey->len2;
    size_t tmp_words = privkey->len2 * 4;
    sdc_word_t *scratch = (sdc_word_t *)sdc_malloc((n_words * 2 + tmp_words) * SDC_WORD_SIZE);
    if (!scratch) return SDC_ERR_MEM_ALLOCATE_FAIL;
    sdc_word_t *em_w = scratch;
    sdc_word_t *sig_w = scratch + n_words;
    sdc_word_t *tmp = scratch + n_words * 2;

    sdc_int_frombytes_be(em_w, n_words, em);
    ret = _sdc_rsa_private(sig_w, em_w, privkey, tmp);
    if (ret == SDC_ERR_OK) {
        sdc_int_tobytes_be(sig_w, n_words, sig);
        *sig_len = mod_bytes;
    }
    sdc_free(scratch);
    return ret;
}

int sdc_rsassa_pkcs1v15_verify(const sdc_hash_ops_t *hash_ops,
                               const sdc_rsa_pubkey_t *pubkey,
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t *sig, size_t sig_len) {
    if (!hash_ops || !pubkey || !msg || !sig) return SDC_ERR_INVALID_PARAM;

    size_t mod_bytes = pubkey->nlen * SDC_WORD_SIZE;
    if (sig_len != mod_bytes) return SDC_ERR_INVALID_PARAM;

    /* Calculate hash */
    uint8_t digest[64];
    size_t digest_len = sizeof(digest);
    int ret = sdc_hash_once(hash_ops, digest, msg, msg_len, &digest_len);
    if (ret != SDC_ERR_OK) return ret;

    /* Build DigestInfo */
    uint8_t di[128];
    size_t di_len = build_digestinfo(hash_ops, digest, digest_len, di, sizeof(di));
    if (di_len == 0) return SDC_ERR_INVALID_PARAM;

    /* Recover em */
    size_t n_words = pubkey->nlen;
    size_t tmp_words = n_words * 4;
    sdc_word_t *scratch = (sdc_word_t *)sdc_malloc((n_words * 2 + tmp_words) * SDC_WORD_SIZE);
    if (!scratch) return SDC_ERR_MEM_ALLOCATE_FAIL;

    sdc_word_t *sig_w = scratch;
    sdc_word_t *em_w = scratch + n_words;
    sdc_word_t *tmp = scratch + n_words * 2;

    sdc_int_frombytes_be(sig_w, n_words, sig);
    ret = _sdc_rsa_public(em_w, sig_w, pubkey, tmp);
    if (ret != SDC_ERR_OK) {
        sdc_free(scratch);
        return ret;
    }

    uint8_t em[512];
    sdc_int_tobytes_be(em_w, n_words, em);
    sdc_free(scratch);

    /* Check padding */
    ret = unpad_pkcs1v15(em, mod_bytes, di, di_len, 0x01);
    return (ret == 0) ? SDC_ERR_OK : SDC_ERR_KEY_INVALID;
}
#endif /* SDC_ENABLE_RSASSA_PKCS1V15 */

#endif