/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * RSA key pair test.
 * 
 * Tests:
 *   - sdc_rsa_keypair: key generation (2048, 1024)
 *   - sdc_rsa_pubkey_init / sdc_rsa_privkey_init
 *   - sdc_rsa_free_keypair
 *   - Mathematical correctness: p*q=n, e*d mod phi=1
 *   - RSA encryption/decryption round-trip
 *   - CRT encryption
 *   - Public key verification
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sdcrypt/rsa.h>
#include <sdcrypt/config.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/mem.h>
#include <sdcrypt/integer.h>
#include <sdcrypt/utils.h>

static int g_passed = 0;
static int g_total = 0;

#define TEST_START(name) printf("\n=== %s ===\n", name)
#define TEST_ASSERT(cond, msg) \
    do { \
        g_total++; \
        if (cond) { \
            printf("  [PASS] %s\n", msg); \
            g_passed++; \
        } else { \
            printf("  [FAIL] %s\n", msg); \
        } \
    } while (0)

/* ============================================================
   Helper: allocate and zero memory
   ============================================================ */
static void *alloc_zero(size_t size) {
    void *p = sdc_malloc(size);
    if (p) memset(p, 0, size);
    return p;
}

/* ============================================================
   Helper: generate a random message < n
   ============================================================ */
static void gen_message(sdc_word_t *m, size_t len) {
    size_t bytes = len * SDC_WORD_SIZE;
    uint8_t *buf = (uint8_t *)m;
    /* deterministic pseudo-random pattern */
    for (size_t i = 0; i < bytes; i++) {
        buf[i] = (uint8_t)(i * 0x9e + 0x37);
    }
    /* ensure m < n by setting top byte to 0x01 */
    buf[0] = 0x01;
}

/* ============================================================
   Test: key generation
   ============================================================ */
static void test_keygen(void) {
    sdc_rsa_pubkey_t pub;
    sdc_rsa_privkey_t priv;

    TEST_START("sdc_rsa_keypair");

    /* 2048-bit */
    memset(&pub, 0, sizeof(pub));
    memset(&priv, 0, sizeof(priv));

    int ret = sdc_rsa_keypair(&pub, &priv, 65537, 2048);
    TEST_ASSERT(ret == SDC_ERR_OK, "2048-bit key generation");

    if (ret == SDC_ERR_OK) {
        TEST_ASSERT(pub.n != NULL, "pub.n != NULL");
        TEST_ASSERT(pub.nlen == 2048 / SDC_WORD_BITS, "pub.nlen correct");
        TEST_ASSERT(pub.e == 65537, "pub.e correct");

        TEST_ASSERT(priv._block_start != NULL, "priv._block_start != NULL");
        TEST_ASSERT(priv.p != NULL, "priv.p != NULL");
        TEST_ASSERT(priv.q != NULL, "priv.q != NULL");
        TEST_ASSERT(priv.d != NULL, "priv.d != NULL");
        TEST_ASSERT(priv.n != NULL, "priv.n != NULL");
        TEST_ASSERT(priv.len1 == 2048 / 2 / SDC_WORD_BITS, "priv.len1 correct");
        TEST_ASSERT(priv.len2 == 2048 / SDC_WORD_BITS, "priv.len2 correct");

        sdc_rsa_free_keypair(&pub, &priv);
    }

    /* 1024-bit with e=3 */
    memset(&pub, 0, sizeof(pub));
    memset(&priv, 0, sizeof(priv));

    ret = sdc_rsa_keypair(&pub, &priv, 3, 1024);
    TEST_ASSERT(ret == SDC_ERR_OK, "1024-bit with e=3");

    if (ret == SDC_ERR_OK) {
        TEST_ASSERT(pub.e == 3, "pub.e == 3");
        TEST_ASSERT(pub.nlen == 1024 / SDC_WORD_BITS, "1024-bit nlen correct");
        sdc_rsa_free_keypair(&pub, &priv);
    }

    /* invalid params */
    ret = sdc_rsa_keypair(NULL, NULL, 65537, 2048);
    TEST_ASSERT(ret == SDC_ERR_INVALID_PARAM, "NULL pubkey");

    ret = sdc_rsa_keypair(&pub, NULL, 65537, 2048);
    TEST_ASSERT(ret == SDC_ERR_INVALID_PARAM, "NULL privkey");

    ret = sdc_rsa_keypair(&pub, &priv, 65537, 0);
    TEST_ASSERT(ret == SDC_ERR_INVALID_PARAM, "bits == 0");

    ret = sdc_rsa_keypair(&pub, &priv, 65537, 2047);
    TEST_ASSERT(ret == SDC_ERR_INVALID_PARAM, "bits not word-aligned");
}

/* ============================================================
   Test: key math correctness
   ============================================================ */
static void test_math(void) {
    sdc_rsa_pubkey_t pub;
    sdc_rsa_privkey_t priv;

    TEST_START("RSA math correctness");

    memset(&pub, 0, sizeof(pub));
    memset(&priv, 0, sizeof(priv));

    int ret = sdc_rsa_keypair(&pub, &priv, 65537, 2048);
    if (ret != SDC_ERR_OK) {
        TEST_ASSERT(0, "keypair generation failed");
        return;
    }

    size_t len1 = priv.len1;
    size_t len2 = priv.len2;

    /*
     * Scratch layout:
     *   p_minus_1       : len1 words
     *   q_minus_1       : len1 words
     *   phi             : len2 words
     *   ed              : len2 + 1 words
     *   mul_result      : len1 * 2 words (for q * qinv)
     *   reduce_result   : len1 words
     *   scratch_pad     : len2 * 4 words (for mont operations)
     */
    size_t tmp_words = len1 + len1 + len2 + (len2 + 1) + (len1 * 2) + len1 + (len2 * 4);
    sdc_word_t *tmp = (sdc_word_t *)alloc_zero(tmp_words * SDC_WORD_SIZE);
    if (!tmp) {
        TEST_ASSERT(0, "malloc failed");
        sdc_rsa_free_keypair(&pub, &priv);
        return;
    }

    sdc_word_t *p_minus_1 = tmp;
    sdc_word_t *q_minus_1 = p_minus_1 + len1;
    sdc_word_t *phi = q_minus_1 + len1;
    sdc_word_t *ed = phi + len2;
    sdc_word_t *mul_result = ed + len2 + 1;
    sdc_word_t *reduce_result = mul_result + len1 * 2;
    sdc_word_t *scratch = reduce_result + len1;

    /* Test 1: n == p * q */
    sdc_int_mul(scratch, priv.p, priv.q, len1);
    TEST_ASSERT(sdc_int_eq(scratch, priv.n, len2) == 1, "n == p * q");

    /* Test 2: public n == private n */
    TEST_ASSERT(sdc_int_eq(pub.n, priv.n, len2) == 1, "public n == private n");

    /* Test 3: phi = (p-1)*(q-1) */
    sdc_int_copy(p_minus_1, priv.p, len1);
    sdc_int_copy(q_minus_1, priv.q, len1);
    p_minus_1[0]--;
    q_minus_1[0]--;
    sdc_int_mul(phi, p_minus_1, q_minus_1, len1);

    /* Test 4: e * d == 1 mod phi */
    sdc_int_mul_word(ed, priv.d, pub.e, len2);
    sdc_int_reduce(scratch, ed, len2 + 1, phi, len2);
    TEST_ASSERT(sdc_int_eq_word(scratch, 1, len2) == 1, "e * d == 1 mod phi");

    /* Test 5: dp == d mod (p-1) */
    sdc_int_copy(p_minus_1, priv.p, len1);
    p_minus_1[0]--;
    sdc_int_reduce(scratch, priv.d, len2, p_minus_1, len1);
    TEST_ASSERT(sdc_int_eq(scratch, priv.dp, len1) == 1, "dp == d mod (p-1)");

    /* Test 6: dq == d mod (q-1) */
    sdc_int_copy(q_minus_1, priv.q, len1);
    q_minus_1[0]--;
    sdc_int_reduce(scratch, priv.d, len2, q_minus_1, len1);
    TEST_ASSERT(sdc_int_eq(scratch, priv.dq, len1) == 1, "dq == d mod (q-1)");

    /* Test 7: qinv == q^{-1} mod p */
    sdc_int_mul(mul_result, priv.q, priv.qinv, len1);
    sdc_int_reduce(reduce_result, mul_result, len1 * 2, priv.p, len1);
    TEST_ASSERT(sdc_int_eq_word(reduce_result, 1, len1) == 1, "qinv == q^{-1} mod p");

    sdc_free(tmp);
    sdc_rsa_free_keypair(&pub, &priv);
}

/* ============================================================
   Test: RSA round-trip
   ============================================================ */
static void test_roundtrip(void) {
    sdc_rsa_pubkey_t pub;
    sdc_rsa_privkey_t priv;

    TEST_START("RSA encrypt/decrypt round-trip");

    memset(&pub, 0, sizeof(pub));
    memset(&priv, 0, sizeof(priv));

    int ret = sdc_rsa_keypair(&pub, &priv, 65537, 2048);
    if (ret != SDC_ERR_OK) {
        TEST_ASSERT(0, "keypair generation failed");
        return;
    }

    size_t len2 = priv.len2;
    size_t bytes = len2 * SDC_WORD_SIZE;

    /* allocate buffers */
    sdc_word_t *msg = (sdc_word_t *)alloc_zero(bytes);
    sdc_word_t *cipher = (sdc_word_t *)alloc_zero(bytes);
    sdc_word_t *decrypted = (sdc_word_t *)alloc_zero(bytes);
    sdc_word_t *verify = (sdc_word_t *)alloc_zero(bytes);
    sdc_word_t *tmp = (sdc_word_t *)alloc_zero(len2 * 4 * SDC_WORD_SIZE);

    if (!msg || !cipher || !decrypted || !verify || !tmp) {
        TEST_ASSERT(0, "malloc failed");
        goto cleanup;
    }

    /* generate message < n */
    gen_message(msg, len2);

    sdc_word_t ninv = sdc_int_calculate_ninv(pub.n[0]);

    /* encrypt: c = m^e mod n */
    sdc_int_mont_modexp_with_ebits(cipher, msg, pub.e, pub.e_bits, pub.n, tmp, len2, ninv);
    /* decrypt: m' = c^d mod n */
    sdc_int_mont_modexp_word(decrypted, cipher, priv.d, len2, pub.n, tmp, len2, ninv);
    TEST_ASSERT(sdc_int_eq(msg, decrypted, len2) == 1, "round-trip: decrypt(encrypt(msg)) == msg");

cleanup:
    sdc_free(msg);
    sdc_free(cipher);
    sdc_free(decrypted);
    sdc_free(verify);
    sdc_free(tmp);
    sdc_rsa_free_keypair(&pub, &priv);
}

/* ============================================================
   Test: CRT
   ============================================================ */
static void test_crt(void) {
    sdc_rsa_pubkey_t pubkey;
    sdc_rsa_privkey_t privkey;
    int ret;

    TEST_START("CRT decryption");

    memset(&pubkey, 0, sizeof(pubkey));
    memset(&privkey, 0, sizeof(privkey));

    ret = sdc_rsa_keypair(&pubkey, &privkey, 65537, 2048);
    TEST_ASSERT(ret == SDC_ERR_OK, "Generate key for CRT test");
    if (ret != SDC_ERR_OK) {
        return;
    }

    size_t len1 = privkey.len1;
    size_t len2 = privkey.len2;
    size_t mod_bytes = len2 * SDC_WORD_SIZE;

    /* Allocate buffers */
    sdc_word_t *msg = sdc_malloc(len2 * SDC_WORD_SIZE);
    sdc_word_t *cipher = sdc_malloc(len2 * SDC_WORD_SIZE);
    sdc_word_t *dec_direct = sdc_malloc(len2 * SDC_WORD_SIZE);
    sdc_word_t *dec_crt = sdc_malloc(len2 * SDC_WORD_SIZE);
    sdc_word_t *tmp = sdc_malloc(len2 * 6 * SDC_WORD_SIZE);

    if (!msg || !cipher || !dec_direct || !dec_crt || !tmp) {
        TEST_ASSERT(0, "Memory allocation failed");
        goto cleanup;
    }

    /* Generate random message and encrypt */
    for (size_t i = 0; i < mod_bytes; i++) {
        ((uint8_t *)msg)[i] = (uint8_t)(i * 0x37 + 0x9e);
    }
    ((uint8_t *)msg)[0] = 0x01;

    sdc_word_t ninv = sdc_int_calculate_ninv(pubkey.n[0]);
    sdc_int_mont_modexp_with_ebits(cipher, msg, pubkey.e, pubkey.e_bits,
                             pubkey.n, tmp, len2, ninv);

    /* 1. Direct decryption: m = c^d mod n */
    sdc_int_mont_modexp_word(dec_direct, cipher, privkey.d, len2,
                             pubkey.n, tmp, len2, ninv);

    /* 2. CRT decryption */
    /* m1 = c mod p, m2 = c mod q */
    sdc_int_reduce(tmp, cipher, len2, privkey.p, len1);
    sdc_word_t *m1 = tmp;
    sdc_word_t *m2 = tmp + len1;
    sdc_int_reduce(m2, cipher, len2, privkey.q, len1);

    /* c1 = m1^dp mod p, c2 = m2^dq mod q */
    sdc_word_t *c1 = tmp + 2 * len1;
    sdc_word_t *c2 = tmp + 3 * len1;
    sdc_word_t *scratch = tmp + 4 * len1;

    sdc_word_t pinv = sdc_int_calculate_ninv(privkey.p[0]);
    sdc_int_mont_modexp_word(c1, m1, privkey.dp, len1,
                             privkey.p, scratch, len1, pinv);

    sdc_word_t qinv = sdc_int_calculate_ninv(privkey.q[0]);
    sdc_int_mont_modexp_word(c2, m2, privkey.dq, len1,
                             privkey.q, scratch, len1, qinv);

    /* CRT combination: m = c2 + q * ((c1 - c2) * qinv mod p) */
    sdc_word_t *t = scratch;
    sdc_word_t *prod = scratch + len1;
    sdc_word_t *qt = scratch + 2 * len1;

    /* t = (c1 - c2) mod p */
    sdc_int_sub(t, c1, c2, len1);
    sdc_int_add_ctl(t, privkey.p, len1, sdc_int_lt(c1, c2, len1));

    /* t = t * qinv mod p */
    sdc_int_mul(prod, t, privkey.qinv, len1);
    sdc_int_reduce(t, prod, len1 * 2, privkey.p, len1);

    /* m = c2 + q * t */
    sdc_int_mul(qt, privkey.q, t, len1);
    sdc_int_set_word(dec_crt, 0, len2);
    sdc_int_copy(dec_crt, c2, len1);
    sdc_int_add(dec_crt, dec_crt, qt, len2);

    /* Compare direct decryption and CRT decryption */
    TEST_ASSERT(sdc_int_eq(dec_direct, dec_crt, len2) == 1,
                "CRT decryption matches direct decryption");

    /* Verify decrypted message matches original message */
    TEST_ASSERT(sdc_int_eq(msg, dec_direct, len2) == 1,
                "Decrypted message matches original");

cleanup:
    sdc_free(msg);
    sdc_free(cipher);
    sdc_free(dec_direct);
    sdc_free(dec_crt);
    sdc_free(tmp);
    sdc_rsa_free_keypair(&pubkey, &privkey);
}

/* ============================================================
   Test: public key init
   ============================================================ */

static void test_pubkey_init(void) {
    sdc_rsa_pubkey_t pub;
    int ret;

    TEST_START("sdc_rsa_pubkey_init");

    /* generate a key to get real modulus */
    sdc_rsa_privkey_t priv;
    memset(&pub, 0, sizeof(pub));
    memset(&priv, 0, sizeof(priv));

    ret = sdc_rsa_keypair(&pub, &priv, 65537, 1024);
    if (ret == SDC_ERR_OK) {
        sdc_rsa_pubkey_t pub2;
        memset(&pub2, 0, sizeof(pub2));

        size_t nbytes = pub.nlen * SDC_WORD_SIZE;
        uint8_t *n_bytes = (uint8_t *)sdc_malloc(nbytes);
        if (n_bytes) {
            sdc_int_tobytes_be(pub.n, pub.nlen, n_bytes);
            ret = sdc_rsa_pubkey_init(&pub2, n_bytes, nbytes, pub.e);
            TEST_ASSERT(ret == SDC_ERR_OK, "init from bytes");
            sdc_free(n_bytes);
            sdc_rsa_free_keypair(&pub2, NULL);
        }
        sdc_rsa_free_keypair(&pub, &priv);
    }

    /* error cases */
    ret = sdc_rsa_pubkey_init(NULL, NULL, 0, 0);
    TEST_ASSERT(ret == SDC_ERR_INVALID_PARAM, "NULL pubkey");

    ret = sdc_rsa_pubkey_init(&pub, NULL, 32, 65537);
    TEST_ASSERT(ret == SDC_ERR_INVALID_PARAM, "NULL n");

    ret = sdc_rsa_pubkey_init(&pub, (uint8_t *)"\x01\x02", 2, 0);
    TEST_ASSERT(ret == SDC_ERR_INVALID_PARAM, "e == 0");

    ret = sdc_rsa_pubkey_init(&pub, (uint8_t *)"\x01\x02", 3, 65537);
    TEST_ASSERT(ret == SDC_ERR_INVALID_PARAM, "misaligned nlen");

    ret = sdc_rsa_pubkey_init(&pub, (uint8_t *)"\x00\x00\x00\x00\x00\x00\x00\x00", 8, 65537);
    TEST_ASSERT(ret == SDC_ERR_KEY_INVALID || ret == SDC_ERR_INVALID_PARAM, "zero modulus");
}

/* ============================================================
   Test: private key init (error paths only)
   ============================================================ */

static void test_privkey_init(void) {
    sdc_rsa_privkey_t priv;
    int ret;

    TEST_START("sdc_rsa_privkey_init");

    memset(&priv, 0, sizeof(priv));

    ret = sdc_rsa_privkey_init(NULL, NULL, NULL, NULL, NULL, 0, 0, NULL, NULL, 0);
    TEST_ASSERT(ret == SDC_ERR_INVALID_PARAM, "NULL privkey");

    ret = sdc_rsa_privkey_init(&priv, (uint8_t *)"\x01", (uint8_t *)"\x02",
                               NULL, NULL, NULL, 1,
                               (uint8_t *)"\x03", (uint8_t *)"\x04", 2);
    TEST_ASSERT(ret == SDC_ERR_INVALID_PARAM, "misaligned len1");

    ret = sdc_rsa_privkey_init(&priv, (uint8_t *)"\x01\x02", (uint8_t *)"\x03\x04",
                               NULL, NULL, NULL, 2,
                               (uint8_t *)"\x05\x06", (uint8_t *)"\x07\x08", 1);
    TEST_ASSERT(ret == SDC_ERR_INVALID_PARAM, "misaligned len2");

    ret = sdc_rsa_privkey_init(&priv, (uint8_t *)"\x01\x02", (uint8_t *)"\x03\x04",
                               NULL, NULL, NULL, 2,
                               (uint8_t *)"\x05\x06", (uint8_t *)"\x07\x08", 8);
    TEST_ASSERT(ret == SDC_ERR_INVALID_PARAM, "len2 != len1*2");
}

/* ============================================================
   Test: free keypair
   ============================================================ */

static void test_free(void) {
    sdc_rsa_pubkey_t pub;
    sdc_rsa_privkey_t priv;

    TEST_START("sdc_rsa_free_keypair");

    sdc_rsa_free_keypair(NULL, NULL);
    TEST_ASSERT(1 == 1, "free(NULL, NULL) no crash");

    memset(&pub, 0, sizeof(pub));
    memset(&priv, 0, sizeof(priv));

    int ret = sdc_rsa_keypair(&pub, &priv, 65537, 1024);
    if (ret == SDC_ERR_OK) {
        sdc_rsa_free_keypair(&pub, &priv);
        TEST_ASSERT(pub.n == NULL, "pub.n == NULL");
        TEST_ASSERT(priv._block_start == NULL, "priv._block_start == NULL");
        TEST_ASSERT(priv.p == NULL, "priv.p == NULL");
        TEST_ASSERT(priv.q == NULL, "priv.q == NULL");
        TEST_ASSERT(priv.d == NULL, "priv.d == NULL");
        TEST_ASSERT(priv.n == NULL, "priv.n == NULL");
    }
}

/* ============================================================
   Test: CRT performance comparison
   ============================================================ */
static void test_crt_performance(void) {
    sdc_rsa_pubkey_t pubkey;
    sdc_rsa_privkey_t privkey;
    int ret;

    TEST_START("CRT performance");

    memset(&pubkey, 0, sizeof(pubkey));
    memset(&privkey, 0, sizeof(privkey));

    ret = sdc_rsa_keypair(&pubkey, &privkey, 65537, 2048);
    if (ret != SDC_ERR_OK) {
        TEST_ASSERT(0, "keypair generation failed");
        return;
    }

    size_t len1 = privkey.len1;
    size_t len2 = privkey.len2;
    size_t mod_bytes = len2 * SDC_WORD_SIZE;

    sdc_word_t *msg = sdc_malloc(len2 * SDC_WORD_SIZE);
    sdc_word_t *cipher = sdc_malloc(len2 * SDC_WORD_SIZE);
    sdc_word_t *dec_direct = sdc_malloc(len2 * SDC_WORD_SIZE);
    sdc_word_t *dec_crt = sdc_malloc(len2 * SDC_WORD_SIZE);
    sdc_word_t *tmp = sdc_malloc(len2 * 6 * SDC_WORD_SIZE);

    if (!msg || !cipher || !dec_direct || !dec_crt || !tmp) {
        TEST_ASSERT(0, "Memory allocation failed");
        goto cleanup;
    }

    /* Generate a random message and encrypt it */
    for (size_t i = 0; i < mod_bytes; i++) {
        ((uint8_t *)msg)[i] = (uint8_t)(i * 0x37 + 0x9e);
    }
    ((uint8_t *)msg)[0] = 0x01;

    sdc_word_t ninv = sdc_int_calculate_ninv(pubkey.n[0]);
    sdc_int_mont_modexp_with_ebits(cipher, msg, pubkey.e, pubkey.e_bits,
                             pubkey.n, tmp, len2, ninv);

    /* Warmup: run once to warm up the cache */
    sdc_int_mont_modexp_word(dec_direct, cipher, privkey.d, len2,
                             pubkey.n, tmp, len2, ninv);

    /* Direct decryption timing */
    clock_t start = clock();
    int iterations = 10;
    for (int i = 0; i < iterations; i++) {
        sdc_int_mont_modexp_word(dec_direct, cipher, privkey.d, len2,
                                 pubkey.n, tmp, len2, ninv);
    }
    clock_t end = clock();
    double direct_time = (double)(end - start) / CLOCKS_PER_SEC * 1000.0 / iterations;

    /* CRT decryption timing */
    start = clock();
    for (int i = 0; i < iterations; i++) {
        /* m1 = c mod p, m2 = c mod q */
        sdc_int_reduce(tmp, cipher, len2, privkey.p, len1);
        sdc_word_t *m1 = tmp;
        sdc_word_t *m2 = tmp + len1;
        sdc_int_reduce(m2, cipher, len2, privkey.q, len1);

        sdc_word_t *c1 = tmp + 2 * len1;
        sdc_word_t *c2 = tmp + 3 * len1;
        sdc_word_t *scratch = tmp + 4 * len1;

        sdc_word_t pinv = sdc_int_calculate_ninv(privkey.p[0]);
        sdc_int_mont_modexp_word(c1, m1, privkey.dp, len1,
                                 privkey.p, scratch, len1, pinv);

        sdc_word_t qinv_n = sdc_int_calculate_ninv(privkey.q[0]);
        sdc_int_mont_modexp_word(c2, m2, privkey.dq, len1,
                                 privkey.q, scratch, len1, qinv_n);

        sdc_word_t *t = scratch;
        sdc_word_t *prod = scratch + len1;
        sdc_word_t *qt = scratch + 2 * len1;

        sdc_int_sub(t, c1, c2, len1);
        sdc_int_add_ctl(t, privkey.p, len1, sdc_int_lt(c1, c2, len1));

        sdc_int_mul(prod, t, privkey.qinv, len1);
        sdc_int_reduce(t, prod, len1 * 2, privkey.p, len1);

        sdc_int_mul(qt, privkey.q, t, len1);
        sdc_int_set_word(dec_crt, 0, len2);
        sdc_int_copy(dec_crt, c2, len1);
        sdc_int_add(dec_crt, dec_crt, qt, len2);
    }
    end = clock();
    double crt_time = (double)(end - start) / CLOCKS_PER_SEC * 1000.0 / iterations;

    printf("  Direct decryption: %.3f ms (avg of %d iterations)\n", direct_time, iterations);
    printf("  CRT decryption:    %.3f ms (avg of %d iterations)\n", crt_time, iterations);
    printf("  Speedup:           %.2fx\n", direct_time / crt_time);

    TEST_ASSERT(sdc_int_eq(msg, dec_direct, len2) == 1,
                "Direct decryption correct");

    TEST_ASSERT(sdc_int_eq(dec_direct, dec_crt, len2) == 1,
                "CRT result matches direct");

cleanup:
    sdc_free(msg);
    sdc_free(cipher);
    sdc_free(dec_direct);
    sdc_free(dec_crt);
    sdc_free(tmp);
    sdc_rsa_free_keypair(&pubkey, &privkey);
}

/* ============================================================
   main
   ============================================================ */

int main(void) {
    printf("===========================================\n");
    printf("  RSA Key Pair Test\n");
    printf("===========================================\n");

    test_keygen();
    test_math();
    test_roundtrip();
    test_crt();
    test_pubkey_init();
    test_privkey_init();
    test_free();
    test_crt_performance();

    printf("\n========================================\n");
    printf("Result: %d/%d tests passed\n", g_passed, g_total);
    printf("========================================\n");

    return (g_passed == g_total) ? 0 : 1;
}