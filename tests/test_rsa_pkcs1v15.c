/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * RSA-PKCS#1 v1.5 test
 * Includes: sign/verify and encrypt/decrypt
 */

#include <stdio.h>
#include <string.h>
#include <sdcrypt/config.h>
#include <sdcrypt/rsa.h>
#include <sdcrypt/hash.h>
#include <sdcrypt/sha2.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/rng.h>

#if SDC_ENABLE_RSASSA_PKCS1V15 && SDC_ENABLE_RSAES_PKCS1V15 && SDC_ENABLE_RSA_KEYGEN

static int test_passed = 0;
static int test_total = 0;

#define TEST_START(name) printf("\n=== %s ===\n", name)
#define TEST_ASSERT(cond, msg) \
    do { \
        test_total++; \
        if (cond) { \
            printf("  [PASS] %s\n", msg); \
            test_passed++; \
        } else { \
            printf("  [FAIL] %s\n", msg); \
        } \
    } while (0)

static int compare_bytes(const uint8_t *a, const uint8_t *b, size_t len) {
    return memcmp(a, b, len) == 0;
}

/* ============================================================
   Test 1: RSASSA-PKCS#1-v1.5 sign/verify
   ============================================================ */
static void test_sign_verify(void) {
    sdc_rsa_pubkey_t pubkey;
    sdc_rsa_privkey_t privkey;
    sdc_rng_ctx rng_ctx;
    int ret;

    sdc_rng_init(&rng_ctx, &sdc_system_rng_ops, NULL);
    TEST_START("RSASSA-PKCS#1-v1.5 sign/verify");

    /* 生成密钥对 */
    memset(&pubkey, 0, sizeof(pubkey));
    memset(&privkey, 0, sizeof(privkey));
    ret = sdc_rsa_keypair(&pubkey, &privkey, 0x10001, 2048, &rng_ctx);
    TEST_ASSERT(ret == SDC_ERR_OK, "Key pair generated");
    if (ret != SDC_ERR_OK) return;

    /* 测试消息 */
    const uint8_t msg[] = "Hello, RSA PKCS#1 v1.5!";
    uint8_t sig[256];
    size_t sig_len = sizeof(sig);

    /* 签名 */
    ret = sdc_rsassa_pkcs1v15_sign(&sdc_sha256_ops, &privkey,
                                   msg, sizeof(msg) - 1,
                                   sig, &sig_len, &rng_ctx);
    TEST_ASSERT(ret == SDC_ERR_OK, "Sign");
    TEST_ASSERT(sig_len == 2048 / 8, "Signature length correct");

    /* 验签（正确签名） */
    ret = sdc_rsassa_pkcs1v15_verify(&sdc_sha256_ops, &pubkey,
                                     msg, sizeof(msg) - 1,
                                     sig, sig_len);
    TEST_ASSERT(ret == SDC_ERR_OK, "Verify correct signature");

    /* 验签（篡改消息） */
    const uint8_t bad_msg[] = "Hello, RSA PKCS#1 v1.5! (tampered)";
    ret = sdc_rsassa_pkcs1v15_verify(&sdc_sha256_ops, &pubkey,
                                     bad_msg, sizeof(bad_msg) - 1,
                                     sig, sig_len);
    TEST_ASSERT(ret != SDC_ERR_OK, "Verify with tampered message fails");

    /* 验签（篡改签名） */
    uint8_t bad_sig[256];
    memcpy(bad_sig, sig, sig_len);
    bad_sig[0] ^= 0xFF;
    ret = sdc_rsassa_pkcs1v15_verify(&sdc_sha256_ops, &pubkey,
                                     msg, sizeof(msg) - 1,
                                     bad_sig, sig_len);
    TEST_ASSERT(ret != SDC_ERR_OK, "Verify with tampered signature fails");

    sdc_rsa_free_keypair(&pubkey, &privkey);
}

/* ============================================================
   Test 2: RSAES-PKCS#1-v1.5 encrypt/decrypt
   ============================================================ */
static void test_encrypt_decrypt(void) {
    sdc_rsa_pubkey_t pubkey;
    sdc_rsa_privkey_t privkey;
    sdc_rng_ctx rng_ctx;
    int ret;

    sdc_rng_init(&rng_ctx, &sdc_system_rng_ops, NULL);
    TEST_START("RSAES-PKCS#1-v1.5 encrypt/decrypt");

    /* 生成密钥对 */
    memset(&pubkey, 0, sizeof(pubkey));
    memset(&privkey, 0, sizeof(privkey));
    ret = sdc_rsa_keypair(&pubkey, &privkey, 0x10001, 2048, &rng_ctx);
    TEST_ASSERT(ret == SDC_ERR_OK, "Key pair generated");
    if (ret != SDC_ERR_OK) return;

    /* 测试明文（长度小于 mod_bytes - 11） */
    const uint8_t plaintext[] = "Hello, RSA Encryption!";
    uint8_t cipher[256];
    size_t cipher_len = sizeof(cipher);
    uint8_t decrypted[256];
    size_t decrypted_len = sizeof(decrypted);

    /* 加密 */
    ret = sdc_rsaes_pkcs1v15_encrypt(&pubkey,
                                     plaintext, sizeof(plaintext) - 1,
                                     cipher, &cipher_len,
                                     &rng_ctx);
    TEST_ASSERT(ret == SDC_ERR_OK, "Encrypt");
    TEST_ASSERT(cipher_len == 2048 / 8, "Ciphertext length correct");

    /* 解密 */
    ret = sdc_rsaes_pkcs1v15_decrypt(&privkey,
                                     cipher, cipher_len,
                                     decrypted, &decrypted_len, &rng_ctx);
    TEST_ASSERT(ret == SDC_ERR_OK, "Decrypt");
    TEST_ASSERT(decrypted_len == sizeof(plaintext) - 1, "Plaintext length correct");
    TEST_ASSERT(compare_bytes(plaintext, decrypted, decrypted_len), "Plaintext matches");

    /* 解密（篡改密文） */
    uint8_t bad_cipher[256];
    memcpy(bad_cipher, cipher, cipher_len);
    bad_cipher[0] ^= 0xFF;
    ret = sdc_rsaes_pkcs1v15_decrypt(&privkey,
                                     bad_cipher, cipher_len,
                                     decrypted, &decrypted_len, &rng_ctx);
    TEST_ASSERT(ret != SDC_ERR_OK, "Decrypt with tampered ciphertext fails");

    sdc_rsa_free_keypair(&pubkey, &privkey);
}

/* ============================================================
   Test 3: Edge cases
   ============================================================ */
static void test_edge_cases(void) {
    sdc_rsa_pubkey_t pubkey;
    sdc_rsa_privkey_t privkey;
    sdc_rng_ctx rng_ctx;
    int ret;
    uint8_t buf[256];
    size_t buf_len = sizeof(buf);

    sdc_rng_init(&rng_ctx, &sdc_system_rng_ops, NULL);
    TEST_START("Edge cases");

    memset(&pubkey, 0, sizeof(pubkey));
    memset(&privkey, 0, sizeof(privkey));
    ret = sdc_rsa_keypair(&pubkey, &privkey, 0x10001, 2048, &rng_ctx);
    TEST_ASSERT(ret == SDC_ERR_OK, "Key pair generated");
    if (ret != SDC_ERR_OK) return;

    size_t mod_bytes = pubkey.nlen * SDC_WORD_SIZE;

    /* 加密：明文长度恰好为 mod_bytes - 11（最大长度） */
    uint8_t max_plaintext[256];
    size_t max_len = mod_bytes - 11;
    for (size_t i = 0; i < max_len; i++) {
        max_plaintext[i] = (uint8_t)(i & 0xFF);
    }
    uint8_t max_cipher[256];
    size_t max_cipher_len = sizeof(max_cipher);
    ret = sdc_rsaes_pkcs1v15_encrypt(&pubkey,
                                     max_plaintext, max_len,
                                     max_cipher, &max_cipher_len,
                                     &rng_ctx);
    TEST_ASSERT(ret == SDC_ERR_OK, "Encrypt max length plaintext");

    /* 加密：明文长度超过 mod_bytes - 11（应失败） */
    uint8_t too_long[512];
    ret = sdc_rsaes_pkcs1v15_encrypt(&pubkey,
                                     too_long, mod_bytes - 10,
                                     buf, &buf_len,
                                     &rng_ctx);
    TEST_ASSERT(ret == SDC_ERR_INVALID_PARAM, "Encrypt too long plaintext fails");

    sdc_rsa_free_keypair(&pubkey, &privkey);
}

/* ============================================================
   main
   ============================================================ */
int main(void) {
    printf("===========================================\n");
    printf("  RSA PKCS#1 v1.5 Test\n");
    printf("===========================================\n");

    test_sign_verify();
    test_encrypt_decrypt();
    test_edge_cases();

    printf("\n========================================\n");
    printf("Result: %d/%d tests passed\n", test_passed, test_total);
    printf("========================================\n");

    return (test_passed == test_total) ? 0 : 1;
}

#else

int main(void) {
    printf("RSA PKCS#1 v1.5 is disabled.\n");
    return 0;
}

#endif /* SDC_ENABLE_RSASSA_PKCS1V15 && SDC_ENABLE_RSAES_PKCS1V15 && SDC_ENABLE_RSA_KEYGEN */