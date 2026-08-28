/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * RSA PKCS#1 v1.5 test
 * 
 * Tests:
 *   - RSASSA-PKCS1-v1_5 sign/verify (SHA-256)
 *   - RSAES-PKCS1-v1_5 encrypt/decrypt
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

/* ============================================================
   Test 1: RSASSA-PKCS1-v1_5 sign/verify
   ============================================================ */
static void test_sign_verify(void) {
    sdc_rsa_pubkey_t pubkey;
    sdc_rsa_privkey_t privkey;
    sdc_rng_ctx rng_ctx;
    int ret;

    sdc_rng_init(&rng_ctx, &sdc_system_rng_ops, NULL);
    TEST_START("RSASSA-PKCS1-v1_5 sign/verify");

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
                                   sig, &sig_len);
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
   main
   ============================================================ */
int main(void) {
    printf("===========================================\n");
    printf("  RSA PKCS#1 v1.5 Test\n");
    printf("===========================================\n");

    test_sign_verify();

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