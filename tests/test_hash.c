/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Test hash lookup by OID.
 */

#include <stdio.h>
#include <string.h>
#include <sdcrypt/hash.h>
#include <sdcrypt/config.h>
#include <sdcrypt/errcode.h>

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
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

static void custom_hash(uint8_t *out, const uint8_t *in, size_t len) {
    (void)in; (void)len;
    memset(out, 0xAA, 32);
}

int main(void) {
    uint8_t hash[64];
    size_t out_len;
    const uint8_t msg[] = "abc";
    int ret;

    printf("===========================================\n");
    printf("  Hash OID Lookup Test (with WyHash Table)\n");
    printf("===========================================\n");

    /* Initialize hash table */
    TEST_START("sdc_hash_init");
    ret = sdc_hash_init();
    TEST_ASSERT(ret == SDC_ERR_OK, "sdc_hash_init()");

    /* ============================================================
       Test 1: Find and compute SHA-256
       ============================================================ */
    TEST_START("SHA-256");
    out_len = sizeof(hash);
    ret = sdc_hash_compute(SDC_OID_SHA256, SDC_OID_SHA256_LEN,
                           msg, sizeof(msg) - 1,
                           hash, &out_len);

    TEST_ASSERT(ret == SDC_ERR_OK, "sdc_hash_compute(SHA-256)");

    /* SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad */
    const uint8_t expected_sha256[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
        0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
        0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    TEST_ASSERT(out_len == 32 && compare_bytes(hash, expected_sha256, 32),
                "SHA-256(\"abc\") correct");

    /* ============================================================
       Test 2: Find and compute SHA-224
       ============================================================ */
    TEST_START("SHA-224");
    out_len = sizeof(hash);
    ret = sdc_hash_compute(SDC_OID_SHA224, SDC_OID_SHA224_LEN,
                           msg, sizeof(msg) - 1,
                           hash, &out_len);

    TEST_ASSERT(ret == SDC_ERR_OK, "sdc_hash_compute(SHA-224)");

    const uint8_t expected_sha224[28] = {
        0x23,0x09,0x7d,0x22,0x34,0x05,0xd8,0x22,
        0x86,0x42,0xa4,0x77,0xbd,0xa2,0x55,0xb3,
        0x2a,0xad,0xbc,0xe4,0xbd,0xa0,0xb3,0xf7,
        0xe3,0x6c,0x9d,0xa7
    };
    TEST_ASSERT(out_len == 28 && compare_bytes(hash, expected_sha224, 28),
                "SHA-224(\"abc\") correct");

    /* ============================================================
       Test 3: SHA-384
       ============================================================ */
    TEST_START("SHA-384");
    out_len = sizeof(hash);
    ret = sdc_hash_compute(SDC_OID_SHA384, SDC_OID_SHA384_LEN,
                           msg, sizeof(msg) - 1,
                           hash, &out_len);

    TEST_ASSERT(ret == SDC_ERR_OK, "sdc_hash_compute(SHA-384)");

    const uint8_t expected_sha384[48] = {
        0xcb,0x00,0x75,0x3f,0x45,0xa3,0x5e,0x8b,
        0xb5,0xa0,0x3d,0x69,0x9a,0xc6,0x50,0x07,
        0x27,0x2c,0x32,0xab,0x0e,0xde,0xd1,0x63,
        0x1a,0x8b,0x60,0x5a,0x43,0xff,0x5b,0xed,
        0x80,0x86,0x07,0x2b,0xa1,0xe7,0xcc,0x23,
        0x58,0xba,0xec,0xa1,0x34,0xc8,0x25,0xa7
    };
    TEST_ASSERT(out_len == 48 && compare_bytes(hash, expected_sha384, 48),
                "SHA-384(\"abc\") correct");

    /* ============================================================
       Test 4: SHA-512
       ============================================================ */
    TEST_START("SHA-512");
    out_len = sizeof(hash);
    ret = sdc_hash_compute(SDC_OID_SHA512, SDC_OID_SHA512_LEN,
                           msg, sizeof(msg) - 1,
                           hash, &out_len);

    TEST_ASSERT(ret == SDC_ERR_OK, "sdc_hash_compute(SHA-512)");

    const uint8_t expected_sha512[64] = {
        0xdd,0xaf,0x35,0xa1,0x93,0x61,0x7a,0xba,
        0xcc,0x41,0x73,0x49,0xae,0x20,0x41,0x31,
        0x12,0xe6,0xfa,0x4e,0x89,0xa9,0x7e,0xa2,
        0x0a,0x9e,0xee,0xe6,0x4b,0x55,0xd3,0x9a,
        0x21,0x92,0x99,0x2a,0x27,0x4f,0xc1,0xa8,
        0x36,0xba,0x3c,0x23,0xa3,0xfe,0xeb,0xbd,
        0x45,0x4d,0x44,0x23,0x64,0x3c,0xe8,0x0e,
        0x2a,0x9a,0xc9,0x4f,0xa5,0x4c,0xa4,0x9f
    };
    TEST_ASSERT(out_len == 64 && compare_bytes(hash, expected_sha512, 64),
                "SHA-512(\"abc\") correct");

    /* ============================================================
       Test 5: Unknown OID (should fail)
       ============================================================ */
    TEST_START("Unknown OID");
    const uint8_t unknown_oid[] = {0x01, 0x02, 0x03};
    out_len = sizeof(hash);
    ret = sdc_hash_compute(unknown_oid, sizeof(unknown_oid),
                           msg, sizeof(msg) - 1,
                           hash, &out_len);

    TEST_ASSERT(ret == SDC_ERR_NOT_FOUND, "Unknown OID returns SDC_ERR_NOT_FOUND");

    /* ============================================================
       Test 6: Register custom hash
       ============================================================ */
    TEST_START("Register custom hash");
    const uint8_t custom_oid[] = {0x01, 0x02, 0x03, 0x04};
    sdc_hash_ops_t custom_ops = {
        .hash = custom_hash,
        .hash_len = 32,
        .name = "CUSTOM"
    };

    ret = sdc_hash_register(custom_oid, sizeof(custom_oid), &custom_ops);
    TEST_ASSERT(ret == SDC_ERR_OK, "sdc_hash_register()");

    uint8_t custom_out[32];
    out_len = sizeof(custom_out);
    ret = sdc_hash_compute(custom_oid, sizeof(custom_oid),
                           msg, sizeof(msg) - 1,
                           custom_out, &out_len);
    TEST_ASSERT(ret == SDC_ERR_OK && out_len == 32,
                "Custom hash called and returns 32 bytes");

    /* ============================================================
       Final result
       ============================================================ */
    printf("\n========================================\n");
    printf("Result: %d/%d tests passed\n", test_passed, test_total);
    printf("========================================\n");

    return (test_passed == test_total) ? 0 : 1;
}