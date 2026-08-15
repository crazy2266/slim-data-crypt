/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Comprehensive test for hash scheduler.
 * Tests:
 *   - Built-in hash algorithms (SHA-224/256/384/512)
 *   - Per-thread custom registration
 *   - Lookup priority (custom overrides built-in)
 *   - Unregister and clear
 */

#include <stdio.h>
#include <string.h>
#include <sdcrypt/hash.h>
#include <sdcrypt/config.h>
#include <sdcrypt/errcode.h>

/* ============================================================
   Test vectors (RFC 6234 / NIST)
   ============================================================ */

/* ----- 空消息 ----- */
static const uint8_t empty_sha224[28] = {
    0xd1,0x4a,0x02,0x8c,0x2a,0x3a,0x2b,0xc9,0x47,0x61,0x02,0xbb,0x28,0x82,
    0x34,0xc4,0x15,0xa2,0xb0,0x1f,0x82,0x8e,0xa6,0x2a,0xc5,0xb3,0xe4,0x2f
};
static const uint8_t empty_sha256[32] = {
    0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,
    0xb9,0x24,0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,
    0x78,0x52,0xb8,0x55
};
static const uint8_t empty_sha384[48] = {
    0x38,0xb0,0x60,0xa7,0x51,0xac,0x96,0x38,0x4c,0xd9,0x32,0x7e,0xb1,0xb1,
    0xe3,0x6a,0x21,0xfd,0xb7,0x11,0x14,0xbe,0x07,0x43,0x4c,0x0c,0xc7,0xbf,
    0x63,0xf6,0xe1,0xda,0x27,0x4e,0xde,0xbf,0xe7,0x6f,0x65,0xfb,0xd5,0x1a,
    0xd2,0xf1,0x48,0x98,0xb9,0x5b
};
static const uint8_t empty_sha512[64] = {
    0xcf,0x83,0xe1,0x35,0x7e,0xef,0xb8,0xbd,0xf1,0x54,0x28,0x50,0xd6,0x6d,
    0x80,0x07,0xd6,0x20,0xe4,0x05,0x0b,0x57,0x15,0xdc,0x83,0xf4,0xa9,0x21,
    0xd3,0x6c,0xe9,0xce,0x47,0xd0,0xd1,0x3c,0x5d,0x85,0xf2,0xb0,0xff,0x83,
    0x18,0xd2,0x87,0x7e,0xec,0x2f,0x63,0xb9,0x31,0xbd,0x47,0x41,0x7a,0x81,
    0xa5,0x38,0x32,0x7a,0xf9,0x27,0xda,0x3e
};

/* ----- "abc" ----- */
static const uint8_t abc_sha224[28] = {
    0x23,0x09,0x7d,0x22,0x34,0x05,0xd8,0x22,0x86,0x42,0xa4,0x77,0xbd,0xa2,
    0x55,0xb3,0x2a,0xad,0xbc,0xe4,0xbd,0xa0,0xb3,0xf7,0xe3,0x6c,0x9d,0xa7
};
static const uint8_t abc_sha256[32] = {
    0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,
    0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,
    0xf2,0x00,0x15,0xad
};
static const uint8_t abc_sha384[48] = {
    0xcb,0x00,0x75,0x3f,0x45,0xa3,0x5e,0x8b,0xb5,0xa0,0x3d,0x69,0x9a,0xc6,
    0x50,0x07,0x27,0x2c,0x32,0xab,0x0e,0xde,0xd1,0x63,0x1a,0x8b,0x60,0x5a,
    0x43,0xff,0x5b,0xed,0x80,0x86,0x07,0x2b,0xa1,0xe7,0xcc,0x23,0x58,0xba,
    0xec,0xa1,0x34,0xc8,0x25,0xa7
};
static const uint8_t abc_sha512[64] = {
    0xdd,0xaf,0x35,0xa1,0x93,0x61,0x7a,0xba,0xcc,0x41,0x73,0x49,0xae,0x20,
    0x41,0x31,0x12,0xe6,0xfa,0x4e,0x89,0xa9,0x7e,0xa2,0x0a,0x9e,0xee,0xe6,
    0x4b,0x55,0xd3,0x9a,0x21,0x92,0x99,0x2a,0x27,0x4f,0xc1,0xa8,0x36,0xba,
    0x3c,0x23,0xa3,0xfe,0xeb,0xbd,0x45,0x4d,0x44,0x23,0x64,0x3c,0xe8,0x0e,
    0x2a,0x9a,0xc9,0x4f,0xa5,0x4c,0xa4,0x9f
};

/* ============================================================
   Helper functions
   ============================================================ */

static int compare_bytes(const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

static void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}

static int run_hash_test(sdc_hash_id_t id,
                         const uint8_t *in, size_t in_len,
                         const uint8_t *expected, size_t expected_len) {
    uint8_t out[64];
    size_t out_len;
    int ret = sdc_hash_compute(id, in, in_len, out, &out_len);

    if (ret != SDC_ERR_OK) {
        printf("  [FAIL] sdc_hash_compute returned %d\n", ret);
        return 0;
    }

    if (out_len != expected_len) {
        printf("  [FAIL] length mismatch: expected %zu, got %zu\n",
               expected_len, out_len);
        return 0;
    }

    if (!compare_bytes(out, expected, expected_len)) {
        printf("  [FAIL] hash mismatch\n");
        printf("    期望: ");
        print_hex(expected, expected_len);
        printf("\n    计算: ");
        print_hex(out, expected_len);
        printf("\n");
        return 0;
    }

    printf("  [PASS] %s\n", sdc_hash_name(id) ? sdc_hash_name(id) : "Unknown");
    return 1;
}

/* ============================================================
   Custom hash implementation for testing override
   ============================================================ */

/* 一个“假”的 SHA-256 实现，用于验证自定义注册能覆盖内置算法 */
static void fake_sha256_hash(uint8_t *out, const uint8_t *in, size_t len) {
    (void)in;
    (void)len;
    /* 输出全 0x01，便于识别 */
    memset(out, 0x01, 32);
}

static const sdc_hash_ops_t fake_sha256_ops = {
    .hash = fake_sha256_hash,
    .hash_len = 32,
    .name = "FAKE-SHA-256"
};

/* ============================================================
   Main
   ============================================================ */

int main(void) {
    int passed = 0, total = 0;

    printf("========================================\n");
    printf("  Hash Scheduler Test\n");
    printf("========================================\n\n");

    sdc_hash_table_clear();

    /* ============================================================
       Test 1: Built-in algorithms (empty message)
       ============================================================ */
    printf("[Test 1] Built-in: empty message\n");
    const uint8_t empty[] = "";
    total += 4;
    if (run_hash_test(SDC_HASH_SHA224, empty, 0, empty_sha224, 28)) passed++;
    if (run_hash_test(SDC_HASH_SHA256, empty, 0, empty_sha256, 32)) passed++;
    if (run_hash_test(SDC_HASH_SHA384, empty, 0, empty_sha384, 48)) passed++;
    if (run_hash_test(SDC_HASH_SHA512, empty, 0, empty_sha512, 64)) passed++;
    printf("\n");

    /* ============================================================
       Test 2: Built-in algorithms ("abc")
       ============================================================ */
    printf("[Test 2] Built-in: \"abc\"\n");
    const uint8_t abc[] = "abc";
    total += 4;
    if (run_hash_test(SDC_HASH_SHA224, abc, 3, abc_sha224, 28)) passed++;
    if (run_hash_test(SDC_HASH_SHA256, abc, 3, abc_sha256, 32)) passed++;
    if (run_hash_test(SDC_HASH_SHA384, abc, 3, abc_sha384, 48)) passed++;
    if (run_hash_test(SDC_HASH_SHA512, abc, 3, abc_sha512, 64)) passed++;
    printf("\n");

    /* ============================================================
       Test 3: Custom registration (override built-in)
       ============================================================ */
    printf("[Test 3] Custom registration (override SHA-256)\n");
    total += 2;

    /* 注册自定义 SHA-256 */
    int ret = sdc_hash_register(SDC_HASH_SHA256, &fake_sha256_ops);
    if (ret != SDC_ERR_OK) {
        printf("  [FAIL] sdc_hash_register returned %d\n", ret);
    } else {
        printf("  [PASS] sdc_hash_register\n");
        passed++;
    }

    /* 现在 SHA-256 应该返回 fake 值 (全 0x01) */
    uint8_t out[64];
    size_t out_len;
    ret = sdc_hash_compute(SDC_HASH_SHA256, abc, 3, out, &out_len);
    if (ret != SDC_ERR_OK) {
        printf("  [FAIL] sdc_hash_compute returned %d\n", ret);
    } else if (out_len != 32) {
        printf("  [FAIL] length mismatch: expected 32, got %zu\n", out_len);
    } else {
        /* 检查是否全 0x01 */
        int all_one = 1;
        for (size_t i = 0; i < 32; i++) {
            if (out[i] != 0x01) { all_one = 0; break; }
        }
        if (all_one) {
            printf("  [PASS] custom SHA-256 produced expected output (all 0x01)\n");
            passed++;
        } else {
            printf("  [FAIL] custom SHA-256 output mismatch\n");
        }
    }
    printf("\n");

    /* ============================================================
       Test 4: Unregister custom (restore built-in)
       ============================================================ */
    printf("[Test 4] Unregister custom (restore built-in SHA-256)\n");
    total += 1;

    sdc_hash_unregister(SDC_HASH_SHA256);
    if (run_hash_test(SDC_HASH_SHA256, abc, 3, abc_sha256, 32)) passed++;
    printf("\n");

    /* ============================================================
       Test 5: Clear all custom
       ============================================================ */
    printf("[Test 5] Register then clear all\n");
    total += 2;

    sdc_hash_register(SDC_HASH_SHA256, &fake_sha256_ops);
    sdc_hash_register(SDC_HASH_SHA384, &fake_sha256_ops);  /* 用 fake 填 SHA-384 */

    sdc_hash_table_clear();

    /* 清除后，应该恢复为内置实现 */
    if (run_hash_test(SDC_HASH_SHA256, abc, 3, abc_sha256, 32)) passed++;
    if (run_hash_test(SDC_HASH_SHA384, abc, 3, abc_sha384, 48)) passed++;
    printf("\n");

    /* ============================================================
       Test 6: sdc_hash_available and sdc_hash_len
       ============================================================ */
    printf("[Test 6] sdc_hash_available and sdc_hash_len\n");
    total += 4;

    if (sdc_hash_available(SDC_HASH_SHA256)) {
        printf("  [PASS] sdc_hash_available(SHA-256) = true\n");
        passed++;
    } else {
        printf("  [FAIL] sdc_hash_available(SHA-256) = false\n");
    }

    if (sdc_hash_len(SDC_HASH_SHA256) == 32) {
        printf("  [PASS] sdc_hash_len(SHA-256) = 32\n");
        passed++;
    } else {
        printf("  [FAIL] sdc_hash_len(SHA-256) = %zu\n", sdc_hash_len(SDC_HASH_SHA256));
    }

    if (!sdc_hash_available(SDC_HASH_NONE)) {
        printf("  [PASS] sdc_hash_available(NONE) = false\n");
        passed++;
    } else {
        printf("  [FAIL] sdc_hash_available(NONE) = true\n");
    }

    if (sdc_hash_len(SDC_HASH_NONE) == 0) {
        printf("  [PASS] sdc_hash_len(NONE) = 0\n");
        passed++;
    } else {
        printf("  [FAIL] sdc_hash_len(NONE) = %zu\n", sdc_hash_len(SDC_HASH_NONE));
    }
    printf("\n");

    /* ============================================================
       Final result
       ============================================================ */
    printf("========================================\n");
    printf("Result: %d/%d tests passed\n", passed, total);
    printf("========================================\n");

    return (passed == total) ? 0 : 1;
}