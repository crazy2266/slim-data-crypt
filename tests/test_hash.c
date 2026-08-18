/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Test hash lookup by OID.
 */

#include <stdio.h>
#include <string.h>
#include <sdcrypt/hash.h>
#include <sdcrypt/sha2.h>
#include <sdcrypt/config.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/oid.h>

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

/* ---------- 自定义哈希（用于测试插件机制） ---------- */
static int custom_init(sdc_hash_ctx *ctx) {
    (void)ctx;
    return SDC_ERR_OK;
}

static int custom_update(sdc_hash_ctx *ctx, const uint8_t *in, size_t len) {
    (void)ctx; (void)in; (void)len;
    return SDC_ERR_OK;
}

static int custom_final(sdc_hash_ctx *ctx, uint8_t *out, size_t *out_len) {
    (void)ctx;
    if (*out_len < 32) {
        *out_len = 32;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }
    memset(out, 0xAA, 32);
    *out_len = 32;
    return SDC_ERR_OK;
}

static int custom_hash(uint8_t *out, const uint8_t *in, size_t len, size_t *out_len) {
    (void)in; (void)len;
    if (!out || !out_len) return SDC_ERR_INVALID_PARAM;
    memset(out, 0xAA, 32);
    *out_len = 32;
    return SDC_ERR_OK;
}

/* 自定义 OID（1.2.3.4） */
static const uint8_t custom_oid[] = {0x2A, 0x03, 0x04};
#define CUSTOM_OID_LEN 3

static const sdc_hash_ops_t custom_ops = {
    .init = custom_init,
    .update = custom_update,
    .final = custom_final,
    .hash = custom_hash,
    .hash_len = 32,
    .name = "CUSTOM",
    .oid = custom_oid,
    .oid_len = CUSTOM_OID_LEN,
};

/* ---------- 自定义 getter（用于测试可替换查找） ---------- */
static const sdc_hash_ops_t* custom_getter(const uint8_t *oid, size_t oid_len) {
    if (oid_len == custom_ops.oid_len &&
        memcmp(oid, custom_ops.oid, oid_len) == 0) {
        return &custom_ops;
    }
    /* 回退到默认查找 */
    return sdc_hash_find_by_oid_default(oid, oid_len);
}

/* ---------- 辅助函数：通过 OID 计算哈希 ---------- */
static int hash_compute_by_oid(const uint8_t *oid, size_t oid_len,
                               const uint8_t *msg, size_t msg_len,
                               uint8_t *out, size_t *out_len,
                               sdc_hash_getter_t getter) {
    const sdc_hash_ops_t *ops = sdc_hash_find_by_oid(oid, oid_len, getter);
    if (!ops) return SDC_ERR_NOT_FOUND;

    // 检查输出缓冲区是否足够大
    if (*out_len < ops->hash_len) {
        *out_len = ops->hash_len;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }

    // 使用一次性哈希接口
    int ret = sdc_hash_once(ops, out, msg, msg_len, out_len);
    return ret;
}

/* ---------- main ---------- */
int main(void) {
    uint8_t hash[64];
    size_t out_len = sizeof(hash);
    const uint8_t msg[] = "abc";
    int ret;

    printf("===========================================\n");
    printf("  Hash Framework Test\n");
    printf("===========================================\n");

    /* ============================================================
       Test 1: SHA-256 via sdc_hash_once
       ============================================================ */
    TEST_START("SHA-256 (sdc_hash_once)");
    ret = sdc_hash_once(&sdc_sha256_ops, hash, msg, sizeof(msg) - 1, &out_len);
    TEST_ASSERT(ret == SDC_ERR_OK, "sdc_hash_once(SHA-256)");

    const uint8_t expected_sha256[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
        0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
        0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    TEST_ASSERT(compare_bytes(hash, expected_sha256, 32),
                "SHA-256(\"abc\") correct");

    /* ============================================================
       Test 2: SHA-256 via OID lookup (default getter)
       ============================================================ */
    TEST_START("SHA-256 (OID lookup)");
    out_len = sizeof(hash);
    ret = hash_compute_by_oid(SDC_OID_SHA256, SDC_OID_SHA256_LEN,
                              msg, sizeof(msg) - 1,
                              hash, &out_len, NULL);
    TEST_ASSERT(ret == SDC_ERR_OK && out_len == 32 &&
                compare_bytes(hash, expected_sha256, 32),
                "OID lookup finds SHA-256 and computes correctly");

    /* ============================================================
       Test 3: SHA-224 via OID lookup
       ============================================================ */
    TEST_START("SHA-224 (OID lookup)");
    out_len = sizeof(hash);
    ret = hash_compute_by_oid(SDC_OID_SHA224, SDC_OID_SHA224_LEN,
                              msg, sizeof(msg) - 1,
                              hash, &out_len, NULL);

    const uint8_t expected_sha224[28] = {
        0x23,0x09,0x7d,0x22,0x34,0x05,0xd8,0x22,
        0x86,0x42,0xa4,0x77,0xbd,0xa2,0x55,0xb3,
        0x2a,0xad,0xbc,0xe4,0xbd,0xa0,0xb3,0xf7,
        0xe3,0x6c,0x9d,0xa7
    };
    TEST_ASSERT(ret == SDC_ERR_OK && out_len == 28 &&
                compare_bytes(hash, expected_sha224, 28),
                "SHA-224(\"abc\") correct");

    /* ============================================================
       Test 4: SHA-384 via OID lookup
       ============================================================ */
    TEST_START("SHA-384 (OID lookup)");
    out_len = sizeof(hash);
    ret = hash_compute_by_oid(SDC_OID_SHA384, SDC_OID_SHA384_LEN,
                              msg, sizeof(msg) - 1,
                              hash, &out_len, NULL);

    const uint8_t expected_sha384[48] = {
        0xcb,0x00,0x75,0x3f,0x45,0xa3,0x5e,0x8b,
        0xb5,0xa0,0x3d,0x69,0x9a,0xc6,0x50,0x07,
        0x27,0x2c,0x32,0xab,0x0e,0xde,0xd1,0x63,
        0x1a,0x8b,0x60,0x5a,0x43,0xff,0x5b,0xed,
        0x80,0x86,0x07,0x2b,0xa1,0xe7,0xcc,0x23,
        0x58,0xba,0xec,0xa1,0x34,0xc8,0x25,0xa7
    };
    TEST_ASSERT(ret == SDC_ERR_OK && out_len == 48 &&
                compare_bytes(hash, expected_sha384, 48),
                "SHA-384(\"abc\") correct");

    /* ============================================================
       Test 5: SHA-512 via OID lookup
       ============================================================ */
    TEST_START("SHA-512 (OID lookup)");
    out_len = sizeof(hash);
    ret = hash_compute_by_oid(SDC_OID_SHA512, SDC_OID_SHA512_LEN,
                              msg, sizeof(msg) - 1,
                              hash, &out_len, NULL);

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
    TEST_ASSERT(ret == SDC_ERR_OK && out_len == 64 &&
                compare_bytes(hash, expected_sha512, 64),
                "SHA-512(\"abc\") correct");

    /* ============================================================
       Test 6: Unknown OID (should return NULL)
       ============================================================ */
    TEST_START("Unknown OID");
    const uint8_t unknown_oid[] = {0x01, 0x02, 0x03};
    const sdc_hash_ops_t *ops = sdc_hash_find_by_oid(unknown_oid, sizeof(unknown_oid), NULL);
    TEST_ASSERT(ops == NULL, "Unknown OID returns NULL");

    /* ============================================================
       Test 7: Custom OID via custom getter
       ============================================================ */
    TEST_START("Custom OID (custom getter)");
    out_len = sizeof(hash);
    ret = hash_compute_by_oid(custom_oid, CUSTOM_OID_LEN,
                              msg, sizeof(msg) - 1,
                              hash, &out_len, custom_getter);

    uint8_t expected_custom[32];
    memset(expected_custom, 0xAA, 32);
    TEST_ASSERT(ret == SDC_ERR_OK && out_len == 32 &&
                compare_bytes(hash, expected_custom, 32),
                "Custom getter finds custom OID and returns expected 0xAA bytes");

    /* ============================================================
       Test 8: Custom OID with default getter (should fail)
       ============================================================ */
    TEST_START("Custom OID (default getter, should fail)");
    ops = sdc_hash_find_by_oid(custom_oid, CUSTOM_OID_LEN, NULL);
    TEST_ASSERT(ops == NULL, "Default getter does NOT find custom OID");

    /* ============================================================
       Test 9: sdc_hash_once with NULL ops (should fail)
       ============================================================ */
    TEST_START("sdc_hash_once NULL ops");
    ret = sdc_hash_once(NULL, hash, msg, sizeof(msg) - 1, &out_len);
    TEST_ASSERT(ret == SDC_ERR_INVALID_PARAM, "NULL ops returns SDC_ERR_INVALID_PARAM");

    /* ============================================================
       Test 10: sdc_hash_final with too-small buffer
       ============================================================ */
    TEST_START("sdc_hash_final buffer too small");
    sdc_hash_ctx ctx;
    uint8_t small_buf[16];
    size_t small_len = 16;

    ret = sdc_hash_init(&ctx, &sdc_sha256_ops);
    TEST_ASSERT(ret == SDC_ERR_OK, "sdc_hash_init()");

    ret = sdc_hash_update(&ctx, msg, sizeof(msg) - 1);
    TEST_ASSERT(ret == SDC_ERR_OK, "sdc_hash_update()");

    ret = sdc_hash_final(&ctx, small_buf, &small_len);
    TEST_ASSERT(ret == SDC_ERR_BUFFER_TOO_SMALL && small_len == 32,
                "sdc_hash_final() returns SDC_ERR_BUFFER_TOO_SMALL and sets out_len=32");
/* ============================================================
   Test 11: SM3 via OID lookup
   ============================================================ */
    TEST_START("SM3 (OID lookup)");
    out_len = sizeof(hash);
    ret = hash_compute_by_oid(SDC_OID_SM3, SDC_OID_SM3_LEN,
                              msg, sizeof(msg) - 1,
                              hash, &out_len, NULL);

    /* SM3("abc") = 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0 */
    const uint8_t expected_sm3[32] = {
        0x66,0xc7,0xf0,0xf4,0x62,0xee,0xed,0xd9,
        0xd1,0xf2,0xd4,0x6b,0xdc,0x10,0xe4,0xe2,
        0x41,0x67,0xc4,0x87,0x5c,0xf2,0xf7,0xa2,
        0x29,0x7d,0xa0,0x2b,0x8f,0x4b,0xa8,0xe0
    };
    TEST_ASSERT(ret == SDC_ERR_OK && out_len == 32 &&
                compare_bytes(hash, expected_sm3, 32),
                "SM3(\"abc\") correct");
    /* ============================================================
       Final result
       ============================================================ */
    printf("\n========================================\n");
    printf("Result: %d/%d tests passed\n", test_passed, test_total);
    printf("========================================\n");
    return (test_passed == test_total) ? 0 : 1;
}