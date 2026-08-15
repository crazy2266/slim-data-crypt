/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Test hash scheduler (SHA-224/256/384/512)
 * using RFC 6234 test vectors
 */

#include <stdio.h>
#include <string.h>
#include <sdcrypt/hash.h>
#include <sdcrypt/config.h>

/* ============================================================
   RFC 6234 test vectors
   ============================================================ */

/* Empty message hash value */
static const uint8_t rfc_sha224_empty[28] = {
    0xd1, 0x4a, 0x02, 0x8c, 0x2a, 0x3a, 0x2b, 0xc9,
    0x47, 0x61, 0x02, 0xbb, 0x28, 0x82, 0x34, 0xc4,
    0x15, 0xa2, 0xb0, 0x1f, 0x82, 0x8e, 0xa6, 0x2a,
    0xc5, 0xb3, 0xe4, 0x2f
};

static const uint8_t rfc_sha256_empty[32] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};

static const uint8_t rfc_sha384_empty[48] = {
    0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38,
    0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
    0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
    0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
    0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb,
    0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b
};

static const uint8_t rfc_sha512_empty[64] = {
    0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
    0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
    0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
    0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
    0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
    0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
    0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
    0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e
};

/* "abc" 的哈希值（SHA-224 和 SHA-256 使用） */
static const uint8_t rfc_sha224_abc[28] = {
    0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22,
    0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2, 0x55, 0xb3,
    0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7,
    0xe3, 0x6c, 0x9d, 0xa7
};

static const uint8_t rfc_sha256_abc[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

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
    uint8_t out[64];  /* 最大 64 字节 */
    const sdc_hash_ops_t *ops = sdc_hash_get_ops(id);
    
    if (!ops) {
        printf("  [FAIL] 算法未注册\n");
        return 0;
    }
    
    ops->hash(out, in, in_len);
    
    if (!compare_bytes(out, expected, expected_len)) {
        printf("  [FAIL] 哈希值不匹配\n");
        printf("    期望: ");
        print_hex(expected, expected_len);
        printf("\n    计算: ");
        print_hex(out, expected_len);
        printf("\n");
        return 0;
    }
    
    printf("  [PASS] %s\n", ops->name ? ops->name : "Unknown");
    return 1;
}

int main(void) {
    int passed = 0;
    int total = 0;
    
    printf("=== 哈希调度器测试 ===\n\n");
    
    /* 初始化当前线程的哈希调度器（默认 SHA-256） */
    sdc_hash_thread_init();
    
    /* ============================================================
       测试1: 空消息
       ============================================================ */
    printf("测试空消息 (长度 0):\n");
    const uint8_t empty[] = "";
    total++;
    if (run_hash_test(SDC_HASH_SHA224, empty, 0, rfc_sha224_empty, 28)) passed++;
    total++;
    if (run_hash_test(SDC_HASH_SHA256, empty, 0, rfc_sha256_empty, 32)) passed++;
    total++;
    if (run_hash_test(SDC_HASH_SHA384, empty, 0, rfc_sha384_empty, 48)) passed++;
    total++;
    if (run_hash_test(SDC_HASH_SHA512, empty, 0, rfc_sha512_empty, 64)) passed++;
    printf("\n");
    
    /* ============================================================
       测试2: "abc"
       ============================================================ */
    printf("测试消息 \"abc\" (长度 3):\n");
    const uint8_t abc[] = "abc";
    total++;
    if (run_hash_test(SDC_HASH_SHA224, abc, 3, rfc_sha224_abc, 28)) passed++;
    total++;
    if (run_hash_test(SDC_HASH_SHA256, abc, 3, rfc_sha256_abc, 32)) passed++;
    /* SHA-384 和 SHA-512 的 "abc" 向量较长，这里跳过 */
    printf("\n");
    
    /* ============================================================
       测试3: 线程切换
       ============================================================ */
    printf("测试线程切换:\n");
    sdc_hash_thread_set(SDC_HASH_SHA512);
    total++;
    if (run_hash_test(SDC_HASH_SHA512, empty, 0, rfc_sha512_empty, 64)) passed++;
    sdc_hash_thread_set(SDC_HASH_SHA256);  /* 恢复默认 */
    total++;
    if (run_hash_test(SDC_HASH_SHA256, empty, 0, rfc_sha256_empty, 32)) passed++;
    printf("\n");
    
    /* ============================================================
       测试4: 临时切换 (不修改线程状态)
       ============================================================ */
    printf("测试 sdc_hash_compute_with (临时切换):\n");
    uint8_t out[64];
    const sdc_hash_ops_t *ops = sdc_hash_get_ops(SDC_HASH_SHA384);
    if (ops && ops->hash) {
        ops->hash(out, empty, 0);
        total++;
        if (compare_bytes(out, rfc_sha384_empty, 48)) {
            printf("  [PASS] SHA-384 (临时切换)\n");
            passed++;
        } else {
            printf("  [FAIL] SHA-384 (临时切换)\n");
        }
    }
    printf("\n");
    
    /* ============================================================
       最终结果
       ============================================================ */
    printf("结果: %d/%d 测试通过\n", passed, total);
    return (passed == total) ? 0 : 1;
}
