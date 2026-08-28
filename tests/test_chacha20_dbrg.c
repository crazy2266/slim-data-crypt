/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Test ChaCha20 DRBG.
 */

#include <stdio.h>
#include <string.h>
#include <sdcrypt/config.h>
#include <sdcrypt/rng.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/utils.h>

#if SDC_ENABLE_CHACHA20_RNG

/* ============================================================
   测试框架
   ============================================================ */
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
   Test 1: 基础初始化
   ============================================================ */
static void test_init(void) {
    sdc_rng_ctx ctx;
    uint8_t seed[32] = {0};
    int ret;

    TEST_START("sdc_rng_init with ChaCha20 RNG");

    memset(seed, 0x11, 32);
    ret = sdc_rng_init(&ctx, &sdc_chacha20_rng_ops, seed);
    TEST_ASSERT(ret == SDC_ERR_OK, "init with valid seed");

    /* 测试 NULL seed */
    ret = sdc_rng_init(&ctx, &sdc_chacha20_rng_ops, NULL);
    TEST_ASSERT(ret == SDC_ERR_INVALID_PARAM, "NULL seed returns error");

    /* 测试 NULL ctx */
    ret = sdc_rng_init(NULL, &sdc_chacha20_rng_ops, NULL);
    TEST_ASSERT(ret == SDC_ERR_INVALID_PARAM, "NULL ctx returns error");

    /* 测试 NULL ops */
    ret = sdc_rng_init(&ctx, NULL, NULL);
    TEST_ASSERT(ret == SDC_ERR_INVALID_PARAM, "NULL ops returns error");
}

/* ============================================================
   Test 2: 非确定性输出
   ============================================================ */
static void test_non_deterministic(void) {
    sdc_rng_ctx ctx1, ctx2;
    uint8_t seed[32] = {0};
    uint8_t out1[64], out2[64];
    int ret;

    TEST_START("Deterministic output");

    memset(seed, 0x22, 32);
    
    /* 用相同 seed 初始化两个 DRBG */
    ret = sdc_rng_init(&ctx1, &sdc_chacha20_rng_ops, seed);
    TEST_ASSERT(ret == SDC_ERR_OK, "init ctx1");
    ret = sdc_rng_init(&ctx2, &sdc_chacha20_rng_ops, seed);
    TEST_ASSERT(ret == SDC_ERR_OK, "init ctx2");

    /* 各生成 64 字节 */
    ret = sdc_rng_generate(&ctx1, out1, 64);
    TEST_ASSERT(ret == SDC_ERR_OK, "generate from ctx1");
    ret = sdc_rng_generate(&ctx2, out2, 64);
    TEST_ASSERT(ret == SDC_ERR_OK, "generate from ctx2");

    TEST_ASSERT(memcmp(out1, out2, 64) != 0,
                "same seed -> different output");
}

/* ============================================================
   Test 3: 不同种子产生不同输出
   ============================================================ */
static void test_different_seeds(void) {
    sdc_rng_ctx ctx1, ctx2;
    uint8_t seed1[32], seed2[32];
    uint8_t out1[64], out2[64];
    int ret;

    TEST_START("Different seeds");

    memset(seed1, 0x33, 32);
    memset(seed2, 0x44, 32);
    
    ret = sdc_rng_init(&ctx1, &sdc_chacha20_rng_ops, seed1);
    TEST_ASSERT(ret == SDC_ERR_OK, "init ctx1");
    ret = sdc_rng_init(&ctx2, &sdc_chacha20_rng_ops, seed2);
    TEST_ASSERT(ret == SDC_ERR_OK, "init ctx2");

    ret = sdc_rng_generate(&ctx1, out1, 64);
    TEST_ASSERT(ret == SDC_ERR_OK, "generate from ctx1");
    ret = sdc_rng_generate(&ctx2, out2, 64);
    TEST_ASSERT(ret == SDC_ERR_OK, "generate from ctx2");

    TEST_ASSERT(memcmp(out1, out2, 64) != 0,
                "different seeds -> different outputs");
}

/* ============================================================
   Test 4: 任意长度生成
   ============================================================ */
static void test_arbitrary_length(void) {
    sdc_rng_ctx ctx;
    uint8_t seed[32] = {0};
    uint8_t out1[1], out2[7], out3[16], out4[32], out5[63], out6[100];
    int ret;

    TEST_START("Arbitrary length generation");
    
    memset(seed, 0x55, 32);
    ret = sdc_rng_init(&ctx, &sdc_chacha20_rng_ops, seed);
    TEST_ASSERT(ret == SDC_ERR_OK, "init");

    ret = sdc_rng_generate(&ctx, out1, 1);
    TEST_ASSERT(ret == SDC_ERR_OK, "generate 1 byte");

    ret = sdc_rng_generate(&ctx, out2, 7);
    TEST_ASSERT(ret == SDC_ERR_OK, "generate 7 bytes");

    ret = sdc_rng_generate(&ctx, out3, 16);
    TEST_ASSERT(ret == SDC_ERR_OK, "generate 16 bytes");

    ret = sdc_rng_generate(&ctx, out4, 32);
    TEST_ASSERT(ret == SDC_ERR_OK, "generate 32 bytes");

    ret = sdc_rng_generate(&ctx, out5, 63);
    TEST_ASSERT(ret == SDC_ERR_OK, "generate 63 bytes");

    ret = sdc_rng_generate(&ctx, out6, 100);
    TEST_ASSERT(ret == SDC_ERR_OK, "generate 100 bytes");

    /* 不同长度的输出应该不同（虽然是猜测，但概率极高） */
    uint8_t zero[100] = {0};
    TEST_ASSERT(memcmp(out1, zero, 1) != 0, "output not all zero");
    TEST_ASSERT(memcmp(out6, zero, 100) != 0, "output not all zero");
}

/* ============================================================
   Test 5: 错误处理
   ============================================================ */
static void test_error_handling(void) {
    sdc_rng_ctx ctx;
    uint8_t seed[32] = {0};
    uint8_t out[32];
    int ret;

    TEST_START("Error handling");

    memset(seed, 0x66, 32);
    ret = sdc_rng_init(&ctx, &sdc_chacha20_rng_ops, seed);
    TEST_ASSERT(ret == SDC_ERR_OK, "init");

    /* NULL out */
    ret = sdc_rng_generate(&ctx, NULL, 32);
    TEST_ASSERT(ret == SDC_ERR_INVALID_PARAM, "NULL out returns error");

    /* len = 0 */
    ret = sdc_rng_generate(&ctx, out, 0);
    TEST_ASSERT(ret == SDC_ERR_INVALID_PARAM, "len=0 returns error");
}

/* ============================================================
   Test 6: 大块生成 (测试缓冲区边界)
   ============================================================ */
static void test_large_generation(void) {
    sdc_rng_ctx ctx;
    uint8_t seed[32] = {0};
    uint8_t out[2048];
    int ret;

    TEST_START("Large generation (2048 bytes)");

    memset(seed, 0x77, 32);
    ret = sdc_rng_init(&ctx, &sdc_chacha20_rng_ops, seed);
    TEST_ASSERT(ret == SDC_ERR_OK, "init");

    ret = sdc_rng_generate(&ctx, out, 2048);
    TEST_ASSERT(ret == SDC_ERR_OK, "generate 2048 bytes");

    /* 检查是否全零 */
    uint8_t zero[2048] = {0};
    TEST_ASSERT(memcmp(out, zero, 2048) != 0, "output not all zero");
}

/* ============================================================
   Test 7: 多次生成累积
   ============================================================ */
static void test_multiple_generations(void) {
    sdc_rng_ctx ctx;
    uint8_t seed[32] = {0};
    uint8_t out1[32], out2[32], out3[32];
    int ret;

    TEST_START("Multiple generations");

    memset(seed, 0x88, 32);
    ret = sdc_rng_init(&ctx, &sdc_chacha20_rng_ops, seed);
    TEST_ASSERT(ret == SDC_ERR_OK, "init");

    ret = sdc_rng_generate(&ctx, out1, 32);
    TEST_ASSERT(ret == SDC_ERR_OK, "gen1");

    ret = sdc_rng_generate(&ctx, out2, 32);
    TEST_ASSERT(ret == SDC_ERR_OK, "gen2");

    ret = sdc_rng_generate(&ctx, out3, 32);
    TEST_ASSERT(ret == SDC_ERR_OK, "gen3");

    /* 每次生成都应该不同 */
    TEST_ASSERT(memcmp(out1, out2, 32) != 0, "gen1 != gen2");
    TEST_ASSERT(memcmp(out2, out3, 32) != 0, "gen2 != gen3");
    TEST_ASSERT(memcmp(out1, out3, 32) != 0, "gen1 != gen3");
}

/* ============================================================
   main
   ============================================================ */
int main(void) {
    printf("===========================================\n");
    printf("  ChaCha20 DRBG Test\n");
    printf("===========================================\n");

    test_init();
    test_non_deterministic();
    test_different_seeds();
    test_arbitrary_length();
    test_error_handling();
    test_large_generation();
    test_multiple_generations();

    printf("\n========================================\n");
    printf("Result: %d/%d tests passed\n", test_passed, test_total);
    printf("========================================\n");

    return (test_passed == test_total) ? 0 : 1;
}

#else

int main(void) {
    printf("[SKIP] ChaCha20 RNG is disabled\n");
    return 0;
}

#endif /* SDC_ENABLE_CHACHA20_RNG */