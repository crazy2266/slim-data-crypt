/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * ChaCha20 DRBG tests: init, seeding, arbitrary lengths, error handling.
 */

#include <stdio.h>
#include <string.h>
#include <sdcrypt/config.h>
#include <sdcrypt/rng.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/utils.h>
#include "test_common.h"

#if SDC_ENABLE_CHACHA20_RNG

static void test_init(void) {
    sdc_rng_ctx ctx;
    uint8_t seed[32] = {0};

    T_SECTION("sdc_rng_init with ChaCha20 RNG");

    memset(seed, 0x11, 32);
    T_CHECK(sdc_rng_init(&ctx, &sdc_chacha20_rng_ops, seed) == SDC_ERR_OK,
            "init with valid seed succeeds");
    T_CHECK(sdc_rng_init(&ctx, &sdc_chacha20_rng_ops, NULL) == SDC_ERR_INVALID_PARAM,
            "NULL seed returns SDC_ERR_INVALID_PARAM");
    T_CHECK(sdc_rng_init(NULL, &sdc_chacha20_rng_ops, seed) == SDC_ERR_INVALID_PARAM,
            "NULL ctx returns SDC_ERR_INVALID_PARAM");
    T_CHECK(sdc_rng_init(&ctx, NULL, seed) == SDC_ERR_INVALID_PARAM,
            "NULL ops returns SDC_ERR_INVALID_PARAM");
}

static void test_same_seed_differs(void) {
    sdc_rng_ctx ctx1, ctx2;
    uint8_t seed[32] = {0};
    uint8_t out1[64], out2[64];

    T_SECTION("Same seed produces different output (fresh instances)");

    memset(seed, 0x22, 32);
    T_CHECK(sdc_rng_init(&ctx1, &sdc_chacha20_rng_ops, seed) == SDC_ERR_OK,
            "init ctx1");
    T_CHECK(sdc_rng_init(&ctx2, &sdc_chacha20_rng_ops, seed) == SDC_ERR_OK,
            "init ctx2");
    T_CHECK(sdc_rng_generate(&ctx1, out1, 64) == SDC_ERR_OK, "generate from ctx1");
    T_CHECK(sdc_rng_generate(&ctx2, out2, 64) == SDC_ERR_OK, "generate from ctx2");
    T_CHECK(memcmp(out1, out2, 64) != 0, "same seed -> different output");
}

static void test_different_seeds(void) {
    sdc_rng_ctx ctx1, ctx2;
    uint8_t seed1[32], seed2[32];
    uint8_t out1[64], out2[64];

    T_SECTION("Different seeds produce different output");

    memset(seed1, 0x33, 32);
    memset(seed2, 0x44, 32);
    T_CHECK(sdc_rng_init(&ctx1, &sdc_chacha20_rng_ops, seed1) == SDC_ERR_OK,
            "init ctx1");
    T_CHECK(sdc_rng_init(&ctx2, &sdc_chacha20_rng_ops, seed2) == SDC_ERR_OK,
            "init ctx2");
    T_CHECK(sdc_rng_generate(&ctx1, out1, 64) == SDC_ERR_OK, "generate from ctx1");
    T_CHECK(sdc_rng_generate(&ctx2, out2, 64) == SDC_ERR_OK, "generate from ctx2");
    T_CHECK(memcmp(out1, out2, 64) != 0, "different seeds -> different outputs");
}

static void test_arbitrary_length(void) {
    sdc_rng_ctx ctx;
    uint8_t seed[32] = {0};
    uint8_t out1[1], out2[7], out3[16], out4[32], out5[63], out6[100];
    uint8_t zero[100] = {0};

    T_SECTION("Arbitrary length generation");

    memset(seed, 0x55, 32);
    T_CHECK(sdc_rng_init(&ctx, &sdc_chacha20_rng_ops, seed) == SDC_ERR_OK, "init");
    T_CHECK(sdc_rng_generate(&ctx, out1, 1) == SDC_ERR_OK, "generate 1 byte");
    T_CHECK(sdc_rng_generate(&ctx, out2, 7) == SDC_ERR_OK, "generate 7 bytes");
    T_CHECK(sdc_rng_generate(&ctx, out3, 16) == SDC_ERR_OK, "generate 16 bytes");
    T_CHECK(sdc_rng_generate(&ctx, out4, 32) == SDC_ERR_OK, "generate 32 bytes");
    T_CHECK(sdc_rng_generate(&ctx, out5, 63) == SDC_ERR_OK, "generate 63 bytes");
    T_CHECK(sdc_rng_generate(&ctx, out6, 100) == SDC_ERR_OK, "generate 100 bytes");
    T_CHECK(memcmp(out1, zero, 1) != 0, "1-byte output not all zero");
    T_CHECK(memcmp(out6, zero, 100) != 0, "100-byte output not all zero");
}

static void test_error_handling(void) {
    sdc_rng_ctx ctx;
    uint8_t seed[32] = {0};
    uint8_t out[32];

    T_SECTION("Error handling");

    memset(seed, 0x66, 32);
    T_CHECK(sdc_rng_init(&ctx, &sdc_chacha20_rng_ops, seed) == SDC_ERR_OK, "init");
    T_CHECK(sdc_rng_generate(&ctx, NULL, 32) == SDC_ERR_INVALID_PARAM,
            "NULL out returns SDC_ERR_INVALID_PARAM");
    T_CHECK(sdc_rng_generate(&ctx, out, 0) == SDC_ERR_INVALID_PARAM,
            "len=0 returns SDC_ERR_INVALID_PARAM");
}

static void test_large_generation(void) {
    sdc_rng_ctx ctx;
    uint8_t seed[32] = {0};
    uint8_t out[2048];
    uint8_t zero[2048] = {0};

    T_SECTION("Large generation (2048 bytes)");

    memset(seed, 0x77, 32);
    T_CHECK(sdc_rng_init(&ctx, &sdc_chacha20_rng_ops, seed) == SDC_ERR_OK, "init");
    T_CHECK(sdc_rng_generate(&ctx, out, 2048) == SDC_ERR_OK, "generate 2048 bytes");
    T_CHECK(memcmp(out, zero, 2048) != 0, "2048-byte output not all zero");
}

static void test_multiple_generations(void) {
    sdc_rng_ctx ctx;
    uint8_t seed[32] = {0};
    uint8_t out1[32], out2[32], out3[32];

    T_SECTION("Multiple sequential generations");

    memset(seed, 0x88, 32);
    T_CHECK(sdc_rng_init(&ctx, &sdc_chacha20_rng_ops, seed) == SDC_ERR_OK, "init");
    T_CHECK(sdc_rng_generate(&ctx, out1, 32) == SDC_ERR_OK, "gen1");
    T_CHECK(sdc_rng_generate(&ctx, out2, 32) == SDC_ERR_OK, "gen2");
    T_CHECK(sdc_rng_generate(&ctx, out3, 32) == SDC_ERR_OK, "gen3");
    T_CHECK(memcmp(out1, out2, 32) != 0, "gen1 != gen2");
    T_CHECK(memcmp(out2, out3, 32) != 0, "gen2 != gen3");
    T_CHECK(memcmp(out1, out3, 32) != 0, "gen1 != gen3");
}

int main(void) {
    T_SUITE("ChaCha20 DRBG Tests");

    test_init();
    test_same_seed_differs();
    test_different_seeds();
    test_arbitrary_length();
    test_error_handling();
    test_large_generation();
    test_multiple_generations();

    T_SUMMARY();
}

#else

int main(void) {
    printf("[SKIP] ChaCha20 RNG disabled in config.h\n");
    return 0;
}

#endif /* SDC_ENABLE_CHACHA20_RNG */
