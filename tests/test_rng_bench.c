/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * RNG throughput benchmark.
 * Compares system RNG vs ChaCha20 DRBG.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sdcrypt/config.h>
#include <sdcrypt/rng.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/utils.h>

/* ============================================================
   Timer
   ============================================================ */
#ifdef _WIN32
#  include <windows.h>
static double get_time_ms(void) {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart * 1000.0 / freq.QuadPart;
}
#else
#  include <time.h>
static double get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}
#endif

/* ============================================================
   Benchmark a single RNG
   ============================================================ */
static void bench_rng(const char *name,
                      int (*generate)(sdc_rng_ctx *, uint8_t *, size_t),
                      sdc_rng_ctx *ctx,
                      size_t size,
                      int iterations) {
    uint8_t *buf = malloc(size);
    if (!buf) {
        printf("%-20s size=%-10zu [SKIP] malloc failed\n", name, size);
        return;
    }

    /* Warmup */
    generate(ctx, buf, size);

    double start = get_time_ms();
    for (int i = 0; i < iterations; i++) {
        int ret = generate(ctx, buf, size);
        if (ret != SDC_ERR_OK) {
            printf("%-20s size=%-10zu [ERROR] generate failed\n", name, size);
            free(buf);
            return;
        }
    }
    double elapsed = get_time_ms() - start;

    double mbps = (double)size * iterations / (1024.0 * 1024.0) / (elapsed / 1000.0);
    printf("%-20s size=%-10zu iter=%-6d %.2f MB/s\n",
           name, size, iterations, mbps);

    free(buf);
}

/* ============================================================
   System RNG wrapper
   ============================================================ */
#if SDC_ENABLE_SYSTEM_RNG
static int system_rng_generate_wrapper(sdc_rng_ctx *ctx, uint8_t *out, size_t len) {
    (void)ctx;
    return sdc_system_rng_ops.generate(NULL, out, len);
}
#endif

/* ============================================================
   main
   ============================================================ */
int main(void) {
    printf("===========================================\n");
    printf("  RNG Throughput Benchmark\n");
    printf("===========================================\n");
    printf("(Higher is better)\n\n");

    sdc_rng_ctx chacha_ctx;

    uint8_t seed[32];
    memset(seed, 0x55, 32);

#if SDC_ENABLE_SYSTEM_RNG && SDC_ENABLE_CHACHA20_RNG
    /* 初始化 ChaCha20 DRBG */
    int ret = sdc_rng_init(&chacha_ctx, &sdc_chacha20_rng_ops, seed);
    if (ret != SDC_ERR_OK) {
        printf("Failed to init ChaCha20 DRBG\n");
        return 1;
    }

    /* 测试不同大小 */
    size_t sizes[] = {64, 256, 1024, 4096, 16384, 65536};
    int iterations[] = {100000, 50000, 20000, 5000, 1000, 200};

    printf("=== ChaCha20 DRBG ===\n");
    for (int i = 0; i < 6; i++) {
        bench_rng("ChaCha20", sdc_rng_generate, &chacha_ctx,
                  sizes[i], iterations[i]);
        sdc_rng_init(&chacha_ctx, &sdc_chacha20_rng_ops, seed);
    }

    printf("\n=== System RNG ===\n");
    for (int i = 0; i < 6; i++) {
        bench_rng("System", system_rng_generate_wrapper, NULL,
                  sizes[i], iterations[i]);
    }

#else
    printf("[SKIP] One or both RNGs are disabled\n");
#endif

    printf("\n===========================================\n");
    return 0;
}