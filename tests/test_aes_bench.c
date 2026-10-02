/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * AES / AES-GCM throughput benchmark.
 */

/* clock_gettime needs POSIX 199309L under -std=c99 (non-Windows). */
#ifndef _WIN32
#  define _POSIX_C_SOURCE 199309L
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sdcrypt/config.h>
#include <sdcrypt/aes.h>
#include <sdcrypt/block_cipher.h>
#include <sdcrypt/gcm.h>
#include <sdcrypt/ghash.h>
#include <sdcrypt/aes_gcm.h>
#include <sdcrypt/errcode.h>
#include "test_common.h"

#ifdef _WIN32
#  include <windows.h>
static double now_sec(void) {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart / (double)freq.QuadPart;
}
#else
#  include <time.h>
static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}
#endif

#define BENCH_LEN (1u << 20)   /* 1 MiB */
#define REPS      8

static const char *impl_name(int impl) {
    switch (impl) {
        case SDC_AES_IMPL_AESNI: return "AES-NI";
        case SDC_AES_IMPL_ARMCE: return "ARM-CE";
        default:                 return "scalar";
    }
}

static void report(const char *name, double bytes, double secs) {
    printf("  %-14s %8.1f MB/s   (%.4f s)\n", name, bytes / secs / 1e6, secs);
}

static void bench_key(const uint8_t *key, size_t klen) {
    sdc_aes_key k;
    uint8_t iv[16] = {0};
    uint8_t nonce[12] = {0};
    uint8_t tag[16];
    uint8_t *in = (uint8_t *)malloc(BENCH_LEN);
    uint8_t *out = (uint8_t *)malloc(BENCH_LEN);
    if (!in || !out) { free(in); free(out); return; }
    memset(in, 0x5a, BENCH_LEN);

    sdc_aes_set_encrypt_key(&k, key, klen);

    double t0, t1;

    /* ECB block throughput: 64 independent blocks in flight. */
    {
        uint8_t blk[64][16];
        memset(blk, 0, sizeof(blk));
        for (int r = 0; r < 1000; r++)
            for (int i = 0; i < 64; i++)
                sdc_aes_encrypt_block(&k, blk[i], blk[i]);
        t0 = now_sec();
        for (int r = 0; r < 200000; r++)
            for (int i = 0; i < 64; i++)
                sdc_aes_encrypt_block(&k, blk[i], blk[i]);
        t1 = now_sec();
        report("ECB block", 200000.0 * 64.0 * 16.0, t1 - t0);
    }

    sdc_block_cipher_ctx bctx;
    sdc_block_cipher_init(&bctx, (klen == 16) ? &sdc_aes128_ops
                            : (klen == 24) ? &sdc_aes192_ops
                                           : &sdc_aes256_ops);
    sdc_aes_set_encrypt_key((sdc_aes_key *)bctx.inner_state, key, klen);

    t0 = now_sec();
    for (int r = 0; r < REPS; r++)
        sdc_block_cipher_cbc_encrypt(&bctx, iv, in, BENCH_LEN, out);
    t1 = now_sec();
    report("CBC encrypt", (double)BENCH_LEN * REPS, t1 - t0);

    t0 = now_sec();
    for (int r = 0; r < REPS; r++)
        sdc_block_cipher_ctr(&bctx, nonce, in, BENCH_LEN, out);
    t1 = now_sec();
    report("CTR", (double)BENCH_LEN * REPS, t1 - t0);

    t0 = now_sec();
    for (int r = 0; r < REPS; r++)
        sdc_aes_gcm_encrypt(key, klen, nonce, 12, NULL, 0, in, BENCH_LEN, out, tag);
    t1 = now_sec();
    report("GCM encrypt", (double)BENCH_LEN * REPS, t1 - t0);

    (void)tag;
    free(in);
    free(out);
}

int main(void) {
    uint8_t key128[16], key192[24], key256[32];
    for (int i = 0; i < 32; i++) {
        if (i < 16) key128[i] = (uint8_t)i;
        if (i < 24) key192[i] = (uint8_t)i;
        key256[i] = (uint8_t)i;
    }

    T_SUITE("AES throughput");

    sdc_aes_key probe;
    sdc_aes_set_encrypt_key(&probe, key128, 16);
    printf("  backend: %s\n", impl_name(probe.impl));
    printf("  ghash  : %s\n\n", sdc_ghash_backend());

    printf("--- AES-128 ---\n");
    bench_key(key128, 16);
    printf("--- AES-192 ---\n");
    bench_key(key192, 24);
    printf("--- AES-256 ---\n");
    bench_key(key256, 32);

    T_CHECK(1, "benchmark completed");
    T_SUMMARY();
}
