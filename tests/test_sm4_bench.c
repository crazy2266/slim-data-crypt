/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * SM4 throughput benchmark: table-driven vs constant-time.
 */

#ifndef _WIN32
#  define _POSIX_C_SOURCE 199309L
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sdcrypt/config.h>
#include <sdcrypt/sm4.h>
#include <sdcrypt/block_cipher.h>
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

static void report(const char *name, double bytes, double secs) {
    printf("  %-22s %8.1f MB/s   (%.4f s)\n", name, bytes / secs / 1e6, secs);
}

int main(void) {
    T_SUITE("SM4 throughput");

    uint8_t key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                       0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    uint8_t nonce[12] = {0};

    sdc_sm4_ctx k;
    sdc_sm4_set_encrypt_key(&k, key);

    sdc_block_cipher_ctx bct;
    sdc_block_cipher_init(&bct, &sdc_sm4_ct_ops);
    sdc_sm4_ctx *ctk = (sdc_sm4_ctx *)bct.inner_state;
    sdc_sm4_set_encrypt_key(ctk, key);

    uint8_t *in  = (uint8_t *)malloc(BENCH_LEN);
    uint8_t *out = (uint8_t *)malloc(BENCH_LEN);
    if (!in || !out) { free(in); free(out); return 1; }
    memset(in, 0x5a, BENCH_LEN);

    double t0, t1;

    /* ECB: table-driven */
    t0 = now_sec();
    for (int r = 0; r < REPS; r++)
        sdc_sm4_encrypt_blocks(&k, in, BENCH_LEN / 16, out);
    t1 = now_sec();
    report("ECB table-driven", (double)BENCH_LEN * REPS, t1 - t0);

    /* ECB: constant-time (per-block) */
    t0 = now_sec();
    for (int r = 0; r < REPS; r++) {
        for (size_t off = 0; off < BENCH_LEN; off += 16)
            bct.ops->encrypt_block(&bct, in + off, out + off);
    }
    t1 = now_sec();
    report("ECB constant-time", (double)BENCH_LEN * REPS, t1 - t0);

    /* CTR: table-driven (generic layer) */
    sdc_block_cipher_ctx btab;
    sdc_block_cipher_init(&btab, &sdc_sm4_table_ops);
    sdc_sm4_set_encrypt_key((sdc_sm4_ctx *)btab.inner_state, key);
    t0 = now_sec();
    for (int r = 0; r < REPS; r++)
        sdc_block_cipher_ctr(&btab, nonce, in, BENCH_LEN, out);
    t1 = now_sec();
    report("CTR table-driven", (double)BENCH_LEN * REPS, t1 - t0);

    free(in);
    free(out);
    printf("\n");
    T_CHECK(1, "benchmark completed");
    T_SUMMARY();
    return 0;
}
