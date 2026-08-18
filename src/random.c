/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Random number generation.
 */

#include <sdcrypt/random.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/config.h>

#if defined(_WIN32)
#  include <windows.h>
#  include <bcrypt.h>
#else
#  include <stdio.h>
#endif

static int system_random_bytes(uint8_t *out, size_t len) {
#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status;
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        return SDC_ERR_RANDOM_FAIL;
    }
    status = BCryptGenRandom(hAlg, out, (ULONG)len, 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (!BCRYPT_SUCCESS(status)) {
        return SDC_ERR_RANDOM_FAIL;
    }
    return SDC_ERR_OK;
#else
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp) return SDC_ERR_RANDOM_FAIL;
    size_t n = fread(out, 1, len, fp);
    fclose(fp);
    return (n == len) ? SDC_ERR_OK : SDC_ERR_RANDOM_FAIL;
#endif
}

#if SDC_SWAPPABLE_RANDOM_RNG
static sdc_random_rng_t g_rng = system_random_bytes;
void sdc_random_set_rng(sdc_random_rng_t rng) { if (rng) g_rng = rng; }
void sdc_random_set_rng_to_default(void) { g_rng = system_random_bytes;}
#endif

int sdc_random_bytes(uint8_t *out, size_t len) {
#if SDC_SWAPPABLE_RANDOM_RNG
    return g_rng(out, len);
#else
    return system_random_bytes(out, len);
#endif
}