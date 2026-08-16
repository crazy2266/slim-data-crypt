/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Random number generation.
 */

#include <sdcrypt/random.h>
#include <sdcrypt/errcode.h>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>

int sdc_random_bytes(uint8_t *out, size_t len) {
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
}

#else
#include <stdio.h>

int sdc_random_bytes(uint8_t *out, size_t len) {
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp) return SDC_ERR_RANDOM_FAIL;

    size_t n = fread(out, 1, len, fp);
    fclose(fp);

    return (n == len) ? SDC_ERR_OK : SDC_ERR_RANDOM_FAIL;
}
#endif