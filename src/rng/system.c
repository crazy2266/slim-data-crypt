/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * System RNG table definition.
 */

#include <sdcrypt/config.h>
#include <sdcrypt/rng.h>
#include <sdcrypt/errcode.h>

#if SDC_ENABLE_SYSTEM_RNG

#ifdef _WIN32
#  include <windows.h>
#  include <bcrypt.h>
#else
#  include <stdio.h>
#  include <unistd.h>
#  include <fcntl.h>
#  include <errno.h>
#endif

static int system_rng_init(sdc_rng_ctx *ctx, const uint8_t *seed) {
    (void)ctx; (void)seed;
    return SDC_ERR_OK;
}

static int system_rng_generate(sdc_rng_ctx *ctx, uint8_t *out, size_t len) {
    (void)ctx;
    if (out == NULL || len == 0) return SDC_ERR_INVALID_PARAM;
#ifdef _WIN32
    uint8_t *p = (uint8_t *)out;
    size_t remaining = len;
    
    while (remaining > 0) {
        ULONG chunk = (remaining > ULONG_MAX) ? ULONG_MAX : (ULONG)remaining;
        if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, (PUCHAR)p, chunk,
                               BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
            return SDC_ERR_RANDOM_FAIL;
        }
        p += chunk;
        remaining -= chunk;
    }
    return SDC_ERR_OK;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return SDC_ERR_RANDOM_FAIL;
    
    uint8_t *p = (uint8_t *)out;
    size_t remaining = len;
    
    while (remaining > 0) {
        ssize_t ret = read(fd, p, remaining);
        if (ret < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return SDC_ERR_RANDOM_FAIL;
        }
        if (ret == 0) break;
        p += ret;
        remaining -= ret;
    }
    close(fd);
    return (remaining == 0) ? SDC_ERR_OK : SDC_ERR_RANDOM_FAIL;
#endif
}

const sdc_rng_ops_t sdc_system_rng_ops = {
    .init = system_rng_init,
    .generate = system_rng_generate,
    .seed_len = 0,
};

#endif /* SDC_ENABLE_SYSTEM_RNG */