/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * HMAC (Hash-based Message Authentication Code)
 *
 * References:
 *   - RFC 2104: HMAC: Keyed-Hashing for Message Authentication
 *   - FIPS 198-1: The Keyed-Hash Message Authentication Code (HMAC)
 *
 * Implementation conforms to the above standards.
 */

#include <sdcrypt/config.h>
#include <sdcrypt/hmac.h>
#include <sdcrypt/sha2.h>
#include <sdcrypt/utils.h>
#include <string.h>

#if SDC_ENABLE_HMAC

#if !SDC_ENABLE_SHA256
    #error "HMAC-SHA256 requires SHA256 support"
#endif

void sdc_hmac_sha256_init(sdc_hmac_sha256_ctx *ctx, const uint8_t *key, size_t key_len) {
    uint8_t k[64] = {0};

    memset(ctx, 0, sizeof(sdc_hmac_sha256_ctx));

    if (key_len > 64) {
        sdc_sha256_hash(k, key, key_len);
        key_len = 32;
    } else {
        memcpy(k, key, key_len);
    }

    for (int i = 0; i < 64; i++) {
        ctx->ipad[i] = k[i] ^ 0x36;
        ctx->opad[i] = k[i] ^ 0x5c;
    }

    sdc_sha256_init(&ctx->inner);
    sdc_sha256_update(&ctx->inner, ctx->ipad, 64);
}

void sdc_hmac_sha256_update(sdc_hmac_sha256_ctx *ctx, const uint8_t *data, size_t len) {
    sdc_sha256_update(&ctx->inner, data, len);
}

void sdc_hmac_sha256_final(sdc_hmac_sha256_ctx *ctx, uint8_t out[32]) {
    uint8_t inner_hash[32];

    sdc_sha256_final(&ctx->inner, inner_hash);
    sdc_sha256_init(&ctx->outer);
    sdc_sha256_update(&ctx->outer, ctx->opad, 64);
    sdc_sha256_update(&ctx->outer, inner_hash, 32);
    sdc_sha256_final(&ctx->outer, out);

    sdc_secure_memzero(inner_hash, sizeof(inner_hash));
    sdc_secure_memzero(ctx, sizeof(sdc_hmac_sha256_ctx));
}

void sdc_hmac_sha256(uint8_t out[32], const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len) {
    sdc_hmac_sha256_ctx ctx;
    sdc_hmac_sha256_init(&ctx, key, key_len);
    sdc_hmac_sha256_update(&ctx, data, data_len);
    sdc_hmac_sha256_final(&ctx, out);
}

#endif /* SDC_ENABLE_HMAC */
