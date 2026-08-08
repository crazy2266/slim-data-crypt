#include "hmac.h"
#include "sha2.h"
#include "utils.h"
#include <string.h>

void hmac_sha256_init(hmac_sha256_ctx *ctx, const uint8_t *key, size_t key_len) {
    uint8_t k[64] = {0};

    memset(ctx, 0, sizeof(hmac_sha256_ctx));

    if (key_len > 64) {
        sha256_hash(k, key, key_len);
        key_len = 32;
    } else {
        memcpy(k, key, key_len);
    }

    for (int i = 0; i < 64; i++) {
        ctx->ipad[i] = k[i] ^ 0x36;
        ctx->opad[i] = k[i] ^ 0x5c;
    }

    sha256_init(&ctx->inner);
    sha256_update(&ctx->inner, ctx->ipad, 64);
}

void hmac_sha256_update(hmac_sha256_ctx *ctx, const uint8_t *data, size_t len) {
    sha256_update(&ctx->inner, data, len);
}

void hmac_sha256_final(hmac_sha256_ctx *ctx, uint8_t out[32]) {
    uint8_t inner_hash[32];

    sha256_final(&ctx->inner, inner_hash);
    sha256_init(&ctx->outer);
    sha256_update(&ctx->outer, ctx->opad, 64);
    sha256_update(&ctx->outer, inner_hash, 32);
    sha256_final(&ctx->outer, out);

    secure_memzero(inner_hash, sizeof(inner_hash));
    secure_memzero(ctx, sizeof(hmac_sha256_ctx));
}

void hmac_sha256(uint8_t out[32], const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len) {
    hmac_sha256_ctx ctx;
    hmac_sha256_init(&ctx, key, key_len);
    hmac_sha256_update(&ctx, data, data_len);
    hmac_sha256_final(&ctx, out);
}