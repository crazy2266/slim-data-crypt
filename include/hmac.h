#ifndef HMAC_H
#define HMAC_H

#include <stdint.h>
#include <stddef.h>
#include "sha2.h"

typedef struct {
    sha256_ctx inner;
    sha256_ctx outer;
    uint8_t ipad[64];
    uint8_t opad[64];
} hmac_sha256_ctx;

void hmac_sha256_init(hmac_sha256_ctx *ctx, const uint8_t *key, size_t key_len);
void hmac_sha256_update(hmac_sha256_ctx *ctx, const uint8_t *data, size_t len);
void hmac_sha256_final(hmac_sha256_ctx *ctx, uint8_t out[32]);
void hmac_sha256(uint8_t out[32], const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len);

#endif