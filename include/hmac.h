#ifndef SDC_HMAC_H
#define SDC_HMAC_H

#include <stdint.h>
#include <stddef.h>
#include "sha2.h"

typedef struct {
    sdc_sha256_ctx inner;
    sdc_sha256_ctx outer;
    uint8_t ipad[64];
    uint8_t opad[64];
} sdc_hmac_sha256_ctx;

void sdc_hmac_sha256_init(sdc_hmac_sha256_ctx *ctx, const uint8_t *key, size_t key_len);
void sdc_hmac_sha256_update(sdc_hmac_sha256_ctx *ctx, const uint8_t *data, size_t len);
void sdc_hmac_sha256_final(sdc_hmac_sha256_ctx *ctx, uint8_t out[32]);
void sdc_hmac_sha256(uint8_t out[32], const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len);

#endif