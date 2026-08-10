#ifndef SDC_SHA2_H
#define SDC_SHA2_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buffer[64];
    size_t   len;
} sdc_sha256_ctx;

typedef struct {
    uint64_t state[8];
    uint64_t count[2];
    uint8_t  buffer[128];
    size_t   len;
} sdc_sha512_ctx;

/* SHA-256 */
void sdc_sha256_init(sdc_sha256_ctx *ctx);
void sdc_sha256_update(sdc_sha256_ctx *ctx, const uint8_t *data, size_t len);
void sdc_sha256_final(sdc_sha256_ctx *ctx, uint8_t out[32]);
void sdc_sha256_hash(uint8_t out[32], const uint8_t *in, size_t len);
/* SHA-512 */
void sdc_sha512_init(sdc_sha512_ctx *ctx);
void sdc_sha512_update(sdc_sha512_ctx *ctx, const uint8_t *data, size_t len);
void sdc_sha512_final(sdc_sha512_ctx *ctx, uint8_t out[64]);
void sdc_sha512_hash(uint8_t out[64], const uint8_t *in, size_t len);

#endif