#ifndef SHA2_H
#define SHA2_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buffer[64];
    size_t   len;
} sha256_ctx;

typedef struct {
    uint64_t state[8];
    uint64_t count[2];
    uint8_t  buffer[128];
    size_t   len;
} sha512_ctx;

/* SHA-256 */
void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx *ctx, uint8_t out[32]);
void sha256_hash(uint8_t out[32], const uint8_t *in, size_t len);
/* SHA-512 */
void sha512_init(sha512_ctx *ctx);
void sha512_update(sha512_ctx *ctx, const uint8_t *data, size_t len);
void sha512_final(sha512_ctx *ctx, uint8_t out[64]);
void sha512_hash(uint8_t out[64], const uint8_t *in, size_t len);

#endif