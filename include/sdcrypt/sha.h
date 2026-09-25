/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * SHA2 hash functions.
 */

#ifndef SDC_SHA_H
#define SDC_SHA_H

#include <stdint.h>
#include <stddef.h>
#include <sdcrypt/config.h>
#include <sdcrypt/hash.h>

#ifdef __cplusplus
extern "C" {
#endif

#if SDC_ENABLE_SHA224 || SDC_ENABLE_SHA256

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buffer[64];
    size_t   len;
} sdc_sha256_ctx;

#if SDC_ENABLE_SHA224
/* SHA-224 */
void sdc_sha224_init(sdc_sha256_ctx *ctx);
void sdc_sha224_update(sdc_sha256_ctx *ctx, const uint8_t *data, size_t len);
void sdc_sha224_final(sdc_sha256_ctx *ctx, uint8_t out[28]);
void sdc_sha224_hash(uint8_t out[28], const uint8_t *in, size_t len);
extern const sdc_hash_ops_t sdc_sha224_ops;
#endif /* SDC_ENABLE_SHA224 */

#if SDC_ENABLE_SHA256
/* SHA-256 */
void sdc_sha256_init(sdc_sha256_ctx *ctx);
void sdc_sha256_update(sdc_sha256_ctx *ctx, const uint8_t *data, size_t len);
void sdc_sha256_final(sdc_sha256_ctx *ctx, uint8_t out[32]);
void sdc_sha256_hash(uint8_t out[32], const uint8_t *in, size_t len);
extern const sdc_hash_ops_t sdc_sha256_ops;
#endif /* SDC_ENABLE_SHA256 */

#endif /* SDC_ENABLE_SHA224 || SDC_ENABLE_SHA256 */

#if SDC_ENABLE_SHA384 || SDC_ENABLE_SHA512

typedef struct {
    uint64_t state[8];
    uint64_t count[2];
    uint8_t  buffer[128];
    size_t   len;
} sdc_sha512_ctx;

#if SDC_ENABLE_SHA384
/* SHA-384 */
void sdc_sha384_init(sdc_sha512_ctx *ctx);
void sdc_sha384_update(sdc_sha512_ctx *ctx, const uint8_t *data, size_t len);
void sdc_sha384_final(sdc_sha512_ctx *ctx, uint8_t out[48]);
void sdc_sha384_hash(uint8_t out[48], const uint8_t *in, size_t len);
extern const sdc_hash_ops_t sdc_sha384_ops;
#endif /* SDC_ENABLE_SHA384 */

#if SDC_ENABLE_SHA512
/* SHA-512 */
void sdc_sha512_init(sdc_sha512_ctx *ctx);
void sdc_sha512_update(sdc_sha512_ctx *ctx, const uint8_t *data, size_t len);
void sdc_sha512_final(sdc_sha512_ctx *ctx, uint8_t out[64]);
void sdc_sha512_hash(uint8_t out[64], const uint8_t *in, size_t len);
extern const sdc_hash_ops_t sdc_sha512_ops;
#endif /* SDC_ENABLE_SHA512 */

#endif /* SDC_ENABLE_SHA384 || SDC_ENABLE_SHA512 */

#if SDC_ENABLE_SHA3

typedef struct {
    uint64_t state[25];
    uint8_t  buffer[200];
    size_t   buf_len;
    size_t   rate;
    size_t   out_len;
} sdc_sha3_ctx;

/* SHA3-224 */
void sdc_sha3_224_init(sdc_sha3_ctx *ctx);
void sdc_sha3_224_update(sdc_sha3_ctx *ctx, const uint8_t *data, size_t len);
void sdc_sha3_224_final(sdc_sha3_ctx *ctx, uint8_t out[28]);
void sdc_sha3_224_hash(uint8_t out[28], const uint8_t *in, size_t len);
extern const sdc_hash_ops_t sdc_sha3_224_ops;
/* SHA3-256 */
void sdc_sha3_256_init(sdc_sha3_ctx *ctx);
void sdc_sha3_256_update(sdc_sha3_ctx *ctx, const uint8_t *data, size_t len);
void sdc_sha3_256_final(sdc_sha3_ctx *ctx, uint8_t out[32]);
void sdc_sha3_256_hash(uint8_t out[32], const uint8_t *in, size_t len);
extern const sdc_hash_ops_t sdc_sha3_256_ops;
/* SHA3-384 */
void sdc_sha3_384_init(sdc_sha3_ctx *ctx);
void sdc_sha3_384_update(sdc_sha3_ctx *ctx, const uint8_t *data, size_t len);
void sdc_sha3_384_final(sdc_sha3_ctx *ctx, uint8_t out[48]);
void sdc_sha3_384_hash(uint8_t out[48], const uint8_t *in, size_t len);
extern const sdc_hash_ops_t sdc_sha3_384_ops;
/* SHA3-512 */
void sdc_sha3_512_init(sdc_sha3_ctx *ctx);
void sdc_sha3_512_update(sdc_sha3_ctx *ctx, const uint8_t *data, size_t len);
void sdc_sha3_512_final(sdc_sha3_ctx *ctx, uint8_t out[64]);
void sdc_sha3_512_hash(uint8_t out[64], const uint8_t *in, size_t len);
extern const sdc_hash_ops_t sdc_sha3_512_ops;
/* SHAKE128 */
void sdc_shake128_init(sdc_sha3_ctx *ctx);
void sdc_shake128_update(sdc_sha3_ctx *ctx, const uint8_t *data, size_t len);
void sdc_shake128_final(sdc_sha3_ctx *ctx);
void sdc_shake128_squeeze(sdc_sha3_ctx *ctx, uint8_t *out, size_t len);
void sdc_shake128_hash(uint8_t *out, const uint8_t *in, size_t len, size_t out_len);
/* SHAKE256 */
void sdc_shake256_init(sdc_sha3_ctx *ctx);
void sdc_shake256_update(sdc_sha3_ctx *ctx, const uint8_t *data, size_t len);
void sdc_shake256_final(sdc_sha3_ctx *ctx);
void sdc_shake256_squeeze(sdc_sha3_ctx *ctx, uint8_t *out, size_t len);
void sdc_shake256_hash(uint8_t *out, const uint8_t *in, size_t len, size_t out_len);

#endif /* SDC_ENABLE_SHA3 */

#ifdef __cplusplus
}
#endif

#endif /* SDC_SHA_H */
