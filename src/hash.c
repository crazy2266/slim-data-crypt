/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * This module defines the interface for obtaining hash algorithm implementations.
 *
 * Users may register a custom getter function to resolve an algorithm by its OID.
 * If the custom getter is NULL, the library automatically reverts to the default
 * internal getter.
 *
 * This design allows users to extend support to algorithms that are not included
 * in the default table. For example, when encountering a certificate signed with
 * an unsupported hash algorithm, users can implement the algorithm and register
 * a corresponding getter callback, thereby enabling certificate verification.
 */

#include <string.h>
#include <sdcrypt/hash.h>
#include <sdcrypt/config.h>
#include <sdcrypt/oid.h>
#include <sdcrypt/sha2.h>
#include <sdcrypt/errcode.h>

typedef struct {
    const uint8_t *oid;
    size_t oid_len;
    const sdc_hash_ops_t *ops;
} sdc_hash_oid_entry_t;

static const sdc_hash_oid_entry_t hash_oid_table[] = {
#if SDC_ENABLE_SHA256
    { SDC_OID_SHA256, SDC_OID_SHA256_LEN, &sdc_sha256_ops },
#endif
#if SDC_ENABLE_SHA224
    { SDC_OID_SHA224, SDC_OID_SHA224_LEN, &sdc_sha224_ops },
#endif
#if SDC_ENABLE_SHA384
    { SDC_OID_SHA384, SDC_OID_SHA384_LEN, &sdc_sha384_ops },
#endif
#if SDC_ENABLE_SHA512
    { SDC_OID_SHA512, SDC_OID_SHA512_LEN, &sdc_sha512_ops },
#endif
};

int sdc_hash_init(sdc_hash_ctx *ctx, const sdc_hash_ops_t *ops) {
    if (!ctx || !ops || !ops->init) return SDC_ERR_INVALID_PARAM;
    ctx->ops = ops;
    return ops->init(ctx);
}

int sdc_hash_update(sdc_hash_ctx *ctx, const uint8_t *in, size_t len) {
    if (!ctx || !ctx->ops || !ctx->ops->update) return SDC_ERR_INVALID_PARAM;
    if (!in && len > 0) return SDC_ERR_INVALID_PARAM;
    return ctx->ops->update(ctx, in, len);
}

int sdc_hash_final(sdc_hash_ctx *ctx, uint8_t *out, size_t *out_len) {
    if (!ctx || !ctx->ops || !ctx->ops->final) return SDC_ERR_INVALID_PARAM;
    if (!out || !out_len) return SDC_ERR_INVALID_PARAM;
    if (*out_len < ctx->ops->hash_len) {
        *out_len = ctx->ops->hash_len;
        return SDC_ERR_BUFFER_TOO_SMALL;
    }
    *out_len = ctx->ops->hash_len;
    return ctx->ops->final(ctx, out, out_len);
}

int sdc_hash_once(const sdc_hash_ops_t *ops, uint8_t *out, const uint8_t *in, size_t len, size_t *out_len) {
    if (!ops || !ops->hash) return SDC_ERR_INVALID_PARAM;
    if (!out || !out_len) return SDC_ERR_INVALID_PARAM;
    return ops->hash(out, in, len, out_len);
}

const sdc_hash_ops_t *sdc_hash_find_by_oid(const uint8_t *oid, size_t oid_len, sdc_hash_getter_t getter) {
    if (!oid || !oid_len) return NULL;
    if (getter) {
        const sdc_hash_ops_t *ops = getter(oid, oid_len);
        if (ops) return ops;
    }
    for (size_t i = 0; i < sizeof(hash_oid_table) / sizeof(hash_oid_table[0]); i++) {
        if (hash_oid_table[i].oid_len == oid_len &&
            memcmp(hash_oid_table[i].oid, oid, oid_len) == 0) {
            return hash_oid_table[i].ops;
        }
    }
    return NULL;
}