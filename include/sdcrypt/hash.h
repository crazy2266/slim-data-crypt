/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Hash algorithm interface.
 *
 * ============================================================
 * IMPORTANT: out_len parameter convention
 * ============================================================
 *
 * All functions that accept a size_t* out_len parameter follow
 * the same convention:
 *
 *   - INPUT:  Caller MUST initialize *out_len to the size of
 *             the output buffer (in bytes).
 *   - OUTPUT: On success, *out_len is updated to the actual
 *             digest length of the algorithm.
 *   - ERROR:  If *out_len is smaller than the required digest
 *             length, the function returns SDC_ERR_BUFFER_TOO_SMALL
 *             and sets *out_len to the required size.
 *
 * Example:
 *   uint8_t digest[64];
 *   size_t out_len = sizeof(digest);
 *   sdc_hash_once(&sdc_sha256_ops, digest, data, len, &out_len);
 *   // out_len is now 32
 *
 * DO NOT pass an uninitialized out_len. The library does not
 * and cannot guess the size of your buffer.
 */

#ifndef SDC_HASH_H
#define SDC_HASH_H

#include <stdint.h>
#include <stddef.h>
#include <sdcrypt/config.h>
#ifndef __cplusplus
#  include <stdalign.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sdc_hash_ops_t sdc_hash_ops_t;

typedef struct {
    const sdc_hash_ops_t *ops;
    alignas(8) uint8_t inner_state[SDC_HASH_CUSTOM_MAX];
} sdc_hash_ctx;

/* ---------- Hash operation table ---------- */
struct sdc_hash_ops_t {
    int (*init)(sdc_hash_ctx *ctx);
    int (*update)(sdc_hash_ctx *ctx, const uint8_t *in, size_t len);
    int (*final)(sdc_hash_ctx *ctx, uint8_t *out, size_t *out_len);
    int (*hash)(uint8_t *out, const uint8_t *in, size_t len, size_t *out_len);
    size_t hash_len;
    const char *name;
    const uint8_t *oid;
    size_t oid_len;
};

/**
 * Hash algorithm getter function type.
 * @param oid     DER-encoded OID
 * @param oid_len Length of OID in bytes
 * @return        Pointer to sdc_hash_ops_t if found, NULL otherwise
 */
typedef const sdc_hash_ops_t* (*sdc_hash_getter_t)(const uint8_t *oid, size_t oid_len);

int sdc_hash_init(sdc_hash_ctx *ctx, const sdc_hash_ops_t *ops);
int sdc_hash_update(sdc_hash_ctx *ctx, const uint8_t *in, size_t len);
int sdc_hash_final(sdc_hash_ctx *ctx, uint8_t *out, size_t *out_len);
int sdc_hash_once(const sdc_hash_ops_t *ops, uint8_t *out, const uint8_t *in, size_t len, size_t *out_len);

/**
 * Search the default internal OID table only.
 *
 * This function does NOT call any custom getter. It is intended for:
 *   - Internal use within the library
 *   - Custom getters that want to explicitly fall back to the default table
 *
 * @param oid     DER-encoded OID
 * @param oid_len Length of OID in bytes
 * @return        Pointer to sdc_hash_ops_t if found, NULL otherwise
 */
const sdc_hash_ops_t *sdc_hash_find_by_oid_default(const uint8_t *oid, size_t oid_len);

/**
 * Find a hash algorithm implementation by its OID.
 *
 * If a custom getter is provided:
 *   - If the getter returns a non-NULL value, that value is returned.
 *   - If the getter returns NULL, the search terminates immediately.
 *     NO fallback to the default table occurs.
 *
 * If no custom getter is provided (getter == NULL):
 *   - The default internal OID table is searched.
 *   - Returns the matching ops table, or NULL if not found.
 *
 * This design gives the caller full control: the custom getter decides
 * whether to fall back to the default table by explicitly calling
 * sdc_hash_find_by_oid_default(oid, oid_len).
 *
 * @param oid     DER-encoded OID
 * @param oid_len Length of OID in bytes
 * @param getter  Custom getter function, or NULL to use default table only
 * @return        Pointer to sdc_hash_ops_t if found, NULL otherwise
 */
const sdc_hash_ops_t *sdc_hash_find_by_oid(const uint8_t *oid, size_t oid_len, sdc_hash_getter_t getter);

#ifdef __cplusplus
}
#endif

#endif /* SDC_HASH_H */