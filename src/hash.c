/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Hash algorithm lookup by OID.
 */

#include <string.h>
#include <sdcrypt/hash.h>
#include <sdcrypt/sha2.h>
#include <sdcrypt/config.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/oid.h>
#include <sdcrypt/mem.h>

/* ---------- Builtin hash entry ---------- */
#if SDC_ENABLE_SHA224
static void hash_sha224(uint8_t *out, const uint8_t *in, size_t len) {
    sdc_sha224_hash(out, in, len);
}
#endif

#if SDC_ENABLE_SHA256
static void hash_sha256(uint8_t *out, const uint8_t *in, size_t len) {
    sdc_sha256_hash(out, in, len);
}
#endif

#if SDC_ENABLE_SHA384
static void hash_sha384(uint8_t *out, const uint8_t *in, size_t len) {
    sdc_sha384_hash(out, in, len);
}
#endif

#if SDC_ENABLE_SHA512
static void hash_sha512(uint8_t *out, const uint8_t *in, size_t len) {
    sdc_sha512_hash(out, in, len);
}
#endif

/* ---------- Builtin hash table entry ---------- */
typedef struct {
    const uint8_t *oid;
    size_t oid_len;
    const sdc_hash_ops_t *ops;
    int id;
} sdc_hash_entry_t;

static const sdc_hash_ops_t sha224_ops = {.hash = hash_sha224, .hash_len = 28, .name = "SHA-224"};
static const sdc_hash_ops_t sha256_ops = {.hash = hash_sha256, .hash_len = 32, .name = "SHA-256"};
static const sdc_hash_ops_t sha384_ops = {.hash = hash_sha384, .hash_len = 48, .name = "SHA-384"};
static const sdc_hash_ops_t sha512_ops = {.hash = hash_sha512, .hash_len = 64, .name = "SHA-512"};

static const sdc_hash_entry_t builtin_table[] = {
#if SDC_ENABLE_SHA224
    {SDC_OID_SHA224, SDC_OID_SHA224_LEN, &sha224_ops},
#endif
#if SDC_ENABLE_SHA256
    {SDC_OID_SHA256, SDC_OID_SHA256_LEN, &sha256_ops},
#endif
#if SDC_ENABLE_SHA384
    {SDC_OID_SHA384, SDC_OID_SHA384_LEN, &sha384_ops},
#endif
#if SDC_ENABLE_SHA512
    {SDC_OID_SHA512, SDC_OID_SHA512_LEN, &sha512_ops},
#endif
};
#define BUILTIN_COUNT (sizeof(builtin_table) / sizeof(builtin_table[0]))

/* ---------- Custom hash table entry ---------- */
#define SDC_HASH_CUSTOM_MAX 8
static sdc_hash_entry_t custom_table[SDC_HASH_CUSTOM_MAX] = {0};
static size_t custom_count = 0;
static int initialized = 0;

static const sdc_hash_ops_t *find_in_table(const sdc_hash_entry_t *table,
                                           size_t count,
                                           const uint8_t *oid,
                                           size_t oid_len) {
    for (size_t i = 0; i < count; i++) {
        if (table[i].oid_len == oid_len &&
            memcmp(table[i].oid, oid, oid_len) == 0) {
            return table[i].ops;
        }
    }
    return NULL;
}

/* ---------- API ---------- */

int sdc_hash_init(void) {
    if (initialized) return SDC_ERR_OK;
    memset(custom_table, 0, sizeof(custom_table));
    custom_count = 0;
    initialized = 1;
    return SDC_ERR_OK;
}

int sdc_hash_register(const uint8_t *oid, size_t oid_len,
                      const sdc_hash_ops_t *ops) {
    if (!oid || !ops || !ops->hash) return SDC_ERR_INVALID_PARAM;
    if (!initialized) return SDC_ERR_NOT_READY;

    if (find_in_table(custom_table, custom_count, oid, oid_len)) {
        return SDC_ERR_ALREADY_EXISTS;
    }

    if (custom_count >= SDC_HASH_CUSTOM_MAX) {
        return SDC_ERR_BUFFER_TOO_SMALL;
    }

    custom_table[custom_count].oid = oid;
    custom_table[custom_count].oid_len = oid_len;
    custom_table[custom_count].ops = ops;
    custom_count++;
    return SDC_ERR_OK;
}

const sdc_hash_ops_t *sdc_hash_find(const uint8_t *oid, size_t oid_len) {
    if (!oid || !initialized) return NULL;

    const sdc_hash_ops_t *ops = find_in_table(custom_table, custom_count,
                                              oid, oid_len);
    if (ops) return ops;

    return find_in_table(builtin_table, BUILTIN_COUNT, oid, oid_len);
}

int sdc_hash_compute(const uint8_t *oid, size_t oid_len,
                     const uint8_t *in, size_t in_len,
                     uint8_t *out, size_t *out_len) {
    const sdc_hash_ops_t *ops = sdc_hash_find(oid, oid_len);
    if (!ops) return SDC_ERR_NOT_FOUND;
    if (!ops->hash) return SDC_ERR_NOT_IMPLEMENTED;
    if (out_len) *out_len = ops->hash_len;
    ops->hash(out, in, in_len);
    return SDC_ERR_OK;
}