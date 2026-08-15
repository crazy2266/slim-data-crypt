/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Hash algorithm lookup table.
 * - Built-in table: global read-only, shared by all threads.
 * - Custom table: per-thread, users can register their own implementations.
 */

#include <sdcrypt/hash.h>
#include <sdcrypt/sha2.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/platform.h>
#include <sdcrypt/config.h>
#include <string.h>

/* ============================================================
   Built-in hash wrappers
   ============================================================ */

#if SDC_ENABLE_SHA224
static void sha224_hash_wrap(uint8_t *out, const uint8_t *in, size_t len) {
    sdc_sha224_hash(out, in, len);
}
#endif

#if SDC_ENABLE_SHA256
static void sha256_hash_wrap(uint8_t *out, const uint8_t *in, size_t len) {
    sdc_sha256_hash(out, in, len);
}
#endif

#if SDC_ENABLE_SHA384
static void sha384_hash_wrap(uint8_t *out, const uint8_t *in, size_t len) {
    sdc_sha384_hash(out, in, len);
}
#endif

#if SDC_ENABLE_SHA512
static void sha512_hash_wrap(uint8_t *out, const uint8_t *in, size_t len) {
    sdc_sha512_hash(out, in, len);
}
#endif

/* ============================================================
   Built-in hash table (global read-only)
   ============================================================ */
static const sdc_hash_ops_t builtin_table[SDC_HASH_COUNT] = {
    [SDC_HASH_NONE] = {
        .hash = NULL,
        .hash_len = 0,
        .name = "NONE"
    },

#if SDC_ENABLE_SHA224
    [SDC_HASH_SHA224] = {
        .hash = sha224_hash_wrap,
        .hash_len = 28,
        .name = "SHA-224"
    },
#else
    [SDC_HASH_SHA224] = {
        .hash = NULL,
        .hash_len = 0,
        .name = "SHA-224 (disabled)"
    },
#endif

#if SDC_ENABLE_SHA256
    [SDC_HASH_SHA256] = {
        .hash = sha256_hash_wrap,
        .hash_len = 32,
        .name = "SHA-256"
    },
#else
    [SDC_HASH_SHA256] = {
        .hash = NULL,
        .hash_len = 0,
        .name = "SHA-256 (disabled)"
    },
#endif

#if SDC_ENABLE_SHA384
    [SDC_HASH_SHA384] = {
        .hash = sha384_hash_wrap,
        .hash_len = 48,
        .name = "SHA-384"
    },
#else
    [SDC_HASH_SHA384] = {
        .hash = NULL,
        .hash_len = 0,
        .name = "SHA-384 (disabled)"
    },
#endif

#if SDC_ENABLE_SHA512
    [SDC_HASH_SHA512] = {
        .hash = sha512_hash_wrap,
        .hash_len = 64,
        .name = "SHA-512"
    },
#else
    [SDC_HASH_SHA512] = {
        .hash = NULL,
        .hash_len = 0,
        .name = "SHA-512 (disabled)"
    },
#endif
};

/* ============================================================
   Per-thread custom hash table
   ============================================================ */
static SDC_THREAD_LOCAL sdc_hash_ops_t custom_table[SDC_HASH_COUNT] = {0};

/* ============================================================
   Register a custom hash implementation for current thread
   ============================================================ */
int sdc_hash_register(sdc_hash_id_t id, const sdc_hash_ops_t *ops) {
    if (id <= SDC_HASH_NONE || id >= SDC_HASH_COUNT) {
        return SDC_ERR_INVALID_PARAM;
    }
    if (!ops || !ops->hash) {
        return SDC_ERR_INVALID_PARAM;
    }
    custom_table[id] = *ops;
    return SDC_ERR_OK;
}

/* ============================================================
   Unregister a custom hash implementation for current thread
   ============================================================ */
void sdc_hash_unregister(sdc_hash_id_t id) {
    if (id > SDC_HASH_NONE && id < SDC_HASH_COUNT) {
        memset(&custom_table[id], 0, sizeof(sdc_hash_ops_t));
    }
}

/* ============================================================
   Clear all custom hash implementations for current thread
   ============================================================ */
void sdc_hash_table_clear(void) {
    memset(custom_table, 0, sizeof(custom_table));
}

/* ============================================================
   Lookup hash ops for current thread
   ============================================================ */
const sdc_hash_ops_t *sdc_hash_get_ops(sdc_hash_id_t id) {
    if (id <= SDC_HASH_NONE || id >= SDC_HASH_COUNT) {
        return NULL;
    }
    /* Look up custom table first. */
    if (custom_table[id].hash) {
        return &custom_table[id];
    }
    /* Look up builtin table. */
    if (builtin_table[id].hash) {
        return &builtin_table[id];
    }
    return NULL;
}

/* ============================================================
   Check if a hash algorithm is available in current thread
   ============================================================ */

int sdc_hash_available(sdc_hash_id_t id) {
    return sdc_hash_get_ops(id) != NULL;
}

/* ============================================================
   Get hash length
   ============================================================ */
size_t sdc_hash_len(sdc_hash_id_t id) {
    const sdc_hash_ops_t *ops = sdc_hash_get_ops(id);
    return ops ? ops->hash_len : 0;
}

/* ============================================================
   Get hash name
   ============================================================ */
const char *sdc_hash_name(sdc_hash_id_t id) {
    const sdc_hash_ops_t *ops = sdc_hash_get_ops(id);
    return ops ? ops->name : NULL;
}

/* ============================================================
   Convenience compute function
   ============================================================ */
int sdc_hash_compute(sdc_hash_id_t id,
                     const uint8_t *in, size_t in_len,
                     uint8_t *out, size_t *out_len) {
    const sdc_hash_ops_t *ops = sdc_hash_get_ops(id);
    if (!ops || !ops->hash) {
        return SDC_ERR_NOT_IMPLEMENTED;
    }
    if (out_len) {
        *out_len = ops->hash_len;
    }
    ops->hash(out, in, in_len);
    return SDC_ERR_OK;
}