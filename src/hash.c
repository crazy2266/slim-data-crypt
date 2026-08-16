/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Hash lookup implementation.
 */

#include <string.h>
#include <sdcrypt/hash.h>
#include <sdcrypt/sha2.h>
#include <sdcrypt/config.h>
#include <sdcrypt/random.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/utils.h>
#include <sdcrypt/mem.h>
#include <sdcrypt/private/wyhash.h>

/* ============================================================
   OID definitions & built-in hash implementations
   ============================================================ */

#if SDC_ENABLE_SHA224
const uint8_t SDC_OID_SHA224[9] = {0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x04};
static void hash_sha224(uint8_t *out, const uint8_t *in, size_t len) {
    sdc_sha224_hash(out, in, len);
}
#endif

#if SDC_ENABLE_SHA256
const uint8_t SDC_OID_SHA256[9] = {0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01};
static void hash_sha256(uint8_t *out, const uint8_t *in, size_t len) {
    sdc_sha256_hash(out, in, len);
}
#endif

#if SDC_ENABLE_SHA384
const uint8_t SDC_OID_SHA384[9] = {0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02};
static void hash_sha384(uint8_t *out, const uint8_t *in, size_t len) {
    sdc_sha384_hash(out, in, len);
}
#endif

#if SDC_ENABLE_SHA512
const uint8_t SDC_OID_SHA512[9] = {0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03};
static void hash_sha512(uint8_t *out, const uint8_t *in, size_t len) {
    sdc_sha512_hash(out, in, len);
}
#endif

/* ============================================================
   Built-in entries (only include enabled algorithms)
   ============================================================ */
static const struct {
    const uint8_t *oid;
    size_t oid_len;
    const sdc_hash_ops_t *ops;
} builtin_entries[] = {
#if SDC_ENABLE_SHA224
    {SDC_OID_SHA224, SDC_OID_SHA224_LEN, &(sdc_hash_ops_t){.hash = hash_sha224, .hash_len = 28, .name = "SHA-224"}},
#endif
#if SDC_ENABLE_SHA256
    {SDC_OID_SHA256, SDC_OID_SHA256_LEN, &(sdc_hash_ops_t){.hash = hash_sha256, .hash_len = 32, .name = "SHA-256"}},
#endif
#if SDC_ENABLE_SHA384
    {SDC_OID_SHA384, SDC_OID_SHA384_LEN, &(sdc_hash_ops_t){.hash = hash_sha384, .hash_len = 48, .name = "SHA-384"}},
#endif
#if SDC_ENABLE_SHA512
    {SDC_OID_SHA512, SDC_OID_SHA512_LEN, &(sdc_hash_ops_t){.hash = hash_sha512, .hash_len = 64, .name = "SHA-512"}},
#endif
};
#define BUILTIN_COUNT (sizeof(builtin_entries) / sizeof(builtin_entries[0]))

/* ============================================================
   Hash table (fixed buckets + linked list)
   ============================================================ */
typedef struct entry {
    uint8_t *oid;
    size_t oid_len;
    sdc_hash_ops_t ops;
    struct entry *next;
} entry_t;

static entry_t *buckets[SDC_HASH_BUCKETS];
static uint32_t seed = 0;
static int initialized = 0;

static inline uint32_t hash_oid(const uint8_t *oid, size_t len) {
    return wyhash32(oid, len, seed) % SDC_HASH_BUCKETS;
}

static entry_t *find_entry(const uint8_t *oid, size_t oid_len) {
    uint32_t idx = hash_oid(oid, oid_len);
    for (entry_t *e = buckets[idx]; e; e = e->next) {
        if (e->oid_len == oid_len && memcmp(e->oid, oid, oid_len) == 0) {
            return e;
        }
    }
    return NULL;
}

/* ============================================================
   API
   ============================================================ */
int sdc_hash_init(void) {
    if (initialized) return SDC_ERR_OK;

    int ret = sdc_random_bytes((uint8_t*)&seed, sizeof(seed));
    if (ret != SDC_ERR_OK) seed = 0x9e3779b9;

    memset(buckets, 0, sizeof(buckets));
    initialized = 1;

    for (size_t i = 0; i < BUILTIN_COUNT; i++) {
        uint8_t *copy = sdc_malloc(builtin_entries[i].oid_len);
        if (!copy) return SDC_ERR_MEM_ALLOCATE_FAIL;
        memcpy(copy, builtin_entries[i].oid, builtin_entries[i].oid_len);

        entry_t *e = sdc_malloc(sizeof(entry_t));
        if (!e) { sdc_free(copy); return SDC_ERR_MEM_ALLOCATE_FAIL; }

        e->oid = copy;
        e->oid_len = builtin_entries[i].oid_len;
        e->ops = *builtin_entries[i].ops;

        uint32_t idx = hash_oid(builtin_entries[i].oid, builtin_entries[i].oid_len);
        e->next = buckets[idx];
        buckets[idx] = e;
    }
    return SDC_ERR_OK;
}

int sdc_hash_register(const uint8_t *oid, size_t oid_len, const sdc_hash_ops_t *ops) {
    if (!oid || !ops || !ops->hash) return SDC_ERR_INVALID_PARAM;
    if (!initialized) return SDC_ERR_NOT_READY;
    if (find_entry(oid, oid_len)) return SDC_ERR_ALREADY_EXISTS;

    uint8_t *copy = sdc_malloc(oid_len);
    if (!copy) return SDC_ERR_MEM_ALLOCATE_FAIL;
    memcpy(copy, oid, oid_len);

    entry_t *e = sdc_malloc(sizeof(entry_t));
    if (!e) { sdc_free(copy); return SDC_ERR_MEM_ALLOCATE_FAIL; }

    e->oid = copy;
    e->oid_len = oid_len;
    e->ops = *ops;

    uint32_t idx = hash_oid(oid, oid_len);
    e->next = buckets[idx];
    buckets[idx] = e;
    return SDC_ERR_OK;
}

const sdc_hash_ops_t *sdc_hash_find(const uint8_t *oid, size_t oid_len) {
    if (!initialized || !oid) return NULL;
    entry_t *e = find_entry(oid, oid_len);
    return e ? &e->ops : NULL;
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