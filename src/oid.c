/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Object Identifier (OID) definitions for hash algorithms.
 */

#include <sdcrypt/oid.h>
#include <string.h>

/* ============================================================
   OID Definitions (DER Encoding)
   ============================================================ */

/* SHA-224: 2.16.840.1.101.3.4.2.4 */
static const uint8_t oid_sha224[] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04
};
#define OID_SHA224_LEN 9

/* SHA-256: 2.16.840.1.101.3.4.2.1 */
static const uint8_t oid_sha256[] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
};
#define OID_SHA256_LEN 9

/* SHA-384: 2.16.840.1.101.3.4.2.2 */
static const uint8_t oid_sha384[] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02
};
#define OID_SHA384_LEN 9

/* SHA-512: 2.16.840.1.101.3.4.2.3 */
static const uint8_t oid_sha512[] = {
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03
};
#define OID_SHA512_LEN 9

/* ============================================================
   Hash Algorithm Metadata Array
   ============================================================ */
const sdc_hash_meta_t sdc_hash_meta[SDC_HASH_COUNT] = {
    [SDC_HASH_NONE] = {
        .id = SDC_HASH_NONE,
        .name = "NONE",
        .hash_len = 0,
        .oid = NULL,
        .oid_len = 0
    },
    [SDC_HASH_SHA224] = {
        .id = SDC_HASH_SHA224,
        .name = "SHA-224",
        .hash_len = 28,
        .oid = oid_sha224,
        .oid_len = OID_SHA224_LEN
    },
    [SDC_HASH_SHA256] = {
        .id = SDC_HASH_SHA256,
        .name = "SHA-256",
        .hash_len = 32,
        .oid = oid_sha256,
        .oid_len = OID_SHA256_LEN
    },
    [SDC_HASH_SHA384] = {
        .id = SDC_HASH_SHA384,
        .name = "SHA-384",
        .hash_len = 48,
        .oid = oid_sha384,
        .oid_len = OID_SHA384_LEN
    },
    [SDC_HASH_SHA512] = {
        .id = SDC_HASH_SHA512,
        .name = "SHA-512",
        .hash_len = 64,
        .oid = oid_sha512,
        .oid_len = OID_SHA512_LEN
    }
};

/* ============================================================
   OID → ID Lookup (Iterative Search)
   ============================================================ */
sdc_hash_id_t sdc_hash_id_from_oid(const uint8_t *oid, size_t oid_len) {
    for (int i = SDC_HASH_SHA224; i < SDC_HASH_COUNT; i++) {
        const sdc_hash_meta_t *meta = &sdc_hash_meta[i];
        if (meta->oid_len == oid_len && memcmp(meta->oid, oid, oid_len) == 0) {
            return (sdc_hash_id_t)i;
        }
    }
    return SDC_HASH_NONE;
}

/* ============================================================
   ID → OID Lookup (Direct Indexing)
   ============================================================ */
const sdc_oid_t *sdc_hash_oid_from_id(sdc_hash_id_t id) {
    if (id <= SDC_HASH_NONE || id >= SDC_HASH_COUNT) return NULL;
    const sdc_hash_meta_t *meta = &sdc_hash_meta[id];
    if (!meta->oid) return NULL;
    static sdc_oid_t oid;
    oid.oid = meta->oid;
    oid.oid_len = meta->oid_len;
    return &oid;
}