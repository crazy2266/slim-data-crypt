/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Object Identifier (OID) definitions for hash algorithms.
 * Used for X.509 certificates, PKCS#1 signatures, and CMS.
 */

#ifndef SDC_OID_H
#define SDC_OID_H

#include <stdint.h>
#include <stddef.h>
#include <sdcrypt/hash.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
   OID Container
   ============================================================ */
typedef struct {
    const uint8_t *oid;
    size_t oid_len;
} sdc_oid_t;

/* ============================================================
   Hash Algorithm Metadata
   ============================================================ */
typedef struct {
    sdc_hash_id_t id;
    const char *name;
    size_t hash_len;
    const uint8_t *oid;
    size_t oid_len;
} sdc_hash_meta_t;

extern const sdc_hash_meta_t sdc_hash_meta[SDC_HASH_COUNT];

/* ============================================================
   OID Lookup Functions
   ============================================================ */

/* Lookup the hash ID corresponding to an OID. (Direct Indexing) */
sdc_hash_id_t sdc_hash_id_from_oid(const uint8_t *oid, size_t oid_len);

/* Lookup the OID from the hash ID. (Direct Indexing) */
const sdc_oid_t *sdc_hash_oid_from_id(sdc_hash_id_t id);

#ifdef __cplusplus
}
#endif

#endif /* SDC_OID_H */