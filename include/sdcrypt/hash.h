/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Hash algorithm lookup by OID.
 */

#ifndef SDC_HASH_H
#define SDC_HASH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- OID constants ---------- */
#define SDC_OID_SHA224_LEN 9
#define SDC_OID_SHA256_LEN 9
#define SDC_OID_SHA384_LEN 9
#define SDC_OID_SHA512_LEN 9

extern const uint8_t SDC_OID_SHA224[SDC_OID_SHA224_LEN];
extern const uint8_t SDC_OID_SHA256[SDC_OID_SHA256_LEN];
extern const uint8_t SDC_OID_SHA384[SDC_OID_SHA384_LEN];
extern const uint8_t SDC_OID_SHA512[SDC_OID_SHA512_LEN];

/* ---------- Hash operation table ---------- */
typedef struct {
    void (*hash)(uint8_t *out, const uint8_t *in, size_t len);
    size_t hash_len;
    const char *name;
} sdc_hash_ops_t;

/* ---------- API functions ---------- */
int sdc_hash_init(void);
int sdc_hash_register(const uint8_t *oid, size_t oid_len, const sdc_hash_ops_t *ops);
const sdc_hash_ops_t *sdc_hash_find(const uint8_t *oid, size_t oid_len);
int sdc_hash_compute(const uint8_t *oid, size_t oid_len,
                     const uint8_t *in, size_t in_len,
                     uint8_t *out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* SDC_HASH_H */