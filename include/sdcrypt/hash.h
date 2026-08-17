/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Hash algorithm interface.
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

/*
 * Use custom getter first, if getter is NULL, use default getter.
 * if the hash algorithm is not found by getter, fallback to default OID table.
 * if the hash algorithm is not found in default OID table, return NULL.
 */ 
const sdc_hash_ops_t *sdc_hash_find_by_oid(const uint8_t *oid, size_t oid_len, sdc_hash_getter_t getter);

#ifdef __cplusplus
}
#endif

#endif /* SDC_HASH_H */