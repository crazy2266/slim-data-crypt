/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Hash algorithm lookup table - public interface.
 */

#ifndef SDC_HASH_H
#define SDC_HASH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
   Hash algorithm IDs
   ============================================================ */

typedef enum {
    SDC_HASH_NONE = 0,
    SDC_HASH_SHA224,
    SDC_HASH_SHA256,
    SDC_HASH_SHA384,
    SDC_HASH_SHA512,
    SDC_HASH_COUNT
} sdc_hash_id_t;

/* ============================================================
   Hash operations
   ============================================================ */

typedef struct {
    void (*hash)(uint8_t *out, const uint8_t *in, size_t len);
    size_t hash_len;
    const char *name;
} sdc_hash_ops_t;

/* ============================================================
   API - per-thread custom table + global built-in table
   ============================================================ */

/* Register a custom hash implementation for current thread only */
int sdc_hash_register(sdc_hash_id_t id, const sdc_hash_ops_t *ops);

/* Unregister a custom hash implementation for current thread */
void sdc_hash_unregister(sdc_hash_id_t id);

/* Clear all custom hash implementations for current thread */
void sdc_hash_table_clear(void);

/* Lookup hash ops for current thread (custom first, then built-in) */
const sdc_hash_ops_t *sdc_hash_get_ops(sdc_hash_id_t id);

/* Check if a hash algorithm is available in current thread */
int sdc_hash_available(sdc_hash_id_t id);

/* Get hash length */
size_t sdc_hash_len(sdc_hash_id_t id);

/* Get hash name */
const char *sdc_hash_name(sdc_hash_id_t id);

/* Convenience: compute hash with given ID */
int sdc_hash_compute(sdc_hash_id_t id,
                     const uint8_t *in, size_t in_len,
                     uint8_t *out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* SDC_HASH_H */