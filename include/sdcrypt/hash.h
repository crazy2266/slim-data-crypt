/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Hash interface API file.
 */

#ifndef SDC_HASH_H
#define SDC_HASH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
   Hash algorithm ID
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
   Hash operation table
   ============================================================ */
typedef struct {
    void (*init)(void *ctx);
    void (*update)(void *ctx, const uint8_t *data, size_t len);
    void (*final)(void *ctx, uint8_t *out);
    void (*hash)(uint8_t *out, const uint8_t *in, size_t len);
    size_t hash_len;
    const char *name;
} sdc_hash_ops_t;

/* ============================================================
   API
   ============================================================ */

/* Initialize current thread hash algorithm (default: SHA-256) */
void sdc_hash_thread_init(void);

/* Set current thread hash algorithm */
void sdc_hash_thread_set(sdc_hash_id_t id);

/* Get current thread hash algorithm ID */
sdc_hash_id_t sdc_hash_thread_get(void);

/* Get hash operation table by ID */
const sdc_hash_ops_t *sdc_hash_get_ops(sdc_hash_id_t id);

/* Compute hash using current thread algorithm */
void sdc_hash_compute(const uint8_t *in, size_t in_len, uint8_t *out);

/* Compute hash using specified algorithm */
void sdc_hash_compute_with(sdc_hash_id_t id,
                           const uint8_t *in, size_t in_len,
                           uint8_t *out);

/* Get current thread hash length */
size_t sdc_hash_current_len(void);

/* Get hash length for specified algorithm */
size_t sdc_hash_len(sdc_hash_id_t id);

#ifdef __cplusplus
}
#endif

#endif /* SDC_HASH_H */