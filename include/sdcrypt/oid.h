/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * OID definitions for algorithms.
 */

#ifndef SDC_OID_H
#define SDC_OID_H

#include <stdint.h>
#include <stddef.h>
#include <sdcrypt/config.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ===== Hash algorithms OID ===== */
// SHA-224
#if SDC_ENABLE_SHA224
#define SDC_OID_SHA224_LEN 9
extern const uint8_t SDC_OID_SHA224[SDC_OID_SHA224_LEN];
#endif
// SHA-256
#if SDC_ENABLE_SHA256
#define SDC_OID_SHA256_LEN 9
extern const uint8_t SDC_OID_SHA256[SDC_OID_SHA256_LEN];
#endif
// SHA-384
#if SDC_ENABLE_SHA384
#define SDC_OID_SHA384_LEN 9
extern const uint8_t SDC_OID_SHA384[SDC_OID_SHA384_LEN];
#endif
// SHA-512
#if SDC_ENABLE_SHA512
#define SDC_OID_SHA512_LEN 9
extern const uint8_t SDC_OID_SHA512[SDC_OID_SHA512_LEN];
#endif
// SM3
#if SDC_ENABLE_SM3
#define SDC_OID_SM3_LEN 8
extern const uint8_t SDC_OID_SM3[SDC_OID_SM3_LEN];
#endif

#ifdef __cplusplus
}
#endif

#endif /* SDC_OID_H */