/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Configuration file.
 */

#ifndef SDC_CONFIG_H
#define SDC_CONFIG_H

// Enable algorithms
#define SDC_ENABLE_INTEGER                1
#define SDC_ENABLE_HMAC                   1
#define SDC_ENABLE_SHA224                 1
#define SDC_ENABLE_SHA256                 1
#define SDC_ENABLE_SHA384                 1
#define SDC_ENABLE_SHA512                 1
#define SDC_ENABLE_X25519                 1
#define SDC_ENABLE_PBKDF2                 1
#define SDC_ENABLE_CHACHA20               1
#define SDC_ENABLE_XCHACHA20              1
#define SDC_ENABLE_POLY1305               1
#define SDC_ENABLE_CHACHA20POLY1305_AEAD  1
#define SDC_ENABLE_XCHACHA20POLY1305_AEAD 1
#define SDC_ENABLE_RSA_KEYGEN             1
#define SDC_ENABLE_RSAES_PKCS1V15         1
#define SDC_ENABLE_RSASSA_PKCS1V15        1
#define SDC_ENABLE_RSAES_OAEP             1
#define SDC_ENABLE_RSASSA_PSS             1

// Enable features
#define SDC_SWAPPABLE_ALLOCATOR           0
#define SDC_RSA_ENABLE_BLIDING_MODE       1

#endif /* SDC_CONFIG_H */
