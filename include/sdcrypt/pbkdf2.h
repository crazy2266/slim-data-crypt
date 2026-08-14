/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * PBKDF2-HMAC-SHA256 key derivation function.
 */

#ifndef SDC_PBKDF2_H
#define SDC_PBKDF2_H

#include <stdint.h>
#include <stddef.h>
#include <sdcrypt/config.h>

#if SDC_ENABLE_PBKDF2

#if !SDC_ENABLE_HMAC || !SDC_ENABLE_SHA256
#  error "PBKDF2-HMAC-SHA256 requires HMAC and SHA256 support"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * PBKDF2-HMAC-SHA256: 从密码派生密钥
 *
 * @param out        输出缓冲区
 * @param outlen     输出长度（字节）
 * @param password   用户密码
 * @param pwdlen     密码长度
 * @param salt       盐值
 * @param saltlen    盐值长度
 * @param iterations 迭代次数（推荐 600000）
 */
void sdc_kdf_pbkdf2_sha256(
    uint8_t *out, size_t outlen,
    const uint8_t *password, size_t pwdlen,
    const uint8_t *salt, size_t saltlen,
    uint32_t iterations
);

#ifdef __cplusplus
}
#endif

#endif /* SDC_ENABLE_PBKDF2 */

#endif /* SDC_PBKDF2_H */