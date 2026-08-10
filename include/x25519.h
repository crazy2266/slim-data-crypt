/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * X25519 functions for key exchange.
 */

#ifndef SDC_X25519_H
#define SDC_X25519_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * X25519 密钥交换
 *
 * @param out       输出共享密钥（32 字节）
 * @param priv      私钥（32 字节）
 * @param pub       对方公钥（32 字节）
 * @return 0 成功，负数错误码
 */
int sdc_x25519_exchange(uint8_t shared[32], const uint8_t priv[32], const uint8_t pub[32]);

/**
 * 生成 X25519 密钥对
 *
 * @param pub       输出公钥（32 字节）
 * @param priv      输出私钥（32 字节）
 * @param rng       随机数生成器（可为 NULL，使用默认）
 * @return 0 成功，负数错误码
 */
int sdc_x25519_keygen(uint8_t pub[32], uint8_t priv[32]);

#ifdef __cplusplus
}
#endif

#endif /* SDC_X25519_H */
