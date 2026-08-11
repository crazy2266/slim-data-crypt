/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * XChaCha20-Poly1305 AEAD cipher.
 */

#ifndef SDC_AEAD_H
#define SDC_AEAD_H

#include <stdint.h>
#include <stddef.h>
#include "xchacha20.h"
#include "poly1305.h"
#include "config.h"

#if SDC_ENABLE_XCHACHA20POLY1305_AEAD

#if !SDC_ENABLE_XCHACHA20 || !SDC_ENABLE_POLY1305
#  error "XChaCha20 and Poly1305 must be enabled to use XChaCha20-Poly1305 AEAD"
#endif

typedef struct {
    sdc_xchacha20_ctx chacha;
    sdc_poly1305_ctx poly;
    uint64_t aad_len;
    uint64_t total_len;
    uint8_t finalized;
    uint8_t verified;
} sdc_xchacha20_poly1305_ctx;

// ========== 公共初始化 ==========
void sdc_xchacha20_poly1305_init(
    sdc_xchacha20_poly1305_ctx *ctx,
    const uint8_t key[32],
    const uint8_t nonce[24],
    const uint8_t *aad,
    size_t aad_len
);

// ========== 加密 ==========
void sdc_xchacha20_poly1305_encrypt_update(
    sdc_xchacha20_poly1305_ctx *ctx,
    const uint8_t *in,
    uint8_t *out,
    size_t len
);

void sdc_xchacha20_poly1305_encrypt_final(
    sdc_xchacha20_poly1305_ctx *ctx,
    uint8_t tag[16]
);

// ========== 解密 ==========
// 第一遍：认证密文（不解密）
void sdc_xchacha20_poly1305_auth_update(
    sdc_xchacha20_poly1305_ctx *ctx,
    const uint8_t *in,
    size_t len
);

// 验证 Tag（结束认证阶段）
int sdc_xchacha20_poly1305_auth_final(
    sdc_xchacha20_poly1305_ctx *ctx,
    const uint8_t tag[16]
);

// 第二遍：真正解密（仅当 verified == 1）
void sdc_xchacha20_poly1305_decrypt_update(
    sdc_xchacha20_poly1305_ctx *ctx,
    const uint8_t *in,
    uint8_t *out,
    size_t len
);

// 完成解密，安全清零上下文内存
void sdc_xchacha20_poly1305_decrypt_final(
    sdc_xchacha20_poly1305_ctx *ctx
);

// ========== 一次性接口 ==========
void sdc_xchacha20_poly1305_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[24],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    size_t msg_len,
    uint8_t *ciphertext,
    uint8_t tag[16]
);

int sdc_xchacha20_poly1305_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[24],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ciphertext,
    size_t msg_len,
    const uint8_t tag[16],
    uint8_t *plaintext
);

#endif /* SDC_ENABLE_XCHACHA20POLY1305_AEAD */

#endif /* SDC_AEAD_H */