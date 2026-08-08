#ifndef XCHACHA20_POLY1305_H
#define XCHACHA20_POLY1305_H

#include <stdint.h>
#include <stddef.h>
#include "xchacha20.h"
#include "poly1305.h"

typedef struct {
    xchacha20_ctx chacha;
    poly1305_ctx poly;
    uint64_t aad_len;
    uint64_t total_len;
    uint8_t finalized;
    uint8_t verified;
} xchacha20_poly1305_ctx;

// ========== 公共初始化 ==========
void xchacha20_poly1305_init(
    xchacha20_poly1305_ctx *ctx,
    const uint8_t key[32],
    const uint8_t nonce[24],
    const uint8_t *aad,
    size_t aad_len
);

// ========== 加密 ==========
void xchacha20_poly1305_encrypt_update(
    xchacha20_poly1305_ctx *ctx,
    const uint8_t *in,
    uint8_t *out,
    size_t len
);

void xchacha20_poly1305_encrypt_final(
    xchacha20_poly1305_ctx *ctx,
    uint8_t tag[16]
);

// ========== 解密 ==========
// 第一遍：认证密文（不解密）
void xchacha20_poly1305_auth_update(
    xchacha20_poly1305_ctx *ctx,
    const uint8_t *in,
    size_t len
);

// 验证 Tag（结束认证阶段）
int xchacha20_poly1305_auth_final(
    xchacha20_poly1305_ctx *ctx,
    const uint8_t tag[16]
);

// 第二遍：真正解密（仅当 verified == 1）
void xchacha20_poly1305_decrypt_update(
    xchacha20_poly1305_ctx *ctx,
    const uint8_t *in,
    uint8_t *out,
    size_t len
);

// 完成解密，安全清零上下文内存
void xchacha20_poly1305_decrypt_final(
    xchacha20_poly1305_ctx *ctx
);

// ========== 一次性接口 ==========
void xchacha20_poly1305_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[24],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    size_t msg_len,
    uint8_t *ciphertext,
    uint8_t tag[16]
);

int xchacha20_poly1305_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[24],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ciphertext,
    size_t msg_len,
    const uint8_t tag[16],
    uint8_t *plaintext
);

#endif