#include <string.h>
#include "aead.h"
#include "utils.h"

// RFC 8439 / XChaCha20-Poly1305: pad AAD/ciphertext to a 16-byte boundary.
static void poly1305_pad16(poly1305_ctx *ctx, uint64_t len) {
    static const uint8_t zero[16] = {0};
    size_t rem = (size_t)(len & 15u);
    if (rem != 0) {
        poly1305_update(ctx, zero, 16 - rem);
    }
}

void xchacha20_poly1305_init(
    xchacha20_poly1305_ctx *ctx,
    const uint8_t key[32],
    const uint8_t nonce[24],
    const uint8_t *aad,
    size_t aad_len
) {
    // 1. 派生子密钥
    uint8_t block0[64], subkey[32];
    memset(block0, 0, sizeof(block0));
    xchacha20_init(&ctx->chacha, key, nonce, 0);
    xchacha20_crypt(&ctx->chacha, block0, block0, 64);
    memcpy(subkey, block0, 32);
    secure_memzero(block0, sizeof(block0));
    // 2. 重新初始化 XChaCha20
    xchacha20_init(&ctx->chacha, key, nonce, 1);
    // 3. 初始化 Poly1305
    poly1305_init(&ctx->poly, subkey);
    secure_memzero(subkey, sizeof(subkey));
    // 4. 认证 AAD
    if (aad && aad_len) {
        poly1305_update(&ctx->poly, aad, aad_len);
    }
    poly1305_pad16(&ctx->poly, aad_len);
    ctx->aad_len = aad_len;
    ctx->total_len = 0;
    ctx->finalized = 0;
    ctx->verified = 0;
}

// ========== 加密模式 ==========
void xchacha20_poly1305_encrypt_update(
    xchacha20_poly1305_ctx *ctx,
    const uint8_t *in,
    uint8_t *out,
    size_t len
) {
    if (ctx->finalized || len == 0) return;
    // XChaCha20 加密
    xchacha20_crypt(&ctx->chacha, in, out, len);
    // Poly1305 认证密文
    poly1305_update(&ctx->poly, out, len);
    ctx->total_len += len;
}

void xchacha20_poly1305_encrypt_final(
    xchacha20_poly1305_ctx *ctx,
    uint8_t tag[16]
) {
    if (ctx->finalized) return;
    ctx->finalized = 1;

    // pad16(ciphertext)，然后添加长度信息
    poly1305_pad16(&ctx->poly, ctx->total_len);

    uint8_t len_buf[16];
    uint64_t aad_len = ctx->aad_len;
    uint64_t msg_len = ctx->total_len;

    for (int i = 0; i < 8; i++) {
        len_buf[i] = (uint8_t)(aad_len & 0xff);
        aad_len >>= 8;
        len_buf[i + 8] = (uint8_t)(msg_len & 0xff);
        msg_len >>= 8;
    }
    poly1305_update(&ctx->poly, len_buf, 16);
    poly1305_final(&ctx->poly, tag);
    secure_memzero(ctx, sizeof(xchacha20_poly1305_ctx));
}

// ========== 解密模式 ==========
void xchacha20_poly1305_auth_update(
    xchacha20_poly1305_ctx *ctx,
    const uint8_t *in,
    size_t len
) {
    if (ctx->finalized || len == 0) return;
    // 只认证密文，不解密
    poly1305_update(&ctx->poly, in, len);
    ctx->total_len += len;
}

int xchacha20_poly1305_auth_final(
    xchacha20_poly1305_ctx *ctx,
    const uint8_t tag[16]
) {
    if (ctx->finalized) return -1;

    // pad16(ciphertext)，然后计算期望的 Tag
    poly1305_pad16(&ctx->poly, ctx->total_len);

    uint8_t expected[16];
    uint8_t len_buf[16];
    uint64_t aad_len = ctx->aad_len;
    uint64_t msg_len = ctx->total_len;

    for (int i = 0; i < 8; i++) {
        len_buf[i] = (uint8_t)(aad_len & 0xff);
        aad_len >>= 8;
        len_buf[i + 8] = (uint8_t)(msg_len & 0xff);
        msg_len >>= 8;
    }
    poly1305_update(&ctx->poly, len_buf, 16);
    poly1305_final(&ctx->poly, expected);
    ctx->verified = secure_memcmp(tag, expected, 16) ? 1 : 0;
    return ctx->verified ? 0 : -1;
}

void xchacha20_poly1305_decrypt_update(
    xchacha20_poly1305_ctx *ctx,
    const uint8_t *in,
    uint8_t *out,
    size_t len
) {
    if (!ctx->verified || ctx->finalized || len == 0) return;
    // 只有 Tag 验证通过才解密
    xchacha20_crypt(&ctx->chacha, in, out, len);
}

void xchacha20_poly1305_decrypt_final(xchacha20_poly1305_ctx *ctx) {
    secure_memzero(ctx, sizeof(xchacha20_poly1305_ctx));
}

void xchacha20_poly1305_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[24],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    size_t msg_len,
    uint8_t *ciphertext,
    uint8_t tag[16]
) {
    xchacha20_poly1305_ctx ctx;
    xchacha20_poly1305_init(&ctx, key, nonce, aad, aad_len);
    xchacha20_poly1305_encrypt_update(&ctx, plaintext, ciphertext, msg_len);
    xchacha20_poly1305_encrypt_final(&ctx, tag);
}

int xchacha20_poly1305_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[24],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ciphertext,
    size_t msg_len,
    const uint8_t tag[16],
    uint8_t *plaintext
) {
    xchacha20_poly1305_ctx ctx;
    xchacha20_poly1305_init(&ctx, key, nonce, aad, aad_len);
    xchacha20_poly1305_auth_update(&ctx, ciphertext, msg_len);
    int ret = xchacha20_poly1305_auth_final(&ctx, tag);
    if (ret == 0) xchacha20_poly1305_decrypt_update(&ctx, ciphertext, plaintext, msg_len);
    xchacha20_poly1305_decrypt_final(&ctx);
    return ret;
}