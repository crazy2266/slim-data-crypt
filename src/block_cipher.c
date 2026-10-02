/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Generic block-cipher helpers (CTR and CBC modes).
 */

#include <string.h>
#include <sdcrypt/config.h>
#include <sdcrypt/block_cipher.h>
#include <sdcrypt/utils.h>

void sdc_block_cipher_ctr(const sdc_block_cipher_ctx *ctx, const uint8_t nonce[12],
                          const uint8_t *in, size_t len, uint8_t *out) {
    enum { BATCH = 8 };
    uint8_t ctrblk[BATCH * 16];
    uint8_t ks[BATCH * 16];
    uint8_t base[12];
    uint32_t ctr = 0;

    memcpy(base, nonce, 12);

    size_t off = 0;
    while (off < len) {
        size_t remain = len - off;
        size_t nb = (remain + 15) / 16;
        if (nb > BATCH) nb = BATCH;

        for (size_t i = 0; i < nb; i++) {
            uint32_t c = ctr + (uint32_t)i;
            memcpy(ctrblk + 16 * i, base, 12);
            ctrblk[16 * i + 12] = (uint8_t)(c >> 24);
            ctrblk[16 * i + 13] = (uint8_t)(c >> 16);
            ctrblk[16 * i + 14] = (uint8_t)(c >> 8);
            ctrblk[16 * i + 15] = (uint8_t)(c);
        }
        ctx->ops->encrypt_blocks(ctx, ctrblk, nb, ks);

        size_t bytes = (remain < nb * 16) ? remain : nb * 16;
        for (size_t i = 0; i < bytes; i++) out[off + i] = in[off + i] ^ ks[i];

        ctr += (uint32_t)nb;
        off += bytes;
    }

    sdc_secure_memzero(ctrblk, sizeof(ctrblk));
    sdc_secure_memzero(ks, sizeof(ks));
    sdc_secure_memzero(base, sizeof(base));
}

void sdc_block_cipher_cbc_encrypt(const sdc_block_cipher_ctx *ctx, const uint8_t iv[16],
                                  const uint8_t *in, size_t len, uint8_t *out) {
    uint8_t prev[16];
    memcpy(prev, iv, 16);
    for (size_t off = 0; off < len; off += 16) {
        uint8_t blk[16];
        for (int i = 0; i < 16; i++) blk[i] = in[off + i] ^ prev[i];
        ctx->ops->encrypt_block(ctx, blk, out + off);
        memcpy(prev, out + off, 16);
    }
    sdc_secure_memzero(prev, sizeof(prev));
}

void sdc_block_cipher_cbc_decrypt(const sdc_block_cipher_ctx *ctx, const uint8_t iv[16],
                                  const uint8_t *in, size_t len, uint8_t *out) {
    uint8_t prev[16];
    memcpy(prev, iv, 16);
    for (size_t off = 0; off < len; off += 16) {
        uint8_t blk[16];
        ctx->ops->decrypt_block(ctx, in + off, blk);
        for (int i = 0; i < 16; i++) out[off + i] = blk[i] ^ prev[i];
        memcpy(prev, in + off, 16);
    }
    sdc_secure_memzero(prev, sizeof(prev));
}
