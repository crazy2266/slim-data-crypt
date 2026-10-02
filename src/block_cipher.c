/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Generic block-cipher helpers (currently CTR mode).
 */

#include <string.h>
#include <sdcrypt/config.h>
#include <sdcrypt/block_cipher.h>
#include <sdcrypt/utils.h>

void sdc_block_cipher_ctr(const sdc_block_cipher_ctx *ctx, const uint8_t nonce[12],
                          const uint8_t *in, size_t len, uint8_t *out) {
    uint8_t counter[16];
    uint8_t keystream[16];
    uint32_t ctr = 0;

    memcpy(counter, nonce, 12);
    counter[12] = counter[13] = counter[14] = counter[15] = 0;

    for (size_t off = 0; off < len; off += 16) {
        counter[12] = (uint8_t)(ctr >> 24);
        counter[13] = (uint8_t)(ctr >> 16);
        counter[14] = (uint8_t)(ctr >> 8);
        counter[15] = (uint8_t)(ctr);
        ctr++;

        ctx->ops->encrypt_block(ctx, counter, keystream);

        size_t n = (len - off < 16) ? (len - off) : 16;
        for (size_t i = 0; i < n; i++) out[off + i] = in[off + i] ^ keystream[i];
    }

    sdc_secure_memzero(counter, sizeof(counter));
    sdc_secure_memzero(keystream, sizeof(keystream));
}
