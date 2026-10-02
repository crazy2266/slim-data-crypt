/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * AES backend using ARMv8 Crypto Extensions (AESE/AESMC/AESD/AESIMC).
 *
 * Compiled with a baseline target; the crypto instructions are enabled
 * per-function via __attribute__((target("+crypto"))) so the rest of the
 * library stays portable. Callers must gate on runtime detection.
 */

#include <sdcrypt/config.h>

#if SDC_ENABLE_AES && defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))

#include <string.h>
#include <arm_neon.h>
#include <sdcrypt/aes.h>
#include "aes_backend.h"

#define SDC_ARMCE_TARGET __attribute__((target("+crypto")))

void sdc_aes_armce_set_key(sdc_aes_key *key) {
    memcpy(key->be, key->rk, 16 * (key->nr + 1));
}

SDC_ARMCE_TARGET
void sdc_aes_armce_encrypt(const sdc_aes_key *key, const uint8_t in[16], uint8_t out[16]) {
    const uint8_t *rk = key->be;
    uint8x16_t b = vld1q_u8(in);

    for (int r = 0; r < key->nr - 1; r++) {
        b = vaeseq_u8(b, vld1q_u8(rk + 16 * r));
        b = vaesmcq_u8(b);
    }
    b = vaeseq_u8(b, vld1q_u8(rk + 16 * (key->nr - 1)));
    b = veorq_u8(b, vld1q_u8(rk + 16 * key->nr));

    vst1q_u8(out, b);
}

SDC_ARMCE_TARGET
void sdc_aes_armce_decrypt(const sdc_aes_key *key, const uint8_t in[16], uint8_t out[16]) {
    const uint8_t *rk = key->be;
    const uint8x16_t zero = vdupq_n_u8(0);
    uint8x16_t b = vld1q_u8(in);

    b = veorq_u8(b, vld1q_u8(rk + 16 * key->nr));
    for (int r = key->nr - 1; r >= 1; r--) {
        b = vaesdq_u8(b, zero);
        b = veorq_u8(b, vld1q_u8(rk + 16 * r));
        b = vaesimcq_u8(b);
    }
    b = vaesdq_u8(b, zero);
    b = veorq_u8(b, vld1q_u8(rk));

    vst1q_u8(out, b);
}

SDC_ARMCE_TARGET
void sdc_aes_armce_encrypt_blocks(const sdc_aes_key *key, const uint8_t *in, size_t nblocks, uint8_t *out) {
    const uint8_t *rk = key->be;
    const int nr = key->nr;

    while (nblocks >= 4) {
        uint8x16_t b0 = vld1q_u8(in + 0);
        uint8x16_t b1 = vld1q_u8(in + 16);
        uint8x16_t b2 = vld1q_u8(in + 32);
        uint8x16_t b3 = vld1q_u8(in + 48);

        for (int r = 0; r < nr - 1; r++) {
            uint8x16_t k = vld1q_u8(rk + 16 * r);
            b0 = vaesmcq_u8(vaeseq_u8(b0, k));
            b1 = vaesmcq_u8(vaeseq_u8(b1, k));
            b2 = vaesmcq_u8(vaeseq_u8(b2, k));
            b3 = vaesmcq_u8(vaeseq_u8(b3, k));
        }
        uint8x16_t kl = vld1q_u8(rk + 16 * (nr - 1));
        uint8x16_t kf = vld1q_u8(rk + 16 * nr);
        b0 = veorq_u8(vaeseq_u8(b0, kl), kf);
        b1 = veorq_u8(vaeseq_u8(b1, kl), kf);
        b2 = veorq_u8(vaeseq_u8(b2, kl), kf);
        b3 = veorq_u8(vaeseq_u8(b3, kl), kf);

        vst1q_u8(out + 0, b0);
        vst1q_u8(out + 16, b1);
        vst1q_u8(out + 32, b2);
        vst1q_u8(out + 48, b3);

        in += 64; out += 64; nblocks -= 4;
    }

    while (nblocks--) {
        sdc_aes_armce_encrypt(key, in, out);
        in += 16; out += 16;
    }
}

#endif /* arm64 */
