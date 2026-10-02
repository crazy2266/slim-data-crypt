/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * AES-NI backend (x86).
 *
 * The AES-NI intrinsics are gated with __attribute__((target("aes"))) so the
 * rest of the library can keep a portable baseline; these functions are only
 * reached after a runtime CPU check (sdc_cpu_get()->aes).
 */

#include <sdcrypt/config.h>

#if SDC_ENABLE_AES && (defined(__x86_64__) || defined(__i386__)) \
    && (defined(__GNUC__) || defined(__clang__))

#include <string.h>
#include <wmmintrin.h>
#include <emmintrin.h>
#include <sdcrypt/aes.h>
#include "aes_backend.h"

#define AESNI_TARGET __attribute__((target("aes")))

/* Round-key layout is identical to the portable one. */
void sdc_aes_aesni_set_key(sdc_aes_key *key) {
    memcpy(key->be, key->rk, 16 * (key->nr + 1));
}

AESNI_TARGET
void sdc_aes_aesni_encrypt(const sdc_aes_key *key, const uint8_t in[16], uint8_t out[16]) {
    __m128i b = _mm_loadu_si128((const __m128i *)in);
    const uint8_t *rk = key->be;

    b = _mm_xor_si128(b, _mm_loadu_si128((const __m128i *)rk));
    for (int r = 1; r < key->nr; r++)
        b = _mm_aesenc_si128(b, _mm_loadu_si128((const __m128i *)(rk + 16 * r)));
    b = _mm_aesenclast_si128(b, _mm_loadu_si128((const __m128i *)(rk + 16 * key->nr)));

    _mm_storeu_si128((__m128i *)out, b);
}

AESNI_TARGET
void sdc_aes_aesni_decrypt(const sdc_aes_key *key, const uint8_t in[16], uint8_t out[16]) {
    __m128i b = _mm_loadu_si128((const __m128i *)in);
    const uint8_t *rk = key->be;

    b = _mm_xor_si128(b, _mm_loadu_si128((const __m128i *)(rk + 16 * key->nr)));
    for (int r = key->nr - 1; r >= 1; r--) {
        __m128i k = _mm_loadu_si128((const __m128i *)(rk + 16 * r));
        b = _mm_aesdec_si128(b, _mm_aesimc_si128(k));
    }
    b = _mm_aesdeclast_si128(b, _mm_loadu_si128((const __m128i *)rk));

    _mm_storeu_si128((__m128i *)out, b);
}

AESNI_TARGET
void sdc_aes_aesni_encrypt_blocks(const sdc_aes_key *key, const uint8_t *in, size_t nblocks, uint8_t *out) {
    const uint8_t *rk = key->be;
    const int nr = key->nr;

    while (nblocks >= 8) {
        __m128i b0 = _mm_loadu_si128((const __m128i *)(in + 0));
        __m128i b1 = _mm_loadu_si128((const __m128i *)(in + 16));
        __m128i b2 = _mm_loadu_si128((const __m128i *)(in + 32));
        __m128i b3 = _mm_loadu_si128((const __m128i *)(in + 48));
        __m128i b4 = _mm_loadu_si128((const __m128i *)(in + 64));
        __m128i b5 = _mm_loadu_si128((const __m128i *)(in + 80));
        __m128i b6 = _mm_loadu_si128((const __m128i *)(in + 96));
        __m128i b7 = _mm_loadu_si128((const __m128i *)(in + 112));

        __m128i k0 = _mm_loadu_si128((const __m128i *)rk);
        b0 = _mm_xor_si128(b0, k0); b1 = _mm_xor_si128(b1, k0);
        b2 = _mm_xor_si128(b2, k0); b3 = _mm_xor_si128(b3, k0);
        b4 = _mm_xor_si128(b4, k0); b5 = _mm_xor_si128(b5, k0);
        b6 = _mm_xor_si128(b6, k0); b7 = _mm_xor_si128(b7, k0);

        for (int r = 1; r < nr; r++) {
            __m128i kr = _mm_loadu_si128((const __m128i *)(rk + 16 * r));
            b0 = _mm_aesenc_si128(b0, kr); b1 = _mm_aesenc_si128(b1, kr);
            b2 = _mm_aesenc_si128(b2, kr); b3 = _mm_aesenc_si128(b3, kr);
            b4 = _mm_aesenc_si128(b4, kr); b5 = _mm_aesenc_si128(b5, kr);
            b6 = _mm_aesenc_si128(b6, kr); b7 = _mm_aesenc_si128(b7, kr);
        }
        __m128i kl = _mm_loadu_si128((const __m128i *)(rk + 16 * nr));
        b0 = _mm_aesenclast_si128(b0, kl); b1 = _mm_aesenclast_si128(b1, kl);
        b2 = _mm_aesenclast_si128(b2, kl); b3 = _mm_aesenclast_si128(b3, kl);
        b4 = _mm_aesenclast_si128(b4, kl); b5 = _mm_aesenclast_si128(b5, kl);
        b6 = _mm_aesenclast_si128(b6, kl); b7 = _mm_aesenclast_si128(b7, kl);

        _mm_storeu_si128((__m128i *)(out + 0), b0);
        _mm_storeu_si128((__m128i *)(out + 16), b1);
        _mm_storeu_si128((__m128i *)(out + 32), b2);
        _mm_storeu_si128((__m128i *)(out + 48), b3);
        _mm_storeu_si128((__m128i *)(out + 64), b4);
        _mm_storeu_si128((__m128i *)(out + 80), b5);
        _mm_storeu_si128((__m128i *)(out + 96), b6);
        _mm_storeu_si128((__m128i *)(out + 112), b7);

        in += 128; out += 128; nblocks -= 8;
    }

    while (nblocks--) {
        sdc_aes_aesni_encrypt(key, in, out);
        in += 16; out += 16;
    }
}

#endif /* x86 + AES-NI */
