/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * GHASH using x86 PCLMULQDQ.
 *
 * Representation: after loading, each 16-byte block is byte-reversed with
 * _mm_shuffle_epi8 (BSWAP).  The whole computation then runs in that order;
 * the extra 1-bit shift implied by the bit-reversal is folded into the
 * reduction step.  8-block aggregation with precomputed H^1..H^8.
 */

#include <sdcrypt/config.h>

#if SDC_ENABLE_GCM && (defined(__x86_64__) || defined(__i386__)) \
    && (defined(__GNUC__) || defined(__clang__))

#include <string.h>
#include <immintrin.h>
#include <wmmintrin.h>
#include "ghash_impl.h"

#define SDC_PCLMUL_TARGET __attribute__((target("pclmul,ssse3")))

/* Byte-reversal shuffle mask: byte 0 <-> 15, 1 <-> 14, ... */
#define BSWAP_IDX _mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15)

typedef struct {
    __m128i H;
    __m128i H2, H3, H4, H5, H6, H7, H8;
    __m128i Hx, H2x, H3x, H4x, H5x, H6x, H7x, H8x;
    __m128i state;
    uint8_t buf[128];
    size_t buf_len;
    uint64_t aad_len;
    uint64_t data_len;
    int phase;   /* 0 = AAD, 1 = data */
} ghash_x86_ctx;

_Static_assert(sizeof(ghash_x86_ctx) <= SDC_GHASH_CTX_BYTES,
               "ghash_x86_ctx does not fit in sdc_ghash_ctx");

/* Reduce a 256-bit carry-less product (t0..t3, t3 most significant) to 128 bits. */
SDC_PCLMUL_TARGET
static inline __m128i gf128_reduce(__m128i t0, __m128i t1, __m128i t2, __m128i t3) {
    t0 = _mm_or_si128(_mm_slli_epi64(t0, 1), _mm_srli_epi64(t1, 63));
    t1 = _mm_or_si128(_mm_slli_epi64(t1, 1), _mm_srli_epi64(t2, 63));
    t2 = _mm_or_si128(_mm_slli_epi64(t2, 1), _mm_srli_epi64(t3, 63));
    t3 = _mm_slli_epi64(t3, 1);

    t1 = _mm_xor_si128(t1, _mm_xor_si128(
        _mm_xor_si128(t3, _mm_srli_epi64(t3, 1)),
        _mm_xor_si128(_mm_srli_epi64(t3, 2), _mm_srli_epi64(t3, 7))));
    t2 = _mm_xor_si128(
        _mm_xor_si128(t2, _mm_slli_epi64(t3, 63)),
        _mm_xor_si128(_mm_slli_epi64(t3, 62), _mm_slli_epi64(t3, 57)));
    t0 = _mm_xor_si128(t0, _mm_xor_si128(
        _mm_xor_si128(t2, _mm_srli_epi64(t2, 1)),
        _mm_xor_si128(_mm_srli_epi64(t2, 2), _mm_srli_epi64(t2, 7))));
    t1 = _mm_xor_si128(
        _mm_xor_si128(t1, _mm_slli_epi64(t2, 63)),
        _mm_xor_si128(_mm_slli_epi64(t2, 62), _mm_slli_epi64(t2, 57)));

    return _mm_unpacklo_epi64(t1, t0);
}

SDC_PCLMUL_TARGET
static inline __m128i gf128_mul(__m128i a, __m128i b) {
    __m128i ax = _mm_xor_si128(a, _mm_shuffle_epi32(a, 0x0E));
    __m128i bx = _mm_xor_si128(b, _mm_shuffle_epi32(b, 0x0E));

    __m128i t1 = _mm_clmulepi64_si128(a, b, 0x11);
    __m128i t3 = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i t2 = _mm_clmulepi64_si128(ax, bx, 0x00);
    t2 = _mm_xor_si128(t2, _mm_xor_si128(t1, t3));

    __m128i t0 = _mm_shuffle_epi32(t1, 0x0E);
    t1 = _mm_xor_si128(t1, _mm_shuffle_epi32(t2, 0x0E));
    t2 = _mm_xor_si128(t2, _mm_shuffle_epi32(t3, 0x0E));

    return gf128_reduce(t0, t1, t2, t3);
}

SDC_PCLMUL_TARGET
static void ghash_x86_precompute(ghash_x86_ctx *c) {
    __m128i H = c->H;
    c->H2 = gf128_mul(H, H);
    c->H3 = gf128_mul(H, c->H2);
    c->H4 = gf128_mul(H, c->H3);
    c->H5 = gf128_mul(H, c->H4);
    c->H6 = gf128_mul(H, c->H5);
    c->H7 = gf128_mul(H, c->H6);
    c->H8 = gf128_mul(H, c->H7);
#define HX(dst, src) dst = _mm_xor_si128(src, _mm_shuffle_epi32(src, 0x0E))
    HX(c->Hx, c->H); HX(c->H2x, c->H2); HX(c->H3x, c->H3); HX(c->H4x, c->H4);
    HX(c->H5x, c->H5); HX(c->H6x, c->H6); HX(c->H7x, c->H7); HX(c->H8x, c->H8);
#undef HX
}

SDC_PCLMUL_TARGET
static void ghash_x86_1block(ghash_x86_ctx *c, const uint8_t *blk) {
    __m128i d = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)blk), BSWAP_IDX);
    d = _mm_xor_si128(d, c->state);
    __m128i dx = _mm_xor_si128(d, _mm_shuffle_epi32(d, 0x0E));
    __m128i Hx = _mm_xor_si128(c->H, _mm_shuffle_epi32(c->H, 0x0E));

    __m128i t1 = _mm_clmulepi64_si128(d, c->H, 0x11);
    __m128i t3 = _mm_clmulepi64_si128(d, c->H, 0x00);
    __m128i t2 = _mm_clmulepi64_si128(dx, Hx, 0x00);
    t2 = _mm_xor_si128(t2, _mm_xor_si128(t1, t3));

    __m128i t0 = _mm_shuffle_epi32(t1, 0x0E);
    t1 = _mm_xor_si128(t1, _mm_shuffle_epi32(t2, 0x0E));
    t2 = _mm_xor_si128(t2, _mm_shuffle_epi32(t3, 0x0E));

    c->state = gf128_reduce(t0, t1, t2, t3);
}

SDC_PCLMUL_TARGET
static void ghash_x86_4blocks(ghash_x86_ctx *c, const uint8_t *data) {
    __m128i d0 = _mm_xor_si128(_mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(data)), BSWAP_IDX), c->state);
    __m128i d1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(data + 16)), BSWAP_IDX);
    __m128i d2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(data + 32)), BSWAP_IDX);
    __m128i d3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(data + 48)), BSWAP_IDX);
    __m128i d0x = _mm_xor_si128(d0, _mm_shuffle_epi32(d0, 0x0E));
    __m128i d1x = _mm_xor_si128(d1, _mm_shuffle_epi32(d1, 0x0E));
    __m128i d2x = _mm_xor_si128(d2, _mm_shuffle_epi32(d2, 0x0E));
    __m128i d3x = _mm_xor_si128(d3, _mm_shuffle_epi32(d3, 0x0E));

    __m128i t1 = _mm_xor_si128(
        _mm_xor_si128(_mm_clmulepi64_si128(d0, c->H4, 0x11), _mm_clmulepi64_si128(d1, c->H3, 0x11)),
        _mm_xor_si128(_mm_clmulepi64_si128(d2, c->H2, 0x11), _mm_clmulepi64_si128(d3, c->H,  0x11)));
    __m128i t3 = _mm_xor_si128(
        _mm_xor_si128(_mm_clmulepi64_si128(d0, c->H4, 0x00), _mm_clmulepi64_si128(d1, c->H3, 0x00)),
        _mm_xor_si128(_mm_clmulepi64_si128(d2, c->H2, 0x00), _mm_clmulepi64_si128(d3, c->H,  0x00)));
    __m128i t2 = _mm_xor_si128(
        _mm_xor_si128(_mm_clmulepi64_si128(d0x, c->H4x, 0x00), _mm_clmulepi64_si128(d1x, c->H3x, 0x00)),
        _mm_xor_si128(_mm_clmulepi64_si128(d2x, c->H2x, 0x00), _mm_clmulepi64_si128(d3x, c->Hx,  0x00)));
    t2 = _mm_xor_si128(t2, _mm_xor_si128(t1, t3));

    __m128i t0 = _mm_shuffle_epi32(t1, 0x0E);
    t1 = _mm_xor_si128(t1, _mm_shuffle_epi32(t2, 0x0E));
    t2 = _mm_xor_si128(t2, _mm_shuffle_epi32(t3, 0x0E));

    c->state = gf128_reduce(t0, t1, t2, t3);
}

SDC_PCLMUL_TARGET
static void ghash_x86_8blocks(ghash_x86_ctx *c, const uint8_t *data) {
    __m128i d0 = _mm_xor_si128(_mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(data)), BSWAP_IDX), c->state);
    __m128i d1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(data + 16)), BSWAP_IDX);
    __m128i d2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(data + 32)), BSWAP_IDX);
    __m128i d3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(data + 48)), BSWAP_IDX);
    __m128i d4 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(data + 64)), BSWAP_IDX);
    __m128i d5 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(data + 80)), BSWAP_IDX);
    __m128i d6 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(data + 96)), BSWAP_IDX);
    __m128i d7 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(data + 112)), BSWAP_IDX);
    __m128i d0x = _mm_xor_si128(d0, _mm_shuffle_epi32(d0, 0x0E));
    __m128i d1x = _mm_xor_si128(d1, _mm_shuffle_epi32(d1, 0x0E));
    __m128i d2x = _mm_xor_si128(d2, _mm_shuffle_epi32(d2, 0x0E));
    __m128i d3x = _mm_xor_si128(d3, _mm_shuffle_epi32(d3, 0x0E));
    __m128i d4x = _mm_xor_si128(d4, _mm_shuffle_epi32(d4, 0x0E));
    __m128i d5x = _mm_xor_si128(d5, _mm_shuffle_epi32(d5, 0x0E));
    __m128i d6x = _mm_xor_si128(d6, _mm_shuffle_epi32(d6, 0x0E));
    __m128i d7x = _mm_xor_si128(d7, _mm_shuffle_epi32(d7, 0x0E));

    __m128i t1 = _mm_xor_si128(
        _mm_xor_si128(
            _mm_xor_si128(_mm_clmulepi64_si128(d0, c->H8, 0x11), _mm_clmulepi64_si128(d1, c->H7, 0x11)),
            _mm_xor_si128(_mm_clmulepi64_si128(d2, c->H6, 0x11), _mm_clmulepi64_si128(d3, c->H5, 0x11))),
        _mm_xor_si128(
            _mm_xor_si128(_mm_clmulepi64_si128(d4, c->H4, 0x11), _mm_clmulepi64_si128(d5, c->H3, 0x11)),
            _mm_xor_si128(_mm_clmulepi64_si128(d6, c->H2, 0x11), _mm_clmulepi64_si128(d7, c->H,  0x11))));
    __m128i t3 = _mm_xor_si128(
        _mm_xor_si128(
            _mm_xor_si128(_mm_clmulepi64_si128(d0, c->H8, 0x00), _mm_clmulepi64_si128(d1, c->H7, 0x00)),
            _mm_xor_si128(_mm_clmulepi64_si128(d2, c->H6, 0x00), _mm_clmulepi64_si128(d3, c->H5, 0x00))),
        _mm_xor_si128(
            _mm_xor_si128(_mm_clmulepi64_si128(d4, c->H4, 0x00), _mm_clmulepi64_si128(d5, c->H3, 0x00)),
            _mm_xor_si128(_mm_clmulepi64_si128(d6, c->H2, 0x00), _mm_clmulepi64_si128(d7, c->H,  0x00))));
    __m128i t2 = _mm_xor_si128(
        _mm_xor_si128(
            _mm_xor_si128(_mm_clmulepi64_si128(d0x, c->H8x, 0x00), _mm_clmulepi64_si128(d1x, c->H7x, 0x00)),
            _mm_xor_si128(_mm_clmulepi64_si128(d2x, c->H6x, 0x00), _mm_clmulepi64_si128(d3x, c->H5x, 0x00))),
        _mm_xor_si128(
            _mm_xor_si128(_mm_clmulepi64_si128(d4x, c->H4x, 0x00), _mm_clmulepi64_si128(d5x, c->H3x, 0x00)),
            _mm_xor_si128(_mm_clmulepi64_si128(d6x, c->H2x, 0x00), _mm_clmulepi64_si128(d7x, c->Hx,  0x00))));
    t2 = _mm_xor_si128(t2, _mm_xor_si128(t1, t3));

    __m128i t0 = _mm_shuffle_epi32(t1, 0x0E);
    t1 = _mm_xor_si128(t1, _mm_shuffle_epi32(t2, 0x0E));
    t2 = _mm_xor_si128(t2, _mm_shuffle_epi32(t3, 0x0E));

    c->state = gf128_reduce(t0, t1, t2, t3);
}

SDC_PCLMUL_TARGET
static void ghash_x86_process(ghash_x86_ctx *c, const uint8_t *data, size_t len) {
    while (len >= 128) { ghash_x86_8blocks(c, data); data += 128; len -= 128; }
    while (len >= 64)  { ghash_x86_4blocks(c, data); data += 64;  len -= 64;  }
    while (len >= 16)  { ghash_x86_1block(c, data);  data += 16;  len -= 16;  }
    if (len > 0) {
        memcpy(c->buf + c->buf_len, data, len);
        c->buf_len += len;
    }
}

SDC_PCLMUL_TARGET
static void x86_init(void *ctx, const uint8_t H[16]) {
    ghash_x86_ctx *c = (ghash_x86_ctx *)ctx;
    memset(c, 0, sizeof(*c));
    c->H = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)H), BSWAP_IDX);
    c->state = _mm_setzero_si128();
    ghash_x86_precompute(c);
}

SDC_PCLMUL_TARGET
static void x86_aad(void *ctx, const uint8_t *aad, size_t len) {
    ghash_x86_ctx *c = (ghash_x86_ctx *)ctx;
    if (c->phase != 0 || len == 0) return;
    c->aad_len += (uint64_t)len * 8;
    ghash_x86_process(c, aad, len);
}

SDC_PCLMUL_TARGET
static void x86_update(void *ctx, const uint8_t *data, size_t len) {
    ghash_x86_ctx *c = (ghash_x86_ctx *)ctx;
    if (c->phase == 0) {
        /* zero-pad any partial AAD block */
        if (c->buf_len > 0) {
            size_t total = c->buf_len;
            size_t full = total & ~(size_t)15;
            if (full) ghash_x86_process(c, c->buf, full);
            size_t rem = total - full;
            if (rem > 0) {
                uint8_t blk[16] = {0};
                memcpy(blk, c->buf + full, rem);
                ghash_x86_1block(c, blk);
            }
            c->buf_len = 0;
        }
        c->phase = 1;
    }
    if (len == 0) return;
    c->data_len += (uint64_t)len * 8;
    if (c->buf_len > 0) {
        size_t need = 16 - c->buf_len;
        size_t want = (need < len) ? need : len;
        memcpy(c->buf + c->buf_len, data, want);
        c->buf_len += want;
        data += want; len -= want;
        if (c->buf_len == 16) {
            ghash_x86_1block(c, c->buf);
            c->buf_len = 0;
        }
    }
    ghash_x86_process(c, data, len);
}

SDC_PCLMUL_TARGET
static void x86_final(void *ctx, uint8_t out[16]) {
    ghash_x86_ctx *c = (ghash_x86_ctx *)ctx;
    if (c->phase == 0) { c->phase = 1; }

    if (c->buf_len > 0) {
        uint8_t blk[16] = {0};
        memcpy(blk, c->buf, c->buf_len);
        ghash_x86_1block(c, blk);
        c->buf_len = 0;
    }
    uint8_t lb[16] = {0};
    for (int i = 0; i < 8; i++) lb[i] = (uint8_t)(c->aad_len >> (56 - 8 * i));
    for (int i = 0; i < 8; i++) lb[8 + i] = (uint8_t)(c->data_len >> (56 - 8 * i));
    ghash_x86_1block(c, lb);

    __m128i t = _mm_shuffle_epi8(c->state, BSWAP_IDX);
    _mm_storeu_si128((__m128i *)out, t);
}

const sdc_ghash_vtable sdc_ghash_pclmul_vtable = {
    x86_init, x86_aad, x86_update, x86_final
};

#endif /* x86 + PCLMUL */
