/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Ed25519 signature (RFC 8032).
 * Ported from orlp/ed25519 (https://github.com/orlp/ed25519).
 */

#include <string.h>
#include <sdcrypt/config.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/ed25519.h>
#include <sdcrypt/rng.h>
#include <sdcrypt/sha.h>
#include <sdcrypt/utils.h>

#if SDC_ENABLE_ED25519

#if !SDC_ENABLE_SHA512
#  error "Ed25519 requires SHA-512 (set SDC_ENABLE_SHA512 to 1)"
#endif

#include "ge.h"
#include "sc.h"
#include "fe.h"

static void ed25519_sha512(uint8_t out[64], const uint8_t *in, size_t len) {
    sdc_sha512_hash(out, in, len);
}

/* ---------- key pair ---------- */

void sdc_ed25519_keypair(uint8_t public_key[32], uint8_t private_key[64],
                         const uint8_t seed[32]) {
    ge_p3 A;

    ed25519_sha512(private_key, seed, 32);
    private_key[0] &= 248;
    private_key[31] &= 63;
    private_key[31] |= 64;

    ge_scalarmult_base(&A, private_key);
    ge_p3_tobytes(public_key, &A);
}

int sdc_ed25519_keypair_random(uint8_t public_key[32], uint8_t private_key[64],
                               sdc_rng_ctx *rng_ctx) {
    uint8_t seed[32];
    int ret;

    if (!public_key || !private_key || !rng_ctx) {
        return SDC_ERR_INVALID_PARAM;
    }

    ret = sdc_rng_generate(rng_ctx, seed, sizeof(seed));
    if (ret != SDC_ERR_OK) {
        return ret;
    }

    sdc_ed25519_keypair(public_key, private_key, seed);
    sdc_secure_memzero(seed, sizeof(seed));
    return SDC_ERR_OK;
}

/* ---------- sign ---------- */

void sdc_ed25519_sign(uint8_t signature[64], const uint8_t *message, size_t message_len,
                      const uint8_t public_key[32], const uint8_t private_key[64]) {
    sdc_sha512_ctx hash;
    uint8_t hram[64];
    uint8_t r[64];
    ge_p3 R;

    /* r = SHA512(private_key[32..64] || message) */
    sdc_sha512_init(&hash);
    sdc_sha512_update(&hash, private_key + 32, 32);
    sdc_sha512_update(&hash, message, message_len);
    sdc_sha512_final(&hash, r);

    sc_reduce(r);
    ge_scalarmult_base(&R, r);
    ge_p3_tobytes(signature, &R);

    /* hram = SHA512(R || public_key || message) */
    sdc_sha512_init(&hash);
    sdc_sha512_update(&hash, signature, 32);
    sdc_sha512_update(&hash, public_key, 32);
    sdc_sha512_update(&hash, message, message_len);
    sdc_sha512_final(&hash, hram);

    sc_reduce(hram);
    sc_muladd(signature + 32, hram, private_key, r);
}

/* ---------- verify ---------- */

int sdc_ed25519_verify(const uint8_t signature[64], const uint8_t *message, size_t message_len,
                       const uint8_t public_key[32]) {
    uint8_t h[64];
    uint8_t checker[32];
    sdc_sha512_ctx hash;
    ge_p3 A;
    ge_p2 R;

    if (signature[63] & 224) {
        return SDC_ERR_SIGNATURE_INVALID;
    }

    if (ge_frombytes_negate_vartime(&A, public_key) != 0) {
        return SDC_ERR_SIGNATURE_INVALID;
    }

    sdc_sha512_init(&hash);
    sdc_sha512_update(&hash, signature, 32);
    sdc_sha512_update(&hash, public_key, 32);
    sdc_sha512_update(&hash, message, message_len);
    sdc_sha512_final(&hash, h);

    sc_reduce(h);
    ge_double_scalarmult_vartime(&R, h, &A, signature + 32);
    ge_tobytes(checker, &R);

    if (sdc_secure_memcmp(checker, signature, 32) != 0) {
        return SDC_ERR_SIGNATURE_INVALID;
    }

    return SDC_ERR_OK;
}

#endif /* SDC_ENABLE_ED25519 */
