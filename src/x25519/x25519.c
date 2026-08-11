/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2008-2017 Daniel J. Bernstein <djb@cr.yp.to>
 *
 * This file is a direct port of the ref10 implementation of Curve25519
 * by Daniel J. Bernstein.
 * Original source: https://cr.yp.to/ecdh.html
 *
 * Ported to slim-data-crypt by crazy2266.
 */

#include "x25519.h"
#include "fe.h"
#include "random.h"
#include "utils.h"
#include "config.h"

#if SDC_ENABLE_X25519

static void sdc_x25519_scalarmult(uint8_t out[32], const uint8_t scalar[32],
        const uint8_t point[32]) 
{
    fe x1, x2, z2, x3, z3, tmp0, tmp1;
    uint8_t t[32];
    unsigned swap, bit;
    int pos;

    swap = 0;
    memcpy(t, scalar, 32);
    t[0] &= 0xf8;
    t[31] &= 0x7f;
    t[31] |= 0x40;
    fe_frombytes(x1, point);
    fe_1(x2);
    fe_0(z2);
    fe_copy(x3, x1);
    fe_1(z3);

    for (pos = 254; pos >= 0; --pos) {
        bit = (t[pos / 8] >> (pos & 7)) & 1;

        swap ^= bit;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = bit;
        fe_sub(tmp0, x3, z3);
        fe_sub(tmp1, x2, z2);
        fe_add(x2, x2, z2);
        fe_add(z2, x3, z3);
        fe_mul(z3, tmp0, x2);
        fe_mul(z2, z2, tmp1);
        fe_sq(tmp0, tmp1);
        fe_sq(tmp1, x2);
        fe_add(x3, z3, z2);
        fe_sub(z2, z3, z2);
        fe_mul(x2, tmp1, tmp0);
        fe_sub(tmp1, tmp1, tmp0);
        fe_sq(z2, z2);
        fe_mul121666(z3, tmp1);
        fe_sq(x3, x3);
        fe_add(tmp0, tmp0, z3);
        fe_mul(z3, x1, z2);
        fe_mul(z2, tmp1, tmp0);
    }

    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(out, x2);
    sdc_secure_memzero(t, sizeof(t));
}

int sdc_x25519_exchange(uint8_t shared[32], const uint8_t priv[32], const uint8_t pub[32]) {
    if (!shared || !priv || !pub) return -1;
    sdc_x25519_scalarmult(shared, priv, pub);
    return 0;
}

int sdc_x25519_keygen(uint8_t pub[32], uint8_t priv[32]) {
    if (!pub || !priv) return -1;
    int ret = sdc_random_bytes(priv, 32);
    if (ret != 0) return ret;
    // clamp 私钥
    priv[0] &= 0xf8;
    priv[31] &= 0x7f;
    priv[31] |= 0x40;
    
    static const uint8_t basepoint[32] = {9};
    sdc_x25519_scalarmult(pub, priv, basepoint);
    return 0;
}

#endif /* SDC_ENABLE_X25519 */
