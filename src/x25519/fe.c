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

#include "fe.h"

#define MASK51 0x7FFFFFFFFFFFF
typedef unsigned __int128 u128;

void fe_0(fe h) {
    h[0] = 0;
    h[1] = 0;
    h[2] = 0;
    h[3] = 0;
    h[4] = 0;
}

void fe_1(fe h) {
    h[0] = 1;
    h[1] = 0;
    h[2] = 0;
    h[3] = 0;
    h[4] = 0;
}

void fe_copy(fe h, const fe f) {
    h[0] = f[0];
    h[1] = f[1];
    h[2] = f[2];
    h[3] = f[3];
    h[4] = f[4];
}

void fe_cswap(fe f, fe g, unsigned ctl) {
    int i;
    uint64_t mask, x;
    mask = 0 - (uint64_t)ctl;
    for (i = 0; i < 5; i++) {
        x = (f[i] ^ g[i]) & mask;
        f[i] ^= x;
        g[i] ^= x;
    }
}

void fe_add(fe h, const fe f, const fe g) {
    h[0] = f[0] + g[0];
    h[1] = f[1] + g[1];
    h[2] = f[2] + g[2];
    h[3] = f[3] + g[3];
    h[4] = f[4] + g[4];
}

void fe_sub(fe h, const fe f, const fe g) {
    uint64_t h0, h1, h2, h3, h4;

    h0 = g[0];
    h1 = g[1];
    h2 = g[2];
    h3 = g[3];
    h4 = g[4];

    h1 += h0 >> 51; h0 &= MASK51;
    h2 += h1 >> 51; h1 &= MASK51;
    h3 += h2 >> 51; h2 &= MASK51;
    h4 += h3 >> 51; h3 &= MASK51;
    h0 += (h4 >> 51) * 19; h4 &= MASK51;
    h1 += h0 >> 51; h0 &= MASK51;

    h0 = (f[0] + 0xFFFFFFFFFFFDA) - h0;
    h1 = (f[1] + 0xFFFFFFFFFFFFE) - h1;
    h2 = (f[2] + 0xFFFFFFFFFFFFE) - h2;
    h3 = (f[3] + 0xFFFFFFFFFFFFE) - h3;
    h4 = (f[4] + 0xFFFFFFFFFFFFE) - h4;

    h[0] = h0;
    h[1] = h1;
    h[2] = h2;
    h[3] = h3;
    h[4] = h4;
}

void fe_mul(fe h, const fe f, const fe g) {
    u128 h0, h1, h2, h3, h4, h5, h6, h7, h8;
    
    h0 = (u128)f[0] * g[0];
    h1 = (u128)f[0] * g[1] + (u128)f[1] * g[0];
    h2 = (u128)f[0] * g[2] + (u128)f[1] * g[1] + (u128)f[2] * g[0];
    h3 = (u128)f[0] * g[3] + (u128)f[1] * g[2] + (u128)f[2] * g[1] + (u128)f[3] * g[0];
    h4 = (u128)f[0] * g[4] + (u128)f[1] * g[3] + (u128)f[2] * g[2] + (u128)f[3] * g[1] + (u128)f[4] * g[0];
    h5 = (u128)f[1] * g[4] + (u128)f[2] * g[3] + (u128)f[3] * g[2] + (u128)f[4] * g[1];
    h6 = (u128)f[2] * g[4] + (u128)f[3] * g[3] + (u128)f[4] * g[2];
    h7 = (u128)f[3] * g[4] + (u128)f[4] * g[3];
    h8 = (u128)f[4] * g[4];

    h0 += h5 * 19;
    h1 += h6 * 19;
    h2 += h7 * 19;
    h3 += h8 * 19;
    
    h1 += h0 >> 51; h0 &= MASK51;
    h2 += h1 >> 51; h1 &= MASK51;
    h3 += h2 >> 51; h2 &= MASK51;
    h4 += h3 >> 51; h3 &= MASK51;
    h0 += (h4 >> 51) * 19; h4 &= MASK51;
    h1 += h0 >> 51; h0 &= MASK51;
    h2 += h1 >> 51; h1 &= MASK51;
    
    h[0] = (uint64_t)h0;
    h[1] = (uint64_t)h1;
    h[2] = (uint64_t)h2;
    h[3] = (uint64_t)h3;
    h[4] = (uint64_t)h4;
}

void fe_sq(fe h, const fe f) {
    u128 h0, h1, h2, h3, h4, h5, h6, h7, h8;
    
    h0 = (u128)f[0] * f[0];
    h1 = 2 * (u128)f[0] * f[1];
    h2 = 2 * (u128)f[0] * f[2] + (u128)f[1] * f[1];
    h3 = 2 * ((u128)f[0] * f[3] + (u128)f[1] * f[2]);
    h4 = (u128)f[2] * f[2] + 2 * ((u128)f[0] * f[4] + (u128)f[1] * f[3]);
    h5 = 2 * ((u128)f[1] * f[4] + (u128)f[2] * f[3]);
    h6 = (u128)f[3] * f[3] + 2 * (u128)f[2] * f[4];
    h7 = 2 * (u128)f[3] * f[4];
    h8 = (u128)f[4] * f[4];
    
    h0 += h5 * 19;
    h1 += h6 * 19;
    h2 += h7 * 19;
    h3 += h8 * 19;
    
    h1 += h0 >> 51; h0 &= MASK51;
    h2 += h1 >> 51; h1 &= MASK51;
    h3 += h2 >> 51; h2 &= MASK51;
    h4 += h3 >> 51; h3 &= MASK51;
    h0 += (h4 >> 51) * 19; h4 &= MASK51;
    h1 += h0 >> 51; h0 &= MASK51;
    h2 += h1 >> 51; h1 &= MASK51;
    
    h[0] = (uint64_t)h0;
    h[1] = (uint64_t)h1;
    h[2] = (uint64_t)h2;
    h[3] = (uint64_t)h3;
    h[4] = (uint64_t)h4;
}

void fe_mul121666(fe h, const fe f) {
    u128 h0, h1, h2, h3, h4;
    uint64_t c;
    
    h0 = (u128)f[0] * 121666;
    h1 = (u128)f[1] * 121666;
    h2 = (u128)f[2] * 121666;
    h3 = (u128)f[3] * 121666;
    h4 = (u128)f[4] * 121666;
    
    c = h0 >> 51; h[0] = h0 & MASK51; h1 += c;
    c = h1 >> 51; h[1] = h1 & MASK51; h2 += c;
    c = h2 >> 51; h[2] = h2 & MASK51; h3 += c;
    c = h3 >> 51; h[3] = h3 & MASK51; h4 += c;
    c = h4 >> 51; h[4] = h4 & MASK51; h[0] += c * 19;
    c = h[0] >> 51; h[0] &= MASK51; h[1] += c;
    c = h[1] >> 51; h[1] &= MASK51; h[2] += c;
}

void fe_frombytes(fe h, const uint8_t in[32]) {
    uint64_t t0, t1, t2, t3, t4;
    
    t0  = (uint64_t)in[0];
    t0 |= (uint64_t)in[1] << 8;
    t0 |= (uint64_t)in[2] << 16;
    t0 |= (uint64_t)in[3] << 24;
    t0 |= (uint64_t)in[4] << 32;
    t0 |= (uint64_t)in[5] << 40;
    t0 |= (uint64_t)(in[6] & 0x07) << 48;
    
    t1  = (uint64_t)(in[6] >> 3);
    t1 |= (uint64_t)in[7] << 5;
    t1 |= (uint64_t)in[8] << 13;
    t1 |= (uint64_t)in[9] << 21;
    t1 |= (uint64_t)in[10] << 29;
    t1 |= (uint64_t)in[11] << 37;
    t1 |= (uint64_t)(in[12] & 0x3F) << 45;
    
    t2  = (uint64_t)(in[12] >> 6);
    t2 |= (uint64_t)in[13] << 2;
    t2 |= (uint64_t)in[14] << 10;
    t2 |= (uint64_t)in[15] << 18;
    t2 |= (uint64_t)in[16] << 26;
    t2 |= (uint64_t)in[17] << 34;
    t2 |= (uint64_t)in[18] << 42;
    t2 |= (uint64_t)(in[19] & 0x01) << 50;
    
    t3  = (uint64_t)(in[19] >> 1);
    t3 |= (uint64_t)in[20] << 7;
    t3 |= (uint64_t)in[21] << 15;
    t3 |= (uint64_t)in[22] << 23;
    t3 |= (uint64_t)in[23] << 31;
    t3 |= (uint64_t)in[24] << 39;
    t3 |= (uint64_t)(in[25] & 0x0F) << 47;
    
    t4  = (uint64_t)(in[25] >> 4);
    t4 |= (uint64_t)in[26] << 4;
    t4 |= (uint64_t)in[27] << 12;
    t4 |= (uint64_t)in[28] << 20;
    t4 |= (uint64_t)in[29] << 28;
    t4 |= (uint64_t)in[30] << 36;
    t4 |= (uint64_t)(in[31] & 0x7F) << 44;
    
    h[0] = t0;
    h[1] = t1;
    h[2] = t2;
    h[3] = t3;
    h[4] = t4;
}

void fe_tobytes(uint8_t s[32], const fe h) {
    uint64_t h0 = h[0];
    uint64_t h1 = h[1];
    uint64_t h2 = h[2];
    uint64_t h3 = h[3];
    uint64_t h4 = h[4];
    uint64_t q;

    /* compare to modulus */
    q = (h0 + 19) >> 51;
    q = (h1 + q) >> 51;
    q = (h2 + q) >> 51;
    q = (h3 + q) >> 51;
    q = (h4 + q) >> 51;

    /* full reduce */
    h0 += 19 * q;
    h1 += h0 >> 51;
    h0 &= MASK51;
    h2 += h1 >> 51;
    h1 &= MASK51;
    h3 += h2 >> 51;
    h2 &= MASK51;
    h4 += h3 >> 51;
    h3 &= MASK51;
    h4 &= MASK51;

    /* smash */
    s[0] = (uint8_t)(h0 >> 0);
    s[1] = (uint8_t)(h0 >> 8);
    s[2] = (uint8_t)(h0 >> 16);
    s[3] = (uint8_t)(h0 >> 24);
    s[4] = (uint8_t)(h0 >> 32);
    s[5] = (uint8_t)(h0 >> 40);
    s[6] = (uint8_t)((h0 >> 48) | ((uint32_t)h1 << 3));
    s[7] = (uint8_t)(h1 >> 5);
    s[8] = (uint8_t)(h1 >> 13);
    s[9] = (uint8_t)(h1 >> 21);
    s[10] = (uint8_t)(h1 >> 29);
    s[11] = (uint8_t)(h1 >> 37);
    s[12] = (uint8_t)((h1 >> 45) | ((uint32_t)h2 << 6));
    s[13] = (uint8_t)(h2 >> 2);
    s[14] = (uint8_t)(h2 >> 10);
    s[15] = (uint8_t)(h2 >> 18);
    s[16] = (uint8_t)(h2 >> 26);
    s[17] = (uint8_t)(h2 >> 34);
    s[18] = (uint8_t)(h2 >> 42);
    s[19] = (uint8_t)((h2 >> 50) | ((uint32_t)h3 << 1));
    s[20] = (uint8_t)(h3 >> 7);
    s[21] = (uint8_t)(h3 >> 15);
    s[22] = (uint8_t)(h3 >> 23);
    s[23] = (uint8_t)(h3 >> 31);
    s[24] = (uint8_t)(h3 >> 39);
    s[25] = (uint8_t)((h3 >> 47) | ((uint32_t)h4 << 4));
    s[26] = (uint8_t)(h4 >> 4);
    s[27] = (uint8_t)(h4 >> 12);
    s[28] = (uint8_t)(h4 >> 20);
    s[29] = (uint8_t)(h4 >> 28);
    s[30] = (uint8_t)(h4 >> 36);
    s[31] = (uint8_t)(h4 >> 44);
}

void fe_invert(fe out, const fe z) {
    fe t0, t1, t2, t3;
    int i;
    
    /* 2^1 - 2^0 = 1 */
    fe_sq(t0, z);
    fe_sq(t1, t0);
    fe_sq(t1, t1);
    fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    
    /* 2^2 - 2^0 = 3 */
    fe_sq(t2, t0);
    fe_mul(t1, t1, t2);
    fe_sq(t2, t1);
    for (i = 1; i < 5; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    
    /* 2^5 - 2^0 = 31 */
    fe_sq(t2, t1);
    for (i = 1; i < 10; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    
    /* 2^10 - 2^0 = 1023 */
    fe_sq(t3, t2);
    for (i = 1; i < 20; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    
    /* 2^20 - 2^0 = 1048575 */
    fe_sq(t2, t2);
    for (i = 1; i < 10; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    
    /* 2^30 - 2^10 */
    fe_sq(t2, t1);
    for (i = 1; i < 50; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    
    /* 2^50 - 2^0 */
    fe_sq(t3, t2);
    for (i = 1; i < 100; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    
    /* 2^100 - 2^0 */
    fe_sq(t2, t2);
    for (i = 1; i < 50; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);

    /* 2^250 - 2^0 */
    fe_sq(t1, t1);
    for (i = 1; i < 5; i++) fe_sq(t1, t1);
    fe_mul(out, t1, t0);
}