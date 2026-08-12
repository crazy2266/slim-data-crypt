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
#include "config.h"

#if SDC_ENABLE_X25519 && SDC_32BIT

void fe_0(fe h) {
    memset(h, 0, sizeof(h));
}

void fe_1(fe h) {
    memset(h, 0, sizeof(h));
    h[0] = 1;
}

void fe_copy(fe h, const fe f) {
    memcpy(h, f, sizeof(h));
}




#endif /* SDC_ENABLE_X25519 && SDC_32BIT */
