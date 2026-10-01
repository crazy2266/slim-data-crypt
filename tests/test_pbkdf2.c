/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * PBKDF2-HMAC-SHA256 known-answer tests.
 * Vectors from RFC 7914 (scrypt test vectors use PBKDF2-HMAC-SHA256).
 */

#include <stdio.h>
#include <string.h>
#include <sdcrypt/pbkdf2.h>
#include <sdcrypt/config.h>
#include "test_common.h"

#if SDC_ENABLE_PBKDF2

/* Vector 1: P="passwd", S="salt", c=1, dkLen=64 */
static const uint8_t pw1[]   = "passwd";
static const uint8_t salt1[] = "salt";
static const uint8_t exp1[64] = {
    0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f,
    0xec, 0x16, 0x91, 0xc2, 0x25, 0x44, 0xb6, 0x05,
    0xf9, 0x41, 0x85, 0x21, 0x6d, 0xde, 0x04, 0x65,
    0xe6, 0x8b, 0x9d, 0x57, 0xc2, 0x0d, 0xac, 0xbc,
    0x49, 0xca, 0x9c, 0xcc, 0xf1, 0x79, 0xb6, 0x45,
    0x99, 0x16, 0x64, 0xb3, 0x9d, 0x77, 0xef, 0x31,
    0x7c, 0x71, 0xb8, 0x45, 0xb1, 0xe3, 0x0b, 0xd5,
    0x09, 0x11, 0x20, 0x41, 0xd3, 0xa1, 0x97, 0x83
};

/* Vector 2: P="Password", S="NaCl", c=80000, dkLen=64 */
static const uint8_t pw2[]   = "Password";
static const uint8_t salt2[] = "NaCl";
static const uint8_t exp2[64] = {
    0x4d, 0xdc, 0xd8, 0xf6, 0x0b, 0x98, 0xbe, 0x21,
    0x83, 0x0c, 0xee, 0x5e, 0xf2, 0x27, 0x01, 0xf9,
    0x64, 0x1a, 0x44, 0x18, 0xd0, 0x4c, 0x04, 0x14,
    0xae, 0xff, 0x08, 0x87, 0x6b, 0x34, 0xab, 0x56,
    0xa1, 0xd4, 0x25, 0xa1, 0x22, 0x58, 0x33, 0x54,
    0x9a, 0xdb, 0x84, 0x1b, 0x51, 0xc9, 0xb3, 0x17,
    0x6a, 0x27, 0x2b, 0xde, 0xbb, 0xa1, 0xd0, 0x78,
    0x47, 0x8f, 0x62, 0xb3, 0x97, 0xf3, 0x3c, 0x8d
};

int main(void) {
    T_SUITE("PBKDF2-HMAC-SHA256 Known-Answer Tests");

    uint8_t out[64];

    T_SECTION("RFC 7914 vector 1 (passwd/salt/c=1/dkLen=64)");
    memset(out, 0, sizeof(out));
    sdc_kdf_pbkdf2_sha256(out, sizeof(out),
                          pw1, sizeof(pw1) - 1,
                          salt1, sizeof(salt1) - 1, 1);
    t_print_hex("expected", exp1, sizeof(exp1));
    t_print_hex("computed", out, sizeof(out));
    T_CHECK_MEM(out, exp1, sizeof(exp1), "vector 1 matches RFC 7914");

    T_SECTION("RFC 7914 vector 2 (Password/NaCl/c=80000/dkLen=64)");
    memset(out, 0, sizeof(out));
    sdc_kdf_pbkdf2_sha256(out, sizeof(out),
                          pw2, sizeof(pw2) - 1,
                          salt2, sizeof(salt2) - 1, 80000);
    t_print_hex("expected", exp2, sizeof(exp2));
    t_print_hex("computed", out, sizeof(out));
    T_CHECK_MEM(out, exp2, sizeof(exp2), "vector 2 matches RFC 7914");

    T_SUMMARY();
}

#else

int main(void) {
    printf("[SKIP] PBKDF2 disabled in config.h\n");
    return 0;
}

#endif /* SDC_ENABLE_PBKDF2 */
