/*
 * SPDX-License-Identifier: MIT
 * AES test (FIPS-197 + NIST SP 800-38A vectors).
 */
#include <stdio.h>
#include <string.h>
#include <sdcrypt/aes.h>
#include "test_common.h"

/* Which backend is active? */
static void test_backend(void) {
    uint8_t key[16] = {0};
    sdc_aes_key k;
    sdc_aes_set_encrypt_key(&k, key, 16);
    const char *name = (k.impl == SDC_AES_IMPL_AESNI) ? "AES-NI"
                     : (k.impl == SDC_AES_IMPL_ARMCE) ? "ARM-CE"
                     : "scalar";
    printf("  [INFO] AES backend: %s\n", name);
    T_CHECK(1, "backend selected");
}

/* FIPS-197 Appendix C.1: AES-128 */
static void test_fips197_aes128(void) {
    uint8_t key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                       0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t pt[16]  = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                       0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    uint8_t exp[16] = {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
                       0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
    uint8_t ct[16], dec[16];
    sdc_aes_key k;
    sdc_aes_set_encrypt_key(&k, key, 16);
    sdc_aes_encrypt_block(&k, pt, ct);
    T_CHECK_MEM(ct, exp, 16, "FIPS-197 C.1 AES-128 encrypt");
    sdc_aes_set_decrypt_key(&k, key, 16);
    sdc_aes_decrypt_block(&k, ct, dec);
    T_CHECK_MEM(dec, pt, 16, "FIPS-197 C.1 AES-128 decrypt");
}

/* FIPS-197 Appendix C.2: AES-192 */
static void test_fips197_aes192(void) {
    uint8_t key[24] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                       0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
                       0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17};
    uint8_t pt[16]  = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                       0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    uint8_t exp[16] = {0xdd,0xa9,0x7c,0xa4,0x86,0x4c,0xdf,0xe0,
                       0x6e,0xaf,0x70,0xa0,0xec,0x0d,0x71,0x91};
    uint8_t ct[16];
    sdc_aes_key k;
    sdc_aes_set_encrypt_key(&k, key, 24);
    sdc_aes_encrypt_block(&k, pt, ct);
    T_CHECK_MEM(ct, exp, 16, "FIPS-197 C.2 AES-192 encrypt");
}

/* FIPS-197 Appendix C.3: AES-256 */
static void test_fips197_aes256(void) {
    uint8_t key[32] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                       0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
                       0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                       0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
    uint8_t pt[16]  = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                       0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    uint8_t exp[16] = {0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,
                       0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89};
    uint8_t ct[16], dec[16];
    sdc_aes_key k;
    sdc_aes_set_encrypt_key(&k, key, 32);
    sdc_aes_encrypt_block(&k, pt, ct);
    T_CHECK_MEM(ct, exp, 16, "FIPS-197 C.3 AES-256 encrypt");
    sdc_aes_set_decrypt_key(&k, key, 32);
    sdc_aes_decrypt_block(&k, ct, dec);
    T_CHECK_MEM(dec, pt, 16, "FIPS-197 C.3 AES-256 decrypt");
}

/* CTR: roundtrip + keystream vs ECB(nonce||counter) */
static void test_ctr(void) {
    uint8_t key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                       0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    uint8_t nonce[12] = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
                         0xf8,0xf9,0xfa,0xfb};
    uint8_t pt[32], ct[32], back[32], ks[32];
    for (int i = 0; i < 32; i++) pt[i] = (uint8_t)(0x6b + i * 7);

    sdc_aes_key k;
    sdc_aes_set_encrypt_key(&k, key, 16);
    sdc_aes_ctr(&k, nonce, pt, 32, ct);

    /* keystream from ECB(nonce || counter_be32) */
    for (int blk = 0; blk < 2; blk++) {
        uint8_t ctrblk[16];
        memcpy(ctrblk, nonce, 12);
        ctrblk[12] = 0; ctrblk[13] = 0; ctrblk[14] = 0; ctrblk[15] = (uint8_t)blk;
        sdc_aes_encrypt_block(&k, ctrblk, ks + 16*blk);
    }
    for (int i = 0; i < 32; i++) {
        if ((uint8_t)(pt[i] ^ ks[i]) != ct[i]) {
            T_CHECK(0, "CTR keystream matches ECB(nonce||counter)");
            return;
        }
    }
    T_CHECK(1, "CTR keystream matches ECB(nonce||counter)");

    sdc_aes_ctr(&k, nonce, ct, 32, back);
    T_CHECK_MEM(back, pt, 32, "CTR roundtrip");
}

int main(void) {
    T_SUITE("AES");
    test_backend();
    test_fips197_aes128();
    test_fips197_aes192();
    test_fips197_aes256();
    test_ctr();
    T_SUMMARY();
}
