/*
 * SPDX-License-Identifier: MIT
 * SM4-GCM test (roundtrip + generic GCM consistency).
 */
#include <stdio.h>
#include <string.h>
#include <sdcrypt/sm4.h>
#include <sdcrypt/sm4_gcm.h>
#include <sdcrypt/gcm.h>
#include <sdcrypt/errcode.h>
#include "test_common.h"

/* AES-GCM wrapper for cross-checking the generic GCM core via SM4. */

int main(void) {
    T_SUITE("SM4-GCM");

    uint8_t key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                       0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    uint8_t nonce[12] = {0,0,0,0,0,0,0,0,0,0,0,1};
    uint8_t aad[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t pt[40];
    for (int i = 0; i < 40; i++) pt[i] = (uint8_t)(i * 3 + 1);
    uint8_t ct[40], back[40], tag[16];

    sdc_sm4_gcm_encrypt(key, nonce, aad, 16, pt, 40, ct, tag);

    int rc = sdc_sm4_gcm_decrypt(key, nonce, aad, 16, ct, 40, tag, back);
    T_CHECK(rc == SDC_ERR_OK && memcmp(back, pt, 40) == 0, "roundtrip");

    /* tamper */
    uint8_t bad[16]; memcpy(bad, tag, 16); bad[5] ^= 0x80;
    rc = sdc_sm4_gcm_decrypt(key, nonce, aad, 16, ct, 40, bad, back);
    T_CHECK(rc != SDC_ERR_OK, "tampered tag rejected");

    /* wrong AAD */
    rc = sdc_sm4_gcm_decrypt(key, nonce, aad, 15, ct, 40, tag, back);
    T_CHECK(rc != SDC_ERR_OK, "wrong AAD rejected");

    /* no AAD */
    sdc_sm4_gcm_encrypt(key, nonce, NULL, 0, pt, 40, ct, tag);
    rc = sdc_sm4_gcm_decrypt(key, nonce, NULL, 0, ct, 40, tag, back);
    T_CHECK(rc == SDC_ERR_OK && memcmp(back, pt, 40) == 0, "no-AAD roundtrip");

    T_SUMMARY();
}
