/*
 * SPDX-License-Identifier: MIT
 * SM4 test (GB/T 32907-2016 vector).
 */
#include <stdio.h>
#include <string.h>
#include <sdcrypt/sm4.h>
#include "test_common.h"

int main(void) {
    T_SUITE("SM4");

    /* GB/T 32907-2016 标准向量 */
    uint8_t key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                       0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    uint8_t pt[16]  = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                       0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    uint8_t ct_exp[16] = {0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,
                          0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46};
    uint8_t ct[16], dec[16];

    sdc_sm4_key ek, dk;
    sdc_sm4_set_encrypt_key(&ek, key);
    sdc_sm4_encrypt_block(&ek, pt, ct);
    T_CHECK_MEM(ct, ct_exp, 16, "encrypt block (GB/T 32907 vector)");

    sdc_sm4_set_decrypt_key(&dk, key);
    sdc_sm4_decrypt_block(&dk, ct, dec);
    T_CHECK_MEM(dec, pt, 16, "decrypt block");

    /* 多块加密 */
    uint8_t in2[32], out2[32];
    memcpy(in2, pt, 16); memcpy(in2+16, pt, 16);
    sdc_sm4_encrypt_blocks(&ek, in2, 2, out2);
    T_CHECK_MEM(out2, ct_exp, 16, "encrypt_blocks block0");
    T_CHECK_MEM(out2+16, ct_exp, 16, "encrypt_blocks block1");

    /* CTR 往返 */
    uint8_t nonce[12] = {0};
    uint8_t msg[40], enc[40], back[40];
    for (int i = 0; i < 40; i++) msg[i] = (uint8_t)(i * 3 + 1);
    sdc_sm4_ctr(&ek, nonce, msg, 40, enc);
    sdc_sm4_ctr(&ek, nonce, enc, 40, back);
    T_CHECK_MEM(back, msg, 40, "CTR roundtrip");

    T_SUMMARY();
}
