/*
 * SPDX-License-Identifier: MIT
 * SM4 test (GB/T 32907-2016 vector).
 */
#include <stdio.h>
#include <string.h>
#include <sdcrypt/sm4.h>
#include <sdcrypt/block_cipher.h>
#include "test_common.h"

int main(void) {
    T_SUITE("SM4");

    /* GB/T 32907-2016 Standard Vector */
    uint8_t key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                       0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    uint8_t pt[16]  = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                       0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    uint8_t ct_exp[16] = {0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,
                          0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46};
    uint8_t ct[16], dec[16];

    /* Native (table-driven) API. */
    sdc_sm4_ctx ek, dk;
    sdc_sm4_set_encrypt_key(&ek, key);
    sdc_sm4_encrypt_block(&ek, pt, ct);
    T_CHECK_MEM(ct, ct_exp, 16, "encrypt block (GB/T 32907 vector)");

    sdc_sm4_set_decrypt_key(&dk, key);
    sdc_sm4_decrypt_block(&dk, ct, dec);
    T_CHECK_MEM(dec, pt, 16, "decrypt block");

    /* Multi-block encryption */
    uint8_t in2[32], out2[32];
    memcpy(in2, pt, 16); memcpy(in2+16, pt, 16);
    sdc_sm4_encrypt_blocks(&ek, in2, 2, out2);
    T_CHECK_MEM(out2, ct_exp, 16, "encrypt_blocks block0");
    T_CHECK_MEM(out2+16, ct_exp, 16, "encrypt_blocks block1");

    /* CTR roundtrip via the generic block-cipher layer. */
    uint8_t nonce[12] = {0};
    uint8_t msg[40], enc[40], back[40];
    for (int i = 0; i < 40; i++) msg[i] = (uint8_t)(i * 3 + 1);

    sdc_block_cipher_ctx bkey;
    sdc_block_cipher_init(&bkey, &sdc_sm4_table_ops);
    sdc_sm4_ctx *bk = (sdc_sm4_ctx *)bkey.inner_state;
    sdc_sm4_set_encrypt_key(bk, key);

    sdc_block_cipher_ctr(&bkey, nonce, msg, 40, enc);
    sdc_block_cipher_ctr(&bkey, nonce, enc, 40, back);
    T_CHECK_MEM(back, msg, 40, "CTR roundtrip");

#if SDC_ENABLE_SM4_CT
    {
        /* Constant-time backend through the ops layer. */
        sdc_block_cipher_ctx bct;
        sdc_block_cipher_init(&bct, &sdc_sm4_ct_ops);
        sdc_sm4_ctx *ctk = (sdc_sm4_ctx *)bct.inner_state;
        sdc_sm4_set_encrypt_key(ctk, key);

        int all_ok = 1;
        uint8_t inb[16] = {0}, a[16], b[16];
        for (int v = 0; v < 256; v++) {
            inb[0] = (uint8_t)v;
            sdc_sm4_encrypt_block(&ek, inb, a);
            bct.ops->encrypt_block(&bct, inb, b);
            if (memcmp(a, b, 16) != 0) { all_ok = 0; break; }
        }
        T_CHECK(all_ok, "constant-time backend matches table-driven (256 inputs)");

        int ks_ok = 1;
        uint8_t k2[16];
        for (int v = 0; v < 256; v++) {
            memcpy(k2, key, 16);
            k2[0] = (uint8_t)v;
            sdc_sm4_set_encrypt_key(&ek, k2);
            bct.ops->set_encrypt_key(&bct, k2, 16);
            const sdc_sm4_ctx *ckt = (const sdc_sm4_ctx *)bct.inner_state;
            if (memcmp(ek.rk, ckt->rk, 32 * sizeof(uint32_t)) != 0) { ks_ok = 0; break; }
        }
        T_CHECK(ks_ok, "constant-time key schedule matches (256 keys)");
    }
#endif

    T_SUMMARY();
}
