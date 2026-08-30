/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * RSA core test (public/private operations).
 * 
 * This test dynamically generates an RSA-2048 key pair and verifies
 * that encryption and decryption are inverses of each other.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sdcrypt/config.h>
#include <sdcrypt/rsa.h>
#include <sdcrypt/errcode.h>
#include <sdcrypt/integer.h>
#include <sdcrypt/rng.h>
#include <sdcrypt/mem.h>
#include "../src/rsa/rsa_inner.h"

#if SDC_ENABLE_RSA && SDC_ENABLE_RSA_KEYGEN

/* ============================================================
   Helper
   ============================================================ */
static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 32; i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) printf("...");
    printf("\n");
}

/* ============================================================
   Test: RSA public/private round-trip (dynamically generated key)
   ============================================================ */
static int test_rsa_roundtrip(void) {
    sdc_rsa_pubkey_t pubkey;
    sdc_rsa_privkey_t privkey;
    sdc_rng_ctx rng_ctx;
    sdc_rng_init(&rng_ctx, &sdc_system_rng_ops, NULL);
    int ret;

    printf("\n=== RSA-2048 Round-trip Test (Dynamic Key) ===\n");

    memset(&pubkey, 0, sizeof(pubkey));
    memset(&privkey, 0, sizeof(privkey));

    ret = sdc_rsa_keypair(&pubkey, &privkey, 0x10001, 2048, &rng_ctx);
    if (ret != SDC_ERR_OK) {
        printf("  [FAIL] sdc_rsa_keypair: %d\n", ret);
        return -1;
    }
    printf("  [PASS] Key pair generated\n");

    size_t n_words = pubkey.nlen;
    size_t n_bytes = n_words * SDC_WORD_SIZE;

    uint8_t *msg = (uint8_t *)sdc_malloc(n_bytes);
    uint8_t *cipher = (uint8_t *)sdc_malloc(n_bytes);
    uint8_t *decrypted = (uint8_t *)sdc_malloc(n_bytes);
    sdc_word_t *msg_w = (sdc_word_t *)sdc_malloc(n_bytes);
    sdc_word_t *cipher_w = (sdc_word_t *)sdc_malloc(n_bytes);
    sdc_word_t *decrypted_w = (sdc_word_t *)sdc_malloc(n_bytes);
    sdc_word_t *tmp = (sdc_word_t *)sdc_malloc(n_words * 6 * SDC_WORD_SIZE);

    if (!msg || !cipher || !decrypted || !msg_w || !cipher_w || !decrypted_w || !tmp) {
        printf("  [FAIL] malloc\n");
        goto cleanup;
    }

    for (size_t i = 0; i < n_bytes; i++) {
        msg[i] = (uint8_t)(i * 0x9e + 0x37);
    }
    msg[0] = 0x01;

    sdc_int_frombytes_be(msg_w, n_words, msg);

    /* c = m^e mod n */
    ret = _sdc_rsa_public(cipher_w, msg_w, &pubkey, tmp);
    if (ret != SDC_ERR_OK) {
        printf("  [FAIL] _sdc_rsa_public: %d\n", ret);
        goto cleanup;
    }

    /* m' = c^d mod n */
    ret = _sdc_rsa_private(decrypted_w, cipher_w, &privkey, tmp, &rng_ctx);
    if (ret != SDC_ERR_OK) {
        printf("  [FAIL] _sdc_rsa_private: %d\n", ret);
        goto cleanup;
    }

    /* Compare decrypted message with original message */
    if (sdc_int_eq(msg_w, decrypted_w, n_words) == 1) {
        printf("  [PASS] RSA round-trip: decrypt(encrypt(msg)) == msg\n");
    } else {
        printf("  [FAIL] RSA round-trip failed\n");
        sdc_int_tobytes_be(decrypted_w, n_words, decrypted);
        print_hex("  msg", msg, n_bytes);
        print_hex("  decrypted", decrypted, n_bytes);
        goto cleanup;
    }

cleanup:
    sdc_free(msg);
    sdc_free(cipher);
    sdc_free(decrypted);
    sdc_free(msg_w);
    sdc_free(cipher_w);
    sdc_free(decrypted_w);
    sdc_free(tmp);
    sdc_rsa_free_keypair(&pubkey, &privkey);
    return 0;
}

/* ============================================================
   main
   ============================================================ */
int main(void) {
    printf("===========================================\n");
    printf("  RSA Core Test (Dynamic Key)\n");
    printf("===========================================\n");

    int failed = 0;

    if (test_rsa_roundtrip() != 0) failed++;

    if (failed == 0) {
        printf("\n===========================================\n");
        printf("  ALL TESTS PASSED\n");
        printf("===========================================\n");
        return 0;
    } else {
        printf("\n===========================================\n");
        printf("  %d TESTS FAILED\n", failed);
        printf("===========================================\n");
        return 1;
    }
}

#else

int main(void) {
    printf("RSA or RSA keygen is disabled in this build.\n");
    return 0;
}

#endif /* SDC_ENABLE_RSA && SDC_ENABLE_RSA_KEYGEN */