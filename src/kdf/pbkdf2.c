/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * PBKDF2 (Password-Based Key Derivation Function 2)
 *
 * References:
 *   - RFC 8018: PKCS #5 v2.1 (https://tools.ietf.org/html/rfc8018)
 *   - NIST SP 800-132: Recommendation for Password-Based Key Derivation
 *
 * Implementation conforms to RFC 8018, using HMAC-SHA256 as the PRF.
 */

#include <string.h>
#include <sdcrypt/config.h>
#include <sdcrypt/pbkdf2.h>
#include <sdcrypt/hmac.h>
#include <sdcrypt/utils.h>

#if SDC_ENABLE_PBKDF2

#if !SDC_ENABLE_HMAC || !SDC_ENABLE_SHA256
#  error "PBKDF2-HMAC-SHA256 requires HMAC and SHA256 support"
#endif

void sdc_kdf_pbkdf2_sha256(
    uint8_t *out, size_t outlen,
    const uint8_t *password, size_t pwdlen,
    const uint8_t *salt, size_t saltlen,
    uint32_t iterations
) {
    if (!out || !password || !salt || outlen == 0 || iterations == 0) return;

    sdc_hmac_sha256_ctx ctx;
    uint8_t u[32];
    uint8_t t[32];
    uint32_t block = 1;
    size_t pos = 0;

    while (pos < outlen) {
        sdc_hmac_sha256_init(&ctx, password, pwdlen);
        sdc_hmac_sha256_update(&ctx, salt, saltlen);

        uint8_t block_bytes[4];
        store32_be(block_bytes, block);
        sdc_hmac_sha256_update(&ctx, block_bytes, 4);
        sdc_hmac_sha256_final(&ctx, u);
        memcpy(t, u, 32);

        // U_i = HMAC(Password, U_{i-1})
        for (uint32_t i = 1; i < iterations; i++) {
            sdc_hmac_sha256(u, password, pwdlen, u, 32);
            for (int j = 0; j < 32; j++) {
                t[j] ^= u[j];
            }
        }

        size_t copy = (outlen - pos > 32) ? 32 : (outlen - pos);
        memcpy(out + pos, t, copy);
        pos += copy;
        block++;
    }
    sdc_secure_memzero(u, sizeof(u));
    sdc_secure_memzero(t, sizeof(t));
}

#endif /* SDC_ENABLE_PBKDF2 */
