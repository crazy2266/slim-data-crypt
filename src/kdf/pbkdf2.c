#include <string.h>
#include "pbkdf2.h"
#include "hmac.h"
#include "utils.h"

int sdc_kdf_pbkdf2_sha256(
    uint8_t *out, size_t outlen,
    const uint8_t *password, size_t pwdlen,
    const uint8_t *salt, size_t saltlen,
    uint32_t iterations
) {
    if (!out || !password || !salt || outlen == 0 || iterations == 0) {
        return -1;
    }

    uint8_t u[32] = {0};
    uint8_t t[32] = {0};
    uint32_t block = 1;
    size_t pos = 0;

    while (pos < outlen) {
        // salt || block (big-endian)
        uint8_t salt_block[256];
        size_t salt_block_len = saltlen + 4;

        if (salt_block_len > sizeof(salt_block)) {
            sdc_secure_memzero(u, sizeof(u));
            sdc_secure_memzero(t, sizeof(t));
            return -1;
        }

        memcpy(salt_block, salt, saltlen);
        salt_block[saltlen + 0] = (uint8_t)((block >> 24) & 0xff);
        salt_block[saltlen + 1] = (uint8_t)((block >> 16) & 0xff);
        salt_block[saltlen + 2] = (uint8_t)((block >> 8) & 0xff);
        salt_block[saltlen + 3] = (uint8_t)(block & 0xff);

        // U1 = HMAC-SHA256(password, salt || block)
        sdc_hmac_sha256(u, password, pwdlen, salt_block, salt_block_len);
        memcpy(t, u, 32);

        // U2..U_iterations
        for (uint32_t i = 1; i < iterations; i++) {
            sdc_hmac_sha256(u, password, pwdlen, u, 32);
            for (int j = 0; j < 32; j++) {
                t[j] ^= u[j];
            }
        }

        // 复制到输出
        size_t copy = (outlen - pos > 32) ? 32 : (outlen - pos);
        memcpy(out + pos, t, copy);
        pos += copy;
        block++;
    }

    sdc_secure_memzero(u, sizeof(u));
    sdc_secure_memzero(t, sizeof(t));

    return 0;
}