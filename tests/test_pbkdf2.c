#include "config.h"
#include <stdio.h>
#include <string.h>
#include "pbkdf2.h"

#if SDC_ENABLE_PBKDF2

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

int main(void) {
    printf("=== PBKDF2-HMAC-SHA256 测试 ===\n");

    // 测试向量 1: RFC 7914 (P="passwd", S="salt", c=1, dkLen=64)
    const uint8_t password1[] = "passwd";
    const uint8_t salt1[] = "salt";
    const uint32_t iterations1 = 1;
    uint8_t out1[64] = {0};
    const uint8_t expected1[64] = {
        0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f,
        0xec, 0x16, 0x91, 0xc2, 0x25, 0x44, 0xb6, 0x05,
        0xf9, 0x41, 0x85, 0x21, 0x6d, 0xde, 0x04, 0x65,
        0xe6, 0x8b, 0x9d, 0x57, 0xc2, 0x0d, 0xac, 0xbc,
        0x49, 0xca, 0x9c, 0xcc, 0xf1, 0x79, 0xb6, 0x45,
        0x99, 0x16, 0x64, 0xb3, 0x9d, 0x77, 0xef, 0x31,
        0x7c, 0x71, 0xb8, 0x45, 0xb1, 0xe3, 0x0b, 0xd5,
        0x09, 0x11, 0x20, 0x41, 0xd3, 0xa1, 0x97, 0x83
    };

    int ret = sdc_kdf_pbkdf2_sha256(out1, 64,
                                  password1, sizeof(password1) - 1,
                                  salt1, sizeof(salt1) - 1,
                                  iterations1);
    if (ret != 0) {
        printf("  [FAIL] PBKDF2 派生失败 (ret=%d)\n", ret);
        return 1;
    }

    printf("\n测试向量 1 (passwd/salt/c=1/dkLen=64):\n");
    print_hex("  期望", expected1, 64);
    print_hex("  计算", out1, 64);

    if (memcmp(out1, expected1, 64) == 0) {
        printf("  [OK]\n");
    } else {
        printf("  [FAIL]\n");
        return 1;
    }

    // 测试向量 2: RFC 7914 (P="Password", S="NaCl", c=80000, dkLen=64)
    const uint8_t password2[] = "Password";
    const uint8_t salt2[] = "NaCl";
    const uint32_t iterations2 = 80000;
    uint8_t out2[64] = {0};
    const uint8_t expected2[64] = {
        0x4d, 0xdc, 0xd8, 0xf6, 0x0b, 0x98, 0xbe, 0x21,
        0x83, 0x0c, 0xee, 0x5e, 0xf2, 0x27, 0x01, 0xf9,
        0x64, 0x1a, 0x44, 0x18, 0xd0, 0x4c, 0x04, 0x14,
        0xae, 0xff, 0x08, 0x87, 0x6b, 0x34, 0xab, 0x56,
        0xa1, 0xd4, 0x25, 0xa1, 0x22, 0x58, 0x33, 0x54,
        0x9a, 0xdb, 0x84, 0x1b, 0x51, 0xc9, 0xb3, 0x17,
        0x6a, 0x27, 0x2b, 0xde, 0xbb, 0xa1, 0xd0, 0x78,
        0x47, 0x8f, 0x62, 0xb3, 0x97, 0xf3, 0x3c, 0x8d
    };

    ret = sdc_kdf_pbkdf2_sha256(out2, 64,
                              password2, sizeof(password2) - 1,
                              salt2, sizeof(salt2) - 1,
                              iterations2);
    if (ret != 0) {
        printf("  [FAIL] PBKDF2 派生失败 (ret=%d)\n", ret);
        return 1;
    }

    printf("\n测试向量 2 (Password/NaCl/c=80000/dkLen=64):\n");
    print_hex("  期望", expected2, 64);
    print_hex("  计算", out2, 64);

    if (memcmp(out2, expected2, 64) == 0) {
        printf("  [OK]\n");
    } else {
        printf("  [FAIL]\n");
        return 1;
    }

    printf("\n✅ PBKDF2 测试全部通过\n");
    return 0;
}

#else

int main(void) {
    printf("[SKIP] PBKDF2 测试未启用\n");
    return 0;
}

#endif /* SDC_ENABLE_PBKDF2 */