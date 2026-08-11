#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include "integer.h"

#if SDC_ENABLE_INTEGER

static void print_hex(const char *label, const uint64_t *a, size_t len) {
    printf("%s: ", label);
    int started = 0;
    for (int i = len - 1; i >= 0; i--) {
        if (started || a[i] != 0) {
            printf("%016llx", (unsigned long long)a[i]);
            started = 1;
        }
    }
    if (!started) printf("0");
    printf("\n");
}

static int is_eq(const uint64_t *a, const uint64_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

static void random_fill(uint64_t *a, size_t len) {
    for (size_t i = 0; i < len; i++) {
        a[i] = ((uint64_t)rand() << 32) | rand();
    }
}

/* ============================================================
   测试 1: 模逆
   ============================================================ */
static void test_modinv(void) {
    size_t len = 4;
    uint64_t phi[4] = {0x00000c30, 0, 0, 0};
    uint64_t d[4];
    uint64_t tmp[9];
    uint64_t expected[4] = {0x00000ac1, 0, 0, 0};
    uint64_t check[8];
    uint64_t one[4] = {1, 0, 0, 0};
    uint64_t e[4] = {17, 0, 0, 0};

    printf("\n=== 模逆测试 (phi=3120, e=17) ===\n");
    sdc_int_modinv(d, phi, e[0], tmp, len);
    print_hex("计算出的 d", d, len);
    print_hex("期望的 d", expected, len);

    if (!is_eq(d, expected, len)) {
        printf("❌ 模逆失败\n");
        return;
    }

    /* 验证: d * e ≡ 1 (mod phi) */
    sdc_int_mul(check, d, e, len);
    while (sdc_int_gte(check, phi, len)) {
        sdc_int_sub(check, check, phi, len);
    }
    print_hex("d * e mod phi", check, len);

    if (is_eq(check, one, 1)) {
        printf("✅ 模逆正确\n");
    } else {
        printf("❌ 验证失败\n");
    }
}

/* ============================================================
   测试 2: 蒙哥马利模幂 (费马小定理)
   ============================================================ */
static void test_modexp(void) {
    size_t len = 4;
    uint64_t n[4] = {0xFFFFFFFFFFFFFFED, 0xFFFFFFFFFFFFFFFF,
                     0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF};
    uint64_t a[4], exp[4], result[4], one[4];
    uint64_t tmp[4 * 4];
    uint64_t ninv;

    printf("\n=== 蒙哥马利模幂测试 (费马小定理) ===\n");
    print_hex("p (2^255 - 19)", n, len);

    srand((unsigned)time(NULL));
    random_fill(a, len);
    sdc_int_sub_ctl(a, n, len, sdc_int_gte(a, n, len));
    if (sdc_int_eq_word(a, 0, len)) a[0] = 2;

    print_hex("a", a, len);

    /* exp = n - 2 */
    sdc_int_copy(exp, n, len);
    sdc_int_sub_word(exp, exp, 1, len);

    ninv = sdc_int_calculate_ninv(n[0]);
    sdc_int_mont_modexp_u64(result, a, exp, len, n, tmp, len, ninv);

    print_hex("a^(p-1) mod p", result, len);

    /* 验证: exp ≡ 1 (mod p) */
    sdc_int_set_word(one, 1, len);
    if (is_eq(result, one, len)) {
        printf("✅ 费马小定理验证通过\n");
    } else {
        printf("❌ 费马小定理验证失败\n");
    }
}

/* ============================================================
   测试 3: RSA 加密/解密
   ============================================================ */
static void test_rsa(void) {
    size_t len = 8;
    uint64_t n[len];
    uint64_t phi[len];
    uint64_t d[len];
    uint64_t d_calc[len];
    uint64_t tmp[4 * len];
    uint64_t m[len], c[len], m_dec[len];
    uint64_t m_mont[len], c_mont[len], m_dec_mont[len];
    uint64_t e_arr[len];
    uint64_t ninv;
    uint64_t e = 65537;

    uint64_t n_init[8] = {
        0xe16f10b550e47917ULL,
        0x1afadb576fdd09b0ULL,
        0x50ab7a30d9342296ULL,
        0xb2563be2b04d2bf4ULL,
        0x3c2736890ef6010bULL,
        0x313307d28f1c2fb3ULL,
        0x9ba40b672a84bda9ULL,
        0xa6c79b087544f5c4ULL,
    };

    uint64_t phi_init[8] = {
        0xcaceac202a614290ULL,
        0x13fc31cec1734b5aULL,
        0x389bcffa1db8ab66ULL,
        0x1513d19f159e467dULL,
        0x3c2736890ef6010aULL,
        0x313307d28f1c2fb3ULL,
        0x9ba40b672a84bda9ULL,
        0xa6c79b087544f5c4ULL,
    };

    static const uint64_t d_init[8] = {
        0xcebdc971c4c41da1ULL,  // limb 0
        0xa25bfbb768fda34bULL,  // limb 1
        0x5b6b7afcd85e033cULL,  // limb 2
        0x5e3ac35e4d342c06ULL,  // limb 3
        0x16183fdb4652011bULL,  // limb 4
        0xff4dc5d4a4a3500bULL,  // limb 5
        0x99ae5f365b906097ULL,  // limb 6
        0x3300d3ee903e5892ULL  // limb 7
    };
    printf("\n=== RSA 加密/解密验证 ===\n");

    memcpy(n, n_init, sizeof(n));
    memcpy(phi, phi_init, sizeof(phi));
    memcpy(d, d_init, sizeof(d));

    printf("模逆测试 (512位): \n");
    sdc_int_modinv(d_calc, phi, e, tmp, len);
    print_hex("计算出的 d", d_calc, len);
    print_hex("期望的 d", d_init, len);

    if (is_eq(d_calc, d_init, len)) {
        printf("✅ 模逆正确\n\n");
    } else {
        printf("❌ 模逆错误\n\n");
    }

    /*
     * RSA 加密/解密验证 (测试用例由 python sympy 生成)
     * 测试用例：
     * p = 0xcf1d225af516eea21489e59a7fbfdb859b16b9b6aeb5ea53b85de612b57a140f
     * q = 0xce2547e8a597f6d50385c49c3bbb9baa6be7efd1ffb3d4025e427e8271092279
     * n = 0xa6c79b087544f5c49ba40b672a84bda9313307d28f1c2fb33c2736890ef6010bb2563be2b04d2bf450ab7a30d93422961afadb576fdd09b0e16f10b550e47917
     * phi = 0xa6c79b087544f5c49ba40b672a84bda9313307d28f1c2fb33c2736890ef6010a1513d19f159e467d389bcffa1db8ab6613fc31cec1734b5acaceac202a614290
     * d = 0x3300d3ee903e589299ae5f365b906097ff4dc5d4a4a3500b16183fdb4652011b5e3ac35e4d342c065b6b7afcd85e033ca25bfbb768fda34bcebdc971c4c41da1
     */
    printf("RSA 加密/解密验证 (512位): \n");
    ninv = sdc_int_calculate_ninv(n[0]);
    print_hex("n", n, len);
    printf("e = %llu (0x%llx)\n", (unsigned long long)e, (unsigned long long)e);
    printf("ninv = %016llx\n", (unsigned long long)ninv);

    srand((unsigned)time(NULL));
    for (size_t i = 0; i < len; i++) {
        m[i] = ((uint64_t)rand() << 32) | rand();
    }
    sdc_int_sub_ctl(m, n, len, sdc_int_gte(m, n, len));
    if (sdc_int_eq_word(m, 0, len)) m[0] = 2;

    print_hex("m (明文)", m, len);

    sdc_int_set_word(e_arr, 0, len);
    e_arr[0] = e;

    sdc_int_copy(m_mont, m, len);
    sdc_int_mont_modexp_u64(c_mont, m_mont, e_arr, len, n, tmp, len, ninv);
    sdc_int_copy(c, c_mont, len);

    print_hex("c (密文)", c, len);

    sdc_int_copy(c_mont, c, len);
    uint64_t d_arr[len];
    sdc_int_copy(d_arr, d_calc, len);
    sdc_int_mont_modexp_u64(m_dec_mont, c_mont, d_arr, len, n, tmp, len, ninv);
    sdc_int_copy(m_dec, m_dec_mont, len);

    print_hex("m_dec (解密后)", m_dec, len);

    if (is_eq(m, m_dec, len)) {
        printf("✅ RSA 加密/解密成功！\n");
    } else {
        printf("❌ RSA 加密/解密失败\n");
    }
}

/* ============================================================
   main
   ============================================================ */
int main(void) {
    printf("========================================\n");
    printf("Slim Data Crypt - Integer Library Test\n");
    printf("========================================\n");

    test_modinv();
    test_modexp();
    test_rsa();

    printf("\n========================================\n");
    printf("All tests completed.\n");
    printf("========================================\n");

    return 0;
}

#else

int main(void) {
    printf("[SKIP] Integer 测试未启用\n");
    return 0;
}

#endif /* SDC_ENABLE_INTEGER */