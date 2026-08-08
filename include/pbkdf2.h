#ifndef KDF_H
#define KDF_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * PBKDF2-HMAC-SHA256: 从密码派生密钥
 *
 * @param out        输出缓冲区
 * @param outlen     输出长度（字节）
 * @param password   用户密码
 * @param pwdlen     密码长度
 * @param salt       盐值
 * @param saltlen    盐值长度
 * @param iterations 迭代次数（推荐 600000）
 * @return 0 成功，-1 失败
 */
int kdf_pbkdf2_sha256(
    uint8_t *out, size_t outlen,
    const uint8_t *password, size_t pwdlen,
    const uint8_t *salt, size_t saltlen,
    uint32_t iterations
);

#ifdef __cplusplus
}
#endif

#endif /* KDF_H */