/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Ed25519 signature (RFC 8032).
 */

#ifndef SDC_ED25519_H
#define SDC_ED25519_H

#include <stdint.h>
#include <stddef.h>
#include <sdcrypt/config.h>
#include <sdcrypt/rng.h>

#ifdef __cplusplus
extern "C" {
#endif

#if SDC_ENABLE_ED25519

#define SDC_ED25519_SEED_SIZE  32
#define SDC_ED25519_PUBLIC_KEY_SIZE  32
#define SDC_ED25519_PRIVATE_KEY_SIZE 64
#define SDC_ED25519_SIGNATURE_SIZE   64

/**
 * Create an Ed25519 key pair from a 32-byte seed.
 *
 * @param public_key   Output public key (32 bytes).
 * @param private_key  Output private key (64 bytes: expanded from seed).
 * @param seed         32-byte random seed.
 */
void sdc_ed25519_keypair(uint8_t public_key[SDC_ED25519_PUBLIC_KEY_SIZE],
                         uint8_t private_key[SDC_ED25519_PRIVATE_KEY_SIZE],
                         const uint8_t seed[SDC_ED25519_SEED_SIZE]);

/**
 * Generate a random key pair.
 *
 * @param public_key   Output public key (32 bytes).
 * @param private_key  Output private key (64 bytes).
 * @param rng_ctx      Random number generator context.
 * @return SDC_ERR_OK on success, other error codes.
 */
int sdc_ed25519_keypair_random(uint8_t public_key[SDC_ED25519_PUBLIC_KEY_SIZE],
                               uint8_t private_key[SDC_ED25519_PRIVATE_KEY_SIZE],
                               sdc_rng_ctx *rng_ctx);

/**
 * Sign a message.
 *
 * @param signature    Output signature (64 bytes).
 * @param message      Message to sign.
 * @param message_len  Message length.
 * @param public_key   Public key (32 bytes).
 * @param private_key  Private key (64 bytes).
 */
void sdc_ed25519_sign(uint8_t signature[SDC_ED25519_SIGNATURE_SIZE],
                      const uint8_t *message, size_t message_len,
                      const uint8_t public_key[SDC_ED25519_PUBLIC_KEY_SIZE],
                      const uint8_t private_key[SDC_ED25519_PRIVATE_KEY_SIZE]);

/**
 * Verify a signature.
 *
 * @return SDC_ERR_OK if valid, SDC_ERR_SIGNATURE_INVALID if not.
 */
int sdc_ed25519_verify(const uint8_t signature[SDC_ED25519_SIGNATURE_SIZE],
                       const uint8_t *message, size_t message_len,
                       const uint8_t public_key[SDC_ED25519_PUBLIC_KEY_SIZE]);

#endif /* SDC_ENABLE_ED25519 */

#ifdef __cplusplus
}
#endif

#endif /* SDC_ED25519_H */
