/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * X25519 functions for key exchange.
 */

#ifndef SDC_X25519_H
#define SDC_X25519_H

#include <stdint.h>
#include <stddef.h>
#include <sdcrypt/config.h>
#include <sdcrypt/rng.h>

#if SDC_ENABLE_X25519

#ifdef __cplusplus
extern "C" {
#endif

/**
 * X25519 Key Exchange
 *
 * @param shared    Output Shared key (32 bytes)
 * @param priv      Private key (32 bytes)
 * @param pub       Public key (32 bytes)
 */
void sdc_x25519_exchange(uint8_t shared[32], const uint8_t priv[32], const uint8_t pub[32]);

/**
 * X25519 Key Generation
 *
 * @param pub       Output public key (32 bytes)
 * @param priv      Output private key (32 bytes)
 * @param rng_ctx   Random number generator context
 * @return SDC_ERR_OK on success, other error codes
 */
int sdc_x25519_keygen(uint8_t pub[32], uint8_t priv[32], sdc_rng_ctx *rng_ctx);

#ifdef __cplusplus
}
#endif

#endif /* SDC_ENABLE_X25519 */
#endif /* SDC_X25519_H */
