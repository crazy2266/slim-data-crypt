#ifndef XCHACHA20_H
#define XCHACHA20_H

#include <stdint.h>
#include <stddef.h>
#include <stdalign.h>

#if defined(__ARM_NEON) || defined(__ARM_NEON__)
#  include <arm_neon.h>
#else
#  error "NEON support is required for this project."
#endif

typedef struct {
    uint32x4_t state[16];
    alignas(16) uint8_t buf[256];
    size_t buf_used;
} xchacha20_ctx;

void xchacha20_init(xchacha20_ctx *ctx, const uint8_t key[32], const uint8_t nonce[24], uint64_t counter);
void xchacha20_crypt(xchacha20_ctx *ctx, const uint8_t *in, uint8_t *out, size_t len);

#endif /* XCHACHA20_H */