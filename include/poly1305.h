#ifndef POLY1305_H
#define POLY1305_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t r[3];
    uint64_t h[3];
    uint64_t pad[2];
    uint8_t  buffer[16];
    size_t   leftover;
    uint8_t  final;
} poly1305_ctx;

void poly1305_init(poly1305_ctx *ctx, const uint8_t key[32]);
void poly1305_update(poly1305_ctx *ctx, const uint8_t *in, size_t len);
void poly1305_final(poly1305_ctx *ctx, uint8_t mac[16]);
void poly1305_mac(uint8_t mac[16], const uint8_t *in, size_t len, const uint8_t key[32]);

#endif