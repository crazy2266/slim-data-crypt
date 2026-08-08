#ifndef RANDOM_H
#define RANDOM_H

#include <stdint.h>
#include <stddef.h>

int random_bytes(uint8_t *out, size_t len);

#endif /* RANDOM_H */