#ifndef SDC_RANDOM_H
#define SDC_RANDOM_H

#include <stdint.h>
#include <stddef.h>

int sdc_random_bytes(uint8_t *out, size_t len);

#endif /* SDC_RANDOM_H */