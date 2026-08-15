/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * ASN.1 time parsing module.
 *
 * Time cache strategy:
 *   - Default range: ±30 years (61 elements, 488 bytes)
 *   - Adjustable via SDC_ASN1_TIME_CACHE_RANGE macro
 *   - Minimum: 0 (pure loop, 0 bytes)
 *   - Maximum: 50 (101 elements, 808 bytes)
 *
 * Time source:
 *   - Default: system time.h (Linux/Unix)
 *   - Embedded: user provides sdc_asn1_get_current_year()
 */

#ifndef SDC_ASN1TIME_H
#define SDC_ASN1TIME_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SDC_ASN1_TIME_CACHE_RANGE 30
// Time Provider: 0 = Standard time.h, 1 = User-defined
#define SDC_ASN1_TIME_PROVIDER 0

uint64_t sdc_asn1_time_to_timestamp(int year, int month, int day,
                                    int hour, int min, int sec);
void sdc_asn1_time_set_current(uint64_t timestamp);
void sdc_asn1_time_cache_refresh(void);
void sdc_asn1_time_get_cache_range(int *start_year, int *end_year);
int sdc_asn1_time_now(uint64_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SDC_ASN1TIME_H */