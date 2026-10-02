/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Internal CPU feature detection (x86 / ARM).
 */

#ifndef SDC_CPU_H
#define SDC_CPU_H

typedef struct {
    int aes;      /* x86 AES-NI or ARMv8 AES extension */
    int pclmul;   /* x86 PCLMULQDQ or ARMv8 PMULL */
    int neon;     /* ARM Advanced SIMD */
    int avx2;     /* x86 AVX2 */
} sdc_cpu_features;

/* Returns a pointer to a process-wide cached features struct. */
const sdc_cpu_features *sdc_cpu_get(void);

#endif /* SDC_CPU_H */
