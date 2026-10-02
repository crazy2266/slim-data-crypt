/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * CPU feature detection.
 *
 * x86  : GCC/Clang builtins -- no system headers.
 * ARM  : getauxval(AT_HWCAP).  We define the HWCAP bits ourselves so that
 *        Android NDK (which does not ship <asm/hwcap.h>) builds unchanged.
 */

#include "cpu.h"

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#  define SDC_CPU_X86 1
#endif

#if defined(__aarch64__) || defined(__arm__)
#  define SDC_CPU_ARM 1
#endif

#if defined(SDC_CPU_ARM) && defined(__linux__)
#  include <sys/auxv.h>
   /* asm-generic HWCAP bits (aarch64). */
#  ifndef HWCAP_ASIMD
#    define HWCAP_ASIMD (1u << 1)
#  endif
#  ifndef HWCAP_AES
#    define HWCAP_AES   (1u << 3)
#  endif
#  ifndef HWCAP_PMULL
#    define HWCAP_PMULL (1u << 4)
#  endif
#endif

static sdc_cpu_features g_feat;
static int g_feat_ready = 0;

static void detect(sdc_cpu_features *f) {
    f->aes = 0; f->pclmul = 0; f->neon = 0; f->avx2 = 0;

#if defined(SDC_CPU_X86) && (defined(__GNUC__) || defined(__clang__))
    __builtin_cpu_init();
    if (__builtin_cpu_supports("aes"))    f->aes = 1;
    if (__builtin_cpu_supports("pclmul")) f->pclmul = 1;
    if (__builtin_cpu_supports("avx2"))   f->avx2 = 1;
#elif defined(SDC_CPU_ARM) && defined(__linux__)
    unsigned long hw = getauxval(AT_HWCAP);
    if (hw & HWCAP_AES)   f->aes = 1;
    if (hw & HWCAP_PMULL) f->pclmul = 1;
    if (hw & HWCAP_ASIMD) f->neon = 1;
#elif defined(SDC_CPU_ARM) && defined(__APPLE__)
    f->aes = 1; f->pclmul = 1; f->neon = 1;   /* Apple silicon always has these */
#endif
}

const sdc_cpu_features *sdc_cpu_get(void) {
    if (!g_feat_ready) {
        detect(&g_feat);
        g_feat_ready = 1;
    }
    return &g_feat;
}
