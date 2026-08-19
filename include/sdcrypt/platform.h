/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Define platform-specific macros and types.
 */

#ifndef SDC_PLATFORM_H
#define SDC_PLATFORM_H

#include <stdint.h>
#include <stddef.h>

#if !defined(__GNUC__) && !defined(__clang__)
#  error "Unsupported compiler"
#endif

/* Uncomment the line below to force a specific platform. */
// #define SDC_64BIT 1
// #define SDC_32BIT 1

#if defined(__SIZEOF_POINTER__) && \
    !(defined(SDC_64BIT) || defined(SDC_32BIT))
#  if __SIZEOF_POINTER__ == 8
#    define SDC_64BIT      1
#  elif __SIZEOF_POINTER__ == 4
#    define SDC_32BIT      1
#  else
#    error "Unsupported platform or compiler"
#  endif
#endif

#if SDC_64BIT
#  define SDC_WORD_SIZE  8
#  define SDC_WORD_BITS  64
#  define SDC_DWORD_BITS 128
typedef uint64_t sdc_word_t;
typedef unsigned __int128 sdc_dword_t;
#  define SDC_WORD_MASK 0xFFFFFFFFFFFFFFFFULL
#  define sdc_word_clz __builtin_clzll
#  define sdc_word_ctz __builtin_ctzll
#elif SDC_32BIT
#  define SDC_WORD_SIZE  4
#  define SDC_WORD_BITS  32
#  define SDC_DWORD_BITS 64
typedef uint32_t sdc_word_t;
typedef uint64_t sdc_dword_t;
#  define SDC_WORD_MASK 0xFFFFFFFFU
#  define sdc_word_clz __builtin_clz
#  define sdc_word_ctz __builtin_ctz
#endif

#define SDC_THREAD_LOCAL __thread

#endif /* SDC_PLATFORM_H */