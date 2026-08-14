/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 crazy2266
 *
 * Pluggable dynamic memory allocator.
 */

#ifndef SDC_MEM_H
#define SDC_MEM_H

#include <stddef.h>
#include <stdlib.h>
#include <sdcrypt/config.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !SDC_SWAPPABLE_ALLOCATOR
#  define sdc_malloc malloc
#  define sdc_free   free
#else
typedef void *(*sdc_malloc_func_t)(size_t size);
typedef void (*sdc_free_func_t)(void *ptr);

// Set the allocator function. if malloc_fn or free_fn is NULL, the function will do nothing.
void sdc_set_allocator(sdc_malloc_func_t malloc_fn, sdc_free_func_t free_fn);
// Set the allocator function to default malloc and free.
void sdc_set_allocator_to_default(void);
void *sdc_malloc(size_t size);
void sdc_free(void *ptr);
#endif

// Allocate aligned memory.
// if alignment is not power of two or size is 0, the function will return NULL.
void *sdc_aligned_alloc(size_t alignment, size_t size);
void sdc_aligned_free(void *ptr);

#ifdef __cplusplus
}
#endif

#endif /* SDC_MEM_H */
