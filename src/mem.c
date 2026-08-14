#include <stdint.h>
#include <sdcrypt/mem.h>

#if SDC_SWAPPABLE_ALLOCATOR
static sdc_malloc_func_t g_malloc_fn = malloc;
static sdc_free_func_t g_free_fn = free;

void sdc_set_allocator(sdc_malloc_func_t malloc_fn, sdc_free_func_t free_fn) {
    if (!malloc_fn || !free_fn) return;
    g_malloc_fn = malloc_fn;
    g_free_fn = free_fn;
}

void sdc_set_allocator_to_default(void) {
    g_malloc_fn = malloc;
    g_free_fn = free;
}

void *sdc_malloc(size_t size) { return g_malloc_fn(size); }
void sdc_free(void *ptr) { g_free_fn(ptr); }
#endif

static inline void *sdc_align_ptr(void *ptr, size_t alignment) {
    uintptr_t addr = (uintptr_t)ptr;
    uintptr_t aligned = (addr + alignment - 1) & ~(alignment - 1);
    return (void *)aligned;
}

void *sdc_aligned_alloc(size_t alignment, size_t size) {
    if (size == 0) return NULL;
    if (alignment == 0 || (alignment & (alignment - 1)) != 0) return NULL;
    if (size > SIZE_MAX - alignment - sizeof(void*)) return NULL;
    size_t alloc_size = size + alignment + sizeof(void*);
    void *raw_ptr = sdc_malloc(alloc_size);
    if (!raw_ptr) return NULL;
    void *aligned_ptr = sdc_align_ptr((char *)raw_ptr + sizeof(void*), alignment);
    void **header = (void **)aligned_ptr - 1;
    *header = raw_ptr;
    return aligned_ptr;
}

void sdc_aligned_free(void *ptr) {
    if (!ptr) return;
    void **header = (void **)ptr - 1;
    void *raw_ptr = *header;
    sdc_free(raw_ptr);
}