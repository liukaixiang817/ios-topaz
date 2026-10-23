/* Fixed RAM backing for the volatile root. Reserve before storage I/O starts;
 * subsequent allocations cannot fault, reclaim memory or recurse into VFS. */
#ifndef POLARIS_COW_ARENA_H
#define POLARIS_COW_ARENA_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define POLARIS_ARENA_GRANULE 16384u
struct polaris_cow_arena {
    uint8_t *base;
    size_t size, used;
};

static inline bool
polaris_arena_budget(unsigned mib, size_t *bytes, unsigned *groups)
{
    if (!bytes || !groups || mib < 16 || mib > 512) return false;
    *bytes = (size_t)mib << 20;
    *groups = (unsigned)(*bytes / POLARIS_ARENA_GRANULE);
    return true;
}

static inline void *
polaris_arena_allocate(size_t bytes, void *context)
{
    struct polaris_cow_arena *arena = context;
    if (!arena || !arena->base || bytes != POLARIS_ARENA_GRANULE ||
        arena->used > arena->size || bytes > arena->size - arena->used) return NULL;
    void *result = arena->base + arena->used;
    arena->used += bytes;
    return result;
}
#endif
