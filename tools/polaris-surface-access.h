/* Private Polaris IOSurface CPU-display/GPU exclusion. No hardware writes.
 * polarisGPUBusy: 0 idle, 1 GPU (uncertain DMA remains 1), 2 panel reader.
 * A reader must pin the WHOLE selected frame before touching panel memory.
 * Only an owner may release its own state. No forced clear or timeout unlock. */
#ifndef POLARIS_SURFACE_ACCESS_H
#define POLARIS_SURFACE_ACCESS_H
#include <stdint.h>
#include <stdbool.h>
enum { PFS_IDLE=0, PFS_GPU=1, PFS_PANEL=2 };
static inline bool pfs_acquire(uint32_t *state,uint32_t owner)
{
    if(!state || (owner!=PFS_GPU && owner!=PFS_PANEL))return false;
    uint32_t expected=PFS_IDLE;
    return __atomic_compare_exchange_n(state,&expected,owner,false,
        __ATOMIC_ACQUIRE,__ATOMIC_RELAXED);
}
static inline bool pfs_release(uint32_t *state,uint32_t owner)
{
    if(!state || (owner!=PFS_GPU && owner!=PFS_PANEL))return false;
    uint32_t expected=owner;
    return __atomic_compare_exchange_n(state,&expected,PFS_IDLE,false,
        __ATOMIC_RELEASE,__ATOMIC_RELAXED);
}
#endif
