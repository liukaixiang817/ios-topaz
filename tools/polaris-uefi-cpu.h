/* Explicit single-kernel-core admission for a resident firmware USB server.
 * 0x100 is the phone's own DT cpu@100; 1 is QEMU virt's second processor.
 * Default ABL boots keep the original physical/logical CPU0 requirement. */
#ifndef POLARIS_UEFI_CPU_H
#define POLARIS_UEFI_CPU_H
#include <stdint.h>
static inline int polaris_uefi_cpu_allowed(uint32_t mode,uint32_t target,
    uint32_t count,uint32_t logical,uint32_t physical,uint64_t actual)
{
    if(mode!=1 || (target!=0x100 && target!=1) || count!=1 || logical!=0)
        return 0;
    return physical==target && (actual&UINT64_C(0xffffff))==target;
}
#endif
