/* Explicit bounded-kernel-core admission for a resident firmware USB server.
 * 0x100/0x700 are the phone's own DT small/big cores. 1/7 are their generic
 * QEMU affinity counterparts. Firmware CPU0 always remains reserved.
 * Default ABL boots keep the original physical/logical CPU0 requirement. */
#ifndef POLARIS_UEFI_CPU_H
#define POLARIS_UEFI_CPU_H
#include <stdint.h>
static inline int polaris_uefi_cpu_declared(uint32_t mode,uint32_t target,
    uint32_t count,uint32_t logical,uint32_t physical)
{
    if(mode!=1 || (target!=0x100 && target!=0x700 && target!=1 && target!=7) ||
        logical>=count || (count!=1 && count!=2 && count!=4)) return 0;
    if(count>1 && target!=0x700 && target!=7) return 0;
    uint32_t step=target==0x700?0x100:1;
    return physical==target-logical*step && physical!=0;
}
static inline int polaris_uefi_cpu_allowed(uint32_t mode,uint32_t target,
    uint32_t count,uint32_t logical,uint32_t physical,uint64_t actual)
{
    if(logical!=0 || !polaris_uefi_cpu_declared(mode,target,count,logical,physical))
        return 0;
    return physical==target && (actual&UINT64_C(0xffffff))==target;
}
/* The generic virt board declares PSCI HVC; the phone uses secure SMC.
 * Select only after the executing boot core matches its explicit trial.
 * Return -1 for an unbound caller, never probe the other conduit on failure. */
static inline int polaris_uefi_psci_conduit(uint32_t mode,uint32_t target,
    uint32_t count,uint64_t actual)
{
    if(!polaris_uefi_cpu_allowed(mode,target,count,0,target,actual)) return -1;
    return target==1 || target==7;
}
/* CPU_ON is a scheduler-thread operation: after the first peer comes online
 * the initiating thread may run on any declared XNU core. Accept only the
 * actual MPIDR of that bounded set; firmware CPU0 and foreign cores stay out.
 * Bootstrap/coordinator admission above remains strictly boot-core-only. */
static inline int polaris_uefi_psci_running_conduit(uint32_t mode,uint32_t target,
    uint32_t count,uint64_t actual)
{
    uint32_t physical=(uint32_t)(actual&UINT64_C(0xffffff));
    for(uint32_t logical=0;logical<4;logical++) {
        if(polaris_uefi_cpu_declared(mode,target,count,logical,physical))
            return target==1 || target==7;
    }
    return -1;
}
#endif
