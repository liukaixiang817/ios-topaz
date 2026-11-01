/* Shared exact CPU-local typed mask/restore primitives and raw layouts.
 * Not a provider/EE/EL3/TCS/DMA lease. No caller uses a callback as permission. */
#ifndef POLARIS_UEFI_WIFI_CPU_LOCAL_MASK_H
#define POLARIS_UEFI_WIFI_CPU_LOCAL_MASK_H
#include "uefi-audio-i2c-cache.h"
struct pwrpc_transition {
    uint64_t target_daif,target_group,daif_before,group_before,daif_read,group_read;
    uint32_t returned,precondition_error,daif_written,daif_observed,group_written,group_observed;
};
struct pwrpc_context {struct pgcd_arch arch;uint64_t TPL,boot,tables,count;uint32_t complete;};
struct pwrpc_masked_psci {
    struct pwrpc_context before,after;struct pgcd_fp_guard fp;
    uint64_t target;int64_t raw;
    uint32_t issued,returned,unknown,native_before,native_after,complete;
};
static inline int pwrpc_actual_mask(void *ctx,struct pwrpc_transition *t)
{
    (void)ctx;
#if defined(__aarch64__) || defined(__arm64__)
    uint64_t el,sre;__asm__ volatile("mrs %0,currentel":"=r"(el));
    if(el!=4){t->precondition_error=1;return 1;}
    __asm__ volatile("mrs %0,ICC_SRE_EL1":"=r"(sre));
    if(!(sre&1)||t->target_daif!=0xc0||t->target_group){t->precondition_error=1;return 1;}
    __asm__ volatile("mrs %0,daif; mrs %1,ICC_IGRPEN1_EL1":"=r"(t->daif_before),"=r"(t->group_before));
    if(t->daif_before||t->group_before!=1){t->precondition_error=2;return 1;}
    __asm__ volatile("msr daifset,#3; isb":::"memory");t->daif_written=1;paic_actual_order(0);
    __asm__ volatile("mrs %0,daif":"=r"(t->daif_read));t->daif_observed=1;
    __asm__ volatile("msr ICC_IGRPEN1_EL1,xzr; dsb sy; isb":::"memory");t->group_written=1;paic_actual_order(0);
    __asm__ volatile("mrs %0,ICC_IGRPEN1_EL1":"=r"(t->group_read));t->group_observed=1;return 1;
#else
    (void)t;return 0;
#endif
}
static inline int pwrpc_actual_restore(void *ctx,struct pwrpc_transition *t)
{
    (void)ctx;
#if defined(__aarch64__) || defined(__arm64__)
    uint64_t el,sre;__asm__ volatile("mrs %0,currentel":"=r"(el));
    if(el!=4){t->precondition_error=1;return 1;}
    __asm__ volatile("mrs %0,ICC_SRE_EL1":"=r"(sre));
    if(!(sre&1)||t->target_daif||t->target_group!=1){t->precondition_error=1;return 1;}
    __asm__ volatile("mrs %0,daif; mrs %1,ICC_IGRPEN1_EL1":"=r"(t->daif_before),"=r"(t->group_before));
    if(t->daif_before!=0xc0||t->group_before){t->precondition_error=2;return 1;}
    __asm__ volatile("msr ICC_IGRPEN1_EL1,%0; dsb sy; isb"::"r"(t->target_group):"memory");t->group_written=1;paic_actual_order(0);
    __asm__ volatile("mrs %0,ICC_IGRPEN1_EL1":"=r"(t->group_read));t->group_observed=1;
    __asm__ volatile("msr daif,%0; isb"::"r"(t->target_daif):"memory");t->daif_written=1;paic_actual_order(0);
    __asm__ volatile("mrs %0,daif":"=r"(t->daif_read));t->daif_observed=1;return 1;
#else
    (void)t;return 0;
#endif
}
#endif
