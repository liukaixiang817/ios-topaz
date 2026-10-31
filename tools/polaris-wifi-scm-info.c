/* Native availability-only integration, intentionally separate from frozen
 *0910/current candidate. No SMEM address/pointer is ever an SMC argument. */
#include <sys/param.h>
#include <libkern/libkern.h>
#include <pexpert/pexpert.h>
#include "polaris-wifi-scm-info.h"
extern bool polaris_ram_overlay_allowed(void);
extern bool polaris_gpu_overlay_ready(void);
extern int polaris_uefi_shutdown_pending(void);
void polaris_wifi_scm_info_once(void);
static uint32_t pwi_consumed;
static struct pwi_report pwi_result;
static bool pwi_ready(void *context)
{
    (void)context;
    uint64_t el,freq;
    __asm__ volatile("mrs %0,currentel":"=r"(el));
    __asm__ volatile("mrs %0,cntfrq_el0":"=r"(freq));
    uint32_t mode=0;PE_parse_boot_argn("polarisuefi",&mode,sizeof(mode));
    return el==4&&freq==19200000&&mode==1&&!polaris_uefi_shutdown_pending()&&
        polaris_ram_overlay_allowed()&&polaris_gpu_overlay_ready();
}
static uint64_t pwi_counter(void *context)
{
    (void)context;uint64_t ticks;
    __asm__ volatile("isb\n\tmrs %0,cntvct_el0":"=r"(ticks)::"memory");return ticks;
}
static void pwi_invoke(void *context,uint64_t raw[7])
{
    (void)context;
    /* Same register ABI as audited a630_scm_call and own __scm_call_armv8_64.
     * The function ID is NON-fast SMC64 INFO, matching scm_call2, not the
     * atomic IO_READ0xc2000501. No GPU-owner gate is weakened or borrowed. */
    register uint64_t x0 __asm__("x0")=raw[0],x1 __asm__("x1")=raw[1];
    register uint64_t x2 __asm__("x2")=raw[2],x3 __asm__("x3")=raw[3];
    register uint64_t x4 __asm__("x4")=raw[4],x5 __asm__("x5")=raw[5];
    register uint64_t x6 __asm__("x6")=raw[6];
    __asm__ volatile("dsb sy\n\tsmc #0\n\tdsb sy"
        :"+r"(x0),"+r"(x1),"+r"(x2),"+r"(x3),"+r"(x4),"+r"(x5),"+r"(x6)
        ::"x7","x8","x9","x10","x11","x12","x13","x14","x15","x16","x17","memory","cc");
    raw[0]=x0;raw[1]=x1;raw[2]=x2;raw[3]=x3;raw[4]=x4;raw[5]=x5;raw[6]=x6;
}
void polaris_wifi_scm_info_once(void)
{
    /* Caller is0910's resident-thread path AFTER exact board/DT/overlay/CPU
     * gates and before reporting missing MPU proof. Atomic consume prevents
     * a second logical query even if another caller appears unexpectedly. */
    if(__atomic_exchange_n(&pwi_consumed,1,__ATOMIC_ACQ_REL))return;
    const struct pwi_io io={NULL,pwi_ready,pwi_counter,pwi_invoke};
    polaris_wifi_scm_info_query(&io,&pwi_result);
    printf("POLARIS WIFI SCM INFO: once fn=42000601 parm=1 target=02000501 calls=%u issued=%u complete=%u available=%u error=%u begin=%llu end=%llu; API exists is NOT address/MPU/lease permission, may_transmit=0\n",
        pwi_result.calls,(unsigned)pwi_result.issued,(unsigned)pwi_result.complete,
        (unsigned)pwi_result.available,pwi_result.error,pwi_result.begin,pwi_result.end);
    for(unsigned i=0;i<pwi_result.calls;i++) {
        const struct pwi_round *r=&pwi_result.rounds[i];
        printf("POLARIS WIFI SCM INFO RAW: round=%u before=%llu after=%llu x0=%llx x1=%llx x2=%llx x3=%llx x4=%llx x5=%llx x6=%llx\n",
            i,r->before,r->after,r->raw[0],r->raw[1],r->raw[2],r->raw[3],r->raw[4],r->raw[5],r->raw[6]);
    }
    /* Never calls IO_READ/IO_WRITE, changes permissions, maps SMEM or unlocks
     *0910. Timeout/unknown/error is retained, no fallback or future replay. */
}
