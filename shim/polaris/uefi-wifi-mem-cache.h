/* One qualified, retained, exclusive page. The descriptor transaction and
 * explicit MSS staging callers each establish their own target scope first.
 * The caller must
 * prove normal writable mappings, allocation lifetime, cache ownership and
 * the complete execution envelope. This leaf does not establish those facts.
 * INVALIDATE is allowed by the protocol only after a completed secure return;
 * no CPU writes may occur between its CLEAN_INVALIDATE and INVALIDATE steps. */
#ifndef POLARIS_UEFI_WIFI_MEM_CACHE_H
#define POLARIS_UEFI_WIFI_MEM_CACHE_H
#ifndef EFI_XNU_WIFI_MEM_ASSIGN_AVAILABLE
#define EFI_XNU_WIFI_MEM_ASSIGN_AVAILABLE 0
#endif
#if (EFI_XNU_WIFI_MEM_ASSIGN_AVAILABLE || (defined(EFI_XNU_MSS_STAGING_AVAILABLE) && EFI_XNU_MSS_STAGING_AVAILABLE)) && defined(__aarch64__) && !defined(POLARIS_EFI_TEST_QEMU)
#include "../../tools/polaris-wifi-mem-cache.h"
static inline int pwma_actual_cache_page(struct pwma_page*page,unsigned operation,struct pwmk_record*r)
{
    if(!page||!r||((uintptr_t)page&4095)||!pwma_span((uintptr_t)page,4096)||
       !pwma_span((uintptr_t)r,sizeof(*r))||
       pwma_overlap((uintptr_t)page,4096,(uintptr_t)r,sizeof(*r))||
       (operation!=PWMK_CLEAN_INVALIDATE&&operation!=PWMK_INVALIDATE))return 0;
    const uint8_t*raw=(const void*)r;
    for(unsigned k=0;k<sizeof(*r);k++)if(raw[k])return 0;
    r->attempted=1;r->address=(uintptr_t)page;r->operation=operation;
    __asm__ volatile("mrs %0,CurrentEL":"=r"(r->el)::"memory");
    if(r->el!=4){r->error=1;return 0;}
    __asm__ volatile("mrs %0,SCTLR_EL1; mrs %1,CTR_EL0":"=r"(r->sctlr),"=r"(r->ctr_before)::"memory");
    const unsigned line_bytes=pwmk_line_bytes(r->ctr_before);r->line_bytes=line_bytes;
    if((r->sctlr&5)!=5||!line_bytes){r->error=2;return 0;}
    /* Page alignment makes both ends whole cache lines; never touch adjacent
     * allocations. At most256 operations for an admitted line size. */
    for(unsigned offset=0;offset<4096;offset+=line_bytes){
        uint64_t address=(uintptr_t)page+offset;r->lines_issued++;
        __asm__ volatile("":::"memory");
        if(operation==PWMK_CLEAN_INVALIDATE)__asm__ volatile("dc civac,%0"::"r"(address):"memory");
        else __asm__ volatile("dc ivac,%0"::"r"(address):"memory");
        __asm__ volatile("":::"memory");r->lines_returned++;
    }
    r->barrier_issued=1;__asm__ volatile("dsb sy; isb":::"memory");r->barrier_returned=1;
    __asm__ volatile("mrs %0,CTR_EL0":"=r"(r->ctr_after)::"memory");
    if(r->ctr_after!=r->ctr_before){r->error=3;return 0;}
    r->complete=1;return 1;
}
#endif
#endif
