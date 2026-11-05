/* Exact cache-line operations for independent CE rings/buffers. The native
 * transport qualifies ownership and CPU translation before calling this leaf.
 * Whole-page clean is forbidden for live RX descriptor rings. */
#ifndef POLARIS_UEFI_WIFI_CE_CACHE_H
#define POLARIS_UEFI_WIFI_CE_CACHE_H
#include "../../tools/polaris-wifi-mem-cache.h"
struct pccl_record {struct pwmk_record cache;uint32_t bytes,reserved;};
static inline int pccl_valid(const struct pccl_record*r,uint64_t address,unsigned bytes,unsigned operation)
{
    if(!r||!address||(address&63)||!bytes||(bytes&63)||bytes>8192||address>UINT64_MAX-bytes||
       (operation!=PWMK_CLEAN_INVALIDATE&&operation!=PWMK_INVALIDATE))return 0;
    const struct pwmk_record*c=&r->cache;
    return r->bytes==bytes&&!r->reserved&&c->address==address&&c->operation==operation&&c->attempted==1&&
        c->el==4&&(c->sctlr&5)==5&&pwmk_line_bytes(c->ctr_before)==64&&c->ctr_before==c->ctr_after&&
        c->line_bytes==64&&c->lines_issued==bytes/64&&c->lines_returned==c->lines_issued&&
        c->barrier_issued==1&&c->barrier_returned==1&&c->complete==1&&!c->error&&!c->reserved;
}
#if defined(POLARIS_WIFI_CE_TRANSPORT_SOFTWARE_PEER)
static int pccl_actual(uint64_t,unsigned,unsigned,struct pccl_record*);
#else
static inline int pccl_actual(uint64_t address,unsigned bytes,unsigned operation,struct pccl_record*r)
{
    if(!r||!address||(address&63)||!bytes||(bytes&63)||bytes>8192||address>UINT64_MAX-bytes||
       (operation!=PWMK_CLEAN_INVALIDATE&&operation!=PWMK_INVALIDATE))return 0;
    const uint8_t*b=(const uint8_t*)r;for(unsigned n=0;n<sizeof(*r);n++)if(b[n])return 0;
    struct pwmk_record*c=&r->cache;r->bytes=bytes;c->address=address;c->operation=operation;c->attempted=1;
#if defined(__aarch64__) || defined(__arm64__)
    __asm__ volatile("mrs %0,ctr_el0; mrs %1,currentel; mrs %2,sctlr_el1":"=r"(c->ctr_before),"=r"(c->el),"=r"(c->sctlr)::"memory");
    if(c->el!=4||(c->sctlr&5)!=5||pwmk_line_bytes(c->ctr_before)!=64){c->error=1;return 0;}c->line_bytes=64;
    for(unsigned n=0;n<bytes;n+=64){
        uint64_t at=address+n;c->lines_issued++;
        if(operation==PWMK_CLEAN_INVALIDATE)__asm__ volatile("dc civac,%0"::"r"(at):"memory");
        else __asm__ volatile("dc ivac,%0"::"r"(at):"memory");c->lines_returned++;
    }
    c->barrier_issued=1;__asm__ volatile("dsb sy":::"memory");c->barrier_returned=1;
    __asm__ volatile("mrs %0,ctr_el0":"=r"(c->ctr_after)::"memory");c->complete=1;
    if(!pccl_valid(r,address,bytes,operation)){c->error=2;return 0;}return 1;
#else
    c->error=3;return 0;
#endif
}
#endif
#endif
