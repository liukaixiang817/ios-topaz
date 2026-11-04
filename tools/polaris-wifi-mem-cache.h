/* Descriptor-page cache protocol. Addresses are DATA until a qualified native
 * caller invokes the separate leaf. No target-region cache operation, mapping,
 * allocation, secure owner or DMA-retirement assertion is made here. */
#ifndef POLARIS_WIFI_MEM_CACHE_H
#define POLARIS_WIFI_MEM_CACHE_H
#include "polaris-wifi-mem-assign.h"
enum pwmk_operation {PWMK_CLEAN_INVALIDATE=1,PWMK_INVALIDATE=2};
struct pwmk_record {
    uint64_t address,ctr_before,ctr_after,el,sctlr;
    uint32_t operation,line_bytes,lines_issued,lines_returned;
    uint32_t attempted,barrier_issued,barrier_returned,complete,error,reserved;
};
static inline unsigned pwmk_line_bytes(uint64_t ctr)
{
    unsigned bytes=4u<<((ctr>>16)&15);
    return bytes>=16&&bytes<=4096?bytes:0;
}
static inline int pwmk_record_valid(const struct pwmk_record*r,uint64_t page,unsigned operation)
{
    if(!r||!page||(page&4095)||!pwma_span(page,4096)||
       (operation!=PWMK_CLEAN_INVALIDATE&&operation!=PWMK_INVALIDATE))return 0;
    unsigned bytes=pwmk_line_bytes(r->ctr_before);
    return bytes&&r->address==page&&r->operation==operation&&r->attempted==1&&
        r->el==4&&(r->sctlr&5)==5&&r->ctr_before==r->ctr_after&&
        r->line_bytes==bytes&&r->lines_issued==4096/bytes&&
        r->lines_returned==r->lines_issued&&r->barrier_issued==1&&
        r->barrier_returned==1&&r->complete==1&&!r->error&&!r->reserved;
}
#endif
