/* Own PIL loads filesz and zeros only memsz-filesz. Inter-segment holes and
 * bytes beyond memsz are not target writes. This planner grants no ownership. */
#ifndef POLARIS_MSS_VENDOR_EXTENT_H
#define POLARIS_MSS_VENDOR_EXTENT_H
#include "uefi-mss-firmware-types.h"
#define PMVE_BANK_BYTES UINT32_C(0x7800000)
#define PMVE_PAGES 30720u
enum pmve_kind {PMVE_INVALID=0,PMVE_WRITE=1,PMVE_UNTOUCHED=2};
struct pmve_extent {uint32_t kind,source_bytes,target_bytes;};
static inline int pmve_plan(const struct pmsf_segment*g,unsigned first_page,
    unsigned page,struct pmve_extent*out)
{
    if(!out)return 0;*out=(struct pmve_extent){0};
    if(!g||!g->memsz||g->filesz>g->memsz||(g->target_offset&4095)||
       g->target_offset>=PMVE_BANK_BYTES||g->memsz>PMVE_BANK_BYTES-g->target_offset||
       first_page>g->target_offset/4096||page<first_page||page>=PMVE_PAGES)return 0;
    uint64_t at=(uint64_t)page*4096,end=(uint64_t)g->target_offset+g->memsz;
    if(at>=end)return 0;
    if(at<g->target_offset){out->kind=PMVE_UNTOUCHED;return 1;}
    unsigned offset=(unsigned)(at-g->target_offset);
    out->target_bytes=(unsigned)(end-at);if(out->target_bytes>4096)out->target_bytes=4096;
    out->source_bytes=offset<g->filesz?g->filesz-offset:0;
    if(out->source_bytes>out->target_bytes)out->source_bytes=out->target_bytes;
    out->kind=PMVE_WRITE;return 1;
}
#endif
