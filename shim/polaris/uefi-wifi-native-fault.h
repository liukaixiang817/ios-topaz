/* Layout/record for a terminal firmware-only CPU0 exception diagnostic.
 * This grants no allocation, CPU/radio ownership, return or reset path. */
#ifndef POLARIS_WIFI_NATIVE_FAULT_H
#define POLARIS_WIFI_NATIVE_FAULT_H
#include <stdint.h>
#include <stddef.h>
#define PFNF_STACK_BYTES 16384u
struct pfnf_layout {
    uint64_t image,image_bytes,vectors,vectors_end,code_end,handler;
    uint64_t stack,stack_bytes,record,record_bytes,gop,gop_bytes;
};
struct pfnf_record {
    struct pfnf_layout layout;
    uint64_t old_vbar,vbar,vector,esr,elr,far,spsr,sp,sp0,ticks;
    uint64_t owner_opening,owner_last,parent_turns;
    uint32_t attempted,armed,error,draw_result;
    volatile uint32_t entered,reentered;
    uint32_t boot_phase,parent_phase,parent_error,parent_unknown;
    uint32_t copy_pages,copy_segments,copy_error,copy_ready,auth_phase,modem_step,owner_error,owner_held;
};
static inline int pfnf_inside(uint64_t base,uint64_t bytes,uint64_t at,uint64_t n)
{return n && bytes && base<=UINT64_MAX-bytes && at>=base && at<=UINT64_MAX-n && at+n<=base+bytes;}
static inline int pfnf_disjoint(uint64_t a,uint64_t n,uint64_t b,uint64_t m)
{return n && m && a<=UINT64_MAX-n && b<=UINT64_MAX-m && (a+n<=b || b+m<=a);}
static inline int pfnf_layout_valid(const struct pfnf_layout *l)
{
    if(!l || (l->vectors&2047) || l->vectors>UINT64_MAX-2048 ||
       l->vectors_end!=l->vectors+2048 || l->code_end<=l->vectors_end ||
       l->code_end-l->vectors>4096 || (l->code_end&3) || (l->handler&3) ||
       (l->stack&4095) || l->stack_bytes!=PFNF_STACK_BYTES ||
       (l->record&15) || l->record_bytes!=sizeof(struct pfnf_record) ||
       (l->gop&7) || !l->gop_bytes || l->gop_bytes>262144)return 0;
    const uint64_t at[]={l->vectors,l->stack,l->record,l->gop};
    const uint64_t size[]={l->code_end-l->vectors,l->stack_bytes,l->record_bytes,l->gop_bytes};
    for(unsigned n=0;n<4;n++){
        if(!pfnf_inside(l->image,l->image_bytes,at[n],size[n]))return 0;
        for(unsigned j=0;j<n;j++)if(!pfnf_disjoint(at[n],size[n],at[j],size[j]))return 0;
    }
    if(!pfnf_inside(l->image,l->image_bytes,l->handler,4))return 0;
    for(unsigned n=1;n<4;n++)if(!pfnf_disjoint(l->handler,4,at[n],size[n]))return 0;
    return 1;
}
#endif
