/* Pure failure projection of already-retained MSS maps. No service, target
 * access, allocation, repair or change to the allocation admission policy. */
#ifndef POLARIS_UEFI_MSS_MEMORY_DIAGNOSTIC_H
#define POLARIS_UEFI_MSS_MEMORY_DIAGNOSTIC_H
#include "uefi-mss-memory-policy.h"
struct pmmd_difference {
    uint32_t reason,direction,kind,byte,old_index,new_index,old_word,new_word;
    uint64_t address;
    struct efi_memory before,after;
};
/* Maps are completely validated before any descriptor walk. Reproduce the
 * existing comparison in both directions and retain its first mismatch. */
static inline int pmmd_direction(const struct pmme_memory*r,unsigned kind,const struct pwea_map*a,const struct pwea_map*b,
    uint64_t base,uint64_t bytes,unsigned direction,struct pmmd_difference*out)
{
    unsigned stride=(unsigned)a->map.stride;uint64_t heap_bytes=0;
    for(uint64_t at=0;at<a->map.bytes;at+=stride){
        const struct efi_memory*d=(const void*)(a->data+at);uint64_t cursor=d->physical,end=cursor+d->pages*4096;
        while(cursor<end){
            unsigned found=0;uint64_t next=end;
            for(uint64_t bt=0;bt<b->map.bytes;bt+=stride){
                const struct efi_memory*e=(const void*)(b->data+bt);uint64_t stop=e->physical+e->pages*4096;
                if(e->physical>cursor||cursor>=stop)continue;found++;
                unsigned inside=cursor>=base&&cursor<base+bytes;
                if(stop<next)next=stop;
                if(cursor<base&&base<next)next=base;
                if(cursor<base+bytes&&base+bytes<next)next=base+bytes;
                if(!pmme_segment_equal(r,kind,a->data+at,b->data+bt,stride,cursor,next,direction,&heap_bytes)){
                    out->reason=6;out->direction=direction;out->address=cursor;
                    out->old_index=(uint32_t)(direction?bt:at)/stride;out->new_index=(uint32_t)(direction?at:bt)/stride;
                    const uint8_t*old=direction?b->data+bt:a->data+at;
                    const uint8_t*new=direction?a->data+at:b->data+bt;
                    out->before=*(const struct efi_memory*)old;out->after=*(const struct efi_memory*)new;
                    unsigned offset=0;
                    if(d->type==(inside?(direction?2u:7u):e->type)&&(!inside||e->type==(direction?7u:2u))){
                        for(offset=4;offset<stride;offset++)
                            if(!((offset>=8&&offset<16)||(offset>=24&&offset<32))&&old[offset]!=new[offset])break;
                    }
                    out->byte=offset;
                    if(offset<stride){unsigned word=offset&~3u;
                        out->old_word=(uint32_t)pwfi_le(old+word,4);out->new_word=(uint32_t)pwfi_le(new+word,4);}
                    return 0;
                }
                if(stop<next)next=stop;
            }
            if(found!=1||next<=cursor){out->reason=7;out->direction=direction;out->address=cursor;return 0;}
            if(cursor<base&&base<next)next=base;
            if(cursor<base+bytes&&base+bytes<next)next=base+bytes;
            cursor=next;
        }
    }return 1;
}
static inline void pmmd_capture(const struct pmme_memory*r,struct pmmd_difference*out)
{
    if(!r||!out)return;
    if(r->error!=PWEA_DELTA||r->command.operation!=PWEA_MAP||
       !r->command.index||r->command.index>=PMME_MAPS||r->calls!=2*r->command.index+1){out->reason=1;return;}
    unsigned kind=r->command.index-1;out->kind=kind;
    const struct pwea_claim*q=&r->claim[kind];const struct pwea_map*a=&r->map[kind],*b=&r->map[kind+1];
    if(q->returned!=1||q->status||q->requested!=q->returned_address){out->reason=2;return;}
    struct polaris_efi_memory checked;uint64_t bytes=pmme_bytes(r,kind),base=q->requested;
    if(!a->map.valid||!b->map.valid||a->map.status||b->map.status||!a->map.key||!b->map.key||a->map.key==b->map.key||
       a->map.version!=1||b->map.version!=1||a->map.stride!=b->map.stride||!pmme_allowed(r,kind,base)||
       !polaris_efi_memory_check(a->data,a->map.bytes,PGCD_MAP_CAP,a->map.stride,&checked)||
       !polaris_efi_memory_check(b->data,b->map.bytes,PGCD_MAP_CAP,b->map.stride,&checked)){out->reason=3;return;}
    if(!polaris_efi_range_owned(a->data,a->map.bytes,a->map.stride,base,bytes,7)){out->reason=4;return;}
    if(!polaris_efi_range_owned(b->data,b->map.bytes,b->map.stride,base,bytes,2)){out->reason=5;return;}
    if(!pmmd_direction(r,kind,a,b,base,bytes,0,out)||!pmmd_direction(r,kind,b,a,base,bytes,1,out))return;
    for(unsigned k=0;k<r->command.index;k++)
        if(r->claim[k].retained!=1||!polaris_efi_range_owned(b->data,b->map.bytes,b->map.stride,r->claim[k].requested,r->claim[k].bytes,2)){
            out->reason=8;out->old_index=k;return;
        }
    out->reason=9; /* No current mismatch: never turn this into acceptance. */
}
#endif
