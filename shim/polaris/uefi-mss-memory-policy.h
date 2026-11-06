/* Independent MSS allocations from CURRENT conventional EFI memory only.
 * Explicit new scope: own relocatable modem120MiB/1MiB alignment, MBA1MiB,
 * and page-rounded metadata<=64KiB. Old MSA/RMTFS2MiB policy is unchanged.
 * Reuse the existing full-map and bidirectional semantic delta machinery.
 * No target accesses, VMID grants, firmware publication or free are provided. */
#ifndef POLARIS_UEFI_MSS_MEMORY_POLICY_H
#define POLARIS_UEFI_MSS_MEMORY_POLICY_H
#include "uefi-wifi-early-memory.h"
#define PMME_CLAIMS 3u
#define PMME_MAPS 4u
#define PMME_CALLS 7u
struct pmme_input {struct pwea_input owner;uint64_t metadata_bytes;struct pwmc_range retained[2];};
struct pmme_memory {
    struct pmme_input input;struct pwea_command command;
    uint32_t started,unknown,error,pending,calls,complete;
    struct pwea_claim claim[PMME_CLAIMS];struct pwea_map map[PMME_MAPS];
};
static inline uint64_t pmme_bytes(const struct pmme_memory*r,unsigned kind)
{
    return kind==0?UINT64_C(0x7800000):kind==1?UINT64_C(0x100000):
        kind==2&&r->input.metadata_bytes&&r->input.metadata_bytes<=65536?
        (r->input.metadata_bytes+4095)&~UINT64_C(4095):0;
}
static inline unsigned pmme_exclusion_count(unsigned kind)
{return (unsigned)(sizeof(pwmc_exclusions)/sizeof(pwmc_exclusions[0]))+4+kind;}
static inline struct pwmc_range pmme_exclusion(const struct pmme_memory*r,unsigned n)
{
    unsigned count=(unsigned)(sizeof(pwmc_exclusions)/sizeof(pwmc_exclusions[0]));
    if(n<count)return pwmc_exclusions[n];n-=count;
    if(n==0)return (struct pwmc_range){r->input.owner.image,r->input.owner.image_bytes};
    if(n==1)return (struct pwmc_range){r->input.owner.bank,r->input.owner.bank_bytes};
    if(n<4)return r->input.retained[n-2];n-=4;
    return n<PMME_CLAIMS?(struct pwmc_range){r->claim[n].requested,r->claim[n].bytes}:(struct pwmc_range){0};
}
static inline int pmme_allowed(const struct pmme_memory*r,unsigned kind,uint64_t base)
{
    uint64_t bytes=pmme_bytes(r,kind),alignment=kind==0?0x100000:4096;
    if(!bytes||(base&(alignment-1))||base<0x80000000||base>UINT64_C(0x100000000)-bytes)return 0;
    for(unsigned k=0;k<pmme_exclusion_count(kind);k++){
        struct pwmc_range x=pmme_exclusion(r,k);
        if(!pwea_disjoint(base,bytes,x.base,x.bytes))return 0;
    }return 1;
}
static inline int pmme_select(const struct pmme_memory*r,const struct pwea_map*m,unsigned kind,uint64_t*out)
{
    struct polaris_efi_memory checked;uint64_t bytes=pmme_bytes(r,kind),alignment=kind==0?0x100000:4096,best=0;
    if(!out||!bytes||!m->map.valid||!polaris_efi_memory_check(m->data,m->map.bytes,PGCD_MAP_CAP,m->map.stride,&checked))return 0;
    for(uint64_t at=0;at<m->map.bytes;at+=m->map.stride){
        const struct efi_memory*d=(const void*)(m->data+at);
        if(d->type!=7||d->attributes>>63||d->virtual_address)continue;
        uint64_t lo=d->physical<0x80000000?0x80000000:d->physical,hi=d->physical+d->pages*4096;
        if(hi>UINT64_C(0x100000000))hi=UINT64_C(0x100000000);
        if(hi<bytes||lo>hi-bytes)continue;
        uint64_t candidate=(hi-bytes)&~(alignment-1);
        for(unsigned attempt=0;attempt<=pmme_exclusion_count(kind);attempt++){
            if(candidate<lo)break;
            if(pmme_allowed(r,kind,candidate)){if(candidate>best)best=candidate;break;}
            uint64_t limit=UINT64_MAX;
            for(unsigned k=0;k<pmme_exclusion_count(kind);k++){
                struct pwmc_range x=pmme_exclusion(r,k);
                if(candidate<x.base+x.bytes&&x.base<candidate+bytes&&x.base<limit)limit=x.base;
            }
            if(limit<bytes||limit==UINT64_MAX)break;
            uint64_t lower=(limit-bytes)&~(alignment-1);if(lower>=candidate)break;candidate=lower;
        }
    }if(!best)return 0;*out=best;return 1;
}
/* Original DxeCore b3a8..b3b8 replenishes its descriptor list with ONE
 * BootServicesData page (type4/pages1/alignment4096), via c16c. This may occur
 * inside AllocatePages. Account for that firmware-owned page separately from
 * our type2 claim; never expose, map, write or free it. This observed profile
 * permits it only above4GiB and outside every caller/DT/retained exclusion.
 * All other descriptor bytes and all other transitions remain exact. */
static inline int pmme_segment_equal(const struct pmme_memory*r,unsigned kind,
    const uint8_t*a,const uint8_t*b,unsigned stride,uint64_t start,uint64_t end,
    unsigned reverse,uint64_t*heap_bytes)
{
    uint64_t base=r->claim[kind].requested,bytes=pmme_bytes(r,kind);
    unsigned inside=start>=base&&start<base+bytes;
    if(pwmc_descriptor_equal(a,b,stride,reverse?2:7,reverse?7:2,inside))return 1;
    const struct efi_memory*before=(const void*)(reverse?b:a);
    if(inside||start<UINT64_C(0x100000000)||end<=start||end-start>4096||
       *heap_bytes>4096-(end-start)||before->virtual_address||
       !(before->attributes&8)||before->attributes>>63||
       !pwmc_descriptor_equal(a,b,stride,reverse?4:7,reverse?7:4,1))return 0;
    for(unsigned k=0;k<pmme_exclusion_count(kind+1);k++){
        struct pwmc_range x=pmme_exclusion(r,k);
        if(!pwea_disjoint(start,end-start,x.base,x.bytes))return 0;
    }
    *heap_bytes+=end-start;return 1;
}
static inline int pmme_delta_direction(const struct pmme_memory*r,unsigned kind,
    const struct pwea_map*a,const struct pwea_map*b,unsigned reverse)
{
    uint64_t base=r->claim[kind].requested,bytes=pmme_bytes(r,kind),heap_bytes=0;
    unsigned stride=(unsigned)a->map.stride;
    for(uint64_t at=0;at<a->map.bytes;at+=stride){
        const struct efi_memory*d=(const void*)(a->data+at);
        uint64_t cursor=d->physical,end=cursor+d->pages*4096;
        while(cursor<end){
            unsigned found=0;uint64_t next=end;
            for(uint64_t bt=0;bt<b->map.bytes;bt+=stride){
                const struct efi_memory*e=(const void*)(b->data+bt);
                uint64_t stop=e->physical+e->pages*4096;
                if(e->physical>cursor||cursor>=stop)continue;found++;
                if(stop<next)next=stop;
                if(cursor<base&&base<next)next=base;
                if(cursor<base+bytes&&base+bytes<next)next=base+bytes;
                if(!pmme_segment_equal(r,kind,a->data+at,b->data+bt,stride,cursor,next,reverse,&heap_bytes))return 0;
            }
            if(found!=1||next<=cursor)return 0;
            cursor=next;
        }
    }return 1;
}
static inline int pmme_delta(const struct pmme_memory*r,unsigned kind,const struct pwea_map*a,const struct pwea_map*b)
{
    if(!r||!a||!b||kind>=PMME_CLAIMS)return 0;
    struct polaris_efi_memory checked;uint64_t base=r->claim[kind].requested,bytes=pmme_bytes(r,kind);
    if(!a->map.valid||!b->map.valid||a->map.status||b->map.status||!a->map.key||!b->map.key||a->map.key==b->map.key||
       a->map.version!=1||b->map.version!=1||a->map.stride!=b->map.stride||!pmme_allowed(r,kind,base)||
       !polaris_efi_memory_check(a->data,a->map.bytes,PGCD_MAP_CAP,a->map.stride,&checked)||
       !polaris_efi_memory_check(b->data,b->map.bytes,PGCD_MAP_CAP,b->map.stride,&checked)||
       !polaris_efi_range_owned(a->data,a->map.bytes,a->map.stride,base,bytes,7)||
       !polaris_efi_range_owned(b->data,b->map.bytes,b->map.stride,base,bytes,2))return 0;
    return pmme_delta_direction(r,kind,a,b,0)&&pmme_delta_direction(r,kind,b,a,1);
}
static inline int pmme_fail(struct pmme_memory*r,unsigned error)
{if(r){r->unknown=1;if(!r->error)r->error=error;}return PWEA_FAILED;}
static inline int pmme_begin(struct pmme_memory*r,const struct pmme_input*i)
{
    if(!r||!i||!pwea_disjoint((uintptr_t)r,sizeof(*r),(uintptr_t)i,sizeof(*i))||!pwmc_zero(r,sizeof(*r))||
       !pwea_disjoint(i->owner.image,i->owner.image_bytes,i->owner.bank,i->owner.bank_bytes)||
       (i->owner.image&4095)||(i->owner.bank&4095)||(i->owner.bank_bytes&4095)||
       sizeof(*r)>i->owner.image_bytes||(uintptr_t)r<i->owner.image||
       (uintptr_t)r-i->owner.image>i->owner.image_bytes-sizeof(*r)||!i->metadata_bytes||i->metadata_bytes>65536)return PWEA_FAILED;
    for(unsigned k=0;k<2;k++)if(i->retained[k].bytes!=pwmc_bytes(k)||!pwmc_allowed(i->retained[k].base,i->retained[k].bytes)||
        !pwea_disjoint(i->retained[k].base,i->retained[k].bytes,i->owner.image,i->owner.image_bytes)||
        !pwea_disjoint(i->retained[k].base,i->retained[k].bytes,i->owner.bank,i->owner.bank_bytes))return PWEA_FAILED;
    if(!pwea_disjoint(i->retained[0].base,i->retained[0].bytes,i->retained[1].base,i->retained[1].bytes))return PWEA_FAILED;
    r->input=*i;r->started=1;return PWEA_WAIT;
}
static inline int pmme_next(struct pmme_memory*r,struct pwea_command*out)
{
    if(!r||!out||!r->started||r->unknown||r->error)return PWEA_FAILED;
    if(!pwea_disjoint((uintptr_t)r,sizeof(*r),(uintptr_t)out,sizeof(*out))||r->pending)return pmme_fail(r,PWEA_REENTRY);
    if(r->complete)return r->complete==1&&r->calls==PMME_CALLS?PWEA_RETAINED:pmme_fail(r,PWEA_REENTRY);
    if(r->calls>=PMME_CALLS)return pmme_fail(r,PWEA_REENTRY);
    struct pwea_command c={.sequence=r->calls+1,.operation=(r->calls&1)?PWEA_ALLOCATE:PWEA_MAP,.index=r->calls/2};
    if(c.operation==PWEA_MAP){
        struct pwea_map*m=&r->map[c.index];if(!pwmc_zero(m,sizeof(*m)))return pmme_fail(r,PWEA_REENTRY);
        m->map.bytes=PGCD_MAP_CAP;m->map.issued=1;
    }else{
        struct pwea_claim*q=&r->claim[c.index];
        if(!pwmc_zero(q,sizeof(*q))||!pmme_select(r,&r->map[c.index],c.index,&c.address))return pmme_fail(r,PWEA_RANGE);
        q->requested=q->returned_address=c.address;q->bytes=pmme_bytes(r,c.index);q->pages=c.pages=q->bytes/4096;q->issued=1;
    }
    r->command=c;r->pending=1;r->calls++;*out=c;return PWEA_IO;
}
static inline void pmme_seal(const struct pmme_memory*r,uint8_t digest[32])
{
    const struct pwea_command*c=&r->command;uintptr_t lo=0,hi=0,lo2=0,hi2=0;
    if(c->operation==PWEA_MAP&&c->index<PMME_MAPS){
        lo=(uintptr_t)&r->map[c->index].map;hi=lo+offsetof(struct pgcd_map,issued);
        lo2=(uintptr_t)r->map[c->index].data;hi2=lo2+PGCD_MAP_CAP;
    }else if(c->operation==PWEA_ALLOCATE&&c->index<PMME_CLAIMS){lo=(uintptr_t)&r->claim[c->index].status;hi=lo+16;}
    struct pwfi_sha256 h;pwfi_init(&h);
    for(size_t k=0;k<sizeof(*r);k++){uintptr_t p=(uintptr_t)r+k;
        if((p>=lo&&p<hi)||(p>=lo2&&p<hi2))continue;pwfi_byte(&h,((const uint8_t*)r)[k]);}
    pwfi_final(&h,digest);
}
static inline int pmme_complete(struct pmme_memory*r,const struct pwea_command*c,int returned,const uint8_t before[32])
{
    if(!r||!c||!before||!r->started||r->unknown||r->error)return PWEA_FAILED;
    if(r->pending!=1||!r->calls||r->calls>PMME_CALLS||c->sequence!=r->calls||!pgcd_equal(c,&r->command,sizeof(*c)))return pmme_fail(r,PWEA_REENTRY);
    uint8_t after[32];pmme_seal(r,after);if(!pgcd_equal(before,after,32))return pmme_fail(r,PWEA_EFFECT);
    if(returned!=1)return pmme_fail(r,PWEA_RETURN);
    if(c->operation==PWEA_MAP){
        if(c->index>=PMME_MAPS)return pmme_fail(r,PWEA_REENTRY);
        struct pwea_map*m=&r->map[c->index];struct polaris_efi_memory checked;m->map.returned=1;
        if(m->map.status||!m->map.key||m->map.version!=1||!polaris_efi_memory_check(m->data,m->map.bytes,PGCD_MAP_CAP,m->map.stride,&checked)||
           !polaris_efi_range_owned(m->data,m->map.bytes,m->map.stride,r->input.owner.bank,r->input.owner.bank_bytes,2))return pmme_fail(r,PWEA_MAP_ERROR);
        for(unsigned k=0;k<2;k++)if(!polaris_efi_range_owned(m->data,m->map.bytes,m->map.stride,r->input.retained[k].base,r->input.retained[k].bytes,2))return pmme_fail(r,PWEA_MAP_ERROR);
        m->map.valid=1;
        if(c->index){
            unsigned kind=c->index-1;struct pwea_claim*q=&r->claim[kind];
            if(q->returned!=1||q->status||q->requested!=q->returned_address||!pmme_delta(r,kind,&r->map[kind],m))return pmme_fail(r,PWEA_DELTA);
            q->exposed=q->requested;q->exposed_bytes=kind==2?r->input.metadata_bytes:q->bytes;q->retained=1;
        }
        for(unsigned k=0;k<c->index;k++)if(r->claim[k].retained!=1||!polaris_efi_range_owned(m->data,m->map.bytes,m->map.stride,r->claim[k].requested,r->claim[k].bytes,2))return pmme_fail(r,PWEA_DELTA);
        if(c->index==PMME_CLAIMS)r->complete=1;
    }else{
        if(c->operation!=PWEA_ALLOCATE||c->index>=PMME_CLAIMS)return pmme_fail(r,PWEA_REENTRY);
        struct pwea_claim*q=&r->claim[c->index];q->returned=1;
        if(q->status||q->requested!=q->returned_address)return pmme_fail(r,PWEA_ALLOC_ERROR);
    }
    r->pending=0;return r->complete?PWEA_RETAINED:PWEA_WAIT;
}
#endif
