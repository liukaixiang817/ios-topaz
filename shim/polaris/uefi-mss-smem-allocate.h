/* Own host1 private SMEM allocations, made only under our actual SFPB lock.
 * New APPS SMP2P428/340B, GLINK478/32B and TX479/16KiB. No existing item
 * takeover, RX allocation, common partition fallback or automatic unlock.
 * Initialize/read back all new data and headers before publishing one new
 * uncached frontier. This does not negotiate SMP2P or start a GLINK channel. */
#ifndef POLARIS_UEFI_MSS_SMEM_ALLOCATE_H
#define POLARIS_UEFI_MSS_SMEM_ALLOCATE_H
#if EFI_XNU_MSS_SMEM_NATIVE_AVAILABLE && EFI_XNU_MSS_SFPB_IO_AVAILABLE
#include "uefi-mss-smem-lock.h"
#include "../../tools/polaris-glink-inventory.h"
#define PMSA_ITEMS 3u
#define PMSA_EVENTS 16u
struct pmsa_item {uint32_t id,bytes,allocated,header,data;uint8_t wire[16];};
struct pmsa_delivery {
    uint64_t address;uint32_t bytes,stage,item,zero,issued,returned,words,verified,complete,reserved;
    struct pmli_read node[2];struct pmni_translation AT[2];
    struct pmsl_delivery lock[2];
};
struct pmsa_state {
    uint64_t lock,smem,owner,opening;
    struct polaris_glink_workspace inventory;struct polaris_smem_part partition;
    struct pmsa_item item[PMSA_ITEMS];uint32_t frontier;
    uint8_t initial_header[32],published_header[32];
    struct pmsa_delivery event[PMSA_EVENTS];
    uint32_t attempted,unknown,error,prepared,pending,events,stores,complete;
    uint8_t plan_digest[32],digest[32];
};
#if defined(POLARIS_MSS_SMEM_ALLOCATE_SOFTWARE_PEER)
static int pmsa_store(uint64_t,uint32_t,uint32_t*);
#else
static inline int pmsa_store(uint64_t at,uint32_t value,uint32_t*readback)
{
    __asm__ volatile("str %w1,[%2]; dsb sy; ldr %w0,[%2]":"=r"(*readback):"r"(value),"r"(at):"memory");return 1;
}
#endif
static inline int pmsa_fail(struct pmsa_state*s,unsigned error)
{
    s->unknown=1;if(!s->error)s->error=error;
    if(s->stores)pmsl_fail((void*)(uintptr_t)s->lock,6);return 0;
}
static inline int pmsa_live(struct pmsa_state*s)
{
    if(!s||!s->attempted||s->unknown||s->error)return 0;
    struct pmsl_lock*l=(void*)(uintptr_t)s->lock;struct pmsq_state*q=(void*)(uintptr_t)s->smem;
    return l->smem==s->smem&&l->owner==s->owner&&q->owner==s->owner&&q->opening==s->opening&&pmsl_held(l);
}
static inline bool pmsa_read(void*context,uint32_t offset,void*out,size_t bytes)
{
    struct pmsa_state*s=context;if(!pmsa_live(s)||!out||!bytes||((offset|bytes)&3)||
       offset>=PMSQ_BYTES||bytes>PMSQ_BYTES-offset)return false;
    for(size_t at=0;at<bytes;){unsigned count=(unsigned)(bytes-at);if(count>PMSQ_CHUNK)count=PMSQ_CHUNK;
        const uint8_t*raw=pmsq_read((void*)(uintptr_t)s->smem,offset+(unsigned)at,count);if(!raw)return false;
        pgcd_copy((uint8_t*)out+at,raw,count);at+=count;
    }return pmsa_live(s);
}
static inline int pmsa_prepare(struct pmsa_state*s,struct pmsl_lock*l)
{
    if(!s||!l||!pwmc_zero(s,sizeof(*s))||!pmsl_held(l))return 0;
    struct pmsq_state*q=(void*)(uintptr_t)l->smem;struct pmsc_owner*o=(void*)(uintptr_t)l->owner;
    const struct pweh_result*h=(const void*)(uintptr_t)o->retained;const struct pmsb_result*b=(const void*)(uintptr_t)o->mba;
    if(!pmsi_image_range(h->input.early,&h->map,(uintptr_t)s,sizeof(*s)))return 0;
    const uint64_t at[]={(uintptr_t)l,(uintptr_t)q,(uintptr_t)o,q->namespace,q->images,(uintptr_t)h,(uintptr_t)h->input.early,o->memory,o->mba,b->stage};
    const uint64_t bytes[]={sizeof(*l),sizeof(*q),sizeof(*o),sizeof(struct pmrg_map),sizeof(struct pmli_ledger),sizeof(*h),sizeof(struct pwea_native),sizeof(struct pmmn_native),sizeof(*b),sizeof(struct pmsi_result)};
    for(unsigned n=0;n<10;n++)if(!pwea_disjoint((uintptr_t)s,sizeof(*s),at[n],bytes[n]))return 0;
    s->lock=(uintptr_t)l;s->smem=l->smem;s->owner=l->owner;s->opening=l->opening;s->attempted=1;
    struct polaris_smem_reader reader={pmsa_read,s,PMSQ_BYTES};struct polaris_glink_workspace*w=&s->inventory;
    if(!polaris_smem_inventory(&reader,&w->inventory,&w->smem))return pmsa_fail(s,1);
    unsigned matches=0;
    for(unsigned n=0;n<w->inventory.count;n++){
        const struct polaris_smem_part*p=&w->inventory.parts[n];
        if(p->accessible&&((!p->host0&&p->host1==1)||(!p->host1&&p->host0==1))){s->partition=*p;matches++;}
    }
    const struct polaris_smem_part*p=&s->partition;
    if(matches!=1||p->offset!=0xb9000||p->bytes!=0x7c000||p->cacheline!=32||p->flags||
       p->exclusions[0]||p->exclusions[1]||p->exclusions[2]||p->exclusions[3]||
       (p->uncached_end&7)||(p->cached_begin&7)||!pgl_headers(&reader,p,w,false)||!pgl_headers(&reader,p,w,true))return pmsa_fail(s,1);
    static const unsigned ids[]={428,478,479},sizes[]={340,32,16384};unsigned cursor=p->uncached_end;
    for(unsigned n=0;n<PMSA_ITEMS;n++){
        unsigned id=ids[n];if((w->seen[0][id/8]|w->seen[1][id/8])&(1u<<(id%8)))return pmsa_fail(s,2);
        struct pmsa_item*i=&s->item[n];i->id=id;i->bytes=sizes[n];i->allocated=(i->bytes+7u)&~7u;
        if(cursor>p->cached_begin||16+i->allocated>p->cached_begin-cursor)return pmsa_fail(s,2);
        i->header=p->offset+cursor;i->data=i->header+16;
        uint32_t words[]={0xa5a5u|(id<<16),i->allocated,i->allocated-i->bytes,0};pgcd_copy(i->wire,words,sizeof(words));cursor+=16+i->allocated;
    }
    s->frontier=cursor;pgcd_copy(s->initial_header,w->smem.part_headers[p->index],32);
    pgcd_copy(s->published_header,s->initial_header,32);pgcd_copy(s->published_header+12,&s->frontier,4);
    if(!pmsa_live(s))return pmsa_fail(s,1);
    s->prepared=1;pweh_digest(s,offsetof(struct pmsa_state,event),s->plan_digest);return 1;
}
static inline int pmsa_at(struct pmsa_state*s,struct pmni_translation*t,uint64_t page)
{
    t->page=page;if(!pmsa_live(s)||!pmni_translate(t)||t->page!=page)return 0;
    return t->read_issued==1&&t->read_returned==1&&t->write_issued==1&&t->write_returned==1&&
        t->restore_issued==1&&t->restore_returned==1&&t->saved==t->restored&&
        t->read_par==(UINT64_C(0x4400000000000b00)|page)&&t->write_par==t->read_par&&pmsa_live(s);
}
/* Private range producer: stage1 zeroes exact new payloads, stage2 writes
 * exact16-byte allocation headers, stage3 publishes the exact4-byte frontier. */
static inline int pmsa_write(struct pmsa_state*s,unsigned stage,unsigned item,unsigned offset,unsigned bytes)
{
    if(!pmsa_live(s)||s->pending||s->events==PMSA_EVENTS||stage<1||stage>3||item>=PMSA_ITEMS||!bytes||
       ((offset|bytes)&3)||bytes>4096-(offset&4095))return pmsa_fail(s,3);
    const struct pmsa_item*i=&s->item[item];
    if((stage==1&&(offset<i->data||offset-i->data>i->allocated||bytes>i->allocated-(offset-i->data)))||
       (stage==2&&(offset<i->header||offset-i->header>=16||bytes>16-(offset-i->header)))||
       (stage==3&&(item||offset!=s->partition.offset+12||bytes!=4)))return pmsa_fail(s,3);
    struct pmsq_state*q=(void*)(uintptr_t)s->smem;struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    struct pmsa_delivery*r=&s->event[s->events++];r->address=PMSQ_BASE+offset;r->bytes=bytes;r->stage=stage;r->item=item;r->zero=stage==1;s->pending=s->events;
    uint64_t page=r->address&~UINT64_C(4095);uint8_t hash[32];pweh_digest(s,offsetof(struct pmsa_state,event),hash);
    if(!pgcd_equal(hash,s->plan_digest,32)||!pmsl_check((void*)(uintptr_t)s->lock,&r->lock[0])||
       !pmsq_target(q,&r->node[0],page)||!pmsa_at(s,&r->AT[0],page)||
       !pmsc_mark_effect(o,PMSC_REMOTE))return pmsa_fail(s,3);
    pmsq_order();r->issued=1;
    for(unsigned n=0;n<bytes;n+=4){
        uint32_t value=stage==1?0:stage==2?(uint32_t)pwfi_le(i->wire+offset-i->header+n,4):s->frontier,actual=0;
        s->stores++;r->words++;
        if(!pmsa_store(r->address+n,value,&actual)||actual!=value)return pmsa_fail(s,4);r->verified++;
    }
    pmsq_order();r->returned=1;
    if(!pmsa_at(s,&r->AT[1],page)||!pmsq_target(q,&r->node[1],page)||!pmli_read_equal(&r->node[0],&r->node[1])||
       !pmsl_check((void*)(uintptr_t)s->lock,&r->lock[1])||!pmsa_live(s))return pmsa_fail(s,4);
    r->complete=1;s->pending=0;return 1;
}
static inline int pmsa_publish(struct pmsa_state*s)
{
    if(!pmsa_live(s)||s->prepared!=1||s->pending||s->events||s->complete)return 0;
    uint8_t header[32];if(!pmsa_read(s,s->partition.offset,header,32)||!pgcd_equal(header,s->initial_header,32))return pmsa_fail(s,5);
    for(unsigned n=0;n<PMSA_ITEMS;n++)for(unsigned offset=s->item[n].data,left=s->item[n].allocated;left;){
        unsigned bytes=4096-(offset&4095);if(bytes>left)bytes=left;
        if(!pmsa_write(s,1,n,offset,bytes))return 0;offset+=bytes;left-=bytes;
    }
    for(unsigned n=0;n<PMSA_ITEMS;n++)for(unsigned offset=s->item[n].header,left=16;left;){
        unsigned bytes=4096-(offset&4095);if(bytes>left)bytes=left;
        if(!pmsa_write(s,2,n,offset,bytes))return 0;offset+=bytes;left-=bytes;
    }
    if(!pmsa_write(s,3,0,s->partition.offset+12,4)||!pmsa_read(s,s->partition.offset,header,32)||
       !pgcd_equal(header,s->published_header,32)||!pmsa_live(s))return pmsa_fail(s,5);
    s->complete=1;pweh_digest(s,offsetof(struct pmsa_state,digest),s->digest);return 1;
}
static inline int pmsa_current(struct pmsa_state*s)
{
    if(!s||s->complete!=1||s->unknown||s->error||s->pending)return 0;
    uint8_t hash[32];pweh_digest(s,offsetof(struct pmsa_state,digest),hash);if(!pgcd_equal(hash,s->digest,32))return 0;
    struct pmsl_lock*l=(void*)(uintptr_t)s->lock;struct pmsq_state*q=(void*)(uintptr_t)s->smem;
    if(l->smem!=s->smem||l->owner!=s->owner||l->opening!=s->opening||l->unknown||l->error||
       l->held||l->released!=1||l->events!=PMSL_RECORDS||!pmsq_current(q))return 0;
    pweh_digest(l,offsetof(struct pmsl_lock,digest),hash);return pgcd_equal(hash,l->digest,32);
}
#endif
#endif
