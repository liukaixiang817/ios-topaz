/* Independent current CmdDb capture for the continuous MSS owner. No original
 * getter/query, old diagnostic ticket, Device read or power request. Default
 * OFF. The exact own cached/platform pointer and current WB RAM namespace
 * are required before each database page is copied. */
#ifndef POLARIS_UEFI_MSS_CMDDB_H
#define POLARIS_UEFI_MSS_CMDDB_H
#ifndef EFI_XNU_MSS_CMDDB_AVAILABLE
#define EFI_XNU_MSS_CMDDB_AVAILABLE 0
#endif
#if EFI_XNU_MSS_CMDDB_AVAILABLE
#if !EFI_XNU_MSS_RPMH_STATE_AVAILABLE
#error MSS CmdDb requires the current CPU/image/GCD and read-only RAM leaves
#endif
#include "uefi-mss-rpmh-state.h"
#include "../../tools/polaris-wifi-cmddb-identity.h"
#include "../../tools/polaris-mss-cmddb-resources.h"
#define PMDC_BASE UINT64_C(0x85fe0000)
#define PMDC_PAGES (PMDC_BYTES/4096)
#define PMDC_READS 16u
struct pmdc_identity {
    struct pmrd_at AT[PWCDI_IMAGE_BYTES/4096];uint8_t hashes[PWCDI_RANGE_COUNT][32];
    uint32_t pages,hash_count,hash_failed,complete;
};
struct pmdc_page {struct pmli_read node[2];struct pmrd_at AT;uint32_t index,words,complete,reserved;};
struct pmdc_pass {
    struct pmdc_identity source[2];struct pmrd_read read[PMDC_READS];struct pmdc_page page[PMDC_PAGES];
    uint32_t reads,pages,complete,reserved;uint8_t raw[PMDC_BYTES];struct pmdc_resource resource[PMDC_RESOURCES];
};
struct pmdc_state {
    uint64_t namespace,images,owner,opening,image;uint8_t namespace_digest[32];
    uint32_t protocol_index,loaded_index,attempted,unknown,error,complete;
    struct pmdc_pass pass[2];uint8_t digest[32];
};
#if defined(POLARIS_MSS_CMDDB_SOFTWARE_PEER)
static int pmdc_word(uint64_t,uint64_t*);
#else
static inline int pmdc_word(uint64_t at,uint64_t*out)
{*out=*(const volatile uint64_t*)(uintptr_t)at;return 1;}
#endif
static inline int pmdc_fail(struct pmdc_state*r,unsigned error)
{r->unknown=1;if(!r->error)r->error=error;return 0;}
static inline int pmdc_live(struct pmdc_state*r)
{
    /* Read-only revalidation remains usable while our continuous parent
     * holds power. A new initial capture still explicitly requires effects0. */
    struct pmrg_map*g=(void*)(uintptr_t)r->namespace;
    return g->complete==1&&!g->unknown&&!g->error&&g->owner==r->owner&&g->images==r->images&&
        g->opening==r->opening&&pgcd_equal(g->digest,r->namespace_digest,32)&&pmrg_live(g);
}
static inline int pmdc_at(struct pmdc_state*r,struct pmrd_at*t,uint64_t page)
{
    t->page=page;
    return pmdc_live(r)&&pmrd_translate(t)&&t->page==page&&t->issued==1&&t->returned==1&&t->saved==t->restored&&
        t->par==(UINT64_C(0xff00000000000b80)|page)&&pmdc_live(r);
}
static inline const uint8_t*pmdc_read(struct pmdc_state*r,struct pmdc_pass*p,uint64_t at,unsigned bytes,unsigned heap)
{
    struct pmli_ledger*l=(void*)(uintptr_t)r->images;struct pmsc_owner*o=(void*)(uintptr_t)r->owner;
    const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
    if(!bytes||bytes>96||(at&7)||heap>1||p->reads==PMDC_READS||!pmdc_live(r)||
       !pmli_range(h,at,bytes,heap?4:3,4)||!pwea_disjoint(at,bytes,(uintptr_t)r,sizeof(*r))||
       (heap&&!pmli_heap_excluded(&l->pass[1],at,bytes))){pmdc_fail(r,2);return 0;}
    if(heap)for(unsigned n=0;n<p->reads;n++)if(p->read[n].heap&&!pwea_disjoint(at,bytes,p->read[n].address,p->read[n].bytes)){
        pmdc_fail(r,2);return 0;
    }
    struct pmrd_read*q=&p->read[p->reads++];q->address=at;q->heap=heap;q->issued=1;
    for(uint64_t page=at&~UINT64_C(4095);page<at+bytes;page+=4096)
        if(q->pages==2||!pmdc_at(r,&q->AT[q->pages++],page)){pmdc_fail(r,3);return 0;}
    for(unsigned n=0;n<bytes;n++){q->raw[n]=*(const volatile uint8_t*)(uintptr_t)(at+n);q->bytes=n+1;}
    q->returned=1;if(!pmdc_live(r)){pmdc_fail(r,3);return 0;}return q->raw;
}
static inline int pmdc_source(struct pmdc_state*r,struct pmdc_identity*s)
{
    if(!pwmc_zero(s,sizeof(*s)))return pmdc_fail(r,4);
    for(unsigned n=0;n<PWCDI_IMAGE_BYTES/4096;n++){
        if(!pmdc_at(r,&s->AT[n],r->image+4096*n))return pmdc_fail(r,4);s->pages++;
    }
    if(!pwcdi_verify((const void*)(uintptr_t)r->image,r->image,s->hashes,&s->hash_count,&s->hash_failed)||!pmdc_live(r))return pmdc_fail(r,4);
    s->complete=1;return 1;
}
static inline int pmdc_provider(struct pmdc_state*r,struct pmdc_pass*p)
{
    struct pmli_ledger*l=(void*)(uintptr_t)r->images;struct pmsc_owner*o=(void*)(uintptr_t)r->owner;
    const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
    const struct pmli_read*old=&l->pass[1].protocol[r->protocol_index];
    const uint8_t*entry=pmdc_read(r,p,old->address,72,1);if(!entry||!pgcd_equal(entry,old->raw,72))return pmdc_fail(r,4);
    uint64_t head=old->address+40,link=pwfi_le(entry+40,8);
    if(link<32||link==head||link!=pwfi_le(entry+48,8))return pmdc_fail(r,4);
    const uint8_t*i=pmdc_read(r,p,link-32,88,1);if(!i)return 0;
    if(pwfi_le(i,8)!=UINT64_C(0x63666970)||pwfi_le(i+32,8)!=head||pwfi_le(i+40,8)!=head||pwfi_le(i+48,8)!=old->address)return pmdc_fail(r,4);
    const uint8_t*handle=pmdc_read(r,p,pwfi_le(i+24,8),56,1);
    if(!handle||pwfi_le(handle,8)!=UINT64_C(0x6c646e68))return pmdc_fail(r,4);
    uint64_t table=pwfi_le(i+56,8);unsigned matches=0;
    for(unsigned n=0;n<l->pass[1].images;n++){
        const struct pmli_read*q=&l->pass[1].image[n].loaded;uint64_t base=pwfi_le(q->raw+64,8);
        if(base>UINT64_MAX-0x5088||base+0x5088!=table)continue;matches++;
        const uint8_t*current=pmdc_read(r,p,q->address,96,0);
        if(!current||!pgcd_equal(current,q->raw,96)||pwfi_le(current+72,8)!=PWCDI_IMAGE_BYTES||
           pwfi_le(current+80,4)!=3||pwfi_le(current+84,4)!=4||!pmli_range(h,base,PWCDI_IMAGE_BYTES,3,4))return pmdc_fail(r,4);
        if(r->image&&(r->image!=base||r->loaded_index!=n))return pmdc_fail(r,4);r->image=base;r->loaded_index=n;
    }
    if(matches!=1||!pmdc_source(r,&p->source[0]))return pmdc_fail(r,4);
    const uint8_t*t=pmdc_read(r,p,table,72,0);if(!t||pwfi_le(t,8)!=0x10000)return pmdc_fail(r,4);
    static const unsigned functions[]={0x1878,0x18cc,0x1914,0x195c,0x19a8,0x19f0,0x1a38,0x1a90};
    for(unsigned n=0;n<8;n++)if(pwfi_le(t+8+8*n,8)!=r->image+functions[n])return pmdc_fail(r,4);
    const uint8_t*globals=pmdc_read(r,p,r->image+0x5158,72,0);
    return globals&&pwfi_le(globals,8)==PMDC_BASE&&pwfi_le(globals+64,8)==PMDC_BASE?1:pmdc_fail(r,4);
}
static inline int pmdc_ram(struct pmdc_state*r,uint64_t at)
{
    struct pmsc_owner*o=(void*)(uintptr_t)r->owner;struct pmli_ledger*l=(void*)(uintptr_t)r->images;
    const struct pweh_result*h=(const void*)(uintptr_t)o->retained;const struct pwea_native*e=h->input.early;
    const struct pmmn_native*m=(const void*)(uintptr_t)o->memory;
    if(at<PMDC_BASE||at>=PMDC_BASE+PMDC_BYTES||(at&4095)||!pmli_range(h,at,4096,0,4)||
       !pmli_heap_excluded(&l->pass[1],at,4096)||!pwea_disjoint(at,4096,h->payload,h->payload_bytes)||
       !pwea_disjoint(at,4096,h->log,h->input.log_bytes))return 0;
    for(uint64_t off=0;off<h->map.map.bytes;off+=h->map.map.stride){
        const struct efi_memory*d=(const void*)(h->map.data+off);
        if(d->physical<at+4096&&at<d->physical+d->pages*4096&&
           ((d->type!=0&&d->type!=4)||d->virtual_address||d->attributes!=8))return 0;
    }
    for(unsigned n=0;n<2;n++)if(!pwea_disjoint(at,4096,e->memory.claim[n].requested,e->memory.claim[n].bytes))return 0;
    for(unsigned n=0;n<PMME_CLAIMS;n++)if(!pwea_disjoint(at,4096,m->memory.claim[n].requested,m->memory.claim[n].bytes))return 0;
    return pmdc_live(r);
}
static inline int pmdc_target(struct pmdc_state*r,struct pmdc_page*p,uint64_t at,unsigned slot)
{
    struct pmrg_map*g=(void*)(uintptr_t)r->namespace;
    if(slot>1||!pmdc_ram(r,at))return pmdc_fail(r,5);
    for(unsigned n=0;n<g->pass[1].nodes;n++){
        const struct pmli_read*q=&g->pass[1].node[n];uint64_t base=pwfi_le(q->raw+24,8),end=pwfi_le(q->raw+32,8);
        if(base>at||end<at+4095)continue;
        if((slot&&p->index!=n)||end-base==UINT64_MAX||pwfi_le(q->raw+56,4)!=2||
           !(pwfi_le(q->raw+40,8)&8)||pwfi_le(q->raw+48,8)!=8||!pmrg_read(g,&p->node[slot],q->address,80,1))return pmdc_fail(r,5);
        if(!pmli_read_equal(q,&p->node[slot])){pmrg_fail(g,5);return pmdc_fail(r,5);}p->index=n;return 1;
    }return pmdc_fail(r,5);
}
static inline int pmdc_capture(struct pmdc_state*r,struct pmrg_map*g)
{
    if(!r||!g||!pwmc_zero(r,sizeof(*r)))return 0;r->attempted=1;
    if(!pmrg_current(g))return pmdc_fail(r,1);
    struct pmsc_owner*o=(void*)(uintptr_t)g->owner;struct pmli_ledger*l=(void*)(uintptr_t)g->images;
    const struct pweh_result*h=(const void*)(uintptr_t)o->retained;const struct pwea_native*e=h->input.early;
    const struct pmsb_result*b=(const void*)(uintptr_t)o->mba;
    if(o->effects||!pmsi_image_range(e,&h->map,(uintptr_t)r,sizeof(*r)))return pmdc_fail(r,1);
    const uint64_t bases[]={(uintptr_t)g,(uintptr_t)l,(uintptr_t)o,(uintptr_t)h,(uintptr_t)e,o->memory,o->mba,b->stage,e->native_address,e->image_address};
    const uint64_t sizes[]={sizeof(*g),sizeof(*l),sizeof(*o),sizeof(*h),sizeof(*e),sizeof(struct pmmn_native),sizeof(*b),sizeof(struct pmsi_result),4,sizeof(e->image)};
    for(unsigned n=0;n<10;n++)if(!pwea_disjoint((uintptr_t)r,sizeof(*r),bases[n],sizes[n]))return pmdc_fail(r,1);
    r->namespace=(uintptr_t)g;r->images=g->images;r->owner=g->owner;r->opening=g->opening;pgcd_copy(r->namespace_digest,g->digest,32);
    static const efi_guid guid={0x1c34f691,0xd33d,0x4e14,{0xb8,0xf8,0x32,0xc6,0xc0,0x29,0xe9,0x5b}};unsigned matches=0;
    for(unsigned n=0;n<l->pass[1].protocols;n++)if(pgcd_equal(l->pass[1].protocol[n].raw+24,&guid,16)){matches++;r->protocol_index=n;}
    if(matches!=1||!pmsc_checkpoint(o))return pmdc_fail(r,1);r->unknown=1;
    for(unsigned pass=0;pass<2;pass++){
        struct pmdc_pass*p=&r->pass[pass];if(!pmdc_provider(r,p))return 0;
        for(unsigned n=0;n<PMDC_PAGES;n++){
            struct pmdc_page*q=&p->page[n];uint64_t at=PMDC_BASE+4096*n;
            if(!pmdc_target(r,q,at,0)||!pmdc_at(r,&q->AT,at))return pmdc_fail(r,5);
            for(unsigned j=0;j<512;j++){
                uint64_t word;if(!pmdc_word(at+8*j,&word))return pmdc_fail(r,6);
                pgcd_copy(p->raw+4096*n+8*j,&word,8);q->words++;
            }
            if(!pmdc_target(r,q,at,1))return 0;q->complete=1;p->pages++;
        }
        const uint8_t*globals=pmdc_read(r,p,r->image+0x5158,72,0);
        if(!globals||pwfi_le(globals,8)!=PMDC_BASE||pwfi_le(globals+64,8)!=PMDC_BASE||
           !pmdc_source(r,&p->source[1])||!pmdc_select(p->raw,p->resource)||!pmdc_live(r))return pmdc_fail(r,7);
        p->complete=1;
    }
    const struct pmdc_pass*a=&r->pass[0],*z=&r->pass[1];
    if(a->reads!=z->reads||!pgcd_equal(a->raw,z->raw,PMDC_BYTES)||!pgcd_equal(a->resource,z->resource,sizeof(a->resource)))return pmdc_fail(r,8);
    for(unsigned n=0;n<a->reads;n++){
        const struct pmrd_read*x=&a->read[n],*y=&z->read[n];
        if(x->address!=y->address||x->bytes!=y->bytes||x->heap!=y->heap||!pgcd_equal(x->raw,y->raw,sizeof(x->raw)))return pmdc_fail(r,8);
    }
    if(!pmrg_current(g)||!pmsc_checkpoint(o)||!pmdc_live(r))return pmdc_fail(r,8);
    r->unknown=0;r->complete=1;pweh_digest(r,offsetof(struct pmdc_state,digest),r->digest);return 1;
}
static inline int pmdc_current(struct pmdc_state*r,struct pmrg_map*g)
{
    if(!r||!g||r->namespace!=(uintptr_t)g||r->complete!=1||r->unknown||r->error||r->pass[0].complete!=1||r->pass[1].complete!=1)return 0;
    uint8_t hash[32];pweh_digest(r,offsetof(struct pmdc_state,digest),hash);
    return pgcd_equal(hash,r->digest,32)&&pmrg_current(g)&&pmdc_live(r);
}
#endif
#endif
