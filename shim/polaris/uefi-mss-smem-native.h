/* Current SmemDxe constructor identity and native Normal-NC reader under the
 * continuous CPU owner. No original Get/Alloc, new mappings or firmware call.
 * This reader is groundwork for the locked allocator/transport, not a TX lease.
 * A synchronous native load can still encounter a fatal external abort. */
#ifndef POLARIS_UEFI_MSS_SMEM_NATIVE_H
#define POLARIS_UEFI_MSS_SMEM_NATIVE_H
#ifndef EFI_XNU_MSS_SMEM_NATIVE_AVAILABLE
#define EFI_XNU_MSS_SMEM_NATIVE_AVAILABLE 0
#endif
#if EFI_XNU_MSS_SMEM_NATIVE_AVAILABLE
#if !EFI_XNU_MSS_RPMH_STATE_AVAILABLE
#error Native SMEM requires the continuous CPU/image/GCD readers
#endif
#include "uefi-mss-rpmh-state.h"
#define PMSQ_BASE UINT64_C(0x86000000)
#define PMSQ_BYTES 0x200000u
#define PMSQ_READS 20u
#define PMSQ_CHUNK 208u
struct pmsq_source {
    struct pmrd_at AT[PWFI_IMAGE_BYTES/4096];
    uint8_t hashes[PWFI_RANGE_COUNT][32];uint32_t count,failed,complete,reserved;
};
struct pmsq_pass {
    struct pmsq_source source[2];struct pmli_read read[PMSQ_READS];
    uint8_t cache[PWFC_CACHE_BYTES];uint32_t reads,complete;
};
struct pmsq_access {
    uint64_t before,after;uint32_t offset,bytes,pages,words,issued,returned,complete,reserved;
    struct pmli_read node[2][2];struct pmrd_at AT[2][2];uint8_t raw[PMSQ_CHUNK];
};
struct pmsq_state {
    uint64_t namespace,images,owner,opening,image;uint8_t namespace_digest[32];
    uint32_t protocol_index,loaded_index,attempted,unknown,error,complete;
    struct pmsq_pass pass[2];struct pwea_core core[2];uint8_t binding_digest[32];
    struct pmsq_access access;uint32_t reads,pending;uint8_t history[32];
};
#if defined(POLARIS_MSS_SMEM_SOFTWARE_PEER)
static int pmsq_word(uint64_t,uint32_t*);
static void pmsq_order(void);
#else
static inline int pmsq_word(uint64_t at,uint32_t*out)
{__asm__ volatile("ldr %w0,[%1]":"=r"(*out):"r"(at):"memory");return 1;}
static inline void pmsq_order(void){__asm__ volatile("dsb sy":::"memory");}
#endif
static inline int pmsq_fail(struct pmsq_state*r,unsigned error)
{r->unknown=1;if(!r->error)r->error=error;return 0;}
static inline int pmsq_live(struct pmsq_state*r)
{
    if(!r||r->unknown||r->error)return 0;struct pmrg_map*g=(void*)(uintptr_t)r->namespace;
    struct pmsc_owner*o=(void*)(uintptr_t)r->owner;
    return g->owner==r->owner&&g->images==r->images&&g->opening==r->opening&&o->opening==r->opening&&
        g->complete==1&&!g->unknown&&!g->error&&pgcd_equal(g->digest,r->namespace_digest,32)&&pmrg_live(g);
}
static inline int pmsq_at(struct pmsq_state*r,struct pmrd_at*t,uint64_t page,uint64_t attributes)
{
    t->page=page;return pmsq_live(r)&&pmrd_translate(t)&&t->page==page&&t->issued==1&&t->returned==1&&
        t->saved==t->restored&&t->par==(attributes|page)&&pmsq_live(r);
}
static inline const uint8_t*pmsq_source_read(struct pmsq_state*r,struct pmsq_pass*p,uint64_t at,unsigned bytes,unsigned heap)
{
    if(p->reads==PMSQ_READS||!pmsq_live(r))return 0;struct pmli_read*q=&p->read[p->reads++];
    struct pmli_ledger*l=(void*)(uintptr_t)r->images;
    if((heap&&!pmli_heap_excluded(&l->pass[1],at,bytes))||!pmli_read_ram(l,q,at,bytes,heap)||!pmsq_live(r))return 0;
    return q->raw;
}
static inline int pmsq_identity(struct pmsq_state*r,struct pmsq_source*s)
{
    for(unsigned n=0;n<PWFI_IMAGE_BYTES/4096;n++)if(!pmsq_at(r,&s->AT[n],r->image+4096*n,UINT64_C(0xff00000000000b80)))return 0;
    if(!pwfi_verify((const void*)(uintptr_t)r->image,r->image,PWFI_IMAGE_BYTES,s->hashes,&s->failed,&s->count)||!pmsq_live(r))return 0;
    s->complete=1;return 1;
}
static inline int pmsq_provider(struct pmsq_state*r,struct pmsq_pass*p)
{
    struct pmli_ledger*l=(void*)(uintptr_t)r->images;struct pmsc_owner*o=(void*)(uintptr_t)r->owner;
    const struct pweh_result*h=(const void*)(uintptr_t)o->retained;const struct pmli_read*old=&l->pass[1].protocol[r->protocol_index];
    const uint8_t*entry=pmsq_source_read(r,p,old->address,72,1);if(!entry||!pgcd_equal(entry,old->raw,72))return 0;
    uint64_t head=old->address+40,link=pwfi_le(entry+40,8);if(link<32||link==head||link!=pwfi_le(entry+48,8))return 0;
    const uint8_t*i=pmsq_source_read(r,p,link-32,88,1);
    if(!i||pwfi_le(i,8)!=0x63666970||pwfi_le(i+32,8)!=head||pwfi_le(i+40,8)!=head||pwfi_le(i+48,8)!=old->address)return 0;
    uint64_t table=pwfi_le(i+56,8);unsigned matches=0;
    for(unsigned n=0;n<l->pass[1].images;n++){
        const struct pmli_read*q=&l->pass[1].image[n].loaded;uint64_t base=pwfi_le(q->raw+64,8);
        if(base>UINT64_MAX-0x7090||base+0x7090!=table)continue;matches++;
        const uint8_t*current=pmsq_source_read(r,p,q->address,96,0);
        if(!current||!pgcd_equal(current,q->raw,96)||pwfi_le(current+72,8)!=PWFI_IMAGE_BYTES||
           pwfi_le(current+80,4)!=3||pwfi_le(current+84,4)!=4||!pmli_range(h,base,PWFI_IMAGE_BYTES,3,4))return 0;
        if(r->image&&(r->image!=base||r->loaded_index!=n))return 0;r->image=base;r->loaded_index=n;
    }
    if(matches!=1||!pmsq_identity(r,&p->source[0]))return 0;
    const uint8_t*t=pmsq_source_read(r,p,table,40,0);
    if(!t||pwfi_le(t,8)!=0x10001||pwfi_le(t+8,8)!=r->image+0x1ca0||pwfi_le(t+16,8)!=r->image+0x1ccc||pwfi_le(t+24,8)||pwfi_le(t+32,8))return 0;
    for(unsigned at=0;at<PWFC_CACHE_BYTES;){
        unsigned bytes=PWFC_CACHE_BYTES-at;if(bytes>96)bytes=96;
        const uint8_t*v=pmsq_source_read(r,p,r->image+PWFC_CACHE_RVA+at,bytes,0);if(!v)return 0;
        pgcd_copy(p->cache+at,v,bytes);at+=bytes;
    }
    if(!pwfc_cache_valid(p->cache,r->image)||pwfi_le(p->cache+20,4)!=0xc0000||
       pwfi_le(p->cache+96,8)!=PMSQ_BASE+0xb9000||pwfi_le(p->cache+104,4)!=0x7c000||
       pwfi_le(p->cache+108,4)!=32||!pmsq_identity(r,&p->source[1]))return 0;
    p->complete=1;return 1;
}
static inline int pmsq_capture(struct pmsq_state*r,struct pmrg_map*g)
{
    if(!r||!g||!pwmc_zero(r,sizeof(*r)))return 0;r->attempted=1;
    if(!pmrg_current(g))return pmsq_fail(r,1);struct pmsc_owner*o=(void*)(uintptr_t)g->owner;
    struct pmli_ledger*l=(void*)(uintptr_t)g->images;const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
    const struct pmsb_result*b=(const void*)(uintptr_t)o->mba;const struct pwea_native*e=h->input.early;
    if(!pmsi_image_range(e,&h->map,(uintptr_t)r,sizeof(*r)))return pmsq_fail(r,1);
    const uint64_t at[]={(uintptr_t)g,(uintptr_t)l,(uintptr_t)o,(uintptr_t)h,(uintptr_t)e,o->memory,o->mba,b->stage};
    const uint64_t bytes[]={sizeof(*g),sizeof(*l),sizeof(*o),sizeof(*h),sizeof(*e),sizeof(struct pmmn_native),sizeof(*b),sizeof(struct pmsi_result)};
    for(unsigned n=0;n<8;n++)if(!pwea_disjoint((uintptr_t)r,sizeof(*r),at[n],bytes[n]))return pmsq_fail(r,1);
    r->namespace=(uintptr_t)g;r->images=g->images;r->owner=g->owner;r->opening=g->opening;pgcd_copy(r->namespace_digest,g->digest,32);
    static const efi_guid guid={0xf4e5c7d0,0xd239,0x47cb,{0xaa,0xcd,0x7f,0x66,0xef,0x76,0x32,0x38}};unsigned matches=0;
    for(unsigned n=0;n<l->pass[1].protocols;n++)if(pgcd_equal(l->pass[1].protocol[n].raw+24,&guid,16)){matches++;r->protocol_index=n;}
    if(matches!=1||!pwea_core_check(e,&r->core[0],&h->map)||!pmsq_provider(r,&r->pass[0])||
       !pmsq_provider(r,&r->pass[1])||r->pass[0].reads!=r->pass[1].reads||
       !pgcd_equal(r->pass[0].cache,r->pass[1].cache,PWFC_CACHE_BYTES))return pmsq_fail(r,2);
    for(unsigned n=0;n<r->pass[0].reads;n++)if(!pmli_read_equal(&r->pass[0].read[n],&r->pass[1].read[n]))return pmsq_fail(r,2);
    if(!pwea_core_check(e,&r->core[1],&h->map)||!pmrg_current(g)||!pmsq_live(r))return pmsq_fail(r,2);
    r->complete=1;pweh_digest(r,offsetof(struct pmsq_state,binding_digest),r->binding_digest);return 1;
}
static inline int pmsq_current(struct pmsq_state*r)
{
    if(!pmsq_live(r)||r->complete!=1)return 0;uint8_t hash[32];pweh_digest(r,offsetof(struct pmsq_state,binding_digest),hash);
    return pgcd_equal(hash,r->binding_digest,32)&&pgcd_equal(r->pass[1].cache,
        (const void*)(uintptr_t)(r->image+PWFC_CACHE_RVA),PWFC_CACHE_BYTES)&&pmsq_live(r);
}
/* Normal-NC is deliberate: own actual CPU0 uses ATTR44/OuterShareable/NS.
 * EFI UC and GCD UC are namespace descriptions, not a Device-AT substitute.
 * A complete unique reserved EFI descriptor and own image/claim exclusions
 * precede the exact selected GCD node comparison. No map changes are made. */
static inline int pmsq_target(struct pmsq_state*r,struct pmli_read*q,uint64_t page)
{
    if(page<PMSQ_BASE||page>=PMSQ_BASE+PMSQ_BYTES||(page&4095)||!pmsq_live(r))return 0;
    struct pmrg_map*g=(void*)(uintptr_t)r->namespace;struct pmli_ledger*l=(void*)(uintptr_t)r->images;
    struct pmsc_owner*o=(void*)(uintptr_t)r->owner;const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
    const struct pwea_native*e=h->input.early;const struct pmmn_native*m=(const void*)(uintptr_t)o->memory;
    unsigned cover=0;
    for(uint64_t off=0;off<h->map.map.bytes;off+=h->map.map.stride){
        const struct efi_memory*d=(const void*)(h->map.data+off);
        if(d->physical>=page+4096||page>=d->physical+d->pages*4096)continue;
        if(d->type||d->virtual_address||d->attributes!=1||d->physical>page||d->physical+d->pages*4096<page+4096)return 0;cover++;
    }
    if(cover!=1||!pmli_heap_excluded(&l->pass[1],page,4096)||
       !pwea_disjoint(page,4096,h->payload,h->payload_bytes)||!pwea_disjoint(page,4096,h->log,h->input.log_bytes))return 0;
    for(unsigned n=0;n<2;n++)if(!pwea_disjoint(page,4096,e->memory.claim[n].requested,e->memory.claim[n].bytes))return 0;
    for(unsigned n=0;n<PMME_CLAIMS;n++)if(!pwea_disjoint(page,4096,m->memory.claim[n].requested,m->memory.claim[n].bytes))return 0;
    for(unsigned n=0;n<g->pass[1].nodes;n++){
        const struct pmli_read*v=&g->pass[1].node[n];uint64_t base=pwfi_le(v->raw+24,8),last=pwfi_le(v->raw+32,8);
        if(base>page||last<page+4095)continue;
        unsigned type=(unsigned)pwfi_le(v->raw+56,4);
        if((type!=1&&type!=2)||!(pwfi_le(v->raw+40,8)&1)||pwfi_le(v->raw+48,8)!=1||
           !pmrg_read(g,q,v->address,80,1)||!pmli_read_equal(v,q))return 0;
        return pmsq_live(r);
    }return 0;
}
/* Output belongs to this reader and is valid only on success until next read.
 * Typed inventory/transport adapters must copy it to their own workspace.
 * Keep last full observation plus chained history instead of unbounded BSS. */
static inline const uint8_t*pmsq_read(struct pmsq_state*r,unsigned offset,unsigned bytes)
{
    if(!r||r->pending||r->reads==65536||!bytes||bytes>PMSQ_CHUNK||((offset|bytes)&3)||
       offset>=PMSQ_BYTES||bytes>PMSQ_BYTES-offset)return 0;
    if(!pmsq_current(r)){pmsq_fail(r,4);return 0;}
    struct pmsq_access*a=&r->access;for(unsigned n=0;n<sizeof(*a);n++)((uint8_t*)a)[n]=0;
    a->offset=offset;a->bytes=bytes;r->pending=1;
    struct pmsc_owner*o=(void*)(uintptr_t)r->owner;a->before=o->last;
    uint64_t start=(PMSQ_BASE+offset)&~UINT64_C(4095),end=PMSQ_BASE+offset+bytes;
    for(uint64_t page=start;page<end;page+=4096){
        unsigned n=a->pages++;if(n==2||!pmsq_target(r,&a->node[0][n],page)||
           !pmsq_at(r,&a->AT[0][n],page,UINT64_C(0x4400000000000b00)))goto fail;
    }
    pmsq_order();a->issued=1;
    for(unsigned at=0;at<bytes;at+=4){uint32_t value;
        if(!pmsq_word(PMSQ_BASE+offset+at,&value))goto fail;pgcd_copy(a->raw+at,&value,4);a->words++;
    }
    pmsq_order();a->returned=1;
    for(unsigned n=0;n<a->pages;n++)if(!pmsq_at(r,&a->AT[1][n],start+4096*n,UINT64_C(0x4400000000000b00))||
        !pmsq_target(r,&a->node[1][n],start+4096*n)||!pmli_read_equal(&a->node[0][n],&a->node[1][n]))goto fail;
    if(a->offset!=offset||a->bytes!=bytes||a->words!=bytes/4||a->pages!=(end-start+4095)/4096||
       r->pending!=1||!pmsq_current(r))goto fail;
    a->after=o->last;a->complete=1;r->reads++;
    struct pwfi_sha256 hash;pwfi_init(&hash);for(unsigned n=0;n<32;n++)pwfi_byte(&hash,r->history[n]);
    for(unsigned n=0;n<sizeof(*a);n++)pwfi_byte(&hash,((const uint8_t*)a)[n]);pwfi_final(&hash,r->history);r->pending=0;return a->raw;
fail:pmsq_fail(r,3);return 0;
}
#endif
#endif
