/* Current own RpmhDxe RAM state under the continuous CPU owner. No provider
 * call, client creation, vote or MMIO. Unlike Core pool objects, this driver's
 * allocations may be4mod8; byte copies and read-only AT preserve that ABI.
 * A quiet RAM graph is necessary evidence, not hardware TCS/EE ownership. */
#ifndef POLARIS_UEFI_MSS_RPMH_STATE_H
#define POLARIS_UEFI_MSS_RPMH_STATE_H
#ifndef EFI_XNU_MSS_RPMH_STATE_AVAILABLE
#define EFI_XNU_MSS_RPMH_STATE_AVAILABLE 0
#endif
#if EFI_XNU_MSS_RPMH_STATE_AVAILABLE
#if !EFI_XNU_MSS_RESOURCE_MAP_AVAILABLE
#error Current RPMh state requires the current CPU/image/GCD producers
#endif
#include "uefi-mss-resource-map.h"
#include "../../tools/polaris-wifi-rpmh-identity.h"
#define PMRD_READS 2048u
#define PMRD_OBJECTS 128u
struct pmrd_at {uint64_t page,saved,par,restored;uint32_t issued,returned;};
struct pmrd_read {
    uint64_t address;uint32_t bytes,pages,heap,issued,returned,reserved;
    struct pmrd_at AT[2];uint8_t raw[96];
};
struct pmrd_identity {
    struct pmrd_at source_AT[PWRPI_IMAGE_BYTES/4096];uint8_t hashes[PWRPI_RANGE_COUNT][32];
    uint32_t source_pages,hash_count,hash_failed,complete;
};
struct pmrd_pass {
    struct pmrd_identity source[2];
    uint32_t reads,active_mask,clients[2],free_requests,cache_rows,complete;
    uint8_t global[0x110],HAL[80],runtime[8+16*24],tcs[192],protocol[200];
    struct pmrd_read read[PMRD_READS];
};
struct pmrd_state {
    uint64_t owner,images,namespace,opening,image;uint32_t protocol_index,loaded_index;
    uint8_t images_digest[32],namespace_digest[32];struct pmrd_pass pass[2];
    uint32_t attempted,unknown,error,complete;uint8_t digest[32];
};
#if defined(POLARIS_MSS_RPMH_SOFTWARE_PEER)
static int pmrd_translate(struct pmrd_at*);
#else
static inline int pmrd_translate(struct pmrd_at*t)
{
    __asm__ volatile("mrs %0,par_el1":"=r"(t->saved)::"memory");t->issued=1;
    __asm__ volatile("at s1e1r,%1; isb; mrs %0,par_el1":"=r"(t->par):"r"(t->page):"memory");
    __asm__ volatile("msr par_el1,%1; isb; mrs %0,par_el1":"=r"(t->restored):"r"(t->saved):"memory");
    t->returned=1;return 1;
}
#endif
static inline int pmrd_fail(struct pmrd_state*r,unsigned e)
{r->unknown=1;if(!r->error)r->error=e;return 0;}
static inline int pmrd_live(struct pmrd_state*r)
{
    struct pmli_ledger*l=(void*)(uintptr_t)r->images;struct pmrg_map*g=(void*)(uintptr_t)r->namespace;
    struct pmsc_owner*o=(void*)(uintptr_t)r->owner;
    return g->owner==r->owner&&g->images==r->images&&o->opening==r->opening&&
        g->complete==1&&!g->error&&!g->unknown&&pgcd_equal(g->digest,r->namespace_digest,32)&&
        pgcd_equal(l->digest,r->images_digest,32)&&pmrg_live(g);
}
static inline int pmrd_at_read(struct pmrd_state*r,struct pmrd_at*t,uint64_t page)
{
    t->page=page;
    return pmrd_live(r)&&pmrd_translate(t)&&t->page==page&&t->issued==1&&t->returned==1&&
        t->saved==t->restored&&t->par==(UINT64_C(0xff00000000000b80)|page)&&pmrd_live(r);
}
/* New heap objects cannot overlap earlier independently mutable objects.
 * An explicit verification read may repeat only an identical prior extent. */
static inline const uint8_t*pmrd_read(struct pmrd_state*r,struct pmrd_pass*p,uint64_t at,unsigned bytes,unsigned heap)
{
    struct pmli_ledger*l=(void*)(uintptr_t)r->images;struct pmsc_owner*o=(void*)(uintptr_t)r->owner;
    const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
    if(!bytes||bytes>96||(at&3)||heap>2||p->reads==PMRD_READS||!pmrd_live(r)||
       !pmli_range(h,at,bytes,heap?4:3,4)||!pwea_disjoint(at,bytes,(uintptr_t)r,sizeof(*r))||
       (heap&&!pmli_heap_excluded(&l->pass[1],at,bytes))){pmrd_fail(r,2);return 0;}
    unsigned repeated=0;
    if(heap)for(unsigned n=0;n<p->reads;n++){
        const struct pmrd_read*q=&p->read[n];if(!q->heap)continue;
        if(!pwea_disjoint(at,bytes,q->address,q->bytes)){
            if(heap!=2||at!=q->address||bytes!=q->bytes){pmrd_fail(r,2);return 0;}repeated=1;
        }
    }
    if(heap==2&&!repeated){pmrd_fail(r,2);return 0;}
    struct pmrd_read*q=&p->read[p->reads++];q->address=at;q->heap=heap;q->issued=1;
    for(uint64_t page=at&~UINT64_C(4095);page<at+bytes;page+=4096){
        if(q->pages==2||!pmrd_at_read(r,&q->AT[q->pages++],page)){pmrd_fail(r,3);return 0;}
    }
    for(unsigned n=0;n<bytes;n++){q->raw[n]=*(const volatile uint8_t*)(uintptr_t)(at+n);q->bytes=n+1;}
    q->returned=1;if(!pmrd_live(r)){pmrd_fail(r,3);return 0;}return q->raw;
}
static inline int pmrd_bulk(struct pmrd_state*r,struct pmrd_pass*p,void*out,uint64_t at,unsigned bytes,unsigned heap)
{
    if(!bytes||bytes>4096||at>UINT64_MAX-bytes)return pmrd_fail(r,2);
    for(unsigned off=0;off<bytes;off+=96){unsigned n=bytes-off;if(n>96)n=96;
        const uint8_t*q=pmrd_read(r,p,at+off,n,heap);if(!q)return 0;pgcd_copy((uint8_t*)out+off,q,n);
    }return 1;
}
static inline int pmrd_source(struct pmrd_state*r,struct pmrd_identity*p)
{
    if(!pwmc_zero(p,sizeof(*p)))return pmrd_fail(r,5);
    for(unsigned n=0;n<PWRPI_IMAGE_BYTES/4096;n++){
        if(!pmrd_at_read(r,&p->source_AT[n],r->image+4096*n))return pmrd_fail(r,5);p->source_pages++;
    }
    if(!pwrpi_verify((const void*)(uintptr_t)r->image,r->image,p->hashes,&p->hash_count,&p->hash_failed)||!pmrd_live(r))
        return pmrd_fail(r,5);
    p->complete=1;return 1;
}
static inline int pmrd_registration(struct pmrd_state*r,struct pmrd_pass*p)
{
    struct pmli_ledger*l=(void*)(uintptr_t)r->images;struct pmsc_owner*o=(void*)(uintptr_t)r->owner;
    const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
    const struct pmli_read*old=&l->pass[1].protocol[r->protocol_index];
    const uint8_t*entry=pmrd_read(r,p,old->address,72,1);if(!entry||!pgcd_equal(entry,old->raw,72))return pmrd_fail(r,4);
    uint64_t head=old->address+40,link=pwfi_le(entry+40,8);
    if(link<32||link==head||link!=pwfi_le(entry+48,8))return pmrd_fail(r,4);
    const uint8_t*interface=pmrd_read(r,p,link-32,88,1);if(!interface)return 0;
    if(pwfi_le(interface,8)!=UINT64_C(0x63666970)||pwfi_le(interface+32,8)!=head||pwfi_le(interface+40,8)!=head||
       pwfi_le(interface+48,8)!=old->address)return pmrd_fail(r,4);
    const uint8_t*handle=pmrd_read(r,p,pwfi_le(interface+24,8),56,1);
    if(!handle||pwfi_le(handle,8)!=UINT64_C(0x6c646e68))return pmrd_fail(r,4);
    uint64_t table=pwfi_le(interface+56,8);unsigned matches=0;
    for(unsigned n=0;n<l->pass[1].images;n++){
        const struct pmli_read*i=&l->pass[1].image[n].loaded;uint64_t base=pwfi_le(i->raw+64,8);
        if(base>UINT64_MAX-0xd0d8||base+0xd0d8!=table)continue;matches++;
        const uint8_t*current=pmrd_read(r,p,i->address,96,0);
        if(!current||!pgcd_equal(current,i->raw,96)||pwfi_le(current+72,8)!=PWRPI_IMAGE_BYTES||
           pwfi_le(current+80,4)!=3||pwfi_le(current+84,4)!=4||
           !pmli_range(h,base,PWRPI_IMAGE_BYTES,3,4))return pmrd_fail(r,4);
        if(r->image&&(r->image!=base||r->loaded_index!=n))return pmrd_fail(r,4);r->image=base;r->loaded_index=n;
    }
    if(matches!=1)return pmrd_fail(r,4);
    if(!pmrd_source(r,&p->source[0])||!pmrd_bulk(r,p,p->protocol,table,200,0))return pmrd_fail(r,5);
    return 1;
}
static inline int pmrd_driver(struct pmrd_state*r,struct pmrd_pass*p)
{
    if(!pmrd_bulk(r,p,p->global,r->image+0xd2e8,0x110,0)||pwfi_le(p->global,4)!=1||
       !pmrd_bulk(r,p,p->HAL,r->image+0xd208,80,0)||!pmrd_bulk(r,p,p->runtime,r->image+0xd538,sizeof(p->runtime),0))return pmrd_fail(r,6);
    const uint8_t*root=pmrd_read(r,p,r->image+0xb100,8,0);if(!root)return 0;
    const uint8_t*config=pmrd_read(r,p,pwfi_le(root,8),40,0);if(!config)return 0;
    const uint8_t*row=pmrd_read(r,p,pwfi_le(config+32,8),48,0);if(!row)return 0;
    if(pwfi_le(config,4)!=1||pwfi_le(row,4)!=2||pwfi_le(row+4,4)!=2||pwfi_le(row+20,4)||
       pwfi_le(row+24,4)!=8||pwfi_le(row+28,4)!=16||pwfi_le(row+32,4)!=1)return pmrd_fail(r,6);
    const uint8_t*mp=pmrd_read(r,p,pwfi_le(row+40,8),8,0);if(!mp)return 0;
    const uint8_t*mode=pmrd_read(r,p,pwfi_le(mp,8),24,0);if(!mode)return 0;
    unsigned active=(unsigned)pwfi_le(mode,4);if(!active||active>8)return pmrd_fail(r,6);p->active_mask=(1u<<active)-1;
    if(pwfi_le(p->HAL+0x30,4)!=1||pwfi_le(p->HAL+0x20,4)!=2||p->runtime[0]!=1||pwfi_le(p->runtime+4,4)!=1||
       pwfi_le(p->runtime+48+24,4)!=8||pwfi_le(p->runtime+48+28,4)!=16)return pmrd_fail(r,6);
    unsigned matches=0;
    for(unsigned n=0;n<16;n++){
        const uint8_t*q=p->runtime+24*n;
        if(q[20]==1&&pwfi_le(q+12,4)==0x179c0000&&pwfi_le(q+16,4)==2){if(n!=2)return pmrd_fail(r,6);matches++;}
    }if(matches!=1)return pmrd_fail(r,6);
    const uint8_t*qp=pmrd_read(r,p,pwfi_le(p->global+16,8),8,1);if(!qp)return 0;
    const uint8_t*qs=pmrd_read(r,p,pwfi_le(qp,8),48,1);if(!qs||pwfi_le(qs,4)!=16)return pmrd_fail(r,7);
    const uint8_t*free=0;
    for(unsigned n=0;n<5;n++){
        const uint8_t*q=pmrd_read(r,p,pwfi_le(qs+8+8*n,8),40,1);if(!q)return 0;
        unsigned count=(unsigned)pwfi_le(q+4,4);
        if(pwfi_le(q,4)!=40||count>PMRD_OBJECTS||(n!=2&&count)||(!count&&(pwfi_le(q+8,8)||pwfi_le(q+16,8))))return pmrd_fail(r,7);
        if(n==2)free=q;
    }
    uint64_t cursor=pwfi_le(free+8,8);unsigned count=(unsigned)pwfi_le(free+4,4);uint8_t commands[128];
    for(unsigned n=0;n<count;n++){
        uint64_t address=cursor;const uint8_t*q=pmrd_read(r,p,cursor,48,1);if(!q)return 0;
        if(!pmrd_bulk(r,p,commands,pwfi_le(q,8),128,1))return 0;
        cursor=pwfi_le(q+40,8);p->free_requests++;
        if(n+1==count&&(cursor||address!=pwfi_le(free+16,8)))return pmrd_fail(r,7);
    }if(cursor)return pmrd_fail(r,7);
    const uint8_t*tp=pmrd_read(r,p,pwfi_le(p->global+0xf8,8),8,1);if(!tp)return 0;
    if(!pmrd_bulk(r,p,p->tcs,pwfi_le(tp,8),192,1))return 0;
    const uint8_t*index=pmrd_read(r,p,pwfi_le(p->global+0x100,8),4,1);if(!index||pwfi_le(index,4))return pmrd_fail(r,7);
    for(unsigned n=0;n<8;n++){
        const uint8_t*t=p->tcs+24*n;
        if(pwfi_le(t,4)!=n||pwfi_le(t+4,4)!=(n<active?0u:3u)||pwfi_le(t+16,8))return pmrd_fail(r,7);
    }return 1;
}
static inline int pmrd_clients(struct pmrd_state*r,struct pmrd_pass*p)
{
    const uint8_t*pool=pmrd_read(r,p,pwfi_le(p->global+24,8),16,1);if(!pool)return 0;
    for(unsigned side=0;side<2;side++){
        const uint8_t*list=pmrd_read(r,p,pwfi_le(pool+8*side,8),24,1);if(!list)return 0;
        unsigned count=(unsigned)pwfi_le(list+4,4);uint64_t cursor=pwfi_le(list+8,8),tail=pwfi_le(list+16,8);
        if(pwfi_le(list,4)!=80||count>PMRD_OBJECTS||(!count&&(cursor||tail)))return pmrd_fail(r,8);
        for(unsigned n=0;n<count;n++){
            uint64_t address=cursor;const uint8_t*client=pmrd_read(r,p,cursor,88,1);if(!client)return 0;
            if(pwfi_le(client,4)!=2)return pmrd_fail(r,8);
            if(!side){
                if(pwfi_le(client+0x38,4)||pwfi_le(client+0x34,4)!=UINT32_MAX)return pmrd_fail(r,8);
                for(unsigned j=0;j<4;j++){
                    const uint8_t*q=pmrd_read(r,p,pwfi_le(client+0x10+8*j,8),24,1);if(!q)return 0;
                    unsigned entries=(unsigned)pwfi_le(q+4,4);
                    if(pwfi_le(q,4)!=(j<2?16u:24u)||entries>PMRD_OBJECTS||(j!=1&&entries)||
                       (!entries&&(pwfi_le(q+8,8)||pwfi_le(q+16,8)))||
                       (entries&&(!pwfi_le(q+8,8)||!pwfi_le(q+16,8))))return pmrd_fail(r,8);
                }
            }
            cursor=pwfi_le(client+80,8);p->clients[side]++;
            if(n+1==count&&(cursor||address!=tail))return pmrd_fail(r,8);
        }if(cursor)return pmrd_fail(r,8);
    }return 1;
}
static inline int pmrd_cache(struct pmrd_state*r,struct pmrd_pass*p)
{
    unsigned count=(unsigned)pwfi_le(p->global+4,4);uint64_t base=pwfi_le(p->global+8,8),previous=0;
    if(count>PMRD_OBJECTS||(!count&&base)||(count&&!base)||base>UINT64_MAX-24u*count)return pmrd_fail(r,9);
    for(unsigned n=0;n<count;n++){
        const uint8_t*row=pmrd_read(r,p,base+24*n,24,1);if(!row)return 0;
        uint64_t address=pwfi_le(row,4);if(!address||address<=previous)return pmrd_fail(r,9);previous=address;
        uint64_t state=pwfi_le(row+8,8);
        if(state){const uint8_t*q=pmrd_read(r,p,state,72,1);if(!q)return 0;
            if(pwfi_le(q,4)!=2||pwfi_le(q+4,4)||q[0x10]>1||q[0x1c]>1||pwfi_le(q+0x40,8))return pmrd_fail(r,9);
        }p->cache_rows++;
    }return 1;
}
static inline int pmrd_capture(struct pmrd_state*r,struct pmrg_map*g)
{
    if(!r||!g||!pwmc_zero(r,sizeof(*r)))return 0;r->attempted=1;
    if(!pmrg_current(g))return pmrd_fail(r,1);
    struct pmsc_owner*o=(void*)(uintptr_t)g->owner;struct pmli_ledger*l=(void*)(uintptr_t)g->images;
    const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
    if(o->effects||!pmsi_image_range(h->input.early,&h->map,(uintptr_t)r,sizeof(*r))||
       !pwea_disjoint((uintptr_t)r,sizeof(*r),(uintptr_t)g,sizeof(*g))||
       !pwea_disjoint((uintptr_t)r,sizeof(*r),(uintptr_t)l,sizeof(*l))||
       !pwea_disjoint((uintptr_t)r,sizeof(*r),(uintptr_t)o,sizeof(*o)))return pmrd_fail(r,1);
    const struct pmsb_result*bsource=(const void*)(uintptr_t)o->mba;const struct pwea_native*e=h->input.early;
    const uint64_t bases[]={(uintptr_t)h,(uintptr_t)e,o->memory,o->mba,bsource->stage,e->native_address,e->image_address};
    const uint64_t sizes[]={sizeof(*h),sizeof(*e),sizeof(struct pmmn_native),sizeof(*bsource),sizeof(struct pmsi_result),4,sizeof(e->image)};
    for(unsigned n=0;n<7;n++)if(!pwea_disjoint((uintptr_t)r,sizeof(*r),bases[n],sizes[n]))return pmrd_fail(r,1);
    r->owner=g->owner;r->images=g->images;r->namespace=(uintptr_t)g;r->opening=g->opening;
    pgcd_copy(r->images_digest,l->digest,32);pgcd_copy(r->namespace_digest,g->digest,32);
    static const efi_guid guid={0xe1d0b573,0xf29f,0x495d,{0x93,0x52,0xca,0x0d,0xd4,0x2a,0x0a,0x74}};unsigned matches=0;
    for(unsigned n=0;n<l->pass[1].protocols;n++)if(pgcd_equal(l->pass[1].protocol[n].raw+24,&guid,16)){matches++;r->protocol_index=n;}
    if(matches!=1||!pmsc_checkpoint(o))return pmrd_fail(r,1);r->unknown=1;
    for(unsigned pass=0;pass<2;pass++){
        struct pmrd_pass*p=&r->pass[pass];
        if(!pmrd_registration(r,p)||!pmrd_driver(r,p)||!pmrd_clients(r,p)||!pmrd_cache(r,p)||
           !pmrd_source(r,&p->source[1])||!pmrd_live(r))return 0;
        p->complete=1;
    }
    const struct pmrd_pass*a=&r->pass[0],*b=&r->pass[1];
    if(a->reads!=b->reads||a->active_mask!=b->active_mask||a->clients[0]!=b->clients[0]||a->clients[1]!=b->clients[1]||
       a->free_requests!=b->free_requests||a->cache_rows!=b->cache_rows)return pmrd_fail(r,10);
    for(unsigned n=0;n<a->reads;n++){
        const struct pmrd_read*x=&a->read[n],*y=&b->read[n];
        if(x->address!=y->address||x->bytes!=y->bytes||x->heap!=y->heap||!pgcd_equal(x->raw,y->raw,sizeof(x->raw)))return pmrd_fail(r,10);
    }
    if(!pmrg_current(g)||!pmsc_checkpoint(o)||!pmrd_live(r))return pmrd_fail(r,10);
    r->unknown=0;r->complete=1;pweh_digest(r,offsetof(struct pmrd_state,digest),r->digest);return 1;
}
static inline int pmrd_current(struct pmrd_state*r,struct pmrg_map*g)
{
    if(!r||!g||r->namespace!=(uintptr_t)g||r->complete!=1||r->unknown||r->error||
       r->pass[0].complete!=1||r->pass[1].complete!=1)return 0;
    uint8_t hash[32];pweh_digest(r,offsetof(struct pmrd_state,digest),hash);
    return pgcd_equal(hash,r->digest,32)&&pmrg_current(g)&&pmrd_live(r);
}
#endif
#endif
