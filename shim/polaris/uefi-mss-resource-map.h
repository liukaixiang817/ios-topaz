/* Current own-Core GCD namespace for the continuous MSS owner. Independent
 * of the old CmdDb-only pgns scope. Read-only RAM, never an original getter
 * return or a DRV2/EE/VMID permission. Device translation and exact pending
 * native access remain separate requirements at the real parent boundary. */
#ifndef POLARIS_UEFI_MSS_RESOURCE_MAP_H
#define POLARIS_UEFI_MSS_RESOURCE_MAP_H
#ifndef EFI_XNU_MSS_RESOURCE_MAP_AVAILABLE
#define EFI_XNU_MSS_RESOURCE_MAP_AVAILABLE 0
#endif
#if EFI_XNU_MSS_RESOURCE_MAP_AVAILABLE
#if !EFI_XNU_MSS_IMAGE_LEDGER_AVAILABLE
#error MSS resource namespace requires the current complete image ledger
#endif
#include "uefi-mss-image-ledger.h"
#define PMRG_NODES 512u
#define PMRG_HEAD 0x1bd60u
#define PMRG_LOCK 0x1bd48u
#define PMRG_TEMPLATE 0x1bd70u
struct pmrg_pass {
    struct pmli_read head[2],lock[2],template[2],node[PMRG_NODES];
    uint32_t nodes,complete;
};
struct pmrg_map {
    uint64_t owner,images,opening,core;
    uint8_t images_digest[32],head[16],lock[24],template[80];
    struct pmrg_pass pass[2];
    uint32_t attempted,unknown,error,complete;uint8_t digest[32];
};
struct pmrg_target {
    uint64_t page,before,after;struct pgcd_descriptor descriptor;
    struct pmli_read node;uint32_t index,attempted,unknown,complete;
};
static inline int pmrg_fail(struct pmrg_map*r,unsigned error)
{r->unknown=1;if(!r->error)r->error=error;return 0;}
static inline int pmrg_live(struct pmrg_map*r)
{
    struct pmli_ledger*l=(void*)(uintptr_t)r->images;
    struct pmsc_owner*o=(void*)(uintptr_t)r->owner;
    return l->owner==r->owner&&l->opening==r->opening&&o->opening==r->opening&&
        l->complete==1&&!l->unknown&&!l->error&&pgcd_equal(l->digest,r->images_digest,32)&&pmli_live(l)&&
        pgcd_equal(r->head,(const void*)(uintptr_t)(r->core+PMRG_HEAD),16)&&
        pgcd_equal(r->lock,(const void*)(uintptr_t)(r->core+PMRG_LOCK),24)&&
        pgcd_equal(r->template,(const void*)(uintptr_t)(r->core+PMRG_TEMPLATE),80);
}
static inline int pmrg_read(struct pmrg_map*r,struct pmli_read*q,uint64_t at,unsigned bytes,unsigned heap)
{
    struct pmli_ledger*l=(void*)(uintptr_t)r->images;
    if(!pmrg_live(r)||(heap&&!pmli_heap_excluded(&l->pass[1],at,bytes))||
       !pmli_read_ram(l,q,at,bytes,heap)||!pmrg_live(r))return pmrg_fail(r,2);
    return 1;
}
static inline int pmrg_roots(struct pmrg_map*r,struct pmrg_pass*p,unsigned slot)
{
    return pmrg_read(r,&p->head[slot],r->core+PMRG_HEAD,16,0)&&
        pmrg_read(r,&p->lock[slot],r->core+PMRG_LOCK,24,0)&&
        pmrg_read(r,&p->template[slot],r->core+PMRG_TEMPLATE,80,0);
}
static inline int pmrg_capture(struct pmrg_map*r,struct pmli_ledger*l,struct pmsc_owner*o)
{
    if(!r||!l||!o||!pwmc_zero(r,sizeof(*r)))return 0;r->attempted=1;
    if(o->effects||!pmli_current(l,o)||!pmsc_bound(o))return pmrg_fail(r,1);
    const struct pweh_result*h=(const void*)(uintptr_t)o->retained;const struct pwea_native*e=h->input.early;
    const struct pmsb_result*b=(const void*)(uintptr_t)o->mba;
    if(!pmsi_image_range(e,&h->map,(uintptr_t)r,sizeof(*r)))return pmrg_fail(r,1);
    const uint64_t base[]={(uintptr_t)o,(uintptr_t)l,(uintptr_t)h,(uintptr_t)e,o->memory,o->mba,b->stage};
    const uint64_t size[]={sizeof(*o),sizeof(*l),sizeof(*h),sizeof(*e),sizeof(struct pmmn_native),sizeof(*b),sizeof(struct pmsi_result)};
    for(unsigned n=0;n<7;n++)if(!pwea_disjoint((uintptr_t)r,sizeof(*r),base[n],size[n]))return pmrg_fail(r,1);
    r->owner=(uintptr_t)o;r->images=(uintptr_t)l;r->opening=o->opening;r->core=l->core;
    pgcd_copy(r->images_digest,l->digest,32);
    if(!pmsc_checkpoint(o))return pmrg_fail(r,1);
    pgcd_copy(r->head,(const void*)(uintptr_t)(r->core+PMRG_HEAD),16);
    pgcd_copy(r->lock,(const void*)(uintptr_t)(r->core+PMRG_LOCK),24);
    pgcd_copy(r->template,(const void*)(uintptr_t)(r->core+PMRG_TEMPLATE),80);
    if(pwfi_le(r->lock,8)!=16||pwfi_le(r->lock+8,8)>16||pwfi_le(r->lock+16,8)!=1||
       pwfi_le(r->template,8)!=UINT64_C(0x6d646367)||!pwmc_zero(r->template+8,72)||!pmrg_live(r))return pmrg_fail(r,1);
    r->unknown=1;
    for(unsigned pass=0;pass<2;pass++){
        struct pmrg_pass*p=&r->pass[pass];uint64_t head=r->core+PMRG_HEAD,previous=head,cursor=pwfi_le(r->head,8),last=0;
        if(!pmrg_roots(r,p,0))return 0;
        while(cursor!=head){
            if(p->nodes==PMRG_NODES||cursor<8||(cursor&7))return pmrg_fail(r,3);
            struct pmli_read*q=&p->node[p->nodes];if(!pmrg_read(r,q,cursor-8,80,1))return 0;
            for(unsigned j=0;j<p->nodes;j++)if(!pmli_distinct(q,&p->node[j]))return pmrg_fail(r,3);
            uint64_t base=pwfi_le(q->raw+24,8),end=pwfi_le(q->raw+32,8);
            if(pwfi_le(q->raw,8)!=UINT64_C(0x6d646367)||pwfi_le(q->raw+16,8)!=previous||!pwfi_le(q->raw+8,8)||
               end<base||pwfi_le(q->raw+56,4)>4||pwfi_le(q->raw+60,4)||
               (!p->nodes&&base)||(p->nodes&&(last==UINT64_MAX||base!=last+1)))return pmrg_fail(r,3);
            previous=cursor;cursor=pwfi_le(q->raw+8,8);last=end;p->nodes++;
        }
        if(!p->nodes||previous!=pwfi_le(r->head+8,8)||!pmrg_roots(r,p,1))return pmrg_fail(r,3);
        p->complete=1;
    }
    const struct pmrg_pass*a=&r->pass[0],*bpass=&r->pass[1];
    if(a->nodes!=bpass->nodes)return pmrg_fail(r,4);
    for(unsigned n=0;n<a->nodes;n++)if(!pmli_read_equal(&a->node[n],&bpass->node[n]))return pmrg_fail(r,4);
    if(!pmli_current(l,o)||!pmsc_checkpoint(o)||!pmrg_live(r))return pmrg_fail(r,4);
    r->unknown=0;r->complete=1;pweh_digest(r,offsetof(struct pmrg_map,digest),r->digest);return 1;
}
static inline int pmrg_current(struct pmrg_map*r)
{
    if(!r||r->complete!=1||r->unknown||r->error||r->pass[0].complete!=1||r->pass[1].complete!=1||
       !r->pass[1].nodes||r->pass[1].nodes>PMRG_NODES)return 0;
    uint8_t hash[32];pweh_digest(r,offsetof(struct pmrg_map,digest),hash);
    return pgcd_equal(hash,r->digest,32)&&pmli_current((void*)(uintptr_t)r->images,(void*)(uintptr_t)r->owner)&&pmrg_live(r);
}
/* Own MSS clock/reset/RMB/AXI, DRV2 and AOP pages only. AXI includes the
 * vendor IDLE+8 word on each explicitly named page, not an arbitrary window. */
static inline int pmrg_device_page(uint64_t page)
{
    if(page&4095)return 0;
#if defined(EFI_XNU_WIFI_SMMU_NATIVE_AVAILABLE) && EFI_XNU_WIFI_SMMU_NATIVE_AVAILABLE
    if(page==0x15000000||page==0x15001000||(page>=0x15040000&&page<0x15080000))return 1;
#endif
#if defined(EFI_XNU_WIFI_CE_NATIVE_AVAILABLE) && EFI_XNU_WIFI_CE_NATIVE_AVAILABLE
    if(page>=UINT64_C(0x18a40000)&&page<=UINT64_C(0x18a4c000))return 1;
#endif
#if defined(EFI_XNU_MSS_SFPB_IO_AVAILABLE) && EFI_XNU_MSS_SFPB_IO_AVAILABLE
    if(page==UINT64_C(0x1f43000))return 1;
#endif
    if(page>=0xc300000&&page<0xc400000)return 1;
    const uint64_t pages[]={0x134000,0x138000,0x152000,0x18a000,0x1f63000,0x1f64000,0x1f65000,
        0x4080000,0x4084000,0x4180000,0xb2e0000,0xc2b0000,0x17990000,0x179e0000,0x179e1000,0x179e2000};
    for(unsigned n=0;n<sizeof(pages)/sizeof(pages[0]);n++)if(page==pages[n])return 1;return 0;
}
static inline int pmrg_map_excludes(const struct pweh_result*h,uint64_t page)
{
    for(uint64_t off=0;off<h->map.map.bytes;off+=h->map.map.stride){
        const struct efi_memory*d=(const void*)(h->map.data+off);
        if(d->physical<page+4096&&page<d->physical+d->pages*4096&&
           (d->type!=11||d->virtual_address||(d->attributes!=0&&d->attributes!=1)))return 0;
    }return 1;
}
/* Current namespace comparison only. No Device address is dereferenced here;
 * the eventual native access must still perform exact Device R/W AT and bind
 * a typed pending command plus the persistent resource owner. */
static inline int pmrg_target_now(struct pmrg_map*r,uint64_t page,struct pmrg_target*t)
{
    if(!r||!t||!pwmc_zero(t,sizeof(*t)))return 0;t->attempted=t->unknown=1;t->page=page;
    if(!pmrg_device_page(page)||!pmrg_current(r))return 0;
    struct pmsc_owner*o=(void*)(uintptr_t)r->owner;
    const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
    if(!pmsi_image_range(h->input.early,&h->map,(uintptr_t)t,sizeof(*t))||
       !pwea_disjoint((uintptr_t)t,sizeof(*t),(uintptr_t)r,sizeof(*r))||
       !pwea_disjoint((uintptr_t)t,sizeof(*t),r->images,sizeof(struct pmli_ledger))||
       !pwea_disjoint((uintptr_t)t,sizeof(*t),r->owner,sizeof(struct pmsc_owner))||!pmrg_map_excludes(h,page))return 0;
    t->before=o->last;
    for(unsigned n=0;n<r->pass[1].nodes;n++){
        const struct pmli_read*q=&r->pass[1].node[n];uint64_t base=pwfi_le(q->raw+24,8),end=pwfi_le(q->raw+32,8);
        if(base>page||end<page+4095)continue;t->index=n;
        if(end-base==UINT64_MAX||pwfi_le(q->raw+56,4)!=3||!(pwfi_le(q->raw+40,8)&1)||
           pwfi_le(q->raw+48,8)>1||!pmrg_read(r,&t->node,q->address,80,1))return 0;
        if(!pmli_read_equal(&t->node,q))return pmrg_fail(r,5);
        t->descriptor=(struct pgcd_descriptor){base,end-base+1,pwfi_le(q->raw+40,8),pwfi_le(q->raw+48,8),
            3,0,pwfi_le(q->raw+64,8),pwfi_le(q->raw+72,8)};
        t->after=o->last;t->unknown=0;t->complete=1;return 1;
    }return 0;
}
#endif
#endif
