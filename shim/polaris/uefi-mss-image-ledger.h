/* Current LoadedImage ledger directly from the own Core protocol database.
 * Read-only native RAM traversal under the separate continuous CPU interval.
 * No original LocateHandleBuffer/HandleProtocol, pool, lock or TPL call.
 * Layout is tied to the exact Core text checked by pmsc, not generic EDK2.
 * This supplies image exclusions for later heap/GCD reads, not MMIO ownership. */
#ifndef POLARIS_UEFI_MSS_IMAGE_LEDGER_H
#define POLARIS_UEFI_MSS_IMAGE_LEDGER_H
#ifndef EFI_XNU_MSS_IMAGE_LEDGER_AVAILABLE
#define EFI_XNU_MSS_IMAGE_LEDGER_AVAILABLE 0
#endif
#if EFI_XNU_MSS_IMAGE_LEDGER_AVAILABLE
#if !EFI_XNU_MSS_CPU_OWNER_AVAILABLE
#error Current image ledger requires the continuous CPU owner
#endif
#include "uefi-mss-cpu-owner.h"
#define PMLI_PROTOCOLS 1024u
#define PMLI_IMAGES 256u
#define PMLI_HEAD 0x1c210u
#define PMLI_LOCK 0x1b3f8u
#define PMLI_HANDLE_KEY 0x1cb28u
#define PMLI_LOCATE_KEY 0x1cbd0u
struct pmli_read {
    uint64_t address;uint32_t bytes,pages,issued,returned;
    struct pwmc_translation AT[2];uint8_t raw[96];
};
struct pmli_image {struct pmli_read interface,handle,loaded;};
struct pmli_pass {
    struct pmli_read root[2];
    struct pmli_read protocol[PMLI_PROTOCOLS];struct pmli_image image[PMLI_IMAGES];
    uint32_t protocols,images,selected,own_matches,core_matches,complete;
};
struct pmli_ledger {
    uint64_t owner,opening,core,key,locate;uint8_t lock[24],head[16];
    struct pmli_pass pass[2];
    uint32_t attempted,unknown,error,complete;uint8_t digest[32];
};
static inline int pmli_fail(struct pmli_ledger*r,unsigned e)
{r->unknown=1;if(!r->error)r->error=e;return 0;}
static inline int pmli_live(struct pmli_ledger*r)
{
    struct pmsc_owner*o=(void*)(uintptr_t)r->owner;
    return pmsc_live(o)&&o->opening==r->opening&&
        pgcd_equal(r->lock,(const void*)(uintptr_t)(r->core+PMLI_LOCK),24)&&
        pgcd_equal(r->head,(const void*)(uintptr_t)(r->core+PMLI_HEAD),16)&&
        r->key==pwfi_le((const void*)(uintptr_t)(r->core+PMLI_HANDLE_KEY),8)&&
        r->locate==pwfi_le((const void*)(uintptr_t)(r->core+PMLI_LOCATE_KEY),8);
}
static inline int pmli_range(const struct pweh_result*h,uint64_t at,uint64_t bytes,unsigned code,unsigned data)
{
    if(!at||!bytes||at>UINT64_MAX-bytes||at+bytes>UINT64_MAX-4095)return 0;
    for(uint64_t page=at&~UINT64_C(4095);page<at+bytes;page+=4096){
        unsigned found=0;
        for(uint64_t off=0;off<h->map.map.bytes;off+=h->map.map.stride){
            const struct efi_memory*d=(const void*)(h->map.data+off);
            if(page>=d->physical&&page-d->physical<d->pages*4096&&(d->type==code||d->type==data)&&
               (d->attributes>>63)==(d->type==5||d->type==6)&&(d->attributes&15)==8)found++;
        }
        if(found!=1)return 0;
    }
    return 1;
}
static inline int pmli_read_ram(struct pmli_ledger*r,struct pmli_read*q,uint64_t at,unsigned bytes,unsigned heap)
{
    struct pmsc_owner*o=(void*)(uintptr_t)r->owner;
    const struct pweh_result*h=(const void*)(uintptr_t)o->retained;const struct pwea_native*e=h->input.early;
    if(!pwmc_zero(q,sizeof(*q))||!bytes||bytes>sizeof(q->raw)||(at&7)||!pmli_live(r)||
       !pmli_range(h,at,bytes,heap?4:3,4)||
       !pwea_disjoint(at,bytes,(uintptr_t)r,sizeof(*r))||!pwea_disjoint(at,bytes,(uintptr_t)o,sizeof(*o)))
        return pmli_fail(r,2);
    if(heap&&(!pwea_disjoint(at,bytes,r->core,PGCI_IMAGE_BYTES)||
       !pwea_disjoint(at,bytes,(uintptr_t)e->image.base,e->image.bytes)))return pmli_fail(r,2);
    q->address=at;q->issued=1;
    for(uint64_t page=at&~UINT64_C(4095);page<at+bytes;page+=4096){
        if(q->pages>=2)return pmli_fail(r,2);struct pwmc_translation*t=&q->AT[q->pages++];t->page=page;
        if(!pwmc_actual_translate(t)||!pwmc_translation_valid(t)||t->page!=page||!pmli_live(r))return pmli_fail(r,3);
    }
    for(unsigned k=0;k<bytes;k++){q->raw[k]=*(const volatile uint8_t*)(uintptr_t)(at+k);q->bytes=k+1;}
    q->returned=1;return pmli_live(r)?1:pmli_fail(r,3);
}
static inline int pmli_distinct(const struct pmli_read*a,const struct pmli_read*b)
{return pwea_disjoint(a->address,a->bytes,b->address,b->bytes);}
static inline int pmli_read_equal(const struct pmli_read*a,const struct pmli_read*b)
{return a->address==b->address&&a->bytes==b->bytes&&pgcd_equal(a->raw,b->raw,sizeof(a->raw));}
static inline int pmli_heap_excluded(const struct pmli_pass*p,uint64_t at,unsigned bytes)
{
    for(unsigned k=0;k<p->images;k++){
        const uint8_t*q=p->image[k].loaded.raw;
        if(!pwea_disjoint(at,bytes,pwfi_le(q+64,8),pwfi_le(q+72,8)))return 0;
    }return 1;
}
static inline int pmli_capture(struct pmli_ledger*r,struct pmsc_owner*o)
{
    if(!r||!o||!pwmc_zero(r,sizeof(*r)))return 0;r->attempted=1;
    if(!pmsc_live(o)||o->effects||!pmsc_bound(o))return pmli_fail(r,1);
    const struct pweh_result*h=(const void*)(uintptr_t)o->retained;const struct pwea_native*e=h->input.early;
    if(!pmsi_image_range(e,&h->map,(uintptr_t)r,sizeof(*r))||
       !pwea_disjoint((uintptr_t)r,sizeof(*r),(uintptr_t)o,sizeof(*o))||
       !pwea_disjoint((uintptr_t)r,sizeof(*r),(uintptr_t)h,sizeof(*h))||
       !pwea_disjoint((uintptr_t)r,sizeof(*r),(uintptr_t)e,sizeof(*e))||
       !pwea_disjoint((uintptr_t)r,sizeof(*r),o->memory,sizeof(struct pmmn_native))||
       !pwea_disjoint((uintptr_t)r,sizeof(*r),o->mba,sizeof(struct pmsb_result)))return pmli_fail(r,1);
    r->owner=(uintptr_t)o;r->opening=o->opening;r->core=e->core;
    if(!pmsc_checkpoint(o))return pmli_fail(r,1);
    pgcd_copy(r->lock,(const void*)(uintptr_t)(r->core+PMLI_LOCK),24);
    pgcd_copy(r->head,(const void*)(uintptr_t)(r->core+PMLI_HEAD),16);
    r->key=pwfi_le((const void*)(uintptr_t)(r->core+PMLI_HANDLE_KEY),8);
    r->locate=pwfi_le((const void*)(uintptr_t)(r->core+PMLI_LOCATE_KEY),8);
    if(pwfi_le(r->lock,8)!=16||pwfi_le(r->lock+8,8)>16||pwfi_le(r->lock+16,8)!=1||!pmli_live(r))return pmli_fail(r,1);
    static const efi_guid loaded={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
    r->unknown=1;
    for(unsigned pass=0;pass<2;pass++){
        struct pmli_pass*p=&r->pass[pass];uint64_t head=r->core+PMLI_HEAD,previous=head,cursor=pwfi_le(r->head,8);
        if(!pmli_read_ram(r,&p->root[0],head,16,0)||!pgcd_equal(p->root[0].raw,r->head,16))return pmli_fail(r,3);
        while(cursor!=head){
            if(p->protocols==PMLI_PROTOCOLS||cursor<8||(cursor&7))return pmli_fail(r,4);
            struct pmli_read*q=&p->protocol[p->protocols];
            if(!pmli_read_ram(r,q,cursor-8,72,1))return 0;
            for(unsigned j=0;j<p->protocols;j++)if(!pmli_distinct(q,&p->protocol[j]))return pmli_fail(r,4);
            if(pwfi_le(q->raw,8)!=UINT64_C(0x65747270)||pwfi_le(q->raw+16,8)!=previous||!pwfi_le(q->raw+8,8))
                return pmli_fail(r,4);
            if(pgcd_equal(q->raw+24,&loaded,16)){if(p->selected)return pmli_fail(r,4);p->selected=p->protocols+1;}
            previous=cursor;cursor=pwfi_le(q->raw+8,8);p->protocols++;
        }
        if(!p->selected||previous!=pwfi_le(r->head+8,8))return pmli_fail(r,4);
        const struct pmli_read*protocol=&p->protocol[p->selected-1];head=protocol->address+40;
        previous=head;cursor=pwfi_le(protocol->raw+40,8);
        while(cursor!=head){
            if(p->images==PMLI_IMAGES||cursor<32||(cursor&7))return pmli_fail(r,5);
            struct pmli_image*i=&p->image[p->images];struct pmli_read*q=&i->interface;
            if(!pmli_read_ram(r,q,cursor-32,88,1))return 0;
            for(unsigned j=0;j<p->protocols;j++)if(!pmli_distinct(q,&p->protocol[j]))return pmli_fail(r,5);
            for(unsigned j=0;j<p->images;j++)if(!pmli_distinct(q,&p->image[j].interface))return pmli_fail(r,5);
            if(pwfi_le(q->raw,8)!=UINT64_C(0x63666970)||pwfi_le(q->raw+40,8)!=previous||!pwfi_le(q->raw+32,8)||
               pwfi_le(q->raw+48,8)!=protocol->address)return pmli_fail(r,5);
            if(!pmli_read_ram(r,&i->handle,pwfi_le(q->raw+24,8),56,1)||
               !pmli_read_ram(r,&i->loaded,pwfi_le(q->raw+56,8),sizeof(struct efi_loaded),0))return 0;
            if(pwfi_le(i->handle.raw,8)!=UINT64_C(0x6c646e68)||!pmli_distinct(q,&i->handle)||
               !pmli_distinct(q,&i->loaded)||!pmli_distinct(&i->handle,&i->loaded))return pmli_fail(r,5);
            for(unsigned j=0;j<p->images;j++)if(i->handle.address==p->image[j].handle.address||
                i->loaded.address==p->image[j].loaded.address)return pmli_fail(r,5);
            struct efi_loaded image;pgcd_copy(&image,i->loaded.raw,sizeof(image));uint64_t base=(uintptr_t)image.base;
            /* Full MSS retained journals/copy evidence can grow our own BSS.
             * Only the exact already-bound self LoadedImage gets128MiB;
             * foreign images keep64MiB and self equality remains mandatory. */
            uint64_t limit=i->loaded.address==e->image_address?UINT64_C(0x8000000):UINT64_C(0x4000000);
            if(image.revision!=0x1000||(uintptr_t)image.system!=e->system||!image.bytes||image.bytes>limit||(base&4095)||
               (image.code_type!=1&&image.code_type!=3&&image.code_type!=5)||
               (image.data_type!=2&&image.data_type!=4&&image.data_type!=6)||
               !pmli_range(h,base,image.bytes,image.code_type,image.data_type))return pmli_fail(r,6);
            if(i->loaded.address==e->image_address){if(!pgcd_equal(&image,&e->image,sizeof(image)))return pmli_fail(r,6);p->own_matches++;}
            if(base==r->core){if(image.bytes!=PGCI_IMAGE_BYTES)return pmli_fail(r,6);p->core_matches++;}
            previous=cursor;cursor=pwfi_le(q->raw+32,8);p->images++;
        }
        if(!p->images||p->own_matches!=1||p->core_matches!=1||previous!=pwfi_le(protocol->raw+48,8))return pmli_fail(r,5);
        /* Only after complete enumeration can every heap node be excluded
         * from ALL images. Earlier reads were bounded WB RAM reads only. */
        for(unsigned j=0;j<p->protocols;j++)if(!pmli_heap_excluded(p,p->protocol[j].address,72))return pmli_fail(r,7);
        for(unsigned j=0;j<p->images;j++)if(!pmli_heap_excluded(p,p->image[j].interface.address,88)||
            !pmli_heap_excluded(p,p->image[j].handle.address,56))return pmli_fail(r,7);
        if(!pmli_read_ram(r,&p->root[1],r->core+PMLI_HEAD,16,0)||!pmli_read_equal(&p->root[0],&p->root[1]))return pmli_fail(r,7);
        p->complete=1;
    }
    const struct pmli_pass*a=&r->pass[0],*b=&r->pass[1];
    if(a->protocols!=b->protocols||a->images!=b->images||a->selected!=b->selected)return pmli_fail(r,8);
    for(unsigned j=0;j<a->protocols;j++)if(!pmli_read_equal(&a->protocol[j],&b->protocol[j]))return pmli_fail(r,8);
    for(unsigned j=0;j<a->images;j++)if(!pmli_read_equal(&a->image[j].interface,&b->image[j].interface)||
        !pmli_read_equal(&a->image[j].handle,&b->image[j].handle)||!pmli_read_equal(&a->image[j].loaded,&b->image[j].loaded))return pmli_fail(r,8);
    if(!pmsc_checkpoint(o)||!pmli_live(r))return pmli_fail(r,8);
    r->unknown=0;r->complete=1;pweh_digest(r,offsetof(struct pmli_ledger,digest),r->digest);return 1;
}
static inline int pmli_current(struct pmli_ledger*r,struct pmsc_owner*o)
{
    if(!r||!o||r->owner!=(uintptr_t)o||r->complete!=1||r->unknown||r->error||
       r->pass[0].complete!=1||r->pass[1].complete!=1)return 0;
    uint8_t hash[32];pweh_digest(r,offsetof(struct pmli_ledger,digest),hash);
    return pgcd_equal(hash,r->digest,32)&&pmsc_bound(o)&&pmli_live(r);
}
#endif
#endif
