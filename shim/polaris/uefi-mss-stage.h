/* Stage only own MBA and metadata into the actual retained HLOS allocations.
 * No firmware/secure call, device MMIO, publication, power, or remote start.
 * Target ownership remains local; normal incoming UEFI execution continues.
 * Each target page gets fresh R/W AT, exact word writes/readback, whole-page
 * CIVAC and DSB. Neither this record nor EFI type2 supplies a VMID permission. */
#ifndef POLARIS_UEFI_MSS_STAGE_H
#define POLARIS_UEFI_MSS_STAGE_H
#ifndef EFI_XNU_MSS_STAGING_AVAILABLE
#define EFI_XNU_MSS_STAGING_AVAILABLE 0
#endif
#ifndef EFI_XNU_MSS_PAYLOAD_FIRMWARE_AVAILABLE
#define EFI_XNU_MSS_PAYLOAD_FIRMWARE_AVAILABLE 0
#endif
#if EFI_XNU_MSS_STAGING_AVAILABLE
#if !EFI_XNU_MSS_MEMORY_AVAILABLE || defined(POLARIS_EFI_TEST_QEMU)
#error "MSS staging needs the actual independent physical allocation producer"
#endif
#include "uefi-mss-memory.h"
#include "uefi-mss-firmware-types.h"
#include "../../tools/polaris-wifi-mem-cache.h"
#define PMSI_PAGES 259u
struct pmsi_page {
    struct pwmc_translation source,target;struct pwmk_record cache;
    struct pgcd_arch after;
    uint32_t bytes,words_issued,words_returned,complete;
};
struct pmsi_result {
    uint64_t memory,retained,blob,blob_bytes,assets,asset_count;
    uint8_t memory_digest[32],retained_digest[32];
    struct pmsf_asset asset[2];struct pgcd_arch entry,final;
    struct pwea_core core[2];struct pwmc_translation source_AT[2][64];
    uint8_t source_hash[2][32],copied_hash[2][32];
    struct pmsi_page page[PMSI_PAGES];
    uint32_t attempted,unknown,error,source_pages[2],pages,assets_complete,complete;
};
_Static_assert(sizeof(struct pmsi_result)==91656,"MSS_STAGE_RAW_V1 ABI");
static inline int pmsi_fail(struct pmsi_result*r,unsigned error)
{r->unknown=1;if(!r->error)r->error=error;return 0;}
static inline int pmsi_arch(const struct pmsi_result*r,struct pgcd_arch*a)
{return pgcd_actual_arch(0,a)&&pwea_native_arch_valid(a)&&(a->cpu.sctlr&5)==5&&
    pwfc_arch_stable(&r->entry.cpu,&a->cpu)&&a->cpacr==r->entry.cpacr&&
    a->cpu.ticks-r->entry.cpu.ticks<=PGCD_FRESH_TICKS;}
static inline int pmsi_blob_owned(const struct pweh_result*h,uint64_t blob,uint64_t bytes)
{
#if EFI_XNU_MSS_PAYLOAD_FIRMWARE_AVAILABLE
    if(!bytes||bytes!=EFI_XNU_MSS_PAYLOAD_FW_BYTES||!EFI_XNU_MSS_FIRMWARE_OFFSET||
       (EFI_XNU_MSS_FIRMWARE_OFFSET&4095)||h->input.logical_bytes!=EFI_XNU_MSS_FIRMWARE_OFFSET+bytes||
       h->payload>UINT64_MAX-h->input.logical_bytes||blob!=h->payload+EFI_XNU_MSS_FIRMWARE_OFFSET)return 0;
    return polaris_efi_range_owned(h->map.data,h->map.map.bytes,h->map.map.stride,blob,bytes,2);
#else
    return pwmc_parent_in_image(&h->input.early->image,blob,bytes);
#endif
}
static inline int pmsi_binding_at(const struct pmsi_result*r,unsigned native,unsigned state)
{
    const struct pmmn_native*m=(const void*)(uintptr_t)r->memory;
    const struct pweh_result*h=(const void*)(uintptr_t)r->retained;uint8_t digest[32];
    pweh_digest(h,sizeof(*h),digest);
    return pgcd_equal(digest,r->retained_digest,32)&&pmmn_retained_at(m,r->memory_digest,h,native,state)&&
        pgcd_equal((const void*)(uintptr_t)r->assets,r->asset,sizeof(r->asset))&&pmsi_blob_owned(h,r->blob,r->blob_bytes);
}
static inline int pmsi_binding(const struct pmsi_result*r)
{return pmsi_binding_at(r,0,2);}
/* Shared with the software peer on guarded RAM shadows. All source accesses
 * stop at filesz; complete destination pages are initialized, including tails. */
static inline int pmsi_words(uint64_t destination,uint64_t source,unsigned bytes,struct pwfi_sha256*hash,struct pmsi_page*p)
{
    if((destination&4095)||bytes>4096||(bytes&&!source))return 0;
    p->bytes=bytes;
    for(unsigned n=0;n<512;n++){
        uint64_t value=0;
        for(unsigned j=0;j<8;j++)if(8*n+j<bytes){
            uint8_t b=*(const volatile uint8_t*)(uintptr_t)(source+8*n+j);
            value|=(uint64_t)b<<(8*j);pwfi_byte(hash,b);
        }
        volatile uint64_t*to=(void*)(uintptr_t)(destination+8*n);p->words_issued++;
        *to=value;if(*to!=value)return 0;p->words_returned++;
    }return 1;
}
#if defined(POLARIS_MSS_STAGE_SOFTWARE_PEER)
static int pmsi_write_page(uint64_t,uint64_t,unsigned,struct pwfi_sha256*,struct pmsi_page*);
static int pmsi_cache_page(uint64_t,struct pwmk_record*);
#else
#include "uefi-wifi-mem-cache.h"
static inline int pmsi_write_page(uint64_t to,uint64_t from,unsigned n,struct pwfi_sha256*h,struct pmsi_page*p)
{return pmsi_words(to,from,n,h,p);}
static inline int pmsi_cache_page(uint64_t to,struct pwmk_record*c)
{return pwma_actual_cache_page((void*)(uintptr_t)to,PWMK_CLEAN_INVALIDATE,c);}
#endif
static inline int pmsi_image_range(const struct pwea_native*e,const struct pwea_map*map,uint64_t at,uint64_t bytes)
{
    if(!pwmc_parent_in_image(&e->image,at,bytes))return 0;
    for(uint64_t p=at&~UINT64_C(4095);p<at+bytes;p+=4096)
        if(!polaris_efi_range_owned(map->data,map->map.bytes,map->map.stride,p,4096,3)&&
           !polaris_efi_range_owned(map->data,map->map.bytes,map->map.stride,p,4096,4))return 0;
    return 1;
}
static inline int pmsi_source_range(const struct pweh_result*h,uint64_t at,uint64_t bytes)
{
#if EFI_XNU_MSS_PAYLOAD_FIRMWARE_AVAILABLE
    if(!bytes||at<h->payload||at-h->payload>h->input.logical_bytes||bytes>h->input.logical_bytes-(at-h->payload))return 0;
    if(at>UINT64_MAX-bytes||at+bytes>UINT64_MAX-4095)return 0;
    uint64_t page=at&~UINT64_C(4095),end=(at+bytes+4095)&~UINT64_C(4095);
    return polaris_efi_range_owned(h->map.data,h->map.map.bytes,h->map.map.stride,page,end-page,2);
#else
    return pmsi_image_range(h->input.early,&h->map,at,bytes);
#endif
}
static inline int pmsi_stage(struct pmsi_result*r,const struct pmmn_native*m,const uint8_t digest[32],
    const struct pweh_result*h,const uint8_t*blob,uint64_t blob_bytes,const struct pmsf_asset*assets,unsigned count)
{
    if(!r||!m||!digest||!h||!blob||!assets||!pwmc_zero(r,sizeof(*r)))return 0;r->attempted=1;
    const struct pwea_native*e=h->input.early;
    if(!e||count<2||count>32||!blob_bytes||blob_bytes>0x4000000||((uintptr_t)blob&4095)||
       !pmmn_retained(m,digest,h)||!pmsi_image_range(e,&h->map,(uintptr_t)r,sizeof(*r))||
       !pmsi_image_range(e,&h->map,(uintptr_t)assets,count*sizeof(*assets))||
       !pmsi_blob_owned(h,(uintptr_t)blob,blob_bytes))return pmsi_fail(r,1);
    const uint64_t bases[]={(uintptr_t)m,(uintptr_t)h,(uintptr_t)e,(uintptr_t)digest,(uintptr_t)blob,(uintptr_t)assets,
        e->native_address,e->image_address,(uintptr_t)h->input.digest,(uintptr_t)h->input.payload_slot,
        (uintptr_t)h->input.log_slot,(uintptr_t)h->input.state,(uintptr_t)h->input.received,(uintptr_t)h->input.count};
    const uint64_t sizes[]={sizeof(*m),sizeof(*h),sizeof(*e),32,blob_bytes,count*sizeof(*assets),4,sizeof(e->image),32,8,8,4,8,8};
    for(unsigned n=0;n<14;n++)if(!pwea_disjoint((uintptr_t)r,sizeof(*r),bases[n],sizes[n]))return pmsi_fail(r,1);
    if(!pwea_disjoint((uintptr_t)blob,blob_bytes,(uintptr_t)m,sizeof(*m))||
       !pwea_disjoint((uintptr_t)blob,blob_bytes,(uintptr_t)h,sizeof(*h))||
       !pwea_disjoint((uintptr_t)blob,blob_bytes,(uintptr_t)e,sizeof(*e)))return pmsi_fail(r,1);
    r->memory=(uintptr_t)m;r->retained=(uintptr_t)h;r->blob=(uintptr_t)blob;r->blob_bytes=blob_bytes;
    r->assets=(uintptr_t)assets;r->asset_count=count;pgcd_copy(r->asset,assets,sizeof(r->asset));
    pgcd_copy(r->memory_digest,digest,32);pweh_digest(h,sizeof(*h),r->retained_digest);
    for(unsigned kind=0;kind<2;kind++){
        const struct pmsf_asset*a=&r->asset[kind];const struct pwea_claim*q=&m->memory.claim[kind+1];
        if(a->bytes!=(kind?8412u:238304u)||(a->offset&4095)||a->offset>blob_bytes||a->bytes>blob_bytes-a->offset||
           q->bytes!=(kind?12288u:0x100000u)||q->exposed_bytes!=(kind?8412u:0x100000u)||
           !pmsi_source_range(h,(uintptr_t)blob+a->offset,a->bytes))return pmsi_fail(r,2);
    }
    if(!pwea_disjoint((uintptr_t)blob+r->asset[0].offset,r->asset[0].bytes,(uintptr_t)blob+r->asset[1].offset,r->asset[1].bytes)||
       !pgcd_actual_arch(0,&r->entry)||!pwea_native_arch_valid(&r->entry)||(r->entry.cpu.sctlr&5)!=5||
       !pwfc_arch_stable(&h->final.cpu,&r->entry.cpu)||h->final.cpacr!=r->entry.cpacr||
       !pwea_core_check(e,&r->core[0],&h->map)||!pmsi_binding(r))return pmsi_fail(r,3);
    r->unknown=1;
    /* Authenticate both source assets before the first target write. */
    for(unsigned kind=0;kind<2;kind++){
        const struct pmsf_asset*a=&r->asset[kind];struct pwfi_sha256 hash;pwfi_init(&hash);
        for(unsigned n=0;n<(a->bytes+4095)/4096;n++){
            struct pwmc_translation*t=&r->source_AT[kind][n];struct pgcd_arch now;
            t->page=(uintptr_t)blob+a->offset+4096*n;
            if(!pmsi_arch(r,&now)||!pwmc_actual_translate(t)||!pwmc_translation_valid(t)||
               t->page!=(uintptr_t)blob+a->offset+4096*n)return pmsi_fail(r,4);
            unsigned bytes=a->bytes-4096*n;if(bytes>4096)bytes=4096;
            for(unsigned j=0;j<bytes;j++)pwfi_byte(&hash,*(const volatile uint8_t*)(uintptr_t)(t->page+j));
            r->source_pages[kind]++;
        }
        pwfi_final(&hash,r->source_hash[kind]);if(!pgcd_equal(r->source_hash[kind],a->sha256,32))return pmsi_fail(r,5);
    }
    for(unsigned kind=0;kind<2;kind++){
        const struct pmsf_asset*a=&r->asset[kind];const struct pwea_claim*q=&m->memory.claim[kind+1];
        struct pwfi_sha256 hash;pwfi_init(&hash);
        for(unsigned n=0;n<q->bytes/4096;n++){
            struct pmsi_page*p=&r->page[r->pages];struct pgcd_arch now;
            uint64_t to=q->requested+4096*n,from=0;unsigned bytes=a->bytes>4096*n?a->bytes-4096*n:0;if(bytes>4096)bytes=4096;
            if(!pmsi_arch(r,&now))return pmsi_fail(r,6);
            if(bytes){
                from=(uintptr_t)blob+a->offset+4096*n;p->source.page=from;
                if(!pwmc_actual_translate(&p->source)||!pwmc_translation_valid(&p->source)||p->source.page!=from)return pmsi_fail(r,7);
            }
            p->target.page=to;
            if(!pwmc_actual_translate(&p->target)||!pwmc_translation_valid(&p->target)||p->target.page!=to)return pmsi_fail(r,8);
            if(!pmsi_write_page(to,from,bytes,&hash,p)||p->bytes!=bytes||p->words_issued!=512||p->words_returned!=512)return pmsi_fail(r,9);
            if(!pmsi_cache_page(to,&p->cache)||!pwmk_record_valid(&p->cache,to,PWMK_CLEAN_INVALIDATE)||
               !pmsi_arch(r,&p->after)||p->after.cpu.ticks<now.cpu.ticks)return pmsi_fail(r,10);
            p->complete=1;r->pages++;
        }
        pwfi_final(&hash,r->copied_hash[kind]);
        if(!pgcd_equal(r->copied_hash[kind],a->sha256,32))return pmsi_fail(r,11);
        r->assets_complete++;
    }
    if(r->pages!=PMSI_PAGES||!pmsi_binding(r)||!pwea_core_check(e,&r->core[1],&h->map)||
       !pmsi_arch(r,&r->final)||r->final.cpu.ticks<r->page[PMSI_PAGES-1].after.cpu.ticks)return pmsi_fail(r,12);
    r->unknown=0;r->complete=1;return 1;
}
#endif
#endif
