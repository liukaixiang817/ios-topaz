/* Actual resident modem copy/cache producer. Default OFF, no parent hook yet.
 * Consumes the continuous CPU interval and returned shared-bank assignment.
 * No original provider, MMIO or SMC is called here. RMB publication becomes
 * eligible only after source authentication, actual writes/readback and CIVAC.
 * Every bank page is initialized once, including inter-segment holes; the
 * advertised length remains the vendor sum of memsz, never the bank span. */
#ifndef POLARIS_UEFI_MSS_MODEM_COPY_H
#define POLARIS_UEFI_MSS_MODEM_COPY_H
#ifndef EFI_XNU_MSS_MODEM_COPY_AVAILABLE
#define EFI_XNU_MSS_MODEM_COPY_AVAILABLE 0
#endif
#if EFI_XNU_MSS_MODEM_COPY_AVAILABLE
#if !EFI_XNU_MSS_CPU_OWNER_AVAILABLE
#error Modem copy requires the continuous native CPU interval
#endif
#include "uefi-mss-cpu-owner.h"
#include "../../tools/polaris-mss-modem-auth.h"
#define PMLC_PAGES 30720u
#define PMLC_SOURCE_PAGES 16384u
#ifndef EFI_XNU_WIFI_NATIVE_COPY_TRACE_FIRST
#define EFI_XNU_WIFI_NATIVE_COPY_TRACE_FIRST 0
#endif
#if EFI_XNU_WIFI_NATIVE_COPY_TRACE_FIRST < 0 || EFI_XNU_WIFI_NATIVE_COPY_TRACE_FIRST > 30464 || (EFI_XNU_WIFI_NATIVE_COPY_TRACE_FIRST && !EFI_XNU_WIFI_NATIVE_FAULT_HOLD)
#error "Fine copy trace requires a bounded256-page fault diagnostic window"
#endif
struct pmlc_segment {
    uint64_t opening,finished;
    uint32_t first_page,pages,complete,published;
    uint8_t copied_hash[32];
};
struct pmlc_copy {
    uint64_t owner,auth,shared,stage,base,blob,blob_bytes,assets,asset_count,opening,last;
    uint8_t shared_digest[32],stage_digest[32],assets_digest[32];
    struct pmsf_segment geometry[PMIM_SEGMENTS];
    struct pmlc_segment segment[PMIM_SEGMENTS];
    uint8_t source_hash[PMIM_SEGMENTS][32];
    struct pwmc_translation source_AT[PMLC_SOURCE_PAGES];
    struct pmsi_page page[PMLC_PAGES];
    uint32_t attempted,unknown,error,ready,complete,source_pages,pages,segments;
#if EFI_XNU_WIFI_NATIVE_FAULT_HOLD
    uint32_t observe_page,observe_stage,observe_words_issued,observe_words_returned;
#endif
};
#if EFI_XNU_WIFI_NATIVE_FAULT_HOLD
/* Explicit terminal diagnostic only; own-RAM progress publication, no
 * provider/secure operation, remote target access or deadline renewal. */
static int pmlc_observe(struct pmlc_copy*);
#define PMLC_OBSERVE(r) do{if(!pmlc_observe(r))return pmlc_fail(r,2);}while(0)
/* Retained progress can precede page221 even after a returned RMB command.
 * Bound the finer diagnostic to256 selected pages; operations/deadline stay fixed.
 * Stage1 precedes initialization, so it never reads the page's old fields. */
#define PMLC_TRACE_PAGE(r,p,index,where) do{unsigned page_index=(index);if(page_index>=EFI_XNU_WIFI_NATIVE_COPY_TRACE_FIRST&&page_index-EFI_XNU_WIFI_NATIVE_COPY_TRACE_FIRST<256){ \
    (r)->observe_page=page_index;(r)->observe_stage=(where); \
    (r)->observe_words_issued=(where)>=3?(p)->words_issued:0; \
    (r)->observe_words_returned=(where)>=3?(p)->words_returned:0;PMLC_OBSERVE(r);}}while(0)
#else
#define PMLC_OBSERVE(r) do{}while(0)
#define PMLC_TRACE_PAGE(r,p,index,where) do{}while(0)
#endif
#if EFI_XNU_WIFI_AUTH_METADATA_CHECKPOINT == 9
#if !EFI_XNU_WIFI_FIRMWARE_DIAGNOSTIC_ONLY || EFI_XNU_WIFI_COPY_PAGE_BEFORE < 1 || EFI_XNU_WIFI_COPY_PAGE_BEFORE >= PMLC_PAGES
#error "Page checkpoint requires the explicit terminal firmware diagnostic and page1..30719"
#endif
__attribute__((noinline,noreturn)) static void pmlc_page_checkpoint(struct pmlc_copy*);
#endif
static inline int pmlc_fail(struct pmlc_copy*r,unsigned error)
{r->unknown=1;if(!r->error)r->error=error;return 0;}
static inline int pmlc_live(struct pmlc_copy*r)
{
    struct pmsc_owner*o=(void*)(uintptr_t)r->owner;
    const struct pmim_auth*a=(const void*)(uintptr_t)r->auth;
    if(!pmsc_live(o)||(o->effects&7)!=7||o->opening!=r->opening||a->unknown||a->error||a->pending||
       a->phase!=1||a->segment!=r->segments||a->submitted!=r->segments||a->base!=r->base||
       a->bytes!=0x7800000||a->exclusive_at||a->exclusive_page||a->authenticated_at||
       o->last<a->last||o->last<a->opening||o->last-a->opening>PMIM_TOTAL||o->last<r->last)
        return pmlc_fail(r,2);
    r->last=o->last;return 1;
}
static inline int pmlc_bound(struct pmlc_copy*r)
{
    const struct pwmt_transaction*t=(const void*)(uintptr_t)r->shared;
    const struct pmsi_result*s=(const void*)(uintptr_t)r->stage;
    const struct pmim_auth*a=(const void*)(uintptr_t)r->auth;
    struct pmsc_owner*o=(void*)(uintptr_t)r->owner;uint8_t hash[32];
    pweh_digest(t,sizeof(*t),hash);if(!pgcd_equal(hash,r->shared_digest,32))return 0;
    pweh_digest(s,sizeof(*s),hash);if(!pgcd_equal(hash,r->stage_digest,32))return 0;
    pweh_digest((const void*)(uintptr_t)r->assets,r->asset_count*sizeof(struct pmsf_asset),hash);
    return pgcd_equal(hash,r->assets_digest,32)&&pgcd_equal(a->segments,r->geometry,sizeof(r->geometry))&&
        pmsc_bound(o)&&pmsi_binding(s)&&pmim_assignment(t,0,r->base,a->metadata_returned)&&
        t->page==a->shared_page&&t->last==a->shared_at&&t->opening>=o->opening;
}
#if defined(POLARIS_MSS_MODEM_COPY_SOFTWARE_PEER)
static int pmlc_write(uint64_t,uint64_t,unsigned,struct pwfi_sha256*,struct pmsi_page*);
static int pmlc_cache(uint64_t,struct pwmk_record*);
#else
static inline int pmlc_write(uint64_t to,uint64_t from,unsigned bytes,struct pwfi_sha256*h,struct pmsi_page*p)
{return pmsi_words(to,from,bytes,h,p);}
static inline int pmlc_cache(uint64_t to,struct pwmk_record*c)
{return pwma_actual_cache_page((void*)(uintptr_t)to,PWMK_CLEAN_INVALIDATE,c);}
#endif
static inline int pmlc_begin(struct pmlc_copy*r,struct pmsc_owner*o,struct pmim_auth*a,const struct pwmt_transaction*t)
{
    if(!r||!o||!a||!t||!pwmc_zero(r,sizeof(*r)))return 0;r->attempted=1;
    PMLC_OBSERVE(r);
    if(!pmsc_live(o)||!pmsc_bound(o)||(o->effects&7)!=7)return pmlc_fail(r,1);
    const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
    const struct pmmn_native*m=(const void*)(uintptr_t)o->memory;
    const struct pmsb_result*b=(const void*)(uintptr_t)o->mba;
    const struct pmsi_result*s=(const void*)(uintptr_t)b->stage;
    const struct pwea_claim*q=&m->memory.claim[0];const struct pwea_native*e=h->input.early;
    if(s->complete!=1||s->unknown||s->error||s->memory!=o->memory||
       s->asset_count<27||s->asset_count>32||!pmsi_binding(s)||!pmsi_blob_owned(h,s->blob,s->blob_bytes)||
       !pmsi_image_range(e,&h->map,(uintptr_t)r,sizeof(*r))||
       !pmsi_image_range(e,&h->map,(uintptr_t)a,sizeof(*a))||
       !pmsi_image_range(e,&h->map,(uintptr_t)t,sizeof(*t))||
       t->page!=t->spec.descriptor_pa||!pmsi_image_range(e,&h->map,t->page,4096)||
       !pwea_disjoint((uintptr_t)r,sizeof(*r),t->page,4096)||
       !pmsi_image_range(e,&h->map,s->assets,s->asset_count*sizeof(struct pmsf_asset))||
       q->bytes!=0x7800000||q->exposed_bytes!=q->bytes||q->requested!=a->base||
       !polaris_efi_range_owned(h->map.data,h->map.map.bytes,h->map.map.stride,q->requested,q->bytes,2)||
       !pwea_disjoint(q->requested,q->bytes,t->page,4096)||
       a->phase!=1||a->segment||a->submitted||!a->epoch||a->metadata_returned<o->opening||
       !pmim_assignment(t,0,q->requested,a->metadata_returned)||t->opening<o->opening)
        return pmlc_fail(r,1);
    const uint64_t bases[]={(uintptr_t)o,(uintptr_t)a,(uintptr_t)t,(uintptr_t)s,(uintptr_t)b,(uintptr_t)h,
        (uintptr_t)m,(uintptr_t)e,s->assets,s->blob,e->native_address,e->image_address,(uintptr_t)h->input.digest,
        (uintptr_t)h->input.payload_slot,(uintptr_t)h->input.log_slot,(uintptr_t)h->input.state,
        (uintptr_t)h->input.received,(uintptr_t)h->input.count};
    const uint64_t sizes[]={sizeof(*o),sizeof(*a),sizeof(*t),sizeof(*s),sizeof(*b),sizeof(*h),sizeof(*m),sizeof(*e),
        s->asset_count*sizeof(struct pmsf_asset),s->blob_bytes,4,sizeof(e->image),32,8,8,4,8,8};
    for(unsigned n=0;n<18;n++)if(!pwea_disjoint((uintptr_t)r,sizeof(*r),bases[n],sizes[n])||
        !pwea_disjoint(q->requested,q->bytes,bases[n],sizes[n]))return pmlc_fail(r,1);
    r->owner=(uintptr_t)o;r->auth=(uintptr_t)a;r->shared=(uintptr_t)t;r->stage=(uintptr_t)s;
    r->base=q->requested;r->blob=s->blob;r->blob_bytes=s->blob_bytes;r->assets=s->assets;r->asset_count=s->asset_count;
    r->opening=o->opening;r->last=o->last;
    pweh_digest(t,sizeof(*t),r->shared_digest);pweh_digest(s,sizeof(*s),r->stage_digest);
    pweh_digest((const void*)(uintptr_t)s->assets,s->asset_count*sizeof(struct pmsf_asset),r->assets_digest);
    pgcd_copy(r->geometry,a->segments,sizeof(r->geometry));
    uint64_t end=0,total=0;unsigned asset_index=2;
    for(unsigned k=0;k<PMIM_SEGMENTS;k++){
        const struct pmsf_segment*g=&r->geometry[k];
        if(g->index!=k+2||!g->memsz||g->filesz>g->memsz||(g->target_offset&4095)||g->target_offset<end||
           g->target_offset>=0x7800000||g->memsz>0x7800000-g->target_offset||
           g->alignment!=(k?4096u:0x100000u)||g->flags<0x8000004||g->flags>0x8000007||
           (!k&&g->target_offset))return pmlc_fail(r,3);
        end=((uint64_t)g->target_offset+g->memsz+4095)&~UINT64_C(4095);total+=g->memsz;
        if(!g->filesz){if(g->asset!=UINT32_MAX)return pmlc_fail(r,3);continue;}
        if(g->asset!=asset_index++||g->asset>=r->asset_count||g->asset>26)return pmlc_fail(r,3);
        const struct pmsf_asset*f=&((const struct pmsf_asset*)(uintptr_t)r->assets)[g->asset];
        if(f->bytes!=g->filesz||(f->offset&4095)||f->offset>r->blob_bytes||f->bytes>r->blob_bytes-f->offset||
           !pmsi_source_range(h,r->blob+f->offset,f->bytes))return pmlc_fail(r,3);
        for(unsigned j=0;j<g->asset;j++){
            const struct pmsf_asset*prior=&((const struct pmsf_asset*)(uintptr_t)r->assets)[j];
            if(prior->offset>r->blob_bytes||prior->bytes>r->blob_bytes-prior->offset||
               !pwea_disjoint(r->blob+f->offset,f->bytes,r->blob+prior->offset,prior->bytes))return pmlc_fail(r,3);
        }
    }
    if(end!=0x7800000||total>0x7800000||asset_index!=27||!pmlc_live(r)||!pmlc_bound(r)||!pmsc_checkpoint(o))
        return pmlc_fail(r,3);
    r->unknown=1;
    PMLC_OBSERVE(r);
    /* Authenticate every modem asset before the first target store. */
    for(unsigned k=0;k<PMIM_SEGMENTS;k++){
        const struct pmsf_segment*g=&r->geometry[k];if(!g->filesz)continue;
        const struct pmsf_asset*f=&((const struct pmsf_asset*)(uintptr_t)r->assets)[g->asset];
        struct pwfi_sha256 hash;pwfi_init(&hash);
        for(unsigned offset=0;offset<f->bytes;offset+=4096){
            if(r->source_pages>=PMLC_SOURCE_PAGES||!pmlc_live(r))return pmlc_fail(r,4);
            struct pwmc_translation*x=&r->source_AT[r->source_pages];uint64_t page=r->blob+f->offset+offset;x->page=page;
            if(!pwmc_actual_translate(x)||!pwmc_translation_valid(x)||x->page!=page||!pmlc_live(r))return pmlc_fail(r,4);
            unsigned bytes=f->bytes-offset;if(bytes>4096)bytes=4096;
            for(unsigned j=0;j<bytes;j++)pwfi_byte(&hash,*(const volatile uint8_t*)(uintptr_t)(page+j));
            r->source_pages++;
            if(!(r->source_pages&255))PMLC_OBSERVE(r);
        }
        pwfi_final(&hash,r->source_hash[k]);if(!pgcd_equal(r->source_hash[k],f->sha256,32))return pmlc_fail(r,5);
    }
    if(!pmlc_live(r)||!pmlc_bound(r))return pmlc_fail(r,5);
    r->unknown=0;r->ready=1;PMLC_OBSERVE(r);return 1;
}
static inline int pmlc_next_segment(struct pmlc_copy*r)
{
    if(!r||r->unknown||r->error||r->ready!=1||r->complete||r->segments>=PMIM_SEGMENTS)return 0;
    if(!pmlc_live(r)||!pmlc_bound(r))return pmlc_fail(r,6);
    struct pmsc_owner*o=(void*)(uintptr_t)r->owner;struct pmim_auth*a=(void*)(uintptr_t)r->auth;
    const struct pmsf_segment*g=&r->geometry[r->segments];
    const struct pmsf_asset*f=g->filesz?&((const struct pmsf_asset*)(uintptr_t)r->assets)[g->asset]:0;
    struct pmlc_segment*s=&r->segment[r->segments];if(!pwmc_zero(s,sizeof(*s)))return pmlc_fail(r,6);
    s->opening=r->last;s->first_page=r->pages;r->unknown=1;struct pwfi_sha256 hash;pwfi_init(&hash);
    unsigned end=(g->target_offset+g->memsz+4095)/4096;
    if(end>PMLC_PAGES||end<=r->pages)return pmlc_fail(r,6);
    while(r->pages<end){
#if EFI_XNU_WIFI_AUTH_METADATA_CHECKPOINT == 9 && !EFI_XNU_WIFI_COPY_PAGE_AFTER_WRITE
        /* Stop before even translating the selected next target page. The
         * ordinary producer has no callback or branch when this is OFF. */
        if(r->pages==EFI_XNU_WIFI_COPY_PAGE_BEFORE)pmlc_page_checkpoint(r);
#endif
        struct pmsi_page*p=&r->page[r->pages];uint64_t to=r->base+4096*r->pages,from=0;unsigned bytes=0;
        unsigned offset=4096*r->pages;
        if(f&&offset>=g->target_offset&&offset-g->target_offset<g->filesz){
            unsigned position=offset-g->target_offset;bytes=g->filesz-position;if(bytes>4096)bytes=4096;
            from=r->blob+f->offset+position;
        }
        PMLC_TRACE_PAGE(r,p,r->pages,1);
        if(!pwmc_zero(p,sizeof(*p))||!pmlc_live(r))return pmlc_fail(r,7);
        if(bytes){p->source.page=from;if(!pwmc_actual_translate(&p->source)||!pwmc_translation_valid(&p->source)||p->source.page!=from)
            return pmlc_fail(r,7);}
        p->target.page=to;
        if(!pwmc_actual_translate(&p->target)||!pwmc_translation_valid(&p->target)||p->target.page!=to||!pmlc_live(r))
            return pmlc_fail(r,8);
        PMLC_TRACE_PAGE(r,p,r->pages,2);
        if(!pmlc_write(to,from,bytes,&hash,p)||p->bytes!=bytes||p->words_issued!=512||p->words_returned!=512||!pmlc_live(r))
            return pmlc_fail(r,9);
        PMLC_TRACE_PAGE(r,p,r->pages,3);
#if EFI_XNU_WIFI_AUTH_METADATA_CHECKPOINT == 9 && EFI_XNU_WIFI_COPY_PAGE_AFTER_WRITE
        /* Original write/readback and its live check returned; cache and
         * completion/publication have not been issued for this page. */
        if(r->pages==EFI_XNU_WIFI_COPY_PAGE_BEFORE)pmlc_page_checkpoint(r);
#endif
        if(!pmlc_cache(to,&p->cache)||!pwmk_record_valid(&p->cache,to,PWMK_CLEAN_INVALIDATE)||!pmlc_live(r))
            return pmlc_fail(r,10);
        PMLC_TRACE_PAGE(r,p,r->pages,4);
        p->after=o->current;p->complete=1;r->pages++;s->pages++;
        PMLC_TRACE_PAGE(r,p,r->pages-1,5);
        if(!(r->pages&255))PMLC_OBSERVE(r);
    }
    pwfi_final(&hash,s->copied_hash);
    if((f&&!pgcd_equal(s->copied_hash,f->sha256,32))||!pmlc_live(r)||!pmlc_bound(r))return pmlc_fail(r,11);
    s->finished=r->last;s->complete=1;
    if(r->segments==PMIM_SEGMENTS-1&&(r->pages!=PMLC_PAGES||!pmsc_checkpoint(o)))return pmlc_fail(r,12);
    if(pmim_publish(a,r->segments,o->last)!=PMIM_WAIT)return pmlc_fail(r,12);
    s->published=1;r->segments++;r->unknown=0;if(r->segments==PMIM_SEGMENTS)r->complete=1;
    PMLC_OBSERVE(r);return 1;
}
#endif
#endif
