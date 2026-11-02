/* Owned EFI pages for a future MSS/MSA/RMTFS caller. Default OFF, no parent
 * hook yet. These are actual AllocatePages/FreePages adapters, not an MPU,
 * VMID, remote-DMA or radio grant. The original Core is never patched.
 * Each call has a NEW resident source context; no closed GCD ticket is reused
 * or renewed. An allocation persists as an EFI claim, not a CPU/power lease.
 * Once external exposure might be issued, this local-only release path locks
 * out permanently until a real secure/remote handback provider is integrated.
 */
#ifndef POLARIS_UEFI_WIFI_REMOTE_MEMORY_H
#define POLARIS_UEFI_WIFI_REMOTE_MEMORY_H
#ifndef EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE
#define EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
#include "uefi-gcd-mmio-readonly.h"
#define PWMC_PAGES 514u
#define PWMC_BS_BYTES 376u
#define PWMC_ALLOC_RVA UINT64_C(0xc258)
#define PWMC_FREE_RVA UINT64_C(0xc32c)
enum pwmc_kind {PWMC_MSA,PWMC_RMTFS};
enum pwmc_error {PWMC_OK,PWMC_ARGUMENT,PWMC_REUSED,PWMC_SOURCE,PWMC_RANGE,
    PWMC_CONTEXT,PWMC_SERVICE,PWMC_MAP,PWMC_TRANSLATION,PWMC_EXPOSED};
struct pwmc_range {uint64_t base,bytes;};
/* Fixed reg ranges of the original own reserved-memory node, plus SMEM.
 * Dynamic size-only DT pools have no PA to borrow; current EFI type7 is still
 * required. Current loader/payload/native/root allocations are excluded by
 * the complete map; none of their type2/3/4 pages can pass selection.
 */
static const struct pwmc_range pwmc_exclusions[]={
    {0x85700000,0x600000},{0x85d00000,0x200000},{0x85fc0000,0x4940000},
    {0x8ab00000,0x1400000},{0x8bf00000,0x500000},{0x8c400000,0x10000},
    {0x8c410000,0x5000},{0x8c415000,0x2000},{0x8c500000,0x1e00000},
    {0x8e300000,0x100000},{0x8e400000,0x7800000},{0x95c00000,0x500000},
    {0x96100000,0x800000},{0x96900000,0x200000},{0x96b00000,0x1400000},
    {0x97f00000,0x100000},{0x9d400000,0x2400000},{0xb0000000,0x400000},
    {0xaf000000,0x1000000},{0x86000000,0x200000}
};
struct pwmc_translation {
    uint64_t page,saved,read_par,write_par,restored;
    uint32_t read_issued,read_returned,write_issued,write_returned;
};
struct pwmc_call {
    uint64_t requested,returned_address,pages,status,entry,profile_hook,pending_events;
    uint64_t native_address;uint32_t native_before,native_after;
    uint32_t issued,returned,unknown,map_checked;
    struct pgcd_service_guard guard;
    uint8_t BS_before[PWMC_BS_BYTES],BS_after[PWMC_BS_BYTES];
};
struct pwmc_result {
    uint32_t bound,attempted,error,unknown,held,allocated,released,external_issued;
    uint32_t kind,bound_kind,pages,translated,translation_pending,native_reads[2],native_last[2];
    uint32_t release_translated,release_pending,final_hash_count[2],final_hash_failed[2];
    uint64_t backing,backing_bytes,exposed,exposed_bytes,native_flag,bound_native_flag;
    struct pgcd_result source[2];
    struct pgcd_context context[2];struct pgcd_lifetime ticket[2];
    struct pwmc_call call[2];
    struct pwmc_translation AT[PWMC_PAGES],release_AT[PWMC_PAGES];
    uint8_t final_hashes[2][PGCI_RANGE_COUNT][32];
};
_Static_assert(sizeof(struct pwmc_translation)==56,"both returned PAR translations and exact restore");
_Static_assert(sizeof(struct pwmc_result)==121344,"complete independent allocation and release evidence");
static inline int pwmc_fail(struct pwmc_result*r,unsigned error,unsigned unknown)
{if(!r->error)r->error=error;if(unknown)r->unknown=1;return 0;}
static inline int pwmc_zero(const void*p,size_t n)
{const uint8_t*b=p;for(size_t k=0;k<n;k++)if(b[k])return 0;return 1;}
static inline uint64_t pwmc_bytes(unsigned kind)
{return kind==PWMC_MSA?UINT64_C(0x200000):kind==PWMC_RMTFS?UINT64_C(0x202000):0;}
static inline int pwmc_allowed(uint64_t base,uint64_t bytes)
{
    if(!bytes||(bytes&4095)||bytes>0x202000||(base&4095)||base<UINT64_C(0x80000000)||base>UINT64_C(0x100000000)-bytes)return 0;
    for(unsigned k=0;k<sizeof(pwmc_exclusions)/sizeof(pwmc_exclusions[0]);k++){
        const struct pwmc_range*s=&pwmc_exclusions[k];if(base<s->base+s->bytes&&s->base<base+bytes)return 0;
    }return 1;
}
/* Reuse the complete existing map validator; do not parse a selected subset.
 * Compare semantic descriptor partitions in both directions, preserving all
 * attribute, virtual, padding and extension bytes. Only type/physical/pages
 * may differ through a split/merge, and type only inside the exact claim.
 */
static inline int pwmc_descriptor_equal(const uint8_t*a,const uint8_t*b,unsigned stride,
    uint32_t before,uint32_t after,unsigned inside)
{
    if(((const struct efi_memory*)a)->type!=(inside?before:((const struct efi_memory*)b)->type)||
       (inside&&((const struct efi_memory*)b)->type!=after))return 0;
    for(unsigned k=4;k<stride;k++)if(!((k>=8&&k<16)||(k>=24&&k<32))&&a[k]!=b[k])return 0;
    return 1;
}
static inline int pwmc_delta_direction(const uint8_t*a,uint64_t na,const uint8_t*b,uint64_t nb,
    unsigned stride,uint64_t base,uint64_t bytes,uint32_t before,uint32_t after)
{
    for(uint64_t at=0;at<na;at+=stride){
        const struct efi_memory*d=(const void*)(a+at);uint64_t cursor=d->physical,end=cursor+d->pages*4096;
        while(cursor<end){
            unsigned found=0;uint64_t next=end;
            for(uint64_t bt=0;bt<nb;bt+=stride){const struct efi_memory*e=(const void*)(b+bt);
                uint64_t stop=e->physical+e->pages*4096;if(e->physical<=cursor&&cursor<stop){
                    unsigned inside=cursor>=base&&cursor<base+bytes;found++;
                    if(!pwmc_descriptor_equal(a+at,b+bt,stride,before,after,inside))return 0;
                    if(stop<next)next=stop;
                }
            }
            if(found!=1||next<=cursor)return 0;
            if(cursor<base&&base<next)next=base;
            if(cursor<base+bytes&&base+bytes<next)next=base+bytes;
            cursor=next;
        }
    }return 1;
}
static inline int pwmc_map_delta(const struct pgcd_result*s,uint64_t base,uint64_t bytes,unsigned release)
{
    const struct pgcd_map*a=&s->map[0],*b=&s->map[1];struct polaris_efi_memory checked;
    uint32_t before=release?2:7,after=release?7:2;
    if(!a->valid||!b->valid||a->status||b->status||!a->key||!b->key||a->key==b->key||a->version!=1||b->version!=1||
       a->stride!=b->stride||!pwmc_allowed(base,bytes)||
       !polaris_efi_memory_check(s->maps[0],a->bytes,PGCD_MAP_CAP,a->stride,&checked)||
       !polaris_efi_memory_check(s->maps[1],b->bytes,PGCD_MAP_CAP,b->stride,&checked)||
       !polaris_efi_range_owned(s->maps[0],a->bytes,a->stride,base,bytes,before)||
       !polaris_efi_range_owned(s->maps[1],b->bytes,b->stride,base,bytes,after))return 0;
    return pwmc_delta_direction(s->maps[0],a->bytes,s->maps[1],b->bytes,(unsigned)a->stride,base,bytes,before,after)&&
        pwmc_delta_direction(s->maps[1],b->bytes,s->maps[0],a->bytes,(unsigned)a->stride,base,bytes,after,before);
}
static inline int pwmc_select(const struct pgcd_result*s,unsigned kind,uint64_t*out)
{
    struct polaris_efi_memory checked;const struct pgcd_map*m=&s->map[0];uint64_t bytes=pwmc_bytes(kind);
    uint64_t alignment=kind==PWMC_MSA?UINT64_C(0x200000):4096;
    if(!out||!bytes||!m->valid||!polaris_efi_memory_check(s->maps[0],m->bytes,PGCD_MAP_CAP,m->stride,&checked))return 0;
    uint64_t best=0;
    for(uint64_t at=0;at<m->bytes;at+=m->stride){const struct efi_memory*d=(const void*)(s->maps[0]+at);
        if(d->type!=7||d->attributes>>63||d->virtual_address)continue;
        uint64_t lo=d->physical<UINT64_C(0x80000000)?UINT64_C(0x80000000):d->physical;
        uint64_t hi=d->physical+d->pages*4096;if(hi>UINT64_C(0x100000000))hi=UINT64_C(0x100000000);
        if(hi<bytes||lo>hi-bytes)continue;
        uint64_t candidate=(hi-bytes)&~(alignment-1);
        /* Each collision moves below one exact excluded interval; at most
         *20 exclusions can be crossed, with no unbounded page scan. */
        for(unsigned attempt=0;attempt<=sizeof(pwmc_exclusions)/sizeof(pwmc_exclusions[0]);attempt++){
            if(candidate<lo)break;
            if(pwmc_allowed(candidate,bytes)){if(candidate>best)best=candidate;break;}
            uint64_t limit=UINT64_MAX;
            for(unsigned k=0;k<sizeof(pwmc_exclusions)/sizeof(pwmc_exclusions[0]);k++){
                const struct pwmc_range*x=&pwmc_exclusions[k];
                if(candidate<x->base+x->bytes&&x->base<candidate+bytes&&x->base<limit)limit=x->base;
            }
            if(limit<bytes||limit==UINT64_MAX)break;
            uint64_t lower=(limit-bytes)&~(alignment-1);if(lower>=candidate)break;candidate=lower;
        }
    }
    if(!best)return 0;*out=best;return 1;
}
static inline int pwmc_layout(const struct pwmc_result*r)
{
    uint64_t bytes=pwmc_bytes(r->kind);return bytes&&r->backing_bytes==bytes&&r->pages==bytes/4096&&
        pwmc_allowed(r->backing,bytes)&&!(r->backing&(r->kind==PWMC_MSA?0x1fffffu:4095u))&&
        r->exposed==r->backing+(r->kind==PWMC_RMTFS?4096:0)&&
        r->exposed_bytes==(r->kind==PWMC_MSA?0x100000u:0x200000u);
}
static inline int pwmc_parameters(const struct pwmc_result*r)
{
    if(r->kind!=r->bound_kind||r->native_flag!=r->bound_native_flag||!pwmc_layout(r))return 0;
    uint64_t selected=0;
    return pwmc_select(&r->source[0],r->bound_kind,&selected)&&selected==r->backing;
}
/* The original service guard marks its exact resident call pending BEFORE
 * the final source/native check. Recognize only that unissued own call;
 * never clear outstanding, accept a foreign pending call or sample UNKNOWN. */
static inline int pwmc_call_guard_valid(const struct pwmc_result*r,unsigned operation)
{
    const struct pwmc_call*q=&r->call[operation];const struct pgcd_result*s=&r->source[operation];
    const struct pgcd_service_guard*g=&q->guard;
    return !s->uncertain&&s->outstanding==0x10000&&
        q->requested==r->backing&&q->returned_address==r->backing&&q->pages==r->pages&&
        q->entry==s->core+(operation?PWMC_FREE_RVA:PWMC_ALLOC_RVA)&&q->native_address==r->bound_native_flag&&
        g->entered==1&&g->unknown==1&&g->left==0&&g->foreign_returned==0&&g->fp.saved==1&&g->fp.restored==0&&
        g->TPL_before==4&&g->boot_before==s->core+0x1b800&&g->tables_before==s->config_pointer&&g->count_before==s->config_count;
}
static inline int pwmc_own_prepared_call(const struct pwmc_result*r,unsigned operation)
{const struct pwmc_call*q=&r->call[operation];return !q->issued&&!q->returned&&!q->unknown&&pwmc_call_guard_valid(r,operation);}
static inline int pwmc_source(struct pwmc_result*r,unsigned operation)
{
    struct pgcd_context*c=&r->context[operation];struct pgcd_result*s=c->record;struct pgcd_arch a;
    if(r->error||r->unknown||r->kind!=r->bound_kind||r->native_flag!=r->bound_native_flag||
       (r->backing&&!pwmc_parameters(r))||s!=&r->source[operation]||c->ticket!=&r->ticket[operation]||c->finished||!c->opened||s->error||
       s->uncertain||(s->outstanding&&!pwmc_own_prepared_call(r,operation))||!pgcd_live(c,&a,0)||a.cpu.daif||a.cpu.group1!=1||
       !pgcd_cached_owner_stable(c)||!pgcd_in_self(s,(uintptr_t)r,sizeof(*r))||
       !pgcd_in_self(s,r->native_flag,4)||!pgcd_owned(c,0,r->native_flag,4)||
       (uintptr_t)c->io.system!=s->self_system||(uintptr_t)c->io.system->boot!=s->core+0x1b800||
       pwfi_le((const void*)(uintptr_t)(s->core+0x1b098),8)!=4||
       (uintptr_t)c->io.system->boot->allocate_pages!=s->core+PWMC_ALLOC_RVA||
       (uintptr_t)c->io.system->boot->free_pages!=s->core+PWMC_FREE_RVA||
       pwfi_le((const void*)(uintptr_t)(s->core+0x1cb78),8))return pwmc_fail(r,PWMC_SOURCE,operation||r->held);
    if(c->record!=s||c->ticket!=&r->ticket[operation]||r->kind!=r->bound_kind||r->native_flag!=r->bound_native_flag||
       (r->backing&&!pwmc_parameters(r))||s->uncertain||(s->outstanding&&!pwmc_own_prepared_call(r,operation)))return pwmc_fail(r,PWMC_CONTEXT,1);
    r->native_reads[operation]++;r->native_last[operation]=*(const volatile uint32_t*)(uintptr_t)r->native_flag;
    if(r->native_last[operation])return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
    return 1;
}
/* No mutable lookup is executed: actual source-bound ABI entries only.
 * The software peer replaces only these two call leaves in hosted tests. */
#if defined(POLARIS_WIFI_MEMORY_SOFTWARE_PEER)
#if !__STDC_HOSTED__
#error Software EFI allocation leaves must never enter the physical firmware
#endif
static int pwmc_test_call(struct pwmc_result*,unsigned);
#endif
static inline int pwmc_retained_claim(const struct pwmc_result*);
static inline int pwmc_actual_call(struct pwmc_result*r,unsigned operation)
{
    struct pwmc_call*q=&r->call[operation];
    if(!pwmc_parameters(r)||q->requested!=r->backing||q->returned_address!=r->backing||q->pages!=r->pages||
       q->native_address!=r->bound_native_flag||q->entry!=r->source[operation].core+(operation?PWMC_FREE_RVA:PWMC_ALLOC_RVA)||
       q->issued!=1||q->returned||q->unknown!=1||q->guard.entered!=1||q->guard.left||q->guard.unknown!=1||
       !pwmc_call_guard_valid(r,operation)||(operation&&!pwmc_retained_claim(r)))return 0;
#if defined(POLARIS_WIFI_MEMORY_SOFTWARE_PEER)
    return pwmc_test_call(r,operation);
#else
    struct efi_boot*b=r->context[operation].io.system->boot;
    if(operation)q->status=b->free_pages(q->requested,q->pages);
    else q->status=b->allocate_pages(2,2,q->pages,&q->returned_address);
    return 1;
#endif
}
static inline int pwmc_close_source(struct pwmc_result*r,unsigned operation)
{
    struct pgcd_context*c=&r->context[operation];
    if(!pgcd_map_read(c,1)||!pgcd_equal(r->call[operation].BS_before,c->io.system->boot,PWMC_BS_BYTES)||
       !pgcd_snapshot(c,1)||!pwmc_source(r,operation))return pwmc_fail(r,PWMC_SOURCE,1);
    if(!pgcd_equal(r->call[operation].BS_before,r->call[operation].BS_after,PWMC_BS_BYTES))return pwmc_fail(r,PWMC_SOURCE,1);
    /* This is an expected-mutating allocation source operation, not an
     * original read-only GCD finish. Keep that original RAW phase unchanged. */
    return 1;
}
static inline int pwmc_invoke(struct pwmc_result*r,unsigned operation)
{
    struct pgcd_context*c=&r->context[operation];struct pgcd_result*s=c->record;struct pwmc_call*q=&r->call[operation];
    if(!pwmc_source(r,operation)||!pgcd_service_enter(c,&q->guard))return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
    q->entry=s->core+(operation?PWMC_FREE_RVA:PWMC_ALLOC_RVA);q->pages=r->pages;
    q->requested=q->returned_address=r->backing;q->status=UINT64_MAX;q->native_address=r->native_flag;
    q->native_before=*(const volatile uint32_t*)(uintptr_t)r->native_flag;
    q->profile_hook=pwfi_le((const void*)(uintptr_t)(s->core+0x1cb78),8);
    q->pending_events=pwfi_le((const void*)(uintptr_t)(s->core+0x1dbc0),8);
    pgcd_copy(q->BS_before,c->io.system->boot,PWMC_BS_BYTES);
    if(q->native_before||q->profile_hook||!pwmc_source(r,operation))return pwmc_fail(r,PWMC_CONTEXT,1);
    q->issued=q->unknown=r->held=1;c->io.order(c->io.opaque);
    int returned=pwmc_actual_call(r,operation);q->returned=returned?1:0;c->io.order(c->io.opaque);
    if(!returned)return pwmc_fail(r,PWMC_SERVICE,1); /* No post-failure sampling or cleanup. */
    q->native_after=*(const volatile uint32_t*)(uintptr_t)r->native_flag;
    pgcd_copy(q->BS_after,c->io.system->boot,PWMC_BS_BYTES);
    if(!pgcd_service_leave(c,&q->guard,returned)||q->native_after||
       !pgcd_equal(q->BS_before,c->io.system->boot,PWMC_BS_BYTES)||!pwmc_close_source(r,operation))return pwmc_fail(r,PWMC_SERVICE,1);
    q->unknown=0;c->io.order(c->io.opaque);return 1;
}
static inline int pwmc_translation_valid(const struct pwmc_translation*t)
{
    return t->read_issued==1&&t->read_returned==1&&t->write_issued==1&&t->write_returned==1&&
        t->saved==t->restored&&t->read_par==(UINT64_C(0xff00000000000b80)|t->page)&&t->write_par==t->read_par;
}
static inline int pwmc_retained_claim(const struct pwmc_result*r)
{
    const struct pgcd_result*s=&r->source[0];const struct pwmc_call*q=&r->call[0];const struct pgcd_service_guard*g=&q->guard;
    if(r->bound!=1||!r->attempted||!r->allocated||!r->held||r->released||r->error||r->unknown||r->external_issued||
       !pwmc_parameters(r)||r->translated!=r->pages||r->translation_pending||
       q->issued!=1||q->returned!=1||q->unknown||q->status||q->map_checked!=1||q->requested!=r->backing||
       q->returned_address!=r->backing||q->pages!=r->pages||q->entry!=s->core+PWMC_ALLOC_RVA||
       q->native_address!=r->bound_native_flag||q->native_before||q->native_after||q->profile_hook||
       g->entered!=1||g->left!=1||g->foreign_returned!=1||g->unknown||g->fp.saved!=1||g->fp.restored!=1||
       g->TPL_before!=4||g->TPL_after!=4||g->boot_before!=s->core+0x1b800||g->boot_before!=g->boot_after||
       g->tables_before!=g->tables_after||g->count_before!=g->count_after||
       !r->context[0].finished||r->context[0].record!=s||r->context[0].ticket!=&r->ticket[0]||
       r->ticket[0].spent!=1||r->ticket[0].result!=(uintptr_t)s||s->attempted!=1||s->error||s->uncertain||s->outstanding||
       s->hash_count[0]!=5||s->hash_count[1]!=5||s->hash_failed[0]||s->hash_failed[1]||
       r->final_hash_count[0]!=5||r->final_hash_failed[0]||!r->native_reads[0]||r->native_last[0]||
       !pgcd_equal(q->BS_before,q->BS_after,PWMC_BS_BYTES)||!pwmc_map_delta(s,r->backing,r->backing_bytes,0))return 0;
    for(unsigned k=0;k<5;k++)if(!pgcd_equal(s->hashes[0][k],pgci_ranges[k].sha256,32)||
       !pgcd_equal(s->hashes[1][k],pgci_ranges[k].sha256,32)||!pgcd_equal(r->final_hashes[0][k],pgci_ranges[k].sha256,32))return 0;
    for(unsigned k=0;k<r->pages;k++)if(r->AT[k].page!=r->backing+4096*k||!pwmc_translation_valid(&r->AT[k]))return 0;
    return pwmc_zero(r->AT+r->pages,(PWMC_PAGES-r->pages)*sizeof(r->AT[0]));
}
static inline int pwmc_actual_translate(struct pwmc_translation*t)
{
#if defined(__aarch64__) || defined(__arm64__)
    __asm__ volatile("mrs %0,par_el1":"=r"(t->saved));t->read_issued=1;
    __asm__ volatile("at s1e1r,%1\n\tisb\n\tmrs %0,par_el1":"=r"(t->read_par):"r"(t->page):"memory");t->read_returned=1;
    t->write_issued=1;
    __asm__ volatile("at s1e1w,%1\n\tisb\n\tmrs %0,par_el1":"=r"(t->write_par):"r"(t->page):"memory");t->write_returned=1;
    __asm__ volatile("msr par_el1,%1\n\tisb\n\tmrs %0,par_el1":"=r"(t->restored):"r"(t->saved):"memory");return 1;
#else
    (void)t;return 0;
#endif
}
static inline int pwmc_final_source(struct pwmc_result*r,unsigned operation)
{
    struct pgcd_result*s=&r->source[operation];
    if(!pwmc_source(r,operation)||r->final_hash_count[operation]||
       !pgci_verify((const void*)(uintptr_t)s->core,s->core,PGCI_IMAGE_BYTES,r->final_hashes[operation],
        &r->final_hash_failed[operation],&r->final_hash_count[operation])||!pwmc_source(r,operation))return pwmc_fail(r,PWMC_SOURCE,1);
    return 1;
}
static inline int pwmc_claim(struct pwmc_result*r,int(*translate)(struct pwmc_translation*))
{
    if(!r||!r->bound||r->attempted)return 0;r->attempted=1;
    if(!translate||r->kind>PWMC_RMTFS||r->error||r->unknown||r->held||r->allocated||r->released||r->external_issued||
       r->translated||r->translation_pending||!pwmc_zero(r->AT,sizeof(r->AT))||
       r->context[0].opened||r->context[0].finished||r->ticket[0].spent||r->source[0].attempted)return pwmc_fail(r,PWMC_ARGUMENT,0);
    struct pgcd_context*c=&r->context[0];
    if(!pgcd_open(c)||!pwmc_source(r,0))return pwmc_fail(r,PWMC_SOURCE,pgcd_uncertain(c));
    if(!pwmc_select(c->record,r->kind,&r->backing))return pwmc_fail(r,PWMC_RANGE,0);
    r->backing_bytes=pwmc_bytes(r->kind);r->pages=(uint32_t)(r->backing_bytes/4096);
    r->exposed=r->backing+(r->kind==PWMC_RMTFS?4096:0);r->exposed_bytes=r->kind==PWMC_MSA?0x100000:0x200000;
    if(!pwmc_layout(r)||!pwmc_invoke(r,0))return 0;
    /* Even a returned EFI error may have partial effects: retain the claim
     * UNKNOWN unless a future explicit error-path full-map proof is added. */
    if(r->call[0].status||r->call[0].returned_address!=r->backing||!pwmc_map_delta(c->record,r->backing,r->backing_bytes,0))return pwmc_fail(r,PWMC_MAP,1);
    r->call[0].map_checked=1;
    for(unsigned k=0;k<r->pages;k++){
        struct pwmc_translation*t=&r->AT[k];t->page=r->backing+4096*k;r->translation_pending=k+1;c->io.order(c->io.opaque);
        if(!pwmc_source(r,0)||!translate(t)||t->page!=r->backing+4096*k||!pwmc_translation_valid(t)||!pwmc_source(r,0))return pwmc_fail(r,PWMC_TRANSLATION,1);
        r->translated=k+1;r->translation_pending=0;c->io.order(c->io.opaque);
    }
    if(!pwmc_zero(r->AT+r->pages,(PWMC_PAGES-r->pages)*sizeof(r->AT[0])))return pwmc_fail(r,PWMC_TRANSLATION,1);
    if(!pwmc_final_source(r,0))return 0;
    r->allocated=1;c->finished=1;c->io.order(c->io.opaque);return 1;
}
static inline int pwmc_exposure_intent(struct pwmc_result*r)
{
    if(!r||!r->attempted||r->released||r->error||r->unknown||r->external_issued)return 0;
    if(!pwmc_retained_claim(r))return pwmc_fail(r,PWMC_CONTEXT,1);
    /* Preserve exposure intent in two independently checked lifecycle fields;
     * clearing just the veto flag cannot make local-only release eligible. */
    r->bound=2;r->external_issued=1;r->context[0].io.order(r->context[0].io.opaque);return 1;
}
/* Local, NEVER-exposed pages only. This is deliberately not a callback bool
 * asserting remote retirement. No release path exists for exposed/UNKNOWN. */
static inline int pwmc_release_local(struct pwmc_result*r,int(*translate)(struct pwmc_translation*))
{
    if(!r||!translate||!r->attempted||r->released||r->error||r->unknown||r->external_issued)return 0;
    if(!pwmc_retained_claim(r)||r->release_translated||r->release_pending||
       !pwmc_zero(r->release_AT,sizeof(r->release_AT)))return pwmc_fail(r,PWMC_CONTEXT,1);
    struct pgcd_context*c=&r->context[1];
    if(c->opened||c->finished||r->ticket[1].spent||r->source[1].attempted)return pwmc_fail(r,PWMC_REUSED,1);
    if(!pgcd_open(c)||!pwmc_source(r,1)||c->record->core!=r->source[0].core||
       !pwfc_arch_stable(&r->source[0].before.cpu,&r->source[1].before.cpu)||
       r->source[0].before.cpacr!=r->source[1].before.cpacr||
       !polaris_efi_range_owned(c->record->maps[0],c->record->map[0].bytes,c->record->map[0].stride,r->backing,r->backing_bytes,2))return pwmc_fail(r,PWMC_SOURCE,1);
    for(unsigned k=0;k<r->pages;k++)if(r->AT[k].page!=r->backing+4096*k||!pwmc_translation_valid(&r->AT[k]))return pwmc_fail(r,PWMC_TRANSLATION,1);
    if(!pwmc_zero(r->AT+r->pages,(PWMC_PAGES-r->pages)*sizeof(r->AT[0])))return pwmc_fail(r,PWMC_TRANSLATION,1);
    for(unsigned k=0;k<r->pages;k++){
        struct pwmc_translation*t=&r->release_AT[k];t->page=r->backing+4096*k;r->release_pending=k+1;c->io.order(c->io.opaque);
        if(!pwmc_source(r,1)||!translate(t)||t->page!=r->backing+4096*k||!pwmc_translation_valid(t)||!pwmc_source(r,1))return pwmc_fail(r,PWMC_TRANSLATION,1);
        r->release_translated=k+1;r->release_pending=0;c->io.order(c->io.opaque);
    }
    if(!pwmc_retained_claim(r)||!pwmc_zero(r->release_AT+r->pages,(PWMC_PAGES-r->pages)*sizeof(r->release_AT[0]))||!pwmc_final_source(r,1))return pwmc_fail(r,PWMC_SOURCE,1);
    if(!pwmc_invoke(r,1))return 0;
    if(r->call[1].status||!pwmc_map_delta(c->record,r->backing,r->backing_bytes,1))return pwmc_fail(r,PWMC_MAP,1);
    r->call[1].map_checked=1;r->held=0;r->released=1;c->finished=1;c->io.order(c->io.opaque);return 1;
}
/* Actual initializer is callable only from a future qualified parent. It
 * binds two independent Core source records to the same resident object.
 * No parent/CLI/build hook is added by this header. */
static inline int pwmc_bind(struct pwmc_result*r,const struct efi_loaded*self,
    struct efi_system*system,const volatile uint32_t*native_flag,unsigned kind,const struct pgcd_io*io)
{
    if(!r||!self||!system||!native_flag||!io||io->system!=system||kind>PWMC_RMTFS||!pwmc_zero(r,sizeof(*r)))return 0;
    r->kind=r->bound_kind=kind;r->native_flag=r->bound_native_flag=(uintptr_t)native_flag;
    for(unsigned k=0;k<2;k++){
        if(!pgcd_bind(&r->source[k],self)||!pgcd_in_self(&r->source[k],(uintptr_t)r,sizeof(*r))||
           !pgcd_in_self(&r->source[k],r->native_flag,4))return pwmc_fail(r,PWMC_ARGUMENT,0);
        r->context[k]=(struct pgcd_context){.io=*io,.record=&r->source[k],.ticket=&r->ticket[k],.stage=2};
    }
    r->bound=1;return 1;
}
#endif
#endif
