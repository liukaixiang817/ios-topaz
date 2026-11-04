/* Own SFPB lock3, APPS token1, bound to the continuous native SMEM source.
 * Try exactly once. Never clear a busy/foreign/unknown lock. Acquired lock
 * stays held for the typed SMEM allocator; release is explicit and verified. */
#ifndef POLARIS_UEFI_MSS_SMEM_LOCK_H
#define POLARIS_UEFI_MSS_SMEM_LOCK_H
#if EFI_XNU_MSS_SMEM_NATIVE_AVAILABLE && EFI_XNU_MSS_SFPB_IO_AVAILABLE
#include "uefi-mss-smem-native.h"
#include "uefi-mss-mmio-native.h"
#define PMSL_ADDRESS UINT64_C(0x1f43000)
#define PMSL_RECORDS 8u
struct pmsl_delivery {struct pmrg_target target[2];struct pmni_arch opening;struct pmni_result native;};
struct pmsl_lock {
    uint64_t smem,owner,opening;struct pmsl_delivery record[PMSL_RECORDS];
    uint32_t attempted,unknown,error,busy,held,released,events,pending;uint8_t digest[32];
};
static inline int pmsl_fail(struct pmsl_lock*l,unsigned error)
{l->unknown=1;if(!l->error)l->error=error;return 0;}
static inline int pmsl_live(struct pmsl_lock*l)
{
    if(!l||!l->attempted||l->unknown||l->error||l->busy||l->released)return 0;
    struct pmsq_state*s=(void*)(uintptr_t)l->smem;
    return s->owner==l->owner&&s->opening==l->opening&&pmsq_current(s);
}
static inline int pmsl_arch(struct pmsl_lock*l,struct pmni_arch*a)
{
    if(!pmsl_live(l)||!pmni_arch_read(a)||!pmni_arch_valid(a))return 0;
    struct pmsc_owner*o=(void*)(uintptr_t)l->owner;const struct pwfc_arch*b=&o->current.cpu;
    return a->el==b->el&&a->mpidr==b->mpidr&&a->ttbr0==b->ttbr0&&a->ttbr1==b->ttbr1&&a->tcr==b->tcr&&
        a->sctlr==b->sctlr&&a->mair==b->mair&&a->daif==b->daif&&a->sre==b->sre&&a->group1==b->group1&&
        a->cpacr==o->current.cpacr&&a->frequency==b->frequency&&a->ticks>=o->last&&
        a->ticks-l->opening<=PMSC_TOTAL&&pmsl_live(l);
}
static inline void pmsl_seal(const struct pmsl_lock*l,const void*out,size_t bytes,uint8_t digest[32])
{
    struct pwfi_sha256 h;pwfi_init(&h);uintptr_t a=(uintptr_t)out,b=a+bytes;
    for(unsigned n=0;n<sizeof(*l);n++){uintptr_t at=(uintptr_t)l+n;if(at<a||at>=b)pwfi_byte(&h,((const uint8_t*)l)[n]);}
    pwfi_final(&h,digest);
}
/* Private caller supplies only the next hardcoded lock transaction. */
static inline int pmsl_run(struct pmsl_lock*l,struct pmsl_delivery*r,unsigned kind,unsigned value)
{
    if(!pmsl_live(l))return pmsl_fail(l,2);
    struct pmsq_state*s=(void*)(uintptr_t)l->smem;struct pmrg_map*g=(void*)(uintptr_t)s->namespace;
    struct pmsc_owner*o=(void*)(uintptr_t)l->owner;
    struct pmni_command command={kind==PMNI_FULL_ORDER?0:PMSL_ADDRESS,kind,value};
    if(!pwmc_zero(r,sizeof(*r))||(kind!=PMNI_FULL_ORDER&&!pmrg_target_now(g,PMSL_ADDRESS,&r->target[0]))||!pmsl_arch(l,&r->opening))goto fail;
    if(kind==PMNI_WRITE&&!pmsc_mark_effect(o,PMSC_REMOTE))goto fail;
    uint8_t before[32],after[32],owner_before[32],owner_after[32];
    pmsl_seal(l,&r->native,sizeof(r->native),before);pmsc_seal(o,0,0,owner_before);
    int returned=pmni_access(&r->opening,&command,&r->native);
    pmsl_seal(l,&r->native,sizeof(r->native),after);pmsc_seal(o,0,0,owner_after);
    if(!returned||!pgcd_equal(before,after,32)||!pgcd_equal(owner_before,owner_after,32)||(kind!=PMNI_FULL_ORDER&&
       (!pmrg_target_now(g,PMSL_ADDRESS,&r->target[1])||r->target[0].index!=r->target[1].index))||!pmsl_live(l))goto fail;
    return 1;
fail:return pmsl_fail(l,2);
}
static inline int pmsl_io(struct pmsl_lock*l,unsigned kind,unsigned value)
{
    if(!pmsl_live(l)||l->pending||l->events==PMSL_RECORDS)return pmsl_fail(l,2);
    struct pmsl_delivery*r=&l->record[l->events++];l->pending=l->events;
    if(!pmsl_run(l,r,kind,value))return 0;l->pending=0;return 1;
}
static inline int pmsl_acquire(struct pmsl_lock*l,struct pmsq_state*s)
{
    if(!l||!s||!pwmc_zero(l,sizeof(*l))||!pmsq_current(s))return 0;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;struct pmrg_map*g=(void*)(uintptr_t)s->namespace;
    const struct pweh_result*h=(const void*)(uintptr_t)o->retained;const struct pmsb_result*b=(const void*)(uintptr_t)o->mba;
    if(!pmsi_image_range(h->input.early,&h->map,(uintptr_t)l,sizeof(*l)))return 0;
    const uint64_t at[]={(uintptr_t)s,(uintptr_t)o,(uintptr_t)g,s->images,(uintptr_t)h,(uintptr_t)h->input.early,o->memory,o->mba,b->stage};
    const uint64_t bytes[]={sizeof(*s),sizeof(*o),sizeof(*g),sizeof(struct pmli_ledger),sizeof(*h),sizeof(struct pwea_native),sizeof(struct pmmn_native),sizeof(*b),sizeof(struct pmsi_result)};
    for(unsigned n=0;n<9;n++)if(!pwea_disjoint((uintptr_t)l,sizeof(*l),at[n],bytes[n]))return 0;
    l->smem=(uintptr_t)s;l->owner=s->owner;l->opening=s->opening;l->attempted=1;
    if(!pmsl_io(l,PMNI_READ,0))return 0;
    if(l->record[0].native.value){l->busy=1;return 0;}
    if(!pmsl_io(l,PMNI_WRITE,1)||!pmsl_io(l,PMNI_FULL_ORDER,0)||!pmsl_io(l,PMNI_READ,0))return 0;
    if(l->record[3].native.value!=1)return pmsl_fail(l,3);
    l->held=1;pweh_digest(l,offsetof(struct pmsl_lock,digest),l->digest);return 1;
}
static inline int pmsl_held(struct pmsl_lock*l)
{
    if(!pmsl_live(l)||l->held!=1||l->events!=4||l->pending)return 0;
    uint8_t hash[32];pweh_digest(l,offsetof(struct pmsl_lock,digest),hash);return pgcd_equal(hash,l->digest,32);
}
/* Fresh actual token read around each allocator page. The caller owns the
 * external retained delivery; this never changes the sealed acquire record. */
static inline int pmsl_check(struct pmsl_lock*l,struct pmsl_delivery*r)
{
    if(!pmsl_held(l)||!pmsl_run(l,r,PMNI_READ,0)||r->native.value!=1||!pmsl_held(l))return pmsl_fail(l,7);
    return 1;
}
static inline int pmsl_release(struct pmsl_lock*l)
{
    if(!l||!l->attempted||l->released||l->busy)return 0;
    if(!pmsl_held(l))return pmsl_fail(l,5);
    if(!pmsl_io(l,PMNI_READ,0))return 0;
    if(l->record[4].native.value!=1)return pmsl_fail(l,3);
    if(!pmsl_io(l,PMNI_WRITE,0)||!pmsl_io(l,PMNI_FULL_ORDER,0)||!pmsl_io(l,PMNI_READ,0))return 0;
    if(l->record[7].native.value)return pmsl_fail(l,4);
    l->held=0;l->released=1;pweh_digest(l,offsetof(struct pmsl_lock,digest),l->digest);return 1;
}
#endif
#endif
