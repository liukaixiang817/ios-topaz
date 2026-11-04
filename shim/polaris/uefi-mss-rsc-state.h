/* Current DRV2 device observation for the continuous MSS parent. Default OFF,
 * unregistered; no vote/IRQ ACK/provider call. RAM snapshots bracket the
 * exact own-source geometry/IRQ/TCS reads. This does not grant EL3 ownership. */
#ifndef POLARIS_UEFI_MSS_RSC_STATE_H
#define POLARIS_UEFI_MSS_RSC_STATE_H
#ifndef EFI_XNU_MSS_RSC_STATE_AVAILABLE
#define EFI_XNU_MSS_RSC_STATE_AVAILABLE 0
#endif
#if EFI_XNU_MSS_RSC_STATE_AVAILABLE
#if !EFI_XNU_MSS_RPMH_STATE_AVAILABLE || !EFI_XNU_MSS_NATIVE_IO_AVAILABLE || !EFI_XNU_MSS_RAIL_IO_AVAILABLE
#error MSS DRV2 observation requires the current RAM owner and native rail leaves
#endif
#include "uefi-mss-rpmh-state.h"
#include "uefi-mss-mmio-native.h"
#define PMRS_READS 70u
struct pmrs_event {
    struct pmrg_target target;struct pmni_arch opening;struct pmni_result native;
};
struct pmrs_state {
    uint64_t owner,namespace,rpmh,opening;uint8_t rpmh_digest[32];
    uint32_t config[2],enable[2],irq[2],tcs[2][8][4],active_mask,selected;
    uint32_t attempted,unknown,error,events,pending,complete;
    struct pmrs_event event[PMRS_READS];struct pmrd_state after;uint8_t digest[32];
};
static inline int pmrs_fail(struct pmrs_state*r,unsigned error)
{r->unknown=1;if(!r->error)r->error=error;return 0;}
static inline int pmrs_live(struct pmrs_state*r)
{
    struct pmsc_owner*o=(void*)(uintptr_t)r->owner;struct pmrd_state*p=(void*)(uintptr_t)r->rpmh;
    return !o->effects&&o->opening==r->opening&&p->owner==r->owner&&p->namespace==r->namespace&&
        p->complete==1&&!p->unknown&&!p->error&&pgcd_equal(p->digest,r->rpmh_digest,32)&&pmrd_live(p);
}
static inline int pmrs_arch(struct pmrs_state*r,struct pmni_arch*a)
{
    if(!pmrs_live(r)||!pmni_arch_read(a)||!pmni_arch_valid(a))return 0;
    struct pmsc_owner*o=(void*)(uintptr_t)r->owner;const struct pwfc_arch*b=&o->current.cpu;
    return a->el==b->el&&a->mpidr==b->mpidr&&a->ttbr0==b->ttbr0&&a->ttbr1==b->ttbr1&&
        a->tcr==b->tcr&&a->sctlr==b->sctlr&&a->mair==b->mair&&a->daif==b->daif&&
        a->sre==b->sre&&a->group1==b->group1&&a->cpacr==o->current.cpacr&&a->frequency==b->frequency&&
        a->ticks>=o->last&&a->ticks-r->opening<=PMSC_TOTAL&&pmrs_live(r);
}
static inline int pmrs_readable(uint64_t at)
{
    if(at==0x179e000c||at==PWRSC_BASE||at==PWRSC_BASE+4)return 1;
    if(at<PWRSC_BASE||at>=PWRSC_BASE+8*PWRSC_STRIDE||(at&3))return 0;
    unsigned off=(unsigned)(at-PWRSC_BASE)%PWRSC_STRIDE;
    return off==0x10||off==0x14||off==0x18||off==0x1c;
}
static inline int pmrs_read(struct pmrs_state*r,uint64_t at,uint32_t*out)
{
    if(r->pending||r->events==PMRS_READS||!pmrs_readable(at)||!pmrs_live(r))return pmrs_fail(r,2);
    struct pmrs_event*e=&r->event[r->events++];struct pmrg_map*g=(void*)(uintptr_t)r->namespace;
    r->pending=r->events;
    if(!pmrg_target_now(g,at&~UINT64_C(4095),&e->target)||!pmrs_arch(r,&e->opening))return pmrs_fail(r,2);
    struct pmni_command command={at,PMNI_READ,0};
    if(!pmni_access(&e->opening,&command,&e->native)||!pmrs_live(r))return pmrs_fail(r,3);
    *out=e->native.value;r->pending=0;return 1;
}
static inline int pmrs_capture(struct pmrs_state*r,struct pmrd_state*p,struct pmrg_map*g)
{
    if(!r||!p||!g||!pwmc_zero(r,sizeof(*r)))return 0;r->attempted=1;
    if(!pmrd_current(p,g))return pmrs_fail(r,1);
    struct pmsc_owner*o=(void*)(uintptr_t)p->owner;const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
    const struct pmsb_result*b=(const void*)(uintptr_t)o->mba;const struct pwea_native*e=h->input.early;
    if(o->effects||!pmsi_image_range(e,&h->map,(uintptr_t)r,sizeof(*r)))return pmrs_fail(r,1);
    const uint64_t bases[]={(uintptr_t)p,(uintptr_t)g,g->images,(uintptr_t)o,(uintptr_t)h,(uintptr_t)e,o->memory,o->mba,b->stage,e->native_address,e->image_address};
    const uint64_t sizes[]={sizeof(*p),sizeof(*g),sizeof(struct pmli_ledger),sizeof(*o),sizeof(*h),sizeof(*e),sizeof(struct pmmn_native),sizeof(*b),sizeof(struct pmsi_result),4,sizeof(e->image)};
    for(unsigned n=0;n<11;n++)if(!pwea_disjoint((uintptr_t)r,sizeof(*r),bases[n],sizes[n]))return pmrs_fail(r,1);
    r->owner=p->owner;r->namespace=(uintptr_t)g;r->rpmh=(uintptr_t)p;r->opening=p->opening;r->active_mask=p->pass[1].active_mask;
    pgcd_copy(r->rpmh_digest,p->digest,32);r->unknown=1;
    for(unsigned pass=0;pass<2;pass++){
        if(!pmrs_read(r,0x179e000c,&r->config[pass])||!pmrs_read(r,PWRSC_BASE,&r->enable[pass])||
           !pmrs_read(r,PWRSC_BASE+4,&r->irq[pass]))return 0;
        /* Own HAL6f58/700c: bank2+0xc, count[17:12], NCPT[31:27]. */
        if(((r->config[pass]>>12)&63)!=8||(r->config[pass]>>27)!=16||r->irq[pass]||
           !(r->enable[pass]&r->active_mask))return pmrs_fail(r,4);
        static const unsigned offsets[]={0x10,0x14,0x18,0x1c};
        for(unsigned n=0;n<8;n++)for(unsigned j=0;j<4;j++)
            if(!pmrs_read(r,PWRSC_BASE+PWRSC_STRIDE*n+offsets[j],&r->tcs[pass][n][j]))return 0;
        for(unsigned n=0;n<8;n++)if(r->active_mask&(1u<<n)){
            struct pwrsc_registers saved={0};saved.wait=r->tcs[pass][n][0];saved.control=r->tcs[pass][n][1];
            saved.status=r->tcs[pass][n][2];saved.enable=r->tcs[pass][n][3];
            if(!pwrr_saved_supported(&saved))return pmrs_fail(r,4);
        }
    }
    if(r->config[0]!=r->config[1]||r->enable[0]!=r->enable[1]||r->irq[0]!=r->irq[1]||
       !pgcd_equal(r->tcs[0],r->tcs[1],sizeof(r->tcs[0]))||!pmrd_current(p,g)||!pmrs_live(r)||
       !pmrd_capture(&r->after,g))return pmrs_fail(r,5);
    const struct pmrd_pass*a=&p->pass[1],*z=&r->after.pass[1];
    if(p->image!=r->after.image||p->loaded_index!=r->after.loaded_index||p->protocol_index!=r->after.protocol_index||
       a->reads!=z->reads||a->active_mask!=z->active_mask||a->clients[0]!=z->clients[0]||a->clients[1]!=z->clients[1]||
       a->free_requests!=z->free_requests||a->cache_rows!=z->cache_rows)return pmrs_fail(r,5);
    for(unsigned n=0;n<a->reads;n++){
        const struct pmrd_read*x=&a->read[n],*y=&z->read[n];
        if(x->address!=y->address||x->bytes!=y->bytes||x->heap!=y->heap||!pgcd_equal(x->raw,y->raw,sizeof(x->raw)))return pmrs_fail(r,5);
    }
    if(!pmrs_live(r))return pmrs_fail(r,5);
    unsigned eligible=r->enable[1]&r->active_mask;
    for(unsigned n=0;n<8;n++)if(eligible&(1u<<n)){r->selected=n;break;}
    r->unknown=0;r->complete=1;pweh_digest(r,offsetof(struct pmrs_state,digest),r->digest);return 1;
}
/* Admission before the first effect only. Later requests need the separate
 * persistent parent's unchanged epoch and freshly observed TCS state. */
static inline int pmrs_current(struct pmrs_state*r,struct pmrd_state*p,struct pmrg_map*g)
{
    if(!r||!p||!g||r->rpmh!=(uintptr_t)p||r->namespace!=(uintptr_t)g||r->complete!=1||
       r->unknown||r->error||r->pending||r->events!=PMRS_READS||r->selected>=8||
       !(r->active_mask&r->enable[1]&(1u<<r->selected)))return 0;
    uint8_t hash[32];pweh_digest(r,offsetof(struct pmrs_state,digest),hash);
    return pgcd_equal(hash,r->digest,32)&&pmrd_current(p,g)&&pmrd_current(&r->after,g)&&pmrs_live(r);
}
#endif
#endif
