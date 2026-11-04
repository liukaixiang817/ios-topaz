/* Actual native MBA startup under the composed AOP/power/clock owner.
 * Existing independent staged/assigned MBA is the only image admitted.
 * READY means native RMB/PBL/MBA status observations, not modem auth or WLAN.
 * Default OFF/unregistered; failures retain CPU, resources and all records. */
#ifndef POLARIS_UEFI_MSS_BOOT_NATIVE_H
#define POLARIS_UEFI_MSS_BOOT_NATIVE_H
#ifndef EFI_XNU_MSS_BOOT_NATIVE_AVAILABLE
#define EFI_XNU_MSS_BOOT_NATIVE_AVAILABLE 0
#endif
#if EFI_XNU_MSS_BOOT_NATIVE_AVAILABLE
#if !EFI_XNU_MSS_AOP_NATIVE_AVAILABLE
#error Native MBA startup requires the actual AOP/power/clock composition
#endif
#include "uefi-mss-aop-native.h"
#define PMBN_RECORDS (PMBA_EVENTS+PMSR_EVENTS)
struct pmbn_delivery {
    struct pmba_command command;struct pmrg_target target[2];
    struct pmni_arch opening;struct pmni_result native;
    uint32_t attempted,unknown,error,complete;uint8_t digest[32];
};
struct pmbn_state {
    uint64_t aop,power,clocks,owner,records,opening;struct pmba_boot mba;
    uint32_t attempted,ready,unknown,error,pending,deliveries,complete,reserved;
    uint8_t records_digest[32],digest[32];
};
static inline int pmbn_fail(struct pmbn_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;if(s->power)pmpn_fail((void*)(uintptr_t)s->power,11);return PMBA_FAILED;}
static inline int pmbn_live(struct pmbn_state*s)
{
    if(!s||s->ready!=1||s->unknown||s->error||s->deliveries>PMBN_RECORDS)return 0;
    struct pmpn_state*p=(void*)(uintptr_t)s->power;struct pmcn_state*c=(void*)(uintptr_t)s->clocks;
    struct pman_state*a=(void*)(uintptr_t)s->aop;
    const struct pmck_lifecycle*clock=(const void*)(uintptr_t)c->clocks;
    return s->opening==p->opening&&p->owner==s->owner&&c->power==s->power&&a->power==s->power&&a->clocks==s->clocks&&
        clock&&clock->epoch==s->opening&&clock->phase==2&&clock->held==63&&!clock->pending&&!clock->unknown&&!clock->error&&
        c->clock_calls==clock->events&&a->phase==1&&a->notify[0].complete==1&&!a->pending&&
        pmcn_live(c)&&pman_live(a)&&!p->pending&&!p->restored;
}
static inline int pmbn_child(struct pmbn_state*s,uint64_t at,uint64_t bytes)
{
    struct pmcn_state*c=(void*)(uintptr_t)s->clocks;struct pman_state*a=(void*)(uintptr_t)s->aop;
    return pmcn_child(c,at,bytes)&&pwea_disjoint(at,bytes,(uintptr_t)a,sizeof(*a))&&
        pwea_disjoint(at,bytes,a->records,sizeof(struct pman_delivery)*PMAN_RECORDS)&&
        pwea_disjoint(at,bytes,c->clocks,sizeof(struct pmck_lifecycle));
}
static inline int pmbn_begin(struct pmbn_state*s,struct pmbn_delivery*r,struct pman_state*a)
{
    if(!s||!r||!a||!pwmc_zero(s,sizeof(*s)))return 0;s->attempted=1;
    if(!pman_live(a)||a->phase!=1||a->notify[0].complete!=1||a->pending)return 0;
    struct pmcn_state*c=(void*)(uintptr_t)a->clocks;struct pmpn_state*p=(void*)(uintptr_t)a->power;
    s->aop=(uintptr_t)a;s->clocks=(uintptr_t)c;s->power=(uintptr_t)p;s->owner=p->owner;s->opening=p->opening;
    uint64_t bytes=sizeof(*r)*PMBN_RECORDS;
    if(!pmcn_live(c)||!c->clocks||!pmbn_child(s,(uintptr_t)s,sizeof(*s))||!pmbn_child(s,(uintptr_t)r,bytes)||
       !pwea_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)r,bytes)||!pwmc_zero(r,bytes))return 0;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;const struct pmsb_result*b=(const void*)(uintptr_t)o->mba;
    const struct pmsi_result*stage=(const void*)(uintptr_t)b->stage;
    uint8_t hash[32];pweh_digest(&a->notify[0],sizeof(a->notify[0]),hash);
    if(!pgcd_equal(hash,a->on_digest,32)||!pmsc_bound(o)||!pmrg_current((void*)(uintptr_t)p->namespace))return 0;
    s->records=(uintptr_t)r;s->ready=1;
    if(!pmbn_live(s)||pmba_begin(&s->mba,(const void*)(uintptr_t)c->clocks,&b->transaction,stage->asset[0].bytes,o->last)<0){pmbn_fail(s,1);return 0;}
    return 1;
}
static inline int pmbn_current(struct pmbn_state*s)
{
    if(!pmbn_live(s)||s->complete!=1||s->pending||s->mba.ready!=1||s->mba.phase!=4||s->mba.pending||s->mba.unknown||s->mba.error)return 0;
    uint8_t hash[32];pweh_digest(s,offsetof(struct pmbn_state,digest),hash);if(!pgcd_equal(hash,s->digest,32))return 0;
    pweh_digest((const void*)(uintptr_t)s->records,s->deliveries*sizeof(struct pmbn_delivery),hash);
    return pgcd_equal(hash,s->records_digest,32)&&pmbn_live(s);
}
static inline int pmbn_finish(struct pmbn_state*s)
{
    if(!pmbn_live(s)||s->complete||s->pending||s->mba.phase!=4||s->mba.ready!=1||s->mba.pending||s->mba.unknown||s->mba.error||
       s->mba.events+s->mba.reset.events!=s->deliveries)return 0;
    const struct pmbn_delivery*r=(const void*)(uintptr_t)s->records;uint8_t hash[32];
    for(unsigned n=0;n<s->deliveries;n++){
        pweh_digest(&r[n],offsetof(struct pmbn_delivery,digest),hash);
        if(r[n].complete!=1||r[n].unknown||r[n].error||!pgcd_equal(hash,r[n].digest,32))return 0;
    }
    pweh_digest(r,s->deliveries*sizeof(*r),s->records_digest);
    if(!pmbn_live(s))return 0;s->complete=1;pweh_digest(s,offsetof(struct pmbn_state,digest),s->digest);return 1;
}
static inline int pmbn_step(struct pmbn_state*s)
{
    if(!pmbn_live(s)||s->pending)return PMBA_FAILED;
    if(s->complete)return pmbn_current(s)?PMBA_READY:PMBA_FAILED;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;struct pmba_command command;
    int result=pmba_next(&s->mba,o->last,&command);
    if(result==PMBA_WAIT)return result;
    if(result==PMBA_READY)return pmbn_finish(s)?PMBA_READY:pmbn_fail(s,2);
    if(result!=PMBA_IO||s->deliveries==PMBN_RECORDS)return pmbn_fail(s,2);
    struct pmbn_delivery*r=(struct pmbn_delivery*)(uintptr_t)s->records+s->deliveries;
    if(!pwmc_zero(r,sizeof(*r)))return pmbn_fail(s,2);
    r->command=command;r->attempted=r->unknown=1;s->pending=++s->deliveries;
    uint64_t address=command.phase==2?command.reset.address:command.address;
    unsigned kind=command.phase==2?command.reset.kind:command.kind;
    unsigned memory=kind==PMSR_READ||kind==PMSR_WRITE;struct pmpn_state*p=(void*)(uintptr_t)s->power;
    if((memory&&!pmpn_target(p,address&~UINT64_C(4095),&r->target[0]))||!pmpn_arch(p,&r->opening)||
       !pgcd_equal(&r->opening,&p->architecture,offsetof(struct pmni_arch,ticks)))goto fail;
    if(kind==PMSR_WRITE&&!pmsc_mark_effect(o,PMSC_REMOTE))goto fail;
    if(!pmni_mba(&s->mba,&r->command,&r->opening,&r->native)||
       (memory&&(!pmpn_target(p,address&~UINT64_C(4095),&r->target[1])||r->target[0].index!=r->target[1].index))||
       !pmbn_live(s)||!pgcd_equal(&command,&r->command,sizeof(command)))goto fail;
    result=pmba_complete(&s->mba,&r->command,o->last,1,r->native.value);if(result<0)goto fail;
    r->unknown=0;r->complete=1;pweh_digest(r,offsetof(struct pmbn_delivery,digest),r->digest);s->pending=0;
    if(result==PMBA_READY)return pmbn_finish(s)?PMBA_READY:pmbn_fail(s,2);return result;
fail:r->error=3;return pmbn_fail(s,3);
}
#endif
#endif
