/* Resource retirement after the actual current native STOP/ACK/halt/reset.
 * Frozen startup evidence remains owned; no permission return, free, original
 * provider, CPU restoration or DMA-retired claim is implied by completion. */
#ifndef POLARIS_UEFI_MSS_RETIREMENT_NATIVE_H
#define POLARIS_UEFI_MSS_RETIREMENT_NATIVE_H
#ifndef EFI_XNU_MSS_RETIREMENT_NATIVE_AVAILABLE
#define EFI_XNU_MSS_RETIREMENT_NATIVE_AVAILABLE 0
#endif
#include "uefi-mss-shutdown-native.h"
#if EFI_XNU_MSS_RETIREMENT_NATIVE_AVAILABLE
#if !EFI_XNU_MSS_SHUTDOWN_NATIVE_AVAILABLE
#error Native retirement requires actual current native shutdown
#endif
struct pmnr_state {
    uint64_t shutdown,owner,opening,power,clocks,aop,active,proxy,supplies;
    struct pwea_core source[2];
    uint8_t shutdown_digest[32],wlan_digest[32],auth_digest[32];
    uint32_t attempted,ready,unknown,error,phase,pending,complete,reserved;
    uint8_t digest[32];
    uint64_t handback; /* Unique later permission-return owner, outside seal. */
};
static inline int pmnr_fail(struct pmnr_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return 0;}
/* Startup's LIVE predicates deliberately cease accepting the old state once
 * active clocks leave HELD. This separately claimed continuation uses the
 * same CPU/GCD/resource owner, never weakens those startup predicates. */
static inline int pmnr_live(struct pmnr_state*s)
{
    if(!s||s->ready!=1||s->unknown||s->error||s->phase<1||s->phase>7)return 0;
    struct pmnd_state*d=(void*)(uintptr_t)s->shutdown;
    struct pmpn_state*p=(void*)(uintptr_t)s->power;struct pmcn_state*c=(void*)(uintptr_t)s->clocks;
    struct pman_state*a=(void*)(uintptr_t)s->aop;
    return d->retirement==(uintptr_t)s&&d->owner==s->owner&&d->opening==s->opening&&d->quiesced==1&&d->complete==1&&
        !d->unknown&&!d->error&&!d->pending&&p->owner==s->owner&&p->opening==s->opening&&
        c->power==s->power&&c->opening==s->opening&&c->clocks==s->active&&c->ready==1&&!c->unknown&&!c->error&&
        a->power==s->power&&a->clocks==s->clocks&&a->opening==s->opening&&a->ready==1&&!a->unknown&&!a->error&&
        p->proxy==s->proxy&&p->supplies==s->supplies&&pmpn_live(p);
}
static inline int pmnr_frozen(struct pmnr_state*s)
{
    if(!pmnr_live(s))return 0;struct pmnd_state*d=(void*)(uintptr_t)s->shutdown;uint8_t hash[32];
    pweh_digest(d,offsetof(struct pmnd_state,digest),hash);
    if(!pgcd_equal(hash,s->shutdown_digest,32)||!pgcd_equal(hash,d->digest,32))return 0;
    pweh_digest((const void*)(uintptr_t)d->records,d->deliveries*sizeof(struct pmnd_delivery),hash);
    if(!pgcd_equal(hash,d->records_digest,32))return 0;
    pmwa_seal((void*)(uintptr_t)d->wlan,0,0,hash);if(!pgcd_equal(hash,s->wlan_digest,32))return 0;
    pmsn_seal((void*)(uintptr_t)d->auth,0,0,hash);return pgcd_equal(hash,s->auth_digest,32)&&pmnr_live(s);
}
static inline int pmnr_begin(struct pmnr_state*s,struct pmnd_state*d)
{
    if(!s||!d||!pwmc_zero(s,sizeof(*s))||d->retirement||!pmnd_current(d))return 0;
    struct pmsn_state*q=(void*)(uintptr_t)d->auth;struct pmbn_state*b=(void*)(uintptr_t)q->boot;
    if(!pmsn_child(q,(uintptr_t)s,sizeof(*s))||
       !pwea_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)d,sizeof(*d))||
       !pwea_disjoint((uintptr_t)s,sizeof(*s),d->records,sizeof(struct pmnd_delivery)*PMND_RECORDS))return 0;
    struct pmrf_state*rf=(void*)(uintptr_t)d->service;struct pmsx_state*ch=(void*)(uintptr_t)d->channel;
    const uint64_t at[]={d->wlan,d->service,d->glink,d->channel,d->smp,q->rmtfs,(uintptr_t)q,q->records,q->copy,q->segments,rf->nv,ch->smem,ch->allocation};
    const uint64_t bytes[]={sizeof(struct pmwa_state),sizeof(struct pmrf_state),sizeof(struct pmsg_state),sizeof(struct pmsx_state),sizeof(struct pmsy_state),sizeof(struct pmtf_state),sizeof(*q),sizeof(struct pmsn_delivery)*PMSN_RECORDS,sizeof(struct pmlc_copy),sizeof(struct pmsf_segment)*PMIM_SEGMENTS,sizeof(struct pnnv_state),sizeof(struct pmsq_state),sizeof(struct pmsa_state)};
    for(unsigned n=0;n<13;n++)if(!pwea_disjoint((uintptr_t)s,sizeof(*s),at[n],bytes[n]))return 0;
    struct pmpn_state*p=(void*)(uintptr_t)b->power;struct pmcn_state*c=(void*)(uintptr_t)b->clocks;
    struct pman_state*a=(void*)(uintptr_t)b->aop;struct pmsc_owner*o=(void*)(uintptr_t)d->owner;
    const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
    if(!pmcn_live(c)||!pman_live(a)||p->pending||c->pending||a->pending||p->restored||c->restored||a->restored)return 0;
    s->shutdown=(uintptr_t)d;s->owner=d->owner;s->opening=d->opening;s->power=b->power;s->clocks=b->clocks;s->aop=b->aop;
    s->active=c->clocks;s->proxy=p->proxy;s->supplies=p->supplies;s->attempted=1;
    if(!pwea_core_check(h->input.early,&s->source[0],&h->map)||!pmnd_current(d))return pmnr_fail(s,1);
    pgcd_copy(s->shutdown_digest,d->digest,32);pmwa_seal((void*)(uintptr_t)d->wlan,0,0,s->wlan_digest);
    pmsn_seal(q,0,0,s->auth_digest);s->ready=s->phase=1;d->retirement=(uintptr_t)s;
    if(!pmnr_frozen(s)||!pmcn_clock_release(c,(void*)(uintptr_t)s->active,&d->shutdown))return pmnr_fail(s,1);
    return pmnr_live(s);
}
static inline int pmnr_current(struct pmnr_state*s)
{
    if(!pmnr_frozen(s)||s->complete!=1||s->phase!=7||s->pending)return 0;uint8_t hash[32];
    struct pmpn_state*p=(void*)(uintptr_t)s->power;struct pmcn_state*c=(void*)(uintptr_t)s->clocks;
    struct pman_state*a=(void*)(uintptr_t)s->aop;
    if(p->restored!=1||c->restored!=1||a->restored!=1||a->phase!=3||p->pending||c->pending||a->pending)return 0;
    pweh_digest(p,offsetof(struct pmpn_state,digest),hash);if(!pgcd_equal(hash,p->digest,32))return 0;
    pweh_digest(c,offsetof(struct pmcn_state,digest),hash);if(!pgcd_equal(hash,c->digest,32))return 0;
    pweh_digest(a,offsetof(struct pman_state,digest),hash);if(!pgcd_equal(hash,a->digest,32))return 0;
    pweh_digest(s,offsetof(struct pmnr_state,digest),hash);return pgcd_equal(hash,s->digest,32)&&pmnr_live(s);
}
/*0 sticky refusal;1 work/wait;2 resource votes and AOP restored.*/
static inline int pmnr_step(struct pmnr_state*s)
{
    if(!pmnr_live(s)||s->pending)return 0;if(s->complete)return pmnr_current(s)?2:0;
    struct pmpn_state*p=(void*)(uintptr_t)s->power;struct pmcn_state*c=(void*)(uintptr_t)s->clocks;
    struct pman_state*a=(void*)(uintptr_t)s->aop;struct pmck_lifecycle*k=(void*)(uintptr_t)s->active;
    struct pmpx_lifecycle*x=(void*)(uintptr_t)s->proxy;struct pmsp_lifecycle*v=(void*)(uintptr_t)s->supplies;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;s->pending=1;
    if(s->phase==1){
        struct pmck_command cmd;int r=pmck_next(k,o->last,&cmd);
        if(r==PMCK_RESTORED){if(!pmnr_frozen(s)||!pmpn_proxy_release(p,x,k))return pmnr_fail(s,2);s->phase=2;}
        else if(r!=PMCK_WAIT&&(r!=PMCK_IO||!pmcn_clock(c,k,&cmd)))return pmnr_fail(s,2);
    }else if(s->phase==2){
        struct pmpx_command cmd;int r=pmpx_next(x,o->last,&cmd);
        if(r==PMPX_RESTORED){if(!pmnr_frozen(s)||pmsp_release(v,k,o->last)<0)return pmnr_fail(s,3);s->phase=3;}
        else if(r!=PMPX_WAIT&&(r!=PMPX_IO||(cmd.kind==PMPX_RAIL?!pmpn_proxy(p,x,&cmd):!pmcn_proxy(c,x,&cmd))))return pmnr_fail(s,3);
    }else if(s->phase==3){
        struct pmsp_command cmd;int r=pmsp_next(v,o->last,&cmd);
        if(r==PMSP_RESTORED){if(!pmnr_frozen(s)||!pmpn_finish(p)||!pmcn_finish(c))return pmnr_fail(s,4);s->phase=4;}
        else if(r!=PMSP_WAIT&&(r!=PMSP_REQUEST||!pmpn_supply(p,v,&cmd)))return pmnr_fail(s,4);
    }else if(s->phase==4){if(!pmnr_frozen(s)||!pman_off(a))return pmnr_fail(s,5);s->phase=5;
    }else if(s->phase==5){int r=pman_step(a);
        if(r==PMAQ_CONSUMED){if(!pman_finish(a))return pmnr_fail(s,5);s->phase=6;}
        else if(r!=PMAQ_WAIT)return pmnr_fail(s,5);
    }else if(s->phase==6){
        const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
        if(!pwea_core_check(h->input.early,&s->source[1],&h->map)||!pmnr_frozen(s))return pmnr_fail(s,6);
        s->phase=7;s->complete=1;
    }else return pmnr_fail(s,6);
    if(!pmnr_live(s))return pmnr_fail(s,6);s->pending=0;
    if(s->complete){pweh_digest(s,offsetof(struct pmnr_state,digest),s->digest);return pmnr_current(s)?2:pmnr_fail(s,6);}return 1;
}
#endif
#endif
