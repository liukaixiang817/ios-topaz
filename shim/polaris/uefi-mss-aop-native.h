/* Native AOP load_state on/off within the same current CPU/resource owner.
 * Uses only an already connected idle channel. No link takeover, provider,
 * RX drain, timer renewal, UNKNOWN cleanup or secure/DMA handback inference. */
#ifndef POLARIS_UEFI_MSS_AOP_NATIVE_H
#define POLARIS_UEFI_MSS_AOP_NATIVE_H
#ifndef EFI_XNU_MSS_AOP_NATIVE_AVAILABLE
#define EFI_XNU_MSS_AOP_NATIVE_AVAILABLE 0
#endif
#if EFI_XNU_MSS_AOP_NATIVE_AVAILABLE
#if !EFI_XNU_MSS_CLOCK_NATIVE_AVAILABLE || !EFI_XNU_MSS_AOP_IO_AVAILABLE
#error Native AOP requires the retained power/clock owner and exact AOP leaves
#endif
#include "uefi-mss-clock-native.h"
#define PMAN_RECORDS (2u*PMAQ_EVENTS)
struct pman_delivery {
    struct pmaq_command command;struct pmrg_target target[2];
    struct pmni_arch opening;struct pmni_result native;
    uint32_t side,attempted,unknown,error,complete,reserved;uint8_t digest[32];
};
struct pman_state {
    uint64_t power,clocks,records,opening;struct pmaq_notify notify[2];
    uint32_t attempted,ready,unknown,error,phase,pending,deliveries,completed[2],restored;
    uint8_t on_digest[32],digest[32];
};
static inline int pman_fail(struct pman_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;if(s->power)pmpn_fail((void*)(uintptr_t)s->power,10);return PMAQ_FAILED;}
static inline int pman_live(struct pman_state*s)
{
    if(!s||s->ready!=1||s->unknown||s->error||s->restored||s->deliveries>PMAN_RECORDS)return 0;
    struct pmpn_state*p=(void*)(uintptr_t)s->power;struct pmcn_state*c=(void*)(uintptr_t)s->clocks;
    return p->opening==s->opening&&c->opening==s->opening&&c->power==s->power&&c->ready==1&&!c->unknown&&!c->error&&pmpn_live(p);
}
static inline int pman_begin(struct pman_state*s,struct pman_delivery*r,struct pmcn_state*c)
{
    if(!s||!r||!c||!pwmc_zero(s,sizeof(*s)))return 0;s->attempted=1;
    uint64_t bytes=sizeof(*r)*PMAN_RECORDS;
    if(!pmcn_live(c)||c->deliveries||c->pending||c->clocks||!pmcn_child(c,(uintptr_t)s,sizeof(*s))||
       !pmcn_child(c,(uintptr_t)r,bytes)||!pwea_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)r,bytes)||!pwmc_zero(r,bytes))return 0;
    struct pmpn_state*p=(void*)(uintptr_t)c->power;
    if(p->requests||p->pending||p->supplies||p->proxy||!pmrg_current((void*)(uintptr_t)p->namespace)||!pmcn_live(c))return 0;
    s->power=c->power;s->clocks=(uintptr_t)c;s->records=(uintptr_t)r;s->opening=c->opening;s->ready=1;
    if(pmaq_on(&s->notify[0],s->opening,((struct pmsc_owner*)(uintptr_t)p->owner)->last)<0){pman_fail(s,1);return 0;}
    s->phase=1;return 1;
}
static inline int pman_off(struct pman_state*s)
{
    if(!pman_live(s)||s->phase!=1||s->pending||s->notify[0].complete!=1||s->completed[0]!=s->notify[0].events)return 0;
    struct pmcn_state*c=(void*)(uintptr_t)s->clocks;struct pmpn_state*p=(void*)(uintptr_t)s->power;uint8_t hash[32];
    pweh_digest(c,offsetof(struct pmcn_state,digest),hash);
    if(c->restored!=1||!pgcd_equal(hash,c->digest,32)||p->restored!=1)return 0;
    pweh_digest(p,offsetof(struct pmpn_state,digest),hash);if(!pgcd_equal(hash,p->digest,32))return 0;
    pweh_digest(&s->notify[0],sizeof(s->notify[0]),hash);if(!pgcd_equal(hash,s->on_digest,32))return 0;
    if(!pman_live(s)||pmaq_off(&s->notify[1],&s->notify[0],(const void*)(uintptr_t)p->proxy,
       (const void*)(uintptr_t)p->supplies,((struct pmsc_owner*)(uintptr_t)p->owner)->last)<0){pman_fail(s,2);return 0;}
    s->phase=2;return 1;
}
/* One actual pending command per call; WAIT also covers the protocol's own
 * polling delay. The caller must use the continuous counter, never synthesize
 * elapsed time or restart the phase after an uncertain return. */
static inline int pman_step(struct pman_state*s)
{
    if(!pman_live(s)||s->pending||(s->phase!=1&&s->phase!=2))return PMAQ_FAILED;
    unsigned side=s->phase-1;struct pmaq_notify*q=&s->notify[side];
    if(q->complete==1)return PMAQ_CONSUMED;
    struct pmpn_state*p=(void*)(uintptr_t)s->power;struct pmsc_owner*o=(void*)(uintptr_t)p->owner;
    struct pmaq_command command;int result=pmaq_next(q,o->last,&command);
    if(result==PMAQ_WAIT)return result;
    if(result!=PMAQ_IO||q->events!=s->completed[side]+1||s->deliveries==PMAN_RECORDS)return pman_fail(s,3);
    struct pman_delivery*r=(struct pman_delivery*)(uintptr_t)s->records+s->deliveries;
    if(!pwmc_zero(r,sizeof(*r)))return pman_fail(s,3);
    r->side=side;r->command=command;r->attempted=r->unknown=1;s->pending=++s->deliveries;
    unsigned memory=command.kind!=PMAQ_FULL_ORDER,failure=1;
    if(memory&&!pmpn_target(p,command.address&~UINT64_C(4095),&r->target[0]))goto fail;
    failure=2;if(!pmpn_arch(p,&r->opening))goto fail;
    failure=3;if(!pgcd_equal(&r->opening,&p->architecture,offsetof(struct pmni_arch,ticks)))goto fail;
    failure=4;if(command.kind==PMAQ_WRITE32&&!pmsc_mark_effect(o,PMSC_REMOTE))goto fail;
    failure=5;if(!pmni_aop(q,&r->command,&r->opening,&r->native))goto fail;
    failure=6;if(memory&&!pmpn_target(p,command.address&~UINT64_C(4095),&r->target[1]))goto fail;
    failure=7;if(memory&&r->target[0].index!=r->target[1].index)goto fail;
    failure=8;if(!pman_live(s))goto fail;
    failure=9;if(!pgcd_equal(&command,&r->command,sizeof(command)))goto fail;
    failure=10;result=pmaq_complete(q,&r->command,o->last,1,r->native.value);if(result<0)goto fail;
    r->unknown=0;r->complete=1;pweh_digest(r,offsetof(struct pman_delivery,digest),r->digest);
    s->completed[side]++;s->pending=0;
    if(result==PMAQ_CONSUMED&&!side)pweh_digest(q,sizeof(*q),s->on_digest);
    return result;
/* Keep the existing ABI/UNKNOWN behavior; reserved is failure-only detail. */
fail:r->reserved=failure;r->error=4;return pman_fail(s,4);
}
/* Only AOP transport/resource completion; CPU and secure/remote allocations
 * stay retained. No original firmware calls are re-enabled here. */
static inline int pman_finish(struct pman_state*s)
{
    if(!pman_live(s)||s->phase!=2||s->pending||s->completed[0]+s->completed[1]!=s->deliveries)return 0;
    for(unsigned side=0;side<2;side++){
        const struct pmaq_notify*q=&s->notify[side];
        if(q->complete!=1||q->unknown||q->error||q->pending||q->epoch!=s->opening||q->events!=s->completed[side])return 0;
    }
    uint8_t hash[32];pweh_digest(&s->notify[0],sizeof(s->notify[0]),hash);if(!pgcd_equal(hash,s->on_digest,32))return 0;
    const struct pman_delivery*r=(const void*)(uintptr_t)s->records;unsigned counts[2]={0};
    for(unsigned n=0;n<s->deliveries;n++){
        const struct pman_delivery*q=&r[n];pweh_digest(q,offsetof(struct pman_delivery,digest),hash);
        if(q->side>1||q->complete!=1||q->unknown||q->error||!pgcd_equal(hash,q->digest,32))return 0;counts[q->side]++;
    }
    if(counts[0]!=s->completed[0]||counts[1]!=s->completed[1]||!pman_live(s))return 0;
    s->restored=1;s->phase=3;pweh_digest(s,offsetof(struct pman_state,digest),s->digest);return 1;
}
#endif
#endif
