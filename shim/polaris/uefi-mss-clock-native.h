/* Persistent native PRNG and six active MSS clocks within the current power
 * owner's CPU epoch. No startup registration, original provider, timer reset,
 * automatic unwind or inference that STOP proves secure/DMA retirement. */
#ifndef POLARIS_UEFI_MSS_CLOCK_NATIVE_H
#define POLARIS_UEFI_MSS_CLOCK_NATIVE_H
#ifndef EFI_XNU_MSS_CLOCK_NATIVE_AVAILABLE
#define EFI_XNU_MSS_CLOCK_NATIVE_AVAILABLE 0
#endif
#if EFI_XNU_MSS_CLOCK_NATIVE_AVAILABLE
#if !EFI_XNU_MSS_POWER_NATIVE_AVAILABLE || !EFI_XNU_MSS_PROXY_IO_AVAILABLE
#error Native MSS clocks require the persistent power owner and typed proxy leaves
#endif
#include "uefi-mss-power-native.h"
#define PMCN_RECORDS (PMPX_EVENTS+PMCK_EVENTS)
struct pmcn_delivery {
    uint64_t child;uint32_t kind,attempted,unknown,error,complete,reserved;
    union {struct pmpx_command proxy;struct pmck_command clock;} command;
    struct pmrg_target target[2];struct pmni_arch opening;struct pmni_result native;
    uint8_t digest[32];
};
struct pmcn_state {
    uint64_t power,opening,records,clocks;
    uint32_t attempted,ready,unknown,error,pending,deliveries,proxy_calls,clock_calls,restored,reserved;
    uint8_t digest[32];
};
static inline int pmcn_fail(struct pmcn_state*s,unsigned error)
{
    s->unknown=1;if(!s->error)s->error=error;
    if(s->power)pmpn_fail((void*)(uintptr_t)s->power,9);return 0;
}
static inline int pmcn_live(struct pmcn_state*s)
{
    if(!s||s->ready!=1||s->unknown||s->error||s->restored||s->deliveries>PMCN_RECORDS)return 0;
    struct pmpn_state*p=(void*)(uintptr_t)s->power;
    return p->opening==s->opening&&pmpn_live(p);
}
static inline int pmcn_child(struct pmcn_state*s,uint64_t at,uint64_t bytes)
{
    struct pmpn_state*p=(void*)(uintptr_t)s->power;
    return pmpn_child(p,at,bytes)&&pwea_disjoint(at,bytes,(uintptr_t)s,sizeof(*s))&&
        pwea_disjoint(at,bytes,s->records,sizeof(struct pmcn_delivery)*PMCN_RECORDS)&&
        (!p->supplies||pwea_disjoint(at,bytes,p->supplies,sizeof(struct pmsp_lifecycle)))&&
        (!p->proxy||at==p->proxy||pwea_disjoint(at,bytes,p->proxy,sizeof(struct pmpx_lifecycle)));
}
static inline int pmcn_begin(struct pmcn_state*s,struct pmcn_delivery*r,struct pmpn_state*p)
{
    if(!s||!r||!p||!pwmc_zero(s,sizeof(*s)))return 0;s->attempted=1;
    uint64_t bytes=sizeof(*r)*PMCN_RECORDS;
    if(!pmpn_live(p)||p->requests||p->pending||p->restored||!pmpn_child(p,(uintptr_t)s,sizeof(*s))||
       !pmpn_child(p,(uintptr_t)r,bytes)||!pwea_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)r,bytes)||
       !pwmc_zero(r,bytes))return pmcn_fail(s,1);
    s->power=(uintptr_t)p;s->opening=p->opening;s->records=(uintptr_t)r;s->ready=1;return pmcn_live(s);
}
/* Shared delivery machinery is private: only the two exact typed pending
 * adapters below call it. Each successful full observation stays resident. */
static inline struct pmcn_delivery*pmcn_open(struct pmcn_state*s,uint64_t child,unsigned kind,
    const void*command,const struct pmni_command*access)
{
    if(!pmcn_live(s)||s->pending||s->deliveries==PMCN_RECORDS||(kind!=1&&kind!=2))return 0;
    struct pmpn_state*p=(void*)(uintptr_t)s->power;
    struct pmcn_delivery*r=(struct pmcn_delivery*)(uintptr_t)s->records+s->deliveries;
    if(!pwmc_zero(r,sizeof(*r)))return 0;
    r->attempted=r->unknown=1;r->child=child;r->kind=kind;
    pgcd_copy(&r->command,command,kind==1?sizeof(struct pmpx_command):sizeof(struct pmck_command));
    s->pending=++s->deliveries;
    if((access->kind<=PMNI_WRITE&&!pmpn_target(p,access->address&~UINT64_C(4095),&r->target[0]))||
       !pmpn_arch(p,&r->opening)||!pgcd_equal(&r->opening,&p->architecture,offsetof(struct pmni_arch,ticks)))goto fail;
    if(access->kind==PMNI_WRITE&&!pmsc_mark_effect((void*)(uintptr_t)p->owner,PMSC_POWER))goto fail;
    return r;
fail:r->error=2;pmcn_fail(s,2);return 0;
}
static inline int pmcn_observed(struct pmcn_state*s,struct pmcn_delivery*r,const struct pmni_command*access)
{
    struct pmpn_state*p=(void*)(uintptr_t)s->power;
    if(!r->native.complete||r->native.unknown||r->native.error||
       !pgcd_equal(access,&r->native.command,sizeof(*access))||
       (access->kind<=PMNI_WRITE&&(!pmpn_target(p,access->address&~UINT64_C(4095),&r->target[1])||
           r->target[0].index!=r->target[1].index))||!pmcn_live(s))return pmcn_fail(s,3);
    return 1;
}
static inline int pmcn_close(struct pmcn_state*s,struct pmcn_delivery*r)
{
    if(!pmcn_live(s)||s->pending!=s->deliveries)return pmcn_fail(s,4);
    r->unknown=0;r->complete=1;pweh_digest(r,offsetof(struct pmcn_delivery,digest),r->digest);s->pending=0;return 1;
}
static inline int pmcn_proxy(struct pmcn_state*s,struct pmpx_lifecycle*x,const struct pmpx_command*c)
{
    if(!s||!x||!c||!pmcn_live(s)||!pmsr_disjoint(x,sizeof(*x),c,sizeof(*c)))return 0;
    struct pmpn_state*p=(void*)(uintptr_t)s->power;
    if(p->proxy!=(uintptr_t)x||!pmcn_child(s,(uintptr_t)x,sizeof(*x))||x->epoch!=s->opening||
       (x->phase!=1&&x->phase!=3)||x->unknown||x->error||p->proxy_calls!=3||x->opening!=p->proxy_opening||
       (x->phase==3&&(!p->proxy_release||x->release_at!=p->proxy_release))||
       c->kind<PMPX_READ||c->kind>PMPX_ORDER||!x->pending||x->pending!=x->events||
       x->events>PMPX_EVENTS||x->events!=s->proxy_calls+4||!pgcd_equal(c,&x->event[x->events-1].command,sizeof(*c)))return 0;
    const struct pmsp_lifecycle*supply=(const void*)(uintptr_t)p->supplies;
    if(!supply||supply->epoch!=s->opening||supply->phase!=3||supply->held!=1||supply->pending||supply->unknown||supply->error)return pmcn_fail(s,5);
    struct pmni_command access={c->address,c->kind==PMPX_ORDER?PMNI_FULL_ORDER:c->kind,c->value};
    struct pmcn_delivery*r=pmcn_open(s,(uintptr_t)x,1,c,&access);if(!r)return 0;
    if(!pmni_proxy(x,&r->command.proxy,&r->opening,&r->native)||!pmcn_observed(s,r,&access)||
       !pgcd_equal(c,&r->command.proxy,sizeof(*c))||
       pmpx_complete(x,&r->command.proxy,((struct pmsc_owner*)(uintptr_t)p->owner)->last,1,r->native.value,0)<0)return pmcn_fail(s,5);
    s->proxy_calls++;return pmcn_close(s,r);
}
static inline int pmcn_clock_begin(struct pmcn_state*s,struct pmck_lifecycle*c)
{
    if(!s||!c||!pmcn_live(s)||s->pending||s->clocks||s->clock_calls||!pmcn_child(s,(uintptr_t)c,sizeof(*c)))return 0;
    struct pmpn_state*p=(void*)(uintptr_t)s->power;const struct pmpx_lifecycle*x=(const void*)(uintptr_t)p->proxy;
    if(!x||x->epoch!=s->opening||x->phase!=2||x->held!=1||x->unknown||x->error||x->pending||
       x->events!=s->proxy_calls+3||p->proxy_calls!=3||!pmrg_current((void*)(uintptr_t)p->namespace)||!pmcn_live(s))return pmcn_fail(s,6);
    struct pmsc_owner*o=(void*)(uintptr_t)p->owner;
    if(pmck_begin(c,s->opening,o->last,o->current.cpu.frequency)<0)return pmcn_fail(s,6);
    s->clocks=(uintptr_t)c;return 1;
}
static inline int pmcn_clock_release(struct pmcn_state*s,struct pmck_lifecycle*c,const struct pmsd_shutdown*stop)
{
    if(!s||!c||!stop||!pmcn_live(s)||s->pending||s->clocks!=(uintptr_t)c||!pmcn_child(s,(uintptr_t)stop,sizeof(*stop))||
       !pwea_disjoint((uintptr_t)stop,sizeof(*stop),(uintptr_t)c,sizeof(*c)))return 0;
    struct pmpn_state*p=(void*)(uintptr_t)s->power;
    if(!pmrg_current((void*)(uintptr_t)p->namespace)||!pmcn_live(s)||
       pmck_release(c,stop,((struct pmsc_owner*)(uintptr_t)p->owner)->last)<0)return pmcn_fail(s,6);
    return 1;
}
static inline int pmcn_clock(struct pmcn_state*s,struct pmck_lifecycle*c,const struct pmck_command*command)
{
    if(!s||!c||!command||!pmcn_live(s)||!pmsr_disjoint(c,sizeof(*c),command,sizeof(*command))||
       s->clocks!=(uintptr_t)c||!pmcn_child(s,(uintptr_t)c,sizeof(*c))||c->epoch!=s->opening||
       (c->phase!=1&&c->phase!=3)||c->unknown||c->error||!c->pending||c->pending!=c->events||
       c->events>PMCK_EVENTS||c->events!=s->clock_calls+1||!pgcd_equal(command,&c->event[c->events-1].command,sizeof(*command)))return 0;
    struct pmpn_state*p=(void*)(uintptr_t)s->power;const struct pmpx_lifecycle*x=(const void*)(uintptr_t)p->proxy;
    if(!x||x->phase!=2||x->held!=1||x->epoch!=s->opening||x->unknown||x->error||x->pending)return pmcn_fail(s,7);
    struct pmni_command access={command->address,command->kind==PMCK_ORDER?PMNI_FULL_ORDER:command->kind,command->value};
    struct pmcn_delivery*r=pmcn_open(s,(uintptr_t)c,2,command,&access);if(!r)return 0;
    if(!pmni_clock(c,&r->command.clock,&r->opening,&r->native)||!pmcn_observed(s,r,&access)||
       !pgcd_equal(command,&r->command.clock,sizeof(*command))||
       pmck_complete(c,&r->command.clock,((struct pmsc_owner*)(uintptr_t)p->owner)->last,1,r->native.value)<0)return pmcn_fail(s,7);
    s->clock_calls++;return pmcn_close(s,r);
}
static inline int pmcn_finish(struct pmcn_state*s)
{
    if(!pmcn_live(s)||s->pending||s->deliveries!=s->proxy_calls+s->clock_calls||!s->clocks)return 0;
    struct pmpn_state*p=(void*)(uintptr_t)s->power;const struct pmpx_lifecycle*x=(const void*)(uintptr_t)p->proxy;
    const struct pmck_lifecycle*c=(const void*)(uintptr_t)s->clocks;uint8_t hash[32];
    pweh_digest(p,offsetof(struct pmpn_state,digest),hash);
    if(p->restored!=1||!pgcd_equal(hash,p->digest,32)||!x||x->events!=s->proxy_calls+6||
       c->phase!=4||c->held!=63||c->restored!=63||c->pending||c->unknown||c->error||c->events!=s->clock_calls)return pmcn_fail(s,8);
    const struct pmcn_delivery*r=(const void*)(uintptr_t)s->records;unsigned proxy=0,clocks=0;
    for(unsigned n=0;n<s->deliveries;n++){
        const struct pmcn_delivery*q=&r[n];pweh_digest(q,offsetof(struct pmcn_delivery,digest),hash);
        if(q->complete!=1||q->unknown||q->error||!pgcd_equal(hash,q->digest,32))return pmcn_fail(s,8);
        if(q->kind==1&&q->child==p->proxy)proxy++;else if(q->kind==2&&q->child==s->clocks)clocks++;else return pmcn_fail(s,8);
    }
    if(proxy!=s->proxy_calls||clocks!=s->clock_calls||!pmcn_live(s))return pmcn_fail(s,8);
    s->restored=1;pweh_digest(s,offsetof(struct pmcn_state,digest),s->digest);return 1;
}
#endif
#endif
