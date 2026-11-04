/* Continuous native MSS resource caller. Default OFF/unregistered. Uses only
 * current CPU/image/GCD/RPMh/TCS/CmdDb producers and typed pending supply/XO
 * commands. No provider, old client ticket, timer renewal or automatic unwind.
 * Each request and delivery remains resident. Failed last delivery keeps its
 * complete scratch record; successful deliveries retain all variable fields
 * plus a hash of the full native/namespace observations (constant fields are
 * fixed by the captured architecture and exact GCD node). */
#ifndef POLARIS_UEFI_MSS_POWER_NATIVE_H
#define POLARIS_UEFI_MSS_POWER_NATIVE_H
#ifndef EFI_XNU_MSS_POWER_NATIVE_AVAILABLE
#define EFI_XNU_MSS_POWER_NATIVE_AVAILABLE 0
#endif
#if EFI_XNU_MSS_POWER_NATIVE_AVAILABLE
#if !EFI_XNU_MSS_RSC_STATE_AVAILABLE || !EFI_XNU_MSS_CMDDB_AVAILABLE
#error Persistent MSS requests require current device-state and complete CmdDb producers
#endif
#include "uefi-mss-rsc-state.h"
#include "uefi-mss-cmddb.h"
#include "../../tools/polaris-mss-proxy.h"
#define PMPN_REQUESTS (PMSP_EVENTS+6u)
#define PMPN_CHECKPOINTS 12u
struct pmpn_delivery {
    uint64_t native_ticks[4],native_saved,native_par,namespace_saved[2][2],namespace_ticks[2][2];
    uint32_t namespace_index,native_value,complete,reserved;uint8_t leaf_digest[32];
};
struct pmpn_request {
    struct pmrv_request request;struct pmpn_delivery delivery[PWRSC_HISTORY];
    struct pmrg_target target[2];struct pmni_arch opening;struct pmni_result native;
    uint64_t child;uint32_t kind,attempted,unknown,error,retired,complete,deliveries,reserved;
    union {struct pmsp_command supply;struct pmpx_command proxy;} command;
    uint8_t child_before[32],child_after[32],digest[32];
};
struct pmpn_checkpoint {
    struct pwea_core core;struct pmrd_pass rpmh;struct pmdc_pass cmddb;
    uint64_t before,after;uint32_t attempted,complete;
};
struct pmpn_state {
    uint64_t owner,namespace,rpmh,device,database,records,opening,supplies,proxy,proxy_opening,proxy_release;
    uint8_t namespace_digest[32],rpmh_digest[32],device_digest[32],database_digest[32];
    struct pmni_arch architecture;
    uint32_t attempted,unknown,error,ready,requests,pending,supply_calls,proxy_calls,supply_phase,checkpoints;
    struct pmpn_checkpoint checkpoint[PMPN_CHECKPOINTS];uint32_t restored,reserved;uint8_t digest[32];
};
static inline void pmpn_clear(void*p,size_t bytes)
{for(size_t n=0;n<bytes;n++)((uint8_t*)p)[n]=0;}
static inline int pmpn_fail(struct pmpn_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return 0;}
static inline int pmpn_live(struct pmpn_state*s)
{
    if(!s||s->unknown||s->error||s->ready!=1||s->requests>PMPN_REQUESTS)return 0;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;struct pmrg_map*g=(void*)(uintptr_t)s->namespace;
    struct pmrd_state*p=(void*)(uintptr_t)s->rpmh;struct pmrs_state*d=(void*)(uintptr_t)s->device;
    struct pmdc_state*c=(void*)(uintptr_t)s->database;
    return o->opening==s->opening&&g->owner==s->owner&&p->owner==s->owner&&d->owner==s->owner&&c->owner==s->owner&&
        g->complete==1&&!g->unknown&&!g->error&&p->complete==1&&!p->unknown&&!p->error&&
        d->complete==1&&!d->unknown&&!d->error&&c->complete==1&&!c->unknown&&!c->error&&
        pgcd_equal(g->digest,s->namespace_digest,32)&&pgcd_equal(p->digest,s->rpmh_digest,32)&&
        pgcd_equal(d->digest,s->device_digest,32)&&pgcd_equal(c->digest,s->database_digest,32)&&pmrg_live(g);
}
/* Full immutable record bindings at phase boundaries, outside finite request
 * timing. Later device observations are requests' own snapshots, not the
 * admission snapshot relabeled as current after an effect. */
static inline int pmpn_bound(struct pmpn_state*s)
{
    if(!pmpn_live(s)||s->restored)return 0;
    struct pmrg_map*g=(void*)(uintptr_t)s->namespace;struct pmrd_state*p=(void*)(uintptr_t)s->rpmh;
    struct pmrs_state*d=(void*)(uintptr_t)s->device;struct pmdc_state*c=(void*)(uintptr_t)s->database;
    uint8_t hash[32];
    pweh_digest(d,offsetof(struct pmrs_state,digest),hash);if(!pgcd_equal(hash,s->device_digest,32))return 0;
    pweh_digest(c,offsetof(struct pmdc_state,digest),hash);if(!pgcd_equal(hash,s->database_digest,32))return 0;
    if(!pmrg_current(g)||!pmrd_current(p,g)||!pmrd_current(&d->after,g)||!pmpn_live(s)||s->checkpoints==PMPN_CHECKPOINTS)return 0;
    struct pmpn_checkpoint*q=&s->checkpoint[s->checkpoints++];
    if(!pwmc_zero(q,sizeof(*q)))return 0;q->attempted=1;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
    q->before=o->last;
    if(!pwea_core_check(h->input.early,&q->core,&h->map)||!pmpn_live(s)||!pmrd_source(p,&q->rpmh.source[0]))return 0;
    for(unsigned n=0;n<p->pass[1].reads;n++){
        const struct pmrd_read*old=&p->pass[1].read[n];
        const uint8_t*raw=pmrd_read(p,&q->rpmh,old->address,old->bytes,old->heap);
        if(!raw||!pgcd_equal(raw,old->raw,old->bytes))return 0;
    }
    if(!pmrd_source(p,&q->rpmh.source[1])||!pmdc_source(c,&q->cmddb.source[0]))return 0;
    q->rpmh.complete=1;
    for(unsigned n=0;n<c->pass[1].reads;n++){
        const struct pmrd_read*old=&c->pass[1].read[n];
        const uint8_t*raw=pmdc_read(c,&q->cmddb,old->address,old->bytes,old->heap);
        if(!raw||!pgcd_equal(raw,old->raw,old->bytes))return 0;
    }
    for(unsigned n=0;n<PMDC_PAGES;n++){
        struct pmdc_page*page=&q->cmddb.page[n];uint64_t at=PMDC_BASE+4096*n;
        if(!pmdc_target(c,page,at,0)||!pmdc_at(c,&page->AT,at))return 0;
        for(unsigned j=0;j<512;j++){
            uint64_t word;if(!pmdc_word(at+8*j,&word))return 0;pgcd_copy(q->cmddb.raw+4096*n+8*j,&word,8);page->words++;
        }
        if(!pmdc_target(c,page,at,1))return 0;page->complete=1;q->cmddb.pages++;
    }
    if(!pmdc_source(c,&q->cmddb.source[1])||!pgcd_equal(q->cmddb.raw,c->pass[1].raw,PMDC_BYTES)||
       !pmrg_current(g)||!pmpn_live(s))return 0;
    q->cmddb.complete=1;q->after=o->last;q->complete=1;return 1;
}
static inline int pmpn_arch(struct pmpn_state*s,struct pmni_arch*a)
{
    if(!pmpn_live(s)||!pmni_arch_read(a)||!pmni_arch_valid(a))return 0;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;const struct pwfc_arch*b=&o->current.cpu;
    return a->el==b->el&&a->mpidr==b->mpidr&&a->ttbr0==b->ttbr0&&a->ttbr1==b->ttbr1&&a->tcr==b->tcr&&
        a->sctlr==b->sctlr&&a->mair==b->mair&&a->daif==b->daif&&a->sre==b->sre&&a->group1==b->group1&&
        a->cpacr==o->current.cpacr&&a->frequency==b->frequency&&a->ticks>=o->last&&
        a->ticks-s->opening<=PMSC_TOTAL&&pmpn_live(s);
}
static inline int pmpn_begin(struct pmpn_state*s,struct pmpn_request*records,
    struct pmrs_state*d,struct pmdc_state*c,struct pmrd_state*p,struct pmrg_map*g)
{
    if(!s||!records||!d||!c||!p||!g||!pwmc_zero(s,sizeof(*s)))return 0;s->attempted=1;
    if(!pmrs_current(d,p,g)||!pmdc_current(c,g)||d->owner!=c->owner)return pmpn_fail(s,1);
    struct pmsc_owner*o=(void*)(uintptr_t)g->owner;const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
    const struct pwea_native*e=h->input.early;const struct pmsb_result*b=(const void*)(uintptr_t)o->mba;
    uint64_t bytes=sizeof(*records)*PMPN_REQUESTS;
    if(!pmsi_image_range(e,&h->map,(uintptr_t)s,sizeof(*s))||!pmsi_image_range(e,&h->map,(uintptr_t)records,bytes)||
       !pwea_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)records,bytes)||!pwmc_zero(records,bytes))return pmpn_fail(s,1);
    const uint64_t bases[]={(uintptr_t)d,(uintptr_t)c,(uintptr_t)p,(uintptr_t)g,g->images,(uintptr_t)o,(uintptr_t)h,(uintptr_t)e,o->memory,o->mba,b->stage,e->native_address,e->image_address};
    const uint64_t sizes[]={sizeof(*d),sizeof(*c),sizeof(*p),sizeof(*g),sizeof(struct pmli_ledger),sizeof(*o),sizeof(*h),sizeof(*e),sizeof(struct pmmn_native),sizeof(*b),sizeof(struct pmsi_result),4,sizeof(e->image)};
    for(unsigned n=0;n<13;n++)if(!pwea_disjoint((uintptr_t)s,sizeof(*s),bases[n],sizes[n])||
       !pwea_disjoint((uintptr_t)records,bytes,bases[n],sizes[n]))return pmpn_fail(s,1);
    s->owner=g->owner;s->namespace=(uintptr_t)g;s->rpmh=(uintptr_t)p;s->device=(uintptr_t)d;s->database=(uintptr_t)c;
    s->records=(uintptr_t)records;s->opening=o->opening;
    pgcd_copy(s->namespace_digest,g->digest,32);pgcd_copy(s->rpmh_digest,p->digest,32);
    pgcd_copy(s->device_digest,d->digest,32);pgcd_copy(s->database_digest,c->digest,32);s->ready=1;
    if(!pmpn_arch(s,&s->architecture)||!pmpn_bound(s))return pmpn_fail(s,1);return 1;
}
/* CPU-local source exclusion makes the captured records immutable. Read the
 * actual selected GCD node afresh before AND after each Device delivery. */
static inline int pmpn_target(struct pmpn_state*s,uint64_t page,struct pmrg_target*t)
{
    if(!pwmc_zero(t,sizeof(*t))||!pmrg_device_page(page)||!pmpn_live(s))return 0;
    struct pmrg_map*g=(void*)(uintptr_t)s->namespace;struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
    t->attempted=t->unknown=1;t->page=page;t->before=o->last;
    if(!pmrg_map_excludes(h,page))return 0;
    for(unsigned n=0;n<g->pass[1].nodes;n++){
        const struct pmli_read*q=&g->pass[1].node[n];uint64_t base=pwfi_le(q->raw+24,8),end=pwfi_le(q->raw+32,8);
        if(base>page||end<page+4095)continue;t->index=n;
        if(end-base==UINT64_MAX||pwfi_le(q->raw+56,4)!=3||!(pwfi_le(q->raw+40,8)&1)||pwfi_le(q->raw+48,8)>1||
           !pmrg_read(g,&t->node,q->address,80,1))return 0;
        if(!pmli_read_equal(q,&t->node)){pmrg_fail(g,5);return 0;}
        t->descriptor=(struct pgcd_descriptor){base,end-base+1,pwfi_le(q->raw+40,8),pwfi_le(q->raw+48,8),3,0,pwfi_le(q->raw+64,8),pwfi_le(q->raw+72,8)};
        t->after=o->last;t->unknown=0;t->complete=1;return pmpn_live(s);
    }return 0;
}
static inline int pmpn_clock(void*context,uint64_t*now,uint64_t*hz)
{
    struct pmpn_state*s=context;if(!s->pending||s->pending!=s->requests||!pmpn_live(s))return 0;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;*now=o->last;*hz=o->current.cpu.frequency;return 1;
}
static inline void pmpn_order(void*context)
{
    (void)context;
#if defined(__aarch64__) || defined(__arm64__)
    __asm__ volatile("dsb sy":::"memory");
#else
    __asm__ volatile("":::"memory");
#endif
}
static inline int pmpn_access(struct pmpn_state*s,uint64_t at,uint32_t*value,unsigned write)
{
    if(!s->pending||s->pending!=s->requests||s->requests>PMPN_REQUESTS||!pmpn_live(s))return pmpn_fail(s,2);
    struct pmpn_request*r=(struct pmpn_request*)(uintptr_t)s->records+s->pending-1;struct pmrv_request*q=&r->request;
    if(r->unknown||r->error||r->complete||q->io.events!=r->deliveries+1||q->io.events>PWRSC_HISTORY)return pmpn_fail(s,2);
    struct pwrsc_event*e=&q->io.history[q->io.events-1];
    if(e->address!=at||e->operation!=(write?2u:1u)||(write&&e->value!=*value))return pmpn_fail(s,2);
    pmpn_clear(r->target,sizeof(r->target));pmpn_clear(&r->native,sizeof(r->native));pmpn_clear(&r->opening,sizeof(r->opening));
    if(!pmpn_target(s,at&~UINT64_C(4095),&r->target[0])||!pmpn_arch(s,&r->opening)||
       !pgcd_equal(&r->opening,&s->architecture,offsetof(struct pmni_arch,ticks)))return pmpn_fail(s,3);
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    if(write&&!pmsc_mark_effect(o,PMSC_POWER))return pmpn_fail(s,3);
    if(!pmni_rail(q,e,&r->opening,&r->native)||!pmpn_target(s,at&~UINT64_C(4095),&r->target[1])||
       r->target[0].index!=r->target[1].index||!pmpn_live(s))return pmpn_fail(s,4);
    struct pmpn_delivery*d=&r->delivery[r->deliveries];
    d->native_ticks[0]=r->opening.ticks;d->native_ticks[1]=r->native.before.ticks;
    d->native_ticks[2]=r->native.translated.ticks;d->native_ticks[3]=r->native.after.ticks;
    d->native_saved=r->native.AT.saved;d->native_par=r->native.AT.read_par;
    d->namespace_index=r->target[0].index;d->native_value=r->native.value;
    for(unsigned n=0;n<2;n++){
        d->namespace_ticks[n][0]=r->target[n].before;d->namespace_ticks[n][1]=r->target[n].after;
        for(unsigned j=0;j<r->target[n].node.pages;j++)d->namespace_saved[n][j]=r->target[n].node.AT[j].saved;
    }
    struct pwfi_sha256 hash;pwfi_init(&hash);
    const void*parts[]={&r->opening,&r->native,r->target};const size_t sizes[]={sizeof(r->opening),sizeof(r->native),sizeof(r->target)};
    for(unsigned part=0;part<3;part++)for(size_t n=0;n<sizes[part];n++)pwfi_byte(&hash,((const uint8_t*)parts[part])[n]);
    pwfi_final(&hash,d->leaf_digest);d->complete=1;r->deliveries++;
    if(!write)*value=r->native.value;return 1;
}
static inline int pmpn_read(void*c,uint64_t at,uint32_t*v){return pmpn_access(c,at,v,0);}
static inline int pmpn_write(void*c,uint64_t at,uint32_t v){return pmpn_access(c,at,&v,1);}
static inline int pmpn_child(struct pmpn_state*s,uint64_t at,uint64_t bytes)
{
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
    struct pmrg_map*g=(void*)(uintptr_t)s->namespace;const struct pwea_native*e=h->input.early;
    const struct pmsb_result*b=(const void*)(uintptr_t)o->mba;
    const uint64_t bases[]={(uintptr_t)s,s->records,s->device,s->database,s->rpmh,s->namespace,g->images,s->owner,(uintptr_t)h,o->memory,o->mba,(uintptr_t)e,b->stage,e->native_address,e->image_address};
    const uint64_t sizes[]={sizeof(*s),sizeof(struct pmpn_request)*PMPN_REQUESTS,sizeof(struct pmrs_state),sizeof(struct pmdc_state),sizeof(struct pmrd_state),sizeof(struct pmrg_map),sizeof(struct pmli_ledger),sizeof(*o),sizeof(*h),sizeof(struct pmmn_native),sizeof(struct pmsb_result),sizeof(*e),sizeof(struct pmsi_result),4,sizeof(e->image)};
    if(!pmsi_image_range(h->input.early,&h->map,at,bytes))return 0;
    for(unsigned n=0;n<15;n++)if(!pwea_disjoint(at,bytes,bases[n],sizes[n]))return 0;return 1;
}
static inline struct pmpn_request*pmpn_run(struct pmpn_state*s,uint64_t child,unsigned kind,const void*command,
    unsigned resource,unsigned write,uint32_t value)
{
    if(!pmpn_live(s)||s->pending||s->requests==PMPN_REQUESTS||(kind!=1&&kind!=2)||!pmrv_input(resource,write,value))return 0;
    struct pmpn_request*r=(struct pmpn_request*)(uintptr_t)s->records+s->requests;
    if(!pwmc_zero(r,sizeof(*r)))return 0;r->attempted=1;r->child=child;r->kind=kind;
    size_t child_bytes=kind==1?sizeof(struct pmsp_lifecycle):sizeof(struct pmpx_lifecycle);
    size_t command_bytes=kind==1?sizeof(struct pmsp_command):sizeof(struct pmpx_command);
    pgcd_copy(&r->command,command,command_bytes);pweh_digest((const void*)(uintptr_t)child,child_bytes,r->child_before);
    s->requests++;s->pending=s->requests;struct pmrs_state*d=(void*)(uintptr_t)s->device;
    struct pwrsc_io io={.context=s,.read=pmpn_read,.write=pmpn_write,.clock=pmpn_clock,.order=pmpn_order};
    if(!pmrv_begin(&io,&r->request,s->opening,d->active_mask,d->selected,resource,write,value))goto fail;
    const struct pwrsc_registers*saved=&r->request.io.saved;const uint32_t*expected=d->tcs[1][d->selected];
    if(saved->wait!=expected[0]||saved->control!=expected[1]||saved->status!=expected[2]||saved->enable!=expected[3]||
       r->request.io.IRQ_enable!=d->enable[1])goto fail;
    int result=0;for(unsigned n=0;n<256&&!result;n++)result=pmrv_step(&io,&r->request);
    if(result!=1||!pmrv_retired(&r->request)||r->deliveries!=r->request.io.events||!pmpn_live(s))goto fail;
    pweh_digest((const void*)(uintptr_t)child,child_bytes,r->child_after);
    if(!pgcd_equal(r->child_before,r->child_after,32))goto fail;r->retired=1;return r;
fail:
    r->unknown=1;if(!r->error)r->error=5;pmpn_fail(s,5);return 0;
}
static inline int pmpn_supply(struct pmpn_state*s,struct pmsp_lifecycle*p,const struct pmsp_command*c)
{
    if(!s||!p||!c||!pmsr_disjoint(p,sizeof(*p),c,sizeof(*c))||!pmpn_live(s)||!pmpn_child(s,(uintptr_t)p,sizeof(*p))||
       p->unknown||p->error||p->epoch!=s->opening||!p->pending||p->pending!=p->events||
       p->events!=s->supply_calls+1||p->events>PMSP_EVENTS||!pgcd_equal(c,&p->event[p->events-1].command,sizeof(*c))||
       c->phase!=p->phase||c->index!=p->index||(s->supplies&&s->supplies!=(uintptr_t)p)||
       (s->proxy&&!pwea_disjoint((uintptr_t)p,sizeof(*p),s->proxy,sizeof(struct pmpx_lifecycle))))return 0;
    if(p->phase>=4){
        if(!s->proxy||s->proxy_calls!=6)return pmpn_fail(s,6);
        const struct pmpx_lifecycle*proxy=(const void*)(uintptr_t)s->proxy;
        if(proxy->epoch!=s->opening||proxy->phase!=4||proxy->restored!=1||proxy->unknown||proxy->error||proxy->pending||
           p->release_at<proxy->last)return pmpn_fail(s,6);
    }
    struct pmdc_state*db=(void*)(uintptr_t)s->database;
    for(unsigned n=0;n<3;n++)if(p->minimum[n]!=db->pass[1].resource[n].minimum)return pmpn_fail(s,6);
    if(s->supply_phase!=p->phase){if(!pmpn_bound(s))return pmpn_fail(s,6);s->supply_phase=p->phase;}
    s->supplies=(uintptr_t)p;struct pmpn_request*r=pmpn_run(s,(uintptr_t)p,1,c,c->resource,c->write,c->value);if(!r)return 0;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    if(!pgcd_equal(c,&r->command.supply,sizeof(*c))){r->unknown=1;return pmpn_fail(s,6);}
    int result=pmsp_complete(p,&r->command.supply,&r->request,o->last);
    if(result<0||((result==PMSP_HELD||result==PMSP_RESTORED)&&!pmpn_bound(s))){r->unknown=1;return pmpn_fail(s,6);}
    s->supply_calls++;s->pending=0;r->complete=1;pweh_digest(r,offsetof(struct pmpn_request,digest),r->digest);return 1;
}
/* Perform expensive source checkpoints BEFORE starting the proxy's own200ms
 * transition. This never changes the continuous CPU owner's opening/deadline. */
static inline int pmpn_proxy_begin(struct pmpn_state*s,struct pmpx_lifecycle*p)
{
    if(!s||!p||!pmpn_live(s)||s->pending||s->proxy||s->proxy_calls||!s->supplies||
       !pmpn_child(s,(uintptr_t)p,sizeof(*p))||!pwea_disjoint((uintptr_t)p,sizeof(*p),s->supplies,sizeof(struct pmsp_lifecycle)))return 0;
    const struct pmsp_lifecycle*supply=(const void*)(uintptr_t)s->supplies;
    if(!pmpn_bound(s))return pmpn_fail(s,7);
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    if(pmpx_begin(p,supply,o->last)<0)return pmpn_fail(s,7);
    s->proxy=(uintptr_t)p;s->proxy_opening=p->opening;return 1;
}
static inline int pmpn_proxy_release(struct pmpn_state*s,struct pmpx_lifecycle*p,const struct pmck_lifecycle*c)
{
    if(!s||!p||!c||!pmpn_live(s)||s->pending||s->proxy!=(uintptr_t)p||s->proxy_calls!=3||s->proxy_release||!s->supplies||
       !pmpn_child(s,(uintptr_t)c,sizeof(*c))||!pwea_disjoint((uintptr_t)c,sizeof(*c),s->supplies,sizeof(struct pmsp_lifecycle)))return 0;
    if(!pmpn_bound(s))return pmpn_fail(s,7);
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;const struct pmsp_lifecycle*supply=(const void*)(uintptr_t)s->supplies;
    if(pmpx_release(p,supply,c,o->last)<0)return pmpn_fail(s,7);
    s->proxy_release=p->release_at;return 1;
}
static inline int pmpn_proxy(struct pmpn_state*s,struct pmpx_lifecycle*p,const struct pmpx_command*c)
{
    static const unsigned step[]={PMPX_XO_SAMPLE,PMPX_XO_ON,PMPX_XO_VERIFY,PMPX_XO_RETURN_SAMPLE,PMPX_XO_RETURN,PMPX_XO_RETURN_VERIFY};
    if(!s||!p||!c||!pmsr_disjoint(p,sizeof(*p),c,sizeof(*c))||!pmpn_live(s)||!pmpn_child(s,(uintptr_t)p,sizeof(*p))||s->proxy_calls>=6||!s->supplies||
       p->unknown||p->error||p->epoch!=s->opening||!p->pending||p->pending!=p->events||p->events>PMPX_EVENTS||
       c->kind!=PMPX_RAIL||c->step!=p->step||p->step!=step[s->proxy_calls]||
       !pgcd_equal(c,&p->event[p->events-1].command,sizeof(*c))||s->proxy!=(uintptr_t)p||p->opening!=s->proxy_opening||
       (s->proxy_calls<3?p->phase!=1:(p->phase!=3||!s->proxy_release||p->release_at!=s->proxy_release))||
       !pwea_disjoint((uintptr_t)p,sizeof(*p),s->supplies,sizeof(struct pmsp_lifecycle)))return 0;
    const struct pmsp_lifecycle*supply=(const void*)(uintptr_t)s->supplies;
    if(supply->epoch!=s->opening||supply->phase!=3||supply->held!=1||supply->pending||supply->unknown||supply->error||
       !supply->held_at||p->opening<supply->held_at)return pmpn_fail(s,7);
    s->proxy=(uintptr_t)p;struct pmpn_request*r=pmpn_run(s,(uintptr_t)p,2,c,PMRV_XO,c->write,c->value);if(!r)return 0;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    if(!pgcd_equal(c,&r->command.proxy,sizeof(*c))||pmpx_complete(p,&r->command.proxy,o->last,1,0,&r->request)<0){r->unknown=1;return pmpn_fail(s,7);}
    s->proxy_calls++;s->pending=0;r->complete=1;pweh_digest(r,offsetof(struct pmpn_request,digest),r->digest);return 1;
}
/* Resource retirement only. CPU/remote/DMA/VMID ownership remains held for
 * the full parent's separate retirement, and its effect bits are not cleared. */
static inline int pmpn_finish(struct pmpn_state*s)
{
    if(!s||!pmpn_live(s)||s->restored||s->pending||s->requests!=PMPN_REQUESTS||s->supply_calls!=PMSP_EVENTS||s->proxy_calls!=6||
       !s->supplies||!s->proxy)return 0;
    const struct pmsp_lifecycle*p=(const void*)(uintptr_t)s->supplies;const struct pmpx_lifecycle*x=(const void*)(uintptr_t)s->proxy;
    if(p->epoch!=s->opening||p->phase!=7||p->restored!=1||p->unknown||p->error||p->pending||
       x->epoch!=s->opening||x->phase!=4||x->restored!=1||x->unknown||x->error||x->pending||!pmpn_bound(s))return pmpn_fail(s,8);
    const struct pmpn_request*r=(const void*)(uintptr_t)s->records;uint8_t hash[32];unsigned supplies=0,proxy=0;
    for(unsigned n=0;n<s->requests;n++){
        const struct pmpn_request*q=&r[n];pweh_digest(q,offsetof(struct pmpn_request,digest),hash);
        if(!pgcd_equal(hash,q->digest,32)||q->complete!=1||q->retired!=1||q->unknown||q->error||
           q->request.epoch!=s->opening||!pmrv_retired(&q->request)||q->deliveries!=q->request.io.events)return pmpn_fail(s,8);
        for(unsigned j=0;j<q->deliveries;j++)if(q->delivery[j].complete!=1)return pmpn_fail(s,8);
        if(q->kind==1&&q->child==s->supplies)supplies++;
        else if(q->kind==2&&q->child==s->proxy)proxy++;
        else return pmpn_fail(s,8);
    }
    if(supplies!=PMSP_EVENTS||proxy!=6||!pmpn_live(s))return pmpn_fail(s,8);
    s->restored=1;pweh_digest(s,offsetof(struct pmpn_state,digest),s->digest);return 1;
}
#endif
#endif
