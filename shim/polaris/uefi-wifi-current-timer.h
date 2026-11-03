/* Actual current physical-timer/deferred INPUT inside the still-active
 * later-provider caller. No firmware method, IRQ dispatch or owner lease.
 * The existing two provider closing virtual samples keep the first window. */
#ifndef POLARIS_UEFI_WIFI_CURRENT_TIMER_H
#define POLARIS_UEFI_WIFI_CURRENT_TIMER_H
#if !defined(POLARIS_WIFI_CURRENT_TIMER_INPUT)
#error This input requires the genuine active later-provider path
#endif
struct pcmt_sample {
    uint64_t pending,counter,head[27][2];uint32_t attempted,complete,head_count,reserved;
};
struct pcmt_binding {
    const struct pcmi_live*caller;struct pcmi_live before;
    uint64_t virtual_before;uint8_t provider_seal[32];
};
struct pcmt_result {
    struct pcmt_binding binding;uint8_t binding_digest[32];
    struct pcmt_sample sample[2];struct pwmc_irq_regs regs[2];
    uint32_t native[4],leaf_status[2];uint64_t counter_after[2];struct pcmi_live caller_after;
    uint32_t attempted,complete,unknown,error,issued,returned,native_issued,native_returned,copied,reserved,counter_issued,counter_returned;
    uint8_t digest[32];
};
struct pcmt_live {struct pcmt_result*r;struct pcmi_live*caller;uint8_t binding_seal[32];};
_Static_assert(sizeof(struct pcmi_live)==448&&offsetof(struct pcmi_live,timer)==408&&
    sizeof(struct pcmt_binding)==496&&sizeof(struct pcmt_sample)==464&&sizeof(struct pcmt_result)==2136,
    "independent current physicaltimer/deferred INPUT ABI v1");
_Static_assert(offsetof(struct pcmt_result,sample)==528&&offsetof(struct pcmt_result,regs)==1456&&
    offsetof(struct pcmt_result,caller_after)==1608&&offsetof(struct pcmt_result,digest)==2104,
    "independent current physicaltimer/deferred decoder offsets");
#if defined(POLARIS_WIFI_CURRENT_TIMER_SOFTWARE_PEER)
#if !__STDC_HOSTED__
#error Software physical-register peer must never enter native firmware
#endif
static int pcmt_test_regs(struct pwmc_irq_regs*,unsigned);
#endif
static inline int pcmt_fail(struct pcmt_result*r,unsigned error)
{if(!r->error)r->error=error;r->unknown=1;return 0;}
static inline int pcmt_queues_current(const struct pcmt_result*r,uint64_t core)
{
    for(unsigned n=0;n<2;n++){
        if(!r->sample[n].complete)continue;
        const struct pcmt_sample*s=&r->sample[n];
        if(pwfi_le((const void*)(uintptr_t)(core+0x1dbc0),8)!=s->pending)return 0;
        for(unsigned k=0;k<s->head_count;k++)if(!pgcd_equal(s->head[k],
            (const void*)(uintptr_t)(core+0x1c928+16*(k+5)),16))return 0;
    }
    return 1;
}
static inline int pcmt_control(const struct pcmt_live*l)
{
    const struct pcmt_result*r=l->r;uint8_t hash[32];ppli_sha(&r->binding,sizeof(r->binding),hash);
    if(!pgcd_equal(hash,l->binding_seal,32)||!pgcd_equal(r->binding_digest,l->binding_seal,32)||
       r->binding.caller!=l->caller||!pgcd_equal(l->caller,&r->binding.before,sizeof(*l->caller))||
       r->attempted!=1||r->complete||r->unknown!=1||r->error||r->reserved||r->copied||
       r->issued>3||r->returned>3||(r->returned&~r->issued)||r->native_issued>15||
       r->counter_issued>3||r->counter_returned!=r->counter_issued||
       r->native_returned!=r->native_issued||!pwmc_zero(&r->caller_after,sizeof(r->caller_after))||
       !pwmc_zero(r->digest,sizeof(r->digest)))return 0;
    /* The entire real provider stack is compared before following pointers.
     * Its existing source readers retain every original caller/graph guard. */
    ppli_sha(l->caller->r,sizeof(*l->caller->r),hash);
    if(!pgcd_equal(hash,r->binding.provider_seal,32))return 0;
    for(unsigned n=0;n<2;n++)if(r->sample[n].head_count>27||r->sample[n].reserved)return 0;
    return 1;
}
static inline int pcmt_source(const struct pcmt_live*l)
{
    return pcmt_control(l)&&pcmi_source(l->caller)&&pcmt_queues_current(l->r,l->caller->core);
}
static inline void pcmt_seal(const struct pcmt_result*r,const void*skip,size_t bytes,uint8_t out[32])
{struct pwfi_sha256 h;pwfi_init(&h);pbgi_hash_part(&h,r,sizeof(*r),skip,bytes);pwfi_final(&h,out);}
static inline int pcmt_sample(struct pcmt_live*l,unsigned slot)
{
    struct pcmt_result*r=l->r;struct pcmt_sample*s=&r->sample[slot];
    if(!pcmt_source(l)||!pwmc_zero(s,sizeof(*s)))return 0;s->attempted=1;
    if(!pwmc_deferred_read(l->caller->core,5,27,&s->pending,&s->counter,s->head,&s->head_count))return 0;
    if(pwfi_le((const void*)(uintptr_t)(l->caller->core+0x1dbc0),8)!=s->pending)return 0;
    for(unsigned k=0;k<27;k++)if(!pgcd_equal(s->head[k],
        (const void*)(uintptr_t)(l->caller->core+0x1c928+16*(k+5)),16))return 0;
    s->complete=1;return 1;
}
static __attribute__((noinline)) int pcmt_regs(struct pcmt_live*l,unsigned slot)
{
    struct pcmt_result*r=l->r;if(slot>1||!pcmt_source(l))return 0;
    unsigned first=2*slot;struct pwmc_irq_regs*q=&r->regs[slot];
    if(!pwmc_zero(q,sizeof(*q))||r->issued!=slot||r->returned!=slot)return 0;
    r->native_issued|=1u<<first;r->native[first]=*l->caller->frame.input.native_flag;r->native_returned|=1u<<first;
    if(r->native[first]||!pcmt_sample(l,slot))return 0;r->issued|=1u<<slot;
    uint8_t before[32],after[32],control[32],actual[32];pcmt_seal(r,q,sizeof(*q),before);ppli_sha(l,sizeof(*l),control);
#if defined(POLARIS_WIFI_CURRENT_TIMER_SOFTWARE_PEER)
    int ok=pcmt_test_regs(q,slot);
#else
    int ok=pwmc_irq_regs_native(q);
#endif
    /* Broken own storage/control is left untouched. After that closure,
     * preserve call-return/status independently of source refusal. */
    pcmt_seal(r,q,sizeof(*q),after);ppli_sha(l,sizeof(*l),actual);
    if(!pgcd_equal(control,actual,32)||!pgcd_equal(before,after,32))return 0;
    r->returned|=1u<<slot;r->leaf_status[slot]=ok?1:0;
    if(!ok||!pcmt_control(l))return 0;
    uint64_t end,steps,notify;const struct pcmi_live*p=l->caller;
    uint64_t frequency=p->r->clock[p->r->arch_returned-1].raw.cpu.frequency;
    /* Already sealed own DATA first: refuse a known bad physical sample
     * before following any Core/provider/graph RAM address after the leaf. */
    if(!pwmc_irq_work_math(&p->r->path,&r->regs[0],q,r->binding.virtual_before,
       frequency,r->sample[slot].counter,r->regs[0].ticks,&end,&steps,&notify))return 0;
    uint64_t old_end,old_steps,old_notify;
    if(!pwmc_irq_work_math(&p->r->path,&r->regs[0],&r->regs[0],r->binding.virtual_before,
       frequency,r->sample[0].counter,r->regs[0].ticks,&old_end,&old_steps,&old_notify))return 0;
    uint64_t period=pwfi_le(p->r->path.image[0].state+56,8),missed=pwfi_le(p->r->path.image[0].state,8);
    uint64_t bound=period*(missed+old_steps+2);
    if(slot&&(r->sample[1].counter<r->counter_after[0]||r->sample[1].counter-r->sample[0].counter>bound))return 0;
    if(!pcmt_source(l))return 0;
    r->counter_issued|=1u<<slot;r->counter_after[slot]=pwfi_le((const void*)(uintptr_t)(p->core+0x1dc00),8);r->counter_returned|=1u<<slot;
    if(r->counter_after[slot]<r->sample[slot].counter||r->counter_after[slot]-r->sample[0].counter>bound||
       !pwmc_irq_work_math(&p->r->path,&r->regs[0],q,r->binding.virtual_before,
        frequency,r->counter_after[slot],r->regs[0].ticks,&end,&steps,&notify))return 0;
    r->native_issued|=1u<<(first+1);r->native[first+1]=*p->frame.input.native_flag;r->native_returned|=1u<<(first+1);
    return !r->native[first+1];
}
static __attribute__((noinline)) int pcmt_capture(struct pcmt_result*r,struct pcmi_live*caller)
{
    if(!r||!caller||!pcmi_source(caller)||caller->timer||!pwmc_zero(caller->timer_seal,32)||
       !pcmg_output_storage(r,sizeof(*r),caller->parent)||
       pwmc_parent_overlap((uintptr_t)r,sizeof(*r),(uintptr_t)caller,sizeof(*caller))||
       pwmc_parent_overlap((uintptr_t)r,sizeof(*r),(uintptr_t)caller->r,sizeof(*caller->r))||
       pwmc_parent_overlap((uintptr_t)r,sizeof(*r),(uintptr_t)caller->graph,sizeof(*caller->graph))||!pwmc_zero(r,sizeof(*r)))return 0;
    const struct pcmi_result*p=caller->r;
    if(!p->arch_returned||p->arch_returned>PCMI_CLOCK_MAX||p->arch_issued!=p->arch_returned||
       !caller->rooted||caller->table_mask!=7||!caller->handlers||p->path.complete||p->path.finalized)return 0;
    const struct pbgi_clock*last=&p->clock[p->arch_returned-1];
    if(last->issued!=1||last->returned!=1||last->native_issued!=3||last->native_returned!=3||
       last->native[0]||last->native[1]||last->raw.cpu.ticks<caller->opening||
       last->raw.cpu.ticks-caller->opening>PGCD_FRESH_TICKS)return 0;
    r->attempted=r->unknown=1;r->binding.caller=caller;r->binding.before=*caller;r->binding.virtual_before=last->raw.cpu.ticks;
    ppli_sha(p,sizeof(*p),r->binding.provider_seal);ppli_sha(&r->binding,sizeof(r->binding),r->binding_digest);
    struct pcmt_live live={.r=r,.caller=caller};pgcd_copy(live.binding_seal,r->binding_digest,32);
    unsigned error=1;if(pcmt_regs(&live,0)){error=2;if(pcmt_regs(&live,1)&&pcmt_source(&live))error=0;}
    /* Known actual stack bytes only after refusal; no source/hardware follow. */
    if(!r->copied&&pwmc_zero(&r->caller_after,sizeof(r->caller_after))){pgcd_copy(&r->caller_after,caller,sizeof(*caller));r->copied=1;}
    if(error)return pcmt_fail(r,error);
    if(!pgcd_equal(&r->caller_after,&r->binding.before,sizeof(*caller)))return pcmt_fail(r,3);
    r->unknown=0;r->complete=1;ppli_sha(r,offsetof(struct pcmt_result,digest),r->digest);return 1;
}
static inline int pcmi_timer_retained(const struct pcmi_live*l)
{
    const struct pcmt_result*r=l->timer;uint8_t hash[32];ppli_sha(r,sizeof(*r),hash);
    return pgcd_equal(hash,l->timer_seal,32)&&r->complete==1&&!r->unknown&&!r->error;
}
static inline int pcmi_timer_attach(struct pcmi_live*l,const struct pcmt_result*r)
{
    if(!r||l->timer||!pwmc_zero(l->timer_seal,32)||!pcmi_source(l)||
       !pcmg_output_storage(r,sizeof(*r),l->parent)||
       pwmc_parent_overlap((uintptr_t)r,sizeof(*r),(uintptr_t)l,sizeof(*l))||
       pwmc_parent_overlap((uintptr_t)r,sizeof(*r),(uintptr_t)l->r,sizeof(*l->r))||
       pwmc_parent_overlap((uintptr_t)r,sizeof(*r),(uintptr_t)l->graph,sizeof(*l->graph))||
       r->binding.caller!=l||!pgcd_equal(&r->binding.before,l,sizeof(*l))||
       r->attempted!=1||r->complete!=1||r->unknown||r->error||r->reserved||r->copied!=1||
       r->issued!=3||r->returned!=3||r->native_issued!=15||r->native_returned!=15||
       r->counter_issued!=3||r->counter_returned!=3||
       !pwmc_zero(r->native,sizeof(r->native))||r->leaf_status[0]!=1||r->leaf_status[1]!=1||
       !pgcd_equal(&r->caller_after,l,sizeof(*l)))return 0;
    uint8_t hash[32];ppli_sha(r,offsetof(struct pcmt_result,digest),hash);if(!pgcd_equal(hash,r->digest,32))return 0;
    l->timer=r;ppli_sha(r,sizeof(*r),l->timer_seal);return pcmi_timer_retained(l);
}
static inline const struct pcmt_result*pcmt_route_capture(const struct pcmp_route*routes,unsigned count,
    struct pcmt_result frames[PCMP_PARENT_CONTEXTS][2],const struct pcmi_result providers[PCMP_PARENT_CONTEXTS][2],
    const struct pcmg_result graphs[PCMP_PARENT_CONTEXTS][2],struct pcmi_live*caller)
{
    if(!frames||!providers||!graphs||!caller)return 0;unsigned index=0,slot=0;
    if(!pcmg_active_route(routes,count,caller->parent,&index,&slot)||!pcmi_source(caller)||
       caller->r!=&providers[index][slot]||caller->graph!=&graphs[index][slot]||
       !pcmp_in_self(caller->frame.input.image,frames,PCMP_PARENT_CONTEXTS*sizeof(*frames)))return 0;
    struct pcmt_result*out=&frames[index][slot];
    const struct {const void*address;uint64_t bytes;} arrays[]={
        {routes,count*sizeof(*routes)},{providers,PCMP_PARENT_CONTEXTS*sizeof(*providers)},
        {graphs,PCMP_PARENT_CONTEXTS*sizeof(*graphs)}};
    for(unsigned k=0;k<sizeof(arrays)/sizeof(arrays[0]);k++)if(pwmc_parent_overlap((uintptr_t)out,sizeof(*out),
        (uintptr_t)arrays[k].address,arrays[k].bytes))return 0;
    for(unsigned n=0;n<count;n++){
        const struct {const void*address;uint64_t bytes;} other[]={{routes[n].context,sizeof(*routes[n].context)},
            {routes[n].source,sizeof(*routes[n].source)},{routes[n].ticket,sizeof(*routes[n].ticket)},
            {routes[n].frames,2*sizeof(*routes[n].frames)}};
        for(unsigned k=0;k<sizeof(other)/sizeof(other[0]);k++)if(pwmc_parent_overlap((uintptr_t)out,sizeof(*out),
            (uintptr_t)other[k].address,other[k].bytes))return 0;
    }
    return pcmt_capture(out,caller)?out:0;
}
/* Completed captures are DATA only. In particular caller and before.parent
 * are now expired stack addresses: compare their numbers, never follow them. */
static inline int pcmt_input_retained(const struct pcmt_result*r,const struct pcmi_result*p,
    const struct pcmg_result*graph,const struct pcmp_result*map)
{
    const struct pcmi_live*b=&r->binding.before;uint8_t hash[32];
    if(r->attempted!=1||r->complete!=1||r->unknown||r->error||r->reserved||r->copied!=1||
       r->issued!=3||r->returned!=3||r->leaf_status[0]!=1||r->leaf_status[1]!=1||
       r->counter_issued!=3||r->counter_returned!=3||
       r->native_issued!=15||r->native_returned!=15||!pwmc_zero(r->native,sizeof(r->native))||
       !r->binding.caller||!pgcd_equal(&r->caller_after,b,sizeof(*b))||b->timer||!pwmc_zero(b->timer_seal,32)||
       b->r!=p||b->parent!=(const void*)(uintptr_t)p->binding.parent_address||b->graph!=graph||
       !pgcd_equal(&b->frame,&p->binding.parent,sizeof(b->frame))||!b->page||
       b->core!=graph->graph.core||b->opening!=p->binding.opening||b->minimum!=p->binding.minimum||
       !pgcd_equal(b->binding_seal,p->binding_digest,32)||b->rooted!=1||b->table_mask!=7||b->handlers!=1||
       p->arch_returned<3||r->binding.virtual_before!=p->clock[p->arch_returned-3].raw.cpu.ticks)return 0;
    const struct pbgi_clock*virtual=&p->clock[p->arch_returned-3];
    if(virtual->issued!=1||virtual->returned!=1||virtual->native_issued!=3||virtual->native_returned!=3||
       virtual->native[0]||virtual->native[1]||!r->binding.virtual_before||
       r->binding.virtual_before<b->opening||r->binding.virtual_before-b->opening>PGCD_FRESH_TICKS)return 0;
    ppli_sha(&r->binding,sizeof(r->binding),hash);if(!pgcd_equal(hash,r->binding_digest,32))return 0;
    ppli_sha(r,offsetof(struct pcmt_result,digest),hash);if(!pgcd_equal(hash,r->digest,32))return 0;
    uint64_t first_steps=0;
    for(unsigned n=0;n<2;n++){
        const struct pcmt_sample*s=&r->sample[n];uint64_t end,steps,notify;
        if(s->attempted!=1||s->complete!=1||s->reserved||s->head_count!=27||(s->pending&~UINT64_C(31))||
           !pwmc_irq_work_math(&p->path,&r->regs[0],&r->regs[n],r->binding.virtual_before,
            map->call.after.cpu.frequency,s->counter,r->regs[0].ticks,&end,&steps,&notify)||
           r->counter_after[n]<s->counter||!pwmc_irq_work_math(&p->path,&r->regs[0],&r->regs[n],r->binding.virtual_before,
            map->call.after.cpu.frequency,r->counter_after[n],r->regs[0].ticks,&end,&steps,&notify))return 0;
        for(unsigned k=0;k<27;k++){uint64_t at=b->core+0x1c928+16*(k+5);
            if(s->head[k][0]!=at||s->head[k][1]!=at)return 0;}
        if(!n)first_steps=steps;
    }
    uint64_t period=pwfi_le(p->path.image[0].state+56,8),missed=pwfi_le(p->path.image[0].state,8);
    return r->sample[1].pending==r->sample[0].pending&&r->sample[1].counter>=r->sample[0].counter&&
        r->sample[1].counter>=r->counter_after[0]&&r->counter_after[1]>=r->counter_after[0]&&
        r->counter_after[0]-r->sample[0].counter<=period*(missed+first_steps+2)&&
        r->counter_after[1]-r->sample[0].counter<=period*(missed+first_steps+2);
}
static inline int pcmt_route_minimum(const struct pcmp_route*routes,unsigned count,
    const struct pcmg_result graphs[PCMP_PARENT_CONTEXTS][2],const struct pcmi_result providers[PCMP_PARENT_CONTEXTS][2],
    const struct pcmt_result timers[PCMP_PARENT_CONTEXTS][2],const struct pgcd_context*c,unsigned slot,uint64_t*out)
{
    if(!timers||!pcmi_route_minimum(routes,count,graphs,providers,c,slot,out))return 0;
    unsigned index=0;for(;index<count;index++)if(routes[index].context==c)break;if(index==count)return 0;
    const struct pcmi_result*p=&providers[index][slot];const struct pcmt_result*r=&timers[index][slot];
    return pcmt_input_retained(r,p,&graphs[index][slot],&routes[index].frames[slot]);
}
#endif
