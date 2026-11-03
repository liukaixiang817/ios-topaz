/* Fresh event/checker/nonperiodic-timer DATA after the later provider and
 * physical inputs, while the original pcmp caller is still ACTIVE. Reuses
 * the bounded DATA walks; no NotifyFn, timer method, IRQ or owner lease. */
#ifndef POLARIS_UEFI_WIFI_CURRENT_EVENTS_H
#define POLARIS_UEFI_WIFI_CURRENT_EVENTS_H
#include "uefi-wifi-current-provider.h"
#if !defined(POLARIS_WIFI_CURRENT_TIMER_INPUT)
#error Current event inputs require the genuine physical-input caller
#endif
#define PCME_AT_MAX (2u*(PWMC_EVENT_MAX+PWMC_TIMER_MAX+1u))
#define PCME_CLOCK_MAX (PCME_AT_MAX+2u)
struct pcme_binding {
    uint64_t parent_address;struct pcmp_live parent;
    uint64_t live_address;
    const struct pcmg_result*graph;const struct pcmi_result*provider;const struct pcmt_result*timer;
    uint64_t opening,minimum;uint8_t frame_seal[32],graph_seal[32],provider_seal[32],timer_seal[32];
};
struct pcme_result;
struct pcme_live {
    struct pcme_result*r;struct pcmp_live*parent;struct pcme_binding input;
    int(*page)(struct ppli_at*);uint8_t binding_seal[32];unsigned event_rooted,timer_rooted;
};
struct pcme_result {
    struct pcme_binding binding;uint8_t binding_digest[32];
    struct pwmc_event_path events;struct pwmc_timer_path timers;
    struct ppli_at AT[PCME_AT_MAX];struct pbgi_clock clock[PCME_CLOCK_MAX];
    uint8_t hashes[2][4][5][32];uint32_t hash_count[2][4],hash_failed[2][4];
    uint32_t AT_status[PCME_AT_MAX],arch_status[PCME_CLOCK_MAX];
    struct pcmp_live parent_after;
    struct pcme_live control_after;
    uint32_t attempted,complete,unknown,error,AT_count,arch_issued,arch_returned,parent_copied,reserved,refusal_timer,control_copied,reserved2,AT_issued,AT_returned;
    uint8_t digest[32];
};
_Static_assert(sizeof(struct pcme_binding)==488&&sizeof(struct pcme_live)==552&&sizeof(struct pcme_result)==91488,
    "separate complete current event graph INPUT RAW v2");
_Static_assert(offsetof(struct pcme_result,events)==520&&offsetof(struct pcme_result,timers)==19064&&
    offsetof(struct pcme_result,AT)==27112&&offsetof(struct pcme_result,clock)==45144&&
    offsetof(struct pcme_result,AT_status)==87960&&offsetof(struct pcme_result,parent_after)==90544&&offsetof(struct pcme_result,digest)==91456,
    "independent current event graph INPUT decoder offsets");
static inline int pcme_fail(struct pcme_result*r,unsigned error)
{if(!r->error)r->error=error;r->unknown=1;return 0;}
static inline struct pwmc_irq_map_view pcme_map(const struct pcme_binding*b)
{const struct pbgi_result*g=&b->graph->graph;return (struct pwmc_irq_map_view){g->call.data,g->call.map.bytes,
    g->call.map.stride,(uintptr_t)b->parent.input.image->base,b->parent.input.image->bytes};}
/* Own control and all known resident records first. No firmware source RAM
 * or captured stack/relay address is followed by this closure. */
static inline int pcme_control(const struct pcme_live*l)
{
    const struct pcme_result*r=l->r;const struct pcme_binding*b=&l->input;uint8_t hash[32];
    ppli_sha(&r->binding,sizeof(r->binding),hash);
    if(!pgcd_equal(hash,l->binding_seal,32)||!pgcd_equal(r->binding_digest,l->binding_seal,32)||
       !pgcd_equal(&r->binding,b,sizeof(*b))||b->parent_address!=(uintptr_t)l->parent||b->live_address!=(uintptr_t)l||
       !pgcd_equal(l->parent,&b->parent,sizeof(b->parent))||
       r->attempted!=1||r->complete||r->unknown!=1||r->error||r->reserved||r->reserved2||r->parent_copied||r->control_copied||r->refusal_timer||
       r->AT_count>PCME_AT_MAX||r->AT_issued>PCME_AT_MAX||r->AT_returned>r->AT_issued||
       r->arch_issued>PCME_CLOCK_MAX||r->arch_returned>r->arch_issued||
       r->events.count>PWMC_EVENT_MAX||r->timers.count>PWMC_TIMER_MAX||
       !pwmc_zero(&r->parent_after,sizeof(r->parent_after))||!pwmc_zero(&r->control_after,sizeof(r->control_after))||!pwmc_zero(r->digest,32))return 0;
    const struct {const void*p;size_t bytes;const uint8_t*seal;} inputs[]={
        {b->graph,sizeof(*b->graph),b->graph_seal},{b->provider,sizeof(*b->provider),b->provider_seal},
        {b->timer,sizeof(*b->timer),b->timer_seal}};
    for(unsigned k=0;k<3;k++){ppli_sha(inputs[k].p,inputs[k].bytes,hash);if(!pgcd_equal(hash,inputs[k].seal,32))return 0;}
    pbgi_parent_frame_seal(l->parent,hash);return pgcd_equal(hash,b->frame_seal,32);
}
static inline int pcme_known(const struct pcme_live*l)
{
    const struct pcme_result*r=l->r;uint64_t core=l->input.graph->graph.core;
    if(l->event_rooted){
        const struct pwmc_event_path*e=&r->events;
        if(!pgcd_equal(e->lock,(const void*)(uintptr_t)(core+0x1c350),24)||
           !pgcd_equal(e->head,(const void*)(uintptr_t)(core+0x1c368),16)||
           !pgcd_equal(e->group,(const void*)(uintptr_t)(core+0x1b130),16)||
           pwfi_le((const void*)(uintptr_t)(core+0x1dbc0),8)!=e->pending)return 0;
        for(unsigned k=0;k<e->count;k++)if(!pgcd_equal(e->node[k].raw,(const void*)(uintptr_t)e->node[k].address,88))return 0;
    }
    if(l->timer_rooted){
        const struct pwmc_timer_path*t=&r->timers;
        if(pwfi_le((const void*)(uintptr_t)(core+0x1cbc8),8)!=t->checker||
           !pgcd_equal(t->head,(const void*)(uintptr_t)(core+0x1c3f0),16)||
           !pgcd_equal(t->lock[0],(const void*)(uintptr_t)(core+0x1c3d8),24)||
           !pgcd_equal(t->lock[1],(const void*)(uintptr_t)(core+0x1c400),24))return 0;
        if(t->checker_node.returned&&!pgcd_equal(t->checker_node.raw,(const void*)(uintptr_t)t->checker,184))return 0;
        for(unsigned k=0;k<t->count;k++)if(!pgcd_equal(t->node[k].raw,(const void*)(uintptr_t)t->node[k].address,184))return 0;
    }return 1;
}
static inline int pcme_source(const struct pcme_live*l)
{
    if(!pcme_control(l)||!pcmp_source_stable(l->parent))return 0;
    const struct pbgi_result*g=&l->input.graph->graph;struct pbgi_live view={.r=(struct pbgi_result*)g,.core=g->core};
    pbgi_root_seal(g,view.root_seal);if(!pbgi_roots_current(&view))return 0;
    for(unsigned list=0;list<2;list++)for(unsigned k=0;k<g->count[list];k++){
        const struct pbgi_node*n=&g->node[list][k];if(!pgcd_equal(n->raw,(const void*)(uintptr_t)n->address,n->bytes))return 0;
    }
    return pcmi_known_input(&l->input.provider->path,g->core,1,7,1)&&
        pcmt_queues_current(l->input.timer,g->core)&&pcme_known(l);
}
static inline void pcme_seal(const struct pcme_result*r,const void*skip,size_t bytes,uint8_t out[32])
{struct pwfi_sha256 h;pwfi_init(&h);pbgi_hash_part(&h,r,sizeof(*r),skip,bytes);pwfi_final(&h,out);}
static __attribute__((noinline)) int pcme_tick(struct pcme_live*l)
{
    struct pcme_result*r=l->r;if(!pcme_source(l))return 0;unsigned k=r->arch_issued;
    if(k==PCME_CLOCK_MAX||r->arch_returned!=k)return 0;struct pbgi_clock*c=&r->clock[k];
    if(!pwmc_zero(c,sizeof(*c)))return 0;uint64_t minimum=k?r->clock[k-1].raw.cpu.ticks:l->input.minimum;
    if(k&&(r->clock[k-1].issued!=1||r->clock[k-1].returned!=1||r->clock[k-1].native_issued!=3||
       r->clock[k-1].native_returned!=3||r->clock[k-1].native[0]||r->clock[k-1].native[1]))return 0;
    c->native_issued=1;c->native[0]=*l->input.parent.input.native_flag;c->native_returned=1;if(c->native[0])return 0;
    c->issued=1;r->arch_issued=k+1;uint8_t before[32],after[32],control[32],actual[32];
    pcme_seal(r,&c->raw,sizeof(c->raw),before);ppli_sha(l,sizeof(*l),control);
    int ok=l->input.parent.original_io.arch(l->input.parent.original_io.opaque,&c->raw);
    ppli_sha(l,sizeof(*l),actual);if(!pgcd_equal(control,actual,32))return 0;
    pcme_seal(r,&c->raw,sizeof(c->raw),after);if(!pgcd_equal(before,after,32))return 0;
    c->returned=1;r->arch_returned=k+1;r->arch_status[k]=ok?1:0;
    if(!pcme_control(l))return 0;
    const struct pgcd_arch*a=&l->parent->r->call.after;
    if(!ok||!pwfc_arch_stable(&a->cpu,&c->raw.cpu)||a->cpacr!=c->raw.cpacr||c->raw.cpu.daif||c->raw.cpu.group1!=1||
       c->raw.cpu.ticks<minimum||c->raw.cpu.ticks<l->input.opening||
       c->raw.cpu.ticks-l->input.opening>PGCD_FRESH_TICKS||!pcme_source(l))return 0;
    c->native_issued=3;c->native[1]=*l->input.parent.input.native_flag;c->native_returned=3;return !c->native[1];
}
static __attribute__((noinline)) int pcme_page(struct pcme_live*l,struct ppli_at*a,uint64_t page)
{
    struct pcme_result*r=l->r;unsigned k=r->AT_count;
    if(!pcme_source(l)||k==PCME_AT_MAX||a!=&r->AT[k]||r->AT_issued!=k||r->AT_returned!=k||!pwmc_zero(a,sizeof(*a)))return 0;
    a->page=page;a->native_issued=1;a->native[0]=*l->input.parent.input.native_flag;a->native_returned=1;if(a->native[0])return 0;
    r->AT_issued=k+1;uint8_t before[32],after[32],control[32],actual[32];pcme_seal(r,a,sizeof(*a),before);ppli_sha(l,sizeof(*l),control);
    int ok=l->page(a);ppli_sha(l,sizeof(*l),actual);if(!pgcd_equal(control,actual,32))return 0;
    pcme_seal(r,a,sizeof(*a),after);if(!pgcd_equal(before,after,32))return 0;
    r->AT_returned=k+1;r->AT_status[k]=ok?1:0;
    if(!pcme_control(l)||!ok||a->page!=page||a->issued!=1||a->returned!=1||
       a->saved!=a->restored||a->par!=(UINT64_C(0xff00000000000b80)|page)||a->native_issued!=1||a->native_returned!=1||
       !pwmc_zero(a->native,sizeof(a->native))||!pcme_source(l))return 0;
    a->native_issued=3;a->native[1]=*l->input.parent.input.native_flag;a->native_returned=3;return !a->native[1];
}
static inline int pcme_node(struct pcme_live*l,uint64_t address,size_t bytes,
    uint64_t pages[2],uint64_t raw[2],uint32_t*count)
{
    if(!pcme_source(l)||!address||(address&7)||address>UINT64_MAX-bytes||*count)return 0;
    const struct pbgi_result*g=&l->input.graph->graph;struct pbgi_live view={.r=(struct pbgi_result*)g};
    const struct efi_loaded*i=l->input.parent.input.image;
    if(pwmc_parent_overlap(address,bytes,(uintptr_t)i->base,i->bytes)||
       pwmc_parent_overlap(address,bytes,g->core,PGCI_IMAGE_BYTES)||!pbgi_RAM(&view,address,bytes))return 0;
    for(uint64_t page=address&~UINT64_C(4095);page<address+bytes;page+=4096){
        struct pcme_result*r=l->r;unsigned k=r->AT_count,n=*count;if(k==PCME_AT_MAX||n==2)return 0;pages[n]=page;
        if(!pcme_page(l,&r->AT[k],page)||r->AT_count!=k||*count!=n||pages[n]!=page||raw[n])return 0;
        raw[n]=r->AT[k].par;r->AT_count=k+1;*count=n+1;if(!pcme_tick(l))return 0;
    }return 1;
}
static inline int pcme_event_node(void*opaque,struct pwmc_event_node*n,uint64_t address)
{
    struct pcme_live*l=opaque;n->address=address;n->issued=1;
    if(!pcme_node(l,address,88,n->AT_page,n->AT_raw,&n->AT_count)||n->address!=address||n->issued!=1||n->returned||n->reserved||
       !pwmc_zero(n->raw,sizeof(n->raw)))return 0;
    pgcd_copy(n->raw,(const void*)(uintptr_t)address,88);n->returned=1;return 1;
}
static inline int pcme_timer_node(void*opaque,struct pwmc_timer_node*n,uint64_t address)
{
    struct pcme_live*l=opaque;n->address=address;n->issued=1;
    if(!pcme_node(l,address,184,n->AT_page,n->AT_raw,&n->AT_count)||n->address!=address||n->issued!=1||n->returned||n->reserved||
       !pwmc_zero(n->raw,sizeof(n->raw)))return 0;
    pgcd_copy(n->raw,(const void*)(uintptr_t)address,184);n->returned=1;return 1;
}
static __attribute__((noinline)) int pcme_hash_sources(struct pcme_live*l,unsigned phase)
{
    struct pcme_result*r=l->r;uint64_t core=l->input.graph->graph.core;
    if(phase>1||!pcme_source(l)||!pgci_verify((const void*)(uintptr_t)core,core,PGCI_IMAGE_BYTES,
       r->hashes[phase][0],&r->hash_failed[phase][0],&r->hash_count[phase][0]))return 0;
    for(unsigned k=0;k<3;k++)if(!pwmc_irq_image_hash_data(&l->input.provider->path.image[k],k,
        r->hashes[phase][k+1],&r->hash_count[phase][k+1],&r->hash_failed[phase][k+1]))return 0;
    return pcme_source(l);
}
static inline int pcme_inputs(const struct pcmp_live*parent,const struct pcmg_result*g,
    const struct pcmi_result*p,const struct pcmt_result*t,uint64_t*minimum)
{
    uint8_t hash[32];
    if(!pcmp_source_stable(parent)||g->attempted!=1||g->complete!=1||g->unknown||g->error||
       g->reserved||g->parent_copied!=1||!pcmi_graph_tail(g)||
       g->binding.parent_address!=(uintptr_t)parent||g->binding.opening!=parent->r->source_before.before.cpu.ticks||
       g->binding.minimum!=parent->r->final_arch.cpu.ticks||g->graph.complete!=1||g->graph.unknown||g->graph.error||
       g->graph.core_pages!=PBGI_CORE_PAGES||g->graph.count[0]>PBGI_NODES||g->graph.count[1]>PBGI_NODES||
       !g->graph.arch_returned||g->graph.arch_returned>PBGI_CLOCKS||g->graph.arch_issued!=g->graph.arch_returned||
       !pgcd_equal(&g->binding.parent,parent,sizeof(*parent))||!pgcd_equal(&g->parent_after,parent,sizeof(*parent))||
       p->attempted!=1||p->complete!=1||p->unknown||p->error||p->reserved||p->parent_copied!=1||
       p->path.complete!=1||p->path.finalized||p->AT_count>PCMI_AT_MAX||
       p->binding.parent_address!=(uintptr_t)parent||p->binding.graph!=g||p->binding.opening!=g->binding.opening||
       !pgcd_equal(&p->binding.parent,parent,sizeof(*parent))||!pgcd_equal(&p->parent_after,parent,sizeof(*parent))||
       !pgcd_equal(p->binding.graph_seal,g->digest,32)||
       p->binding.minimum!=g->graph.clock[g->graph.arch_returned-1].raw.cpu.ticks||
       p->hash_count[0]!=5||p->hash_count[1]!=5||p->hash_failed[0]||p->hash_failed[1]||
       !pwmc_zero((const uint8_t*)p+offsetof(struct pcmi_result,digest)+32,sizeof(*p)-offsetof(struct pcmi_result,digest)-32)||
       !p->arch_returned||p->arch_returned>PCMI_CLOCK_MAX||p->arch_issued!=p->arch_returned)return 0;
    ppli_sha(g,offsetof(struct pcmg_result,digest),hash);if(!pgcd_equal(hash,g->digest,32))return 0;
    ppli_sha(p,offsetof(struct pcmi_result,digest),hash);if(!pgcd_equal(hash,p->digest,32))return 0;
    pbgi_parent_frame_seal(parent,hash);
    if(!pgcd_equal(hash,p->binding.frame_seal,32)||!pgcd_equal(hash,g->binding.frame_seal,32))return 0;
    struct pwmc_irq_map_view map={g->graph.call.data,g->graph.call.map.bytes,g->graph.call.map.stride,
        (uintptr_t)parent->input.image->base,parent->input.image->bytes};
    if(!pwmc_irq_bindings_map(&p->path,g->graph.core,(uintptr_t)parent->original_io.system,&map))return 0;
    if(!pcmt_input_retained(t,p,g,parent->r))return 0;
    const struct pbgi_clock*last=&p->clock[p->arch_returned-1];*minimum=last->raw.cpu.ticks;
    return last->issued==1&&last->returned==1&&last->native_issued==3&&last->native_returned==3&&
        !last->native[0]&&!last->native[1]&&*minimum&&*minimum!=UINT64_MAX&&*minimum>=p->binding.minimum&&
        *minimum>=p->binding.opening&&*minimum-p->binding.opening<=PGCD_FRESH_TICKS;
}
static __attribute__((noinline)) int pcme_capture(struct pcme_result*r,struct pcmp_live*parent,
    const struct pcmg_result*g,const struct pcmi_result*p,const struct pcmt_result*t,int(*read_page)(struct ppli_at*))
{
    if(!r||((uintptr_t)r&7)||!parent||!g||!p||!t||!read_page||!pcmg_output_storage(r,sizeof(*r),parent)||
       pwmc_parent_overlap((uintptr_t)r,sizeof(*r),(uintptr_t)g,sizeof(*g))||
       pwmc_parent_overlap((uintptr_t)r,sizeof(*r),(uintptr_t)p,sizeof(*p))||
       pwmc_parent_overlap((uintptr_t)r,sizeof(*r),(uintptr_t)t,sizeof(*t))||!pwmc_zero(r,sizeof(*r)))return 0;
    uint64_t minimum=0;if(!pcme_inputs(parent,g,p,t,&minimum))return 0;
    r->attempted=r->unknown=1;r->binding.parent_address=(uintptr_t)parent;r->binding.parent=*parent;
    r->binding.graph=g;r->binding.provider=p;r->binding.timer=t;r->binding.opening=p->binding.opening;r->binding.minimum=minimum;
    pbgi_parent_frame_seal(parent,r->binding.frame_seal);ppli_sha(g,sizeof(*g),r->binding.graph_seal);
    ppli_sha(p,sizeof(*p),r->binding.provider_seal);ppli_sha(t,sizeof(*t),r->binding.timer_seal);
    struct pcme_live live={.r=r,.parent=parent,.page=read_page};r->binding.live_address=(uintptr_t)&live;live.input=r->binding;
    ppli_sha(&r->binding,sizeof(r->binding),r->binding_digest);pgcd_copy(live.binding_seal,r->binding_digest,32);
    unsigned error=1;struct pwmc_irq_map_view map=pcme_map(&r->binding);
    if(pcme_hash_sources(&live,0)&&pcme_tick(&live)){
        live.event_rooted=1;error=2;
        if(pwmc_events_read(&r->events,g->graph.core,&live,pcme_event_node)&&pcme_source(&live)&&
           pwmc_events_current_map(&r->events,g->graph.core,&map)){
            live.timer_rooted=1;error=3;
            if(pwmc_timers_read(&r->timers,g->graph.core,&live,pcme_timer_node)&&pcme_source(&live)&&
               pwmc_timers_current_map(&r->timers,&r->events,g->graph.core,&map)&&
               pwmc_timer_signal_refusal(&r->timers,&r->refusal_timer)){
                error=4;if(pcme_tick(&live)&&pcme_hash_sources(&live,1))error=0;
            }
        }
    }
    if(!r->parent_copied&&pwmc_zero(&r->parent_after,sizeof(r->parent_after))){pgcd_copy(&r->parent_after,parent,sizeof(*parent));r->parent_copied=1;}
    if(!r->control_copied&&pwmc_zero(&r->control_after,sizeof(r->control_after))){pgcd_copy(&r->control_after,&live,sizeof(live));r->control_copied=1;}
    if(error)return pcme_fail(r,error);
    if(!pgcd_equal(&r->parent_after,&r->binding.parent,sizeof(*parent))||r->control_copied!=1)return pcme_fail(r,5);
    r->unknown=0;r->complete=1;ppli_sha(r,offsetof(struct pcme_result,digest),r->digest);return 1;
}
static inline int pcme_route_capture(const struct pcmp_route*routes,unsigned count,
    struct pcme_result frames[PCMP_PARENT_CONTEXTS][2],const struct pcmg_result graphs[PCMP_PARENT_CONTEXTS][2],
    const struct pcmi_result providers[PCMP_PARENT_CONTEXTS][2],const struct pcmt_result timers[PCMP_PARENT_CONTEXTS][2],
    struct pcmp_live*parent,int(*read_page)(struct ppli_at*))
{
    if(!frames||!graphs||!providers||!timers||!read_page)return 0;unsigned index=0,slot=0;
    if(!pcmg_active_route(routes,count,parent,&index,&slot)||!pcmp_source_stable(parent)||
       !pcmp_in_self(parent->input.image,frames,PCMP_PARENT_CONTEXTS*sizeof(*frames))||
       !pcmp_in_self(parent->input.image,graphs,PCMP_PARENT_CONTEXTS*sizeof(*graphs))||
       !pcmp_in_self(parent->input.image,providers,PCMP_PARENT_CONTEXTS*sizeof(*providers))||
       !pcmp_in_self(parent->input.image,timers,PCMP_PARENT_CONTEXTS*sizeof(*timers)))return 0;
    const struct pcme_result*out=&frames[index][slot];
    const struct {const void*p;size_t bytes;} arrays[]={{routes,count*sizeof(*routes)},
        {graphs,PCMP_PARENT_CONTEXTS*sizeof(*graphs)},{providers,PCMP_PARENT_CONTEXTS*sizeof(*providers)},
        {timers,PCMP_PARENT_CONTEXTS*sizeof(*timers)}};
    for(unsigned k=0;k<4;k++)if(pwmc_parent_overlap((uintptr_t)out,sizeof(*out),(uintptr_t)arrays[k].p,arrays[k].bytes))return 0;
    for(unsigned n=0;n<count;n++){
        const struct {const void*p;size_t bytes;} other[]={{routes[n].context,sizeof(*routes[n].context)},
            {routes[n].source,sizeof(*routes[n].source)},{routes[n].ticket,sizeof(*routes[n].ticket)},
            {routes[n].frames,2*sizeof(*routes[n].frames)}};
        for(unsigned k=0;k<4;k++)if(pwmc_parent_overlap((uintptr_t)out,sizeof(*out),(uintptr_t)other[k].p,other[k].bytes))return 0;
    }
    return pcme_capture(&frames[index][slot],parent,&graphs[index][slot],&providers[index][slot],&timers[index][slot],read_page);
}
/* Completed captured caller/relay addresses remain numeric DATA only. */
static inline int pcme_route_minimum(const struct pcmp_route*routes,unsigned count,
    const struct pcmg_result graphs[PCMP_PARENT_CONTEXTS][2],const struct pcmi_result providers[PCMP_PARENT_CONTEXTS][2],
    const struct pcmt_result timers[PCMP_PARENT_CONTEXTS][2],const struct pcme_result frames[PCMP_PARENT_CONTEXTS][2],
    const struct pgcd_context*c,unsigned slot,uint64_t*out)
{
    if(!frames||!pcmt_route_minimum(routes,count,graphs,providers,timers,c,slot,out))return 0;
    unsigned index=0;for(;index<count;index++)if(routes[index].context==c)break;if(index==count)return 0;
    const struct pcme_result*r=&frames[index][slot];const struct pcme_binding*b=&r->binding;uint8_t hash[32];
    if(r->attempted!=1||r->complete!=1||r->unknown||r->error||r->reserved||r->reserved2||r->refusal_timer||r->parent_copied!=1||r->control_copied!=1||
       r->AT_count>PCME_AT_MAX||!r->arch_returned||r->arch_returned>PCME_CLOCK_MAX||r->arch_issued!=r->arch_returned||
       r->AT_issued!=r->AT_count||r->AT_returned!=r->AT_count||
       b->parent_address!=providers[index][slot].binding.parent_address||
       !pgcd_equal(&b->parent,&providers[index][slot].binding.parent,sizeof(b->parent))||
       !pgcd_equal(&r->parent_after,&b->parent,sizeof(b->parent))||b->graph!=&graphs[index][slot]||
       b->provider!=&providers[index][slot]||b->timer!=&timers[index][slot]||
       !b->live_address||r->control_after.r!=r||r->control_after.parent!=(const void*)(uintptr_t)b->parent_address||
       !pgcd_equal(&r->control_after.input,b,sizeof(*b))||!r->control_after.page||r->control_after.event_rooted!=1||r->control_after.timer_rooted!=1||
       !pgcd_equal(r->control_after.binding_seal,r->binding_digest,32)||
       b->opening!=providers[index][slot].binding.opening||b->minimum!=*out||
       !pgcd_equal(b->frame_seal,providers[index][slot].binding.frame_seal,32))return 0;
    ppli_sha(b,sizeof(*b),hash);if(!pgcd_equal(hash,r->binding_digest,32))return 0;
    ppli_sha(r,offsetof(struct pcme_result,digest),hash);if(!pgcd_equal(hash,r->digest,32))return 0;
    for(unsigned k=0;k<PCME_AT_MAX;k++)if(r->AT_status[k]!=(k<r->AT_count?1u:0u))return 0;
    for(unsigned k=0;k<PCME_CLOCK_MAX;k++)if(r->arch_status[k]!=(k<r->arch_returned?1u:0u))return 0;
    const struct {const void*p;size_t bytes;const uint8_t*seal;} inputs[]={
        {b->graph,sizeof(*b->graph),b->graph_seal},{b->provider,sizeof(*b->provider),b->provider_seal},
        {b->timer,sizeof(*b->timer),b->timer_seal}};
    for(unsigned k=0;k<3;k++){ppli_sha(inputs[k].p,inputs[k].bytes,hash);if(!pgcd_equal(hash,inputs[k].seal,32))return 0;}
    /* Known resident route-frame DATA only at completed handoff. Do not
     * follow the captured LoadedImage descriptor or expired caller stack. */
    const struct pcmp_result*parent=&routes[index].frames[slot];const struct pbgi_result*graph=&graphs[index][slot].graph;
    struct pwmc_irq_map_view map={graph->call.data,graph->call.map.bytes,graph->call.map.stride,
        parent->source_before.self_base,parent->source_before.self_bytes};unsigned bad=0;
    if(!pwmc_timers_replay_map(&r->timers,&r->events,graphs[index][slot].graph.core,&map)||
       !pwmc_timer_signal_refusal(&r->timers,&bad))return 0;
    for(unsigned phase=0;phase<2;phase++)for(unsigned image=0;image<4;image++){
        unsigned n=image?pwmc_irq_bindings[image-1].range_count:PGCI_RANGE_COUNT;
        if(r->hash_count[phase][image]!=n||r->hash_failed[phase][image])return 0;
        for(unsigned k=0;k<n;k++)if(!pgcd_equal(r->hashes[phase][image][k],image?
            pwmc_irq_bindings[image-1].ranges[k].sha256:pgci_ranges[k].sha256,32))return 0;
        if(!pwmc_zero(r->hashes[phase][image]+n,(5-n)*32))return 0;
    }
    const struct pbgi_clock*last=&r->clock[r->arch_returned-1];uint64_t ticks=last->raw.cpu.ticks;
    if(last->issued!=1||last->returned!=1||last->native_issued!=3||last->native_returned!=3||
       last->native[0]||last->native[1]||!ticks||ticks==UINT64_MAX||ticks<*out||ticks<b->opening||
       ticks-b->opening>PGCD_FRESH_TICKS)return 0;
    *out=ticks;return 1;
}
#endif
