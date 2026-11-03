/* Original Timer/GIC/CPU DATA inputs in the real incoming-contract release
 * interval. Reuse the existing immutable/binding readers, without fabricating
 * an opened allocator/GCD context. No provider method is executed. */
#ifndef POLARIS_UEFI_WIFI_CACHE_PROVIDER_H
#define POLARIS_UEFI_WIFI_CACHE_PROVIDER_H
#include "uefi-wifi-cache-timer-graph.h"
#define PBHI_AT_MAX (PWMC_IRQ_IMAGES*PWMC_IRQ_PAGES+5u)
#define PBHI_CLOCK_MAX 40u
#define PBHI_DEFERRED_BYTES 1488u
#define PBHI_TIMER_BYTES 312u
struct pbhi_input {
    struct pbhr_live*caller;struct pbhr_result*witness;const struct pbhr_input*original;
    uint8_t service_seal[32];const void*deferred;const void*timer;
};
struct pbhi_result {
    struct pbhi_input input;struct pbhr_live live_before;
    uint64_t opening,virtual_before,core;struct pwmc_irq_path path;
    struct ppli_at AT[PBHI_AT_MAX];struct pbgi_clock clock[PBHI_CLOCK_MAX];
    uint8_t Core_hash[3][5][32];uint32_t hash_count[3],hash_failed[3];
    uint32_t attempted,captured,closed,complete,unknown,error,AT_count,arch_issued,arch_returned,reserved;
    uint8_t digest[32];
};
_Static_assert(sizeof(struct pbhi_input)==72&&sizeof(struct pbhi_result)==20344,"separate full provider-input ABI");
_Static_assert(offsetof(struct pbhi_result,path)==456&&offsetof(struct pbhi_result,AT)==12856&&offsetof(struct pbhi_result,clock)==14648&&offsetof(struct pbhi_result,digest)==20312,"provider-input decoder offsets");
struct pbhi_live {
    struct pbhi_result*r;struct pbhi_input in;struct pbhr_live frame;struct pbht_result*graph;
    uint64_t core,boot,opening,before;unsigned rooted,table_mask,handlers,event_rooted,timer_rooted;
};
static inline int pbhi_fail(struct pbhi_result*r,unsigned error)
{if(!r->error)r->error=error;r->unknown=1;return 0;}
static inline struct pwmc_irq_map_view pbhi_map(const struct pbhi_result*r)
{
    const struct pbgi_result*s=r->live_before.in.seed;const struct efi_loaded*i=&r->input.witness->image[0];
    return (struct pwmc_irq_map_view){s->call.data,s->call.map.bytes,s->call.map.stride,(uintptr_t)i->base,i->bytes};
}
static inline void pbhi_seal(const struct pbhi_live*l,const void*skip,size_t bytes,uint8_t out[32])
{struct pwfi_sha256 h;pwfi_init(&h);pbgi_hash_part(&h,l->r,sizeof(*l->r),skip,bytes);
 pbgi_hash_part(&h,l->in.deferred,PBHI_DEFERRED_BYTES,0,0);pbgi_hash_part(&h,l->in.timer,PBHI_TIMER_BYTES,skip,bytes);
 if(l->graph)pbgi_hash_part(&h,l->graph,sizeof(*l->graph),skip,bytes);pwfi_final(&h,out);}
/* Compare only already-translated, source-bound retained addresses. This is
 * used BEFORE FreePool; post-return code never follows these provider pages. */
static inline int pbhi_known(const struct pbhi_live*l)
{
    const struct pwmc_irq_path*p=&l->r->path;
    if(l->rooted&&(pwfi_le((const void*)(uintptr_t)(l->core+0x1cb80),8)!=p->tables[0]||
       pwfi_le((const void*)(uintptr_t)(l->core+0x1c8f8),8)!=p->tables[2]))return 0;
    for(unsigned k=0;k<3;k++)if(p->image[k].complete){
        const struct pwmc_irq_image*i=&p->image[k];const struct pwmc_irq_binding*b=&pwmc_irq_bindings[k];
        if(!pgcd_equal(i->state,(const void*)(uintptr_t)(i->base+b->state),b->state_bytes))return 0;
        if((l->table_mask&(1u<<k))&&!pgcd_equal(i->table,(const void*)(uintptr_t)p->tables[k],b->table_bytes))return 0;
    }
    return !l->handlers||pgcd_equal(p->handler,(const void*)(uintptr_t)p->handlers,p->handler_count*8);
}
static inline int pbhi_graph_known(const struct pbhi_live*l)
{
    const struct pbht_result*g=l->graph;if(!g)return 1;
    if(l->event_rooted){
        const struct pwmc_event_path*e=&g->events;
        if(!pgcd_equal(e->lock,(const void*)(uintptr_t)(l->core+0x1c350),24)||
           !pgcd_equal(e->head,(const void*)(uintptr_t)(l->core+0x1c368),16)||
           !pgcd_equal(e->group,(const void*)(uintptr_t)(l->core+0x1b130),16)||
           pwfi_le((const void*)(uintptr_t)(l->core+0x1dbc0),8)!=e->pending)return 0;
        for(unsigned k=0;k<e->count;k++)if(!pgcd_equal(e->node[k].raw,(const void*)(uintptr_t)e->node[k].address,88))return 0;
    }
    if(l->timer_rooted){
        const struct pwmc_timer_path*t=&g->timers;
        if(pwfi_le((const void*)(uintptr_t)(l->core+0x1cbc8),8)!=t->checker||
           !pgcd_equal(t->head,(const void*)(uintptr_t)(l->core+0x1c3f0),16)||
           !pgcd_equal(t->lock[0],(const void*)(uintptr_t)(l->core+0x1c3d8),24)||
           !pgcd_equal(t->lock[1],(const void*)(uintptr_t)(l->core+0x1c400),24))return 0;
        if(t->checker_node.returned&&!pgcd_equal(t->checker_node.raw,(const void*)(uintptr_t)t->checker,184))return 0;
        for(unsigned k=0;k<t->count;k++)if(!pgcd_equal(t->node[k].raw,(const void*)(uintptr_t)t->node[k].address,184))return 0;
    }return 1;
}
static inline int pbhi_source(const struct pbhi_live*l,unsigned post)
{
    const struct pbhi_result*r=l->r;uint8_t hash[32];
    if(!pgcd_equal(&r->input,&l->in,sizeof(l->in))||!pgcd_equal(&r->live_before,&l->frame,sizeof(l->frame))||
       !pgcd_equal(l->in.caller,&l->frame,sizeof(l->frame))||r->core!=l->core||r->opening!=l->opening||r->virtual_before!=l->before||
       r->AT_count>PBHI_AT_MAX||r->arch_issued>PBHI_CLOCK_MAX||r->arch_returned>r->arch_issued)return 0;
    const struct pbht_result*g=l->graph;
    if(g&&(!pgcd_equal(&g->live_before,&l->frame,sizeof(l->frame))||g->input.caller!=l->in.caller||
       g->input.witness!=l->in.witness||g->input.original!=l->in.original||g->input.provider!=r||
       g->input.deferred!=l->in.deferred||g->input.timer!=l->in.timer||!pgcd_equal(g->input.service_seal,l->in.service_seal,32)||
       g->opening!=l->opening||g->virtual_before!=l->before||g->AT_count>PBHT_AT_MAX||
       g->arch_issued>PBHT_CLOCK_MAX||g->arch_returned>g->arch_issued||g->events.count>PWMC_EVENT_MAX||g->timers.count>PWMC_TIMER_MAX))return 0;
    const struct pbhr_result*w=l->in.witness;
    pbhr_seal(w,&w->api,sizeof(w->api),hash);if(!pgcd_equal(hash,l->in.service_seal,32))return 0;
    if(l->in.caller->r!=w||l->in.caller->caller!=l->in.original||
       (uintptr_t)l->frame.in.system->boot!=l->boot||!pgcd_equal(l->frame.in.system->boot,w->BS[0],PWMC_BS_BYTES)||
       !pgcd_equal(l->frame.in.image,&w->image[0],sizeof(w->image[0])))return 0;
    if(post)return w->api.issued==1&&w->api.returned==1&&!w->api.status;
    return !w->api.issued&&!w->api.returned&&w->api.status==UINT64_MAX&&pbhr_stable(l->in.caller)&&pbhi_known(l)&&pbhi_graph_known(l);
}
/* The same actual virtual-arch leaf, with separate bounded output slots.
 * Counts route storage only; they never represent ownership or a new window. */
static __attribute__((noinline)) int pbhi_clock_sample(struct pbhi_live*l,struct pbgi_clock*array,
    uint32_t*issued,uint32_t*returned,unsigned capacity,unsigned post)
{
    struct pbhi_result*r=l->r;if(!pbhi_source(l,post))return 0;unsigned k=*issued;
    if(k>=capacity||*returned!=k)return 0;struct pbgi_clock*c=&array[k];if(!pwmc_zero(c,sizeof(*c)))return 0;
    uint64_t previous=l->before;
    if(r->arch_returned&&r->clock[r->arch_returned-1].raw.cpu.ticks>previous)previous=r->clock[r->arch_returned-1].raw.cpu.ticks;
    if(l->graph&&l->graph->arch_returned&&l->graph->clock[l->graph->arch_returned-1].raw.cpu.ticks>previous)previous=l->graph->clock[l->graph->arch_returned-1].raw.cpu.ticks;
    c->native_issued=1;c->native[0]=*l->frame.in.native;c->native_returned=1;if(c->native[0])return 0;
    *issued=k+1;c->issued=1;uint8_t before[32],after[32];pbhi_seal(l,&c->raw,sizeof(c->raw),before);
    int ok=l->frame.in.io.arch(l->frame.in.io.opaque,&c->raw);if(!ok)return 0;pbhi_seal(l,&c->raw,sizeof(c->raw),after);
    if(!pgcd_equal(before,after,32)||!pbhi_source(l,post)||*issued!=k+1||*returned!=k)return 0;
    c->returned=1;*returned=k+1;const struct pgcd_arch*a=&l->in.witness->arch[0];
    if(!pwfc_arch_stable(&a->cpu,&c->raw.cpu)||a->cpacr!=c->raw.cpacr||c->raw.cpu.daif||c->raw.cpu.group1!=1||
       c->raw.cpu.ticks<previous||c->raw.cpu.ticks<l->opening||c->raw.cpu.ticks-l->opening>PGCD_FRESH_TICKS)return 0;
    c->native_issued=3;c->native[1]=*l->frame.in.native;c->native_returned=3;return !c->native[1];
}
static inline int pbhi_tick(struct pbhi_live*l,unsigned post)
{return pbhi_clock_sample(l,l->r->clock,&l->r->arch_issued,&l->r->arch_returned,PBHI_CLOCK_MAX,post);}
static inline int pbhi_graph_tick(struct pbhi_live*l)
{return pbhi_clock_sample(l,l->graph->clock,&l->graph->arch_issued,&l->graph->arch_returned,PBHT_CLOCK_MAX,0);}
/* Factored existing full AT/PAR/native leaf. The owning record was qualified
 * before entry and every other provider/graph/control byte remains sealed. */
static inline int pbhi_page_sample(struct pbhi_live*l,struct ppli_at*a,uint64_t page)
{
    if(!pbhi_source(l,0)||!pwmc_zero(a,sizeof(*a)))return 0;
    a->page=page;a->native_issued=1;a->native[0]=*l->frame.in.native;a->native_returned=1;if(a->native[0])return 0;
    uint8_t before[32],after[32];pbhi_seal(l,a,sizeof(*a),before);
    int ok=l->frame.in.page(a);if(!ok)return 0;pbhi_seal(l,a,sizeof(*a),after);
    if(!pgcd_equal(before,after,32)||!pbhi_source(l,0)||a->page!=page||a->issued!=1||a->returned!=1||a->saved!=a->restored||
       a->par!=(UINT64_C(0xff00000000000b80)|page)||a->native_issued!=1||a->native_returned!=1||!pwmc_zero(a->native,sizeof(a->native)))return 0;
    a->native_issued=3;a->native[1]=*l->frame.in.native;a->native_returned=3;return !a->native[1];
}
static inline int pbhi_range(const struct pbhi_live*l,uint64_t address,uint64_t bytes)
{
    const struct efi_loaded*i=&l->in.witness->image[0];struct pbgi_live graph={.r=(struct pbgi_result*)l->frame.in.seed};
    return !pwmc_parent_overlap(address,bytes,(uintptr_t)i->base,i->bytes)&&
        !pwmc_parent_overlap(address,bytes,l->core,PGCI_IMAGE_BYTES)&&pbgi_RAM(&graph,address,bytes);
}
static __attribute__((noinline)) int pbhi_pages(struct pbhi_live*l,uint64_t address,uint64_t bytes,
    struct pwmc_irq_AT*out,unsigned capacity,uint32_t*count)
{
    struct pbhi_result*r=l->r;if(!pbhi_source(l,0)||!pbhi_range(l,address,bytes)||*count)return 0;
    for(uint64_t page=address&~UINT64_C(4095);page<address+bytes;page+=4096){
        unsigned k=r->AT_count,n=*count;if(k==PBHI_AT_MAX||n==capacity)return 0;
        struct ppli_at*a=&r->AT[k];struct pwmc_irq_AT*q=&out[n];if(!pwmc_zero(a,sizeof(*a))||!pwmc_zero(q,sizeof(*q)))return 0;
        q->page=page;q->issued=1;
        if(!pbhi_page_sample(l,a,page)||r->AT_count!=k||*count!=n||q->page!=page||q->issued!=1||q->returned||q->raw)return 0;
        q->raw=a->par;q->returned=1;r->AT_count=k+1;*count=n+1;
        if(!pbhi_tick(l,0))return 0;
    }return 1;
}
static inline int pbhi_input_range(const void*opaque,uint64_t at,uint64_t bytes)
{return pbhi_range(opaque,at,bytes);}
static inline int pbhi_input_pages(void*opaque,uint64_t at,uint64_t bytes,struct pwmc_irq_AT*out,unsigned cap,uint32_t*count)
{return pbhi_pages(opaque,at,bytes,out,cap,count);}
static inline int pbhi_input_source(const void*opaque)
{return pbhi_source(opaque,0);}
static inline int pbhi_input_image(void*opaque,unsigned image,uint64_t base)
{
    struct pbhi_live*l=opaque;const struct pwmc_irq_input_reader reader={l,pbhi_input_range,pbhi_input_pages,pbhi_input_source,0,0,0};
    if(!pwmc_irq_image_input(&l->r->path,image,base,&reader))return 0;l->table_mask|=1u<<image;return 1;
}
static inline void pbhi_input_rooted(void*opaque){((struct pbhi_live*)opaque)->rooted=1;}
static inline void pbhi_input_handlers(void*opaque){((struct pbhi_live*)opaque)->handlers=1;}
static inline int pbhi_graph_node(struct pbhi_live*l,uint64_t address,size_t bytes,
    uint64_t pages[2],uint64_t raw[2],uint32_t*count)
{
    struct pbht_result*g=l->graph;const struct efi_loaded*i=&l->in.witness->image[0];struct pbgi_live view={.r=(struct pbgi_result*)l->frame.in.seed};
    if(!address||(address&7)||address>UINT64_MAX-bytes||*count||
       pwmc_parent_overlap(address,bytes,(uintptr_t)i->base,i->bytes)||!pbhi_source(l,0)||!pbgi_RAM(&view,address,bytes))return 0;
    for(uint64_t page=address&~UINT64_C(4095);page<address+bytes;page+=4096){
        unsigned k=g->AT_count,n=*count;if(k>=PBHT_AT_MAX||n==2)return 0;pages[n]=page;
        if(!pbhi_page_sample(l,&g->AT[k],page)||g->AT_count!=k||*count!=n||pages[n]!=page||raw[n])return 0;
        raw[n]=g->AT[k].par;g->AT_count=k+1;*count=n+1;if(!pbhi_graph_tick(l))return 0;
    }return 1;
}
static inline int pbhi_graph_event(void*opaque,struct pwmc_event_node*n,uint64_t address)
{
    struct pbhi_live*l=opaque;n->address=address;n->issued=1;
    if(!pbhi_graph_node(l,address,88,n->AT_page,n->AT_raw,&n->AT_count)||n->address!=address||n->issued!=1||n->returned||n->reserved||!pwmc_zero(n->raw,sizeof(n->raw)))return 0;
    pgcd_copy(n->raw,(const void*)(uintptr_t)address,88);n->returned=1;return 1;
}
static inline int pbhi_graph_timer(void*opaque,struct pwmc_timer_node*n,uint64_t address)
{
    struct pbhi_live*l=opaque;n->address=address;n->issued=1;
    if(!pbhi_graph_node(l,address,184,n->AT_page,n->AT_raw,&n->AT_count)||n->address!=address||n->issued!=1||n->returned||n->reserved||!pwmc_zero(n->raw,sizeof(n->raw)))return 0;
    pgcd_copy(n->raw,(const void*)(uintptr_t)address,184);n->returned=1;return 1;
}
static inline int pbhi_graph_capture(struct pbhi_live*l)
{
    struct pbht_result*g=l->graph;struct pwmc_irq_map_view map=pbhi_map(l->r);
    if(!pbhi_graph_tick(l))return 0;
    l->event_rooted=1;
    if(!pwmc_events_read(&g->events,l->core,l,pbhi_graph_event)||!pbhi_source(l,0)||
       !pwmc_events_current_map(&g->events,l->core,&map))return 0;
    l->timer_rooted=1;
    if(!pwmc_timers_read(&g->timers,l->core,l,pbhi_graph_timer)||!pbhi_source(l,0)||
       !pwmc_timers_current_map(&g->timers,&g->events,l->core,&map)||
       !pwmc_timer_signal_refusal(&g->timers,&g->refusal_timer)||!pbhi_graph_tick(l))return 0;
    g->complete=1;g->unknown=0;pbht_digest(g,g->digest);return 1;
}
static inline int pbhi_graph_retained(const struct pbht_result*g,const struct pbhi_result*p)
{
    uint8_t digest[32];pbht_digest(g,digest);
    return g->input.provider==p&&g->input.caller==p->input.caller&&g->input.witness==p->input.witness&&g->input.original==p->input.original&&
        g->input.deferred==p->input.deferred&&g->input.timer==p->input.timer&&pgcd_equal(g->input.service_seal,p->input.service_seal,32)&&
        pgcd_equal(&g->live_before,&p->live_before,sizeof(g->live_before))&&g->opening==p->opening&&g->virtual_before==p->virtual_before&&
        g->attempted==1&&g->complete==1&&!g->unknown&&!g->error&&!g->refusal_timer&&g->AT_count<=PBHT_AT_MAX&&
        g->arch_returned&&g->arch_returned<=PBHT_CLOCK_MAX&&g->arch_returned==g->arch_issued&&pgcd_equal(digest,g->digest,32);
}
static inline int pbhi_retained(const struct pbhi_result*r,struct pbhr_live*caller,struct pbhr_result*witness,
    const struct pbhr_input*original,const uint8_t seal[32],const void*deferred,const void*timer)
{
    uint8_t hash[32];ppli_sha(r,offsetof(struct pbhi_result,digest),hash);
    return r->input.caller==caller&&r->input.witness==witness&&r->input.original==original&&
        pgcd_equal(r->input.service_seal,seal,32)&&r->input.deferred==deferred&&r->input.timer==timer&&pgcd_equal(hash,r->digest,32)&&
        r->attempted==1&&r->captured==1&&!r->closed&&!r->complete&&r->unknown==1&&!r->error&&
        r->path.complete==1&&!r->path.finalized&&r->hash_count[0]==5&&r->hash_count[1]==5&&!r->hash_count[2]&&
        pwmc_zero(r->hash_failed,sizeof(r->hash_failed));
}
static inline int pbhi_storage(const struct efi_loaded*i,const struct pbhr_live*l,
    const struct pbhr_result*w,const struct pbhr_input*original,const void*out,size_t bytes)
{
    uint64_t a=(uintptr_t)out;
    return !(a&7)&&pwmc_parent_in_image(i,a,bytes)&&
        !pwmc_parent_overlap(a,bytes,(uintptr_t)l,sizeof(*l))&&
        !pwmc_parent_overlap(a,bytes,(uintptr_t)w,sizeof(*w))&&
        !pwmc_parent_overlap(a,bytes,(uintptr_t)original,sizeof(*original))&&
        !pwmc_parent_overlap(a,bytes,(uintptr_t)l->in.allocation,sizeof(*l->in.allocation))&&
        !pwmc_parent_overlap(a,bytes,(uintptr_t)l->in.seed,sizeof(*l->in.seed))&&
        !pwmc_parent_overlap(a,bytes,(uintptr_t)l->in.images,sizeof(*l->in.images))&&
        !pwmc_parent_overlap(a,bytes,(uintptr_t)l->in.native,4)&&
        !pwmc_parent_overlap(a,bytes,(uintptr_t)l->in.system,sizeof(*l->in.system))&&
        !pwmc_parent_overlap(a,bytes,(uintptr_t)l->in.image,sizeof(*l->in.image));
}
/* Supported release/source geometry only: never free a block on a page used
 * by the already captured asynchronous source. This is deliberately stricter
 * than byte overlap; co-page objects remain unsupported, not owner-qualified.
 * Every address is retained identity-AT DATA. No node or firmware is followed. */
static inline int pbhi_release_disjoint(const struct pbhi_live*l)
{
    const struct pbhi_result*r=l->r;const struct pbht_result*g=l->graph;
    const struct pbhr_result*w=l->in.witness;const struct pbha_result*a=&w->before_target;
    const struct efi_loaded*self=&w->image[0];unsigned index;
    uint64_t page=a->container&~UINT64_C(4095),base=(uintptr_t)self->base;
    if(!pbhr_small_path(w,&index)||!page||page>UINT64_MAX-4096||!base||!self->bytes||
       self->bytes>UINT64_MAX-base||pwmc_parent_overlap(page,4096,base,self->bytes)||
       a->core_pages!=PBGI_CORE_PAGES||r->AT_count>PBHI_AT_MAX||g->AT_count>PBHT_AT_MAX)return 0;
    for(unsigned k=0;k<PBGI_CORE_PAGES;k++)if(a->Core_AT[k].page==page)return 0;
    for(unsigned k=0;k<r->AT_count;k++)if(r->AT[k].page==page)return 0;
    for(unsigned k=0;k<g->AT_count;k++)if(g->AT[k].page==page)return 0;
    return 1;
}
static __attribute__((noinline)) int pbhi_capture(struct pbhi_result*r,struct pbhr_live*caller,
    struct pbhr_result*witness,const struct pbhr_input*original,const uint8_t seal[32],const void*deferred,const void*timer,struct pbht_result*g)
{
    if(!g||!r||!caller||!witness||!original||!seal||!deferred||!timer)return 0;
    struct pbhi_live live={.frame=*caller};const struct pbhr_live*frame=&live.frame;uint8_t hash[32];
    if(caller->r!=witness||caller->caller!=original)return 0;
    pbhr_seal(witness,&witness->api,sizeof(witness->api),hash);
    if(!pgcd_equal(hash,seal,32)||!pbhr_stable(caller)||!pbhi_storage(&witness->image[0],caller,witness,original,r,sizeof(*r))||
       !pbhi_storage(&witness->image[0],caller,witness,original,deferred,PBHI_DEFERRED_BYTES)||
       !pbhi_storage(&witness->image[0],caller,witness,original,timer,PBHI_TIMER_BYTES)||
       pwmc_parent_overlap((uintptr_t)r,sizeof(*r),(uintptr_t)deferred,PBHI_DEFERRED_BYTES)||
       pwmc_parent_overlap((uintptr_t)r,sizeof(*r),(uintptr_t)timer,PBHI_TIMER_BYTES)||
       pwmc_parent_overlap((uintptr_t)deferred,PBHI_DEFERRED_BYTES,(uintptr_t)timer,PBHI_TIMER_BYTES)||
       !pbhi_storage(&witness->image[0],caller,witness,original,g,sizeof(*g))||
       pwmc_parent_overlap((uintptr_t)g,sizeof(*g),(uintptr_t)r,sizeof(*r))||
       pwmc_parent_overlap((uintptr_t)g,sizeof(*g),(uintptr_t)deferred,PBHI_DEFERRED_BYTES)||
       pwmc_parent_overlap((uintptr_t)g,sizeof(*g),(uintptr_t)timer,PBHI_TIMER_BYTES)||
       !pwmc_zero(g,sizeof(*g))||!pwmc_zero(r,sizeof(*r)))return 0;
    r->input=(struct pbhi_input){.caller=caller,.witness=witness,.original=original,.deferred=deferred,.timer=timer};pgcd_copy(r->input.service_seal,seal,32);r->live_before=*frame;
    r->opening=frame->in.opening;r->virtual_before=witness->arch[0].cpu.ticks;r->core=frame->core;r->attempted=r->unknown=1;
    g->input=(struct pbht_input){.caller=caller,.witness=witness,.original=original,.provider=r,.deferred=deferred,.timer=timer};
    pgcd_copy(g->input.service_seal,seal,32);g->live_before=*frame;g->opening=r->opening;g->virtual_before=r->virtual_before;g->attempted=g->unknown=1;
    live.graph=g;live.r=r;live.in=r->input;live.core=frame->core;live.boot=frame->boot;live.opening=r->opening;live.before=r->virtual_before;
    if(!pbhi_tick(&live,0)||!pgci_verify((const void*)(uintptr_t)live.core,live.core,PGCI_IMAGE_BYTES,r->Core_hash[0],&r->hash_failed[0],&r->hash_count[0]))return pbhi_fail(r,1);
    struct pwmc_irq_path*p=&r->path;
    const struct pwmc_irq_input_reader reader={&live,pbhi_input_range,pbhi_input_pages,pbhi_input_source,pbhi_input_image,pbhi_input_rooted,pbhi_input_handlers};
    unsigned provider_error=pwmc_irq_provider_input(p,live.core,&reader);if(provider_error)return pbhi_fail(r,provider_error);
    if(!pbhi_graph_capture(&live)){if(!g->error)g->error=1;g->unknown=1;return pbhi_fail(r,7);}
    if(!pbhi_tick(&live,0))return pbhi_fail(r,5);
    if(!pgci_verify((const void*)(uintptr_t)live.core,live.core,PGCI_IMAGE_BYTES,r->Core_hash[1],&r->hash_failed[1],&r->hash_count[1]))return pbhi_fail(r,5);
    for(unsigned k=0;k<3;k++)if(!pwmc_irq_hash_image(&p->image[k],k,1))return pbhi_fail(r,5);
    struct pwmc_irq_map_view map=pbhi_map(r);
    if(!pbhi_source(&live,0)||!pwmc_irq_bindings_map(p,live.core,(uintptr_t)frame->in.system,&map))return pbhi_fail(r,5);
    if(!pbhi_release_disjoint(&live))return pbhi_fail(r,8);
    p->complete=1;pwmc_irq_digest(p,p->digest);r->captured=1;ppli_sha(r,offsetof(struct pbhi_result,digest),r->digest);return 1;
}
static inline int pbhi_pre_current(const struct pbhi_result*r,const struct pbht_result*g)
{
    struct pbhi_live live={.r=(struct pbhi_result*)r,.in=r->input,.frame=r->live_before,.core=r->core,
        .boot=r->live_before.boot,.opening=r->opening,.before=r->virtual_before,.rooted=1,.table_mask=7,.handlers=1,.graph=(struct pbht_result*)g,.event_rooted=1,.timer_rooted=1};
    struct pwmc_irq_map_view map=pbhi_map(r);
    return pbhi_graph_retained(g,r)&&pbhi_source(&live,0)&&pwmc_irq_bindings_map(&r->path,r->core,(uintptr_t)r->live_before.in.system,&map);
}
static __attribute__((noinline)) int pbhi_close(struct pbhi_result*r,struct pbht_result*g)
{
    struct pbhi_live live={.r=r,.in=r->input,.frame=r->live_before,.core=r->core,.boot=r->live_before.boot,
        .opening=r->opening,.before=r->virtual_before,.graph=g};
    if(!pbhi_tick(&live,1)||!pgci_verify((const void*)(uintptr_t)r->core,r->core,PGCI_IMAGE_BYTES,r->Core_hash[2],&r->hash_failed[2],&r->hash_count[2]))return pbhi_fail(r,6);
    r->closed=r->complete=1;r->unknown=0;ppli_sha(r,offsetof(struct pbhi_result,digest),r->digest);return 1;
}
#endif
