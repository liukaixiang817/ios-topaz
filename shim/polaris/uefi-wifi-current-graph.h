/* Fresh typed graph/policy/source INPUT after an existing later GetMap.
 * No extra firmware call, first-call qualification, inventory or owner lease.
 * The old producer's phase4/capacity contract remains in its public wrapper. */
#ifndef POLARIS_UEFI_WIFI_CURRENT_GRAPH_H
#define POLARIS_UEFI_WIFI_CURRENT_GRAPH_H
#include "uefi-wifi-gcd-bootstrap.h"
_Static_assert(sizeof(struct pcmp_live)==304&&sizeof(struct pcmg_binding)==408,"complete active later caller and route binding");
_Static_assert(sizeof(struct pcmg_result)==310480&&offsetof(struct pcmg_result,graph)==448&&
    offsetof(struct pcmg_result,parent_after)==310112&&offsetof(struct pcmg_result,digest)==310440,"separate post-map graph INPUT raw ABI v3");
static inline int pcmg_fail(struct pcmg_result*r,unsigned error)
{if(!r->error)r->error=error;r->unknown=1;return 0;}
static inline int pcmg_output_storage(const void*r,uint64_t bytes,const struct pcmp_live*p)
{
    const struct pcmp_input*i=&p->input;const struct pcmp_result*s=p->r;
    uint64_t payload_extent=pwmc_parent_payload_extent(s->payload,s->payload_count);
    if(!payload_extent||!pcmp_in_self(i->image,r,bytes))return 0;
    const struct {const volatile void*address;uint64_t bytes;} source[]={
        {p,sizeof(*p)},{s,sizeof(*s)},{p->caller_input,sizeof(*p->caller_input)},{p->caller_io,sizeof(*p->caller_io)},
        {i->context,sizeof(*i->context)},{i->context->record,sizeof(*i->context->record)},
        {i->context->ticket,sizeof(*i->context->ticket)},{i->image,sizeof(*i->image)},{i->images,sizeof(*i->images)},
        {i->payload_binding,sizeof(*i->payload_binding)},{i->native_flag,4},{i->load_state,4},
        {i->payload_slot,8},{i->log_slot,8},{i->received,8},{i->payload_count,8},{i->plan,sizeof(*i->plan)},
        {p->original_io.system,sizeof(*p->original_io.system)},{p->original_io.system->boot,PWMC_BS_BYTES},
        {(const void*)(uintptr_t)s->payload,payload_extent},{(const void*)(uintptr_t)s->log,i->log_bytes}
    };
    for(unsigned k=0;k<sizeof(source)/sizeof(source[0]);k++)
        if(pwmc_parent_overlap((uintptr_t)r,bytes,(uintptr_t)source[k].address,source[k].bytes))return 0;
    return 1;
}
static inline int pcmg_storage(const struct pcmg_result*r,const struct pcmp_live*p)
{return pcmg_output_storage(r,sizeof(*r),p);}
static __attribute__((noinline)) int pcmg_capture(struct pcmg_result*r,struct pcmp_live*parent,
    const struct pcmp_route*route,unsigned index,unsigned slot,int(*read_page)(struct ppli_at*))
{
    if(!r||!parent||!route||!read_page||index>=PCMP_PARENT_CONTEXTS||slot>1||
       parent->r!=&route->frames[slot]||parent->input.context!=route->context||
       parent->r->attempted!=1||parent->r->complete||parent->r->unknown!=1||parent->r->error||
       !pcmp_source_stable(parent)||!pcmg_storage(r,parent)||
       pwmc_parent_overlap((uintptr_t)r,sizeof(*r),(uintptr_t)route,sizeof(*route))||!pwmc_zero(r,sizeof(*r)))return 0;
    r->attempted=r->unknown=1;r->binding.parent_address=(uintptr_t)parent;
    pgcd_copy(&r->binding.parent,parent,sizeof(*parent));r->binding.route=*route;
    r->binding.index=index;r->binding.slot=slot;
    r->binding.opening=parent->r->source_before.before.cpu.ticks;
    r->binding.minimum=parent->r->final_arch.cpu.ticks;
    pbgi_parent_frame_seal(parent,r->binding.frame_seal);
    ppli_sha(&r->binding,sizeof(r->binding),r->binding_digest);
    /* Use the original IO bound by this ACTIVE caller. call.io is the
     * captured relay, whose opaque is this stack; it is DATA, not replayed. */
    const struct pbgi_input in={.call=&parent->r->call,.native=parent->input.native_flag,
        .opening=r->binding.opening,.io=parent->original_io};
    struct pbgi_result*g=&r->graph;g->attempted=g->unknown=1;g->input=in;g->call=*in.call;
    uint8_t hash[32];ppli_sha(&g->call,offsetof(struct pwmc_parent_map,digest),hash);
    const struct pgcd_io relay={.opaque=parent,.system=in.io.system,.arch=pcmp_arch,.map=pcmp_map,
        .fp_save=pcmp_save,.fp_restore=pcmp_restore,.order=pcmp_order};
    if(parent->map_copied!=1||parent->map_issued!=1||parent->map_returned!=1||parent->header_started!=1||parent->header_copied!=1||
       parent->r->slot!=slot||parent->r->path!=route->path||parent->r->arch_issued!=1||parent->r->arch_returned!=1||
       route->source!=parent->r->context_before.record||route->ticket!=parent->r->context_before.ticket||
       !in.io.system||!in.io.arch||!in.opening||g->call.input.phase!=3||g->call.input.capacity!=PGCD_MAP_CAP||
       g->call.input.native_flag!=in.native||g->call.input.system!=in.io.system||!pgcd_equal(&g->call.io,&relay,sizeof(relay))||
       g->call.complete!=1||g->call.unknown||g->call.error||g->call.map.bytes>PGCD_MAP_CAP||
       in.opening>g->call.before.cpu.ticks||r->binding.minimum<g->call.after.cpu.ticks||
       r->binding.minimum<in.opening||r->binding.minimum-in.opening>PGCD_FRESH_TICKS||
       !pwmc_parent_map_valid(&g->call)||!pgcd_equal(hash,g->call.digest,32))return pcmg_fail(r,1);
    g->core=g->call.boot_address-0x1b800;
    struct pbgi_active live={.source={.r=g,.in=in,.caller=&in,.core=g->core,.bytes=g->call.map.bytes},
        .minimum=r->binding.minimum,.parent=parent,.current=r};
    pbgi_call_seal(&g->call,live.source.bytes,live.source.call_seal);pgcd_copy(live.source.full_call_seal,hash,32);
    pgcd_copy(live.current_seal,r->binding_digest,32);
    int ok=pbgi_walk(&live,read_page);
    /* Known own stack bytes only, including the actual rejected control.
     * No source pointer or hardware is followed after an error. */
    if(!r->parent_copied&&pwmc_zero(&r->parent_after,sizeof(r->parent_after))){
        pgcd_copy(&r->parent_after,parent,sizeof(*parent));r->parent_copied=1;
    }
    if(!ok)return pcmg_fail(r,2);
    if(!pgcd_equal(&r->parent_after,&r->binding.parent,sizeof(*parent))||!pcmp_source_stable(parent)||
       !g->complete||g->unknown||g->error||!g->arch_returned||g->arch_returned>PBGI_CLOCKS||
       g->arch_issued!=g->arch_returned)return pcmg_fail(r,3);
    r->unknown=0;r->complete=1;ppli_sha(r,offsetof(struct pcmg_result,digest),r->digest);return 1;
}
/* Closed actual frame selection before following any route source pointer.
 * The real parent supplies its six resident objects; foreign/interior frames
 * and the absent client-closing slot have no fallback. */
static inline int pcmg_active_route(const struct pcmp_route*routes,unsigned count,const struct pcmp_live*parent,
    unsigned*chosen,unsigned*part)
{
    if(!routes||count!=PCMP_PARENT_CONTEXTS||!parent||!chosen||!part)return 0;
    unsigned matches=0,index=0,slot=0;
    for(unsigned n=0;n<count;n++){
        const struct pcmp_route*a=&routes[n];
        if(!a->context||!a->source||!a->ticket||!a->frames||a->path>PCMP_CLIENT_OPEN||a->reserved)return 0;
        for(unsigned j=0;j<n;j++)if(a->context==routes[j].context||a->source==routes[j].source||
            a->ticket==routes[j].ticket||a->frames==routes[j].frames)return 0;
        for(unsigned k=0;k<2;k++)if(parent->r==&a->frames[k]){matches++;index=n;slot=k;}
    }
    if(matches!=1||(index==5&&slot)||parent->input.context!=routes[index].context||
       parent->r->attempted!=1||parent->r->complete||parent->r->unknown!=1||parent->r->error||
       parent->r->path!=routes[index].path||parent->r->slot!=slot||
       parent->r->context_before.record!=routes[index].source||parent->r->context_before.ticket!=routes[index].ticket)return 0;
    *chosen=index;*part=slot;return 1;
}
static inline int pcmg_route_capture(const struct pcmp_route*routes,unsigned count,
    struct pcmg_result frames[PCMP_PARENT_CONTEXTS][2],struct pcmp_live*parent,int(*read_page)(struct ppli_at*))
{
    if(!frames||!read_page)return 0;unsigned index=0,slot=0;
    if(!pcmg_active_route(routes,count,parent,&index,&slot)||!pcmp_source_stable(parent)||
       !pcmp_in_self(parent->input.image,frames,PCMP_PARENT_CONTEXTS*sizeof(*frames)))return 0;
    const struct pcmg_result*out=&frames[index][slot];
    if(pwmc_parent_overlap((uintptr_t)out,sizeof(*out),(uintptr_t)routes,count*sizeof(*routes)))return 0;
    for(unsigned n=0;n<count;n++){
        const struct {const void*address;uint64_t bytes;} other[]={
            {routes[n].context,sizeof(*routes[n].context)},{routes[n].source,sizeof(*routes[n].source)},
            {routes[n].ticket,sizeof(*routes[n].ticket)},{routes[n].frames,2*sizeof(*routes[n].frames)}
        };
        for(unsigned k=0;k<sizeof(other)/sizeof(other[0]);k++)
            if(pwmc_parent_overlap((uintptr_t)out,sizeof(*out),(uintptr_t)other[k].address,other[k].bytes))return 0;
    }
    return pcmg_capture(&frames[index][slot],parent,&routes[index],index,slot,read_page);
}
/* Hand an already observed numeric minimum to the still-active outer Map
 * guard. All pointers in completed caller captures remain DATA. Close the
 * actual six resident objects before following the selected source/frame. */
static inline int pcmg_route_minimum(const struct pcmp_route*routes,unsigned count,
    const struct pcmg_result frames[PCMP_PARENT_CONTEXTS][2],const struct pgcd_context*c,unsigned slot,uint64_t*out)
{
    if(!routes||count!=PCMP_PARENT_CONTEXTS||!frames||!c||slot>1||!out)return 0;
    *out=0;unsigned matches=0,index=0;
    for(unsigned n=0;n<count;n++){
        const struct pcmp_route*a=&routes[n];
        if(!a->context||!a->source||!a->ticket||!a->frames||a->path>PCMP_CLIENT_OPEN||a->reserved)return 0;
        for(unsigned j=0;j<n;j++)if(a->context==routes[j].context||a->source==routes[j].source||
            a->ticket==routes[j].ticket||a->frames==routes[j].frames)return 0;
        if(c==a->context){matches++;index=n;}
    }
    if(matches!=1||(index==5&&slot))return 0;
    const struct pcmp_route*a=&routes[index];const struct pcmp_result*m=&a->frames[slot];
    const struct pcmg_result*g=&frames[index][slot];
    if(c->record!=a->source||c->ticket!=a->ticket||!pgcd_equal(c,&m->context_before,sizeof(*c))||
       a->source->outstanding!=0x20000u+slot||a->source->map[slot].issued!=1||a->source->map[slot].returned!=1||
       a->source->map_guard[slot].entered!=1||a->source->map_guard[slot].unknown!=1||a->source->map_guard[slot].left||
       a->source->map_guard[slot].fp.saved!=1||a->source->map_guard[slot].fp.restored||
       m->attempted!=1||m->complete!=1||m->unknown||m->error||m->path!=a->path||m->slot!=slot||
       m->map_issued!=1||m->map_returned!=1||m->input.context!=c||
       g->attempted!=1||g->complete!=1||g->unknown||g->error||g->reserved||g->parent_copied!=1||
       g->binding.index!=index||g->binding.slot!=slot||!pgcd_equal(&g->binding.route,a,sizeof(*a))||
       g->binding.parent.r!=m||g->binding.parent.input.context!=c||
       !pgcd_equal(&g->binding.parent,&g->parent_after,sizeof(g->parent_after))||
       g->binding.opening!=a->source->before.cpu.ticks||g->binding.minimum!=m->final_arch.cpu.ticks||
       g->graph.attempted!=1||g->graph.complete!=1||g->graph.unknown||g->graph.error||
       g->graph.input.call!=&m->call||g->graph.input.opening!=g->binding.opening||
       !g->graph.arch_returned||g->graph.arch_returned>PBGI_CLOCKS||g->graph.arch_issued!=g->graph.arch_returned)return 0;
    uint8_t hash[32];ppli_sha(m,offsetof(struct pcmp_result,digest),hash);
    if(!pgcd_equal(hash,m->digest,32))return 0;
    ppli_sha(g,offsetof(struct pcmg_result,digest),hash);if(!pgcd_equal(hash,g->digest,32))return 0;
    const struct pbgi_clock*last=&g->graph.clock[g->graph.arch_returned-1];uint64_t ticks=last->raw.cpu.ticks;
    if(last->issued!=1||last->returned!=1||last->native_issued!=3||last->native_returned!=3||
       last->native[0]||last->native[1]||!g->binding.opening||!ticks||ticks==UINT64_MAX||
       ticks<g->binding.minimum||ticks<a->source->after.cpu.ticks||ticks<g->binding.opening||
       ticks-g->binding.opening>PGCD_FRESH_TICKS)return 0;
    *out=ticks;return 1;
}
#endif
