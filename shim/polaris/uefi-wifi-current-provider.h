/* Source-bound Timer/GIC/CPU INPUT after an existing later Map and its fresh
 * typed graph, while the genuine enclosing caller is still active. Reuses
 * the incoming-provider DATA walk; no provider method/IRQ dispatch/lease. */
#ifndef POLARIS_UEFI_WIFI_CURRENT_PROVIDER_H
#define POLARIS_UEFI_WIFI_CURRENT_PROVIDER_H
#include "uefi-wifi-current-graph.h"
#define PCMI_AT_MAX (PWMC_IRQ_IMAGES*PWMC_IRQ_PAGES+5u)
#define PCMI_CLOCK_MAX 40u
struct pcmt_result;
struct pcmi_binding {
    uint64_t parent_address;struct pcmp_live parent;const struct pcmg_result*graph;
    uint64_t opening,minimum;uint8_t frame_seal[32],graph_seal[32];
};
struct pcmi_result {
    struct pcmi_binding binding;uint8_t binding_digest[32];struct pwmc_irq_path path;
    struct ppli_at AT[PCMI_AT_MAX];struct pbgi_clock clock[PCMI_CLOCK_MAX];
    uint8_t Core_hash[2][5][32];uint32_t hash_count[2],hash_failed[2];
    struct pcmp_live parent_after;
    uint32_t attempted,complete,unknown,error,AT_count,arch_issued,arch_returned,parent_copied,reserved;
    uint8_t digest[32];
};
struct pcmi_live {
    struct pcmi_result*r;struct pcmp_live*parent;const struct pcmg_result*graph;
    struct pcmp_live frame;int(*page)(struct ppli_at*);
    uint64_t core,opening,minimum;uint8_t binding_seal[32];unsigned rooted,table_mask,handlers;
#if defined(POLARIS_WIFI_CURRENT_TIMER_INPUT)
    const struct pcmt_result*timer;uint8_t timer_seal[32];
#endif
};
#if defined(POLARIS_WIFI_CURRENT_TIMER_INPUT)
#define PCMI_LIVE_BYTES 448u
static const struct pcmt_result*pcmi_parent_timer(struct pcmi_live*);
static inline int pcmi_timer_attach(struct pcmi_live*,const struct pcmt_result*);
static inline int pcmi_timer_retained(const struct pcmi_live*);
#else
#define PCMI_LIVE_BYTES 408u
#endif
_Static_assert(sizeof(struct pcmi_binding)==400&&sizeof(struct pcmi_live)==PCMI_LIVE_BYTES&&sizeof(struct pcmi_result)==20456,
    "separate complete later provider INPUT raw ABI v1");
_Static_assert(offsetof(struct pcmi_result,path)==432&&offsetof(struct pcmi_result,AT)==12832&&
    offsetof(struct pcmi_result,clock)==14624&&offsetof(struct pcmi_result,parent_after)==20080&&
    offsetof(struct pcmi_result,digest)==20420,"independent later provider INPUT decoder offsets");
/* The graph digest covers its prefix; its aligned RAW object also retains
 * eight trailing padding bytes. Close those bytes separately without changing
 * the old graph schema or reinterpreting its historical prefix digest. */
static inline int pcmi_graph_tail(const struct pcmg_result*g)
{return pwmc_zero((const uint8_t*)g+offsetof(struct pcmg_result,digest)+sizeof(g->digest),
    sizeof(*g)-offsetof(struct pcmg_result,digest)-sizeof(g->digest));}
static inline int pcmi_fail(struct pcmi_result*r,unsigned error)
{if(!r->error)r->error=error;r->unknown=1;return 0;}
static inline int pcmi_known_input(const struct pwmc_irq_path*p,uint64_t core,
    unsigned rooted,unsigned table_mask,unsigned handlers)
{
    if(rooted&&(pwfi_le((const void*)(uintptr_t)(core+0x1cb80),8)!=p->tables[0]||
       pwfi_le((const void*)(uintptr_t)(core+0x1c8f8),8)!=p->tables[2]))return 0;
    for(unsigned k=0;k<3;k++)if(p->image[k].complete){
        const struct pwmc_irq_image*i=&p->image[k];const struct pwmc_irq_binding*b=&pwmc_irq_bindings[k];
        if(!pgcd_equal(i->state,(const void*)(uintptr_t)(i->base+b->state),b->state_bytes)||
           ((table_mask&(1u<<k))&&!pgcd_equal(i->table,(const void*)(uintptr_t)p->tables[k],b->table_bytes)))return 0;
    }
    return !handlers||pgcd_equal(p->handler,(const void*)(uintptr_t)p->handlers,p->handler_count*8);
}
static inline int pcmi_known(const struct pcmi_live*l)
{return pcmi_known_input(&l->r->path,l->core,l->rooted,l->table_mask,l->handlers);}
static inline int pcmi_source(const struct pcmi_live*l)
{
    const struct pcmi_result*r=l->r;uint8_t hash[32];ppli_sha(&r->binding,sizeof(r->binding),hash);
    if(!pgcd_equal(hash,l->binding_seal,32)||!pgcd_equal(r->binding_digest,l->binding_seal,32)||
       r->binding.parent_address!=(uintptr_t)l->parent||!pgcd_equal(&r->binding.parent,&l->frame,sizeof(l->frame))||
       !pgcd_equal(l->parent,&l->frame,sizeof(l->frame))||r->binding.graph!=l->graph||
       r->binding.opening!=l->opening||r->binding.minimum!=l->minimum||r->attempted!=1||r->complete||
       r->unknown!=1||r->error||r->reserved||r->parent_copied||!pwmc_zero(&r->parent_after,sizeof(r->parent_after))||
       !pwmc_zero(r->digest,sizeof(r->digest))||r->AT_count>PCMI_AT_MAX||
       r->arch_issued>PCMI_CLOCK_MAX||r->arch_returned>r->arch_issued)return 0;
    ppli_sha(l->graph,offsetof(struct pcmg_result,digest),hash);
    if(!pgcd_equal(hash,r->binding.graph_seal,32)||!pgcd_equal(l->graph->digest,r->binding.graph_seal,32)||
       !pcmi_graph_tail(l->graph))return 0;
    pbgi_parent_frame_seal(l->parent,hash);
    if(!pgcd_equal(hash,r->binding.frame_seal,32)||!pcmp_source_stable(l->parent))return 0;
    /* Qualified DATA view only, never a fabricated opened/live context. The
     * fresh graph's own full bytes are sealed before following its nodes. */
    const struct pbgi_result*g=&l->graph->graph;struct pbgi_live view={.r=(struct pbgi_result*)g,.core=l->core};
    pbgi_root_seal(g,view.root_seal);
    if(!pbgi_roots_current(&view))return 0;
    for(unsigned list=0;list<2;list++)for(unsigned k=0;k<g->count[list];k++){
        const struct pbgi_node*n=&g->node[list][k];
        if(!pgcd_equal(n->raw,(const void*)(uintptr_t)n->address,n->bytes))return 0;
    }
    if(!pcmi_known(l))return 0;
#if defined(POLARIS_WIFI_CURRENT_TIMER_INPUT)
    if(l->timer&&!pcmi_timer_retained(l))return 0;
#endif
    return 1;
}
static inline void pcmi_seal(const struct pcmi_result*r,const void*skip,size_t bytes,uint8_t out[32])
{struct pwfi_sha256 h;pwfi_init(&h);pbgi_hash_part(&h,r,sizeof(*r),skip,bytes);pwfi_final(&h,out);}
static __attribute__((noinline)) int pcmi_tick(struct pcmi_live*l)
{
    struct pcmi_result*r=l->r;if(!pcmi_source(l))return 0;unsigned k=r->arch_issued;
    if(k>=PCMI_CLOCK_MAX||r->arch_returned!=k)return 0;struct pbgi_clock*c=&r->clock[k];
    if(!pwmc_zero(c,sizeof(*c)))return 0;
    uint64_t minimum=k?r->clock[k-1].raw.cpu.ticks:l->minimum;
    if(k&&(r->clock[k-1].issued!=1||r->clock[k-1].returned!=1||r->clock[k-1].native_issued!=3||r->clock[k-1].native_returned!=3))return 0;
    c->native_issued=1;c->native[0]=*l->frame.input.native_flag;c->native_returned=1;if(c->native[0])return 0;
    c->issued=1;r->arch_issued=k+1;
    uint8_t before[32],after[32],control[32],actual[32];pcmi_seal(r,&c->raw,sizeof(c->raw),before);ppli_sha(l,sizeof(*l),control);
    int ok=l->frame.original_io.arch(l->frame.original_io.opaque,&c->raw);
    ppli_sha(l,sizeof(*l),actual);if(!pgcd_equal(control,actual,32)||!ok)return 0;
    pcmi_seal(r,&c->raw,sizeof(c->raw),after);
    if(!pgcd_equal(before,after,32)||!pcmi_source(l)||r->arch_issued!=k+1||r->arch_returned!=k)return 0;
    c->returned=1;r->arch_returned=k+1;
    const struct pgcd_arch*a=&l->frame.r->call.after;
    if(!pwfc_arch_stable(&a->cpu,&c->raw.cpu)||a->cpacr!=c->raw.cpacr||c->raw.cpu.daif||c->raw.cpu.group1!=1||
       c->raw.cpu.ticks<minimum||c->raw.cpu.ticks<l->opening||c->raw.cpu.ticks-l->opening>PGCD_FRESH_TICKS)return 0;
    c->native_issued=3;c->native[1]=*l->frame.input.native_flag;c->native_returned=3;return !c->native[1];
}
static inline int pcmi_range(const void*opaque,uint64_t at,uint64_t bytes)
{
    const struct pcmi_live*l=opaque;struct pbgi_live view={.r=(struct pbgi_result*)&l->graph->graph};
    const struct efi_loaded*i=l->frame.input.image;
    return !pwmc_parent_overlap(at,bytes,(uintptr_t)i->base,i->bytes)&&
        !pwmc_parent_overlap(at,bytes,l->core,PGCI_IMAGE_BYTES)&&pbgi_RAM(&view,at,bytes);
}
static inline int pcmi_page(struct pcmi_live*l,struct ppli_at*a,uint64_t page)
{
    struct pcmi_result*r=l->r;if(!pcmi_source(l)||!pwmc_zero(a,sizeof(*a)))return 0;
    a->page=page;a->native_issued=1;a->native[0]=*l->frame.input.native_flag;a->native_returned=1;if(a->native[0])return 0;
    uint8_t before[32],after[32],control[32],actual[32];pcmi_seal(r,a,sizeof(*a),before);ppli_sha(l,sizeof(*l),control);
    int ok=l->page(a);ppli_sha(l,sizeof(*l),actual);
    if(!pgcd_equal(control,actual,32)||!ok)return 0;pcmi_seal(r,a,sizeof(*a),after);
    if(!pgcd_equal(before,after,32)||!pcmi_source(l)||a->page!=page||a->issued!=1||a->returned!=1||
       a->saved!=a->restored||a->par!=(UINT64_C(0xff00000000000b80)|page)||a->native_issued!=1||a->native_returned!=1||
       !pwmc_zero(a->native,sizeof(a->native)))return 0;
    a->native_issued=3;a->native[1]=*l->frame.input.native_flag;a->native_returned=3;return !a->native[1];
}
static __attribute__((noinline)) int pcmi_pages(void*opaque,uint64_t at,uint64_t bytes,
    struct pwmc_irq_AT*out,unsigned capacity,uint32_t*count)
{
    struct pcmi_live*l=opaque;struct pcmi_result*r=l->r;
    if(!pcmi_source(l)||!pcmi_range(l,at,bytes)||*count)return 0;
    for(uint64_t page=at&~UINT64_C(4095);page<at+bytes;page+=4096){
        unsigned k=r->AT_count,n=*count;if(k==PCMI_AT_MAX||n==capacity)return 0;
        struct ppli_at*a=&r->AT[k];struct pwmc_irq_AT*q=&out[n];if(!pwmc_zero(a,sizeof(*a))||!pwmc_zero(q,sizeof(*q)))return 0;
        q->page=page;q->issued=1;
        if(!pcmi_page(l,a,page)||r->AT_count!=k||*count!=n||q->page!=page||q->issued!=1||q->returned||q->raw)return 0;
        q->raw=a->par;q->returned=1;r->AT_count=k+1;*count=n+1;if(!pcmi_tick(l))return 0;
    }return 1;
}
static inline int pcmi_input_source(const void*opaque){return pcmi_source(opaque);}
static inline int pcmi_input_image(void*opaque,unsigned image,uint64_t base)
{
    struct pcmi_live*l=opaque;const struct pwmc_irq_input_reader reader={l,pcmi_range,pcmi_pages,pcmi_input_source,0,0,0};
    if(!pwmc_irq_image_input(&l->r->path,image,base,&reader))return 0;l->table_mask|=1u<<image;return 1;
}
static inline void pcmi_input_rooted(void*opaque){((struct pcmi_live*)opaque)->rooted=1;}
static inline void pcmi_input_handlers(void*opaque){((struct pcmi_live*)opaque)->handlers=1;}
static __attribute__((noinline)) int pcmi_capture(struct pcmi_result*r,struct pcmp_live*parent,
    const struct pcmg_result*graph,int(*read_page)(struct ppli_at*))
{
    if(!r||!parent||!graph||!read_page||!pcmp_source_stable(parent)||
       !pcmg_output_storage(r,sizeof(*r),parent)||!pcmp_in_self(parent->input.image,graph,sizeof(*graph))||
       pwmc_parent_overlap((uintptr_t)r,sizeof(*r),(uintptr_t)graph,sizeof(*graph))||!pwmc_zero(r,sizeof(*r)))return 0;
    uint8_t hash[32];ppli_sha(graph,offsetof(struct pcmg_result,digest),hash);
    if(graph->attempted!=1||graph->complete!=1||graph->unknown||graph->error||graph->parent_copied!=1||
       !pgcd_equal(hash,graph->digest,32)||!pcmi_graph_tail(graph)||!pgcd_equal(&graph->binding.parent,parent,sizeof(*parent))||
       !pgcd_equal(&graph->parent_after,parent,sizeof(*parent))||graph->binding.parent_address!=(uintptr_t)parent||
       graph->graph.core_pages!=PBGI_CORE_PAGES||graph->graph.count[0]>PBGI_NODES||graph->graph.count[1]>PBGI_NODES||
       !graph->graph.arch_returned||graph->graph.arch_returned>PBGI_CLOCKS||graph->graph.arch_issued!=graph->graph.arch_returned)return 0;
    const struct pbgi_clock*last=&graph->graph.clock[graph->graph.arch_returned-1];
    if(last->issued!=1||last->returned!=1||last->native_issued!=3||last->native_returned!=3||last->native[0]||last->native[1]||
       last->raw.cpu.ticks<graph->binding.opening||last->raw.cpu.ticks-graph->binding.opening>PGCD_FRESH_TICKS)return 0;
    r->attempted=r->unknown=1;r->binding.parent_address=(uintptr_t)parent;r->binding.parent=*parent;r->binding.graph=graph;
    r->binding.opening=graph->binding.opening;r->binding.minimum=last->raw.cpu.ticks;
    pbgi_parent_frame_seal(parent,r->binding.frame_seal);pgcd_copy(r->binding.graph_seal,graph->digest,32);
    ppli_sha(&r->binding,sizeof(r->binding),r->binding_digest);
    struct pcmi_live live={.r=r,.parent=parent,.graph=graph,.frame=*parent,.page=read_page,
        .core=graph->graph.core,.opening=r->binding.opening,.minimum=r->binding.minimum};
    pgcd_copy(live.binding_seal,r->binding_digest,32);
    unsigned error=1;
    if(pcmi_tick(&live)&&pgci_verify((const void*)(uintptr_t)live.core,live.core,PGCI_IMAGE_BYTES,r->Core_hash[0],&r->hash_failed[0],&r->hash_count[0])){
        const struct pwmc_irq_input_reader reader={&live,pcmi_range,pcmi_pages,pcmi_input_source,pcmi_input_image,pcmi_input_rooted,pcmi_input_handlers};
        error=pwmc_irq_provider_input(&r->path,live.core,&reader);
        if(!error){
            error=5;
#if defined(POLARIS_WIFI_CURRENT_TIMER_INPUT)
            const struct pcmt_result*timer=pcmi_parent_timer(&live);
            if(!pcmi_timer_attach(&live,timer))error=7;
#endif
            /* Close immutable source bytes AFTER the last foreign callback;
             * no further callback follows these final hashes and DATA checks. */
            if(error==5&&pcmi_tick(&live)&&pcmi_tick(&live)&&
               pgci_verify((const void*)(uintptr_t)live.core,live.core,PGCI_IMAGE_BYTES,r->Core_hash[1],&r->hash_failed[1],&r->hash_count[1])){
                int hashes=1;for(unsigned k=0;k<3;k++)if(!pwmc_irq_hash_image(&r->path.image[k],k,1)){hashes=0;break;}
                if(hashes&&pcmi_source(&live)){
                    const struct pwmc_irq_map_view map={graph->graph.call.data,graph->graph.call.map.bytes,graph->graph.call.map.stride,
                        (uintptr_t)parent->input.image->base,parent->input.image->bytes};
                    if(pwmc_irq_bindings_map(&r->path,live.core,(uintptr_t)live.frame.original_io.system,&map)){
                        r->path.complete=1;pwmc_irq_digest(&r->path,r->path.digest);error=0;
                    }
                }
            }
        }
    }
    /* Only original own stack/output pointers after a refusal. Preserve any
     * already poisoned output/copy flag instead of clearing it to success. */
    if(!r->parent_copied&&pwmc_zero(&r->parent_after,sizeof(r->parent_after))){pgcd_copy(&r->parent_after,parent,sizeof(*parent));r->parent_copied=1;}
    if(error)return pcmi_fail(r,error);
    if(!pgcd_equal(&r->parent_after,&r->binding.parent,sizeof(r->parent_after)))return pcmi_fail(r,6);
    r->unknown=0;r->complete=1;ppli_sha(r,offsetof(struct pcmi_result,digest),r->digest);return 1;
}
static inline int pcmi_route_capture(const struct pcmp_route*routes,unsigned count,
    struct pcmi_result frames[PCMP_PARENT_CONTEXTS][2],const struct pcmg_result graphs[PCMP_PARENT_CONTEXTS][2],
    struct pcmp_live*parent,int(*read_page)(struct ppli_at*))
{
    if(!frames||!graphs||!read_page)return 0;unsigned index=0,slot=0;
    if(!pcmg_active_route(routes,count,parent,&index,&slot)||!pcmp_source_stable(parent)||
       !pcmp_in_self(parent->input.image,frames,PCMP_PARENT_CONTEXTS*sizeof(*frames))||
       !pcmp_in_self(parent->input.image,graphs,PCMP_PARENT_CONTEXTS*sizeof(*graphs)))return 0;
    const struct pcmi_result*out=&frames[index][slot];
    if(pwmc_parent_overlap((uintptr_t)out,sizeof(*out),(uintptr_t)routes,count*sizeof(*routes))||
       pwmc_parent_overlap((uintptr_t)out,sizeof(*out),(uintptr_t)graphs,PCMP_PARENT_CONTEXTS*sizeof(*graphs)))return 0;
    for(unsigned n=0;n<count;n++){
        const struct {const void*address;uint64_t bytes;} other[]={{routes[n].context,sizeof(*routes[n].context)},
            {routes[n].source,sizeof(*routes[n].source)},{routes[n].ticket,sizeof(*routes[n].ticket)},{routes[n].frames,2*sizeof(*routes[n].frames)}};
        for(unsigned k=0;k<sizeof(other)/sizeof(other[0]);k++)if(pwmc_parent_overlap((uintptr_t)out,sizeof(*out),(uintptr_t)other[k].address,other[k].bytes))return 0;
    }
    return pcmi_capture(&frames[index][slot],parent,&graphs[index][slot],read_page);
}
static inline int pcmi_route_minimum(const struct pcmp_route*routes,unsigned count,
    const struct pcmg_result graphs[PCMP_PARENT_CONTEXTS][2],const struct pcmi_result frames[PCMP_PARENT_CONTEXTS][2],
    const struct pgcd_context*c,unsigned slot,uint64_t*out)
{
    if(!frames||!pcmg_route_minimum(routes,count,graphs,c,slot,out))return 0;
    unsigned index=0;for(;index<count;index++)if(routes[index].context==c)break;if(index==count)return 0;
    const struct pcmi_result*r=&frames[index][slot];const struct pcmg_result*g=&graphs[index][slot];uint8_t hash[32];
    if(!pcmi_graph_tail(g)||!pwmc_zero((const uint8_t*)r+offsetof(struct pcmi_result,digest)+sizeof(r->digest),
       sizeof(*r)-offsetof(struct pcmi_result,digest)-sizeof(r->digest))||
       r->attempted!=1||r->complete!=1||r->unknown||r->error||r->reserved||r->parent_copied!=1||
       r->path.attempted!=1||r->path.complete!=1||r->path.finalized||r->AT_count>PCMI_AT_MAX||
       r->hash_count[0]!=5||r->hash_count[1]!=5||r->hash_failed[0]||r->hash_failed[1]||
       r->binding.graph!=g||r->binding.parent_address!=g->binding.parent_address||
       !pgcd_equal(&r->binding.parent,&g->binding.parent,sizeof(r->binding.parent))||
       !pgcd_equal(&r->parent_after,&r->binding.parent,sizeof(r->parent_after))||
       r->binding.opening!=g->binding.opening||r->binding.minimum!=*out||!pgcd_equal(r->binding.graph_seal,g->digest,32)||
       !r->arch_returned||r->arch_returned>PCMI_CLOCK_MAX||r->arch_issued!=r->arch_returned)return 0;
    ppli_sha(r,offsetof(struct pcmi_result,digest),hash);if(!pgcd_equal(hash,r->digest,32))return 0;
    const struct pbgi_clock*last=&r->clock[r->arch_returned-1];uint64_t ticks=last->raw.cpu.ticks;
    if(last->issued!=1||last->returned!=1||last->native_issued!=3||last->native_returned!=3||last->native[0]||last->native[1]||
       !ticks||ticks==UINT64_MAX||ticks<*out||ticks<r->binding.opening||ticks-r->binding.opening>PGCD_FRESH_TICKS)return 0;
    *out=ticks;return 1;
}
#if defined(POLARIS_WIFI_CURRENT_TIMER_INPUT)
#include "uefi-wifi-current-timer.h"
#endif
#endif
