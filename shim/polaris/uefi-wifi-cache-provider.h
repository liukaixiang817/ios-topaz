/* Original Timer/GIC/CPU DATA inputs in the real incoming-contract release
 * interval. Reuse the existing immutable/binding readers, without fabricating
 * an opened allocator/GCD context. No provider method is executed. */
#ifndef POLARIS_UEFI_WIFI_CACHE_PROVIDER_H
#define POLARIS_UEFI_WIFI_CACHE_PROVIDER_H
#include "uefi-wifi-cache-release.h"
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
    struct pbhi_result*r;struct pbhi_input in;struct pbhr_live frame;
    uint64_t core,boot,opening,before;unsigned rooted,table_mask,handlers;
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
 pbgi_hash_part(&h,l->in.deferred,PBHI_DEFERRED_BYTES,0,0);pbgi_hash_part(&h,l->in.timer,PBHI_TIMER_BYTES,0,0);pwfi_final(&h,out);}
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
static inline int pbhi_source(const struct pbhi_live*l,unsigned post)
{
    const struct pbhi_result*r=l->r;uint8_t hash[32];
    if(!pgcd_equal(&r->input,&l->in,sizeof(l->in))||!pgcd_equal(&r->live_before,&l->frame,sizeof(l->frame))||
       !pgcd_equal(l->in.caller,&l->frame,sizeof(l->frame))||r->core!=l->core||r->opening!=l->opening||r->virtual_before!=l->before||
       r->AT_count>PBHI_AT_MAX||r->arch_issued>PBHI_CLOCK_MAX||r->arch_returned>r->arch_issued)return 0;
    const struct pbhr_result*w=l->in.witness;
    pbhr_seal(w,&w->api,sizeof(w->api),hash);if(!pgcd_equal(hash,l->in.service_seal,32))return 0;
    if(l->in.caller->r!=w||l->in.caller->caller!=l->in.original||
       (uintptr_t)l->frame.in.system->boot!=l->boot||!pgcd_equal(l->frame.in.system->boot,w->BS[0],PWMC_BS_BYTES)||
       !pgcd_equal(l->frame.in.image,&w->image[0],sizeof(w->image[0])))return 0;
    if(post)return w->api.issued==1&&w->api.returned==1&&!w->api.status;
    return !w->api.issued&&!w->api.returned&&w->api.status==UINT64_MAX&&pbhr_stable(l->in.caller)&&pbhi_known(l);
}
static __attribute__((noinline)) int pbhi_tick(struct pbhi_live*l,unsigned post)
{
    struct pbhi_result*r=l->r;if(!pbhi_source(l,post))return 0;unsigned k=r->arch_issued;
    if(k==PBHI_CLOCK_MAX)return 0;struct pbgi_clock*c=&r->clock[k];if(!pwmc_zero(c,sizeof(*c)))return 0;
    c->native_issued=1;c->native[0]=*l->frame.in.native;c->native_returned=1;if(c->native[0])return 0;
    r->arch_issued=k+1;c->issued=1;uint8_t before[32],after[32];pbhi_seal(l,&c->raw,sizeof(c->raw),before);
    int ok=l->frame.in.io.arch(l->frame.in.io.opaque,&c->raw);if(!ok)return 0;pbhi_seal(l,&c->raw,sizeof(c->raw),after);
    if(!pgcd_equal(before,after,32)||!pbhi_source(l,post)||r->arch_issued!=k+1||r->arch_returned!=k)return 0;
    c->returned=1;r->arch_returned=k+1;
    uint64_t previous=k?r->clock[k-1].raw.cpu.ticks:l->before;
    const struct pgcd_arch*a=&l->in.witness->arch[0];
    if(!pwfc_arch_stable(&a->cpu,&c->raw.cpu)||a->cpacr!=c->raw.cpacr||c->raw.cpu.daif||c->raw.cpu.group1!=1||
       c->raw.cpu.ticks<previous||c->raw.cpu.ticks<l->opening||c->raw.cpu.ticks-l->opening>PGCD_FRESH_TICKS)return 0;
    c->native_issued=3;c->native[1]=*l->frame.in.native;c->native_returned=3;return !c->native[1];
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
        q->page=page;q->issued=1;a->page=page;a->native_issued=1;a->native[0]=*l->frame.in.native;a->native_returned=1;if(a->native[0])return 0;
        uint8_t before[32],after[32];pbhi_seal(l,a,sizeof(*a),before);
        int ok=l->frame.in.page(a);if(!ok)return 0;pbhi_seal(l,a,sizeof(*a),after);
        if(!pgcd_equal(before,after,32)||!pbhi_source(l,0)||r->AT_count!=k||*count!=n||q->page!=page||q->issued!=1||q->returned||q->raw||
           a->page!=page||a->issued!=1||a->returned!=1||a->saved!=a->restored||a->par!=(UINT64_C(0xff00000000000b80)|page)||
           a->native_issued!=1||a->native_returned!=1||!pwmc_zero(a->native,sizeof(a->native)))return 0;
        a->native_issued=3;a->native[1]=*l->frame.in.native;a->native_returned=3;if(a->native[1])return 0;
        q->raw=a->par;q->returned=1;r->AT_count=k+1;*count=n+1;
        if(!pbhi_tick(l,0))return 0;
    }return 1;
}
static inline int pbhi_image(struct pbhi_live*l,unsigned image,uint64_t base)
{
    struct pwmc_irq_path*p=&l->r->path;struct pwmc_irq_image*i=&p->image[image];const struct pwmc_irq_binding*b=&pwmc_irq_bindings[image];
    if(!base||(base&4095)||base>UINT64_MAX-b->bytes||!pwmc_zero(i,sizeof(*i))||!pbhi_range(l,base,b->bytes))return 0;
    for(unsigned k=0;k<image;k++)if(pwmc_parent_overlap(base,b->bytes,p->image[k].base,p->image[k].bytes))return 0;
    if(image==1&&p->tables[1]!=base+0x30b8&&p->tables[1]!=base+0x30e0)return 0;
    i->base=base;i->bytes=b->bytes;i->attempted=1;
    if(!pbhi_pages(l,base,b->bytes,i->AT,PWMC_IRQ_PAGES,&i->AT_count)||!pwmc_irq_hash_image(i,image,0)||!pbhi_source(l,0))return 0;
    pgcd_copy(i->state,(const void*)(uintptr_t)(base+b->state),b->state_bytes);
    pgcd_copy(i->table,(const void*)(uintptr_t)p->tables[image],b->table_bytes);i->complete=1;l->table_mask|=1u<<image;return 1;
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
static __attribute__((noinline)) int pbhi_capture(struct pbhi_result*r,struct pbhr_live*caller,
    struct pbhr_result*witness,const struct pbhr_input*original,const uint8_t seal[32],const void*deferred,const void*timer)
{
    if(!r||!caller||!witness||!original||!seal||!deferred||!timer)return 0;
    struct pbhi_live live={.frame=*caller};const struct pbhr_live*frame=&live.frame;uint8_t hash[32];
    if(caller->r!=witness||caller->caller!=original)return 0;
    pbhr_seal(witness,&witness->api,sizeof(witness->api),hash);
    if(!pgcd_equal(hash,seal,32)||!pbhr_stable(caller)||!pbhi_storage(&witness->image[0],caller,witness,original,r,sizeof(*r))||
       !pbhi_storage(&witness->image[0],caller,witness,original,deferred,PBHI_DEFERRED_BYTES)||
       !pbhi_storage(&witness->image[0],caller,witness,original,timer,PBHI_TIMER_BYTES)||
       pwmc_parent_overlap((uintptr_t)r,sizeof(*r),(uintptr_t)deferred,PBHI_DEFERRED_BYTES)||
       pwmc_parent_overlap((uintptr_t)r,sizeof(*r),(uintptr_t)timer,PBHI_TIMER_BYTES)||
       pwmc_parent_overlap((uintptr_t)deferred,PBHI_DEFERRED_BYTES,(uintptr_t)timer,PBHI_TIMER_BYTES)||
       !pwmc_zero(r,sizeof(*r)))return 0;
    r->input=(struct pbhi_input){.caller=caller,.witness=witness,.original=original,.deferred=deferred,.timer=timer};pgcd_copy(r->input.service_seal,seal,32);r->live_before=*frame;
    r->opening=frame->in.opening;r->virtual_before=witness->arch[0].cpu.ticks;r->core=frame->core;r->attempted=r->unknown=1;
    live.r=r;live.in=r->input;live.core=frame->core;live.boot=frame->boot;live.opening=r->opening;live.before=r->virtual_before;
    if(!pbhi_tick(&live,0)||!pgci_verify((const void*)(uintptr_t)live.core,live.core,PGCI_IMAGE_BYTES,r->Core_hash[0],&r->hash_failed[0],&r->hash_count[0]))return pbhi_fail(r,1);
    struct pwmc_irq_path*p=&r->path;p->attempted=1;
    p->tables[0]=pwfi_le((const void*)(uintptr_t)(live.core+0x1cb80),8);p->tables[2]=pwfi_le((const void*)(uintptr_t)(live.core+0x1c8f8),8);live.rooted=1;
    if(p->tables[0]<0x2038||p->tables[2]<0x53d8||!pbhi_image(&live,0,p->tables[0]-0x2038))return pbhi_fail(r,2);
    p->tables[1]=pwfi_le(p->image[0].state+24,8);
    if(!pbhi_pages(&live,p->tables[1],40,p->table_AT,2,&p->table_AT_count))return pbhi_fail(r,3);
    pgcd_copy(p->unbound_hardware_table,(const void*)(uintptr_t)p->tables[1],40);uint64_t entry=pwfi_le(p->unbound_hardware_table,8);
    if(entry<0x1040||!pbhi_image(&live,1,entry-0x1040)||!pbhi_image(&live,2,p->tables[2]-0x53d8))return pbhi_fail(r,3);
    p->handlers=pwfi_le(p->image[1].state+24,8);p->handler_count=pwfi_le(p->image[1].state+72,8);
    if(p->handler_count<32||p->handler_count>1020)return pbhi_fail(r,4);
    for(unsigned k=0;k<3;k++)if(pwmc_parent_overlap(p->handlers,p->handler_count*8,p->image[k].base,p->image[k].bytes))return pbhi_fail(r,4);
    if(!pbhi_pages(&live,p->handlers,p->handler_count*8,p->array_AT,3,&p->array_AT_count))return pbhi_fail(r,4);
    pgcd_copy(p->handler,(const void*)(uintptr_t)p->handlers,p->handler_count*8);live.handlers=1;
    if(!pbhi_tick(&live,0))return pbhi_fail(r,5);
    if(!pgci_verify((const void*)(uintptr_t)live.core,live.core,PGCI_IMAGE_BYTES,r->Core_hash[1],&r->hash_failed[1],&r->hash_count[1]))return pbhi_fail(r,5);
    for(unsigned k=0;k<3;k++)if(!pwmc_irq_hash_image(&p->image[k],k,1))return pbhi_fail(r,5);
    struct pwmc_irq_map_view map=pbhi_map(r);
    if(!pbhi_source(&live,0)||!pwmc_irq_bindings_map(p,live.core,(uintptr_t)frame->in.system,&map))return pbhi_fail(r,5);
    p->complete=1;pwmc_irq_digest(p,p->digest);r->captured=1;ppli_sha(r,offsetof(struct pbhi_result,digest),r->digest);return 1;
}
static inline int pbhi_pre_current(const struct pbhi_result*r)
{
    struct pbhi_live live={.r=(struct pbhi_result*)r,.in=r->input,.frame=r->live_before,.core=r->core,
        .boot=r->live_before.boot,.opening=r->opening,.before=r->virtual_before,.rooted=1,.table_mask=7,.handlers=1};
    struct pwmc_irq_map_view map=pbhi_map(r);
    return pbhi_source(&live,0)&&pwmc_irq_bindings_map(&r->path,r->core,(uintptr_t)r->live_before.in.system,&map);
}
static __attribute__((noinline)) int pbhi_close(struct pbhi_result*r)
{
    struct pbhi_live live={.r=r,.in=r->input,.frame=r->live_before,.core=r->core,.boot=r->live_before.boot,
        .opening=r->opening,.before=r->virtual_before};
    if(!pbhi_tick(&live,1)||!pgci_verify((const void*)(uintptr_t)r->core,r->core,PGCI_IMAGE_BYTES,r->Core_hash[2],&r->hash_failed[2],&r->hash_count[2]))return pbhi_fail(r,6);
    r->closed=r->complete=1;r->unknown=0;ppli_sha(r,offsetof(struct pbhi_result,digest),r->digest);return 1;
}
#endif
