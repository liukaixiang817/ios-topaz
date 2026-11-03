/* Reuse the existing deferred-queue reader at the EXISTING FreePool leaf.
 * Empty pre/post snapshots refuse known dispatch work; they do not exclude
 * an intervening enqueue/dispatch/ABA or grant future IRQ/wholecall time. */
#ifndef POLARIS_UEFI_WIFI_CACHE_DISPATCH_H
#define POLARIS_UEFI_WIFI_CACHE_DISPATCH_H
#include "uefi-wifi-cache-provider.h"
struct pbhd_input {
    struct pbhr_live*live;struct pbhr_result*witness;uint64_t core,boot,entry,handles;
    const volatile uint32_t*native;int(*release)(void*,struct efi_system*,uint64_t,uint64_t,struct pbhr_api*);
    void*opaque;uint8_t witness_seal[32];
};
struct pbhd_sample {
    uint64_t pending,counter,head[27][2];uint32_t attempted,complete,head_count,reserved;
};
struct pbhd_result {
    struct pbhd_input input;struct pbhr_live live_before;struct pbhd_sample sample[2];
    uint32_t native[4],native_issued,native_returned;
    uint32_t attempted,complete,unknown,error,leaf_issued,leaf_returned;
    struct pbhr_api api;uint8_t digest[32];
};
/* Separate current-register input, not a provider-image/IRQ/temporal lease.
 * Keep the original1488B queue record and every older RAW schema unchanged. */
struct pbhd_timer_result {
    struct pbhd_input input;struct pwmc_irq_regs regs[2];
    uint64_t opening,virtual_before;uint32_t native[4];
    uint32_t attempted,complete,unknown,error,issued,returned,native_issued,native_returned;
    uint8_t digest[32];
};
_Static_assert(sizeof(struct pbhd_timer_result)==PBHI_TIMER_BYTES&&offsetof(struct pbhd_timer_result,regs)==104&&offsetof(struct pbhd_timer_result,digest)==280,"separate current physical-timer input ABI");
_Static_assert(sizeof(struct pbhr_live)==360&&sizeof(struct pbhd_input)==104&&sizeof(struct pbhd_sample)==464&&sizeof(struct pbhd_result)==PBHI_DEFERRED_BYTES,"separate complete pre/post dispatch ABI");
_Static_assert(offsetof(struct pbhd_result,sample)==464&&offsetof(struct pbhd_result,api)==1440&&offsetof(struct pbhd_result,digest)==1456,"independent dispatch decoder offsets");
static inline int pbhd_fail(struct pbhd_result*r,unsigned error)
{if(!r->error)r->error=error;r->unknown=1;return 0;}
static inline int pbhd_stable(const struct pbhd_result*r,const struct pbhd_input*in,const struct pbhr_live*live)
{
    uint8_t seal[32];
    /* Check the live stack frame before following any of its pointers. */
    if(!pgcd_equal(&r->input,in,sizeof(*in))||!pgcd_equal(&r->live_before,live,sizeof(*live))||
       !pgcd_equal(in->live,live,sizeof(*live)))return 0;
    pbhr_seal(in->witness,&in->witness->api,sizeof(in->witness->api),seal);
    if(!pgcd_equal(seal,in->witness_seal,32)||
       (uintptr_t)live->in.system->boot!=in->boot||
       !pgcd_equal(live->in.system->boot,in->witness->BS[0],PWMC_BS_BYTES)||
       !pgcd_equal(live->in.image,&in->witness->image[0],sizeof(in->witness->image[0])))return 0;
    return 1;
}
static inline int pbhd_native(struct pbhd_result*r,const struct pbhd_input*in,unsigned slot)
{
    if(slot>=4)return 0;r->native_issued|=1u<<slot;r->native[slot]=*in->native;r->native_returned|=1u<<slot;
    return !r->native[slot];
}
static inline int pbhd_sample(struct pbhd_result*r,const struct pbhd_input*in,unsigned slot)
{
    struct pbhd_sample*q=&r->sample[slot];q->attempted=1;
    if(!pwmc_deferred_read(in->core,5,27,&q->pending,&q->counter,q->head,&q->head_count))return 0;
    if(pwfi_le((const void*)(uintptr_t)(in->core+0x1dbc0),8)!=q->pending)return 0;
    for(unsigned k=0;k<27;k++)if(!pgcd_equal(q->head[k],(const void*)(uintptr_t)(in->core+0x1c928+16*(k+5)),16))return 0;
    q->complete=1;return 1;
}
#if defined(POLARIS_WIFI_CACHE_TIMER_SOFTWARE_PEER)
#if !__STDC_HOSTED__
#error Software timer leaves must never enter physical firmware
#endif
static int pbhd_test_timer_regs(struct pwmc_irq_regs*,unsigned);
#endif
static inline void pbhd_timer_seal(const struct pbhd_timer_result*t,const void*skip,size_t bytes,uint8_t out[32])
{struct pwfi_sha256 h;pwfi_init(&h);pbgi_hash_part(&h,t,sizeof(*t),skip,bytes);pwfi_final(&h,out);}
static inline int pbhd_timer_sample(struct pbhd_result*r,struct pbhd_timer_result*t,
    const struct pbhd_input*in,const struct pbhr_live*live,unsigned slot,
    const struct pbhi_result*p,const uint8_t provider_seal[32])
{
    uint8_t provider_now[32];ppli_sha(p,sizeof(*p),provider_now);
    if(!pgcd_equal(provider_now,provider_seal,32))return 0;
    if(!slot&&!pbhi_pre_current(p))return 0;
    if(slot>1||!pbhd_stable(r,in,live)||!pgcd_equal(&t->input,in,sizeof(*in))||
       t->opening!=in->witness->input.opening||t->virtual_before!=in->witness->arch[0].cpu.ticks||
       !pgcd_equal(&r->api,&in->witness->api,sizeof(r->api)))return 0;
    struct pwmc_irq_regs*q=&t->regs[slot];unsigned first=2*slot;
    if(!pwmc_zero(q,sizeof(*q))||t->issued!=slot||t->returned!=slot||
       !pwfc_arch_admitted(&in->witness->arch[0].cpu)||((in->witness->arch[0].cpacr>>20)&3)!=3||
       !t->opening||t->virtual_before<t->opening||t->virtual_before-t->opening>PGCD_FRESH_TICKS)return 0;
    t->native_issued|=1u<<first;t->native[first]=*in->native;t->native_returned|=1u<<first;
    if(t->native[first])return 0;t->issued|=1u<<slot;
    uint8_t before[32],after[32],queue_before[32],queue_after[32];
    pbhd_timer_seal(t,q,sizeof(*q),before);ppli_sha(r,sizeof(*r),queue_before);
#if defined(POLARIS_WIFI_CACHE_TIMER_SOFTWARE_PEER)
    int ok=pbhd_test_timer_regs(q,slot);
#else
    int ok=pwmc_irq_regs_native(q);
#endif
    pbhd_timer_seal(t,q,sizeof(*q),after);ppli_sha(r,sizeof(*r),queue_after);ppli_sha(p,sizeof(*p),provider_now);t->returned|=1u<<slot;
    /* Close every record/control input before the next native RAM read.
     * No post-service target, graph, table or VBAR pointer is dereferenced. */
    if(!ok||!pgcd_equal(before,after,32)||!pgcd_equal(queue_before,queue_after,32)||!pgcd_equal(provider_now,provider_seal,32)||
       !pbhd_stable(r,in,live)||!pgcd_equal(&r->api,&in->witness->api,sizeof(r->api))||
       q->issued!=63||q->returned!=63||q->el!=4||q->frequency!=19200000||
       q->ctl>7||(q->ctl&3)!=1||!q->ticks||q->vbar!=p->path.image[2].base+0x4000||
       (slot&&(q->ticks<t->regs[0].ticks||q->vbar!=t->regs[0].vbar)))return 0;
    if(!slot&&!pbhi_pre_current(p))return 0;
    t->native_issued|=1u<<(first+1);t->native[first+1]=*in->native;t->native_returned|=1u<<(first+1);
    return !t->native[first+1];
}
static __attribute__((noinline)) int pbhd_call(struct pbhd_result*r,struct pbhd_timer_result*t,struct pbhi_result*p,struct pbhr_live*caller,
    struct pbhr_result*witness,const struct pbhr_input*original_input,const uint8_t expected[32])
{
    if(!r||!t||!p||!caller||!witness||!original_input||!expected||!pwmc_zero(r,sizeof(*r)))return 0;
    r->attempted=r->unknown=1;r->api.status=UINT64_MAX;
    /* caller is the actual enclosing pbhr_call stack frame, never a context
     * reconstructed from a dump or a fabricated opened/owner/ticket flag. */
    struct pbhr_live live=*caller;r->live_before=live;
    r->input.live=caller;r->input.witness=witness;pgcd_copy(r->input.witness_seal,expected,32);
    if(caller->r!=witness||caller->caller!=original_input)return pbhd_fail(r,1);
    struct pbhr_result*w=witness;uint8_t seal[32];
    pbhr_seal(w,&w->api,sizeof(w->api),seal);
    if(!pgcd_equal(seal,expected,32)||!pbhr_stable(caller)||w->attempted!=1||w->complete||w->error||w->unknown!=1||
       w->issued!=1||w->returned||w->api.issued||w->api.returned||w->api.status!=UINT64_MAX||
       w->fp_save_returned!=1||w->fp_restore_issued||w->native_issued!=15||w->native_returned!=15||
       !pwmc_parent_in_image(&w->image[0],(uintptr_t)r,sizeof(*r))||
       ((uintptr_t)t&7)||!pwmc_parent_in_image(&w->image[0],(uintptr_t)t,sizeof(*t))||
       pwmc_parent_overlap((uintptr_t)t,sizeof(*t),(uintptr_t)r,sizeof(*r))||
       pwmc_parent_overlap((uintptr_t)t,sizeof(*t),(uintptr_t)w,sizeof(*w))||
       pwmc_parent_overlap((uintptr_t)t,sizeof(*t),(uintptr_t)caller,sizeof(*caller))||
       pwmc_parent_overlap((uintptr_t)t,sizeof(*t),(uintptr_t)original_input,sizeof(*original_input))||
       pwmc_parent_overlap((uintptr_t)t,sizeof(*t),(uintptr_t)live.in.allocation,sizeof(*live.in.allocation))||
       pwmc_parent_overlap((uintptr_t)t,sizeof(*t),(uintptr_t)live.in.seed,sizeof(*live.in.seed))||
       pwmc_parent_overlap((uintptr_t)t,sizeof(*t),(uintptr_t)live.in.images,sizeof(*live.in.images))||
       pwmc_parent_overlap((uintptr_t)t,sizeof(*t),(uintptr_t)live.in.native,4)||
       pwmc_parent_overlap((uintptr_t)t,sizeof(*t),(uintptr_t)live.in.system,sizeof(*live.in.system))||
       pwmc_parent_overlap((uintptr_t)t,sizeof(*t),(uintptr_t)live.in.image,sizeof(*live.in.image))||
       !pbhi_storage(&w->image[0],caller,w,original_input,p,sizeof(*p))||
       pwmc_parent_overlap((uintptr_t)p,sizeof(*p),(uintptr_t)r,sizeof(*r))||
       pwmc_parent_overlap((uintptr_t)p,sizeof(*p),(uintptr_t)t,sizeof(*t))||
       !pwmc_zero(p,sizeof(*p))||!pwmc_zero(t,sizeof(*t)))return pbhd_fail(r,1);
    struct pbhd_input in={.live=caller,.witness=w,.core=live.core,.boot=live.boot,.entry=live.entry,
        .handles=w->before_target.input.handles,.native=live.in.native,.release=live.in.release,.opaque=live.in.io.opaque};
    pgcd_copy(in.witness_seal,expected,32);r->input=in;r->live_before=live;
    t->input=in;t->opening=w->input.opening;t->virtual_before=w->arch[0].cpu.ticks;t->attempted=t->unknown=1;
    uint8_t queue_saved[32],timer_saved[32],now[32],provider_saved[32];
    ppli_sha(r,sizeof(*r),queue_saved);ppli_sha(t,sizeof(*t),timer_saved);
    int captured=pbhi_capture(p,caller,w,original_input,expected,r,t);
    ppli_sha(r,sizeof(*r),now);if(!pgcd_equal(now,queue_saved,32))return pbhd_fail(r,7);
    ppli_sha(t,sizeof(*t),now);if(!pgcd_equal(now,timer_saved,32)||!captured||
       !pbhi_retained(p,caller,w,original_input,expected,r,t))return pbhd_fail(r,7);
    ppli_sha(p,sizeof(*p),provider_saved);
    if(!pbhd_stable(r,&in,&live)||!pbhd_native(r,&in,0)||!pbhd_sample(r,&in,0)||
       !pbhd_stable(r,&in,&live)||!pbhr_stable(caller)||!pbhd_native(r,&in,1))return pbhd_fail(r,2);
    if(!pbhd_timer_sample(r,t,&in,&live,0,p,provider_saved)){if(!t->error)t->error=1;return pbhd_fail(r,5);}
    r->leaf_issued=1;uint8_t before[32],after[32],timer_before[32],timer_after[32];ppli_sha(r,sizeof(*r),before);ppli_sha(t,sizeof(*t),timer_before);
    int ok=in.release(in.opaque,live.in.system,in.entry,in.handles,&w->api);
    ppli_sha(r,sizeof(*r),after);ppli_sha(t,sizeof(*t),timer_after);ppli_sha(p,sizeof(*p),now);r->leaf_returned=1;
    /* No pre-call target/graph comparison after the service, including on
     * failure. The enclosing frame's API output is its only allowed change. */
    if(!pgcd_equal(before,after,32)||!pgcd_equal(timer_before,timer_after,32)||!pgcd_equal(provider_saved,now,32)||!pbhd_stable(r,&in,&live))return pbhd_fail(r,3);
    r->api=w->api;
    if(!ok||r->api.issued!=1||r->api.returned!=1||r->api.status||!pbhd_native(r,&in,2))return pbhd_fail(r,3);
    /* Only the retained original Core, source/control and virtual arch are
     * read on close. No provider, released target or GCD pointer is followed. */
    ppli_sha(r,sizeof(*r),queue_saved);ppli_sha(t,sizeof(*t),timer_saved);
    int closed=pbhi_close(p);ppli_sha(r,sizeof(*r),now);
    if(!pgcd_equal(now,queue_saved,32))return pbhd_fail(r,8);
    ppli_sha(t,sizeof(*t),now);if(!closed||!pgcd_equal(now,timer_saved,32)||!pbhd_stable(r,&in,&live))return pbhd_fail(r,8);
    ppli_sha(p,sizeof(*p),provider_saved);
    if(!pbhd_sample(r,&in,1)||!pbhd_stable(r,&in,&live)||!pbhd_native(r,&in,3))return pbhd_fail(r,4);
    if(!pbhd_timer_sample(r,t,&in,&live,1,p,provider_saved)){if(!t->error)t->error=2;return pbhd_fail(r,6);}
    t->unknown=0;t->complete=1;ppli_sha(t,offsetof(struct pbhd_timer_result,digest),t->digest);
    r->unknown=0;r->complete=1;ppli_sha(r,offsetof(struct pbhd_result,digest),r->digest);return 1;
}
#endif
