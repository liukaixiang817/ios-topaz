/* Reuse the existing deferred-queue reader at the EXISTING FreePool leaf.
 * Empty pre/post snapshots refuse known dispatch work; they do not exclude
 * an intervening enqueue/dispatch/ABA or grant future IRQ/wholecall time. */
#ifndef POLARIS_UEFI_WIFI_CACHE_DISPATCH_H
#define POLARIS_UEFI_WIFI_CACHE_DISPATCH_H
#include "uefi-wifi-cache-release.h"
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
_Static_assert(sizeof(struct pbhr_live)==360&&sizeof(struct pbhd_input)==104&&sizeof(struct pbhd_sample)==464&&sizeof(struct pbhd_result)==1488,"separate complete pre/post dispatch ABI");
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
static __attribute__((noinline)) int pbhd_call(struct pbhd_result*r,struct pbhr_live*caller,
    struct pbhr_result*witness,const struct pbhr_input*original_input,const uint8_t expected[32])
{
    if(!r||!caller||!witness||!original_input||!expected||!pwmc_zero(r,sizeof(*r)))return 0;
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
       !pwmc_parent_in_image(&w->image[0],(uintptr_t)r,sizeof(*r)))return pbhd_fail(r,1);
    struct pbhd_input in={.live=caller,.witness=w,.core=live.core,.boot=live.boot,.entry=live.entry,
        .handles=w->before_target.input.handles,.native=live.in.native,.release=live.in.release,.opaque=live.in.io.opaque};
    pgcd_copy(in.witness_seal,expected,32);r->input=in;r->live_before=live;
    if(!pbhd_stable(r,&in,&live)||!pbhd_native(r,&in,0)||!pbhd_sample(r,&in,0)||
       !pbhd_stable(r,&in,&live)||!pbhr_stable(caller)||!pbhd_native(r,&in,1))return pbhd_fail(r,2);
    r->leaf_issued=1;uint8_t before[32],after[32];ppli_sha(r,sizeof(*r),before);
    int ok=in.release(in.opaque,live.in.system,in.entry,in.handles,&w->api);
    ppli_sha(r,sizeof(*r),after);r->leaf_returned=1;
    /* No pre-call target/graph comparison after the service, including on
     * failure. The enclosing frame's API output is its only allowed change. */
    if(!pgcd_equal(before,after,32)||!pbhd_stable(r,&in,&live))return pbhd_fail(r,3);
    r->api=w->api;
    if(!ok||r->api.issued!=1||r->api.returned!=1||r->api.status||!pbhd_native(r,&in,2))return pbhd_fail(r,3);
    if(!pbhd_sample(r,&in,1)||!pbhd_stable(r,&in,&live)||!pbhd_native(r,&in,3))return pbhd_fail(r,4);
    r->unknown=0;r->complete=1;ppli_sha(r,offsetof(struct pbhd_result,digest),r->digest);return 1;
}
#endif
