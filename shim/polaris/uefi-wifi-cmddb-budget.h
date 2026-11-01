/* Default-OFF work admission for the complete CmdDb capture. This independent
 * RO context is fully retired BEFORE a private client is created. It never
 * renews an old ticket or grants memory, CPU, rail or DMA ownership. A measured
 * estimate can reject work; the original private 200ms gate still decides
 * actual execution. Original images are read in full, never digest-cached. */
#ifndef POLARIS_UEFI_WIFI_CMDDB_BUDGET_H
#define POLARIS_UEFI_WIFI_CMDDB_BUDGET_H
#ifndef EFI_XNU_WIFI_CMDDB_BUDGET_ADMISSION
#define EFI_XNU_WIFI_CMDDB_BUDGET_ADMISSION 0
#endif
#if EFI_XNU_WIFI_CMDDB_BUDGET_ADMISSION && !defined(POLARIS_EFI_TEST_QEMU)
#if !EFI_XNU_WIFI_CMDDB_CAPTURE_ONLY || !EFI_XNU_WIFI_GCD_NAMESPACE_RO_AVAILABLE || EFI_XNU_WIFI_CMDDB_FIRST_NODE_STOP
#error Complete-capture work admission requires the distinct full bounded RO scope
#endif
#define PWBD_SAMPLES 3u
/* 74 namespace/page checkpoints + open/reader/private-source checkpoints.
 * Every runtime check remains; this static count only makes the rejection
 * estimate conservative. The independent final Clock/GCD starts later. */
#define PWBD_CORE_CHECKPOINTS 80u
#define PWBD_RESERVE_TICKS UINT64_C(480000) /* 25ms at admitted19.2MHz */
#define PWBD_PLAN_TICKS UINT64_C(2400000)   /* 125ms, inside unchanged200ms */
struct pwbd_sample {
    struct pgcd_arch before,after;
    uint32_t hash_count,hash_failed;
    uint8_t hashes[PGCI_RANGE_COUNT][32];
    uint64_t ticks;
};
struct pwbd_result {
    uint32_t attempted,error,unknown,retired,admitted,declined,samples,reserved;
    uint64_t maximum_ticks,estimate_ticks;
    struct pgcd_result core;
    struct pgcd_lifetime ticket;
    struct pgcd_context context;
    struct pwbd_sample sample[PWBD_SAMPLES];
};
_Static_assert(sizeof(struct pwbd_sample)==384,"complete work-admission hash/timing sample");
_Static_assert(sizeof(struct pwbd_result)==31552,"complete work-admission independent raw V1");
enum pwbd_error {PWBD_OK,PWBD_ARGUMENT,PWBD_CONTEXT,PWBD_SOURCE,PWBD_RESTORE,PWBD_CLOCK};
static struct pwbd_result pwbd_record;
static inline int pwbd_unsafe(const struct pwbd_result *r)
{return r->unknown||r->core.uncertain||r->core.outstanding||(r->attempted&&!r->retired);}
static inline int pwbd_fail(struct pwbd_result *r,unsigned e)
{if(!r->error)r->error=e;r->unknown=1;paic_actual_order(0);return 0;}
static inline int pwbd_run(struct pgcd_context *final,unsigned stage,struct pwbd_result *r)
{
    if(!r)return 0;
    if(r->attempted)return pwbd_fail(r,PWBD_ARGUMENT);
    r->attempted=1;
    if(stage!=2||!pwrcl_final_unopened(final)||r->context.record||r->context.opened||
       r->context.finished||r->ticket.spent||r->ticket.result||r->core.attempted||
       !pgcd_bind(&r->core,&final->record->self_owner))return pwbd_fail(r,PWBD_ARGUMENT);
    r->core.self_owner_address=final->record->self_owner_address;
    if(!pgcd_in_self(&r->core,(uintptr_t)r,sizeof(*r)))return pwbd_fail(r,PWBD_ARGUMENT);
    struct pgcd_context *c=&r->context;
    c->io=final->io;c->record=&r->core;c->ticket=&r->ticket;c->stage=2;
    if(!pgcd_open(c)||!pwrph_context_ready(c)||!pgcd_owned(c,0,(uintptr_t)r,sizeof(*r))||
       r->core.TPL_initial!=4)return pwbd_fail(r,PWBD_CONTEXT);
    for(unsigned k=0;k<PWBD_SAMPLES;k++){
        struct pwbd_sample *s=&r->sample[k];
        if(!pgcd_live(c,&s->before,0)||!pgcd_cached_owner_stable(c)||
           !pgcd_owned(c,0,r->core.core,PGCI_IMAGE_BYTES)||
           pwfi_le((const void*)(uintptr_t)(r->core.core+0x1b098),8)!=4||
           !pgcd_equal(r->core.DS_raw[0],(const void*)(uintptr_t)r->core.DS,168))return pwbd_fail(r,PWBD_CONTEXT);
        if(!pgci_verify((const void*)(uintptr_t)r->core.core,r->core.core,PGCI_IMAGE_BYTES,
           s->hashes,&s->hash_failed,&s->hash_count))return pwbd_fail(r,PWBD_SOURCE);
        if(!pgcd_live(c,&s->after,0)||s->hash_count!=5||s->hash_failed||
           !pgcd_cached_owner_stable(c)||
           pwfi_le((const void*)(uintptr_t)(r->core.core+0x1b098),8)!=4||
           !pgcd_equal(r->core.DS_raw[0],(const void*)(uintptr_t)r->core.DS,168))return pwbd_fail(r,PWBD_CONTEXT);
        if(s->after.cpu.ticks<=s->before.cpu.ticks)return pwbd_fail(r,PWBD_CLOCK);
        s->ticks=s->after.cpu.ticks-s->before.cpu.ticks;
        if(s->ticks>r->maximum_ticks)r->maximum_ticks=s->ticks;
        r->samples=k+1;
    }
    /* Complete this RO-only context with its own second guarded map and full
     * source/config snapshot. No original GCD getter or pool/client API. This
     * is deliberately NOT pgcd_finish's eight-query lifecycle/phase2. */
    if(r->core.pre_mask||r->core.post_mask||r->core.prestart_count||
       !pwrph_context_ready(c)||!pgcd_map_read(c,1)||!pgcd_snapshot(c,1)||
       !pgcd_live(c,&r->core.after,1)||!pgcd_cached_owner_stable(c)||
       r->core.map[0].key!=r->core.map[1].key||r->core.map[0].bytes!=r->core.map[1].bytes||
       r->core.map[0].stride!=r->core.map[1].stride||
       !pgcd_equal(r->core.maps[0],r->core.maps[1],r->core.map[0].bytes)||
       !pgcd_equal(r->core.GCD_lock_raw[0],r->core.GCD_lock_raw[1],24)||
       pwfi_le((const void*)(uintptr_t)(r->core.core+0x1b098),8)!=4||
       !pwrcl_final_unopened(final))return pwbd_fail(r,PWBD_RESTORE);
    r->core.TPL_final=4;r->core.phase=3;c->finished=1;
    if(r->maximum_ticks>(UINT64_MAX-PWBD_RESERVE_TICKS)/PWBD_CORE_CHECKPOINTS)
        return pwbd_fail(r,PWBD_CLOCK);
    r->estimate_ticks=r->maximum_ticks*PWBD_CORE_CHECKPOINTS+PWBD_RESERVE_TICKS;
    r->admitted=r->estimate_ticks<=PWBD_PLAN_TICKS;
    r->declined=!r->admitted;r->retired=1;paic_actual_order(0);return 1;
}
static inline int pwbd_parent_unsafe(void){return pwbd_unsafe(&pwbd_record);}
#define PWBD_RAW_BYTES sizeof(pwbd_record)
#else
static inline int pwbd_parent_unsafe(void){return 0;}
#define PWBD_RAW_BYTES 0u
#endif
#endif
