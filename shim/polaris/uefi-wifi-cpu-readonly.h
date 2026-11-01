/* Default OFF: independently retired normal-IRQ CPU logical-state evidence.
 * Runs before ANY private client/mask/TCS write. No observation grants a
 * hardware lease or authorizes continuation into the critical path. */
#ifndef POLARIS_UEFI_WIFI_CPU_READONLY_H
#define POLARIS_UEFI_WIFI_CPU_READONLY_H
#ifndef EFI_XNU_WIFI_CPU_RO_ADMISSION
#define EFI_XNU_WIFI_CPU_RO_ADMISSION 0
#endif
#if EFI_XNU_WIFI_CPU_RO_ADMISSION && !defined(POLARIS_EFI_TEST_QEMU)
#include "uefi-gcd-mmio-readonly.h"
#include "uefi-wifi-psci-affinity.h"
struct pwcq_source {
    struct pgcd_arch before,after;
    uint32_t hash_count,hash_failed,complete,reserved;
    uint8_t hashes[PGCI_RANGE_COUNT][32];
};
struct pwcq_call {
    uint64_t target;int64_t raw;
    uint32_t issued,returned,unknown,complete;
    struct pgcd_service_guard guard;
};
struct pwcq_result {
    uint32_t attempted,error,unknown,outstanding,retired,complete,calls,source_count;
    uint32_t issued,returned,off,on,pending,unsupported,other,logical_all_OFF;
    uint64_t native_flag_address;
    uint32_t native_reads,native[16];
    struct pgcd_result core;struct pgcd_lifetime ticket;struct pgcd_context context;
    struct pwcq_call call[7];struct pwcq_source source[14];
};
_Static_assert(sizeof(struct pwcq_result)==39344,"complete independent CPU RO RAW V1");
struct pwcq_io {void *context;int (*affinity)(void *,uint64_t,int64_t *);};
enum pwcq_error {PWCQ_OK,PWCQ_ARGUMENT,PWCQ_CONTEXT,PWCQ_SOURCE,PWCQ_FLAG,PWCQ_CALL,PWCQ_RESTORE};
static struct pwcq_result pwcq_record;
static inline int pwcq_unsafe(const struct pwcq_result *r)
{return r->unknown||r->outstanding||r->core.uncertain||r->core.outstanding||(r->attempted&&!r->retired);}
static inline int pwcq_fail(struct pwcq_result *r,unsigned error)
{if(!r->error)r->error=error;r->unknown=1;return 0;}
static inline int pwcq_flag(struct pgcd_context *c,struct pwcq_result *r)
{
    if(r->native_reads==16||!pgcd_in_self(&r->core,r->native_flag_address,4)||
       !pgcd_owned(c,0,r->native_flag_address,4))return pwcq_fail(r,PWCQ_FLAG);
    uint32_t value=*(const volatile uint32_t*)(uintptr_t)r->native_flag_address;
    r->native[r->native_reads++]=value;
    return value?pwcq_fail(r,PWCQ_FLAG):1;
}
static inline int pwcq_source_check(struct pgcd_context *c,struct pwcq_result *r)
{
    if(r->source_count==14)return pwcq_fail(r,PWCQ_SOURCE);
    struct pwcq_source *s=&r->source[r->source_count++];
    if(!pgcd_live(c,&s->before,0)||!pgcd_cached_owner_stable(c)||
       !pgcd_owned(c,0,r->core.core,PGCI_IMAGE_BYTES)||
       pwfi_le((const void*)(uintptr_t)(r->core.core+0x1b098),8)!=4||
       !pgcd_equal(r->core.DS_raw[0],(const void*)(uintptr_t)r->core.DS,168))return pwcq_fail(r,PWCQ_CONTEXT);
    if(!pgci_verify((const void*)(uintptr_t)r->core.core,r->core.core,PGCI_IMAGE_BYTES,
       s->hashes,&s->hash_failed,&s->hash_count))return pwcq_fail(r,PWCQ_SOURCE);
    if(!pgcd_live(c,&s->after,0)||s->hash_count!=5||s->hash_failed||
       !pgcd_cached_owner_stable(c)||!pwcq_flag(c,r))return pwcq_fail(r,PWCQ_CONTEXT);
    s->complete=1;return 1;
}
static inline int pwcq_run(const struct pwcq_io *io,struct pgcd_context *final,unsigned stage,
    const volatile uint32_t *native_flag,struct pwcq_result *r)
{
    if(!r)return 0;if(r->attempted)return pwcq_fail(r,PWCQ_ARGUMENT);r->attempted=1;
    if(!io||!io->affinity||stage!=2||!pgcd_final_unopened(final)||r->context.record||
       r->context.opened||r->context.finished||r->ticket.spent||r->ticket.result||r->core.attempted||
       !pgcd_bind(&r->core,&final->record->self_owner))return pwcq_fail(r,PWCQ_ARGUMENT);
    r->core.self_owner_address=final->record->self_owner_address;r->native_flag_address=(uintptr_t)native_flag;
    if(!pgcd_in_self(&r->core,(uintptr_t)r,sizeof(*r)))return pwcq_fail(r,PWCQ_ARGUMENT);
    struct pgcd_context *c=&r->context;c->io=final->io;c->record=&r->core;c->ticket=&r->ticket;c->stage=2;
    if(!pgcd_open(c)||!pgcd_owned(c,0,(uintptr_t)r,sizeof(*r))||r->core.TPL_initial!=4||
       !pwcq_flag(c,r))return pwcq_fail(r,PWCQ_CONTEXT);
    for(unsigned k=0;k<7;k++){
        struct pwcq_call *q=&r->call[k];q->target=0x100u+0x100u*k;
        if(!pwcq_source_check(c,r)||!pgcd_service_enter(c,&q->guard))return pwcq_fail(r,PWCQ_SOURCE);
        q->issued=q->unknown=1;r->issued|=1u<<k;r->outstanding=k+1;c->io.order(c->io.opaque);
        int returned=io->affinity(io->context,q->target,&q->raw);q->returned=returned?1:0;
        if(returned)r->returned|=1u<<k;c->io.order(c->io.opaque);
        if(!pgcd_service_leave(c,&q->guard,returned))return pwcq_fail(r,PWCQ_CALL);
        if(q->guard.entered!=1||q->guard.left!=1||q->guard.foreign_returned!=1||q->guard.unknown||
           q->guard.fp.saved!=1||q->guard.fp.restored!=1||q->guard.fp.cpacr_before!=0x300000||
           q->guard.fp.cpacr_after!=q->guard.fp.cpacr_before||q->guard.TPL_before!=4||q->guard.TPL_after!=4||
           !pwcq_source_check(c,r))return pwcq_fail(r,PWCQ_CONTEXT);
        if(q->raw==1)r->off|=1u<<k;else if(q->raw==0)r->on|=1u<<k;
        else if(q->raw==2)r->pending|=1u<<k;else if(q->raw==-1)r->unsupported|=1u<<k;else r->other|=1u<<k;
        q->unknown=0;q->complete=1;r->outstanding=0;r->calls=k+1;c->io.order(c->io.opaque);
    }
    /* Raw semantic results never authorize critical work, even all OFF.
     * Close independently with two actual guarded maps and exact source,
     * namespace/config/owner/lock before any final Clock allocation. */
    if(!pgcd_map_read(c,1)||!pgcd_snapshot(c,1)||!pgcd_live(c,&r->core.after,1)||
       !pgcd_cached_owner_stable(c)||r->core.map[0].key!=r->core.map[1].key||
       r->core.map[0].bytes!=r->core.map[1].bytes||r->core.map[0].stride!=r->core.map[1].stride||
       !pgcd_equal(r->core.maps[0],r->core.maps[1],r->core.map[0].bytes)||
       !pgcd_equal(r->core.GCD_lock_raw[0],r->core.GCD_lock_raw[1],24)||
       pwfi_le((const void*)(uintptr_t)(r->core.core+0x1b098),8)!=4||!pwcq_flag(c,r)||
       r->core.pre_mask||r->core.post_mask||r->core.prestart_count||!pgcd_final_unopened(final))return pwcq_fail(r,PWCQ_RESTORE);
    r->logical_all_OFF=r->off==127;r->core.TPL_final=4;r->core.phase=3;c->finished=1;
    r->complete=r->retired=1;c->io.order(c->io.opaque);return 1;
}
static inline int pwcq_parent_unsafe(void){return pwcq_unsafe(&pwcq_record);}
#define PWCQ_RAW_BYTES sizeof(pwcq_record)
#else
static inline int pwcq_parent_unsafe(void){return 0;}
#define PWCQ_RAW_BYTES 0u
#endif
#endif
