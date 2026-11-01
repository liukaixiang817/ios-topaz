/* Default OFF: independently retired CPU logical-state evidence. Normal-only
 * and distinct normal+masked/exact-restore scopes have separate raw formats.
 * Both precede any private client/TCS and cannot grant a hardware lease. */
#ifndef POLARIS_UEFI_WIFI_CPU_READONLY_H
#define POLARIS_UEFI_WIFI_CPU_READONLY_H
#ifndef EFI_XNU_WIFI_CPU_RO_ADMISSION
#define EFI_XNU_WIFI_CPU_RO_ADMISSION 0
#endif
#ifndef EFI_XNU_WIFI_CPU_MASKED_RO_ADMISSION
#define EFI_XNU_WIFI_CPU_MASKED_RO_ADMISSION 0
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
#if EFI_XNU_WIFI_CPU_MASKED_RO_ADMISSION
#include "uefi-wifi-cpu-local-mask.h"
struct pwcq_masked_source {
    struct pwrpc_context before,after;
    uint32_t hash_count,hash_failed,complete,reserved;uint8_t hashes[PGCI_RANGE_COUNT][32];
};
struct pwcq_masked_result {
    uint32_t attempted,declined,held,restored,complete,calls,issued,returned,unknown,source_count;
    uint64_t last_ticks;struct pwrpc_transition mask,restore;
    struct pwrpc_context last;struct pwrpc_masked_psci call[7];
    struct pwcq_masked_source source[15];struct pwcq_source after_restore;
};
#define PWCQ_NATIVE_CAPACITY 64u
#else
#define PWCQ_NATIVE_CAPACITY 16u
#endif
struct pwcq_result {
    uint32_t attempted,error,unknown,outstanding,retired,complete,calls,source_count;
    uint32_t issued,returned,off,on,pending,unsupported,other,logical_all_OFF;
    uint64_t native_flag_address;
    uint32_t native_reads,native[PWCQ_NATIVE_CAPACITY];
    struct pgcd_result core;struct pgcd_lifetime ticket;struct pgcd_context context;
    struct pwcq_call call[7];struct pwcq_source source[14];
#if EFI_XNU_WIFI_CPU_MASKED_RO_ADMISSION
    struct pwcq_masked_result masked;
#endif
};
#if EFI_XNU_WIFI_CPU_MASKED_RO_ADMISSION
_Static_assert(sizeof(struct pwcq_result)==50800,"complete CPU masked RO RAW V1");
#else
_Static_assert(sizeof(struct pwcq_result)==39344,"complete independent CPU RO RAW V1");
#endif
struct pwcq_io {void *context;int (*affinity)(void *,uint64_t,int64_t *);
#if EFI_XNU_WIFI_CPU_MASKED_RO_ADMISSION
    int (*mask)(void *,struct pwrpc_transition *);int (*restore)(void *,struct pwrpc_transition *);
#endif
};
enum pwcq_error {PWCQ_OK,PWCQ_ARGUMENT,PWCQ_CONTEXT,PWCQ_SOURCE,PWCQ_FLAG,PWCQ_CALL,PWCQ_RESTORE};
static struct pwcq_result pwcq_record;
static inline int pwcq_unsafe(const struct pwcq_result *r)
{return
#if EFI_XNU_WIFI_CPU_MASKED_RO_ADMISSION
 r->masked.held||r->masked.unknown||
#endif
 r->unknown||r->outstanding||r->core.uncertain||r->core.outstanding||(r->attempted&&!r->retired);}
static inline int pwcq_fail(struct pwcq_result *r,unsigned error)
{if(!r->error)r->error=error;r->unknown=1;return 0;}
static inline int pwcq_flag(struct pgcd_context *c,struct pwcq_result *r)
{
    if(r->native_reads>=PWCQ_NATIVE_CAPACITY||!pgcd_in_self(&r->core,r->native_flag_address,4)||
       !pgcd_owned(c,0,r->native_flag_address,4))return pwcq_fail(r,PWCQ_FLAG);
    uint32_t value=*(const volatile uint32_t*)(uintptr_t)r->native_flag_address;
    r->native[r->native_reads++]=value;
    return value?pwcq_fail(r,PWCQ_FLAG):1;
}
static inline int pwcq_source_into(struct pgcd_context *c,struct pwcq_result *r,struct pwcq_source *s)
{
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
static inline int pwcq_source_check(struct pgcd_context *c,struct pwcq_result *r)
{
    if(r->source_count==14)return pwcq_fail(r,PWCQ_SOURCE);
    return pwcq_source_into(c,r,&r->source[r->source_count++]);
}
#if EFI_XNU_WIFI_CPU_MASKED_RO_ADMISSION
/* Own register/RAM/AT readers only. The ordinary pgcd_live/service guard
 * remains DAIF0/G1-on; no original service may run in this local interval. */
static inline int pwcq_masked_live(struct pgcd_context *c,struct pgcd_context *final,
    struct pwcq_result *r,struct pwrpc_context *out)
{
    struct pwcq_masked_result *m=&r->masked;*out=(struct pwrpc_context){0};
    if(r->error||r->unknown||!m->held||!c->opened||c->finished||c->stage!=2||c->record!=&r->core||
       c->ticket!=&r->ticket||r->ticket.spent!=1||r->ticket.result!=(uintptr_t)&r->core||
       r->core.phase!=1||r->core.error||pgcd_uncertain(c)||!pgcd_final_unopened(final)||!c->io.arch||
       !c->io.arch(c->io.opaque,&out->arch))return pwcq_fail(r,PWCQ_CONTEXT);
    const struct pgcd_arch *n=&r->core.before;struct pgcd_arch *a=&out->arch;
    const struct pwfc_arch *x=&a->cpu,*v=&n->cpu;
    if(!pgcd_owned(c,0,r->core.core+0x1b098,8))return pwcq_fail(r,PWCQ_SOURCE);
    out->TPL=pwfi_le((const void*)(uintptr_t)(r->core.core+0x1b098),8);
    out->boot=(uintptr_t)c->io.system->boot;out->tables=(uintptr_t)c->io.system->tables;out->count=c->io.system->table_count;
    if(x->el!=4||(x->mpidr&0xffffff)||x->frequency!=19200000||x->el!=v->el||x->mpidr!=v->mpidr||
       x->ttbr0!=v->ttbr0||x->ttbr1!=v->ttbr1||x->tcr!=v->tcr||x->sctlr!=v->sctlr||x->mair!=v->mair||
       x->sre!=v->sre||x->daif!=0xc0||x->group1||a->cpacr!=n->cpacr||
       x->ticks<m->last_ticks||x->ticks<v->ticks||x->ticks-v->ticks>PGCD_FRESH_TICKS||
       out->TPL!=4||out->TPL!=r->core.TPL_initial||out->boot!=r->core.core+0x1b800||
       out->tables!=r->core.config_pointer||out->count!=r->core.config_count||
       !pgcd_equal(r->core.DS_raw[0],(const void*)(uintptr_t)r->core.DS,168)||
       !pgcd_cached_owner_stable(c))return pwcq_fail(r,PWCQ_CONTEXT);
    m->last_ticks=x->ticks;out->complete=1;m->last=*out;return 1;
}
static inline int pwcq_masked_source(struct pgcd_context *c,struct pgcd_context *final,struct pwcq_result *r)
{
    struct pwcq_masked_result *m=&r->masked;
    if(m->source_count>=15)return pwcq_fail(r,PWCQ_SOURCE);
    struct pwcq_masked_source *s=&m->source[m->source_count++];
    if(!pwcq_masked_live(c,final,r,&s->before)||!pgcd_owned(c,0,r->core.core,PGCI_IMAGE_BYTES)||
       !pgci_verify((const void*)(uintptr_t)r->core.core,r->core.core,PGCI_IMAGE_BYTES,
          s->hashes,&s->hash_failed,&s->hash_count)||
       !pwcq_masked_live(c,final,r,&s->after)||s->hash_count!=5||s->hash_failed||!pwcq_flag(c,r))
        return pwcq_fail(r,PWCQ_SOURCE);
    s->complete=1;return 1;
}
static inline int pwcq_transition_exact(const struct pwrpc_transition *t,unsigned restore)
{
    return t->returned==1&&!t->precondition_error&&t->daif_written==1&&t->daif_observed==1&&
       t->group_written==1&&t->group_observed==1&&t->target_daif==(restore?0:0xc0)&&
       t->target_group==(restore?1:0)&&t->daif_before==(restore?0xc0:0)&&
       t->group_before==(restore?0:1)&&t->daif_read==t->target_daif&&t->group_read==t->target_group;
}
static inline int pwcq_masked_run(const struct pwcq_io *io,struct pgcd_context *c,
    struct pgcd_context *final,struct pwcq_result *r)
{
    struct pwcq_masked_result *m=&r->masked;
    if(m->attempted||!io->mask||!io->restore||!c->io.fp_save||!c->io.fp_restore)return pwcq_fail(r,PWCQ_ARGUMENT);
    m->attempted=1;
    if(r->off!=127){m->declined=1;return 1;}
    if(!pgcd_final_unopened(final)||!pgcd_live(c,&r->core.after,0)||!pwcq_flag(c,r))return pwcq_fail(r,PWCQ_CONTEXT);
    m->last_ticks=r->core.after.cpu.ticks;m->mask.target_daif=0xc0;m->mask.target_group=0;
    /* Conservative held/unknown BEFORE delivery: any partial/unknown return
     * cannot reach original services or use restoration as cleanup. */
    m->held=m->unknown=1;r->outstanding=8;c->io.order(c->io.opaque);
    m->mask.returned=io->mask(io->context,&m->mask)?1:0;c->io.order(c->io.opaque);
    if(!pwcq_transition_exact(&m->mask,0))return pwcq_fail(r,PWCQ_RESTORE);
    r->outstanding=0;
    for(unsigned k=0;k<7;k++){
        struct pwrpc_masked_psci *q=&m->call[k];q->target=0x100u+0x100u*k;
        if(!pwcq_masked_source(c,final,r)||!pwcq_masked_live(c,final,r,&q->before)||!pwcq_flag(c,r))return pwcq_fail(r,PWCQ_SOURCE);
        q->native_before=r->native[r->native_reads-1];
        if(!c->io.fp_save(c->io.opaque,&q->fp)||q->fp.saved!=1||q->fp.cpacr_before!=0x300000)return pwcq_fail(r,PWCQ_CALL);
        q->issued=q->unknown=1;m->issued|=1u<<k;r->outstanding=16+k;c->io.order(c->io.opaque);
        q->returned=io->affinity(io->context,q->target,&q->raw)?1:0;
        if(q->returned)m->returned|=1u<<k;c->io.order(c->io.opaque);
        int arch_ok=pwcq_masked_live(c,final,r,&q->after);
        int fp_ok=c->io.fp_restore(c->io.opaque,&q->fp);
        if(!q->returned||!arch_ok||!fp_ok||q->fp.saved!=1||q->fp.restored!=1||q->fp.cpacr_before!=0x300000||q->fp.cpacr_after!=q->fp.cpacr_before||
           !pwcq_flag(c,r))return pwcq_fail(r,PWCQ_CALL);
        q->native_after=r->native[r->native_reads-1];
        if(q->raw!=1||!pwcq_masked_source(c,final,r))return pwcq_fail(r,PWCQ_CALL);
        q->unknown=0;q->complete=1;r->outstanding=0;m->calls=k+1;c->io.order(c->io.opaque);
    }
    if(!pwcq_masked_source(c,final,r)||m->issued!=127||m->returned!=127||m->source_count!=15)
        return pwcq_fail(r,PWCQ_SOURCE);
    m->restore.target_daif=0;m->restore.target_group=1;r->outstanding=32;c->io.order(c->io.opaque);
    m->restore.returned=io->restore(io->context,&m->restore)?1:0;c->io.order(c->io.opaque);
    if(!pwcq_transition_exact(&m->restore,1)||!pgcd_live(c,&r->core.after,0)||
       r->core.after.cpu.ticks<m->last_ticks||!pwcq_source_into(c,r,&m->after_restore)||
       !pgcd_final_unopened(final))return pwcq_fail(r,PWCQ_RESTORE);
    m->held=m->unknown=0;m->restored=m->complete=1;r->outstanding=0;c->io.order(c->io.opaque);return 1;
}
#endif
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
#if EFI_XNU_WIFI_CPU_MASKED_RO_ADMISSION
    if(!pwcq_masked_run(io,c,final,r))return 0;
#endif
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
