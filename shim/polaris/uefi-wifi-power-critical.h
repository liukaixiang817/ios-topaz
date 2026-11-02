/* New power caller's CPU-local exclusion interval. This is NOT a DRV2/EL3/
 * TCS/MPU grant: source/cache/geometry/NS-write-map admission remains separate.
 * No original service runs after masking. A second typed PSCI OFF round is
 * admitted under the masked FP/context guard BEFORE local_quiescent. Once
 * that interval is published, no SMC runs until exact restoration.
 * Default OFF; the new parent scope requires an independent host policy. */
#ifndef POLARIS_UEFI_WIFI_POWER_CRITICAL_H
#define POLARIS_UEFI_WIFI_POWER_CRITICAL_H
#ifndef EFI_XNU_WIFI_CPU_LIVE_DIAGNOSTICS
#define EFI_XNU_WIFI_CPU_LIVE_DIAGNOSTICS 0
#endif
#if EFI_XNU_WIFI_CPU_LIVE_DIAGNOSTICS
#include "uefi-wifi-cpu-live-diagnostics.h"
#endif
#if EFI_XNU_WIFI_POWER_TRANSACTION_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
#include "uefi-wifi-rsc-baseline.h"
#include "uefi-wifi-psci-affinity.h"
#include "uefi-wifi-cpu-local-mask.h"
#include "../../tools/polaris-wifi-rsc-transaction.h"
#ifndef EFI_XNU_WIFI_ARC_READ_AVAILABLE
#define EFI_XNU_WIFI_ARC_READ_AVAILABLE 0
#endif
#ifndef EFI_XNU_WIFI_ARC_READ_CAPTURE_ONLY
#define EFI_XNU_WIFI_ARC_READ_CAPTURE_ONLY 1
#endif
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE
#include "uefi-wifi-rsc-read-plan.h"
#endif
struct pwrr_transaction;
struct pwrpc_source {
    uint32_t owner_bytes,table_bytes,hash_count[2],hash_failed[2],complete;
    uint64_t identity_address,identity_par;
    struct efi_loaded owner;uint8_t table[PWRPH_PROTOCOL_BYTES],hashes[2][5][32];
};
struct pwrpc_result {
    uint32_t attempted,error,unknown,outstanding,local_mask_held,local_restored,retired;
    uint32_t affinity_issued,affinity_returned,affinity_unknown,flag_reads;
    uint64_t cpu_on_address;uint32_t cpu_on[10];
    struct pgcd_arch normal,masked,after;
    struct pgcd_service_guard guard[7];int64_t affinity[7];
    struct pwrpc_transition mask,restore;
    struct pwrpc_source source[2];
    /* RSC prefix retains every per-access time. Architectural live checks
     * retain counters, the current/failed raw sample and two source-stage
     * checkpoints; these are not another append-only MMIO event stream. */
    uint32_t live_calls,live_valid;struct pwrpc_context last_context,source_context[2];
    uint32_t masked_issued,masked_returned,masked_unknown,local_quiescent;
    struct pwrpc_masked_psci masked_psci[7];
    struct pwrpc_source masked_source;struct pwrpc_context masked_source_context;
#if EFI_XNU_WIFI_CPU_LIVE_DIAGNOSTICS
    struct pwrpc_live_diagnostic live_failure;
#endif
};
struct pwrpc_io {
    void *context;
    int (*affinity)(void *,uint64_t,int64_t *);
    int (*mask)(void *,struct pwrpc_transition *);
    int (*restore)(void *,struct pwrpc_transition *);
};
enum pwrpc_error {PWRPC_OK,PWRPC_ARGUMENT,PWRPC_SOURCE,PWRPC_ARCH,PWRPC_FLAG,
    PWRPC_PSCI,PWRPC_GUARD,PWRPC_MASK,PWRPC_TIME,PWRPC_PENDING,PWRPC_RESTORE};
static inline int pwrpc_fail(struct pwrpc_result *r,unsigned e,int unknown)
{if(!r->error)r->error=e;if(unknown)r->unknown=1;paic_actual_order(0);return 0;}
static inline int pwrpc_unsafe(const struct pwrpc_result *r)
{return r->unknown||r->outstanding||r->local_mask_held||(r->attempted&&!r->retired);}
static inline int pwrpc_live(struct pgcd_context *g,struct pwrpc_result *r,unsigned masked,struct pgcd_arch *a)
{
    if(!g||!g->record||!g->ticket||!g->io.arch||!g->opened||g->finished||g->stage!=2||
       g->record->phase!=1||g->record->error||pgcd_uncertain(g)||g->ticket->spent!=1||g->ticket->result!=(uintptr_t)g->record)
        return pwrpc_fail(r,PWRPC_SOURCE,r->local_mask_held!=0);
    if(r->error||r->unknown)return 0;
    struct pwrpc_context *sample=&r->last_context;*sample=(struct pwrpc_context){0};r->live_calls++;
#if EFI_XNU_WIFI_CPU_LIVE_DIAGNOSTICS
    if(!g->io.arch(g->io.opaque,&sample->arch)){
        (void)pwrpc_live_capture(&r->live_failure,PWRPC_LIVE_ARCH_CALLBACK,r->live_calls,masked,
            g->record->before.cpu.ticks,r->normal.cpu.ticks,0,0);
        return pwrpc_fail(r,PWRPC_ARCH,r->local_mask_held!=0);
    }
#else
    if(!g->io.arch(g->io.opaque,&sample->arch))return pwrpc_fail(r,PWRPC_ARCH,r->local_mask_held!=0);
#endif
    *a=sample->arch;
    if(!pgcd_owned(g,0,g->record->core+0x1b098,8))return pwrpc_fail(r,PWRPC_SOURCE,r->local_mask_held!=0);
    sample->TPL=pwfi_le((const void*)(uintptr_t)(g->record->core+0x1b098),8);
    sample->boot=(uintptr_t)g->io.system->boot;sample->tables=(uintptr_t)g->io.system->tables;sample->count=g->io.system->table_count;
    const struct pgcd_arch *n=&r->normal;const struct pwfc_arch *x=&a->cpu,*v=&n->cpu;
#if EFI_XNU_WIFI_CPU_LIVE_DIAGNOSTICS
    /* Preserve the exact original short-circuit order and single evaluation.
     * In particular DS/owner readers are not called after an earlier failure.
     * Capture the already returned sample, not a terminal-time observation. */
#define PWRPC_LIVE_BAD(test,why) ((test)?pwrpc_live_capture(&r->live_failure,(why),r->live_calls,masked,g->record->before.cpu.ticks,v->ticks,x->ticks,1):0)
    if(PWRPC_LIVE_BAD(x->el!=4,PWRPC_LIVE_EL)||
       PWRPC_LIVE_BAD(x->mpidr&0xffffff,PWRPC_LIVE_MPIDR_LOCAL)||
       PWRPC_LIVE_BAD(x->frequency!=19200000,PWRPC_LIVE_FREQUENCY)||
       PWRPC_LIVE_BAD(x->el!=v->el,PWRPC_LIVE_EL_CHANGED)||
       PWRPC_LIVE_BAD(x->mpidr!=v->mpidr,PWRPC_LIVE_MPIDR_CHANGED)||
       PWRPC_LIVE_BAD(x->ttbr0!=v->ttbr0,PWRPC_LIVE_TTBR0)||
       PWRPC_LIVE_BAD(x->ttbr1!=v->ttbr1,PWRPC_LIVE_TTBR1)||
       PWRPC_LIVE_BAD(x->tcr!=v->tcr,PWRPC_LIVE_TCR)||
       PWRPC_LIVE_BAD(x->sctlr!=v->sctlr,PWRPC_LIVE_SCTLR)||
       PWRPC_LIVE_BAD(x->mair!=v->mair,PWRPC_LIVE_MAIR)||
       PWRPC_LIVE_BAD(x->sre!=v->sre,PWRPC_LIVE_SRE)||
       PWRPC_LIVE_BAD(x->daif!=(masked?0xc0:0),PWRPC_LIVE_DAIF)||
       PWRPC_LIVE_BAD(x->group1!=(masked?0:1),PWRPC_LIVE_GROUP1)||
       PWRPC_LIVE_BAD(a->cpacr!=n->cpacr,PWRPC_LIVE_CPACR)||
       PWRPC_LIVE_BAD(x->ticks<v->ticks,PWRPC_LIVE_BEFORE_NORMAL)||
       PWRPC_LIVE_BAD(x->ticks-v->ticks>PGCD_FRESH_TICKS,PWRPC_LIVE_NORMAL_AGE)||
       PWRPC_LIVE_BAD(x->ticks<g->record->before.cpu.ticks,PWRPC_LIVE_BEFORE_OPENING)||
       PWRPC_LIVE_BAD(x->ticks-g->record->before.cpu.ticks>PGCD_FRESH_TICKS,PWRPC_LIVE_OPENING_AGE)||
       PWRPC_LIVE_BAD(sample->TPL!=g->record->TPL_initial,PWRPC_LIVE_TPL)||
       PWRPC_LIVE_BAD(sample->boot!=g->record->core+0x1b800,PWRPC_LIVE_BOOT)||
       PWRPC_LIVE_BAD(sample->tables!=g->record->config_pointer,PWRPC_LIVE_TABLES)||
       PWRPC_LIVE_BAD(sample->count!=g->record->config_count,PWRPC_LIVE_TABLE_COUNT)||
       PWRPC_LIVE_BAD(!pgcd_equal(g->record->DS_raw[0],(const void*)(uintptr_t)g->record->DS,168),PWRPC_LIVE_DS)||
       PWRPC_LIVE_BAD(!pgcd_cached_owner_stable(g),PWRPC_LIVE_OWNER))
        return pwrpc_fail(r,PWRPC_ARCH,r->local_mask_held!=0);
#undef PWRPC_LIVE_BAD
#else
    if(x->el!=4||(x->mpidr&0xffffff)||x->frequency!=19200000||x->el!=v->el||x->mpidr!=v->mpidr||
       x->ttbr0!=v->ttbr0||x->ttbr1!=v->ttbr1||x->tcr!=v->tcr||x->sctlr!=v->sctlr||x->mair!=v->mair||
       x->sre!=v->sre||x->daif!=(masked?0xc0:0)||x->group1!=(masked?0:1)||a->cpacr!=n->cpacr||
       x->ticks<v->ticks||x->ticks-v->ticks>PGCD_FRESH_TICKS||x->ticks<g->record->before.cpu.ticks||
       x->ticks-g->record->before.cpu.ticks>PGCD_FRESH_TICKS||sample->TPL!=g->record->TPL_initial||
       sample->boot!=g->record->core+0x1b800||sample->tables!=g->record->config_pointer||sample->count!=g->record->config_count||
       !pgcd_equal(g->record->DS_raw[0],(const void*)(uintptr_t)g->record->DS,168)||!pgcd_cached_owner_stable(g))
        return pwrpc_fail(r,PWRPC_ARCH,r->local_mask_held!=0);
#endif
    sample->complete=1;r->live_valid++;return 1;
}
static inline int pwrpc_cpu_flag(const struct paic_io *memory,struct pwrcl_result *p,
    const struct pwrph_work *w,struct pwrpc_result *r)
{
    if(r->flag_reads==10||!pgcd_in_self(&p->core,r->cpu_on_address,4)||
       !pwrcl_owned(memory,p,w,r->cpu_on_address,4))return pwrpc_fail(r,PWRPC_FLAG,r->local_mask_held!=0);
    uint32_t value=*(const volatile uint32_t*)(uintptr_t)r->cpu_on_address;
    r->cpu_on[r->flag_reads++]=value;
    if(value)return pwrpc_fail(r,PWRPC_FLAG,1);return 1;
}
/* Pure bounded RAM/AT/digest checkpoint. It calls no original service while
 * masked. Immutable Core/RPMh and the registered owner/table are verified
 * before any local mask, and again BEFORE re-enabling original interrupts. */
static inline int pwrpc_source_sample(const struct paic_io *memory,struct pwrcl_result *p,
    const struct pwrph_work *w,struct pgcd_context *g,struct pwrpc_result *r,
    struct pwrpc_source *s,struct pwrpc_context *context)
{
    if(!pgcd_in_self(&p->core,(uintptr_t)s,sizeof(*s))||!pgcd_in_self(&p->core,(uintptr_t)context,sizeof(*context))||
       s->complete||!p->reader.stable||p->reader.owner_matches!=1||p->reader.error||p->reader.unknown||p->reader.outstanding||
       !pwrcl_copy(memory,p,w,&s->owner,p->reader.owner_address,sizeof(s->owner),&s->owner_bytes)||
       !pgcd_equal(&s->owner,&p->reader.owner,sizeof(s->owner))||
       !pwrcl_copy(memory,p,w,s->table,p->reader.protocol[1],sizeof(s->table),&s->table_bytes)||
       !pgcd_equal(s->table,p->reader.protocol_raw[1],sizeof(s->table))||
       !pwrcl_owned(memory,p,w,p->reader.image,PWRPI_IMAGE_BYTES)||!pwrcl_owned(memory,p,w,p->core.core,PGCI_IMAGE_BYTES))
        return pwrpc_fail(r,PWRPC_SOURCE,r->local_mask_held!=0);
    s->identity_address=p->identity_address;s->identity_par=p->identity_par;
    if(!pwrpi_verify((const void*)(uintptr_t)p->reader.image,p->reader.image,s->hashes[0],&s->hash_count[0],&s->hash_failed[0])||
       !pgci_verify((const void*)(uintptr_t)p->core.core,p->core.core,PGCI_IMAGE_BYTES,s->hashes[1],&s->hash_failed[1],&s->hash_count[1])||
       !pwrpc_live(g,r,r->local_mask_held?1:0,&r->after))return pwrpc_fail(r,PWRPC_SOURCE,r->local_mask_held!=0);
    *context=r->last_context;s->complete=1;return 1;
}
static inline int pwrpc_source_check(const struct paic_io *memory,struct pwrcl_result *p,
    const struct pwrph_work *w,struct pgcd_context *g,struct pwrpc_result *r,unsigned slot)
{
    if(slot>1)return pwrpc_fail(r,PWRPC_SOURCE,r->local_mask_held!=0);
    return pwrpc_source_sample(memory,p,w,g,r,&r->source[slot],&r->source_context[slot]);
}
/* AFFINITY_INFO is a logical-state observation, not an EE/EL3 permission.
 * The second round closes the normal-IRQ window BEFORE this CPU-local
 * interval is published. Only typed PSCI, our own FP save/restore and bounded
 * RAM/AT/context readers run here: no original UEFI method/TPL transition.
 * This is deliberately separate from the normal original-service guard;
 * that guard's DAIF0/G1-on contract is never relaxed. */
static inline int pwrpc_masked_off(const struct pwrpc_io *io,const struct paic_io *memory,
    struct pwrcl_result *p,const struct pwrph_work *w,struct pgcd_context *g,struct pwrpc_result *r)
{
    if(!r->local_mask_held||r->local_quiescent||r->masked_issued||r->unknown||r->outstanding||
       !g->io.fp_save||!g->io.fp_restore)return pwrpc_fail(r,PWRPC_PENDING,1);
    for(unsigned k=0;k<7;k++){
        struct pwrpc_masked_psci *q=&r->masked_psci[k];q->target=0x100u+0x100u*k;
        if(!pwrpc_live(g,r,1,&r->after)||!pwrcl_owned(memory,p,w,r->cpu_on_address,4))return pwrpc_fail(r,PWRPC_SOURCE,1);
        q->before=r->last_context;q->native_before=*(const volatile uint32_t*)(uintptr_t)r->cpu_on_address;
        if(q->native_before)return pwrpc_fail(r,PWRPC_FLAG,1);
        if(!g->io.fp_save(g->io.opaque,&q->fp)||!q->fp.saved||q->fp.cpacr_before!=r->normal.cpacr)return pwrpc_fail(r,PWRPC_GUARD,1);
        q->issued=q->unknown=1;r->masked_issued|=1u<<k;r->masked_unknown|=1u<<k;r->outstanding=16+k;paic_actual_order(0);
        int returned=io->affinity(io->context,q->target,&q->raw);q->returned=returned?1:0;
        if(returned)r->masked_returned|=1u<<k;paic_actual_order(0);
        int arch_ok=pwrpc_live(g,r,1,&r->after);q->after=r->last_context;
        int fp_ok=g->io.fp_restore(g->io.opaque,&q->fp);
        if(!returned||!arch_ok||!fp_ok||!q->fp.restored||q->fp.cpacr_after!=q->fp.cpacr_before)return pwrpc_fail(r,PWRPC_GUARD,1);
        if(!pwrcl_owned(memory,p,w,r->cpu_on_address,4))return pwrpc_fail(r,PWRPC_SOURCE,1);
        q->native_after=*(const volatile uint32_t*)(uintptr_t)r->cpu_on_address;
        if(q->native_after||q->raw!=1)return pwrpc_fail(r,q->native_after?PWRPC_FLAG:PWRPC_PSCI,1);
        q->unknown=0;q->complete=1;r->masked_unknown&=~(1u<<k);r->outstanding=0;paic_actual_order(0);
    }
    if(!pwrpc_source_sample(memory,p,w,g,r,&r->masked_source,&r->masked_source_context))return pwrpc_fail(r,PWRPC_SOURCE,1);
    r->local_quiescent=1;paic_actual_order(0);return 1;
}
/* Raw CPU-local evidence only. A successful call is never a DRV/EE/EL3 grant. */
static inline int pwrpc_local_held(const struct pwrpc_result *r)
{
    if(!r||r->error||r->unknown||r->outstanding||r->retired||!r->local_mask_held||!r->local_quiescent||
       r->affinity_issued!=0x7f||r->affinity_returned!=0x7f||r->affinity_unknown||
       r->masked_issued!=0x7f||r->masked_returned!=0x7f||r->masked_unknown||!r->masked_source.complete||!r->source[0].complete||
       r->normal.cpu.el!=4||(r->normal.cpu.mpidr&0xffffff)||r->normal.cpu.frequency!=19200000||r->normal.cpu.daif||r->normal.cpu.group1!=1||
       !r->mask.returned||r->mask.precondition_error||!r->mask.daif_written||!r->mask.group_written||
       !r->mask.daif_observed||!r->mask.group_observed||r->mask.daif_before||r->mask.group_before!=1||r->mask.daif_read!=0xc0||r->mask.group_read||
       r->flag_reads<9||r->flag_reads>10)return 0;
    for(unsigned k=0;k<r->flag_reads;k++)if(r->cpu_on[k])return 0;
    for(unsigned k=0;k<7;k++){
        const struct pgcd_service_guard *g=&r->guard[k];const struct pwrpc_masked_psci *q=&r->masked_psci[k];
        if(r->affinity[k]!=1||!g->entered||!g->left||g->unknown||!g->foreign_returned||!g->fp.saved||!g->fp.restored||
           g->fp.cpacr_before!=0x300000||g->fp.cpacr_after!=g->fp.cpacr_before||g->TPL_before!=g->TPL_after||
           !q->complete||q->issued!=1||q->returned!=1||q->unknown||q->raw!=1||q->target!=0x100u+0x100u*k||
           q->native_before||q->native_after||!q->fp.saved||!q->fp.restored||q->fp.cpacr_before!=0x300000||
           q->fp.cpacr_after!=q->fp.cpacr_before||!q->before.complete||!q->after.complete||
           q->before.arch.cpu.daif!=0xc0||q->after.arch.cpu.daif!=0xc0||q->before.arch.cpu.group1||q->after.arch.cpu.group1||
           q->before.TPL!=q->after.TPL||q->before.boot!=q->after.boot||q->before.tables!=q->after.tables||q->before.count!=q->after.count)
            return 0;
    }return 1;
}
static inline int pwrpc_begin(const struct pwrpc_io *io,const struct paic_io *memory,
    struct pwrcl_result *p,const struct pwrph_work *w,struct pgcd_context *g,
    uint64_t cpu_on_address,struct pwrpc_result *r)
{
    if(!r||r->attempted)return 0;r->attempted=1;r->cpu_on_address=cpu_on_address;
    if(!io||!io->affinity||!io->mask||!io->restore||!memory||!memory->identity||!p||!w||!g||!g->record||!g->io.arch||
       !g->opened||!pwrph_context_ready(g)||p->core.core!=g->record->core||p->core.self_base!=g->record->self_base||
       p->core.self_bytes!=g->record->self_bytes||!pgcd_in_self(g->record,(uintptr_t)r,sizeof(*r))||
       !pwrcl_owned(memory,p,w,(uintptr_t)r,sizeof(*r)))return pwrpc_fail(r,PWRPC_SOURCE,0);
    if(!g->io.arch(g->io.opaque,&r->normal)||!pwfc_arch_admitted(&r->normal.cpu)||
       r->normal.cpu.daif||r->normal.cpu.group1!=1||r->normal.cpacr!=UINT64_C(0x300000)||
       r->normal.cpu.ticks<g->record->before.cpu.ticks||r->normal.cpu.ticks-g->record->before.cpu.ticks>PGCD_FRESH_TICKS)
        return pwrpc_fail(r,PWRPC_ARCH,0);
    if(!pwrpc_source_check(memory,p,w,g,r,0))goto refuse;
    static const uint64_t targets[7]={0x100,0x200,0x300,0x400,0x500,0x600,0x700};
    for(unsigned k=0;k<7;k++){
        if(!pwrpc_cpu_flag(memory,p,w,r))goto refuse;
        if(!pgcd_service_enter(g,&r->guard[k])){pwrpc_fail(r,PWRPC_GUARD,pgcd_uncertain(g));goto refuse;}
        r->affinity_issued|=1u<<k;r->affinity_unknown|=1u<<k;r->outstanding=k+1;paic_actual_order(0);
        int returned=io->affinity(io->context,targets[k],&r->affinity[k]);
        if(returned)r->affinity_returned|=1u<<k;paic_actual_order(0);
        if(!pgcd_service_leave(g,&r->guard[k],returned)){pwrpc_fail(r,PWRPC_GUARD,1);goto refuse;}
        r->affinity_unknown&=~(1u<<k);r->outstanding=0;paic_actual_order(0);
        if(r->affinity[k]!=1){pwrpc_fail(r,PWRPC_PSCI,0);goto refuse;}
    }
    if(!pwrpc_cpu_flag(memory,p,w,r)||!pwrpc_live(g,r,0,&r->after))goto refuse;
    r->mask.target_daif=0xc0;r->mask.target_group=0;r->outstanding=8;paic_actual_order(0);
    int returned=io->mask(io->context,&r->mask);r->mask.returned=returned?1:0;paic_actual_order(0);
    if(!returned||r->mask.daif_written||r->mask.group_written)r->local_mask_held=1;
    if(!returned||r->mask.precondition_error||!r->mask.daif_written||!r->mask.group_written||
       r->mask.daif_before||r->mask.group_before!=1||!r->mask.daif_observed||!r->mask.group_observed||r->mask.daif_read!=0xc0||r->mask.group_read!=0){
        pwrpc_fail(r,PWRPC_MASK,r->local_mask_held!=0);goto refuse;
    }
    if(!pwrpc_live(g,r,1,&r->masked)||!pwrpc_cpu_flag(memory,p,w,r)){r->unknown=1;goto refuse;}
    r->outstanding=0;paic_actual_order(0);
    if(!pwrpc_masked_off(io,memory,p,w,g,r))goto refuse;
    return 1;
refuse:
    if(pgcd_uncertain(g)||r->affinity_unknown||r->outstanding)r->unknown=1;
    if(!r->unknown&&!r->local_mask_held)r->retired=1;
    paic_actual_order(0);return 0;
}
static inline int pwrpc_end_checked(const struct pwrpc_io *io,const struct paic_io *memory,
    struct pwrcl_result *p,const struct pwrph_work *w,struct pgcd_context *g,
    const struct pwrsc_transaction *transaction,const struct pwrpb_baseline *before,
    const struct pwrpb_baseline *after,struct pwrpc_result *r,const struct pwrr_transaction *read)
{
    if(!pwrpc_local_held(r)||!transaction)
        return r?pwrpc_fail(r,PWRPC_PENDING,1):0;
    if(!io||!io->restore||!memory||!memory->identity||!p||!w||!g)return pwrpc_fail(r,PWRPC_ARGUMENT,1);
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE
    if(read&&(!pgcd_in_self(&p->core,(uintptr_t)read,sizeof(*read))||
       !pwrcl_owned(memory,p,w,(uintptr_t)read,sizeof(*read))||!pwrr_retired(read)||
       !pwrpb_equal(before,after)||read->io.started<r->normal.cpu.ticks))return pwrpc_fail(r,PWRPC_PENDING,1);
#else
    if(read)return pwrpc_fail(r,PWRPC_ARGUMENT,1);
#endif
    if(transaction->unknown||transaction->outstanding||
       (!transaction->writes&&(transaction->triggers||transaction->completed||transaction->acknowledged||transaction->finished||transaction->restored))||
       (transaction->writes&&(!pwrsc_retired(transaction)||!pwrpb_equal(before,after))))
        return pwrpc_fail(r,PWRPC_PENDING,1);
    if(!pwrpc_live(g,r,1,&r->after)||!pwrpc_cpu_flag(memory,p,w,r))return pwrpc_fail(r,PWRPC_ARCH,1);
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE
    if(read&&read->io.last>r->after.cpu.ticks)return pwrpc_fail(r,PWRPC_PENDING,1);
#endif
    if(!pwrpc_source_check(memory,p,w,g,r,1))return pwrpc_fail(r,PWRPC_SOURCE,1);
    r->restore.target_daif=r->normal.cpu.daif;r->restore.target_group=r->normal.cpu.group1;
    r->outstanding=9;paic_actual_order(0);
    int returned=io->restore(io->context,&r->restore);r->restore.returned=returned?1:0;paic_actual_order(0);
    if(!returned||r->restore.precondition_error||!r->restore.group_written||!r->restore.daif_written||
       r->restore.daif_before!=0xc0||r->restore.group_before||!r->restore.group_observed||!r->restore.daif_observed||r->restore.daif_read||r->restore.group_read!=1||
       !pwrpc_live(g,r,0,&r->after))return pwrpc_fail(r,PWRPC_RESTORE,1);
    r->outstanding=r->local_mask_held=0;r->local_restored=r->retired=1;paic_actual_order(0);return 1;
}
static inline int pwrpc_end(const struct pwrpc_io *io,const struct paic_io *memory,
    struct pwrcl_result *p,const struct pwrph_work *w,struct pgcd_context *g,
    const struct pwrsc_transaction *transaction,const struct pwrpb_baseline *before,
    const struct pwrpb_baseline *after,struct pwrpc_result *r)
{return pwrpc_end_checked(io,memory,p,w,g,transaction,before,after,r,0);}
#if EFI_XNU_WIFI_FOUR_VRM_AVAILABLE
/* This path receives the REAL VRM READ/WRITE records, never an unused zero
 * ARC transaction relabelled as the completed hardware work. */
static inline int pwrpc_end_vrm(const struct pwrpc_io *io,const struct paic_io *memory,
    struct pwrcl_result *p,const struct pwrph_work *w,struct pgcd_context *g,
    const struct pwv_result *vrm,const struct pwrpb_baseline *before,
    const struct pwrpb_baseline *after,struct pwrpc_result *r)
{
    if(!pwrpc_local_held(r)||!vrm)return r?pwrpc_fail(r,PWRPC_PENDING,1):0;
    if(!io||!io->restore||!memory||!memory->identity||!p||!w||!g)return pwrpc_fail(r,PWRPC_ARGUMENT,1);
    if(!pgcd_in_self(&p->core,(uintptr_t)vrm,sizeof(*vrm))||
       !pwrcl_owned(memory,p,w,(uintptr_t)vrm,sizeof(*vrm))||!vrm->engines_retired||
       vrm->provider!=(uintptr_t)p||vrm->core!=(uintptr_t)g||!pwv_engine_prefix(vrm)||
       !pwrpb_equal(before,after)||vrm->read.io.started<r->normal.cpu.ticks)return pwrpc_fail(r,PWRPC_PENDING,1);
    if(!pwrpc_live(g,r,1,&r->after)||!pwrpc_cpu_flag(memory,p,w,r))return pwrpc_fail(r,PWRPC_ARCH,1);
    uint64_t last=vrm->known_refusal?vrm->read.io.last:vrm->write.io.last;
    if(last>r->after.cpu.ticks)return pwrpc_fail(r,PWRPC_PENDING,1);
    if(!pwrpc_source_check(memory,p,w,g,r,1))return pwrpc_fail(r,PWRPC_SOURCE,1);
    r->restore.target_daif=r->normal.cpu.daif;r->restore.target_group=r->normal.cpu.group1;
    r->outstanding=9;paic_actual_order(0);
    int returned=io->restore(io->context,&r->restore);r->restore.returned=returned?1:0;paic_actual_order(0);
    if(!returned||r->restore.precondition_error||!r->restore.group_written||!r->restore.daif_written||
       r->restore.daif_before!=0xc0||r->restore.group_before||!r->restore.group_observed||!r->restore.daif_observed||r->restore.daif_read||r->restore.group_read!=1||
       !pwrpc_live(g,r,0,&r->after))return pwrpc_fail(r,PWRPC_RESTORE,1);
    r->outstanding=r->local_mask_held=0;r->local_restored=r->retired=1;paic_actual_order(0);return 1;
}
#endif
/* These are real AArch64 instructions, compiled as general-register-only
 * code. Host peers never execute them. No original EFI service is called. */

#endif
#endif
