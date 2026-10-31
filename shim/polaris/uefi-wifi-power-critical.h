/* New power caller's CPU-local exclusion interval. This is NOT a DRV2/EL3/
 * TCS/MPU grant: source/cache/geometry/NS-write-map admission remains separate.
 * No original service or SMC runs after masking until exact restoration.
 * Default OFF; not installed in prepare_boot or any host policy yet. */
#ifndef POLARIS_UEFI_WIFI_POWER_CRITICAL_H
#define POLARIS_UEFI_WIFI_POWER_CRITICAL_H
#if EFI_XNU_WIFI_POWER_TRANSACTION_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
#include "uefi-wifi-rsc-baseline.h"
#include "../../tools/polaris-wifi-rsc-transaction.h"
struct pwrpc_transition {
    uint64_t target_daif,target_group,daif_before,group_before,daif_read,group_read;
    uint32_t returned,precondition_error,daif_written,daif_observed,group_written,group_observed;
};
struct pwrpc_source {
    uint32_t owner_bytes,table_bytes,hash_count[2],hash_failed[2],complete;
    uint64_t identity_address,identity_par;
    struct efi_loaded owner;uint8_t table[PWRPH_PROTOCOL_BYTES],hashes[2][5][32];
};
struct pwrpc_context {struct pgcd_arch arch;uint64_t TPL,boot,tables,count;uint32_t complete;};
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
    if(!g->io.arch(g->io.opaque,&sample->arch))return pwrpc_fail(r,PWRPC_ARCH,r->local_mask_held!=0);
    *a=sample->arch;
    if(!pgcd_owned(g,0,g->record->core+0x1b098,8))return pwrpc_fail(r,PWRPC_SOURCE,r->local_mask_held!=0);
    sample->TPL=pwfi_le((const void*)(uintptr_t)(g->record->core+0x1b098),8);
    sample->boot=(uintptr_t)g->io.system->boot;sample->tables=(uintptr_t)g->io.system->tables;sample->count=g->io.system->table_count;
    const struct pgcd_arch *n=&r->normal;const struct pwfc_arch *x=&a->cpu,*v=&n->cpu;
    if(x->el!=4||(x->mpidr&0xffffff)||x->frequency!=19200000||x->el!=v->el||x->mpidr!=v->mpidr||
       x->ttbr0!=v->ttbr0||x->ttbr1!=v->ttbr1||x->tcr!=v->tcr||x->sctlr!=v->sctlr||x->mair!=v->mair||
       x->sre!=v->sre||x->daif!=(masked?0xc0:0)||x->group1!=(masked?0:1)||a->cpacr!=n->cpacr||
       x->ticks<v->ticks||x->ticks-v->ticks>PGCD_FRESH_TICKS||x->ticks<g->record->before.cpu.ticks||
       x->ticks-g->record->before.cpu.ticks>PGCD_FRESH_TICKS||sample->TPL!=g->record->TPL_initial||
       sample->boot!=g->record->core+0x1b800||sample->tables!=g->record->config_pointer||sample->count!=g->record->config_count||
       !pgcd_equal(g->record->DS_raw[0],(const void*)(uintptr_t)g->record->DS,168)||!pgcd_cached_owner_stable(g))
        return pwrpc_fail(r,PWRPC_ARCH,r->local_mask_held!=0);
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
static inline int pwrpc_source_check(const struct paic_io *memory,struct pwrcl_result *p,
    const struct pwrph_work *w,struct pgcd_context *g,struct pwrpc_result *r,unsigned slot)
{
    if(slot>1)return pwrpc_fail(r,PWRPC_SOURCE,r->local_mask_held!=0);
    struct pwrpc_source *s=&r->source[slot];
    if(s->complete||!p->reader.stable||p->reader.owner_matches!=1||p->reader.error||p->reader.unknown||p->reader.outstanding||
       !pwrcl_copy(memory,p,w,&s->owner,p->reader.owner_address,sizeof(s->owner),&s->owner_bytes)||
       !pgcd_equal(&s->owner,&p->reader.owner,sizeof(s->owner))||
       !pwrcl_copy(memory,p,w,s->table,p->reader.protocol[1],sizeof(s->table),&s->table_bytes)||
       !pgcd_equal(s->table,p->reader.protocol_raw[1],sizeof(s->table))||
       !pwrcl_owned(memory,p,w,p->reader.image,PWRPI_IMAGE_BYTES)||!pwrcl_owned(memory,p,w,p->core.core,PGCI_IMAGE_BYTES))
        return pwrpc_fail(r,PWRPC_SOURCE,r->local_mask_held!=0);
    s->identity_address=p->identity_address;s->identity_par=p->identity_par;
    if(!pwrpi_verify((const void*)(uintptr_t)p->reader.image,p->reader.image,s->hashes[0],&s->hash_count[0],&s->hash_failed[0])||
       !pgci_verify((const void*)(uintptr_t)p->core.core,p->core.core,PGCI_IMAGE_BYTES,s->hashes[1],&s->hash_failed[1],&s->hash_count[1])||
       !pwrpc_live(g,r,slot?1:0,&r->after))return pwrpc_fail(r,PWRPC_SOURCE,r->local_mask_held!=0);
    r->source_context[slot]=r->last_context;s->complete=1;return 1;
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
    r->outstanding=0;paic_actual_order(0);return 1;
refuse:
    if(pgcd_uncertain(g)||r->affinity_unknown||r->outstanding)r->unknown=1;
    if(!r->unknown&&!r->local_mask_held)r->retired=1;
    paic_actual_order(0);return 0;
}
static inline int pwrpc_end(const struct pwrpc_io *io,const struct paic_io *memory,
    struct pwrcl_result *p,const struct pwrph_work *w,struct pgcd_context *g,
    const struct pwrsc_transaction *transaction,const struct pwrpb_baseline *before,
    const struct pwrpb_baseline *after,struct pwrpc_result *r)
{
    if(!r||r->unknown||r->outstanding||!r->local_mask_held||r->retired||!transaction)
        return r?pwrpc_fail(r,PWRPC_PENDING,1):0;
    if(!io||!io->restore||!memory||!memory->identity||!p||!w||!g)return pwrpc_fail(r,PWRPC_ARGUMENT,1);
    if(transaction->unknown||transaction->outstanding||
       (!transaction->writes&&(transaction->triggers||transaction->completed||transaction->acknowledged||transaction->finished||transaction->restored))||
       (transaction->writes&&(!pwrsc_retired(transaction)||!pwrpb_equal(before,after))))
        return pwrpc_fail(r,PWRPC_PENDING,1);
    if(!pwrpc_live(g,r,1,&r->after)||!pwrpc_cpu_flag(memory,p,w,r))return pwrpc_fail(r,PWRPC_ARCH,1);
    if(!pwrpc_source_check(memory,p,w,g,r,1))return pwrpc_fail(r,PWRPC_SOURCE,1);
    r->restore.target_daif=r->normal.cpu.daif;r->restore.target_group=r->normal.cpu.group1;
    r->outstanding=9;paic_actual_order(0);
    int returned=io->restore(io->context,&r->restore);r->restore.returned=returned?1:0;paic_actual_order(0);
    if(!returned||r->restore.precondition_error||!r->restore.group_written||!r->restore.daif_written||
       r->restore.daif_before!=0xc0||r->restore.group_before||!r->restore.group_observed||!r->restore.daif_observed||r->restore.daif_read||r->restore.group_read!=1||
       !pwrpc_live(g,r,0,&r->after))return pwrpc_fail(r,PWRPC_RESTORE,1);
    r->outstanding=r->local_mask_held=0;r->local_restored=r->retired=1;paic_actual_order(0);return 1;
}
/* These are real AArch64 instructions, compiled as general-register-only
 * code. Host peers never execute them. No EFI/SMC call is made while masked. */
static inline int pwrpc_actual_affinity(void *ctx,uint64_t target,int64_t *raw)
{
    (void)ctx;
#if defined(__aarch64__) || defined(__arm64__)
    register uint64_t x0 __asm__("x0")=UINT64_C(0xc4000004),x1 __asm__("x1")=target,x2 __asm__("x2")=0,x3 __asm__("x3")=0;
    __asm__ volatile("smc #0":"+r"(x0),"+r"(x1),"+r"(x2),"+r"(x3)::"x4","x5","x6","x7","x8","x9","x10","x11","x12","x13","x14","x15","x16","x17","cc","memory");*raw=(int64_t)x0;return 1;
#else
    (void)target;(void)raw;return 0;
#endif
}
static inline int pwrpc_actual_mask(void *ctx,struct pwrpc_transition *t)
{
    (void)ctx;
#if defined(__aarch64__) || defined(__arm64__)
    uint64_t el,sre;__asm__ volatile("mrs %0,currentel":"=r"(el));
    if(el!=4){t->precondition_error=1;return 1;}
    __asm__ volatile("mrs %0,ICC_SRE_EL1":"=r"(sre));
    if(!(sre&1)||t->target_daif!=0xc0||t->target_group){t->precondition_error=1;return 1;}
    __asm__ volatile("mrs %0,daif; mrs %1,ICC_IGRPEN1_EL1":"=r"(t->daif_before),"=r"(t->group_before));
    if(t->daif_before||t->group_before!=1){t->precondition_error=2;return 1;}
    __asm__ volatile("msr daifset,#3; isb":::"memory");t->daif_written=1;paic_actual_order(0);
    __asm__ volatile("mrs %0,daif":"=r"(t->daif_read));t->daif_observed=1;
    __asm__ volatile("msr ICC_IGRPEN1_EL1,xzr; dsb sy; isb":::"memory");t->group_written=1;paic_actual_order(0);
    __asm__ volatile("mrs %0,ICC_IGRPEN1_EL1":"=r"(t->group_read));t->group_observed=1;return 1;
#else
    (void)t;return 0;
#endif
}
static inline int pwrpc_actual_restore(void *ctx,struct pwrpc_transition *t)
{
    (void)ctx;
#if defined(__aarch64__) || defined(__arm64__)
    uint64_t el,sre;__asm__ volatile("mrs %0,currentel":"=r"(el));
    if(el!=4){t->precondition_error=1;return 1;}
    __asm__ volatile("mrs %0,ICC_SRE_EL1":"=r"(sre));
    if(!(sre&1)||t->target_daif||t->target_group!=1){t->precondition_error=1;return 1;}
    __asm__ volatile("mrs %0,daif; mrs %1,ICC_IGRPEN1_EL1":"=r"(t->daif_before),"=r"(t->group_before));
    if(t->daif_before!=0xc0||t->group_before){t->precondition_error=2;return 1;}
    __asm__ volatile("msr ICC_IGRPEN1_EL1,%0; dsb sy; isb"::"r"(t->target_group):"memory");t->group_written=1;paic_actual_order(0);
    __asm__ volatile("mrs %0,ICC_IGRPEN1_EL1":"=r"(t->group_read));t->group_observed=1;
    __asm__ volatile("msr daif,%0; isb"::"r"(t->target_daif):"memory");t->daif_written=1;paic_actual_order(0);
    __asm__ volatile("mrs %0,daif":"=r"(t->daif_read));t->daif_observed=1;return 1;
#else
    (void)t;return 0;
#endif
}
#endif
#endif
