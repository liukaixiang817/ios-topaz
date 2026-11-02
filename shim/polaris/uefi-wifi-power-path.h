/* One integrated private-client body: original CmdDb -> source RAM/Device ->
 * masked CPU admission -> bounded transaction -> exact retirement -> original
 * GCD namespace again. No standalone inventory boot.
 * The checked backend is internal to this path; a callback return is delivery,
 * never an ownership grant. Every raw component remains resident. */
#ifndef POLARIS_UEFI_WIFI_POWER_PATH_H
#define POLARIS_UEFI_WIFI_POWER_PATH_H
#ifndef EFI_XNU_WIFI_ARC_READ_WORK_ADMISSION
#define EFI_XNU_WIFI_ARC_READ_WORK_ADMISSION 0
#endif
#ifndef EFI_XNU_WIFI_PRIVATE_CPU_CHECKPOINT
#define EFI_XNU_WIFI_PRIVATE_CPU_CHECKPOINT 0
#endif
#ifndef EFI_XNU_WIFI_READ_ACCESS_CHECKPOINT
#define EFI_XNU_WIFI_READ_ACCESS_CHECKPOINT 0
#endif
#ifndef EFI_XNU_WIFI_PRE_MASK_ARGUMENTS
#define EFI_XNU_WIFI_PRE_MASK_ARGUMENTS 0
#endif
#ifndef EFI_XNU_WIFI_NORMAL_TO_MASKED_DB
#define EFI_XNU_WIFI_NORMAL_TO_MASKED_DB 0
#endif
#ifndef EFI_XNU_WIFI_CURRENT_WORD_READ
#define EFI_XNU_WIFI_CURRENT_WORD_READ 0
#endif
#ifndef EFI_XNU_WIFI_CURRENT_WORD_VOTE
#define EFI_XNU_WIFI_CURRENT_WORD_VOTE 0
#endif
#include "uefi-wifi-rsc-access.h"
#if EFI_XNU_WIFI_POWER_TRANSACTION_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE && !EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE
#error Current ARC READ requires full prepared/current private binding
#endif
#include "uefi-wifi-cmddb-budget.h"
#include "uefi-wifi-cmddb-staged.h"
#if EFI_XNU_WIFI_PRIVATE_CPU_CHECKPOINT && (!EFI_XNU_WIFI_ARC_READ_WORK_ADMISSION || !EFI_XNU_WIFI_ARC_READ_AVAILABLE || !EFI_XNU_WIFI_ARC_READ_CAPTURE_ONLY || !EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE)
#error Private CPU checkpoint requires the complete current/work admission dependencies
#endif
#if EFI_XNU_WIFI_READ_ACCESS_CHECKPOINT && !EFI_XNU_WIFI_PRIVATE_CPU_CHECKPOINT
#error Read access checkpoint requires the complete same-private CPU checkpoint
#endif
#if EFI_XNU_WIFI_READ_DB_CHECKPOINT && !EFI_XNU_WIFI_READ_ACCESS_CHECKPOINT
#error Database checkpoint requires the complete same-private read observation dependencies
#endif
#if EFI_XNU_WIFI_PRE_MASK_ARGUMENTS
#if !EFI_XNU_WIFI_READ_DB_CHECKPOINT && !EFI_XNU_WIFI_CURRENT_WORD_READ
#error Pre-mask arguments require the full current private database dependencies
#endif
#include "uefi-wifi-pre-mask-arguments.h"
#endif
#if EFI_XNU_WIFI_NORMAL_TO_MASKED_DB && (!EFI_XNU_WIFI_PRE_MASK_ARGUMENTS || !EFI_XNU_WIFI_READ_DB_CHECKPOINT)
#error Normal-to-masked database observation requires fresh normal arguments and full database dependencies
#endif
#if EFI_XNU_WIFI_CURRENT_WORD_VOTE && (!EFI_XNU_WIFI_CURRENT_WORD_READ || EFI_XNU_WIFI_ARC_READ_CAPTURE_ONLY)
#error Current word ARC vote requires its explicit fresh READ dependencies and bounded WRITE path
#endif
#if EFI_XNU_WIFI_CURRENT_WORD_READ && (!EFI_XNU_WIFI_ARC_READ_AVAILABLE || (!EFI_XNU_WIFI_ARC_READ_CAPTURE_ONLY && !EFI_XNU_WIFI_CURRENT_WORD_VOTE) || !EFI_XNU_WIFI_ARC_READ_WORK_ADMISSION || !EFI_XNU_WIFI_PRE_MASK_ARGUMENTS || !EFI_XNU_WIFI_DB_WORD_CAPTURE || !EFI_XNU_WIFI_CPU_LIVE_DIAGNOSTICS || EFI_XNU_WIFI_PRIVATE_CPU_CHECKPOINT || EFI_XNU_WIFI_READ_ACCESS_CHECKPOINT || EFI_XNU_WIFI_READ_DB_CHECKPOINT || EFI_XNU_WIFI_NORMAL_TO_MASKED_DB)
#error Current word READ requires its complete independent dependencies, not an override of a checkpoint
#endif
#if EFI_XNU_WIFI_ARC_READ_WORK_ADMISSION
#if !EFI_XNU_WIFI_ARC_READ_AVAILABLE || (!EFI_XNU_WIFI_ARC_READ_CAPTURE_ONLY && !EFI_XNU_WIFI_CURRENT_WORD_VOTE) || !EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE
#error READ work admission requires the full prepared/current READ path
#endif
/* Retired preparation timing is an estimate, never an authority or new lease.
 * A complete source+head+lock+node+target guard includes a full Core hash.
 * Keep every sample (including the slowest), no new timing context/ticket. */
#define PWRPT_WORK_SAMPLES (PWSP_PHASES*(PWSP_PAGES+1u))
#define PWRPT_WORK_RESERVE UINT64_C(480000) /*25ms for non-hash work, estimate only*/
struct pwrpt_work_sample {uint64_t before,after,ticks;};
struct pwrpt_work {
    uint32_t attempted,error,unknown,complete,admitted,declined,samples,source_units;
    uint64_t preparation,core,ticket,maximum_ticks,hash_ticks,READ_ticks,reserve_ticks;
    uint64_t estimate_ticks,elapsed_ticks,remaining_ticks;
    struct pgcd_arch current;uint32_t native_before,native_after;
    struct pwrpt_work_sample sample[PWRPT_WORK_SAMPLES];
};
#endif
struct pwrpt_refusal {
    uint32_t attempted,retired,hash_count[2],hash_failed[2];
    uint8_t before_global[0x110],before_hashes[2][5][32];
    struct pwrcl_pool pool[2];struct pwrcl_client client;
};
struct pwrpt_result {
    uint32_t attempted,error,unknown,phase,retired,known_refusal;
    uint64_t provider,core,native_flag;
    uint32_t saved[3],desired[3],steps;
    struct pwcd_result cmd;
#if EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE
    struct pwcp_result prepared_cmd;
#endif
    struct pwrpb_baseline RAM[3];
    struct pwrmd_result device[2];
    struct pwrpc_result CPU;
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE
    struct pwrr_transaction read;
#endif
    struct pwrsc_transaction transaction;
    struct pwra_result access;
    struct pwra_context access_context;
    struct pwrpt_refusal refusal;
#if EFI_XNU_WIFI_ARC_READ_WORK_ADMISSION
    struct pwrpt_work work;
#endif
#if EFI_XNU_WIFI_PRE_MASK_ARGUMENTS
    struct pwrpa_result arguments;
#endif
};
#if EFI_XNU_WIFI_PRE_MASK_ARGUMENTS
#if EFI_XNU_WIFI_DB_WORD_CAPTURE
_Static_assert(sizeof(struct pwrpt_result)==1969216,"complete word delivery and byte prefix body");
#elif EFI_XNU_WIFI_CPU_LIVE_DIAGNOSTICS
_Static_assert(sizeof(struct pwrpt_result)==1943840+sizeof(struct pwrpa_result)+48,"complete live-failure diagnostic body");
#else
_Static_assert(sizeof(struct pwrpt_result)==1943840+sizeof(struct pwrpa_result),"full pre-mask argument raw extent");
#endif
#elif EFI_XNU_WIFI_ARC_READ_WORK_ADMISSION
_Static_assert(sizeof(struct pwrpt_result)==1943840,"complete current ARC READ/work admission RAW V3");
#elif EFI_XNU_WIFI_ARC_READ_AVAILABLE
_Static_assert(sizeof(struct pwrpt_result)==1941984,"complete current ARC READ scope raw V1");
#endif
struct pwrpt_io {
    struct pwcd_io cmd;struct pwrmd_io device;struct pwrpc_io CPU;struct pwra_io access;
    const struct paic_result *enumeration;uint64_t native_flag;
    struct pwrpt_result *record;
#if EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE
    const struct pwsp_result *preparation;
#endif
};
enum pwrpt_error {PWRPT_OK,PWRPT_ARGUMENT,PWRPT_CMDDB,PWRPT_RAM,PWRPT_PLAN,PWRPT_DEVICE,
    PWRPT_CPU,PWRPT_ACCESS,PWRPT_TRANSACTION,PWRPT_RESTORE,PWRPT_NAMESPACE,PWRPT_READ_ONLY,PWRPT_WORK,PWRPT_CPU_CHECKPOINT,PWRPT_ACCESS_CHECKPOINT,PWRPT_DATABASE_CHECKPOINT};
#if EFI_XNU_WIFI_PRE_MASK_ARGUMENTS
#define PWRPT_ARGUMENT_CHECKPOINT 16u
#endif
static inline int pwrpt_unsafe(const struct pwrpt_result *r)
{return r->unknown||pwcd_unknown(&r->cmd)||
#if EFI_XNU_WIFI_ARC_READ_WORK_ADMISSION
    r->work.unknown||(r->work.attempted&&!r->work.complete)||
#endif
#if EFI_XNU_WIFI_PRE_MASK_ARGUMENTS
    pwrpa_unsafe(&r->arguments)||
#endif
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE
    (r->read.io.attempted&&!pwrr_retired(&r->read))||
#endif
#if EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE
    pwcp_unsafe(&r->prepared_cmd)||
#endif
    (r->attempted&&!r->retired)||pwrpc_unsafe(&r->CPU)||r->access.unknown||r->access.outstanding||r->access.local_held||r->transaction.unknown||r->transaction.outstanding;}
static inline int pwrpt_fail(struct pwrpt_result *r,unsigned e,int unknown)
{if(!r->error)r->error=e;if(unknown)r->unknown=1;paic_actual_order(0);return 0;}
/* One bounded pure-RAM/source retirement after a RETURNED pre-mask refusal.
 * Not a retry, not power cleanup and never used after UNKNOWN. Keep the old
 * post-Create checkpoint before taking a new one; no source bytes are stripped
 * or overwritten without their own resident copy. Delete still needs the
 * same exact private handle/empty queues and unchanged complete pool. */
static inline int pwrpt_refuse_retired(const struct paic_io *memory,struct pwrcl_result *p,
    struct pwrph_work *work,struct pwrpt_result *r)
{
    struct pwrpt_refusal *s=&r->refusal;
    if(s->attempted||r->unknown||p->unknown||p->outstanding||!p->client_held||r->CPU.local_mask_held||r->transaction.writes)return 0;
    s->attempted=1;pgcd_copy(s->before_global,p->globals[1],sizeof(s->before_global));
    pgcd_copy(s->before_hashes,p->hashes[1],sizeof(s->before_hashes));
    pgcd_copy(s->hash_count,p->hash_count[1],sizeof(s->hash_count));pgcd_copy(s->hash_failed,p->hash_failed[1],sizeof(s->hash_failed));
    if(!pwrcl_source(memory,p,work,1)||!pwrcl_pool_read(memory,p,work,&s->pool[0])||
       !pwrcl_pool_read(memory,p,work,&s->pool[1])||!pgcd_equal(&s->pool[0],&s->pool[1],sizeof(s->pool[0]))||
       !pgcd_equal(&s->pool[1],&p->pools[1][1],sizeof(s->pool[1]))||
       !pwrcl_client_read(memory,p,work,&s->pool[1],(uintptr_t)p->handle_output,1,&s->client)||
       !pgcd_equal(&s->client,&p->created,sizeof(s->client)))return pwrpt_fail(r,PWRPT_RESTORE,1);
    s->retired=r->known_refusal=r->retired=1;paic_actual_order(0);return 1;
}
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE && (EFI_XNU_WIFI_ARC_READ_CAPTURE_ONLY || EFI_XNU_WIFI_CURRENT_WORD_VOTE)
/* This permits ONLY retiring a fully returned normal-IRQ ON/ON_PENDING
 * refusal. It never admits READ, masks a CPU, grants a lease or clears an
 * UNKNOWN. Source/pool/client/namespace must still close in before_mask. */
static inline int pwrpt_cpu_returned_refusal(const struct pwrpt_result *r,struct pgcd_context *g)
{
    const struct pwrpc_result *c=&r->CPU;
    if(c->attempted!=1||c->error!=PWRPC_PSCI||c->unknown||c->outstanding||c->retired!=1||
       c->local_mask_held||c->local_restored||c->masked_issued||c->masked_returned||c->masked_unknown||
       !pwrph_context_ready(g)||!c->source[0].complete||
       !pwra_zero(&c->mask,sizeof(c->mask))||!pwra_zero(&c->restore,sizeof(c->restore))||
       !pwra_zero(&r->read,sizeof(r->read))||!pwra_zero(&r->transaction,sizeof(r->transaction))||
       !pwra_zero(&r->access,sizeof(r->access))||
       !c->affinity_issued||c->affinity_issued>127||
       (c->affinity_issued&(c->affinity_issued+1))||c->affinity_returned!=c->affinity_issued||c->affinity_unknown)
        return 0;
    for(unsigned k=0;k<7;k++)if(c->affinity_issued&(1u<<k)){
        const struct pgcd_service_guard *q=&c->guard[k];
        if(q->entered!=1||q->left!=1||q->foreign_returned!=1||q->unknown||
           q->fp.saved!=1||q->fp.restored!=1||q->TPL_before!=4||q->TPL_after!=4)return 0;
        if(c->affinity_issued>>(k+1)){if(c->affinity[k]!=1)return 0;}
        else if(c->affinity[k]!=0&&c->affinity[k]!=2)return 0;
    }
    return 1;
}
#endif
#if EFI_XNU_WIFI_ARC_READ_WORK_ADMISSION
static inline int pwrpt_work_fail(struct pwrpt_result *r,unsigned error)
{if(!r->work.error)r->work.error=error;r->work.unknown=1;return pwrpt_fail(r,PWRPT_WORK,1);}
/* This SAME private phase already revalidated current namespace, selected
 * bytes, full provider RAM and actual Device mappings. Only reject planning
 * work here. All CPU/READ/source/200ms gates still execute after admission.
 * The counted tail is Core(4+pages), RPMh4, CmdDb3. Count both smaller generic
 * scalar image verifiers as TWO Core units each: 18+pages total. The complete
 * engine50ms and25ms non-hash reserve are included, never deducted or reset.
 * Estimates cannot interrupt a nonreturning firmware service/SMC or prove a
 * physical walltime bound; runtime freshness and UNKNOWN remain mandatory. */
static inline int pwrpt_work_admit(const struct paic_io *memory,struct pwrcl_result *p,
    const struct pwrph_work *w,struct pgcd_context *g,const struct pwsp_result *prepared,
    struct pwrpt_result *r)
{
    struct pwrpt_work *b=&r->work;
    if(!pwra_zero(b,sizeof(*b)))return pwrpt_work_fail(r,1);b->attempted=1;
    b->preparation=(uintptr_t)prepared;b->core=(uintptr_t)g;b->ticket=(uintptr_t)(g?g->ticket:0);
    if(!memory||!p||!w||!g||!prepared||g->record!=&p->core||g->ticket!=&p->core_ticket||
       !pwrph_context_ready(g)||p->core_ticket.spent!=1||p->core_ticket.result!=(uintptr_t)&p->core||
       !p->client_held||p->client_returned||p->retired||p->error||p->unknown||p->outstanding||
       !pgcd_in_self(&p->core,(uintptr_t)b,sizeof(*b))||!pwrcl_owned(memory,p,w,(uintptr_t)b,sizeof(*b))||
       !pgcd_in_self(&p->core,(uintptr_t)prepared,sizeof(*prepared))||!pwrcl_owned(memory,p,w,(uintptr_t)prepared,sizeof(*prepared))||
       !pgcd_in_self(&p->core,r->native_flag,4)||!pwrcl_owned(memory,p,w,r->native_flag,4)||
       r->CPU.attempted||!pwra_zero(&r->CPU,sizeof(r->CPU))||!pwra_zero(&r->read,sizeof(r->read))||
       !pwra_zero(&r->transaction,sizeof(r->transaction))||!pwra_zero(&r->access,sizeof(r->access))||
       !r->prepared_cmd.complete||!r->prepared_cmd.stable||pwcp_unsafe(&r->prepared_cmd)||
       r->prepared_cmd.preparation!=(uintptr_t)prepared||!r->prepared_cmd.pages||r->prepared_cmd.pages>PWCP_PAGES||
       !r->RAM[0].complete||r->RAM[0].error||!r->device[0].complete||r->device[0].unknown||r->device[0].error||
       !prepared->complete||!prepared->retired||pwsp_unsafe(prepared)||prepared->parts!=4||
       prepared->assembled[0]!=PWCD_DB_BYTES||prepared->assembled[1]!=PWCD_DB_BYTES||
       !prepared->parsed[0]||!prepared->parsed[1])return pwrpt_work_fail(r,2);
    b->native_before=*(const volatile uint32_t*)(uintptr_t)r->native_flag;
    if(b->native_before)return pwrpt_work_fail(r,3);
    for(unsigned phase=0;phase<PWSP_PHASES;phase++){
        const struct pwsp_phase *s=&prepared->phase[phase];
        if(!s->complete||!s->retired||!s->reader.closed||s->core.phase!=3||s->core.error||
           s->core.TPL_initial!=4||s->core.TPL_final!=4||!s->context.finished||
           s->after.cpu.ticks<s->core.before.cpu.ticks||s->after.cpu.ticks-s->core.before.cpu.ticks>PGCD_FRESH_TICKS||
           !pwfc_arch_stable(&s->core.before.cpu,&s->after.cpu)||s->after.cpacr!=0x300000||
           s->context.record!=&s->core||s->context.ticket!=&s->ticket||s->ticket.spent!=1||s->ticket.result!=(uintptr_t)&s->core||
           s->after.cpu.ticks>g->record->before.cpu.ticks||s->native_before||s->native_after||s->native_last||
           !s->native_before_valid||!s->native_after_valid)return pwrpt_work_fail(r,4);
        for(unsigned k=0;k<PWSP_PAGES+1;k++){
            const struct pgns_target *t=&s->target[k];
            if(t->attempted!=1||t->complete!=1||t->hash_count!=5||t->hash_failed||
               t->head_bytes!=16||t->lock_bytes!=24||t->node.bytes!=80||
               t->target_AT.issued!=1||t->target_AT.returned!=1||t->target_AT.saved!=t->target_AT.restored||
               t->target_AT.page!=t->page||t->target_AT.par!=(UINT64_C(0xff00000000000b80)|t->page)||
               !pwfc_arch_stable(&s->core.before.cpu,&t->before.cpu)||!pwfc_arch_stable(&s->core.before.cpu,&t->after.cpu)||
               t->before.cpacr!=0x300000||t->after.cpacr!=0x300000||
               t->before.cpu.ticks<s->core.before.cpu.ticks||t->after.cpu.ticks<=t->before.cpu.ticks||
               t->after.cpu.ticks>s->after.cpu.ticks)return pwrpt_work_fail(r,5);
            for(unsigned h=0;h<5;h++)if(!pgcd_equal(t->source_hash[h],pgci_ranges[h].sha256,32))return pwrpt_work_fail(r,6);
            if(b->samples>=PWRPT_WORK_SAMPLES)return pwrpt_work_fail(r,5);
            struct pwrpt_work_sample *sample=&b->sample[b->samples++];
            sample->before=t->before.cpu.ticks;sample->after=t->after.cpu.ticks;sample->ticks=sample->after-sample->before;
            if(sample->ticks>b->maximum_ticks)b->maximum_ticks=sample->ticks;
        }
    }
    if(b->samples!=PWRPT_WORK_SAMPLES||!b->maximum_ticks||!pgcd_live(g,&b->current,0)||
       !pwrcl_fresh(memory,p)||!pgcd_cached_owner_stable(g))return pwrpt_work_fail(r,7);
    b->native_after=*(const volatile uint32_t*)(uintptr_t)r->native_flag;
    if(b->native_after||b->current.cpu.ticks<g->record->before.cpu.ticks)return pwrpt_work_fail(r,8);
    b->source_units=18+r->prepared_cmd.pages;b->READ_ticks=PWRSC_DEADLINE;b->reserve_ticks=PWRPT_WORK_RESERVE;
    if(b->maximum_ticks>(UINT64_MAX-b->READ_ticks-b->reserve_ticks)/b->source_units)return pwrpt_work_fail(r,9);
    b->hash_ticks=b->maximum_ticks*b->source_units;b->estimate_ticks=b->hash_ticks+b->READ_ticks+b->reserve_ticks;
    b->elapsed_ticks=b->current.cpu.ticks-g->record->before.cpu.ticks;
    if(b->elapsed_ticks>PGCD_FRESH_TICKS)return pwrpt_work_fail(r,10);
    b->remaining_ticks=PGCD_FRESH_TICKS-b->elapsed_ticks;
    b->admitted=b->estimate_ticks<=b->remaining_ticks;b->declined=!b->admitted;b->complete=1;paic_actual_order(0);return 1;
}
#if EFI_XNU_WIFI_NORMAL_TO_MASKED_DB || EFI_XNU_WIFI_CURRENT_WORD_READ
/* Retain the original admission as evidence. This pure check neither samples
 * a new clock nor resets its ticket, elapsed time, estimate or decision. */
static inline int pwrpt_work_retained(const struct pwsp_result *prepared,
    const struct pgcd_context *g,const struct pwrpt_result *r)
{
    const struct pwrpt_work *b=&r->work;
    if(!prepared||!g||!g->record||b->attempted!=1||b->complete!=1||b->admitted!=1||
       b->declined||b->error||b->unknown||b->samples!=PWRPT_WORK_SAMPLES||
       b->preparation!=(uintptr_t)prepared||b->core!=(uintptr_t)g||b->ticket!=(uintptr_t)g->ticket||
       !r->prepared_cmd.pages||r->prepared_cmd.pages>PWCP_PAGES||
       b->source_units!=18+r->prepared_cmd.pages||b->native_before||b->native_after||
       b->READ_ticks!=PWRSC_DEADLINE||b->reserve_ticks!=PWRPT_WORK_RESERVE||
       !pwfc_arch_stable(&g->record->before.cpu,&b->current.cpu)||
       b->current.cpacr!=g->record->before.cpacr||
       b->current.cpu.ticks>r->arguments.before.cpu.ticks)return 0;
    uint64_t maximum=0;
    for(unsigned k=0;k<PWRPT_WORK_SAMPLES;k++){
        const struct pwrpt_work_sample *s=&b->sample[k];
        const struct pgns_target *t=&prepared->phase[k/(PWSP_PAGES+1)].target[k%(PWSP_PAGES+1)];
        if(s->before!=t->before.cpu.ticks||s->after!=t->after.cpu.ticks||
           s->after<=s->before||s->ticks!=s->after-s->before)return 0;
        if(s->ticks>maximum)maximum=s->ticks;
    }
    if(!maximum||maximum!=b->maximum_ticks||
       maximum>(UINT64_MAX-b->READ_ticks-b->reserve_ticks)/b->source_units||
       b->hash_ticks!=maximum*b->source_units||
       b->estimate_ticks!=b->hash_ticks+b->READ_ticks+b->reserve_ticks||
       b->elapsed_ticks!=b->current.cpu.ticks-g->record->before.cpu.ticks||
       b->elapsed_ticks>PGCD_FRESH_TICKS||b->remaining_ticks!=PGCD_FRESH_TICKS-b->elapsed_ticks||
       b->estimate_ticks>b->remaining_ticks)return 0;
    return 1;
}
#endif
#endif
#if EFI_XNU_WIFI_PRIVATE_CPU_CHECKPOINT || EFI_XNU_WIFI_CURRENT_WORD_READ
/* No fake completed engine/access record. Before either the diagnostic
 * stop or actual READ admission, keep every unopened lifetime byte zero. */
static inline int pwrpt_checkpoint_zero_engines(const struct pwrpt_result *r)
{
    return pwra_zero(&r->read,sizeof(r->read))&&pwra_zero(&r->transaction,sizeof(r->transaction))&&
       pwra_zero(&r->access,sizeof(r->access))&&pwra_zero(&r->access_context,sizeof(r->access_context));
}
#endif
#if EFI_XNU_WIFI_CURRENT_WORD_READ
/* Retain the original normal observations as observations only. The new
 * masked backend still derives its own full current admission. No timestamp
 * is renewed and no normal record becomes a permission boolean. */
static inline int pwrpt_word_read_arguments(const struct pwrpa_input *arguments,
    const struct pwrcl_result *p,const struct pwrph_work *work,const struct pgcd_context *g,
    struct pwrpt_result *r,const struct pwsp_result *prepared,const struct paic_io *memory)
{
    if(!pwrpa_admitted_prefix(arguments,&r->arguments)||r->arguments.provider!=(uintptr_t)p||
       r->arguments.core!=(uintptr_t)g||r->arguments.ticket!=(uintptr_t)g->ticket||
       r->arguments.memory!=(uintptr_t)memory||r->arguments.work!=(uintptr_t)work||
       r->arguments.native_address!=r->native_flag||
       !pwfc_arch_stable(&g->record->before.cpu,&r->arguments.before.cpu)||
       r->arguments.before.cpacr!=g->record->before.cpacr||
       r->arguments.last.cpu.ticks-g->record->before.cpu.ticks>PGCD_FRESH_TICKS)
        return pwrpt_fail(r,PWRPT_ARGUMENT,1);
    if(!pwrpt_work_retained(prepared,g,r))return pwrpt_work_fail(r,11);
    return 1;
}
#endif
static inline int pwrpt_body(void *context,const struct paic_io *memory,struct pwrcl_result *p,
    struct pwrph_work *work,struct pgcd_context *g)
{
    struct pwrpt_io *io=context;struct pwrpt_result *r=io?io->record:0;
    if(!r||r->attempted)return 0;r->attempted=1;
    if(!memory||!p||!work||!g||!io->enumeration||!p->client_held||p->client_returned||p->retired||
       p->unknown||p->outstanding||!pwrph_context_ready(g)||!pgcd_in_self(&p->core,(uintptr_t)r,sizeof(*r))||
       !pwrcl_owned(memory,p,work,(uintptr_t)r,sizeof(*r)))return pwrpt_fail(r,PWRPT_ARGUMENT,1);
    r->provider=(uintptr_t)p;r->core=(uintptr_t)g;r->native_flag=io->native_flag;r->phase=1;
#if EFI_XNU_WIFI_PRIVATE_CPU_CHECKPOINT || EFI_XNU_WIFI_CURRENT_WORD_READ
    if(!pwrpt_checkpoint_zero_engines(r)||
#if EFI_XNU_WIFI_READ_ACCESS_CHECKPOINT || EFI_XNU_WIFI_CURRENT_WORD_READ
       /* All current readers must be bound to the exact private caller's
        * embedded memory object BEFORE any prepared read or CPU transition.
        * This is argument identity only, never a hardware ownership grant. */
       io->access.memory!=memory||io->device.memory!=memory||io->cmd.namespace_io.memory!=memory||
       io->cmd.original.memory.system!=memory->system||io->cmd.original.memory.context!=memory->context||
       io->cmd.original.memory.arch!=memory->arch||io->cmd.original.memory.identity!=memory->identity||
       io->cmd.original.memory.order!=memory->order||
#if EFI_XNU_WIFI_READ_DB_CHECKPOINT
       io->access.translate||io->access.read||!io->access.RAM_translate||
#endif
       io->access.context!=&r->access_context||
#if EFI_XNU_WIFI_CURRENT_WORD_READ
       !io->access.translate||!io->access.read||!io->access.write||!io->access.RAM_translate||
#else
       io->access.write!=pwra_reject_store||
#endif
#else
       !pwra_zero(&io->access,sizeof(io->access))||
#endif
       0)return pwrpt_fail(r,PWRPT_ARGUMENT,1);
#endif
#if EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE
    /* The physical parent binds the actual typed RAM-AT leaf. No missing
     * callback falls back to naked reads or a caller permission boolean. */
    const struct pwcp_io prepared_io={memory,io->cmd.original.memory.context,io->cmd.original.locate,io->cmd.namespace_io.translate};
    if(!io->preparation||!pwcp_collect(&prepared_io,p,work,g,io->preparation,&r->prepared_cmd)){
        pwrpt_fail(r,PWRPT_CMDDB,1);goto before_mask;
    }
#else
#if EFI_XNU_WIFI_GCD_NAMESPACE_RO_AVAILABLE
    io->cmd.namespace_provider=p;io->cmd.namespace_io.memory=&io->cmd.original.memory;
#endif
    if(!pwcd_collect(&io->cmd,io->enumeration,g,&r->cmd,work)){
        pwrpt_fail(r,PWRPT_CMDDB,pwcd_unknown(&r->cmd)||pgcd_uncertain(g)||r->cmd.error==PWCD_CHANGED||
            r->cmd.error==PWCD_SOURCE||r->cmd.error==PWCD_OWNER);goto before_mask;
    }
#endif
#if EFI_XNU_WIFI_CMDDB_CAPTURE_ONLY && !EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE
    /* Capture-only must always stop through the known-refusal retirement.
     * An unexpected success is unsafe, never permission to enter the writer. */
    return pwrpt_fail(r,PWRPT_CMDDB,1);
#else
#if EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE
    const struct pwcd_resource *resources=r->prepared_cmd.resources[1];
#else
    const struct pwcd_resource *resources=r->cmd.resources[1];
#endif
    struct paic_arch normal;
    if(!memory->arch(memory->context,&normal)||!pwrpb_capture(memory,p,work,&p->pools[1][1],&normal,&r->RAM[0])){
        pwrpt_fail(r,PWRPT_RAM,0);goto before_mask;
    }
#if !EFI_XNU_WIFI_ARC_READ_AVAILABLE
    if(!pwrpb_plan(&r->RAM[0],resources,r->saved,r->desired)){
        pwrpt_fail(r,PWRPT_PLAN,0);goto before_mask;
    }
#endif
    if(!pwrmd_collect(&io->device,p,work,g,&r->RAM[0],&r->device[0])){
        pwrpt_fail(r,PWRPT_DEVICE,r->device[0].unknown||r->device[0].outstanding||pgcd_uncertain(g));goto before_mask;
    }
#if EFI_XNU_WIFI_ARC_READ_WORK_ADMISSION
    if(!pwrpt_work_admit(memory,p,work,g,io->preparation,r))goto before_mask;
    if(!r->work.admitted){pwrpt_fail(r,PWRPT_WORK,0);goto before_mask;}
#endif
#if EFI_XNU_WIFI_PRE_MASK_ARGUMENTS
    /* Exact prospective access objects, not a fabricated masked context.
     * The original normal-only scope stops through full known close. Only
     * the explicit NEW composition below proceeds to fresh masked checks. */
    (void)resources;
    const struct pwrpa_input arguments[PWRPA_OBJECTS]={
        {&r->access_context,sizeof(r->access_context)},{p,sizeof(*p)},
        {&r->CPU,sizeof(r->CPU)},{&r->prepared_cmd,sizeof(r->prepared_cmd)},
        {&r->RAM[0],sizeof(r->RAM[0])},{&r->RAM[1],sizeof(r->RAM[1])},
        {&r->device[0],sizeof(r->device[0])},{&r->read,sizeof(r->read)},
        {&r->access,sizeof(r->access)},{&r->transaction,sizeof(r->transaction)}};
    if(!pwra_zero(&r->CPU,sizeof(r->CPU))||!pwrpt_checkpoint_zero_engines(r)||
       !pwrpa_run(memory,p,work,g,io->native_flag,arguments,io->cmd.namespace_io.context,
           io->cmd.namespace_io.translate,&r->arguments))return pwrpt_fail(r,PWRPT_ARGUMENT,1);
    if(pwrpa_unsafe(&r->arguments)||!r->arguments.complete||
       !pwra_zero(&r->CPU,sizeof(r->CPU))||!pwrpt_checkpoint_zero_engines(r))return pwrpt_fail(r,PWRPT_ARGUMENT,1);
#if EFI_XNU_WIFI_NORMAL_TO_MASKED_DB || EFI_XNU_WIFI_CURRENT_WORD_READ
    /* This boot's normal evidence is not masked admission. Keep its prefix
     * and the same original deadline; all existing CPU/cache/source/DB
     * checks below still run afresh. A returned normal decline closes here. */
    if(r->arguments.declined){pwrpt_fail(r,PWRPT_ARGUMENT_CHECKPOINT,0);goto before_mask;}
    if(!pwrpa_admitted_prefix(arguments,&r->arguments)||
       r->arguments.provider!=(uintptr_t)p||r->arguments.core!=(uintptr_t)g||
       r->arguments.ticket!=(uintptr_t)g->ticket||r->arguments.memory!=(uintptr_t)memory||
       r->arguments.work!=(uintptr_t)work||r->arguments.native_address!=io->native_flag||
       !pwfc_arch_stable(&g->record->before.cpu,&r->arguments.before.cpu)||
       r->arguments.before.cpacr!=g->record->before.cpacr||
       r->arguments.last.cpu.ticks-g->record->before.cpu.ticks>PGCD_FRESH_TICKS)
        return pwrpt_fail(r,PWRPT_ARGUMENT,1);
    if(!pwrpt_work_retained(io->preparation,g,r))return pwrpt_work_fail(r,11);
    /* Charge normal argument observation to the SAME original remaining
     * interval. Preserve the earlier admission and every sample unchanged. */
    if(r->work.estimate_ticks>PGCD_FRESH_TICKS-
       (r->arguments.last.cpu.ticks-g->record->before.cpu.ticks)){
        pwrpt_fail(r,PWRPT_WORK,0);goto before_mask;
    }
#else
    pwrpt_fail(r,PWRPT_ARGUMENT_CHECKPOINT,0);goto before_mask;
#endif
#endif
#if !EFI_XNU_WIFI_PRE_MASK_ARGUMENTS || EFI_XNU_WIFI_NORMAL_TO_MASKED_DB || EFI_XNU_WIFI_CURRENT_WORD_READ
    r->phase=2;
    if(!pwrpc_begin(&io->CPU,memory,p,work,g,io->native_flag,&r->CPU)){
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE && (EFI_XNU_WIFI_ARC_READ_CAPTURE_ONLY || EFI_XNU_WIFI_CURRENT_WORD_VOTE)
        if(pwrpt_cpu_returned_refusal(r,g)){
            pwrpt_fail(r,PWRPT_CPU,0);goto before_mask;
        }
#endif
        return pwrpt_fail(r,PWRPT_CPU,1);
    }
    struct paic_arch masked;
    if(!memory->arch(memory->context,&masked)||!pwrpb_capture(memory,p,work,&p->pools[1][1],&masked,&r->RAM[1])||
       !pwrpb_equal(&r->RAM[0],&r->RAM[1]))return pwrpt_fail(r,PWRPT_RAM,1);
#if EFI_XNU_WIFI_PRIVATE_CPU_CHECKPOINT
    /* Exact stop BEFORE the first checked-access/READ/TCS operation. A real
     * zero-write transaction is passed to the existing CPU end checker; no
     * attempted/finished/retired bit is forged for an unexecuted engine. */
    (void)resources;
    if(!pwrpt_checkpoint_zero_engines(r))return pwrpt_fail(r,PWRPT_RESTORE,1);
#if EFI_XNU_WIFI_READ_ACCESS_CHECKPOINT
#if EFI_XNU_WIFI_READ_DB_CHECKPOINT
    /* Complete two fresh masked RAM copies, BEFORE any checked RSC/MMIO
     * access. No acquisition/held/retired state is fabricated for that
     * unopened access lifetime; enclosing CPU/private retirement follows. */
    if(!pwra_prepare_checked(&r->access_context,&io->access,g,p,work,&r->CPU,0,&r->RAM[0],&r->RAM[1],
       &r->device[0],&r->read.io,&r->access,&r->prepared_cmd,&r->read,&r->transaction)||
       !pwra_observe_database_close(&r->access_context))return pwrpt_fail(r,PWRPT_ACCESS,1);
#if EFI_XNU_WIFI_NORMAL_TO_MASKED_DB
    if(!pwrpa_admitted_prefix(arguments,&r->arguments)||
       r->arguments.provider!=(uintptr_t)p||r->arguments.core!=(uintptr_t)g||
       r->arguments.ticket!=(uintptr_t)g->ticket||r->arguments.memory!=(uintptr_t)memory||
       r->arguments.work!=(uintptr_t)work||r->arguments.native_address!=io->native_flag||
       !pwfc_arch_stable(&g->record->before.cpu,&r->arguments.before.cpu)||
       r->arguments.before.cpacr!=g->record->before.cpacr||
       r->arguments.last.cpu.ticks-g->record->before.cpu.ticks>PGCD_FRESH_TICKS)
        return pwrpt_fail(r,PWRPT_ARGUMENT,1);
    if(!pwrpt_work_retained(io->preparation,g,r))return pwrpt_work_fail(r,11);
#endif
    r->phase=3;pwrpt_fail(r,PWRPT_DATABASE_CHECKPOINT,0);
#else
    if(!pwra_acquire_read(&r->access_context,&io->access,g,p,work,&r->CPU,&r->prepared_cmd,&r->RAM[0],&r->RAM[1],
       &r->device[0],&r->read,&r->transaction,&r->access)||!pwra_retire_observation(&r->access_context))return pwrpt_fail(r,PWRPT_ACCESS,1);
    r->phase=3;pwrpt_fail(r,PWRPT_ACCESS_CHECKPOINT,0);
#endif
#else
    r->phase=3;pwrpt_fail(r,PWRPT_CPU_CHECKPOINT,0);
#endif
#else
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE
    if(!pwra_acquire_read(&r->access_context,&io->access,g,p,work,&r->CPU,&r->prepared_cmd,&r->RAM[0],&r->RAM[1],
       &r->device[0],&r->read,&r->transaction,&r->access))return pwrpt_fail(r,PWRPT_ACCESS,1);
#if EFI_XNU_WIFI_CURRENT_WORD_READ
    if(!pwrpt_word_read_arguments(arguments,p,work,g,r,io->preparation,memory))return 0;
#endif
#elif EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE
    if(!pwra_acquire_prepared(&r->access_context,&io->access,g,p,work,&r->CPU,&r->prepared_cmd,&r->RAM[0],&r->RAM[1],
       &r->device[0],&r->transaction,&r->access))return pwrpt_fail(r,PWRPT_ACCESS,1);
#else
    if(!pwra_acquire(&r->access_context,&io->access,g,p,work,&r->CPU,&r->cmd,&r->RAM[0],&r->RAM[1],
       &r->device[0],&r->transaction,&r->access))return pwrpt_fail(r,PWRPT_ACCESS,1);
#endif
    const struct pwrsc_io power={&r->access_context,pwra_read,pwra_write,pwra_clock,pwra_order};r->phase=3;
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE
    if(!pwrr_begin(&power,&r->read,r->RAM[1].active_mask))return pwrpt_fail(r,PWRPT_TRANSACTION,1);
    int read_result=0;
    for(unsigned k=0;k<256&&!read_result;k++)read_result=pwrr_step(&power,&r->read);
    if(read_result!=1||!pwrr_retired(&r->read))return pwrpt_fail(r,PWRPT_TRANSACTION,1);
#if EFI_XNU_WIFI_ARC_READ_CAPTURE_ONLY
    (void)resources;
    /* This first actual READ scope deliberately does not label a RAW word
     * a known per-DRV ARC level. Retire the complete real transaction and
     * restore CPU/source/namespace without making any resource WRITE. */
    if(!pwra_retire(&r->access_context))return pwrpt_fail(r,PWRPT_RESTORE,1);
    pwrpt_fail(r,PWRPT_READ_ONLY,0);goto power_retired;
#else
    if(r->read.io.steps>252||!pwrr_plan(&r->RAM[1],resources,&r->read,r->saved,r->desired)){
        /* RAW responses without a usable ARC interpretation do not become
         * votes. A fully retired READ can close through the exact same
         * RAM/source/CPU/namespace restoration, with WRITE entirely unused. */
        if(!pwra_retire(&r->access_context))return pwrpt_fail(r,PWRPT_RESTORE,1);
        pwrpt_fail(r,PWRPT_PLAN,0);goto power_retired;
    }
    if(!pwra_bind_write(&r->access_context))return pwrpt_fail(r,PWRPT_ACCESS,1);
#endif
#endif
#if !EFI_XNU_WIFI_ARC_READ_AVAILABLE || !EFI_XNU_WIFI_ARC_READ_CAPTURE_ONLY
    if(!pwrsc_begin(&power,&r->transaction,r->RAM[1].active_mask,r->saved,r->desired))return pwrpt_fail(r,PWRPT_TRANSACTION,1);
    int result=0;
    for(unsigned k=0;k<256&&!result;k++){
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE
        if(k+r->read.io.steps==256)break;
#endif
        r->steps=k+1;result=pwrsc_step(&power,&r->transaction);
    }
    if(result!=1||!pwrsc_retired(&r->transaction)||!pwra_retire(&r->access_context))return pwrpt_fail(r,PWRPT_TRANSACTION,1);
#endif
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE
power_retired:
#endif
#endif
#if EFI_XNU_WIFI_CURRENT_WORD_READ
    if(!pwrpt_word_read_arguments(arguments,p,work,g,r,io->preparation,memory))return 0;
#endif
    r->phase=4;
    if(!pwrpb_capture(memory,p,work,&p->pools[1][1],&masked,&r->RAM[2])||!pwrpb_equal(&r->RAM[1],&r->RAM[2])||
#if EFI_XNU_WIFI_PRIVATE_CPU_CHECKPOINT
       !pwrpc_end_checked(&io->CPU,memory,p,work,g,&r->transaction,&r->RAM[1],&r->RAM[2],&r->CPU,0))
        return pwrpt_fail(r,PWRPT_RESTORE,1);
#elif EFI_XNU_WIFI_ARC_READ_AVAILABLE
       !pwrpc_end_checked(&io->CPU,memory,p,work,g,&r->transaction,&r->RAM[1],&r->RAM[2],&r->CPU,&r->read))return pwrpt_fail(r,PWRPT_RESTORE,1);
#else
       !pwrpc_end(&io->CPU,memory,p,work,g,&r->transaction,&r->RAM[1],&r->RAM[2],&r->CPU))return pwrpt_fail(r,PWRPT_RESTORE,1);
#endif
    if(!pwrmd_collect(&io->device,p,work,g,&r->RAM[2],&r->device[1]))return pwrpt_fail(r,PWRPT_NAMESPACE,1);
    for(unsigned k=0;k<3;k++)if(!pgcd_equal(&r->device[0].GCD[k].descriptor,&r->device[1].GCD[k].descriptor,sizeof(struct pgcd_descriptor)))
        return pwrpt_fail(r,PWRPT_NAMESPACE,1);
#if EFI_XNU_WIFI_PRIVATE_CPU_CHECKPOINT
    if(
#if EFI_XNU_WIFI_READ_ACCESS_CHECKPOINT
       !pwra_zero(&r->read,sizeof(r->read))||!pwra_zero(&r->transaction,sizeof(r->transaction))||
#if EFI_XNU_WIFI_READ_DB_CHECKPOINT
       r->access.acquired||r->access.retired||r->access.local_held||r->access.events||r->access.reads||r->access.writes||
       !pwra_observed_databases_valid(&r->access_context)||
#else
       !r->access.retired||r->access.local_held||
#endif
       r->access.error||r->access.unknown||r->access.outstanding||
#else
       !pwrpt_checkpoint_zero_engines(r)||
#endif
       !pgcd_equal(r->device[0].config,r->device[1].config,sizeof(r->device[0].config))||
       !pgcd_equal(r->device[0].IRQ_enable,r->device[1].IRQ_enable,sizeof(r->device[0].IRQ_enable))||
       !pgcd_equal(r->device[0].IRQ_status,r->device[1].IRQ_status,sizeof(r->device[0].IRQ_status))||
       !pgcd_equal(r->device[0].tcs,r->device[1].tcs,sizeof(r->device[0].tcs)))return pwrpt_fail(r,PWRPT_RESTORE,1);
#endif
    if(pgcd_uncertain(g)||!pwrph_context_ready(g)||pwrpc_unsafe(&r->CPU)||
#if !EFI_XNU_WIFI_PRIVATE_CPU_CHECKPOINT
       r->access.local_held||!r->access.retired||
#endif
       0)return pwrpt_fail(r,PWRPT_RESTORE,1);
#if EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE
    if(!pwcp_finish(&prepared_io,p,work,g,io->preparation,&r->prepared_cmd)||!r->prepared_cmd.closed)return pwrpt_fail(r,PWRPT_NAMESPACE,1);
#endif
#if EFI_XNU_WIFI_NORMAL_TO_MASKED_DB || EFI_XNU_WIFI_CURRENT_WORD_READ
    if(!pwrpa_admitted_prefix(arguments,&r->arguments)||
       r->arguments.provider!=(uintptr_t)p||r->arguments.core!=(uintptr_t)g||
       r->arguments.ticket!=(uintptr_t)g->ticket||r->arguments.memory!=(uintptr_t)memory||
       r->arguments.work!=(uintptr_t)work||r->arguments.native_address!=io->native_flag||
       !pwfc_arch_stable(&g->record->before.cpu,&r->arguments.before.cpu)||
       r->arguments.before.cpacr!=g->record->before.cpacr||
       r->arguments.last.cpu.ticks-g->record->before.cpu.ticks>PGCD_FRESH_TICKS)
        return pwrpt_fail(r,PWRPT_ARGUMENT,1);
    if(!pwrpt_work_retained(io->preparation,g,r))return pwrpt_work_fail(r,11);
#endif
    r->phase=5;r->retired=1;
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE
    if(r->error==PWRPT_PLAN||r->error==PWRPT_READ_ONLY
#if EFI_XNU_WIFI_PRIVATE_CPU_CHECKPOINT
       ||r->error==PWRPT_CPU_CHECKPOINT
#if EFI_XNU_WIFI_READ_ACCESS_CHECKPOINT
       ||r->error==PWRPT_ACCESS_CHECKPOINT
#if EFI_XNU_WIFI_READ_DB_CHECKPOINT
       ||r->error==PWRPT_DATABASE_CHECKPOINT
#endif
#endif
#endif
       )r->known_refusal=1;
#endif
    paic_actual_order(0);return 1;
#endif
#endif /* This scope cannot enter CPU/masked access or an engine. */
before_mask:
    /* A returned pre-mask refusal has issued no raw RSC write. The original
     * known-client retirement may proceed. Unknown, partial calls or a held
     * mask never reach original Delete or native/PON/receipt. */
    if(r->unknown||pgcd_uncertain(g)||pwrpc_unsafe(&r->CPU)||r->transaction.writes)return 0;
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE
    if(r->read.io.writes)return 0;
#endif
#if EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE
    if(r->prepared_cmd.complete&&!r->prepared_cmd.closed&&
       !pwcp_finish(&prepared_io,p,work,g,io->preparation,&r->prepared_cmd))return pwrpt_fail(r,PWRPT_NAMESPACE,1);
#endif
    return pwrpt_refuse_retired(memory,p,work,r);
}
/* New parent uses this whole record, never the old ZERO_VOTE scope label. */
static struct pwrpt_result pwrpt_record;
static inline int pwrpt_parent_unsafe(void)
{return pwbd_parent_unsafe()||pwrpt_unsafe(&pwrpt_record)||pwrcl_unsafe()
#if EFI_XNU_WIFI_CMDDB_STAGED_RO_AVAILABLE
    ||pwsp_unsafe(&pwsp_record)
#endif
    ;}
static inline void pwrpt_preboot(const struct paic_io *memory,const struct paic_result *enumeration,
    unsigned stage,struct pgcd_context *final,const volatile uint32_t *native_cpu_on)
{
#if EFI_XNU_WIFI_CMDDB_STAGED_RO_AVAILABLE
    const struct pwsp_io staged={memory,0,pwrph_actual_locate,pgns_actual_translate};
    (void)pwsp_run(&staged,enumeration,stage,final,native_cpu_on,&pwsp_record);
#if EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE
    if(!pwsp_record.complete||!pwsp_record.retired||pwsp_record.error||pwsp_unsafe(&pwsp_record))return;
    const struct pwrcl_io client={{*memory,pwrph_actual_locate,pwrph_actual_map},pwrcl_actual_create,pwrcl_actual_drop,pwrcl_name};
    struct pwrpt_io io={.cmd={.original=client.reader,.query=0,
        .namespace_io={&client.reader.memory,0,pgns_actual_translate}},
        .device={&client.reader.memory,0,pwrmd_actual_translate,pwrmd_actual_read},
#if EFI_XNU_WIFI_PRE_MASK_ARGUMENTS && !EFI_XNU_WIFI_NORMAL_TO_MASKED_DB && !EFI_XNU_WIFI_CURRENT_WORD_READ
        .CPU={0},
#else
        .CPU={0,pwrpc_actual_affinity,pwrpc_actual_mask,pwrpc_actual_restore},
#endif
#if EFI_XNU_WIFI_READ_ACCESS_CHECKPOINT
        /* pwrcl_run_body passes its own copied reader.memory to the body.
         * Bind that exact live object; equal entry-copy contents are not
         * pointer identity and must not relax the body's admission gate. */
        .access=pwra_observation_io(&client.reader.memory,&pwrpt_record.access_context),
#elif EFI_XNU_WIFI_PRIVATE_CPU_CHECKPOINT
        .access={0},
#else
        .access=pwra_physical_io(&client.reader.memory,&pwrpt_record.access_context),
#endif
        .enumeration=enumeration,.native_flag=(uintptr_t)native_cpu_on,.record=&pwrpt_record,.preparation=&pwsp_record};
    (void)pwrcl_run_body(&client,enumeration,stage,final,&pwrcl_early_context,&pwrcl_record,&pwrcl_work,pwrpt_body,&io);
#endif
#else
#if EFI_XNU_WIFI_CMDDB_BUDGET_ADMISSION
    /* Never stage over an old/held client or reuse its context/ticket. A
     * clean budget decline is not permission to retry with another policy. */
    if(pwrcl_record.attempted||pwrcl_unsafe()||pwrpt_record.attempted){
        (void)pwbd_fail(&pwbd_record,PWBD_ARGUMENT);return;
    }
    if(!pwbd_run(final,stage,&pwbd_record)||!pwbd_record.admitted)return;
#endif
    const struct pwrcl_io client={{*memory,pwrph_actual_locate,pwrph_actual_map},pwrcl_actual_create,pwrcl_actual_drop,pwrcl_name};
#if EFI_XNU_WIFI_CMDDB_CAPTURE_ONLY
    struct pwrpt_io io={.cmd={.original={*memory,pwrph_actual_locate,pwrph_actual_map},.query=0},
        .enumeration=enumeration,.native_flag=(uintptr_t)native_cpu_on,.record=&pwrpt_record};
#if EFI_XNU_WIFI_GCD_NAMESPACE_RO_AVAILABLE
    io.cmd.namespace_io.translate=pgns_actual_translate;
#endif
#else
    struct pwrpt_io io={{{*memory,pwrph_actual_locate,pwrph_actual_map},pwcd_actual_query},
        {memory,0,pwrmd_actual_translate,pwrmd_actual_read},
        {0,pwrpc_actual_affinity,pwrpc_actual_mask,pwrpc_actual_restore},
        pwra_physical_io(memory,&pwrpt_record.access_context),enumeration,(uintptr_t)native_cpu_on,&pwrpt_record};
#endif
    (void)pwrcl_run_body(&client,enumeration,stage,final,&pwrcl_early_context,&pwrcl_record,&pwrcl_work,pwrpt_body,&io);
#endif
}
static inline void pwrpt_raw_hex(void (*append)(const char *),const void *raw,size_t bytes)
{
    const uint8_t *p=raw;char chunk[127];
    for(size_t at=0;at<bytes;){unsigned n=(unsigned)(bytes-at);if(n>63)n=63;
        for(unsigned k=0;k<n;k++){chunk[k*2]="0123456789abcdef"[p[at+k]>>4];chunk[k*2+1]="0123456789abcdef"[p[at+k]&15];}
        chunk[n*2]=0;append(chunk);at+=n;}
}
static inline void pwrpt_report(void (*append)(const char *))
{
#if EFI_XNU_WIFI_CMDDB_STAGED_RO_AVAILABLE
    append("WIFI_CMDDB_STAGED_RO_RAW_V1_BEGIN\r\n");pwrpt_raw_hex(append,&pwsp_record,sizeof(pwsp_record));
    append("\r\nWIFI_CMDDB_STAGED_RO_RAW_V1_END\r\n");
#if EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE
    append("WIFI_POWER_CLIENT_RAW_V1_BEGIN\r\n");pwrpt_raw_hex(append,&pwrcl_record,sizeof(pwrcl_record));
    append("\r\nWIFI_POWER_CLIENT_RAW_V1_END\r\n");
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE
#if EFI_XNU_WIFI_ARC_READ_CAPTURE_ONLY
#if EFI_XNU_WIFI_CURRENT_WORD_READ
    append("WIFI_CURRENT_PRIVATE_WORD_READ_RAW_V3_BEGIN\r\n");pwrpt_raw_hex(append,&pwrpt_record,sizeof(pwrpt_record));
    append("\r\nWIFI_CURRENT_PRIVATE_WORD_READ_RAW_V3_END\r\n");
#elif EFI_XNU_WIFI_READ_ACCESS_CHECKPOINT
#if EFI_XNU_WIFI_PRE_MASK_ARGUMENTS
#if EFI_XNU_WIFI_DB_WORD_CAPTURE
    append("WIFI_CURRENT_PRIVATE_DB_WORD_CAPTURE_RAW_V1_BEGIN\r\n");pwrpt_raw_hex(append,&pwrpt_record,sizeof(pwrpt_record));
    append("\r\nWIFI_CURRENT_PRIVATE_DB_WORD_CAPTURE_RAW_V1_END\r\n");
#elif EFI_XNU_WIFI_CPU_LIVE_DIAGNOSTICS
    append("WIFI_CURRENT_PRIVATE_CPU_LIVE_DIAGNOSTIC_RAW_V1_BEGIN\r\n");pwrpt_raw_hex(append,&pwrpt_record,sizeof(pwrpt_record));
    append("\r\nWIFI_CURRENT_PRIVATE_CPU_LIVE_DIAGNOSTIC_RAW_V1_END\r\n");
#elif EFI_XNU_WIFI_NORMAL_TO_MASKED_DB
    append("WIFI_CURRENT_PRIVATE_NORMAL_TO_MASKED_DB_RAW_V1_BEGIN\r\n");pwrpt_raw_hex(append,&pwrpt_record,sizeof(pwrpt_record));
    append("\r\nWIFI_CURRENT_PRIVATE_NORMAL_TO_MASKED_DB_RAW_V1_END\r\n");
#else
    append("WIFI_CURRENT_PRIVATE_PRE_MASK_ARGUMENT_RAW_V1_BEGIN\r\n");pwrpt_raw_hex(append,&pwrpt_record,sizeof(pwrpt_record));
    append("\r\nWIFI_CURRENT_PRIVATE_PRE_MASK_ARGUMENT_RAW_V1_END\r\n");
#endif
#else
#if EFI_XNU_WIFI_READ_DB_CHECKPOINT
    append("WIFI_CURRENT_PRIVATE_MASKED_DB_OBSERVATION_RAW_V1_BEGIN\r\n");pwrpt_raw_hex(append,&pwrpt_record,sizeof(pwrpt_record));
    append("\r\nWIFI_CURRENT_PRIVATE_MASKED_DB_OBSERVATION_RAW_V1_END\r\n");
#else
    append("WIFI_CURRENT_PRIVATE_ACCESS_OBSERVATION_RAW_V1_BEGIN\r\n");pwrpt_raw_hex(append,&pwrpt_record,sizeof(pwrpt_record));
    append("\r\nWIFI_CURRENT_PRIVATE_ACCESS_OBSERVATION_RAW_V1_END\r\n");
#endif
#endif
#elif EFI_XNU_WIFI_PRIVATE_CPU_CHECKPOINT
    append("WIFI_CURRENT_PRIVATE_CPU_CHECKPOINT_RAW_V1_BEGIN\r\n");pwrpt_raw_hex(append,&pwrpt_record,sizeof(pwrpt_record));
    append("\r\nWIFI_CURRENT_PRIVATE_CPU_CHECKPOINT_RAW_V1_END\r\n");
#elif EFI_XNU_WIFI_ARC_READ_WORK_ADMISSION
    append("WIFI_CURRENT_ARC_READ_RAW_V3_BEGIN\r\n");pwrpt_raw_hex(append,&pwrpt_record,sizeof(pwrpt_record));
    append("\r\nWIFI_CURRENT_ARC_READ_RAW_V3_END\r\n");
#else
    append("WIFI_CURRENT_ARC_READ_RAW_V2_BEGIN\r\n");pwrpt_raw_hex(append,&pwrpt_record,sizeof(pwrpt_record));
    append("\r\nWIFI_CURRENT_ARC_READ_RAW_V2_END\r\n");
#endif
#if EFI_XNU_WIFI_PRIVATE_CPU_CHECKPOINT
#if EFI_XNU_WIFI_READ_ACCESS_CHECKPOINT
#if EFI_XNU_WIFI_READ_DB_CHECKPOINT
    append("WIFI_CURRENT_PRIVATE_ACCESS_SCOPE=TWO_FULL_MASKED_CURRENT_CMDDB_RAM_OBSERVATIONS_CLOSE_CPU_SOURCE_NAMESPACE_DELETE_BEFORE_FIRST_MASKED_RSC_MMIO_READ_NO_ACQUIRED_HELD_RETIRED_ACCESS_NO_ENGINE_NO_STORE_NO_HARDWARE_GRANT\r\n");
#else
    append("WIFI_CURRENT_PRIVATE_ACCESS_SCOPE=SAME_PRIVATE_EMBEDDED_CALLER_ARGUMENT_IDENTITY_FULL_CURRENT_CMDDB_AND_CHECKED_RSC_GEOMETRY_READS_COMPLETE_RETIRE_CPU_RESTORE_DELETE_NO_ENGINE_NO_TCS_STORE_NO_READ_REQUEST_NO_HARDWARE_GRANT\r\n");
#endif
#else
    append("WIFI_CURRENT_PRIVATE_CPU_SCOPE=SAME_REAL_PRIVATE_CURRENT_NAMESPACE_RAM_DEVICE_MASKED_CPU_EXACT_RESTORE_DELETE_BEFORE_FIRST_TCS_STORE_NO_ACCESS_CALLBACK_NO_READ_NO_VOTE_NO_HARDWARE_GRANT\r\n");
#endif
#else
    append("WIFI_CURRENT_ARC_READ_SCOPE=THREE_SINGLE_COMMAND_READS_COMPLETE_TCS_RW_RESTORE_SOURCE_CPU_NAMESPACE_DELETE RAW_WORDS_ONLY_NO_RESOURCE_WRITE_NO_MSS_NO_NV_SERVE_NO_RADIO_PERMISSION\r\n");
#endif
#else
#if EFI_XNU_WIFI_CURRENT_WORD_VOTE
    append("WIFI_CURRENT_PRIVATE_WORD_ARC_VOTE_RAW_V1_BEGIN\r\n");pwrpt_raw_hex(append,&pwrpt_record,sizeof(pwrpt_record));
    append("\r\nWIFI_CURRENT_PRIVATE_WORD_ARC_VOTE_RAW_V1_END\r\n");
    append("WIFI_CURRENT_WORD_ARC_VOTE_SCOPE=FRESH_HLOS_DRV2_READ_MAX_SAVED_TARGET_CX_MX_MSS_REVERSE_SAVED_RESTORE_COMBINED50MS_FULL_RW_CPU_SOURCE_NAMESPACE_DELETE_NO_VRM_MSS_NV_SERVE_RADIO_GRANT\r\n");
#else
    append("WIFI_CURRENT_ARC_POWER_RAW_V1_BEGIN\r\n");pwrpt_raw_hex(append,&pwrpt_record,sizeof(pwrpt_record));
    append("\r\nWIFI_CURRENT_ARC_POWER_RAW_V1_END\r\n");
#endif
#endif
#else
    append("WIFI_PREPARED_POWER_RAW_V1_BEGIN\r\n");pwrpt_raw_hex(append,&pwrpt_record,sizeof(pwrpt_record));
    append("\r\nWIFI_PREPARED_POWER_RAW_V1_END\r\n");
#endif
#if EFI_XNU_WIFI_PRIVATE_CPU_CHECKPOINT
#if EFI_XNU_WIFI_READ_ACCESS_CHECKPOINT
#if EFI_XNU_WIFI_READ_DB_CHECKPOINT
    append("WIFI_POWER_SCOPE=SAME_PRIVATE_FULL_CURRENT_MASKED_CMDDB_RAM_OBSERVATION_CPU_SOURCE_NAMESPACE_DELETE_BEFORE_FIRST_MASKED_RSC_MMIO_READ_NO_ACCESS_ACQUISITION_NO_ENGINE_NO_HARDWARE_GRANT_NO_MSS_NO_NV_SERVE\r\n");
#else
    append("WIFI_POWER_SCOPE=SAME_PRIVATE_CURRENT_NAMESPACE_RAM_DEVICE_CPU_FULL_CMDDB_CHECKED_READ_ACCESS_RETIRE_RESTORE_DELETE_NO_TCS_STORE_NO_READ_REQUEST_NO_HARDWARE_GRANT_NO_MSS_NO_NV_SERVE\r\n");
#endif
#else
    append("WIFI_POWER_SCOPE=FULL_RO_PREPARATION_THEN_SAME_KNOWN_PRIVATE_CURRENT_NAMESPACE_DEVICE_CPU_EXACT_RESTORE_DELETE_NO_RSC_ACCESS_NO_QUERY_API_NO_HARDWARE_GRANT_NO_MSS_NO_NV_SERVE\r\n");
#endif
#else
    append("WIFI_POWER_SCOPE=FULL_RO_PREPARATION_THEN_SAME_KNOWN_PRIVATE_CURRENT_ARC_NAMESPACE_CPU_RSC_COMPLETION_SAVED_RESTORE_DELETE NO_QUERY_API NOT_SECURE_GRANT NO_MSS NO_NV_SERVE NO_RADIO_PERMISSION\r\n");
#endif
#else
    append("WIFI_POWER_SCOPE=FOUR_COMPLETED_RO_PREPARATION_PHASES_TWO_FULL_DB_COPIES_NO_PRIVATE_CLIENT_NO_QUERY_NO_CRITICAL_PSCI_NO_RSC NOT_CONTINUOUS_HARDWARE_LEASE NO_MSS NO_NV_SERVE NO_RADIO_PERMISSION\r\n");
#endif
#else
#if EFI_XNU_WIFI_CMDDB_BUDGET_ADMISSION
    append("WIFI_CMDDB_WORK_ADMISSION_RAW_V1_BEGIN\r\n");pwrpt_raw_hex(append,&pwbd_record,sizeof(pwbd_record));
    append("\r\nWIFI_CMDDB_WORK_ADMISSION_RAW_V1_END\r\n");
    append("WIFI_CMDDB_WORK_ADMISSION_SCOPE=INDEPENDENT_COMPLETED_RO_CONTEXT_BEFORE_PRIVATE_CLIENT ESTIMATE_ONLY_NO_DEADLINE_RENEWAL_NO_OWNERSHIP_GRANT\r\n");
#endif
    append("WIFI_POWER_CLIENT_RAW_V1_BEGIN\r\n");pwrpt_raw_hex(append,&pwrcl_record,sizeof(pwrcl_record));
    append("\r\nWIFI_POWER_CLIENT_RAW_V1_END\r\n");
#if EFI_XNU_WIFI_GCD_NAMESPACE_RO_AVAILABLE
    append("WIFI_POWER_PATH_RAW_V2_BEGIN\r\n");
#else
    append("WIFI_POWER_PATH_RAW_V1_BEGIN\r\n");
#endif
    pwrpt_raw_hex(append,&pwrpt_record,sizeof(pwrpt_record));
#if EFI_XNU_WIFI_GCD_NAMESPACE_RO_AVAILABLE
    append("\r\nWIFI_POWER_PATH_RAW_V2_END\r\n");
#if EFI_XNU_WIFI_CMDDB_FIRST_NODE_STOP
    append("WIFI_POWER_SCOPE=FIRST_CORE_NODE_PLANNED_STOP_PARTIAL_NAMESPACE_NO_DATABASE_LOAD_NO_QUERY_NO_CPU_CRITICAL_NO_RSC NO_MSS NO_NV_SERVE NO_RADIO_PERMISSION\r\n");
#else
    append("WIFI_POWER_SCOPE=CMDDB_CAPTURE_BOUNDED_CORE_RAM_NAMESPACE_NO_ORIGINAL_GCD_QUERY_NO_CPU_CRITICAL_NO_RSC NO_MSS NO_NV_SERVE NO_RADIO_PERMISSION\r\n");
#endif
#else
    append("\r\nWIFI_POWER_PATH_RAW_V1_END\r\n");
#if EFI_XNU_WIFI_CMDDB_CAPTURE_ONLY
    append("WIFI_POWER_SCOPE=CMDDB_CAPTURE_ONLY_PLANNED_STOP_NO_QUERY_API_NO_CPU_CRITICAL_NO_RSC NO_MSS NO_NV_SERVE NO_RADIO_PERMISSION\r\n");
#else
    append("WIFI_POWER_SCOPE=PRE_FINAL_GCD_PRIVATE_BOUNDED_ARC_FULL_RETIREMENT NO_MSS NO_NV_SERVE NO_RADIO_PERMISSION\r\n");
#endif
#endif
#endif
}
#endif
#endif
