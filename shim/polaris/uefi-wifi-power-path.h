/* One integrated private-client body: original CmdDb -> source RAM/Device ->
 * masked CPU admission -> bounded transaction -> exact retirement -> original
 * GCD namespace again. No standalone inventory boot or production parent hook.
 * The checked backend is internal to this path; a callback return is delivery,
 * never an ownership grant. Every raw component remains resident. */
#ifndef POLARIS_UEFI_WIFI_POWER_PATH_H
#define POLARIS_UEFI_WIFI_POWER_PATH_H
#include "uefi-wifi-rsc-access.h"
#if EFI_XNU_WIFI_POWER_TRANSACTION_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
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
    struct pwrpb_baseline RAM[3];
    struct pwrmd_result device[2];
    struct pwrpc_result CPU;
    struct pwrsc_transaction transaction;
    struct pwra_result access;
    struct pwra_context access_context;
    struct pwrpt_refusal refusal;
};
struct pwrpt_io {
    struct pwcd_io cmd;struct pwrmd_io device;struct pwrpc_io CPU;struct pwra_io access;
    const struct paic_result *enumeration;uint64_t native_flag;
    struct pwrpt_result *record;
};
enum pwrpt_error {PWRPT_OK,PWRPT_ARGUMENT,PWRPT_CMDDB,PWRPT_RAM,PWRPT_PLAN,PWRPT_DEVICE,
    PWRPT_CPU,PWRPT_ACCESS,PWRPT_TRANSACTION,PWRPT_RESTORE,PWRPT_NAMESPACE};
static inline int pwrpt_unsafe(const struct pwrpt_result *r)
{return r->unknown||(r->attempted&&!r->retired)||pwrpc_unsafe(&r->CPU)||r->access.unknown||r->access.outstanding||r->access.local_held||r->transaction.unknown||r->transaction.outstanding;}
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
static inline int pwrpt_body(void *context,const struct paic_io *memory,struct pwrcl_result *p,
    struct pwrph_work *work,struct pgcd_context *g)
{
    struct pwrpt_io *io=context;struct pwrpt_result *r=io?io->record:0;
    if(!r||r->attempted)return 0;r->attempted=1;
    if(!memory||!p||!work||!g||!io->enumeration||!p->client_held||p->client_returned||p->retired||
       p->unknown||p->outstanding||!pwrph_context_ready(g)||!pgcd_in_self(&p->core,(uintptr_t)r,sizeof(*r))||
       !pwrcl_owned(memory,p,work,(uintptr_t)r,sizeof(*r)))return pwrpt_fail(r,PWRPT_ARGUMENT,1);
    r->provider=(uintptr_t)p;r->core=(uintptr_t)g;r->native_flag=io->native_flag;r->phase=1;
    if(!pwcd_collect(&io->cmd,io->enumeration,g,&r->cmd,work)){
        pwrpt_fail(r,PWRPT_CMDDB,pwcd_unknown(&r->cmd)||pgcd_uncertain(g)||r->cmd.error==PWCD_CHANGED||
            r->cmd.error==PWCD_SOURCE||r->cmd.error==PWCD_OWNER);goto before_mask;
    }
    struct paic_arch normal;
    if(!memory->arch(memory->context,&normal)||!pwrpb_capture(memory,p,work,&p->pools[1][1],&normal,&r->RAM[0])){
        pwrpt_fail(r,PWRPT_RAM,0);goto before_mask;
    }
    if(!pwrpb_plan(&r->RAM[0],r->cmd.resources[1],r->saved,r->desired)){
        pwrpt_fail(r,PWRPT_PLAN,0);goto before_mask;
    }
    if(!pwrmd_collect(&io->device,p,work,g,&r->RAM[0],&r->device[0])){
        pwrpt_fail(r,PWRPT_DEVICE,r->device[0].unknown||r->device[0].outstanding||pgcd_uncertain(g));goto before_mask;
    }
    r->phase=2;
    if(!pwrpc_begin(&io->CPU,memory,p,work,g,io->native_flag,&r->CPU)){
        return pwrpt_fail(r,PWRPT_CPU,1);
    }
    struct paic_arch masked;
    if(!memory->arch(memory->context,&masked)||!pwrpb_capture(memory,p,work,&p->pools[1][1],&masked,&r->RAM[1])||
       !pwrpb_equal(&r->RAM[0],&r->RAM[1]))return pwrpt_fail(r,PWRPT_RAM,1);
    if(!pwra_acquire(&r->access_context,&io->access,g,p,work,&r->CPU,&r->cmd,&r->RAM[0],&r->RAM[1],
       &r->device[0],&r->transaction,&r->access))return pwrpt_fail(r,PWRPT_ACCESS,1);
    const struct pwrsc_io power={&r->access_context,pwra_read,pwra_write,pwra_clock,pwra_order};r->phase=3;
    if(!pwrsc_begin(&power,&r->transaction,r->RAM[1].active_mask,r->saved,r->desired))return pwrpt_fail(r,PWRPT_TRANSACTION,1);
    int result=0;
    for(unsigned k=0;k<256&&!result;k++){r->steps=k+1;result=pwrsc_step(&power,&r->transaction);}
    if(result!=1||!pwrsc_retired(&r->transaction)||!pwra_retire(&r->access_context))return pwrpt_fail(r,PWRPT_TRANSACTION,1);
    r->phase=4;
    if(!pwrpb_capture(memory,p,work,&p->pools[1][1],&masked,&r->RAM[2])||!pwrpb_equal(&r->RAM[1],&r->RAM[2])||
       !pwrpc_end(&io->CPU,memory,p,work,g,&r->transaction,&r->RAM[1],&r->RAM[2],&r->CPU))return pwrpt_fail(r,PWRPT_RESTORE,1);
    if(!pwrmd_collect(&io->device,p,work,g,&r->RAM[2],&r->device[1]))return pwrpt_fail(r,PWRPT_NAMESPACE,1);
    for(unsigned k=0;k<3;k++)if(!pgcd_equal(&r->device[0].GCD[k].descriptor,&r->device[1].GCD[k].descriptor,sizeof(struct pgcd_descriptor)))
        return pwrpt_fail(r,PWRPT_NAMESPACE,1);
    if(pgcd_uncertain(g)||!pwrph_context_ready(g)||pwrpc_unsafe(&r->CPU)||r->access.local_held||!r->access.retired)
        return pwrpt_fail(r,PWRPT_RESTORE,1);
    r->phase=5;r->retired=1;paic_actual_order(0);return 1;
before_mask:
    /* A returned pre-mask refusal has issued no raw RSC write. The original
     * known-client retirement may proceed. Unknown, partial calls or a held
     * mask never reach original Delete or native/PON/receipt. */
    if(r->unknown||pgcd_uncertain(g)||pwrpc_unsafe(&r->CPU)||r->transaction.writes)return 0;
    return pwrpt_refuse_retired(memory,p,work,r);
}
#endif
#endif
