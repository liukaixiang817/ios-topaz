/* Actual staged MBA -> own MSS15 RW MP_ASSIGN caller, default OFF.
 * Exact independent1MiB allocation; descriptor page remains HLOS-owned.
 * No MBA target read/write/cache after assignment starts, no reset/power,
 * publication/free/handback, and no secure-return inference from DMA state. */
#ifndef POLARIS_UEFI_MSS_MBA_SHARE_H
#define POLARIS_UEFI_MSS_MBA_SHARE_H
#ifndef EFI_XNU_MSS_MBA_SHARE_AVAILABLE
#define EFI_XNU_MSS_MBA_SHARE_AVAILABLE 0
#endif
#if EFI_XNU_MSS_MBA_SHARE_AVAILABLE
#if !EFI_XNU_MSS_STAGING_AVAILABLE || !EFI_XNU_WIFI_MEM_ASSIGN_AVAILABLE || defined(POLARIS_EFI_TEST_QEMU)
#error "MBA assignment requires actual staging and separately enabled native secure leaf"
#endif
#include "uefi-mss-stage.h"
#include "uefi-wifi-cpu-local-mask.h"
#include "../../tools/polaris-wifi-mem-transaction.h"
struct pmsb_peer {uint64_t target;int64_t raw;uint32_t issued,returned;};
struct pmsb_result {
    uint64_t stage,base,bytes;uint8_t stage_digest[32];
    struct pgcd_arch entry,masked,assigned,restored;
    struct pgcd_fp_guard fp;struct pwrpc_transition mask,restore;
    struct pwea_core source[2];struct pwmc_translation descriptor_AT;
    struct pmsb_peer peer[2][7];struct pwmt_transaction transaction;
    struct pwma_registers response[PWMT_EVENTS];struct pwmk_record cache[PWMT_EVENTS];
    struct pgcd_arch step[PWMT_EVENTS];
    uint32_t attempted,unknown,error,mask_issued,cpu_held,assignment_issued,
        assignment_returned_zero,restore_issued,complete,reserved;
    struct pwma_page page;
};
_Static_assert(offsetof(struct pmsb_result,page)%4096==0,"independent retained MBA descriptor page");
/* Never export the actual descriptor while a secure continuation or cache
 * invalidation is uncertain. The prefix retains its expected bytes and all
 * returned protocol evidence; it deliberately excludes the descriptor page. */
#define PMSB_RAW_BYTES offsetof(struct pmsb_result,page)
_Static_assert(PMSB_RAW_BYTES==12288,"MSS_MBA_SHARE_RAW_V1 descriptor-free prefix ABI");
#if defined(POLARIS_MSS_MBA_SHARE_SOFTWARE_PEER)
static int pmsb_affinity(uint64_t,int64_t*);
static int pmsb_mask(struct pwrpc_transition*);
static int pmsb_restore(struct pwrpc_transition*);
static int pmsb_cache(struct pwma_page*,unsigned,struct pwmk_record*);
static int pmsb_round(struct pwma_registers*);
#else
#include "uefi-wifi-psci-affinity.h"
#include "uefi-wifi-mem-assign.h"
#include "uefi-wifi-mem-cache.h"
static inline int pmsb_affinity(uint64_t target,int64_t*raw){return pwrpc_actual_affinity(0,target,raw);}
static inline int pmsb_mask(struct pwrpc_transition*t){return pwrpc_actual_mask(0,t);}
static inline int pmsb_restore(struct pwrpc_transition*t){return pwrpc_actual_restore(0,t);}
static inline int pmsb_cache(struct pwma_page*p,unsigned op,struct pwmk_record*r){return pwma_actual_cache_page(p,op,r);}
static inline int pmsb_round(struct pwma_registers*r){pwma_actual_round(r);return 1;}
#endif
static inline int pmsb_fail(struct pmsb_result*r,unsigned error)
{if(!r->error)r->error=error;r->unknown=1;return 0;}
static inline int pmsb_arch(const struct pmsb_result*r,struct pgcd_arch*out,unsigned masked)
{
    if(!pgcd_actual_arch(0,out))return 0;
    const struct pwfc_arch*a=&r->entry.cpu,*b=&out->cpu;
    return b->el==a->el&&b->mpidr==a->mpidr&&b->ttbr0==a->ttbr0&&b->ttbr1==a->ttbr1&&
        b->tcr==a->tcr&&b->sctlr==a->sctlr&&b->mair==a->mair&&b->sre==a->sre&&b->frequency==a->frequency&&
        b->daif==(masked?0xc0:0)&&b->group1==(masked?0:1)&&out->cpacr==r->entry.cpacr&&
        b->ticks>=a->ticks&&b->ticks-a->ticks<=PGCD_FRESH_TICKS;
}
static inline int pmsb_binding_at(const struct pmsb_result*r,unsigned native,unsigned state)
{
    const struct pmsi_result*s=(const void*)(uintptr_t)r->stage;uint8_t hash[32];
    pweh_digest(s,sizeof(*s),hash);
    return pgcd_equal(hash,r->stage_digest,32)&&pmsi_binding_at(s,native,state);
}
static inline int pmsb_binding(const struct pmsb_result*r)
{return pmsb_binding_at(r,0,2);}
static inline void pmsb_seal(const struct pmsb_result*r,const void*output,size_t bytes,uint8_t digest[32])
{
    struct pwfi_sha256 h;pwfi_init(&h);uintptr_t a=(uintptr_t)output,b=a+bytes;
    uintptr_t c=(uintptr_t)&r->page,d=c+sizeof(r->page);
    for(size_t k=0;k<sizeof(*r);k++){
        uintptr_t p=(uintptr_t)r+k;if((p>=a&&p<b)||(p>=c&&p<d))continue;
        pwfi_byte(&h,((const uint8_t*)r)[k]);
    }pwfi_final(&h,digest);
}
static inline int pmsb_peers(struct pmsb_result*r,unsigned phase)
{
    for(unsigned n=0;n<7;n++){
        struct pmsb_peer*p=&r->peer[phase][n];p->target=(n+1)*0x100;p->issued=1;
        uint8_t before[32],after[32];pmsb_seal(r,&p->raw,sizeof(p->raw),before);
        int returned=pmsb_affinity(p->target,&p->raw);
        pmsb_seal(r,&p->raw,sizeof(p->raw),after);
        if(!pgcd_equal(before,after,32)||returned!=1||!pmsb_binding(r))return 0;p->returned=1;
        struct pgcd_arch now;if(p->raw!=1||!pmsb_arch(r,&now,1))return 0;
    }return 1;
}
static inline int pmsb_share(struct pmsb_result*r,const struct pmsi_result*s)
{
    if(!r||!s||((uintptr_t)r&4095)||!pwmc_zero(r,sizeof(*r)))return 0;r->attempted=1;
    if(s->complete!=1||s->unknown||s->error||s->pages!=PMSI_PAGES||s->assets_complete!=2||
       s->source_pages[0]!=59||s->source_pages[1]!=3||!pmsi_binding(s))return pmsb_fail(r,1);
    const struct pmmn_native*m=(const void*)(uintptr_t)s->memory;
    const struct pweh_result*h=(const void*)(uintptr_t)s->retained;
    const struct pwea_native*e=h->input.early;
    if(!pmsi_image_range(e,&h->map,(uintptr_t)r,sizeof(*r)))return pmsb_fail(r,1);
    const uint64_t bases[]={(uintptr_t)s,(uintptr_t)m,(uintptr_t)h,(uintptr_t)e,s->blob,s->assets,e->native_address,e->image_address,
        (uintptr_t)h->input.digest,(uintptr_t)h->input.payload_slot,(uintptr_t)h->input.log_slot,
        (uintptr_t)h->input.state,(uintptr_t)h->input.received,(uintptr_t)h->input.count};
    const uint64_t sizes[]={sizeof(*s),sizeof(*m),sizeof(*h),sizeof(*e),s->blob_bytes,s->asset_count*sizeof(struct pmsf_asset),4,sizeof(e->image),32,8,8,4,8,8};
    for(unsigned k=0;k<14;k++)if(!pwea_disjoint((uintptr_t)r,sizeof(*r),bases[k],sizes[k]))return pmsb_fail(r,1);
    r->stage=(uintptr_t)s;pweh_digest(s,sizeof(*s),r->stage_digest);
    const struct pwea_claim*q=&m->memory.claim[1];r->base=q->requested;r->bytes=q->bytes;
    if(r->bytes!=0x100000||s->asset[0].bytes!=238304||
       !pgcd_equal(s->source_hash[0],s->asset[0].sha256,32)||!pgcd_equal(s->copied_hash[0],s->asset[0].sha256,32))return pmsb_fail(r,2);
    /* Inspect local staging evidence only: never inspect target RAM here. */
    for(unsigned n=0;n<256;n++){
        const struct pmsi_page*p=&s->page[n];uint64_t page=r->base+4096*n;
        if(p->complete!=1||p->words_issued!=512||p->words_returned!=512||p->target.page!=page||
           !pwmc_translation_valid(&p->target)||!pwmk_record_valid(&p->cache,page,PWMK_CLEAN_INVALIDATE))return pmsb_fail(r,2);
    }
    if(!pgcd_actual_arch(0,&r->entry)||!pwea_native_arch_valid(&r->entry)||(r->entry.cpu.sctlr&5)!=5||
       !pwfc_arch_stable(&s->final.cpu,&r->entry.cpu)||s->final.cpacr!=r->entry.cpacr||
       !pwea_core_check(e,&r->source[0],&h->map))return pmsb_fail(r,3);
    r->descriptor_AT.page=(uintptr_t)&r->page;
    if(!pwmc_actual_translate(&r->descriptor_AT)||!pwmc_translation_valid(&r->descriptor_AT)||
       r->descriptor_AT.page!=(uintptr_t)&r->page||!pgcd_actual_fp_save(0,&r->fp)||r->fp.saved!=1||r->fp.restored||
       r->fp.cpacr_before!=r->entry.cpacr||!pmsb_binding(r))return pmsb_fail(r,4);
    r->mask.target_daif=0xc0;r->mask_issued=r->cpu_held=r->unknown=1;r->mask.returned=pmsb_mask(&r->mask);
    if(r->mask.returned!=1||r->mask.precondition_error||r->mask.daif_before||r->mask.group_before!=1||
       r->mask.daif_written!=1||r->mask.daif_observed!=1||r->mask.daif_read!=0xc0||
       r->mask.group_written!=1||r->mask.group_observed!=1||r->mask.group_read||
       !pmsb_arch(r,&r->masked,1)||!pmsb_peers(r,0))return pmsb_fail(r,5);
    struct pwma_spec spec={.descriptor_pa=(uintptr_t)&r->page,.region_pa=r->base,.region_bytes=r->bytes,
        .sources=1,.source={PWMA_HLOS},.destinations=1,.destination={{PWMA_MSS_MSA,PWMA_RW}}};
    /* Peer/source validation belongs to the unchanged whole-caller budget.
     * Start the separate secure transaction budget only after that work;
     * masked is the earlier mask witness, not a transaction timestamp. */
    struct pgcd_arch now;
    if(!pmsb_binding(r)||!pmsb_arch(r,&now,1)||
       pwmt_begin(&r->transaction,&r->page,&spec,now.cpu.ticks,r->entry.cpu.frequency)<0)return pmsb_fail(r,6);
    for(unsigned k=0;k<PWMT_EVENTS;k++){
        struct pwmt_command command;
        if(!pmsb_arch(r,&now,1))return pmsb_fail(r,7);
        int next=pwmt_next(&r->transaction,now.cpu.ticks,&command);
        if(next==PWMT_ZERO)break;
        if(next!=PWMT_IO){r->step[k]=now;return pmsb_fail(r,7);}
        uint8_t before[32],after[32];int returned;
        if(command.operation==PWMT_SMC){
            r->response[k]=command.registers;r->assignment_issued=1;
            pmsb_seal(r,&r->response[k],sizeof(r->response[k]),before);
            returned=pmsb_round(&r->response[k]);pmsb_seal(r,&r->response[k],sizeof(r->response[k]),after);
        }else{
            unsigned op=command.operation==PWMT_CLEAN?PWMK_CLEAN_INVALIDATE:PWMK_INVALIDATE;
            pmsb_seal(r,&r->cache[k],sizeof(r->cache[k]),before);
            returned=pmsb_cache(&r->page,op,&r->cache[k]);pmsb_seal(r,&r->cache[k],sizeof(r->cache[k]),after);
        }
        if(!pgcd_equal(before,after,32)||!pmsb_binding(r)||!pmsb_arch(r,&r->step[k],1))return pmsb_fail(r,8);
        if(pwmt_complete(&r->transaction,&command,r->step[k].cpu.ticks,returned,
            command.operation==PWMT_SMC?&r->response[k]:0,command.operation==PWMT_SMC?0:&r->cache[k])<0)return pmsb_fail(r,9);
    }
    if(!r->transaction.complete||r->transaction.unknown||r->transaction.error||!pmsb_binding(r))return pmsb_fail(r,10);
    r->assignment_returned_zero=1;
    if(!pmsb_peers(r,1)||!pwmt_page_equal(&r->transaction)||!pwea_core_check(e,&r->source[1],&h->map)||
       !pmsb_arch(r,&r->assigned,1)||!pmsb_binding(r)||!pgcd_actual_fp_restore(0,&r->fp)||r->fp.restored!=1)return pmsb_fail(r,11);
    r->restore.target_group=1;r->restore_issued=1;r->restore.returned=pmsb_restore(&r->restore);
    if(r->restore.returned!=1||r->restore.precondition_error||r->restore.daif_before!=0xc0||r->restore.group_before||
       r->restore.daif_written!=1||r->restore.daif_observed!=1||r->restore.daif_read||
       r->restore.group_written!=1||r->restore.group_observed!=1||r->restore.group_read!=1||
       !pmsb_arch(r,&r->restored,0)||!pmsb_binding(r))return pmsb_fail(r,12);
    r->cpu_held=0;r->unknown=0;r->complete=1;return 1;
}
#endif
#endif
