/* Default-OFF native consumer of the actual retained-claim producer.
 * Own sharedmem client1: HLOS -> HLOS+MSS RW, exactly the inner2MiB.
 * No region is published, remote is started, memory is freed, or handback is
 * inferred here. A completed assignment remains held until a real remote
 * lifecycle/retirement caller is attached. Not an operational boot profile. */
#ifndef POLARIS_UEFI_WIFI_RMTFS_SHARE_H
#define POLARIS_UEFI_WIFI_RMTFS_SHARE_H
#ifndef EFI_XNU_WIFI_RMTFS_SHARE_AVAILABLE
#define EFI_XNU_WIFI_RMTFS_SHARE_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_RMTFS_SHARE_AVAILABLE
#if !EFI_XNU_WIFI_EARLY_MEMORY_AVAILABLE || !EFI_XNU_WIFI_MEM_ASSIGN_AVAILABLE || defined(POLARIS_EFI_TEST_QEMU)
#error "RMTFS share needs actual early/retained claims and its separately enabled native secure provider"
#endif
#include "uefi-wifi-retained-memory.h"
#include "uefi-wifi-cpu-local-mask.h"
#include "../../tools/polaris-wifi-mem-transaction.h"
struct pwsr_zero {
    struct pwmc_translation AT;struct pwmk_record cache;
    uint32_t words_issued,words_returned,complete,reserved;
};
struct pwsr_peer {uint64_t target;int64_t raw;uint32_t issued,returned;};
struct pwsr_result {
    uint64_t retained,base,bytes;uint8_t retained_digest[32];
    struct pgcd_arch entry,masked,zeroed,assigned,restored;
    struct pgcd_fp_guard fp;struct pwrpc_transition mask,restore;
    struct pwea_core source[2];struct pwmc_translation descriptor_AT;
    struct pwsr_peer peer[2][7];struct pwsr_zero zero[512];
    struct pwmt_transaction transaction;
    struct pwma_registers response[PWMT_EVENTS];struct pwmk_record cache[PWMT_EVENTS];
    struct pgcd_arch step[PWMT_EVENTS];
    uint32_t attempted,unknown,error,mask_issued,held,zero_pages,assignment_issued,
        assignment_returned_zero,restore_issued,complete,remote_publish_issued,reserved;
    struct pwma_page page;
};
_Static_assert(offsetof(struct pwsr_result,page)%4096==0,"exclusive retained descriptor page");
/* Also executed by the software peer on its owned RAM shadow. The native
 * caller reaches this only after the exact target page's current R/W AT. */
static inline int pwsr_zero_words(uint64_t address,struct pwsr_zero*z)
{
    for(unsigned n=0;n<512;n++){
        volatile uint64_t*p=(void*)(uintptr_t)(address+8*n);z->words_issued++;
        *p=0;if(*p)return 0;z->words_returned++;
    }return 1;
}
#if defined(POLARIS_WIFI_RMTFS_SHARE_SOFTWARE_PEER)
static int pwsr_zero_page(uint64_t,struct pwsr_zero*);
static int pwsr_affinity(uint64_t,int64_t*);
static int pwsr_mask(struct pwrpc_transition*);
static int pwsr_restore(struct pwrpc_transition*);
static int pwsr_cache(struct pwma_page*,unsigned,struct pwmk_record*);
static int pwsr_round(struct pwma_registers*);
#else
#include "uefi-wifi-psci-affinity.h"
#include "uefi-wifi-mem-assign.h"
#include "uefi-wifi-mem-cache.h"
static inline int pwsr_zero_page(uint64_t address,struct pwsr_zero*z)
{
    if(!z||!pwmc_zero(z,sizeof(*z))||(address&4095))return 0;
    z->AT.page=address;
    if(!pwmc_actual_translate(&z->AT)||!pwmc_translation_valid(&z->AT)||z->AT.page!=address)return 0;
    if(!pwsr_zero_words(address,z))return 0;
    if(!pwma_actual_cache_page((void*)(uintptr_t)address,PWMK_CLEAN_INVALIDATE,&z->cache)||
       !pwmk_record_valid(&z->cache,address,PWMK_CLEAN_INVALIDATE))return 0;
    z->complete=1;return 1;
}
static inline int pwsr_affinity(uint64_t target,int64_t*raw)
{return pwrpc_actual_affinity(0,target,raw);}
static inline int pwsr_mask(struct pwrpc_transition*t){return pwrpc_actual_mask(0,t);}
static inline int pwsr_restore(struct pwrpc_transition*t){return pwrpc_actual_restore(0,t);}
static inline int pwsr_cache(struct pwma_page*p,unsigned op,struct pwmk_record*r)
{return pwma_actual_cache_page(p,op,r);}
static inline int pwsr_round(struct pwma_registers*r){pwma_actual_round(r);return 1;}
#endif
static inline int pwsr_fail(struct pwsr_result*r,unsigned error)
{if(!r->error)r->error=error;r->unknown=1;return 0;}
static inline int pwsr_arch(struct pwsr_result*r,struct pgcd_arch*out,unsigned masked)
{
    if(!pgcd_actual_arch(0,out))return 0;
    const struct pwfc_arch*a=&r->entry.cpu,*b=&out->cpu;
    return b->el==a->el&&b->mpidr==a->mpidr&&b->ttbr0==a->ttbr0&&b->ttbr1==a->ttbr1&&
        b->tcr==a->tcr&&b->sctlr==a->sctlr&&b->mair==a->mair&&b->sre==a->sre&&b->frequency==a->frequency&&
        b->daif==(masked?0xc0:0)&&b->group1==(masked?0:1)&&out->cpacr==r->entry.cpacr&&
        b->ticks>=a->ticks&&b->ticks-a->ticks<=PGCD_FRESH_TICKS;
}
static inline int pwsr_binding(const struct pwsr_result*r)
{
    const struct pweh_result*h=(const void*)(uintptr_t)r->retained;uint8_t hash[32];
    pweh_digest(h,sizeof(*h),hash);
    return pgcd_equal(hash,r->retained_digest,32)&&pweh_binding(h);
}
/* Never read the descriptor page after SMC until explicit IVAC completes.
 * Only the current typed leaf's output is excluded from the control seal. */
static inline void pwsr_seal(const struct pwsr_result*r,const void*output,size_t bytes,uint8_t digest[32])
{
    struct pwfi_sha256 h;pwfi_init(&h);uintptr_t a=(uintptr_t)output,b=a+bytes;
    uintptr_t c=(uintptr_t)&r->page,d=c+sizeof(r->page);
    for(size_t k=0;k<sizeof(*r);k++){
        uintptr_t p=(uintptr_t)r+k;if((p>=a&&p<b)||(p>=c&&p<d))continue;
        pwfi_byte(&h,((const uint8_t*)r)[k]);
    }pwfi_final(&h,digest);
}
static inline int pwsr_peers(struct pwsr_result*r,unsigned phase)
{
    for(unsigned n=0;n<7;n++){
        struct pwsr_peer*p=&r->peer[phase][n];p->target=(n+1)*0x100;p->issued=1;
        uint8_t before[32],after[32];pwsr_seal(r,&p->raw,sizeof(p->raw),before);
        int returned=pwsr_affinity(p->target,&p->raw);
        pwsr_seal(r,&p->raw,sizeof(p->raw),after);
        if(!pgcd_equal(before,after,32)||returned!=1)return 0;p->returned=1;
        struct pgcd_arch now;if(p->raw!=1||!pwsr_arch(r,&now,1))return 0;
    }return 1;
}
static inline int pwsr_share(struct pwsr_result*r,const struct pweh_result*h)
{
    if(!r||!h||((uintptr_t)r&4095)||!pwmc_zero(r,sizeof(*r)))return 0;r->attempted=1;
    const struct pwea_native*e=h->input.early;
    if(!e||h->complete!=1||h->unknown||h->error||!pweh_binding(h)||
       !pwmc_parent_in_image(&e->image,(uintptr_t)r,sizeof(*r))||
       !pwea_disjoint((uintptr_t)r,sizeof(*r),(uintptr_t)h,sizeof(*h))||
       !pwea_disjoint((uintptr_t)r,sizeof(*r),(uintptr_t)e,sizeof(*e)))return pwsr_fail(r,1);
    const uint64_t control[]={(uintptr_t)h->input.digest,(uintptr_t)h->input.payload_slot,(uintptr_t)h->input.log_slot,
        (uintptr_t)h->input.state,(uintptr_t)h->input.received,(uintptr_t)h->input.count,e->native_address,e->image_address};
    const unsigned widths[]={32,8,8,4,8,8,4,sizeof(struct efi_loaded)};
    for(unsigned k=0;k<8;k++)if(!pwea_disjoint((uintptr_t)r,sizeof(*r),control[k],widths[k]))return pwsr_fail(r,1);
    for(uint64_t at=(uintptr_t)r;at<(uintptr_t)r+sizeof(*r);at+=4096)
        if(!polaris_efi_range_owned(h->map.data,h->map.map.bytes,h->map.map.stride,at,4096,3)&&
           !polaris_efi_range_owned(h->map.data,h->map.map.bytes,h->map.map.stride,at,4096,4))return pwsr_fail(r,1);
    r->retained=(uintptr_t)h;pweh_digest(h,sizeof(*h),r->retained_digest);
    const struct pwea_claim*q=&e->memory.claim[1];r->base=q->exposed;r->bytes=q->exposed_bytes;
    if(q->retained!=1||r->bytes!=0x200000||q->bytes!=0x202000||r->base!=q->requested+4096||
       !polaris_efi_range_owned(h->map.data,h->map.map.bytes,h->map.map.stride,q->requested,q->bytes,2)||
       !pgcd_actual_arch(0,&r->entry)||!pwea_native_arch_valid(&r->entry)||(r->entry.cpu.sctlr&5)!=5||
       !pwfc_arch_stable(&h->final.cpu,&r->entry.cpu)||h->final.cpacr!=r->entry.cpacr||
       r->entry.cpu.ticks<h->final.cpu.ticks||r->entry.cpu.ticks-h->final.cpu.ticks>PGCD_FRESH_TICKS||
       !pwea_core_check(e,&r->source[0],&h->map))return pwsr_fail(r,2);
    r->descriptor_AT.page=(uintptr_t)&r->page;
    if(!pwmc_actual_translate(&r->descriptor_AT)||!pwmc_translation_valid(&r->descriptor_AT)||
       r->descriptor_AT.page!=(uintptr_t)&r->page||
       !pgcd_actual_fp_save(0,&r->fp)||r->fp.saved!=1||r->fp.restored||r->fp.cpacr_before!=r->entry.cpacr||
       !pwsr_binding(r))return pwsr_fail(r,3);
    r->mask.target_daif=0xc0;r->mask_issued=r->held=r->unknown=1;
    r->mask.returned=pwsr_mask(&r->mask);
    if(r->mask.returned!=1||r->mask.precondition_error||r->mask.daif_before||r->mask.group_before!=1||
       r->mask.daif_written!=1||r->mask.daif_observed!=1||r->mask.daif_read!=0xc0||
       r->mask.group_written!=1||r->mask.group_observed!=1||r->mask.group_read||
       !pwsr_arch(r,&r->masked,1)||!pwsr_peers(r,0))return pwsr_fail(r,4);
    for(unsigned k=0;k<512;k++){
        struct pwsr_zero*z=&r->zero[k];uint64_t address=r->base+4096*k;
        if(!pwsr_zero_page(address,z)||z->complete!=1||z->AT.page!=address||!pwmc_translation_valid(&z->AT)||
           z->words_issued!=512||z->words_returned!=512||
           !pwmk_record_valid(&z->cache,address,PWMK_CLEAN_INVALIDATE)||!pwsr_arch(r,&r->zeroed,1))return pwsr_fail(r,5);
        r->zero_pages++;
    }
    struct pwma_spec spec={.descriptor_pa=(uintptr_t)&r->page,.region_pa=r->base,.region_bytes=r->bytes,
        .sources=1,.source={PWMA_HLOS},.destinations=2,.destination={{PWMA_HLOS,PWMA_RW},{PWMA_MSS_MSA,PWMA_RW}}};
    if(!pwsr_binding(r)||pwmt_begin(&r->transaction,&r->page,&spec,r->zeroed.cpu.ticks,r->entry.cpu.frequency)<0)return pwsr_fail(r,6);
    for(unsigned k=0;k<PWMT_EVENTS;k++){
        struct pwmt_command command;struct pgcd_arch now;
        if(!pwsr_arch(r,&now,1))return pwsr_fail(r,7);
        int next=pwmt_next(&r->transaction,now.cpu.ticks,&command);
        if(next==PWMT_ZERO)break;if(next!=PWMT_IO)return pwsr_fail(r,7);
        uint8_t before[32],after[32];int returned;
        if(command.operation==PWMT_SMC){
            r->response[k]=command.registers;r->assignment_issued=1;
            pwsr_seal(r,&r->response[k],sizeof(r->response[k]),before);
            returned=pwsr_round(&r->response[k]);pwsr_seal(r,&r->response[k],sizeof(r->response[k]),after);
        }else{
            unsigned op=command.operation==PWMT_CLEAN?PWMK_CLEAN_INVALIDATE:PWMK_INVALIDATE;
            pwsr_seal(r,&r->cache[k],sizeof(r->cache[k]),before);
            returned=pwsr_cache(&r->page,op,&r->cache[k]);pwsr_seal(r,&r->cache[k],sizeof(r->cache[k]),after);
        }
        if(!pgcd_equal(before,after,32)||!pwsr_arch(r,&r->step[k],1))return pwsr_fail(r,8);
        if(pwmt_complete(&r->transaction,&command,r->step[k].cpu.ticks,returned,
            command.operation==PWMT_SMC?&r->response[k]:0,command.operation==PWMT_SMC?0:&r->cache[k])<0)return pwsr_fail(r,9);
    }
    if(!r->transaction.complete||r->transaction.unknown||r->transaction.error||!pwsr_binding(r))return pwsr_fail(r,10);
    r->assignment_returned_zero=1;
    if(!pwsr_peers(r,1)||!pwmt_page_equal(&r->transaction)||!pwea_core_check(e,&r->source[1],&h->map)||!pwsr_arch(r,&r->assigned,1)||
       !pwsr_binding(r)||!pgcd_actual_fp_restore(0,&r->fp)||r->fp.restored!=1)return pwsr_fail(r,11);
    r->restore.target_group=1;r->restore_issued=1;r->restore.returned=pwsr_restore(&r->restore);
    if(r->restore.returned!=1||r->restore.precondition_error||r->restore.daif_before!=0xc0||r->restore.group_before||
       r->restore.daif_written!=1||r->restore.daif_observed!=1||r->restore.daif_read||
       r->restore.group_written!=1||r->restore.group_observed!=1||r->restore.group_read!=1||
       !pwsr_arch(r,&r->restored,0)||!pwsr_binding(r))return pwsr_fail(r,12);
    r->held=0;r->unknown=0;r->complete=1;return 1;
}
#endif
#endif
