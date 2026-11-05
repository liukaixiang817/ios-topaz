/* Actual incoming-UEFI producer for independent MSS/MBA/metadata allocations.
 * Runs before payload/log/native launch, following the real early producer.
 * Same normal BootServices contract; no closed PGCD ticket or old ownership
 * lease. Target pages are not touched: staging must freshly AT/cache each page.
 * UNKNOWN retains every claim. No free, VMID assignment or address publication. */
#ifndef POLARIS_UEFI_MSS_MEMORY_H
#define POLARIS_UEFI_MSS_MEMORY_H
#ifndef EFI_XNU_MSS_MEMORY_AVAILABLE
#define EFI_XNU_MSS_MEMORY_AVAILABLE 0
#endif
#if EFI_XNU_MSS_MEMORY_AVAILABLE
#if !EFI_XNU_WIFI_EARLY_MEMORY_AVAILABLE || defined(POLARIS_EFI_TEST_QEMU)
#error "MSS memory requires the actual physical early UEFI producer"
#endif
#include "uefi-wifi-retained-memory.h"
#include "uefi-mss-memory-policy.h"
struct pmmn_native {
    struct pmme_memory memory;
    uint64_t early,digest;uint8_t early_digest[32];
    struct pwea_native_call call[PMME_CALLS];struct pgcd_arch final;
    uint32_t attempted,unknown,error,complete;
};
_Static_assert(sizeof(struct pmmn_native)==58240,"MSS_MEMORY_RAW_V1 ABI");
#if defined(POLARIS_MSS_MEMORY_SOFTWARE_PEER)
static efi_status pmmn_test_map(struct efi_system*,struct pwea_map*);
static efi_status pmmn_test_allocate(struct efi_system*,uint64_t,uint64_t*);
#endif
static inline int pmmn_fail(struct pmmn_native*r,unsigned error)
{r->unknown=1;if(!r->error)r->error=error;return 0;}
static inline int pmmn_binding_at(const struct pmmn_native*r,unsigned native)
{
    const struct pwea_native*e=(const void*)(uintptr_t)r->early;uint8_t digest[32];
    pweh_digest(e,sizeof(*e),digest);
    return pgcd_equal(digest,r->early_digest,32)&&pgcd_equal((const void*)(uintptr_t)r->digest,r->early_digest,32)&&pwea_native_binding_at(e,native);
}
static inline int pmmn_binding(const struct pmmn_native*r)
{return pmmn_binding_at(r,0);}
static inline void pmmn_guard(const struct pmmn_native*r,uint8_t out[32])
{pweh_digest((const uint8_t*)r+sizeof(r->memory),sizeof(*r)-sizeof(r->memory),out);}
static inline int pmmn_owned(const struct pmmn_native*r,const struct pwea_map*m)
{
    for(uint64_t p=(uintptr_t)r&~UINT64_C(4095);p<(uintptr_t)r+sizeof(*r);p+=4096)
        if(!polaris_efi_range_owned(m->data,m->map.bytes,m->map.stride,p,4096,3)&&
           !polaris_efi_range_owned(m->data,m->map.bytes,m->map.stride,p,4096,4))return 0;
    return 1;
}
static inline int pmmn_run(struct pmmn_native*r,const struct pwea_native*e,const uint8_t*digest,uint64_t metadata_bytes)
{
    if(!r||!e||!digest||!pwmc_zero(r,sizeof(*r)))return 0;r->attempted=1;
    if(e->complete!=1||e->unknown||e->error||e->memory.complete!=1||e->memory.unknown||e->memory.error||
       !pwmc_parent_in_image(&e->image,(uintptr_t)r,sizeof(*r))||!pwmc_parent_in_image(&e->image,(uintptr_t)e,sizeof(*e))||
       !pwmc_parent_in_image(&e->image,(uintptr_t)digest,32)||
       !pwea_disjoint((uintptr_t)r,sizeof(*r),(uintptr_t)e,sizeof(*e))||
       !pwea_disjoint((uintptr_t)r,sizeof(*r),(uintptr_t)digest,32)||
       !pwea_disjoint((uintptr_t)r,sizeof(*r),e->native_address,4)||
       !pwea_disjoint((uintptr_t)r,sizeof(*r),e->image_address,sizeof(struct efi_loaded)))return pmmn_fail(r,PWEA_ARGUMENT);
    r->early=(uintptr_t)e;r->digest=(uintptr_t)digest;pgcd_copy(r->early_digest,digest,32);
    if(!pmmn_binding(r))return pmmn_fail(r,PWEA_ARGUMENT);
    struct pmme_input input={.owner=e->memory.input,.metadata_bytes=metadata_bytes};
    for(unsigned k=0;k<2;k++){
        const struct pwea_claim*q=&e->memory.claim[k];
        if(q->retained!=1||q->status||q->returned!=1||q->requested!=q->returned_address||q->bytes!=pwmc_bytes(k))return pmmn_fail(r,PWEA_ARGUMENT);
        input.retained[k]=(struct pwmc_range){q->requested,q->bytes};
    }
    if(pmme_begin(&r->memory,&input)<0)return pmmn_fail(r,PWEA_ARGUMENT);
    for(unsigned n=0;n<PMME_CALLS;n++){
        struct pwea_command command;uint8_t policy_before[32],outer_before[32],outer_after[32];
        if(pmme_next(&r->memory,&command)!=PWEA_IO)return pmmn_fail(r,PWEA_ARGUMENT);
        struct pwea_native_call*c=&r->call[n];
        const struct pwea_map*prior=n?&r->memory.map[(n-1)/2]:&e->memory.map[2];
        if(!pmmn_binding(r)||!pmmn_owned(r,prior)||!pgcd_actual_arch(0,&c->before)||!pwea_native_arch_valid(&c->before)||
           (n&&(!pwfc_arch_stable(&r->call[0].before.cpu,&c->before.cpu)||c->before.cpacr!=r->call[0].before.cpacr||
                 c->before.cpu.ticks<r->call[n-1].after.cpu.ticks))||
           !pwea_core_check(e,&c->source[0],prior))return pmmn_fail(r,PWEA_ARGUMENT);
        c->native_before=*(const volatile uint32_t*)(uintptr_t)e->native_address;
        if(c->native_before||!pgcd_actual_fp_save(0,&c->fp)||c->fp.saved!=1||c->fp.restored||c->fp.cpacr_before!=c->before.cpacr)
            return pmmn_fail(r,PWEA_ARGUMENT);
        c->issued=c->unknown=1;pmme_seal(&r->memory,policy_before);pmmn_guard(r,outer_before);pwfc_actual_order(0);
        struct efi_system*system=(void*)(uintptr_t)e->system;
        if(command.operation==PWEA_MAP){
            struct pwea_map*m=&r->memory.map[command.index];
#if defined(POLARIS_MSS_MEMORY_SOFTWARE_PEER)
            m->map.status=pmmn_test_map(system,m);
#else
            m->map.status=system->boot->get_map(&m->map.bytes,m->data,&m->map.key,&m->map.stride,&m->map.version);
#endif
        }else{
            struct pwea_claim*q=&r->memory.claim[command.index];
#if defined(POLARIS_MSS_MEMORY_SOFTWARE_PEER)
            q->status=pmmn_test_allocate(system,command.pages,&q->returned_address);
#else
            q->status=system->boot->allocate_pages(2,2,command.pages,&q->returned_address);
#endif
        }
        pmmn_guard(r,outer_after);
        if(!pgcd_equal(outer_before,outer_after,32)||!pmmn_binding(r))return pmmn_fail(r,PWEA_EFFECT);
        c->returned=1;c->native_after=*(const volatile uint32_t*)(uintptr_t)e->native_address;
        if(c->native_after||!pgcd_actual_arch(0,&c->after)||!pwea_native_arch_valid(&c->after)||
           !pwfc_arch_stable(&c->before.cpu,&c->after.cpu)||c->before.cpacr!=c->after.cpacr||
           c->after.cpu.ticks<c->before.cpu.ticks||c->after.cpu.ticks-c->before.cpu.ticks>PGCD_FRESH_TICKS||
           !pgcd_actual_fp_restore(0,&c->fp)||c->fp.restored!=1)return pmmn_fail(r,PWEA_ARGUMENT);
        if(pmme_complete(&r->memory,&command,1,policy_before)<0)return pmmn_fail(r,PWEA_EFFECT);
        const struct pwea_map*current=&r->memory.map[n/2];
        if(!pmmn_owned(r,current)||!pwea_core_check(e,&c->source[1],current)||!pmmn_binding(r))return pmmn_fail(r,PWEA_ARGUMENT);
        c->unknown=0;c->complete=1;
    }
    if(r->memory.complete!=1||r->memory.unknown||!pmmn_binding(r)||!pgcd_actual_arch(0,&r->final)||
       !pwea_native_arch_valid(&r->final)||!pwfc_arch_stable(&r->call[0].before.cpu,&r->final.cpu)||
       r->final.cpacr!=r->call[0].before.cpacr||r->final.cpu.ticks<r->call[6].after.cpu.ticks)return pmmn_fail(r,PWEA_EFFECT);
    r->complete=1;return 1;
}
/* Immediate caller of the actual post-payload GetMap producer only. This
 * retains allocations; it is not a CPU mapping/cache or remote-access grant. */
static inline int pmmn_retained_at(const struct pmmn_native*r,const uint8_t digest[32],const struct pweh_result*h,unsigned native,unsigned state)
{
    uint8_t current[32];
    if(!r||!digest||!h||r->complete!=1||r->unknown||r->error||r->memory.complete!=1||
       r->memory.unknown||r->memory.error||h->complete!=1||h->unknown||h->error||
       (uintptr_t)h->input.early!=r->early||h->input.digest!=(const void*)(uintptr_t)r->digest||
       h->before.cpu.ticks<r->final.cpu.ticks)return 0;
    pweh_digest(r,sizeof(*r),current);
    if(!pgcd_equal(current,digest,32)||!pmmn_binding_at(r,native)||!pweh_binding_at(h,native,state)||!pmmn_owned(r,&h->map))return 0;
    const struct pwea_map*m=&h->map;struct polaris_efi_memory checked;
    if(m->map.status||m->map.valid!=1||!m->map.key||m->map.version!=1||
       !polaris_efi_memory_check(m->data,m->map.bytes,PGCD_MAP_CAP,m->map.stride,&checked))return 0;
    for(unsigned k=0;k<PMME_CLAIMS;k++){
        const struct pwea_claim*q=&r->memory.claim[k];
        if(q->retained!=1||q->status||q->returned!=1||q->requested!=q->returned_address||
           q->bytes!=pmme_bytes(&r->memory,k)||!pmme_allowed(&r->memory,k,q->requested)||
           !polaris_efi_range_owned(m->data,m->map.bytes,m->map.stride,q->requested,q->bytes,2)||
           !pwea_disjoint(q->requested,q->bytes,h->payload,h->payload_bytes)||
           !pwea_disjoint(q->requested,q->bytes,h->log,h->input.log_bytes))return 0;
    }return 1;
}
static inline int pmmn_retained(const struct pmmn_native*r,const uint8_t digest[32],const struct pweh_result*h)
{return pmmn_retained_at(r,digest,h,0,2);}
#endif
#endif
