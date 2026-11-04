/* Fresh actual incoming-BootServices check of independently retained claims.
 * Allocation persists because this resident producer never frees/exposes it;
 * the old map is not a later ownership or execution lease. A fresh GetMap and
 * full claim translations follow payload/log allocation. No allocate/free,
 * secure call, remote address publication, power or native startup is here. */
#ifndef POLARIS_UEFI_WIFI_RETAINED_MEMORY_H
#define POLARIS_UEFI_WIFI_RETAINED_MEMORY_H
#include "uefi-wifi-early-native.h"
#if EFI_XNU_WIFI_EARLY_MEMORY_AVAILABLE
struct pweh_input {
    const struct pwea_native*early;const uint8_t*digest;
    uint8_t*const*payload_slot;uint8_t*const*log_slot;
    const uint32_t*state;const uint64_t*received,*count;
    uint64_t logical_bytes,log_bytes;
};
struct pweh_result {
    struct pweh_input input;uint64_t payload,payload_bytes,log;
    uint8_t early_digest[32];struct pwea_map map;
    struct pwea_core source[2];struct pgcd_arch before,after,final;
    struct pgcd_fp_guard fp;struct pwmc_translation AT[2][PWMC_PAGES];
    uint32_t attempted,issued,returned,unknown,error,complete,translated[2];
};
_Static_assert(sizeof(struct pweh_result)==69584,"RETAINED_WIFI_MEMORY_RAW_V1 ABI");
#if defined(POLARIS_WIFI_EARLY_SOFTWARE_PEER)
static efi_status pweh_test_map(struct efi_system*,struct pwea_map*);
#endif
static inline void pweh_digest(const void*data,size_t bytes,uint8_t out[32])
{struct pwfi_sha256 h;pwfi_init(&h);for(size_t k=0;k<bytes;k++)pwfi_byte(&h,((const uint8_t*)data)[k]);pwfi_final(&h,out);}
static inline int pweh_fail(struct pweh_result*r,unsigned error)
{if(!r->error)r->error=error;r->unknown=1;return 0;}
static inline int pweh_binding(const struct pweh_result*r)
{
    const struct pweh_input*i=&r->input;const struct pwea_native*e=i->early;uint8_t digest[32];
    pweh_digest(e,sizeof(*e),digest);
    return pgcd_equal(digest,r->early_digest,32)&&pgcd_equal(i->digest,r->early_digest,32)&&
        pwea_native_binding(e)&&*i->state==2&&*i->received==i->logical_bytes&&*i->count==i->logical_bytes&&
        (uintptr_t)*i->payload_slot==r->payload&&(uintptr_t)*i->log_slot==r->log;
}
static inline void pweh_seal(const struct pweh_result*r,uint8_t out[32])
{
    uintptr_t a=(uintptr_t)&r->map.map,b=a+offsetof(struct pgcd_map,issued);
    uintptr_t c=(uintptr_t)r->map.data,d=c+PGCD_MAP_CAP;
    struct pwfi_sha256 h;pwfi_init(&h);
    for(size_t k=0;k<sizeof(*r);k++){
        uintptr_t p=(uintptr_t)r+k;if((p>=a&&p<b)||(p>=c&&p<d))continue;
        pwfi_byte(&h,((const uint8_t*)r)[k]);
    }pwfi_final(&h,out);
}
static inline int pweh_run(struct pweh_result*r,const struct pweh_input*input)
{
    if(!r||!input||!pwmc_zero(r,sizeof(*r)))return 0;r->attempted=1;
    const struct pwea_native*e=input->early;
    if(!e||!input->digest||!input->payload_slot||!input->log_slot||!input->state||!input->received||!input->count||
       !input->logical_bytes||input->logical_bytes>UINT64_MAX-4095||!input->log_bytes||
       !e->complete||e->unknown||e->error||!e->memory.complete||e->memory.unknown||e->memory.error||
       !pwmc_parent_in_image(&e->image,(uintptr_t)e,sizeof(*e))||
       !pwmc_parent_in_image(&e->image,(uintptr_t)r,sizeof(*r))||
       !pwea_disjoint((uintptr_t)e,sizeof(*e),(uintptr_t)r,sizeof(*r))||
       !pwea_disjoint((uintptr_t)input,sizeof(*input),(uintptr_t)r,sizeof(*r)))return pweh_fail(r,PWEA_ARGUMENT);
    const uint64_t addresses[]={(uintptr_t)input->digest,(uintptr_t)input->payload_slot,(uintptr_t)input->log_slot,
        (uintptr_t)input->state,(uintptr_t)input->received,(uintptr_t)input->count};
    const unsigned sizes[]={32,8,8,4,8,8};
    for(unsigned k=0;k<6;k++)if(!pwmc_parent_in_image(&e->image,addresses[k],sizes[k])||
        !pwea_disjoint((uintptr_t)r,sizeof(*r),addresses[k],sizes[k]))return pweh_fail(r,PWEA_ARGUMENT);
    r->input=*input;r->payload=(uintptr_t)*input->payload_slot;r->log=(uintptr_t)*input->log_slot;
    r->payload_bytes=(input->logical_bytes+4095)&~UINT64_C(4095);pgcd_copy(r->early_digest,input->digest,32);
    if((r->payload&4095)||!pwea_disjoint(r->payload,r->payload_bytes,r->log,input->log_bytes)||
       !pwea_disjoint(r->payload,r->payload_bytes,(uintptr_t)e->image.base,e->image.bytes)||
       !pwea_disjoint(r->log,input->log_bytes,(uintptr_t)e->image.base,e->image.bytes)||
       !pwea_disjoint(r->payload,r->payload_bytes,e->memory.input.bank,e->memory.input.bank_bytes)||
       !pwea_disjoint(r->log,input->log_bytes,e->memory.input.bank,e->memory.input.bank_bytes))return pweh_fail(r,PWEA_RANGE);
    if(!pweh_binding(r)||!pgcd_actual_arch(0,&r->before)||!pwea_native_arch_valid(&r->before)||
       !pwea_core_check(e,&r->source[0],&e->memory.map[2]))return pweh_fail(r,PWEA_ARGUMENT);
    for(unsigned k=0;k<2;k++){
        const struct pwea_claim*q=&e->memory.claim[k];
        if(q->retained!=1||q->bytes!=pwmc_bytes(k)||q->pages!=q->bytes/4096||q->status||q->returned!=1||
           q->requested!=q->returned_address||q->exposed!=q->requested+(k?4096:0)||q->exposed_bytes!=(k?0x200000:0x100000)||
           !pwmc_allowed(q->requested,q->bytes)||
           !pwea_disjoint(q->requested,q->bytes,r->payload,r->payload_bytes)||
           !pwea_disjoint(q->requested,q->bytes,r->log,input->log_bytes)||
           !pwea_disjoint(q->requested,q->bytes,(uintptr_t)e->image.base,e->image.bytes)||
           !pwea_disjoint(q->requested,q->bytes,e->memory.input.bank,e->memory.input.bank_bytes))return pweh_fail(r,PWEA_RANGE);
    }
    if(!pgcd_actual_fp_save(0,&r->fp)||r->fp.saved!=1||r->fp.restored||r->fp.cpacr_before!=r->before.cpacr||!pweh_binding(r))return pweh_fail(r,PWEA_ARGUMENT);
    r->map.map.bytes=PGCD_MAP_CAP;r->map.map.issued=1;r->issued=r->unknown=1;
    uint8_t before[32],after[32];pweh_seal(r,before);pwfc_actual_order(0);
    struct efi_system*system=(void*)(uintptr_t)e->system;
#if defined(POLARIS_WIFI_EARLY_SOFTWARE_PEER)
    r->map.map.status=pweh_test_map(system,&r->map);
#else
    r->map.map.status=system->boot->get_map(&r->map.map.bytes,r->map.data,&r->map.map.key,&r->map.map.stride,&r->map.map.version);
#endif
    pweh_seal(r,after);
    if(!pgcd_equal(before,after,32)||!pweh_binding(r))return pweh_fail(r,PWEA_EFFECT);
    r->returned=r->map.map.returned=1;
    if(!pgcd_actual_arch(0,&r->after)||!pwea_native_arch_valid(&r->after)||
       !pwfc_arch_stable(&r->before.cpu,&r->after.cpu)||r->before.cpacr!=r->after.cpacr||
       r->after.cpu.ticks<r->before.cpu.ticks||r->after.cpu.ticks-r->before.cpu.ticks>PGCD_FRESH_TICKS||
       !pgcd_actual_fp_restore(0,&r->fp)||r->fp.restored!=1)return pweh_fail(r,PWEA_ARGUMENT);
    struct polaris_efi_memory checked;const struct pgcd_map*m=&r->map.map;
    if(m->status||!m->key||m->version!=1||!polaris_efi_memory_check(r->map.data,m->bytes,PGCD_MAP_CAP,m->stride,&checked)||
       !polaris_efi_range_owned(r->map.data,m->bytes,m->stride,r->payload,r->payload_bytes,2)||
       !polaris_efi_range_owned(r->map.data,m->bytes,m->stride,r->log,r->input.log_bytes,2)||
       !polaris_efi_range_owned(r->map.data,m->bytes,m->stride,e->memory.input.bank,e->memory.input.bank_bytes,2))return pweh_fail(r,PWEA_MAP_ERROR);
    r->map.map.valid=1;
    if(!pwea_core_check(e,&r->source[1],&r->map))return pweh_fail(r,PWEA_ARGUMENT);
    for(unsigned kind=0;kind<2;kind++){
        const struct pwea_claim*q=&e->memory.claim[kind];
        if(!polaris_efi_range_owned(r->map.data,m->bytes,m->stride,q->requested,q->bytes,2))return pweh_fail(r,PWEA_DELTA);
        for(unsigned k=0;k<q->pages;k++){
            struct pwmc_translation*a=&r->AT[kind][k];a->page=q->requested+4096*k;
            if(!pwmc_actual_translate(a)||!pwmc_translation_valid(a)||a->page!=q->requested+4096*k)return pweh_fail(r,PWEA_ARGUMENT);
            r->translated[kind]++;
        }
    }
    if(!pweh_binding(r)||!pgcd_actual_arch(0,&r->final)||!pwea_native_arch_valid(&r->final)||
       !pwfc_arch_stable(&r->before.cpu,&r->final.cpu)||r->final.cpacr!=r->before.cpacr||
       r->final.cpu.ticks<r->after.cpu.ticks||r->final.cpu.ticks-r->before.cpu.ticks>PGCD_FRESH_TICKS)return pweh_fail(r,PWEA_EFFECT);
    r->complete=1;r->unknown=0;return 1;
}
#endif
#endif
