/* Early incoming-UEFI producer, intentionally default OFF. Its first GetMap
 * has the same incoming boot-services trust boundary as ordinary admission;
 * a later map/hash is NOT claimed to retroactively qualify that call.
 * Enabling a physical candidate requires separate entry-contract/callback,
 * builder/codec/resource/model/session review. This is not a late-map bypass.
 * No secure assignment, remote startup, FreePages or native CPU startup here. */
#ifndef POLARIS_UEFI_WIFI_EARLY_NATIVE_H
#define POLARIS_UEFI_WIFI_EARLY_NATIVE_H
#ifndef EFI_XNU_WIFI_EARLY_MEMORY_AVAILABLE
#define EFI_XNU_WIFI_EARLY_MEMORY_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_EARLY_MEMORY_AVAILABLE
#if defined(POLARIS_EFI_TEST_QEMU)
#error "Early WiFi allocation requires a separately qualified physical incoming-UEFI profile"
#endif
#include "uefi-wifi-early-memory.h"
#define PWEA_CORE_PAGES ((PGCI_IMAGE_BYTES+4095)/4096)
struct pwea_core {
    struct pwmc_irq_AT AT[PWEA_CORE_PAGES];
    uint8_t hashes[PGCI_RANGE_COUNT][32];uint32_t pages,hash_count,hash_failed,complete;
    uint64_t TPL,smm;
};
struct pwea_native_call {
    struct pgcd_arch before,after;struct pgcd_fp_guard fp;
    struct pwea_core source[2];
    uint32_t issued,returned,unknown,complete,native_before,native_after;
};
struct pwea_native {
    struct pwea_memory memory;struct efi_loaded image;
    uint64_t system,image_address,native_address,boot,core;
    uint8_t BS[PWMC_BS_BYTES];struct pwea_native_call call[PWEA_CALLS];
    struct pwmc_translation AT[2][PWMC_PAGES];
    struct pgcd_arch final;
    uint32_t translated[2],attempted,complete,error,unknown;
};
_Static_assert(sizeof(struct pwea_native)==100848,"EARLY_WIFI_MEMORY_RAW_V1 ABI");
#if defined(POLARIS_WIFI_EARLY_SOFTWARE_PEER)
static int pwea_test_core_at(struct pwmc_irq_AT*);
static efi_status pwea_test_map(struct efi_system*,struct pwea_map*);
static efi_status pwea_test_allocate(struct efi_system*,uint64_t,uint64_t*);
#endif
static inline int pwea_core_at(struct pwmc_irq_AT*a)
{
#if defined(POLARIS_WIFI_EARLY_SOFTWARE_PEER)
    return pwea_test_core_at(a);
#else
    uint64_t saved;a->issued=1;
    __asm__ volatile("mrs %0,par_el1; at s1e1r,%2; isb; mrs %1,par_el1; msr par_el1,%0; isb"
        :"=&r"(saved),"=&r"(a->raw):"r"(a->page):"memory");a->returned=1;return 1;
#endif
}
static inline int pwea_native_fail(struct pwea_native*r,unsigned error)
{if(!r->error)r->error=error;r->unknown=1;return 0;}
static inline int pwea_native_binding(const struct pwea_native*r)
{
    const struct efi_system*s=(const void*)(uintptr_t)r->system;
    return (uintptr_t)s->boot==r->boot&&pgcd_equal(s->boot,r->BS,sizeof(r->BS))&&
        pgcd_equal((const void*)(uintptr_t)r->image_address,&r->image,sizeof(r->image))&&
        !*(const volatile uint32_t*)(uintptr_t)r->native_address;
}
static inline int pwea_native_source(struct pwea_native*r,unsigned call,unsigned phase,unsigned map)
{
    struct pwea_core*q=&r->call[call].source[phase];const struct pwea_map*m=&r->memory.map[map];
    if(!m->map.valid||!pwmc_zero(q,sizeof(*q))||!pwea_native_binding(r))return 0;
    for(unsigned k=0;k<PWEA_CORE_PAGES;k++){
        struct pwmc_irq_AT*a=&q->AT[k];a->page=r->core+4096*k;
        if(!polaris_efi_range_owned(m->data,m->map.bytes,m->map.stride,a->page,4096,3)&&
           !polaris_efi_range_owned(m->data,m->map.bytes,m->map.stride,a->page,4096,4))return 0;
        q->pages++;
        if(!pwea_core_at(a)||a->issued!=1||a->returned!=1||
           a->page!=r->core+4096*k||a->raw!=(UINT64_C(0xff00000000000b80)|a->page))return 0;
    }
    if(!pgci_verify((const void*)(uintptr_t)r->core,r->core,PGCI_IMAGE_BYTES,q->hashes,&q->hash_failed,&q->hash_count))return 0;
    q->TPL=pwfi_le((const void*)(uintptr_t)(r->core+0x1b098),8);
    q->smm=pwfi_le((const void*)(uintptr_t)(r->core+0x1cb78),8);
    if(q->TPL!=4||q->smm||!pwea_native_binding(r))return 0;q->complete=1;return 1;
}
static inline void pwea_native_guard_seal(const struct pwea_native*r,unsigned call,uint8_t out[32])
{
    struct pwfi_sha256 h;pwfi_init(&h);
    /* Foreign service outputs live only in the pure memory frame. Everything
     * outside it, including the saved FP image and earlier call evidence, is
     * protected until the original call has returned. */
    const uint8_t*p=(const void*)r;
    for(size_t k=sizeof(r->memory);k<sizeof(*r);k++)pwfi_byte(&h,p[k]);
    for(unsigned k=0;k<4;k++)pwfi_byte(&h,(uint8_t)(call>>(8*k)));pwfi_final(&h,out);
}
static inline int pwea_native_arch_valid(const struct pgcd_arch*a)
{return pwfc_arch_admitted(&a->cpu)&&a->cpu.mair==UINT64_C(0xffbb4400)&&!a->cpu.daif&&a->cpu.group1==1&&((a->cpacr>>20)&3)==3;}
static inline int pwea_native_run(struct pwea_native*r,struct efi_system*system,
    const struct efi_loaded*image,const volatile uint32_t*native,uint64_t bank,uint64_t bank_bytes)
{
    if(!r||!system||!image||!native||!pwmc_zero(r,sizeof(*r)))return 0;
    r->attempted=1;
    if(image->revision!=0x1000||image->system!=system||image->code_type!=3||image->data_type!=4||
       !pwmc_parent_in_image(image,(uintptr_t)r,sizeof(*r))||!pwmc_parent_in_image(image,(uintptr_t)native,4)||
       !pwea_disjoint((uintptr_t)r,sizeof(*r),(uintptr_t)native,4)||
       !pwea_disjoint((uintptr_t)r,sizeof(*r),(uintptr_t)image,sizeof(*image))||
       !pwea_disjoint((uintptr_t)r,sizeof(*r),(uintptr_t)system,sizeof(*system))||*native)return pwea_native_fail(r,PWEA_ARGUMENT);
    r->image=*image;r->system=(uintptr_t)system;r->image_address=(uintptr_t)image;r->native_address=(uintptr_t)native;
    r->boot=(uintptr_t)system->boot;
    if(r->boot<0x1b800||((r->boot-0x1b800)&4095))return pwea_native_fail(r,PWEA_ARGUMENT);
    r->core=r->boot-0x1b800;
    if(r->core>UINT64_MAX-PGCI_IMAGE_BYTES||
       (uintptr_t)system->boot->get_map!=r->core+0xd3ec||
       (uintptr_t)system->boot->allocate_pages!=r->core+PWMC_ALLOC_RVA||
       !pwea_disjoint(r->core,PGCI_IMAGE_BYTES,(uintptr_t)r,sizeof(*r)))return pwea_native_fail(r,PWEA_ARGUMENT);
    pgcd_copy(r->BS,system->boot,sizeof(r->BS));
    const struct pwea_input input={(uintptr_t)image->base,image->bytes,bank,bank_bytes};
    if(pwea_begin(&r->memory,&input)<0)return pwea_native_fail(r,PWEA_ARGUMENT);
    for(unsigned n=0;n<PWEA_CALLS;n++){
        struct pwea_command command;uint8_t seal[32],guard[32],check[32];struct pwea_native_call*c=&r->call[n];
        if(pwea_next(&r->memory,&command)!=PWEA_IO||command.sequence!=n+1||!pwea_native_binding(r))return pwea_native_fail(r,PWEA_REENTRY);
        c->native_before=*native;
        if(!pgcd_actual_arch(0,&c->before)||!pwea_native_arch_valid(&c->before)||c->native_before)return pwea_native_fail(r,PWEA_ARGUMENT);
        if(n&&(!pwfc_arch_stable(&r->call[0].before.cpu,&c->before.cpu)||c->before.cpacr!=r->call[0].before.cpacr||
           c->before.cpu.ticks<r->call[n-1].after.cpu.ticks||
           !pwea_native_source(r,n,0,(n-1)/2)))return pwea_native_fail(r,PWEA_ARGUMENT);
        if(!pgcd_actual_fp_save(0,&c->fp)||c->fp.saved!=1||c->fp.restored||c->fp.cpacr_before!=c->before.cpacr||!pwea_native_binding(r))return pwea_native_fail(r,PWEA_ARGUMENT);
        c->issued=c->unknown=1;pwea_call_seal(&r->memory,seal);pwea_native_guard_seal(r,n,guard);pwfc_actual_order(0);
        if(command.operation==PWEA_MAP){
            struct pwea_map*m=&r->memory.map[command.index];
#if defined(POLARIS_WIFI_EARLY_SOFTWARE_PEER)
            m->map.status=pwea_test_map(system,m);
#else
            m->map.status=system->boot->get_map(&m->map.bytes,m->data,&m->map.key,&m->map.stride,&m->map.version);
#endif
        }else{
            struct pwea_claim*q=&r->memory.claim[command.index];
#if defined(POLARIS_WIFI_EARLY_SOFTWARE_PEER)
            q->status=pwea_test_allocate(system,command.pages,&q->returned_address);
#else
            q->status=system->boot->allocate_pages(2,2,command.pages,&q->returned_address);
#endif
        }
        pwea_native_guard_seal(r,n,check);
        if(!pgcd_equal(guard,check,32)||!pwea_native_binding(r))return pwea_native_fail(r,PWEA_EFFECT);
        c->returned=1;c->native_after=*native;
        if(!pgcd_actual_arch(0,&c->after)||!pwea_native_arch_valid(&c->after)||
           !pwfc_arch_stable(&c->before.cpu,&c->after.cpu)||c->before.cpacr!=c->after.cpacr||
           c->after.cpu.ticks<c->before.cpu.ticks||c->after.cpu.ticks-c->before.cpu.ticks>PGCD_FRESH_TICKS||
           !pgcd_actual_fp_restore(0,&c->fp)||c->fp.restored!=1||c->native_after)return pwea_native_fail(r,PWEA_ARGUMENT);
        if(pwea_complete(&r->memory,&command,1,seal)<0)return pwea_native_fail(r,PWEA_EFFECT);
        if(!pwea_native_source(r,n,1,n/2))return pwea_native_fail(r,PWEA_ARGUMENT);
        c->complete=1;c->unknown=0;
    }
    for(unsigned kind=0;kind<2;kind++)for(unsigned k=0;k<r->memory.claim[kind].pages;k++){
        struct pwmc_translation*a=&r->AT[kind][k];a->page=r->memory.claim[kind].requested+4096*k;
        if(!pwea_native_binding(r)||!pwmc_actual_translate(a)||!pwmc_translation_valid(a)||
           a->page!=r->memory.claim[kind].requested+4096*k)return pwea_native_fail(r,PWEA_ARGUMENT);
        r->translated[kind]++;
    }
    if(r->memory.complete!=1||r->memory.unknown||!pwea_native_binding(r)||
       !pgcd_actual_arch(0,&r->final)||!pwea_native_arch_valid(&r->final)||
       !pwfc_arch_stable(&r->call[0].before.cpu,&r->final.cpu)||r->final.cpacr!=r->call[0].before.cpacr||
       r->final.cpu.ticks<r->call[4].after.cpu.ticks||r->final.cpu.ticks-r->call[4].after.cpu.ticks>PGCD_FRESH_TICKS)
        return pwea_native_fail(r,PWEA_EFFECT);
    r->complete=1;return 1;
}
#endif
#endif
