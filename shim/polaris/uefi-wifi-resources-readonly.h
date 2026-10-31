/* 0142 proposal, not in0141. Actual CPU0/preCPU_ON resource observations.
 * Exactly2 bounded GetMemoryMap calls and7 known PSCI AFFINITY_INFO calls;
 * fixed register reads only. No MMIO/SMEM/DMA/permission/PIL/power operation.
 * Keep full maps+keys+raw results, never turn Reserved into free/ownership.
 * A complete observed OFF vector is not a same-EE/EL3 exclusive lifetime.
 */
#ifndef POLARIS_UEFI_WIFI_RESOURCES_READONLY_H
#define POLARIS_UEFI_WIFI_RESOURCES_READONLY_H
#include "uefi-wifi-firstread-normal-nc.h"
#include <stddef.h>
#ifndef EFI_XNU_WIFI_RESOURCES_AVAILABLE
#define EFI_XNU_WIFI_RESOURCES_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_RESOURCES_AVAILABLE && !EFI_XNU_WIFI_CACHE_AVAILABLE
#error "Resource observations require the original cache witness"
#endif
#define PFR_MAP_CAP 8192u
#define PFR_RESOURCES 6u
#define PFR_BUDGET_TICKS UINT64_C(3840000)
static const uint64_t pfr_peers[7]={0x100,0x200,0x300,0x400,0x500,0x600,0x700};
struct pfr_range {uint64_t start,bytes;};
static const struct pfr_range pfr_ranges[PFR_RESOURCES]={
    {UINT64_C(0x8e400000),UINT64_C(0x7800000)}, /* ownMPSS, not free */
    {UINT64_C(0x96900000),UINT64_C(0x200000)}, /* ownMBA, not free */
    {UINT64_C(0x8e300000),UINT64_C(0x100000)}, /* WLAN_FW, not automaticallyMSA */
    {UINT64_C(0x8bf00000),UINT64_C(0x500000)}, /* camera exclusion */
    {UINT64_C(0x8c415000),UINT64_C(0x2000)},  /* GPU exclusion */
    {UINT64_C(0x8c500000),UINT64_C(0x1e00000)} /* ADSP exclusion */
};
enum pfr_error {PFR_OK,PFR_DISABLED,PFR_STAGE,PFR_SELF,PFR_WITNESS,PFR_ARCH,PFR_CLOCK,
    PFR_MAP_STATUS,PFR_MAP_GEOMETRY,PFR_MAP_CHANGED,PFR_PSCI_RESULT,PFR_PEER_ON,PFR_OUTSTANDING};
struct pfr_map {
    uint64_t status,bytes,key,stride;uint32_t version;volatile uint32_t issued,completed;uint32_t geometry_valid;
};
struct pfr_coverage {
    uint64_t covered_bytes,type_mask,attributes_or;uint32_t overlapping_descriptors,complete,runtime_seen,unknown_type;
};
struct pfr_result {
    uint64_t self_base,self_bytes,self_system,cookie;
    struct pwfc_arch before,after;
    uint64_t witness_cookie,witness_after_ticks;
    struct pfr_map map[2];
    uint64_t affinity_raw[7],affinity_before[7],affinity_after[7];
    volatile uint32_t attempted,error,phase,affinity_issued,affinity_completed,affinity_unknown;
    uint32_t self_bound,all7_observed_OFF,maps_byteidentical,arch_issued,arch_completed;
    struct pfr_coverage coverage[2][PFR_RESOURCES];
    /* Full raw descriptor bytes and any partial output remain even on error. */
    uint8_t maps[2][PFR_MAP_CAP] __attribute__((aligned(8)));
};
struct pfr_lifetime {volatile uint32_t spent;uint64_t result_address;};
struct pfr_io {
    void *context;struct efi_system *system;
    int (*arch)(void *,struct pwfc_arch *);
    int64_t (*affinity)(void *,uint64_t);
    void (*order)(void *);
};
static inline int pfr_bind(struct pfr_result *r,const struct efi_loaded *self)
{
    if(!r||!self||r->attempted||r->self_bound)return 0;
    uint64_t base=(uintptr_t)self->base,address=(uintptr_t)r;
    if(self->revision!=0x1000||self->code_type!=3||self->data_type!=4||!base||
       !self->bytes||base>UINT64_MAX-self->bytes||address<base||sizeof(*r)>self->bytes||
       address-base>self->bytes-sizeof(*r)||
       (base<UINT64_C(0x86200000)&&UINT64_C(0x86000000)<base+self->bytes))return 0;
    r->self_base=base;r->self_bytes=self->bytes;r->self_system=(uintptr_t)self->system;r->self_bound=1;return 1;
}
static inline int pfr_live(const struct pwfc_result *cache,const struct pfr_io *io,struct pfr_result *r)
{
    struct pwfc_arch a={0};uint64_t previous=r->after.ticks;r->arch_issued++;
    int observed=io->arch(io->context,&a);if(observed)r->arch_completed++;r->after=a;
    if(!observed||!pwnc_arch_same(&cache->after,&a)||a.mair!=UINT64_C(0xffbb4400)){
        r->error=PFR_ARCH;return 0;
    }
    if(a.ticks<cache->after.ticks||a.ticks-cache->after.ticks>PFR_BUDGET_TICKS){r->error=PFR_CLOCK;return 0;}
    if(!r->before.ticks){r->before=a;r->cookie=a.ticks|1;return 1;}
    const struct pwfc_arch *b=&r->before;
    if(a.el!=b->el||a.mpidr!=b->mpidr||a.ttbr0!=b->ttbr0||a.ttbr1!=b->ttbr1||a.tcr!=b->tcr||
       a.sctlr!=b->sctlr||a.mair!=b->mair||a.daif!=b->daif||a.sre!=b->sre||a.group1!=b->group1||a.frequency!=b->frequency){r->error=PFR_ARCH;return 0;}
    if(a.ticks<b->ticks||a.ticks<previous||a.ticks-b->ticks>PFR_BUDGET_TICKS){r->error=PFR_CLOCK;return 0;}
    return 1;
}
static inline int pfr_map(const struct pfr_io *io,struct pfr_result *r,unsigned slot)
{
    struct pfr_map *m=&r->map[slot];m->bytes=PFR_MAP_CAP;m->issued=1;r->error=PFR_OUTSTANDING;io->order(io->context);
    m->status=io->system->boot->get_map(&m->bytes,r->maps[slot],&m->key,&m->stride,&m->version);
    m->completed=1;io->order(io->context);
    if(m->status){r->error=PFR_MAP_STATUS;return 0;}
    struct polaris_efi_memory checked;
    if(!m->key||m->version!=1||!polaris_efi_memory_check(r->maps[slot],m->bytes,PFR_MAP_CAP,m->stride,&checked)){
        r->error=PFR_MAP_GEOMETRY;return 0;
    }
    m->geometry_valid=1;r->error=PFR_OK;io->order(io->context);
    for(unsigned k=0;k<PFR_RESOURCES;k++) {
        struct pfr_coverage *v=&r->coverage[slot][k];uint64_t lo=pfr_ranges[k].start,hi=lo+pfr_ranges[k].bytes;
        for(uint64_t at=0;at<m->bytes;at+=m->stride) {
            const struct efi_memory *d=(const void*)(r->maps[slot]+at);uint64_t end=d->physical+4096*d->pages;
            if(d->physical>=hi||end<=lo)continue;
            uint64_t a=d->physical>lo?d->physical:lo,b=end<hi?end:hi;
            v->covered_bytes+=b-a;v->overlapping_descriptors++;v->attributes_or|=d->attributes;
            if(d->type<64)v->type_mask|=UINT64_C(1)<<d->type;else v->unknown_type=1;
            if(d->attributes>>63)v->runtime_seen=1;
        }
        v->complete=v->covered_bytes==pfr_ranges[k].bytes;
    }
    return 1;
}
static inline int pfr_owned(const struct pfr_result *r,unsigned slot,uint64_t address,uint64_t bytes)
{
    const struct pfr_map *m=&r->map[slot];
    if(!address||!bytes||address>UINT64_MAX-bytes||address+bytes>UINT64_MAX-4095)return 0;
    for(uint64_t p=address&~UINT64_C(4095);p<address+bytes;p+=4096)
        if(!polaris_efi_range_owned(r->maps[slot],m->bytes,m->stride,p,4096,3)&&
           !polaris_efi_range_owned(r->maps[slot],m->bytes,m->stride,p,4096,4))return 0;
    return 1;
}
static inline int pfr_collect(unsigned enabled,unsigned stage,const struct pwfc_result *cache,const struct pfr_io *io,
    struct pfr_lifetime *ticket,struct pfr_result *r)
{
    if(!ticket||!r||ticket->spent)return 0;ticket->spent=1;ticket->result_address=(uintptr_t)r;
    if(r->attempted)return 0;r->attempted=1;
    if(enabled!=1){r->error=PFR_DISABLED;return 0;}
    if(stage!=2){r->error=PFR_STAGE;return 0;}
    if(!pwnc_witness(cache)){r->error=PFR_WITNESS;return 0;}
    r->witness_cookie=cache->cookie;r->witness_after_ticks=cache->after.ticks;
    if(!io||!io->system||!io->system->boot||!io->system->boot->get_map||!io->arch||!io->affinity||!io->order||
       !r->self_bound||!r->self_system||r->self_system!=(uintptr_t)io->system){r->error=PFR_SELF;return 0;}
    if(cache->owner.system!=io->system){r->error=PFR_WITNESS;return 0;}
    uint64_t ticket_address=(uintptr_t)ticket;
    if(ticket_address<r->self_base||sizeof(*ticket)>r->self_bytes||
       ticket_address-r->self_base>r->self_bytes-sizeof(*ticket)){r->error=PFR_SELF;return 0;}
    r->phase=1;if(!pfr_live(cache,io,r)||!pfr_map(io,r,0)||!pfr_live(cache,io,r))return 0;
    if(!pfr_owned(r,0,(uintptr_t)r,sizeof(*r))||!pfr_owned(r,0,(uintptr_t)ticket,sizeof(*ticket))||
       !pfr_owned(r,0,r->self_base,r->self_bytes)){r->error=PFR_SELF;return 0;}
    r->phase=2;unsigned peer_error=0;
    for(unsigned k=0;k<7;k++) {
        if(!pfr_live(cache,io,r))return 0;
        r->affinity_before[k]=r->after.ticks;r->affinity_issued|=1u<<k;r->affinity_unknown|=1u<<k;
        r->error=PFR_OUTSTANDING;io->order(io->context);
        r->affinity_raw[k]=(uint64_t)io->affinity(io->context,pfr_peers[k]);
        r->affinity_completed|=1u<<k;io->order(io->context);
        r->affinity_unknown&=~(1u<<k);r->error=PFR_OK;io->order(io->context);
        if(!pfr_live(cache,io,r))return 0;r->affinity_after[k]=r->after.ticks;
        if(r->affinity_raw[k]!=1&&!peer_error)peer_error=r->affinity_raw[k]==0||r->affinity_raw[k]==2?PFR_PEER_ON:PFR_PSCI_RESULT;
    }
    r->all7_observed_OFF=r->affinity_completed==0x7f&&!r->affinity_unknown&&!peer_error;
    r->phase=3;if(!pfr_map(io,r,1)||!pfr_live(cache,io,r))return 0;
    if(r->map[0].bytes!=r->map[1].bytes||r->map[0].key!=r->map[1].key||
       r->map[0].stride!=r->map[1].stride||r->map[0].version!=r->map[1].version||
       !pwfc_equal(r->maps[0],r->maps[1],r->map[0].bytes)){r->error=PFR_MAP_CHANGED;return 0;}
    r->maps_byteidentical=1;r->phase=4;r->error=peer_error;io->order(io->context);return !peer_error;
}
#if EFI_XNU_WIFI_RESOURCES_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
static struct pfr_result pfr_record;
static struct pfr_lifetime pfr_ticket;
static inline int64_t pfr_actual_affinity(void *context,uint64_t target)
{
    (void)context;
#if defined(__aarch64__) || defined(__arm64__)
    register uint64_t x0 __asm__("x0")=UINT64_C(0xc4000004),x1 __asm__("x1")=target,x2 __asm__("x2")=0,x3 __asm__("x3")=0;
    __asm__ volatile("smc #0":"+r"(x0),"+r"(x1),"+r"(x2),"+r"(x3)::"x4","x5","x6","x7","x8","x9","x10","x11","x12","x13","x14","x15","x16","x17","cc","memory");return (int64_t)x0;
#else
    (void)target;return -1;
#endif
}
static inline int pfr_bind_resident(const struct efi_loaded *self){return pfr_bind(&pfr_record,self);}
static inline int pfr_prepare(struct efi_system *system,const struct pwfc_result *cache,uint32_t stage)
{
    const struct pfr_io io={0,system,pwfc_actual_arch,pfr_actual_affinity,pwfc_actual_order};
    return pfr_collect(1,stage,cache,&io,&pfr_ticket,&pfr_record);
}
#else
static inline int pfr_bind_resident(const struct efi_loaded *self){(void)self;return 0;}
static inline int pfr_prepare(struct efi_system *system,const struct pwfc_result *cache,uint32_t stage){(void)system;(void)cache;(void)stage;return 0;}
#endif
/* No reporting here: main must append sizeof(record), including BOTH complete
 * fixed raw buffers, to RAM log (not slow firmware console). Failed/partial
 * GetMemoryMap has unknown output extent: retain CAP, never claim it filled.
 * Keep both maps if changed. New explicit scope should provide128KiB RAM log
 * with sticky overflow/no claimed complete truncation; old/defaultOFF unchanged.
 * DT RMTFS0/2MiB and dynamic MSA1MiB remain unassigned, with no allow-write bit.
 */
#endif
