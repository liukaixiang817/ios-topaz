/* Actual pre-native independent RAM producer for current NV inputs/shadows.
 * Original UEFI services run only while the early parent's native flag is0.
 * No allocation is freed, shared, or published to a remote processor. */
#ifndef POLARIS_UEFI_WIFI_NV_NATIVE_H
#define POLARIS_UEFI_WIFI_NV_NATIVE_H
#include "uefi-wifi-early-native.h"
#include "uefi-wifi-nv-inputs.h"
#ifndef EFI_XNU_WIFI_NV_NATIVE_AVAILABLE
#define EFI_XNU_WIFI_NV_NATIVE_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_NV_NATIVE_AVAILABLE
#if !EFI_XNU_WIFI_EARLY_MEMORY_AVAILABLE
#error Native NV requires the actual early parent
#endif
#define PNNV_CALLS 5u
#define PNNV_TICKS UINT64_C(2304000000)
struct pnnv_state {
    uint64_t early,self;uint8_t early_digest[32];struct pnv_plan plan;
    struct pwea_map map[3];struct pwea_native_call call[PNNV_CALLS];
    struct {uint64_t address,status;} allocation;
    struct pnv_result inputs;struct pwmc_translation AT;uint8_t AT_history[32];
    struct pgcd_arch entry,current;
    uint32_t attempted,unknown,error,pending,calls,allocated,translated[2],complete,reserved;
    uint8_t digest[32];
    uint64_t consumer; /* One later native RAM-shadow owner; outside producer digest. */
};
#if defined(POLARIS_WIFI_NV_SOFTWARE_PEER)
static efi_status pnnv_map(struct efi_system*,struct pwea_map*);
static efi_status pnnv_allocate(struct efi_system*,uint64_t*);
#else
static inline efi_status pnnv_map(struct efi_system*s,struct pwea_map*m)
{return s->boot->get_map(&m->map.bytes,m->data,&m->map.key,&m->map.stride,&m->map.version);}
static inline efi_status pnnv_allocate(struct efi_system*s,uint64_t*at)
{return s->boot->allocate_pages(0,2,PNV_BYTES/4096,at);}
#endif
static inline int pnnv_fail(struct pnnv_state*r,unsigned error)
{r->unknown=1;if(!r->error)r->error=error;return 0;}
static inline void pnnv_seal(struct pnnv_state*r,const void*out,size_t bytes,uint8_t hash[32])
{
    struct pwfi_sha256 h;pwfi_init(&h);uintptr_t first=(uintptr_t)out,last=first+bytes;
    for(size_t n=0;n<sizeof(*r);n++){uintptr_t p=(uintptr_t)r+n;if(p>=first&&p<last)continue;pwfi_byte(&h,*(const uint8_t*)p);}pwfi_final(&h,hash);
}
static inline int pnnv_bound(struct pnnv_state*r)
{
    if(!r||r->self!=(uintptr_t)r||!r->attempted||r->unknown||r->error)return 0;
    const struct pwea_native*e=(const void*)(uintptr_t)r->early;uint8_t hash[32];pnv_hash(e,sizeof(*e),hash);
    return pnv_equal(hash,r->early_digest,32)&&e->complete==1&&!e->unknown&&!e->error&&pwea_native_binding(e);
}
static inline int pnnv_arch(struct pnnv_state*r,struct pgcd_arch*a)
{
    if(!pgcd_actual_arch(0,a)||!pwea_native_arch_valid(a))return 0;
    const struct pwfc_arch*b=&r->entry.cpu,*c=&a->cpu;
    return b->el==c->el&&b->mpidr==c->mpidr&&b->ttbr0==c->ttbr0&&b->ttbr1==c->ttbr1&&b->tcr==c->tcr&&
        b->sctlr==c->sctlr&&b->mair==c->mair&&b->daif==c->daif&&b->sre==c->sre&&b->group1==c->group1&&
        b->frequency==c->frequency&&r->entry.cpacr==a->cpacr&&c->ticks>=b->ticks&&c->ticks-b->ticks<=PNNV_TICKS;
}
static inline int pnnv_map_valid(struct pwea_map*m)
{
    struct polaris_efi_memory checked;
    if(m->map.status||!m->map.key||m->map.version!=1||!polaris_efi_memory_check(m->data,m->map.bytes,PGCD_MAP_CAP,m->map.stride,&checked))return 0;
    m->map.valid=1;return 1;
}
/* Immutable native records surround each original service phase. Enumeration
 * and read-only BlockIO are one synchronous collector phase; its own checked
 * per-read protocol/media records remain nested in the allowed result. */
static inline int pnnv_call(struct pnnv_state*r,unsigned index)
{
    if(index>=PNNV_CALLS||index!=r->calls||r->pending||!pnnv_bound(r))return 0;
    const struct pwea_native*e=(const void*)(uintptr_t)r->early;struct efi_system*s=(void*)(uintptr_t)e->system;
    struct pwea_native_call*c=&r->call[index];const struct pwea_map*source=index?r->map:(const struct pwea_map*)&e->memory.map[2];
    if(!pwea_core_check(e,&c->source[0],source)||!pnnv_arch(r,&c->before)||
       !pgcd_actual_fp_save(0,&c->fp)||c->fp.saved!=1||c->fp.restored||c->fp.cpacr_before!=c->before.cpacr)return pnnv_fail(r,2);
    void*out;size_t bytes;struct pwea_map*m=0;
    if(index==1){out=&r->allocation;bytes=sizeof(r->allocation);}
    else if(index==3){out=&r->inputs;bytes=sizeof(r->inputs);}
    else{m=&r->map[index/2];m->map.bytes=PGCD_MAP_CAP;m->map.issued=1;out=m;bytes=sizeof(*m);}
    c->issued=c->unknown=1;r->pending=index+1;uint8_t before[32],after[32];pnnv_seal(r,out,bytes,before);
    unsigned ok=1;
    if(index==1)r->allocation.status=pnnv_allocate(s,&r->allocation.address);
    else if(index==3)ok=(unsigned)pnv_collect(s->boot,&r->plan,r->allocation.address,&r->inputs);
    else m->map.status=pnnv_map(s,m);
    pnnv_seal(r,out,bytes,after);
    if(!pnv_equal(before,after,32)||!pnnv_bound(r)||!pnnv_arch(r,&c->after)||c->after.cpu.ticks<c->before.cpu.ticks)return pnnv_fail(r,3);
    c->returned=1;
    if(!pgcd_actual_fp_restore(0,&c->fp)||c->fp.restored!=1||!pnnv_bound(r))return pnnv_fail(r,3);
    if(m){m->map.returned=1;if(!pnnv_map_valid(m))return pnnv_fail(r,4);source=m;}
    if(!ok||(index==1&&r->allocation.status)||!pwea_core_check(e,&c->source[1],source)||!pnnv_arch(r,&r->current))return pnnv_fail(r,4);
    c->unknown=0;c->complete=1;r->calls++;r->pending=0;return 1;
}
static inline int pnnv_translate(struct pnnv_state*r,unsigned pass)
{
    if(pass>1||r->translated[pass])return 0;
    for(unsigned n=0;n<PNV_BYTES/4096;n++){
        struct pwmc_translation*t=&r->AT;for(unsigned j=0;j<sizeof(*t);j++)((uint8_t*)t)[j]=0;t->page=r->allocation.address+4096*n;
        if(r->unknown||r->error||!pwea_native_binding((const void*)(uintptr_t)r->early)||!pwmc_actual_translate(t)||!pwmc_translation_valid(t)||t->page!=r->allocation.address+4096*n||!pnnv_arch(r,&r->current))return pnnv_fail(r,5);
        struct pwfi_sha256 h;pwfi_init(&h);for(unsigned j=0;j<32;j++)pwfi_byte(&h,r->AT_history[j]);
        for(unsigned j=0;j<sizeof(*t);j++)pwfi_byte(&h,((const uint8_t*)t)[j]);pwfi_final(&h,r->AT_history);r->translated[pass]++;
    }return 1;
}
static inline int pnnv_run(struct pnnv_state*r,const struct pwea_native*e,const struct pnv_plan*plan)
{
    if(!r||!e||!plan||!pnv_zero(r,sizeof(*r))||e->complete!=1||e->unknown||e->error||!pwea_native_binding(e)||
       !pwmc_parent_in_image(&e->image,(uintptr_t)r,sizeof(*r))||!pwmc_parent_in_image(&e->image,(uintptr_t)plan,sizeof(*plan))||
       !pwea_disjoint((uintptr_t)r,sizeof(*r),(uintptr_t)e,sizeof(*e))||!pwea_disjoint((uintptr_t)r,sizeof(*r),(uintptr_t)plan,sizeof(*plan)))return 0;
    r->early=(uintptr_t)e;r->self=(uintptr_t)r;r->plan=*plan;pnv_hash(e,sizeof(*e),r->early_digest);r->attempted=1;
    if(!pnv_plan_valid(plan)||!pgcd_actual_arch(0,&r->entry)||!pwea_native_arch_valid(&r->entry)||!pnnv_bound(r))return pnnv_fail(r,1);
    if(!pnnv_call(r,0)||!pnnv_call(r,1))return 0;
    uint64_t at=r->allocation.address;
    if(!at||(at&4095)||at>UINT64_MAX-PNV_BYTES||!polaris_efi_range_owned(r->map[0].data,r->map[0].map.bytes,r->map[0].map.stride,at,PNV_BYTES,7)||
       !pwea_disjoint(at,PNV_BYTES,(uintptr_t)e->image.base,e->image.bytes)||!pwea_disjoint(at,PNV_BYTES,e->memory.input.bank,e->memory.input.bank_bytes))return pnnv_fail(r,6);
    for(unsigned n=0;n<2;n++)if(!pwea_disjoint(at,PNV_BYTES,e->memory.claim[n].requested,e->memory.claim[n].bytes))return pnnv_fail(r,6);
    if(!pnnv_call(r,2))return 0;
    const struct pwea_map*a=&r->map[0],*b=&r->map[1];
    if(a->map.key==b->map.key||a->map.stride!=b->map.stride||!polaris_efi_range_owned(b->data,b->map.bytes,b->map.stride,at,PNV_BYTES,2)||
       !pwmc_delta_direction(a->data,a->map.bytes,b->data,b->map.bytes,(unsigned)a->map.stride,at,PNV_BYTES,7,2)||
       !pwmc_delta_direction(b->data,b->map.bytes,a->data,a->map.bytes,(unsigned)a->map.stride,at,PNV_BYTES,2,7))return pnnv_fail(r,7);
    r->allocated=1;
    if(!pnnv_translate(r,0)||!pnnv_call(r,3)||!pnnv_call(r,4))return 0;
    const struct pwea_map*m=&r->map[2];
    if(!polaris_efi_range_owned(m->data,m->map.bytes,m->map.stride,at,PNV_BYTES,2)||!pnnv_translate(r,1)||!pnnv_bound(r)||!pnnv_arch(r,&r->current))return pnnv_fail(r,8);
    if(!r->inputs.complete||r->inputs.unknown||r->inputs.error||r->inputs.allocation!=at||r->inputs.passes!=2)return pnnv_fail(r,8);
    r->complete=1;pnv_hash(r,offsetof(struct pnnv_state,digest),r->digest);return 1;
}
#endif
#endif
