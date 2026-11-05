/* Pre-native independent CE DMA backing, below WCN3990's35-bit limit.
 * Original services only before native ownership. No buffer is read/written,
 * published to hardware, freed, or used as proof of current SMMU routing. */
#ifndef POLARIS_UEFI_WIFI_CE_MEMORY_NATIVE_H
#define POLARIS_UEFI_WIFI_CE_MEMORY_NATIVE_H
#include "uefi-wifi-early-native.h"
#include "../../tools/polaris-wifi-ce-memory.h"
#ifndef EFI_XNU_WIFI_CE_MEMORY_AVAILABLE
#define EFI_XNU_WIFI_CE_MEMORY_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_CE_MEMORY_AVAILABLE
#if !EFI_XNU_WIFI_EARLY_MEMORY_AVAILABLE
#error Native CE memory requires the actual early parent
#endif
#define PCDM_CALLS 3u
#define PCDM_TICKS UINT64_C(576000000)
struct pcdm_state {
    uint64_t early,self;uint8_t early_digest[32];struct pwdm_layout layout;
    struct pwea_map map[2];struct pwea_native_call call[PCDM_CALLS];
    struct {uint64_t address,status;} allocation;
    struct pwea_core final_source;struct pwmc_translation AT;uint8_t AT_history[32];
    struct pgcd_arch entry,current;
    uint32_t attempted,unknown,error,pending,calls,allocated,translated[2],complete,reserved;
    uint8_t digest[32];
    uint64_t consumer; /* One later native CE owner; outside producer digest. */
};
#if defined(POLARIS_WIFI_CE_MEMORY_SOFTWARE_PEER)
static efi_status pcdm_map(struct efi_system*,struct pwea_map*);
static efi_status pcdm_allocate(struct efi_system*,uint64_t*);
#else
static inline efi_status pcdm_map(struct efi_system*s,struct pwea_map*m)
{return s->boot->get_map(&m->map.bytes,m->data,&m->map.key,&m->map.stride,&m->map.version);}
static inline efi_status pcdm_allocate(struct efi_system*s,uint64_t*at)
{return s->boot->allocate_pages(1,2,PWDM_BYTES/4096,at);}
#endif
static inline void pcdm_hash(const void*p,size_t n,uint8_t out[32])
{struct pwfi_sha256 h;pwfi_init(&h);const uint8_t*b=p;for(size_t j=0;j<n;j++)pwfi_byte(&h,b[j]);pwfi_final(&h,out);}
static inline int pcdm_fail(struct pcdm_state*r,unsigned error)
{r->unknown=1;if(!r->error)r->error=error;return 0;}
static inline void pcdm_seal(struct pcdm_state*r,const void*out,size_t bytes,uint8_t hash[32])
{
    struct pwfi_sha256 h;pwfi_init(&h);uintptr_t first=(uintptr_t)out,last=first+bytes;
    for(size_t n=0;n<sizeof(*r);n++){uintptr_t p=(uintptr_t)r+n;if(p>=first&&p<last)continue;pwfi_byte(&h,*(const uint8_t*)p);}pwfi_final(&h,hash);
}
static inline int pcdm_bound(struct pcdm_state*r)
{
    if(!r||r->self!=(uintptr_t)r||!r->attempted||r->unknown||r->error)return 0;
    const struct pwea_native*e=(const void*)(uintptr_t)r->early;uint8_t hash[32];pcdm_hash(e,sizeof(*e),hash);
    return pgcd_equal(hash,r->early_digest,32)&&e->complete==1&&!e->unknown&&!e->error&&pwea_native_binding(e);
}
static inline int pcdm_arch(struct pcdm_state*r,struct pgcd_arch*a)
{
    if(!pgcd_actual_arch(0,a)||!pwea_native_arch_valid(a))return 0;
    const struct pwfc_arch*b=&r->entry.cpu,*c=&a->cpu;
    return b->el==c->el&&b->mpidr==c->mpidr&&b->ttbr0==c->ttbr0&&b->ttbr1==c->ttbr1&&b->tcr==c->tcr&&
        b->sctlr==c->sctlr&&b->mair==c->mair&&b->daif==c->daif&&b->sre==c->sre&&b->group1==c->group1&&
        b->frequency==c->frequency&&r->entry.cpacr==a->cpacr&&c->ticks>=b->ticks&&c->ticks-b->ticks<=PCDM_TICKS;
}
static inline int pcdm_map_valid(struct pwea_map*m)
{
    struct polaris_efi_memory checked;
    if(m->map.status||!m->map.key||m->map.version!=1||!polaris_efi_memory_check(m->data,m->map.bytes,PGCD_MAP_CAP,m->map.stride,&checked))return 0;
    m->map.valid=1;return 1;
}
/* Preserve Core/FP/source identity around GetMap, AllocateMaxAddress, GetMap. */
static inline int pcdm_call(struct pcdm_state*r,unsigned index)
{
    if(index>=PCDM_CALLS||index!=r->calls||r->pending||!pcdm_bound(r))return 0;
    const struct pwea_native*e=(const void*)(uintptr_t)r->early;struct efi_system*s=(void*)(uintptr_t)e->system;
    struct pwea_native_call*c=&r->call[index];const struct pwea_map*source=index?r->map:(const struct pwea_map*)&e->memory.map[2];
    if(!pwea_core_check(e,&c->source[0],source)||!pcdm_arch(r,&c->before)||
       !pgcd_actual_fp_save(0,&c->fp)||c->fp.saved!=1||c->fp.restored||c->fp.cpacr_before!=c->before.cpacr)return pcdm_fail(r,2);
    void*out;size_t bytes;struct pwea_map*m=0;
    if(index==1){r->allocation.address=PWDM_LIMIT-1;out=&r->allocation;bytes=sizeof(r->allocation);}
    else{m=&r->map[index/2];m->map.bytes=PGCD_MAP_CAP;m->map.issued=1;out=m;bytes=sizeof(*m);}
    c->issued=c->unknown=1;r->pending=index+1;uint8_t before[32],after[32];pcdm_seal(r,out,bytes,before);
    if(index==1)r->allocation.status=pcdm_allocate(s,&r->allocation.address);
    else m->map.status=pcdm_map(s,m);
    pcdm_seal(r,out,bytes,after);
    if(!pgcd_equal(before,after,32)||!pcdm_bound(r)||!pcdm_arch(r,&c->after)||c->after.cpu.ticks<c->before.cpu.ticks)return pcdm_fail(r,3);
    c->returned=1;
    if(!pgcd_actual_fp_restore(0,&c->fp)||c->fp.restored!=1||!pcdm_bound(r))return pcdm_fail(r,3);
    if(m){m->map.returned=1;if(!pcdm_map_valid(m))return pcdm_fail(r,4);source=m;}
    if((index==1&&r->allocation.status)||!pwea_core_check(e,&c->source[1],source)||!pcdm_arch(r,&r->current))return pcdm_fail(r,4);
    c->unknown=0;c->complete=1;r->calls++;r->pending=0;return 1;
}
static inline int pcdm_translate(struct pcdm_state*r,unsigned pass)
{
    if(pass>1||r->translated[pass])return 0;
    for(unsigned n=0;n<PWDM_BYTES/4096;n++){
        struct pwmc_translation*t=&r->AT;for(unsigned j=0;j<sizeof(*t);j++)((uint8_t*)t)[j]=0;t->page=r->allocation.address+4096*n;
        if(r->unknown||r->error||!pwea_native_binding((const void*)(uintptr_t)r->early)||!pwmc_actual_translate(t)||!pwmc_translation_valid(t)||t->page!=r->allocation.address+4096*n||!pcdm_arch(r,&r->current))return pcdm_fail(r,5);
        struct pwfi_sha256 h;pwfi_init(&h);for(unsigned j=0;j<32;j++)pwfi_byte(&h,r->AT_history[j]);
        for(unsigned j=0;j<sizeof(*t);j++)pwfi_byte(&h,((const uint8_t*)t)[j]);pwfi_final(&h,r->AT_history);r->translated[pass]++;
    }return 1;
}
static inline int pcdm_run(struct pcdm_state*r,const struct pwea_native*e)
{
    if(!r||!e||!pwmc_zero(r,sizeof(*r))||e->complete!=1||e->unknown||e->error||!pwea_native_binding(e)||
       !pwmc_parent_in_image(&e->image,(uintptr_t)r,sizeof(*r))||
       !pwea_disjoint((uintptr_t)r,sizeof(*r),(uintptr_t)e,sizeof(*e)))return 0;
    r->early=(uintptr_t)e;r->self=(uintptr_t)r;pcdm_hash(e,sizeof(*e),r->early_digest);r->attempted=1;
    if(!pgcd_actual_arch(0,&r->entry)||!pwea_native_arch_valid(&r->entry)||!pcdm_bound(r))return pcdm_fail(r,1);
    if(!pcdm_call(r,0)||!pcdm_call(r,1))return 0;
    uint64_t at=r->allocation.address;
    if(!at||(at&4095)||at>PWDM_LIMIT-PWDM_BYTES||!polaris_efi_range_owned(r->map[0].data,r->map[0].map.bytes,r->map[0].map.stride,at,PWDM_BYTES,7)||
       !pwea_disjoint(at,PWDM_BYTES,(uintptr_t)e->image.base,e->image.bytes)||!pwea_disjoint(at,PWDM_BYTES,e->memory.input.bank,e->memory.input.bank_bytes))return pcdm_fail(r,6);
    for(unsigned n=0;n<2;n++)if(!pwea_disjoint(at,PWDM_BYTES,e->memory.claim[n].requested,e->memory.claim[n].bytes))return pcdm_fail(r,6);
    if(!pcdm_call(r,2))return 0;
    const struct pwea_map*a=&r->map[0],*b=&r->map[1];
    if(a->map.key==b->map.key||a->map.stride!=b->map.stride||!polaris_efi_range_owned(b->data,b->map.bytes,b->map.stride,at,PWDM_BYTES,2)||
       !pwmc_delta_direction(a->data,a->map.bytes,b->data,b->map.bytes,(unsigned)a->map.stride,at,PWDM_BYTES,7,2)||
       !pwmc_delta_direction(b->data,b->map.bytes,a->data,a->map.bytes,(unsigned)a->map.stride,at,PWDM_BYTES,2,7))return pcdm_fail(r,7);
    r->allocated=1;
    if(!pwdm_plan(&r->layout,at)||!pcdm_translate(r,0)||!pcdm_translate(r,1)||
       !pwea_core_check(e,&r->final_source,b)||!pcdm_bound(r)||!pcdm_arch(r,&r->current))return pcdm_fail(r,8);
    r->complete=1;pcdm_hash(r,offsetof(struct pcdm_state,digest),r->digest);return 1;
}
#endif
#endif
