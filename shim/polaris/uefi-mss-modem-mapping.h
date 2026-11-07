/* Optional incoming-UEFI mapping of ONLY this boot's independent modem bank.
 * Original DxeCore services run before payload/native/secure assignment. No
 * allocation, free, target load/store, remote operation or page-table edit.
 * A failed call retains UNKNOWN; there is no restoration or retry path. */
#ifndef POLARIS_UEFI_MSS_MODEM_MAPPING_H
#define POLARIS_UEFI_MSS_MODEM_MAPPING_H
#ifndef EFI_XNU_MSS_MODEM_NORMAL_NC
#define EFI_XNU_MSS_MODEM_NORMAL_NC 0
#endif
#if (EFI_XNU_MSS_MODEM_NORMAL_NC != 0 && EFI_XNU_MSS_MODEM_NORMAL_NC != 1) || (EFI_XNU_MSS_MODEM_NORMAL_NC && (!EFI_XNU_WIFI_NATIVE_FAULT_HOLD || !EFI_XNU_WIFI_FIRMWARE_DIAGNOSTIC_ONLY || EFI_XNU_WIFI_AUTH_METADATA_CHECKPOINT != 10 || !EFI_XNU_MSS_MEMORY_AVAILABLE))
#error "Modem NormalNC requires the physical native-ready fault diagnostic"
#endif
#if EFI_XNU_MSS_MODEM_NORMAL_NC
#include "uefi-mss-memory.h"
#define PMNC_BYTES UINT64_C(0x7800000)
#define PMNC_CALLS 5u
struct pmnc_result {
    uint64_t self,early,memory,base,bytes,par;
    uint8_t early_digest[32],memory_digest[32],DS[168],lock[24];
    struct pwea_map map[2];struct pwea_native_call call[PMNC_CALLS];
    struct pgcd_descriptor descriptor[2];uint64_t status[3];
    struct pwmc_translation AT;uint8_t AT_history[2][32];
    uint32_t attempted,unknown,error,pending,calls,translated[2],complete,reserved;
    uint8_t digest[32];
};
static inline int pmnc_fail(struct pmnc_result*r,unsigned error)
{r->unknown=1;if(!r->error)r->error=error;return 0;}
/* Exact identity, NS, NormalNC and R/W/PAR preservation. Both architected
 * shareable domains are allowed; a physical run must use ONE across the bank.
 * Device, unshareable, WB, faults, aliases and noncanonical bits all refuse. */
static inline int pmnc_translation(const struct pwmc_translation*t,uint64_t page,uint64_t par)
{
    return t&&page&&!(page&4095)&&page<=UINT64_C(0xfffff000)&&t->page==page&&
        (par==UINT64_C(0x4400000000000b00)||par==UINT64_C(0x4400000000000b80))&&
        t->read_issued==1&&t->read_returned==1&&t->write_issued==1&&t->write_returned==1&&
        t->saved==t->restored&&t->read_par==(par|page)&&t->write_par==t->read_par;
}
/* Compare complete maps in both directions, allowing descriptor splits only.
 * Inside this exact allocation the sole change is WB8->WC2. No new range,
 * allocation/type/VA/extension-byte change is admitted anywhere. */
static inline int pmnc_map_direction(const struct pwea_map*a,const struct pwea_map*b,uint64_t base,unsigned reverse)
{
    unsigned stride=(unsigned)a->map.stride;
    for(uint64_t at=0;at<a->map.bytes;at+=stride){
        const struct efi_memory*d=(const void*)(a->data+at);uint64_t cursor=d->physical,end=cursor+d->pages*4096;
        while(cursor<end){
            unsigned found=0;uint64_t next=end;
            for(uint64_t bt=0;bt<b->map.bytes;bt+=stride){
                const struct efi_memory*e=(const void*)(b->data+bt);uint64_t stop=e->physical+e->pages*4096;
                if(e->physical>cursor||cursor>=stop)continue;found++;if(stop<next)next=stop;
                if(cursor<base&&base<next)next=base;if(cursor<base+PMNC_BYTES&&base+PMNC_BYTES<next)next=base+PMNC_BYTES;
                unsigned inside=cursor>=base&&cursor<base+PMNC_BYTES;
                if(d->type!=e->type||d->virtual_address||e->virtual_address||
                   (inside&&(d->type!=2||d->attributes!=(reverse?2u:8u)||e->attributes!=(reverse?8u:2u)))||
                   (!inside&&d->attributes!=e->attributes))return 0;
                for(unsigned k=4;k<stride;k++){
                    if(k>=8&&k<24)continue;if(k>=24&&k<40)continue;
                    if(a->data[at+k]!=b->data[bt+k])return 0;
                }
            }
            if(found!=1||next<=cursor)return 0;cursor=next;
        }
    }return 1;
}
static inline int pmnc_maps(const struct pwea_map*a,const struct pwea_map*b,uint64_t base)
{
    struct polaris_efi_memory checked;
    return base&&!(base&0xfffff)&&base>=0x80000000&&base<=UINT64_C(0x100000000)-PMNC_BYTES&&
        a->map.valid==1&&b->map.valid==1&&!a->map.status&&!b->map.status&&a->map.key&&b->map.key&&
        a->map.version==1&&b->map.version==1&&a->map.stride==b->map.stride&&
        polaris_efi_memory_check(a->data,a->map.bytes,PGCD_MAP_CAP,a->map.stride,&checked)&&
        polaris_efi_memory_check(b->data,b->map.bytes,PGCD_MAP_CAP,b->map.stride,&checked)&&
        polaris_efi_range_owned(a->data,a->map.bytes,a->map.stride,base,PMNC_BYTES,2)&&
        polaris_efi_range_owned(b->data,b->map.bytes,b->map.stride,base,PMNC_BYTES,2)&&
        pmnc_map_direction(a,b,base,0)&&pmnc_map_direction(b,a,base,1);
}
static inline int pmnc_sources(const struct pmnc_result*r)
{
    const struct pwea_native*e=(const void*)(uintptr_t)r->early;
    const struct pmmn_native*m=(const void*)(uintptr_t)r->memory;uint8_t hash[32];
    pweh_digest(e,sizeof(*e),hash);if(!pgcd_equal(hash,r->early_digest,32)||!pwea_native_binding(e))return 0;
    pweh_digest(m,sizeof(*m),hash);return pgcd_equal(hash,r->memory_digest,32)&&pmmn_binding(m);
}
static inline int pmnc_table(struct pmnc_result*r,unsigned first)
{
    const struct pwea_native*e=(const void*)(uintptr_t)r->early;
    const uint8_t*ds=(const void*)(uintptr_t)(e->core+0x1bb18),*lock=(const void*)(uintptr_t)(e->core+0x1bd48);
    if(first){pgcd_copy(r->DS,ds,168);pgcd_copy(r->lock,lock,24);}
    return pgcd_equal(r->DS,ds,168)&&pgcd_equal(r->lock,lock,24)&&
        pwfi_le(ds,8)==UINT64_C(0x565245535f455844)&&pwfi_le(ds+8,4)==0x10046&&pwfi_le(ds+12,4)==168&&
        !pwfi_le(ds+20,4)&&pgcd_crc(ds,168)&&pwfi_le(ds+0x38,8)==e->core+0x2c68&&
        pwfi_le(ds+0x40,8)==e->core+0x89f8&&pwfi_le(lock,8)==16&&pwfi_le(lock+8,8)<=16&&pwfi_le(lock+16,8)==1;
}
static inline void pmnc_seal(struct pmnc_result*r,const void*out,size_t bytes,uint8_t hash[32])
{
    struct pwfi_sha256 h;pwfi_init(&h);uintptr_t lo=(uintptr_t)out;
    for(size_t n=0;n<sizeof(*r);n++){
        uintptr_t p=(uintptr_t)r+n;if(p>=lo&&p-lo<bytes)continue;pwfi_byte(&h,((const uint8_t*)r)[n]);
    }pwfi_final(&h,hash);
}
#if defined(POLARIS_MSS_MODEM_MAPPING_SOFTWARE_PEER)
static efi_status pmnc_service(struct pmnc_result*,unsigned);
#else
static inline efi_status pmnc_service(struct pmnc_result*r,unsigned index)
{
    const struct pwea_native*e=(const void*)(uintptr_t)r->early;struct efi_system*s=(void*)(uintptr_t)e->system;
    if(index==0||index==4){struct pwea_map*m=&r->map[index/4];
        return s->boot->get_map(&m->map.bytes,m->data,&m->map.key,&m->map.stride,&m->map.version);}
    if(index==2){typedef efi_status(*setter)(uint64_t,uint64_t,uint64_t);
        return ((setter)(uintptr_t)(e->core+0x89f8))(r->base,PMNC_BYTES,2);}
    typedef efi_status(*getter)(uint64_t,struct pgcd_descriptor*);
    return ((getter)(uintptr_t)(e->core+0x2c68))(r->base,&r->descriptor[index/3]);
}
#endif
static inline int pmnc_call(struct pmnc_result*r,unsigned index)
{
    if(index>=PMNC_CALLS||index!=r->calls||r->pending||r->unknown||r->error||!pmnc_sources(r))return 0;
    const struct pwea_native*e=(const void*)(uintptr_t)r->early;const struct pmmn_native*m=(const void*)(uintptr_t)r->memory;
    struct pwea_native_call*c=&r->call[index];const struct pwea_map*source=index?&r->map[0]:&m->memory.map[3];
    if(!pwea_core_check(e,&c->source[0],source)||!pmnc_table(r,index==0)||!pgcd_actual_arch(0,&c->before)||
       !pwea_native_arch_valid(&c->before)||(index&&(!pwfc_arch_stable(&r->call[0].before.cpu,&c->before.cpu)||
       c->before.cpacr!=r->call[0].before.cpacr||c->before.cpu.ticks<r->call[index-1].after.cpu.ticks))||
       !pgcd_actual_fp_save(0,&c->fp)||c->fp.saved!=1||c->fp.restored||c->fp.cpacr_before!=c->before.cpacr)return pmnc_fail(r,2);
    void*out;size_t bytes;struct pwea_map*map=0;
    if(index==0||index==4){map=&r->map[index/4];map->map.bytes=PGCD_MAP_CAP;map->map.issued=1;out=map;bytes=sizeof(*map);}
    else{out=r->descriptor;bytes=0;if(index!=2){out=&r->descriptor[index/3];bytes=sizeof(struct pgcd_descriptor);}}
    c->issued=c->unknown=1;r->pending=index+1;uint8_t before[32],after[32];pmnc_seal(r,out,bytes,before);
    pwfc_actual_order(0);efi_status status=pmnc_service(r,index);pmnc_seal(r,out,bytes,after);
    if(!pgcd_equal(before,after,32)||!pmnc_sources(r)||!pmnc_table(r,0)||!pgcd_actual_arch(0,&c->after)||
       !pwea_native_arch_valid(&c->after)||!pwfc_arch_stable(&c->before.cpu,&c->after.cpu)||c->before.cpacr!=c->after.cpacr||
       c->after.cpu.ticks<c->before.cpu.ticks||c->after.cpu.ticks-c->before.cpu.ticks>PGCD_FRESH_TICKS)return pmnc_fail(r,3);
    c->returned=1;
    if(!pgcd_actual_fp_restore(0,&c->fp)||c->fp.restored!=1)return pmnc_fail(r,3);
    if(map){map->map.status=status;map->map.returned=1;struct polaris_efi_memory checked;
        if(status||!map->map.key||map->map.version!=1||!polaris_efi_memory_check(map->data,map->map.bytes,PGCD_MAP_CAP,map->map.stride,&checked)||
           !polaris_efi_range_owned(map->data,map->map.bytes,map->map.stride,r->base,PMNC_BYTES,2))return pmnc_fail(r,4);
        map->map.valid=1;source=map;
    }else{r->status[index-1]=status;if(status)return pmnc_fail(r,4);}
    if(!pwea_core_check(e,&c->source[1],source)||!pmnc_sources(r))return pmnc_fail(r,4);
    c->unknown=0;c->complete=1;r->pending=0;r->calls++;return 1;
}
static inline int pmnc_descriptor(const struct pmnc_result*r,unsigned after)
{
    const struct pgcd_descriptor*d=&r->descriptor[after];
    return !d->pad&&d->type==2&&d->length&&d->base<=r->base&&d->base<=UINT64_MAX-d->length&&
        r->base-d->base<=d->length&&PMNC_BYTES<=d->length-(r->base-d->base)&&
        (d->capabilities&10)==10&&d->attributes==(after?2u:8u)&&
        (!after||(d->capabilities==r->descriptor[0].capabilities&&d->image_handle==r->descriptor[0].image_handle&&
                  d->device_handle==r->descriptor[0].device_handle));
}
/* Every page is checked before AND after the original mapping service. The
 * complete CPU-only traversal has a separate absolute1s bound, never renewed.
 * These are AT/cacheability observations, not target content accesses. */
static inline int pmnc_at_bank(struct pmnc_result*r,unsigned after)
{
    struct pgcd_arch before,now;
    if(after>1||r->translated[after]||!pmnc_sources(r)||!pgcd_actual_arch(0,&before)||!pwea_native_arch_valid(&before))return pmnc_fail(r,7);
    for(unsigned page=0;page<PMNC_BYTES/4096;page++){
        struct pwmc_translation*t=&r->AT;for(unsigned j=0;j<sizeof(*t);j++)((uint8_t*)t)[j]=0;
        t->page=r->base+4096*page;if(!pwmc_actual_translate(t)||t->page!=r->base+4096*page)return pmnc_fail(r,7);
        if(after){uint64_t par=t->read_par&~UINT64_C(0xfffff000);if(!page)r->par=par;
            if(par!=r->par||!pmnc_translation(t,r->base+4096*page,r->par))return pmnc_fail(r,7);
        }else if(!pwmc_translation_valid(t))return pmnc_fail(r,7);
        struct pwfi_sha256 h;pwfi_init(&h);for(unsigned j=0;j<32;j++)pwfi_byte(&h,r->AT_history[after][j]);
        for(unsigned j=0;j<sizeof(*t);j++)pwfi_byte(&h,((const uint8_t*)t)[j]);pwfi_final(&h,r->AT_history[after]);r->translated[after]++;
    }
    if(!pmnc_sources(r)||!pmnc_table(r,0)||!pgcd_actual_arch(0,&now)||!pwea_native_arch_valid(&now)||
       !pwfc_arch_stable(&r->call[0].before.cpu,&now.cpu)||!pwfc_arch_stable(&before.cpu,&now.cpu)||
       now.cpacr!=before.cpacr||now.cpacr!=r->call[0].before.cpacr||now.cpu.ticks<before.cpu.ticks||
       now.cpu.ticks-before.cpu.ticks>UINT64_C(19200000))return pmnc_fail(r,7);
    return 1;
}
static inline int pmnc_run(struct pmnc_result*r,const struct pwea_native*e,const struct pmmn_native*m,const uint8_t digest[32])
{
    if(!r||!e||!m||!digest||!pwmc_zero(r,sizeof(*r)))return 0;r->attempted=1;
    if(e->complete!=1||e->unknown||e->error||m->complete!=1||m->unknown||m->error||m->memory.complete!=1||
       m->memory.unknown||m->memory.error||m->early!=(uintptr_t)e||!pwmc_parent_in_image(&e->image,(uintptr_t)r,sizeof(*r))||
       !pwmc_parent_in_image(&e->image,(uintptr_t)m,sizeof(*m))||!pwmc_parent_in_image(&e->image,(uintptr_t)digest,32)||
       !pwea_disjoint((uintptr_t)r,sizeof(*r),(uintptr_t)e,sizeof(*e))||!pwea_disjoint((uintptr_t)r,sizeof(*r),(uintptr_t)m,sizeof(*m))||
       !pwea_disjoint((uintptr_t)r,sizeof(*r),(uintptr_t)digest,32))return pmnc_fail(r,1);
    r->self=(uintptr_t)r;r->early=(uintptr_t)e;r->memory=(uintptr_t)m;r->bytes=PMNC_BYTES;
    pgcd_copy(r->early_digest,m->early_digest,32);pgcd_copy(r->memory_digest,digest,32);
    const struct pwea_claim*q=&m->memory.claim[0];r->base=q->requested;
    if(q->retained!=1||q->status||q->returned!=1||q->returned_address!=q->requested||q->bytes!=PMNC_BYTES||
       q->pages!=PMNC_BYTES/4096||!pmme_allowed(&m->memory,0,q->requested)||!pmnc_sources(r))return pmnc_fail(r,1);
    if(!pmnc_call(r,0)||!pmnc_call(r,1))return 0;
    if(!pmnc_descriptor(r,0))return pmnc_fail(r,5);
    if(!pmnc_at_bank(r,0))return 0;
    if(!pmnc_call(r,2)||!pmnc_call(r,3))return 0;
    if(!pmnc_descriptor(r,1))return pmnc_fail(r,5);
    if(!pmnc_call(r,4)||!pmnc_maps(&r->map[0],&r->map[1],r->base))return pmnc_fail(r,6);
    if(!pmnc_at_bank(r,1))return 0;
    r->complete=1;pweh_digest(r,offsetof(struct pmnc_result,digest),r->digest);return 1;
}
#endif
#endif
