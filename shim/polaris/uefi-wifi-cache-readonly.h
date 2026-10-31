/* Next-candidate CPU0 diagnostic: original SmemDxe OWNED IMAGE RAM only.
 * prepare_boot before DAIF/Group1 masking; never called from runtime polling.
 * No original entry/Get/Alloc, cached pointer dereference, IMEM/SMEM access,
 * SMC, XPU/MPU/IRQ write or radio operation. A cache witness cannot grant any
 * nativeCPU7 mapping, FIFO write or transmit permission. */
#ifndef POLARIS_UEFI_WIFI_CACHE_READONLY_H
#define POLARIS_UEFI_WIFI_CACHE_READONLY_H
#include "uefi-memory.h"
#include "../../tools/polaris-wifi-firmware-identity.h"
#define PWFC_CACHE_RVA 0x7118u
#define PWFC_CACHE_BYTES 632u
#define PWFC_HANDLES 256u
enum pwfc_error {PWFC_OK,PWFC_STAGE,PWFC_ARCH,PWFC_PROTOCOL,PWFC_ENUMERATE,
    PWFC_MAP,PWFC_ARRAY,PWFC_HANDLE,PWFC_PROVENANCE,PWFC_IMAGE,PWFC_IDENTITY,
    PWFC_HASH,PWFC_CHANGED_MAP,PWFC_CHANGED_CACHE,PWFC_CACHE,PWFC_LIFETIME,PWFC_RELEASE};
struct pwfc_arch {
    uint64_t el,mpidr,ttbr0,ttbr1,tcr,sctlr,mair,daif,sre,group1,frequency,ticks;
};
struct pwfc_result {
    uint64_t cookie,protocol,image,protocol_status,enumerate_status,map_status,release_status;
    uint64_t handle_count,map_key[2],map_bytes,map_stride,identity_address,identity_par;
    uint64_t handle_status[PWFC_HANDLES],loaded_address[PWFC_HANDLES];
    struct pwfc_arch before,after;
    struct efi_loaded owner;
    struct efi_memory smem_descriptor;
    uint64_t handles,owner_address,protocol_after_status,protocol_after;
    uint32_t error,attempted,owner_matches,hash_failed,hash_count,snapshot_bytes[2],cache_consistent,release_attempted,smem_descriptor_matches,mpss_cached;
    uint8_t hashes[PWFI_RANGE_COUNT][32],snapshot[2][PWFC_CACHE_BYTES];
};
struct pwfc_io {
    struct efi_system *system;
    void *context;
    int (*arch)(void *,struct pwfc_arch *);
    int (*identity)(void *,uint64_t,uint64_t,uint64_t *,uint64_t *);
    void (*order)(void *);
};
struct pwfc_workspace {
    uint8_t map[65536] __attribute__((aligned(8)));
    struct efi_loaded *loaded[PWFC_HANDLES];
};
static inline int pwfc_equal(const uint8_t *a,const uint8_t *b,size_t n)
{unsigned difference=0;for(size_t i=0;i<n;i++)difference|=a[i]^b[i];return !difference;}
static inline int pwfc_owned(const struct pwfc_io *io,struct pwfc_result *r,
    struct pwfc_workspace *w,uint64_t address,uint64_t bytes)
{
    if(!address||!bytes||address>UINT64_MAX-bytes||address+bytes>UINT64_MAX-4095)return 0;
    for(uint64_t p=address&~UINT64_C(4095);p<address+bytes;p+=4096){
        if(!polaris_efi_range_owned(w->map,r->map_bytes,r->map_stride,p,4096,3)&&
           !polaris_efi_range_owned(w->map,r->map_bytes,r->map_stride,p,4096,4))return 0;
    }
    return io->identity(io->context,address,bytes,&r->identity_address,&r->identity_par);
}
static inline int pwfc_map(struct efi_boot *bs,struct pwfc_result *r,struct pwfc_workspace *w,unsigned slot)
{
    uint64_t bytes=sizeof(w->map),key=0,stride=0;uint32_t version=0;
    r->map_status=bs->get_map(&bytes,w->map,&key,&stride,&version);
    struct polaris_efi_memory checked;
    if(r->map_status||!polaris_efi_memory_check(w->map,bytes,sizeof(w->map),stride,&checked))return 0;
    r->map_key[slot]=key;r->map_bytes=bytes;r->map_stride=stride;return 1;
}
static inline int pwfc_arch_admitted(const struct pwfc_arch *a)
{return a->el==4&&(a->mpidr&UINT64_C(0xffffff))==0&&a->frequency==19200000&&a->ticks&&(a->sre&1)&&
    !(a->daif&UINT64_C(0x80))&&(a->group1&1)&&(a->sctlr&1);}
static inline int pwfc_arch_stable(const struct pwfc_arch *a,const struct pwfc_arch *b)
{
    return pwfc_arch_admitted(b)&&a->el==b->el&&a->mpidr==b->mpidr&&a->ttbr0==b->ttbr0&&
        a->ttbr1==b->ttbr1&&a->tcr==b->tcr&&a->sctlr==b->sctlr&&a->mair==b->mair&&
        a->daif==b->daif&&a->sre==b->sre&&a->group1==b->group1&&a->frequency==b->frequency&&
        b->ticks>=a->ticks&&b->ticks-a->ticks<=UINT64_C(38400000);
}
static inline int pwfc_cache_valid(const uint8_t *p,uint64_t image)
{
    const uint64_t base=UINT64_C(0x86000000),bytes=UINT64_C(0x200000);
    uint64_t version=pwfi_le(p+20,4),items=pwfi_le(p+24,2),backend=pwfi_le(p+32,8);
    if(pwfi_le(p,8)!=base||pwfi_le(p+8,8)!=base||pwfi_le(p+16,4)!=bytes||
       (version>>16!=11&&version>>16!=12)||items<481||items>4096||pwfi_le(p+40,4)!=3||
       backend!=image+(version>>16==11?0x5b78u:0x5cb0u)||
       pwfi_le(p+528,4)!=UINT64_C(0x49494953)||pwfi_le(p+532,4)!=bytes||pwfi_le(p+536,8)!=base)return 0;
    uint64_t target_items=pwfi_le(p+544,2);
    if(items!=(target_items?target_items:498))return 0;
    /* Validate cached numeric metadata only; NEVER follow these addresses. */
    for(unsigned n=0;n<10;n++){
        const uint8_t *q=p+48+48*n;uint64_t address=pwfi_le(q,8),size=pwfi_le(q+8,4);
        if(!address){if(size)return 0;continue;}
        uint64_t line=pwfi_le(q+12,4),uncached=pwfi_le(q+16,4),cached=pwfi_le(q+20,4);
        if(address<base||address-base>=bytes-4096||(address&4095)||!size||(size&4095)||
           size>bytes-4096-(address-base)||line<16||line>4096||(line&(line-1))||
           uncached>cached||cached>size)return 0;
    }
    for(unsigned n=0;n<8;n++)if(pwfi_le(p+552+8*n,8)!=UINT64_C(0x1f40000)+4096*n)return 0;
    return pwfi_le(p+616,8)==UINT64_C(0x1fd4000)&&pwfi_le(p+624,8)==UINT64_C(0x1fd4004);
}
/* Common collector is exercised with synthetic services in host fixtures.
 * Production entry below always supplies actual UEFI services/EL1 readers. */
static inline int pwfc_collect(const struct pwfc_io *io,uint32_t stage,
    struct pwfc_result *r,struct pwfc_workspace *w)
{
    static const efi_guid protocol={0xf4e5c7d0,0xd239,0x47cb,{0xaa,0xcd,0x7f,0x66,0xef,0x76,0x32,0x38}};
    static const efi_guid loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
    if(!r||!w||r->attempted)return 0;r->attempted=1;
    if(stage!=2){r->error=PWFC_STAGE;return 0;}
    if(!io||!io->system||!io->system->boot||!io->arch||!io->identity||!io->order||
       !io->arch(io->context,&r->before)||!pwfc_arch_admitted(&r->before)){
        r->error=PWFC_ARCH;return 0;
    }
    r->cookie=r->before.ticks|1;
    struct efi_boot *bs=io->system->boot;efi_handle *handles=0;void *table=0;unsigned handles_owned=0;
    if(!bs->locate_protocol||!bs->locate_buffer||!bs->handle_protocol||!bs->get_map||!bs->free_pool){
        r->error=PWFC_PROTOCOL;return 0;
    }
    r->protocol_status=bs->locate_protocol(&protocol,0,&table);r->protocol=(uintptr_t)table;
    if(r->protocol_status||!table){r->error=PWFC_PROTOCOL;return 0;}
    r->enumerate_status=bs->locate_buffer(2,&loaded_guid,0,&r->handle_count,&handles);
    r->handles=(uintptr_t)handles;
    if(r->enumerate_status||!handles){r->error=PWFC_ENUMERATE;return 0;}
    if(!r->handle_count||r->handle_count>PWFC_HANDLES){r->error=PWFC_ENUMERATE;goto release;}
    if(!pwfc_map(bs,r,w,0)){r->error=PWFC_MAP;goto release;}
    if(!pwfc_owned(io,r,w,(uintptr_t)handles,r->handle_count*sizeof(*handles))){r->error=PWFC_ARRAY;goto release;}
    handles_owned=1;
    for(unsigned n=0;n<r->handle_count;n++){
        r->handle_status[n]=bs->handle_protocol(handles[n],&loaded_guid,(void**)&w->loaded[n]);
        r->loaded_address[n]=(uintptr_t)w->loaded[n];
        if(r->handle_status[n]||!w->loaded[n]){r->error=PWFC_HANDLE;goto release;}
    }
    if(!pwfc_map(bs,r,w,0)){r->error=PWFC_MAP;goto release;}
    if(!pwfc_owned(io,r,w,r->protocol,40)){r->error=PWFC_PROVENANCE;goto release;}
    for(unsigned n=0;n<r->handle_count;n++){
        if(!pwfc_owned(io,r,w,r->loaded_address[n],sizeof(struct efi_loaded))){r->error=PWFC_PROVENANCE;goto release;}
        const struct efi_loaded *image=w->loaded[n];uint64_t base=(uintptr_t)image->base;
        if(base>UINT64_MAX-0x7090||base+0x7090!=r->protocol)continue;
        r->owner_matches++;r->image=base;
        r->owner_address=r->loaded_address[n];r->owner=*image;
        if(image->revision!=0x1000||image->system!=io->system||image->bytes!=PWFI_IMAGE_BYTES||
           image->code_type!=3||image->data_type!=4||(base&4095)){
            r->error=PWFC_IMAGE;goto release;
        }
    }
    if(r->owner_matches!=1){r->error=PWFC_PROVENANCE;goto release;}
    if(!pwfc_owned(io,r,w,r->image,PWFI_IMAGE_BYTES)){r->error=PWFC_IDENTITY;goto release;}
    const uint8_t *image=(const void*)(uintptr_t)r->image;
    if(!pwfi_verify(image,r->image,PWFI_IMAGE_BYTES,r->hashes,&r->hash_failed,&r->hash_count)){
        r->error=PWFC_HASH;goto release;
    }
    if(pwfi_le(image+0x7090,8)!=0x10001||pwfi_le(image+0x7098,8)!=r->image+0x1ca0||
       pwfi_le(image+0x70a0,8)!=r->image+0x1ccc||pwfi_le(image+0x70a8,8)||pwfi_le(image+0x70b0,8)){
        r->error=PWFC_PROVENANCE;goto release;
    }
    io->order(io->context);
    for(unsigned s=0;s<2;s++){
        /* Ordinary reads of owned original-image RAM; no cache invalidate or
         * clean that could affect a remote/shared allocation. */
        for(unsigned n=0;n<PWFC_CACHE_BYTES;n++)r->snapshot[s][n]=((const volatile uint8_t*)image)[PWFC_CACHE_RVA+n];
        r->snapshot_bytes[s]=PWFC_CACHE_BYTES;
        io->order(io->context);
    }
    table=0;r->protocol_after_status=bs->locate_protocol(&protocol,0,&table);r->protocol_after=(uintptr_t)table;
    if(r->protocol_after_status||r->protocol_after!=r->protocol){r->error=PWFC_PROVENANCE;goto release;}
    if(!pwfc_map(bs,r,w,1)){r->error=PWFC_MAP;goto release;}
    if(r->map_key[0]!=r->map_key[1]||!pwfc_owned(io,r,w,r->image,PWFI_IMAGE_BYTES)){
        r->error=PWFC_CHANGED_MAP;goto release;
    }
    /* This copies an existing map DESCRIPTOR, not its physical memory. UC
     * classification is logged as such and never becomes read permission. */
    for(uint64_t at=0;at<r->map_bytes;at+=r->map_stride){
        const struct efi_memory *m=(const void*)(w->map+at);
        if(m->physical==UINT64_C(0x86000000)&&m->pages==512){
            r->smem_descriptor=*m;r->smem_descriptor_matches++;
        }
    }
    if(!pwfc_owned(io,r,w,r->owner_address,sizeof(r->owner))||
       !pwfc_equal((const uint8_t*)&r->owner,(const uint8_t*)(uintptr_t)r->owner_address,sizeof(r->owner))){
        r->error=PWFC_PROVENANCE;goto release;
    }
    if(!pwfc_equal(r->snapshot[0],r->snapshot[1],PWFC_CACHE_BYTES)){
        r->error=PWFC_CHANGED_CACHE;goto release;
    }
    r->cache_consistent=pwfc_cache_valid(r->snapshot[0],r->image);
    r->mpss_cached=pwfi_le(r->snapshot[0]+96,8)!=0;
    if(!r->cache_consistent){r->error=PWFC_CACHE;goto release;}
release:
    /* Never free an unvalidated/unknown returned pointer. Failure retains its
     * raw value and consumes this one attempt; no arbitrary FreePool retry. */
    if(handles_owned){r->release_attempted=1;r->release_status=bs->free_pool(handles);}
    if(r->release_status&&!r->error)r->error=PWFC_RELEASE;
    if(!io->arch(io->context,&r->after)||!pwfc_arch_stable(&r->before,&r->after)){
        if(!r->error)r->error=PWFC_LIFETIME;
    }
    return r->error==PWFC_OK;
}
static inline int pwfc_actual_arch(void *context,struct pwfc_arch *a)
{
    (void)context;
#if defined(__aarch64__) || defined(__arm64__)
    __asm__ volatile("mrs %0,currentel":"=r"(a->el));
    if(a->el!=4)return 0;
    __asm__ volatile("mrs %0,mpidr_el1":"=r"(a->mpidr));
    __asm__ volatile("mrs %0,ttbr0_el1":"=r"(a->ttbr0));
    __asm__ volatile("mrs %0,ttbr1_el1":"=r"(a->ttbr1));
    __asm__ volatile("mrs %0,tcr_el1":"=r"(a->tcr));
    __asm__ volatile("mrs %0,sctlr_el1":"=r"(a->sctlr));
    __asm__ volatile("mrs %0,mair_el1":"=r"(a->mair));
    __asm__ volatile("mrs %0,daif":"=r"(a->daif));
    __asm__ volatile("mrs %0,ICC_SRE_EL1":"=r"(a->sre));
    if(!(a->sre&1))return 0; /* Do not access GIC system registers with SRE off. */
    __asm__ volatile("mrs %0,ICC_IGRPEN1_EL1":"=r"(a->group1));
    __asm__ volatile("mrs %0,cntfrq_el0":"=r"(a->frequency));
    __asm__ volatile("isb\n\tmrs %0,cntvct_el0":"=r"(a->ticks)::"memory");return 1;
#else
    (void)a;return 0;
#endif
}
static inline int pwfc_actual_identity(void *context,uint64_t address,uint64_t bytes,uint64_t *where,uint64_t *raw)
{
    (void)context;
#if defined(__aarch64__) || defined(__arm64__)
    if(!bytes||address>UINT64_MAX-bytes||address+bytes>UINT64_MAX-4095)return 0;
    for(uint64_t p=address&~UINT64_C(4095);p<address+bytes;p+=4096){
        uint64_t saved,par;
        __asm__ volatile("mrs %0,par_el1\n\tat s1e1r,%2\n\tisb\n\tmrs %1,par_el1\n\tmsr par_el1,%0"
            :"=&r"(saved),"=&r"(par):"r"(p):"memory");
        *where=p;*raw=par;
        if((par&1)||(par&UINT64_C(0x0000fffffffff000))!=p)return 0;
    }
    return 1;
#else
    (void)address;(void)bytes;(void)where;(void)raw;return 0;
#endif
}
static inline void pwfc_actual_order(void *context)
{
    (void)context;
#if defined(__aarch64__) || defined(__arm64__)
    __asm__ volatile("dsb sy":::"memory");
#endif
}
/* Production integration uses existing resident text/report functions. */
static struct pwfc_result pwfc_record;
static struct pwfc_workspace pwfc_work;
static inline void pwfc_hex(const uint8_t *raw,size_t bytes)
{
    char line[97];
    for(size_t at=0;at<bytes;){
        unsigned n=(unsigned)(bytes-at);if(n>48)n=48;
        for(unsigned j=0;j<n;j++){line[2*j]="0123456789abcdef"[raw[at+j]>>4];line[2*j+1]="0123456789abcdef"[raw[at+j]&15];}
        line[2*n]=0;text(line);text("\r\n");at+=n;
    }
}
static inline void pwfc_prepare(struct efi_system *system,uint32_t stage)
{
    if(pwfc_record.attempted)return;
    const struct pwfc_io io={system,0,pwfc_actual_arch,pwfc_actual_identity,pwfc_actual_order};
    (void)pwfc_collect(&io,stage,&pwfc_record,&pwfc_work);
    report("WIFI_CACHE_ONLY_ERROR=",pwfc_record.error);report("WIFI_CACHE_COOKIE=",pwfc_record.cookie);
    report("WIFI_CACHE_PROTOCOL_STATUS=",pwfc_record.protocol_status);
    report("WIFI_CACHE_ENUM_STATUS=",pwfc_record.enumerate_status);report("WIFI_CACHE_MAP_STATUS=",pwfc_record.map_status);
    report("WIFI_CACHE_RELEASE_STATUS=",pwfc_record.release_status);report("WIFI_CACHE_OWNER_MATCHES=",pwfc_record.owner_matches);
    report("WIFI_CACHE_RELEASE_ATTEMPTED=",pwfc_record.release_attempted);
    report("WIFI_CACHE_PROTOCOL_AFTER_STATUS=",pwfc_record.protocol_after_status);
    report("WIFI_CACHE_PROTOCOL_AFTER=",pwfc_record.protocol_after);
    report("WIFI_CACHE_ORIGINAL_IMAGE=",pwfc_record.image);report("WIFI_CACHE_HANDLES=",pwfc_record.handle_count);
    report("WIFI_CACHE_HASH_FAILED_RANGE=",pwfc_record.hash_failed);report("WIFI_CACHE_MAP_KEY_BEFORE=",pwfc_record.map_key[0]);
    report("WIFI_CACHE_HASH_COMPUTED_COUNT=",pwfc_record.hash_count);
    report("WIFI_CACHE_MPSS_PARTITION_CACHED=",pwfc_record.mpss_cached);
    report("WIFI_CACHE_MAP_KEY_AFTER=",pwfc_record.map_key[1]);
    report("WIFI_CACHE_IDENTITY_ADDRESS=",pwfc_record.identity_address);report("WIFI_CACHE_IDENTITY_PAR=",pwfc_record.identity_par);
    report("WIFI_CACHE_SMEM_DESCRIPTOR_MATCHES=",pwfc_record.smem_descriptor_matches);
    report("WIFI_CACHE_SMEM_DESCRIPTOR_TYPE=",pwfc_record.smem_descriptor.type);
    report("WIFI_CACHE_SMEM_DESCRIPTOR_ATTRIBUTES=",pwfc_record.smem_descriptor.attributes);
    report("WIFI_CACHE_SMEM_DESCRIPTOR_VIRTUAL=",pwfc_record.smem_descriptor.virtual_address);
    for(unsigned n=0;n<pwfc_record.handle_count&&n<PWFC_HANDLES;n++)if(pwfc_record.handle_status[n]){
        report("WIFI_CACHE_BAD_HANDLE_INDEX=",n);report("WIFI_CACHE_BAD_HANDLE_STATUS=",pwfc_record.handle_status[n]);
        report("WIFI_CACHE_BAD_HANDLE_LOADED_ADDRESS=",pwfc_record.loaded_address[n]);break;
    }
    if(pwfc_record.hash_count){
        text("WIFI_CACHE_IMMUTABLE_ACTUAL_HASHES_BEGIN\r\n");
        pwfc_hex(&pwfc_record.hashes[0][0],32u*pwfc_record.hash_count);text("WIFI_CACHE_IMMUTABLE_ACTUAL_HASHES_END\r\n");
    }
    const struct pwfc_arch *states[2]={&pwfc_record.before,&pwfc_record.after};
    for(unsigned n=0;n<2;n++){
        text(n?"WIFI_CACHE_ARCH_AFTER\r\n":"WIFI_CACHE_ARCH_BEFORE\r\n");const struct pwfc_arch *a=states[n];
        report("EL=",a->el);report("MPIDR=",a->mpidr);report("TTBR0=",a->ttbr0);report("TTBR1=",a->ttbr1);
        report("TCR=",a->tcr);report("SCTLR=",a->sctlr);report("MAIR=",a->mair);report("DAIF=",a->daif);
        report("SRE=",a->sre);report("GROUP1=",a->group1);report("CNTFRQ=",a->frequency);report("CNTVCT=",a->ticks);
    }
    for(unsigned n=0;n<2;n++)if(pwfc_record.snapshot_bytes[n]){
        text(n?"WIFI_CACHE_RAW2_BEGIN bytes=632\r\n":"WIFI_CACHE_RAW1_BEGIN bytes=632\r\n");
        pwfc_hex(pwfc_record.snapshot[n],PWFC_CACHE_BYTES);text("WIFI_CACHE_RAW_END\r\n");
    }
    text("WIFI_CACHE_SOURCE_SHA256=" PWFI_SOURCE_SHA256 "\r\n");
    text("WIFI_CACHE_ONLY: original-image RAM witness; new_SMEM_reads=0 native_permission=0 FIFO=0 radio=0 may_transmit=0\r\n");
}
#endif
