/* Next-candidate CPU0 audio diagnostic: original I2CDxe OWNED IMAGE RAM only.
 * prepare_boot before DAIF/Group1 masking; never called from runtime polling.
 * No original entry/Open/Close/Read/Write/Transfer/DAL, pointer follow or MMIO,
 * SMC, XPU/MPU/IRQ write, DSP startup or power/clock write. A cache witness cannot grant any
 * SE5/bus/clock ownership, TAS identity, PCM or native mapping permission. */
#ifndef POLARIS_UEFI_AUDIO_I2C_CACHE_READONLY_H
#define POLARIS_UEFI_AUDIO_I2C_CACHE_READONLY_H
#include "uefi-memory.h"
#include "../../tools/polaris-audio-i2c-firmware-identity.h"
#define PAIC_CACHE_RVA 0x6d60u
#define PAIC_CACHE_BYTES 120u
#define PAIC_HANDLES 256u
#ifndef EFI_XNU_AUDIO_I2C_CACHE_AVAILABLE
#define EFI_XNU_AUDIO_I2C_CACHE_AVAILABLE 0
#endif
enum paic_error {PAIC_OK,PAIC_DISABLED,PAIC_STAGE,PAIC_ARCH,PAIC_PROTOCOL,PAIC_ENUMERATE,
    PAIC_MAP,PAIC_ARRAY,PAIC_HANDLE,PAIC_PROVENANCE,PAIC_IMAGE,PAIC_IDENTITY,
    PAIC_HASH,PAIC_CHANGED_MAP,PAIC_CHANGED_CACHE,PAIC_CACHE,PAIC_LIFETIME,PAIC_RELEASE};
struct paic_arch {
    uint64_t el,mpidr,ttbr0,ttbr1,tcr,sctlr,mair,daif,sre,group1,frequency,ticks;
};
struct paic_map_sample {uint64_t status,key,bytes,stride;uint32_t version;};
struct paic_result {
    uint64_t cookie,protocol,image,protocol_status,enumerate_status,map_status,release_status;
    uint64_t handle_count,map_key[2],map_bytes,map_stride,identity_address,identity_par;
    uint32_t map_version[2];
    struct paic_map_sample map_sample[3];
    uint32_t map_samples;
    uint64_t handle_status[PAIC_HANDLES],loaded_address[PAIC_HANDLES];
    struct paic_arch before,after;
    struct efi_loaded owner;
    uint64_t handles,owner_address,protocol_after_status,protocol_after;
    uint32_t error,attempted,owner_matches,hash_failed,hash_count,snapshot_bytes[2],cache_consistent,release_attempted,map_keys_before_release_only;
    uint64_t raw_context_head,raw_clock_handle,raw_TLMM_handle;
    uint8_t hashes[PAII_RANGE_COUNT][32],snapshot[2][PAIC_CACHE_BYTES];
};
struct paic_io {
    struct efi_system *system;
    void *context;
    int (*arch)(void *,struct paic_arch *);
    int (*identity)(void *,uint64_t,uint64_t,uint64_t *,uint64_t *);
    void (*order)(void *);
};
struct paic_workspace {
    uint8_t map[65536] __attribute__((aligned(8)));
    struct efi_loaded *loaded[PAIC_HANDLES];
};
static inline int paic_equal(const uint8_t *a,const uint8_t *b,size_t n)
{unsigned difference=0;for(size_t i=0;i<n;i++)difference|=a[i]^b[i];return !difference;}
static inline int paic_owned(const struct paic_io *io,struct paic_result *r,
    struct paic_workspace *w,uint64_t address,uint64_t bytes)
{
    if(!address||!bytes||address>UINT64_MAX-bytes||address+bytes>UINT64_MAX-4095)return 0;
    for(uint64_t p=address&~UINT64_C(4095);p<address+bytes;p+=4096){
        if(!polaris_efi_range_owned(w->map,r->map_bytes,r->map_stride,p,4096,3)&&
           !polaris_efi_range_owned(w->map,r->map_bytes,r->map_stride,p,4096,4))return 0;
    }
    return io->identity(io->context,address,bytes,&r->identity_address,&r->identity_par);
}
static inline int paic_map(struct efi_boot *bs,struct paic_result *r,struct paic_workspace *w,unsigned slot)
{
    uint64_t bytes=sizeof(w->map),key=0,stride=0;uint32_t version=0;
    if(r->map_samples>=3)return 0;
    r->map_status=bs->get_map(&bytes,w->map,&key,&stride,&version);
    r->map_sample[r->map_samples++]=(struct paic_map_sample){r->map_status,key,bytes,stride,version};
    r->map_version[slot]=version;
    struct polaris_efi_memory checked;
    if(r->map_status||version!=1||!polaris_efi_memory_check(w->map,bytes,sizeof(w->map),stride,&checked))return 0;
    r->map_key[slot]=key;r->map_bytes=bytes;r->map_stride=stride;return 1;
}
static inline int paic_arch_admitted(const struct paic_arch *a)
{return a->el==4&&(a->mpidr&UINT64_C(0xffffff))==0&&a->frequency==19200000&&a->ticks&&(a->sre&1)&&
    !(a->daif&UINT64_C(0x80))&&(a->group1&1)&&(a->sctlr&1);}
static inline int paic_arch_stable(const struct paic_arch *a,const struct paic_arch *b)
{
    return paic_arch_admitted(b)&&a->el==b->el&&a->mpidr==b->mpidr&&a->ttbr0==b->ttbr0&&
        a->ttbr1==b->ttbr1&&a->tcr==b->tcr&&a->sctlr==b->sctlr&&a->mair==b->mair&&
        a->daif==b->daif&&a->sre==b->sre&&a->group1==b->group1&&a->frequency==b->frequency&&
        b->ticks>=a->ticks&&b->ticks-a->ticks<=UINT64_C(38400000);
}
/* Common collector is exercised with synthetic services in host fixtures.
 * Production entry below always supplies actual UEFI services/EL1 readers. */
static inline int paic_collect(const struct paic_io *io,uint32_t stage,
    struct paic_result *r,struct paic_workspace *w)
{
#if EFI_XNU_AUDIO_I2C_CACHE_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
    static const efi_guid protocol={0xb27ae8b1,0x3e10,0x4d07,{0xab,0x5c,0xeb,0x9a,0x6d,0xc6,0xfa,0x8f}};
    static const efi_guid loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
#endif
    if(!r||!w||r->attempted)return 0;r->attempted=1;
#if !EFI_XNU_AUDIO_I2C_CACHE_AVAILABLE || defined(POLARIS_EFI_TEST_QEMU)
    (void)io;(void)stage;r->error=PAIC_DISABLED;return 0;
#else
    if(stage!=2){r->error=PAIC_STAGE;return 0;}
    if(!io||!io->system||!io->system->boot||!io->arch||!io->identity||!io->order||
       !io->arch(io->context,&r->before)||!paic_arch_admitted(&r->before)){
        r->error=PAIC_ARCH;return 0;
    }
    r->cookie=r->before.ticks|1;
    struct efi_boot *bs=io->system->boot;efi_handle *handles=0;void *table=0;unsigned handles_owned=0;
    if(!bs->locate_protocol||!bs->locate_buffer||!bs->handle_protocol||!bs->get_map||!bs->free_pool){
        r->error=PAIC_PROTOCOL;return 0;
    }
    r->protocol_status=bs->locate_protocol(&protocol,0,&table);r->protocol=(uintptr_t)table;
    if(r->protocol_status||!table){r->error=PAIC_PROTOCOL;return 0;}
    r->enumerate_status=bs->locate_buffer(2,&loaded_guid,0,&r->handle_count,&handles);
    r->handles=(uintptr_t)handles;
    if(r->enumerate_status||!handles){r->error=PAIC_ENUMERATE;return 0;}
    if(!r->handle_count||r->handle_count>PAIC_HANDLES){r->error=PAIC_ENUMERATE;goto release;}
    if(!paic_map(bs,r,w,0)){r->error=PAIC_MAP;goto release;}
    if(!paic_owned(io,r,w,(uintptr_t)r,sizeof(*r))||!paic_owned(io,r,w,(uintptr_t)w,sizeof(*w))){r->error=PAIC_PROVENANCE;goto release;}
    if(!paic_owned(io,r,w,(uintptr_t)handles,r->handle_count*sizeof(*handles))){r->error=PAIC_ARRAY;goto release;}
    handles_owned=1;
    for(unsigned n=0;n<r->handle_count;n++){
        r->handle_status[n]=bs->handle_protocol(handles[n],&loaded_guid,(void**)&w->loaded[n]);
        r->loaded_address[n]=(uintptr_t)w->loaded[n];
        if(r->handle_status[n]||!w->loaded[n]){r->error=PAIC_HANDLE;goto release;}
    }
    handles_owned=0; /* A new/failed map must not reuse an earlier ownership witness. */
    if(!paic_map(bs,r,w,0)){r->error=PAIC_MAP;goto release;}
    if(!paic_owned(io,r,w,(uintptr_t)handles,r->handle_count*sizeof(*handles))){r->error=PAIC_ARRAY;goto release;}
    handles_owned=1;
    if(!paic_owned(io,r,w,r->protocol,48)){r->error=PAIC_PROVENANCE;goto release;}
    for(unsigned n=0;n<r->handle_count;n++){
        if(!paic_owned(io,r,w,r->loaded_address[n],sizeof(struct efi_loaded))){r->error=PAIC_PROVENANCE;goto release;}
        const struct efi_loaded *image=w->loaded[n];uint64_t base=(uintptr_t)image->base;
        if(base>UINT64_MAX-0x6098||base+0x6098!=r->protocol)continue;
        r->owner_matches++;r->image=base;
        r->owner_address=r->loaded_address[n];r->owner=*image;
        if(image->revision!=0x1000||image->system!=io->system||image->bytes!=PAII_IMAGE_BYTES||
           image->code_type!=3||image->data_type!=4||(base&4095)){
            r->error=PAIC_IMAGE;goto release;
        }
    }
    if(r->owner_matches!=1){r->error=PAIC_PROVENANCE;goto release;}
    if(!paic_owned(io,r,w,r->image,PAII_IMAGE_BYTES)){r->error=PAIC_IDENTITY;goto release;}
    const uint8_t *image=(const void*)(uintptr_t)r->image;
    if(!paii_verify(image,r->image,PAII_IMAGE_BYTES,r->hashes,&r->hash_failed,&r->hash_count)){
        r->error=PAIC_HASH;goto release;
    }
    if(paii_le(image+0x6098,8)!=0x10000||paii_le(image+0x60a0,8)!=r->image+0x2510||
       paii_le(image+0x60a8,8)!=r->image+0x2808||paii_le(image+0x60b0,8)!=r->image+0x2c2c||
       paii_le(image+0x60b8,8)!=r->image+0x295c||paii_le(image+0x60c0,8)!=r->image+0x2dd8){
        r->error=PAIC_PROVENANCE;goto release;
    }
    io->order(io->context);
    for(unsigned s=0;s<2;s++){
        /* Ordinary reads of owned original-image RAM; no cache invalidate or
         * clean that could affect a remote/shared allocation. */
        for(unsigned n=0;n<PAIC_CACHE_BYTES;n++)r->snapshot[s][n]=((const volatile uint8_t*)image)[PAIC_CACHE_RVA+n];
        r->snapshot_bytes[s]=PAIC_CACHE_BYTES;
        io->order(io->context);
    }
    table=0;r->protocol_after_status=bs->locate_protocol(&protocol,0,&table);r->protocol_after=(uintptr_t)table;
    if(r->protocol_after_status||r->protocol_after!=r->protocol){r->error=PAIC_PROVENANCE;goto release;}
    handles_owned=0;
    if(!paic_map(bs,r,w,1)){r->error=PAIC_MAP;goto release;}
    if(!paic_owned(io,r,w,(uintptr_t)handles,r->handle_count*sizeof(*handles))){r->error=PAIC_ARRAY;goto release;}
    handles_owned=1;
    if(r->map_key[0]!=r->map_key[1]||!paic_owned(io,r,w,r->image,PAII_IMAGE_BYTES)){
        r->error=PAIC_CHANGED_MAP;goto release;
    }
    if(!paic_owned(io,r,w,r->owner_address,sizeof(r->owner))||
       !paic_equal((const uint8_t*)&r->owner,(const uint8_t*)(uintptr_t)r->owner_address,sizeof(r->owner))){
        r->error=PAIC_PROVENANCE;goto release;
    }
    if(!paic_equal(r->snapshot[0],r->snapshot[1],PAIC_CACHE_BYTES)){
        r->error=PAIC_CHANGED_CACHE;goto release;
    }
    r->cache_consistent=1;
    /* Raw numeric observations only. No value is dereferenced or promoted to
     * active SE5/clock/TLMM/bus ownership, TAS identity or hardware permission. */
    r->raw_context_head=paii_le(r->snapshot[0]+0x40,8);
    r->raw_clock_handle=paii_le(r->snapshot[0]+0x48,8);
    r->raw_TLMM_handle=paii_le(r->snapshot[0]+0x50,8);
    r->map_keys_before_release_only=1;
release:
    /* Never free an unvalidated/unknown returned pointer. Failure retains its
     * raw value and consumes this one attempt; no arbitrary FreePool retry. */
    if(handles_owned){r->release_attempted=1;r->release_status=bs->free_pool(handles);}
    if(r->release_status&&!r->error)r->error=PAIC_RELEASE;
    if(!io->arch(io->context,&r->after)||!paic_arch_stable(&r->before,&r->after)){
        if(!r->error)r->error=PAIC_LIFETIME;
    }
    return r->error==PAIC_OK;
#endif
}
static inline int paic_actual_arch(void *context,struct paic_arch *a)
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
static inline int paic_actual_identity(void *context,uint64_t address,uint64_t bytes,uint64_t *where,uint64_t *raw)
{
    (void)context;
#if defined(__aarch64__) || defined(__arm64__)
    if(!bytes||address>UINT64_MAX-bytes||address+bytes>UINT64_MAX-4095)return 0;
    for(uint64_t p=address&~UINT64_C(4095);p<address+bytes;p+=4096){
        uint64_t saved,par;
        __asm__ volatile("mrs %0,par_el1\n\tat s1e1r,%2\n\tisb\n\tmrs %1,par_el1\n\tmsr par_el1,%0"
            :"=&r"(saved),"=&r"(par):"r"(p):"memory");
        *where=p;*raw=par;
        if((par&1)||!(par&UINT64_C(0x200))||(par>>56)!=0xff||(par&UINT64_C(0x0000fffffffff000))!=p)return 0;
    }
    return 1;
#else
    (void)address;(void)bytes;(void)where;(void)raw;return 0;
#endif
}
static inline void paic_actual_order(void *context)
{
    (void)context;
#if defined(__aarch64__) || defined(__arm64__)
    __asm__ volatile("dsb sy":::"memory");
#endif
}
/* Parent may call once from admitted prepare_boot stage2 before IRQ masking.
 * Not integrated into any phone image. QEMU and defaultOFF execute no BS. */
static struct paic_result paic_record;
static struct paic_workspace paic_work;
static inline void paic_report_arch(const struct paic_arch *a,unsigned pass)
{
    report("AUDIO_I2C_CACHE_ARCH_PASS=",pass);
    report("AUDIO_I2C_CACHE_EL=",a->el);report("AUDIO_I2C_CACHE_MPIDR=",a->mpidr);
    report("AUDIO_I2C_CACHE_TTBR0=",a->ttbr0);report("AUDIO_I2C_CACHE_TTBR1=",a->ttbr1);
    report("AUDIO_I2C_CACHE_TCR=",a->tcr);report("AUDIO_I2C_CACHE_SCTLR=",a->sctlr);report("AUDIO_I2C_CACHE_MAIR=",a->mair);
    report("AUDIO_I2C_CACHE_DAIF=",a->daif);report("AUDIO_I2C_CACHE_SRE=",a->sre);report("AUDIO_I2C_CACHE_GROUP1=",a->group1);
    report("AUDIO_I2C_CACHE_FREQUENCY=",a->frequency);report("AUDIO_I2C_CACHE_TICKS=",a->ticks);
}
static inline void paic_prepare(struct efi_system *system,uint32_t stage)
{
    if(paic_record.attempted)return;
    const struct paic_io io={system,0,paic_actual_arch,paic_actual_identity,paic_actual_order};
    (void)paic_collect(&io,stage,&paic_record,&paic_work);
    report("AUDIO_I2C_CACHE_ERROR=",paic_record.error);report("AUDIO_I2C_CACHE_COOKIE=",paic_record.cookie);
    paic_report_arch(&paic_record.before,0);paic_report_arch(&paic_record.after,1);
    report("AUDIO_I2C_CACHE_IMAGE=",paic_record.image);report("AUDIO_I2C_CACHE_PROTOCOL=",paic_record.protocol);
    report("AUDIO_I2C_CACHE_PROTOCOL_STATUS=",paic_record.protocol_status);report("AUDIO_I2C_CACHE_ENUMERATE_STATUS=",paic_record.enumerate_status);
    report("AUDIO_I2C_CACHE_PROTOCOL_AFTER_STATUS=",paic_record.protocol_after_status);report("AUDIO_I2C_CACHE_PROTOCOL_AFTER=",paic_record.protocol_after);
    report("AUDIO_I2C_CACHE_IDENTITY_ADDRESS=",paic_record.identity_address);report("AUDIO_I2C_CACHE_IDENTITY_PAR=",paic_record.identity_par);
    report("AUDIO_I2C_CACHE_OWNER_MATCHES=",paic_record.owner_matches);
    report("AUDIO_I2C_CACHE_OWNER_ADDRESS=",paic_record.owner_address);report("AUDIO_I2C_CACHE_HANDLE_COUNT=",paic_record.handle_count);
    for(unsigned n=0;n<paic_record.handle_count&&n<PAIC_HANDLES;n++){
        report("AUDIO_I2C_CACHE_HANDLE_INDEX=",n);report("AUDIO_I2C_CACHE_HANDLE_STATUS=",paic_record.handle_status[n]);
        report("AUDIO_I2C_CACHE_LOADED_ADDRESS=",paic_record.loaded_address[n]);
    }
    report("AUDIO_I2C_CACHE_HASH_COUNT=",paic_record.hash_count);report("AUDIO_I2C_CACHE_FAILED_HASH=",paic_record.hash_failed);
    for(unsigned n=0;n<paic_record.hash_count&&n<PAII_RANGE_COUNT;n++){
        report("AUDIO_I2C_CACHE_HASH_INDEX=",n);
        for(unsigned byte=0;byte<32;byte+=8)report("AUDIO_I2C_CACHE_HASH_RAW64=",paii_le(paic_record.hashes[n]+byte,8));
    }
    report("AUDIO_I2C_CACHE_MAP_KEY_BEFORE=",paic_record.map_key[0]);report("AUDIO_I2C_CACHE_MAP_KEY_BEFORE_FREEPOOL=",paic_record.map_key[1]);
    report("AUDIO_I2C_CACHE_MAP_VERSION_BEFORE=",paic_record.map_version[0]);report("AUDIO_I2C_CACHE_MAP_VERSION_BEFORE_FREEPOOL=",paic_record.map_version[1]);
    for(unsigned n=0;n<paic_record.map_samples;n++){
        const struct paic_map_sample *m=&paic_record.map_sample[n];report("AUDIO_I2C_CACHE_MAP_SAMPLE=",n);
        report("AUDIO_I2C_CACHE_MAP_STATUS=",m->status);report("AUDIO_I2C_CACHE_MAP_KEY=",m->key);
        report("AUDIO_I2C_CACHE_MAP_BYTES=",m->bytes);report("AUDIO_I2C_CACHE_MAP_STRIDE=",m->stride);report("AUDIO_I2C_CACHE_MAP_VERSION=",m->version);
    }
    report("AUDIO_I2C_CACHE_FREE_STATUS=",paic_record.release_status);
    report("AUDIO_I2C_CACHE_RAW_CONTEXT_HEAD_NOT_FOLLOWED=",paic_record.raw_context_head);
    report("AUDIO_I2C_CACHE_RAW_CLOCK_HANDLE_NOT_CALLED=",paic_record.raw_clock_handle);
    report("AUDIO_I2C_CACHE_RAW_TLMM_HANDLE_NOT_CALLED=",paic_record.raw_TLMM_handle);
    for(unsigned pass=0;pass<2;pass++)if(paic_record.snapshot_bytes[pass]){
        report("AUDIO_I2C_CACHE_RAW_PASS=",pass);report("AUDIO_I2C_CACHE_RAW_BYTES=",paic_record.snapshot_bytes[pass]);
        for(unsigned n=0;n<PAIC_CACHE_BYTES;n+=8)report("AUDIO_I2C_CACHE_RAW64=",paii_le(paic_record.snapshot[pass]+n,8));
    }
    text("AUDIO_I2C_CACHE: original-image RAM only; pointer_follow=0 methods_called=0 DAL=0 MMIO=0 SE5_owner_proved=0 TAS_identity_proved=0 PCM_completed=0\r\n");
}
#endif
