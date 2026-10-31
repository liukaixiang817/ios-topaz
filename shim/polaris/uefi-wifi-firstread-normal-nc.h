/* Independent default-OFF Normal-NC first read in the ORIGINAL CPU0 world.
 * This never widens the old Device-only reader or its consumed candidate.
 * Exact ATTR44/OuterShareable/NS/identity for all3pages is required. Normal
 * memory permits speculative/repeated/coalesced bus accesses:18 is ONLY the
 * maximum architecturally issued target LDR32 instructions, NOT a bus cap.
 * Admission is a fresh exact original constructor-cache retrospective witness,
 * NOT a hardware MPU/VMID query or a fault-contained reader. External SError
 * may be unrecoverable. No nativeCPU7 permission, FIFO, TX or Wi-Fi claim.
 * Only prepare_boot immediately after cache PASS; no runtime/USB command API. */
#ifndef POLARIS_UEFI_WIFI_NORMAL_NC_FIRSTREAD_H
#define POLARIS_UEFI_WIFI_NORMAL_NC_FIRSTREAD_H
#include "uefi-wifi-cache-readonly.h"
#ifndef EFI_XNU_WIFI_NORMAL_NC_FIRSTREAD_AVAILABLE
#define EFI_XNU_WIFI_NORMAL_NC_FIRSTREAD_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_NORMAL_NC_FIRSTREAD_AVAILABLE && EFI_XNU_WIFI_FIRSTREAD_AVAILABLE
#error "Normal-NC and original Device-only firstread are mutually exclusive"
#endif
#if EFI_XNU_WIFI_NORMAL_NC_FIRSTREAD_AVAILABLE && !EFI_XNU_WIFI_CACHE_AVAILABLE
#error "Normal-NC firstread requires the exact original cache witness"
#endif
#define PWNC_PAR_CLASS UINT64_C(0x4400000000000b00) /* Normal Inner/OuterNC, NS, OuterShareable. */
#define PWNC_WORDS 9u
#define PWNC_PAGES 3u
#define PWNC_FULL_MASK 0x1ffu
#define PWNC_MAX_AGE_TICKS UINT64_C(3840000) /* Real19.2MHz:200ms; no retries. */
enum pwnc_error {PWNC_OK,PWNC_DISABLED,PWNC_WITNESS,PWNC_SELF,PWNC_ARCH,
    PWNC_STALE,PWNC_TRANSLATION,PWNC_ATTRIBUTES,PWNC_CHANGED_TRANSLATION,
    PWNC_READ,PWNC_VALUE,PWNC_MISMATCH,PWNC_LIFETIME,PWNC_OUTSTANDING};
static const uint64_t pwnc_addresses[PWNC_WORDS]={
    UINT64_C(0x8600005c),UINT64_C(0x860000c0),
    UINT64_C(0x861ff000),UINT64_C(0x861ff004),UINT64_C(0x861ff008),
    UINT64_C(0x860b9000),UINT64_C(0x860b9008),UINT64_C(0x860b900c),UINT64_C(0x860b9010)};
static const uint64_t pwnc_pages[PWNC_PAGES]={
    UINT64_C(0x86000000),UINT64_C(0x860b9000),UINT64_C(0x861ff000)};
struct pwnc_result {
    uint64_t self_base,self_bytes,self_system,cookie,start_ticks,end_ticks;
    uint64_t par[2][2][PWNC_PAGES],last_address,last_par;
    struct pwfc_arch before,after;
    /* Volatile progress is stored and DSB'd BEFORE each target LDR32. It is
     * diagnostic RAM, not persistent storage or guaranteed SError recovery. */
    volatile uint32_t attempted,error,phase,pass,index;
    volatile uint32_t issued[2],completed[2],raw[2][PWNC_WORDS];
    uint32_t self_bound,cache_admitted,par_issued,par_completed,arch_issued,arch_completed;
};
struct pwnc_io {
    void *context;
    int (*arch)(void *,struct pwfc_arch *);
    int (*owned)(void *,uint64_t,uint64_t);
    int (*translate)(void *,uint64_t,uint64_t *);
    int (*load32)(void *,uint64_t,uint32_t *);
    void (*order)(void *);
};
static inline int pwnc_bind(struct pwnc_result *r,const struct efi_loaded *image)
{
    if(!r||!image||r->self_bound||r->attempted)return 0;
    uint64_t base=(uintptr_t)image->base,address=(uintptr_t)r;
    if(image->revision!=0x1000||image->code_type!=3||image->data_type!=4||!base||
       !image->bytes||base>UINT64_MAX-image->bytes||address<base||sizeof(*r)>image->bytes||
       address-base>image->bytes-sizeof(*r)||
       (base<UINT64_C(0x86200000)&&UINT64_C(0x86000000)<base+image->bytes))return 0;
    r->self_base=base;r->self_bytes=image->bytes;r->self_system=(uintptr_t)image->system;
    r->self_bound=1;return 1;
}
static inline int pwnc_witness(const struct pwfc_result *c)
{
    if(!c||!c->attempted||c->error||!c->cookie||c->hash_failed||c->hash_count!=4||
       c->after.mair!=UINT64_C(0xffbb4400)||
       c->owner_matches!=1||!c->image||c->image>UINT64_MAX-PWFI_IMAGE_BYTES||
       c->protocol!=c->image+0x7090||c->protocol_after!=c->protocol||
       c->protocol_status||c->protocol_after_status||c->enumerate_status||c->map_status||c->release_status||
       !c->release_attempted||!c->cache_consistent||!c->mpss_cached||
       c->snapshot_bytes[0]!=632||c->snapshot_bytes[1]!=632||
       !pwfc_equal(c->snapshot[0],c->snapshot[1],632)||
       !pwfc_cache_valid(c->snapshot[0],c->image)||
       c->map_key[0]!=c->map_key[1]||!c->map_key[0]||
       c->smem_descriptor_matches!=1||c->smem_descriptor.physical!=UINT64_C(0x86000000)||
       c->smem_descriptor.pages!=512||c->smem_descriptor.type!=0||c->smem_descriptor.attributes!=1||
       !pwfc_arch_stable(&c->before,&c->after)||c->cookie!=(c->before.ticks|1))return 0;
    const uint8_t *p=c->snapshot[0];
    if(pwfi_le(p+20,4)!=0xc0000||pwfi_le(p+24,2)!=615||
       pwfi_le(p+32,8)!=c->image+0x5cb0||pwfi_le(p+48,8)!=UINT64_C(0x86001000)||
       pwfi_le(p+56,4)!=0x88000||pwfi_le(p+60,4)!=32||
       pwfi_le(p+96,8)!=UINT64_C(0x860b9000)||pwfi_le(p+104,4)!=0x7c000||pwfi_le(p+108,4)!=32||
       pwfi_le(p+544,2)!=615)return 0;
    for(unsigned n=0;n<PWFI_RANGE_COUNT;n++)if(!pwfc_equal(c->hashes[n],pwfi_ranges[n].sha256,32))return 0;
    return c->owner.bytes==PWFI_IMAGE_BYTES&&c->owner.base==(void*)(uintptr_t)c->image&&
        c->owner.revision==0x1000&&c->owner.code_type==3&&c->owner.data_type==4;
}
static inline int pwnc_arch_same(const struct pwfc_arch *w,const struct pwfc_arch *a)
{
    return pwfc_arch_admitted(a)&&w->el==a->el&&w->mpidr==a->mpidr&&w->ttbr0==a->ttbr0&&
        w->ttbr1==a->ttbr1&&w->tcr==a->tcr&&w->sctlr==a->sctlr&&w->mair==a->mair&&
        w->daif==a->daif&&w->sre==a->sre&&w->group1==a->group1&&w->frequency==a->frequency;
}
static inline int pwnc_live(const struct pwfc_result *c,const struct pwnc_io *io,struct pwnc_result *r)
{
    struct pwfc_arch a={0};uint64_t previous=r->end_ticks;
    r->arch_issued++;int observed=io->arch(io->context,&a);
    if(observed)r->arch_completed++;r->after=a;r->end_ticks=a.ticks;
    if(!observed||!pwnc_arch_same(&c->after,&a)){
        if(!r->error)r->error=PWNC_ARCH;return 0;
    }
    if(a.ticks<c->after.ticks||a.ticks-c->after.ticks>PWNC_MAX_AGE_TICKS||
       (r->start_ticks&&a.ticks<r->start_ticks)||(previous&&a.ticks<previous)){
        if(!r->error)r->error=PWNC_STALE;return 0;
    }
    return 1;
}
static inline int pwnc_pars(const struct pwfc_result *c,const struct pwnc_io *io,
    struct pwnc_result *r,unsigned pass,unsigned after)
{
    r->index=UINT32_MAX;
    for(unsigned n=0;n<PWNC_PAGES;n++){
        if(!pwnc_live(c,io,r))return 0;
        uint64_t raw=0;r->last_address=pwnc_pages[n];r->par_issued++;
        io->order(io->context);
        if(!io->translate(io->context,pwnc_pages[n],&raw)){
            r->last_par=raw;r->par[pass][after][n]=raw;r->error=PWNC_TRANSLATION;return 0;
        }
        r->par_completed++;r->last_par=raw;r->par[pass][after][n]=raw;
        if((raw&1)||(raw&UINT64_C(0x0000fffffffff000))!=pwnc_pages[n]){
            r->error=PWNC_TRANSLATION;return 0;
        }
        /* Exact separate Normal-NC policy. This is a translation class,
         * never a fresh MPU/VMID grant or proof speculative reads are absent.
         * No Device/WB/WT/other-NC fallback and no mapping/cache writes. */
        if(raw!=(PWNC_PAR_CLASS|pwnc_pages[n])){r->error=PWNC_ATTRIBUTES;return 0;}
        if((after&&raw!=r->par[pass][0][n])||(pass&&raw!=r->par[0][0][n])){
            r->error=PWNC_CHANGED_TRANSLATION;return 0;
        }
    }
    return 1;
}
static inline int pwnc_value(unsigned index,uint32_t value,const struct pwnc_result *r,unsigned pass)
{
    switch(index){
    case 0:return value==0xc0000;
    case 1:return value==1;
    case 2:return value==0x434f5424;
    case 3:return value==1;
    case 4:return value>=6&&value<=20;
    case 5:return value==0x54525024;
    case 6:return value==0x7c000;
    case 7:return value>=0x20&&value<=0x7c000&&!(value&7);
    case 8:return value>=r->raw[pass][7]&&value<=0x7c000&&!(value&7);
    default:return 0;
    }
}
/* Generic core's fake services are only used by host fixtures. Physical entry
 * below has no externally selectable address/callback/command argument. */
static inline int pwnc_collect(unsigned enabled,uint32_t stage,const struct pwfc_result *c,
    const struct pwnc_io *io,struct pwnc_result *r)
{
    if(!r||r->attempted)return 0;r->attempted=1;r->index=UINT32_MAX;
    if(enabled!=1){r->error=PWNC_DISABLED;return 0;}
    if(stage!=2){r->error=PWNC_LIFETIME;return 0;}
    if(!pwnc_witness(c)){r->error=PWNC_WITNESS;return 0;}
    if(!io||!io->arch||!io->owned||!io->translate||!io->load32||!io->order||
       !r->self_bound||!r->self_system||r->self_system!=(uintptr_t)c->owner.system||
       !r->self_base||r->self_base>UINT64_MAX-r->self_bytes||
       (uintptr_t)r<r->self_base||sizeof(*r)>r->self_bytes||
       (uintptr_t)r-r->self_base>r->self_bytes-sizeof(*r)||
       !io->owned(io->context,(uintptr_t)r,sizeof(*r))||
       !io->owned(io->context,(uintptr_t)c,sizeof(*c))||
       !io->owned(io->context,c->image,PWFI_IMAGE_BYTES)){
        r->error=PWNC_SELF;return 0;
    }
    r->cookie=c->cookie;r->cache_admitted=1;
    if(!pwnc_live(c,io,r))return 0;
    r->before=r->after;r->start_ticks=r->after.ticks;
    for(unsigned pass=0;pass<2;pass++){
        r->pass=pass;r->phase=1;io->order(io->context);
        if(!pwnc_pars(c,io,r,pass,0))return 0;
        r->phase=2;
        for(unsigned n=0;n<PWNC_WORDS;n++){
            if(!pwnc_live(c,io,r))return 0;
            r->index=n;r->raw[pass][n]=0;r->error=PWNC_OUTSTANDING;
            r->issued[pass]|=1u<<n;r->last_address=pwnc_addresses[n];
            io->order(io->context);
            uint32_t value=0;
            int completed=io->load32(io->context,pwnc_addresses[n],&value);
            r->raw[pass][n]=value;
            if(!completed){
                r->error=PWNC_READ;io->order(io->context);return 0;
            }
            io->order(io->context);
            r->completed[pass]|=1u<<n;
            io->order(io->context);
            /* A nonreturning/external-fault path retains OUTSTANDING. Clear
             * only after this load returned and raw+completed were ordered. */
            r->error=PWNC_OK;io->order(io->context);
            if(!pwnc_value(n,value,r,pass)){r->error=PWNC_VALUE;io->order(io->context);return 0;}
        }
        r->phase=3;
        if(!pwnc_pars(c,io,r,pass,1)||!pwnc_live(c,io,r))return 0;
        if(pass)for(unsigned n=0;n<PWNC_WORDS;n++)if(r->raw[0][n]!=r->raw[1][n]){
            r->error=PWNC_MISMATCH;io->order(io->context);return 0;
        }
    }
    r->phase=4;r->index=UINT32_MAX;io->order(io->context);return 1;
}
static inline int pwnc_actual_owned(void *context,uint64_t address,uint64_t bytes)
{
    (void)context;
    /* Uses the just-validated map from the preceding cache inspection. No
     * BootServices query after cache PASS and no lookup of any shared pointer. */
    if(!address||!bytes||address>UINT64_MAX-bytes||address+bytes>UINT64_MAX-4095)return 0;
    for(uint64_t page=address&~UINT64_C(4095);page<address+bytes;page+=4096){
        if(!polaris_efi_range_owned(pwfc_work.map,pwfc_record.map_bytes,pwfc_record.map_stride,page,4096,3)&&
           !polaris_efi_range_owned(pwfc_work.map,pwfc_record.map_bytes,pwfc_record.map_stride,page,4096,4))return 0;
    }
    uint64_t where=0,raw=0;return pwfc_actual_identity(0,address,bytes,&where,&raw);
}
static inline int pwnc_actual_translate(void *context,uint64_t address,uint64_t *raw)
{
    (void)context;
#if defined(__aarch64__) || defined(__arm64__)
    uint64_t saved;
    __asm__ volatile("mrs %0,par_el1\n\tat s1e1r,%2\n\tisb\n\tmrs %1,par_el1\n\tmsr par_el1,%0"
        :"=&r"(saved),"=&r"(*raw):"r"(address):"memory");return 1;
#else
    (void)address;(void)raw;return 0;
#endif
}
static inline int pwnc_actual_load32(void *context,uint64_t address,uint32_t *value)
{
    (void)context;
#if defined(__aarch64__) || defined(__arm64__)
    /* Ordinary LDR32. There is deliberately NO promise of catching external
     * abort/SError. Issued/index was stored+DSB before arriving at this load. */
    __asm__ volatile("ldr %w0,[%1]":"=r"(*value):"r"(address):"memory");return 1;
#else
    (void)address;(void)value;return 0;
#endif
}
static struct pwnc_result pwnc_record;
/* Parent calls from already admitted self LoadedImage path, with no new BS. */
static inline int pwnc_bind_resident(const struct efi_loaded *image)
{return pwnc_bind(&pwnc_record,image);}
static inline void pwnc_prepare(const struct pwfc_result *cache,uint32_t stage)
{
    if(pwnc_record.attempted)return;
#if EFI_XNU_WIFI_NORMAL_NC_FIRSTREAD_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
    const struct pwnc_io io={0,pwfc_actual_arch,pwnc_actual_owned,pwnc_actual_translate,
        pwnc_actual_load32,pwfc_actual_order};
    if(cache!=&pwfc_record){pwnc_record.attempted=1;pwnc_record.error=PWNC_WITNESS;}
    else (void)pwnc_collect(1,stage,cache,&io,&pwnc_record);
#else
    (void)cache;(void)stage;pwnc_record.attempted=1;pwnc_record.error=PWNC_DISABLED;
#endif
    report("WIFI_NORMAL_NC_FIRSTREAD_ATTEMPTED=",pwnc_record.attempted);
    report("WIFI_NORMAL_NC_FIRSTREAD_ARCHITECTURAL_LDR32_MAX=",18);
    report("WIFI_NORMAL_NC_FIRSTREAD_PHYSICAL_BUS_TRANSACTION_CAP=",0);
    report("WIFI_NORMAL_NC_FIRSTREAD_ERROR=",pwnc_record.error);report("WIFI_NORMAL_NC_FIRSTREAD_COOKIE=",pwnc_record.cookie);
    report("WIFI_NORMAL_NC_FIRSTREAD_PHASE=",pwnc_record.phase);report("WIFI_NORMAL_NC_FIRSTREAD_PASS=",pwnc_record.pass);
    report("WIFI_NORMAL_NC_FIRSTREAD_INDEX=",pwnc_record.index);report("WIFI_NORMAL_NC_FIRSTREAD_START=",pwnc_record.start_ticks);
    report("WIFI_NORMAL_NC_FIRSTREAD_END=",pwnc_record.end_ticks);report("WIFI_NORMAL_NC_FIRSTREAD_SELF_BOUND=",pwnc_record.self_bound);
    report("WIFI_NORMAL_NC_FIRSTREAD_CACHE_ADMITTED=",pwnc_record.cache_admitted);
    report("WIFI_NORMAL_NC_FIRSTREAD_ARCH_ISSUED=",pwnc_record.arch_issued);report("WIFI_NORMAL_NC_FIRSTREAD_ARCH_COMPLETED=",pwnc_record.arch_completed);
    report("WIFI_NORMAL_NC_FIRSTREAD_PAR_ISSUED=",pwnc_record.par_issued);report("WIFI_NORMAL_NC_FIRSTREAD_PAR_COMPLETED=",pwnc_record.par_completed);
    report("WIFI_NORMAL_NC_FIRSTREAD_LAST_ADDRESS=",pwnc_record.last_address);report("WIFI_NORMAL_NC_FIRSTREAD_LAST_PAR=",pwnc_record.last_par);
    if(pwnc_record.arch_issued){
        const struct pwfc_arch *states[2]={&pwnc_record.before,&pwnc_record.after};
        for(unsigned n=0;n<2;n++){
            text(n?"WIFI_NORMAL_NC_FIRSTREAD_ARCH_AFTER_RAW_PARTIAL_IF_ERROR\r\n":"WIFI_NORMAL_NC_FIRSTREAD_ARCH_BEFORE_RAW\r\n");
            const struct pwfc_arch *a=states[n];
            report("EL=",a->el);report("MPIDR=",a->mpidr);report("TTBR0=",a->ttbr0);report("TTBR1=",a->ttbr1);
            report("TCR=",a->tcr);report("SCTLR=",a->sctlr);report("MAIR=",a->mair);report("DAIF=",a->daif);
            report("SRE=",a->sre);report("GROUP1=",a->group1);report("CNTFRQ=",a->frequency);report("CNTVCT=",a->ticks);
        }
    }
    for(unsigned pass=0;pass<2;pass++){
        report("WIFI_NORMAL_NC_FIRSTREAD_RAW_PASS=",pass);report("WIFI_NORMAL_NC_FIRSTREAD_ISSUED_MASK=",pwnc_record.issued[pass]);
        report("WIFI_NORMAL_NC_FIRSTREAD_COMPLETED_MASK=",pwnc_record.completed[pass]);
        for(unsigned n=0;n<PWNC_WORDS;n++)if(pwnc_record.issued[pass]&(1u<<n)){
            report("WIFI_NORMAL_NC_FIRSTREAD_WORD_INDEX=",n);report("WIFI_NORMAL_NC_FIRSTREAD_RAW32=",pwnc_record.raw[pass][n]);
        }
        for(unsigned after=0;after<2;after++)for(unsigned n=0;n<PWNC_PAGES;n++)
            report("WIFI_NORMAL_NC_FIRSTREAD_PAR_RAW=",pwnc_record.par[pass][after][n]);
    }
    text("WIFI_NORMAL_NC_FIRSTREAD: CPU0 NormalNC constructor retrospective admission only; architectural_LDR32_max=18 physical_bus_transaction_cap=0 speculative_coalesced_repeated_reads_possible=1 external_SERROR_recoverable=0 hardware_MPU_query=0 VMID_query=0 native_permission=0 FIFO=0 radio=0 may_transmit=0\r\n");
}
#endif
