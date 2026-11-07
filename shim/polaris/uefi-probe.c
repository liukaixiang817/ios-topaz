/* UEFI inventory: never exits Boot Services, writes storage/NVRAM or enters
 * XNU. Bounded RAM logs/map/GOP reads; a separately enabled, explicit host
 * FASTBOOT return may set only the existing volatile restart markers. */
#include "uefi-memory.h"
#ifdef POLARIS_EFI_APPS_WATCHDOG_READONLY
#include "uefi-apps-watchdog-readonly.h"
#if !defined(POLARIS_EFI_READY_TO_BOOT) || !defined(POLARIS_EFI_USB_DIAG) || !POLARIS_EFI_HOLD
#error Apps watchdog inventory requires a hold-only USB diagnostic driver
#endif
#endif
#ifdef POLARIS_EFI_NATIVE_FAULT_WITNESS
#include "uefi-native-fault-witness.h"
#include "native-fault-witness-config.h"
#if !defined(POLARIS_EFI_READY_TO_BOOT) || !defined(POLARIS_EFI_USB_DIAG) || !POLARIS_EFI_HOLD
#error Native fault witness requires a hold-only USB diagnostic driver
#endif
#endif
#ifdef POLARIS_EFI_PROBE_BOOTLOADER_RESET
#include "uefi-probe-reset.h"
#if !defined(POLARIS_EFI_READY_TO_BOOT) || !defined(POLARIS_EFI_USB_DIAG) || !POLARIS_EFI_HOLD
#error Probe FASTBOOT return requires a hold-only USB diagnostic driver
#endif
#endif
#ifdef POLARIS_EFI_USB_DIAG
#include "uefi-usb.h"
static uint8_t ram_log[32768];static uint64_t ram_log_bytes;
static struct {uint64_t magic,bytes,stride,version;uint8_t data[65536];} saved_map;
static uint64_t saved_map_bytes;
#endif
#ifndef POLARIS_EFI_HOLD
#define POLARIS_EFI_HOLD 0
#endif
static struct efi_output *output;
static struct efi_boot *boot;
static void text(const char *s)
{
#ifdef POLARIS_EFI_USB_DIAG
    for(unsigned i=0;s[i] && ram_log_bytes<sizeof(ram_log);i++)ram_log[ram_log_bytes++]=(uint8_t)s[i];
#endif
    uint16_t b[128];unsigned n=0;
    while(*s && n<127)b[n++]=(uint8_t)*s++;
    b[n]=0;output->string(output,b);
}
static void hex(const char *label,uint64_t v)
{
    char b[19];b[0]='0';b[1]='x';
    for(unsigned i=0;i<16;i++)b[2+i]="0123456789abcdef"[(v>>(60-i*4))&15];
    b[18]=0;text(label);text(b);text("\r\n");
}
#if defined(POLARIS_EFI_APPS_WATCHDOG_READONLY) || defined(POLARIS_EFI_NATIVE_FAULT_WITNESS) || defined(POLARIS_EFI_PROBE_BOOTLOADER_RESET)
static int probe_arch(void *context,struct pawr_arch *a)
{
    (void)context;
    __asm__ volatile("mrs %0,CurrentEL":"=r"(a->el));
    if(a->el!=4)return 0;
#define PAWR_MRS(member,reg) __asm__ volatile("mrs %0," #reg:"=r"(a->member))
    PAWR_MRS(mpidr,mpidr_el1);PAWR_MRS(daif,daif);PAWR_MRS(sctlr,sctlr_el1);
    PAWR_MRS(tcr,tcr_el1);PAWR_MRS(ttbr0,ttbr0_el1);PAWR_MRS(ttbr1,ttbr1_el1);
    PAWR_MRS(mair,mair_el1);PAWR_MRS(frequency,cntfrq_el0);
    __asm__ volatile("isb; mrs %0,cntvct_el0":"=r"(a->ticks)::"memory");
#undef PAWR_MRS
    return 1;
}
#endif
#ifdef POLARIS_EFI_PROBE_BOOTLOADER_RESET
static struct efi_system *reset_system_table;
static struct ppr_result reset_result;
static struct ppr_ops reset_ops;
static int probe_reset_translate(void *context,unsigned write,struct pawr_translation*t)
{
    (void)context;uint64_t at=PPR_REASON;
    if(write)__asm__ volatile("mrs %0,par_el1; at s1e1w,%3; isb; mrs %1,par_el1; msr par_el1,%0; isb; mrs %2,par_el1"
        :"=&r"(t->saved),"=&r"(t->par),"=&r"(t->restored):"r"(at):"memory");
    else __asm__ volatile("mrs %0,par_el1; at s1e1r,%3; isb; mrs %1,par_el1; msr par_el1,%0; isb; mrs %2,par_el1"
        :"=&r"(t->saved),"=&r"(t->par),"=&r"(t->restored):"r"(at):"memory");
    return 1;
}
static int probe_reason_read(void *context,uint32_t*v)
{(void)context;*v=*(const volatile uint32_t*)(uintptr_t)PPR_REASON;return 1;}
static int probe_reason_write(void *context,uint32_t v)
{
    (void)context;volatile uint32_t*p=(void*)(uintptr_t)PPR_REASON;
    *p=v;__asm__ volatile("dsb sy":::"memory");return *p==v;
}
static void probe_reset_system(void *context)
{(void)context;reset_system_table->runtime->reset_system(0,0,0,0);}
static int probe_prepare_reset(void *context,unsigned mode)
{
    (void)context;
    if(mode!=2||reset_result.attempted||!reset_system_table||
       !reset_system_table->runtime||reset_system_table->runtime->hdr.size<112||
       reset_system_table->runtime->hdr.signature!=UINT64_C(0x56524553544e5552)||
       !reset_system_table->runtime->reset_system)return 0;
    static const efi_guid pon_guid={0x97044b58,0xfea4,0x4ad0,{0x9d,0x0b,0xe4,0x17,0xd6,0x0f,0x11,0xa1}};
    struct polaris_efi_pon*pon=0;
    struct pawr_arch a={0};if(!probe_arch(0,&a)||!pawr_arch_valid(&a))return 0;
    if(reset_system_table->boot->locate_protocol(&pon_guid,0,(void**)&pon))return 0;
    reset_ops=(struct ppr_ops){0,probe_arch,probe_reset_translate,probe_reason_read,probe_reason_write,probe_reset_system,pon};
    return ppr_prepare(&reset_result,&reset_ops,mode);
}
static void probe_reset(void *context,unsigned mode)
{
    (void)context;ppr_execute(&reset_result,&reset_ops,mode);
    hex("PROBE_RESET_RETURNED_ERROR=",reset_result.error);
    hex("PROBE_RESET_REASON_RESTORED=",reset_result.reason_restored);
    hex("PROBE_RESET_PON_RESTORED=",reset_result.pon_restored);
}
#endif
#ifdef POLARIS_EFI_APPS_WATCHDOG_READONLY
static int watchdog_translate(void *context,uint64_t address,struct pawr_translation *t)
{
    (void)context;
    if(address!=PAWR_BASE+8 && address!=PAWR_BASE+12 &&
       address!=PAWR_BASE+16 && address!=PAWR_BASE+20)return 0;
    __asm__ volatile("mrs %0,par_el1; at s1e1r,%3; isb; mrs %1,par_el1; "
        "msr par_el1,%0; isb; mrs %2,par_el1"
        :"=&r"(t->saved),"=&r"(t->par),"=&r"(t->restored):"r"(address):"memory");
    return 1;
}
static int watchdog_read(void *context,uint64_t address,uint32_t *value)
{
    (void)context;
    if(address!=PAWR_BASE+8 && address!=PAWR_BASE+12 &&
       address!=PAWR_BASE+16 && address!=PAWR_BASE+20)return 0;
    __asm__ volatile("dsb sy":::"memory");
    *value=*(const volatile uint32_t *)(uintptr_t)address;
    __asm__ volatile("dsb sy":::"memory");return 1;
}
static void watchdog_inventory(const void *map,uint64_t bytes,uint64_t capacity,
    uint64_t stride,uint32_t version)
{
    static struct pawr_result r;
    const struct pawr_ops ops={0,probe_arch,watchdog_translate,watchdog_read};
    int ok=pawr_run(map,bytes,capacity,stride,version,&ops,&r);
    hex("APPS_WDT_READONLY_OK=",ok);hex("APPS_WDT_ERROR=",r.error);
    hex("APPS_WDT_MAP_PRESENT=",r.map_present);
    hex("APPS_WDT_MAP_TYPE=",r.map_type);hex("APPS_WDT_MAP_BASE=",r.map_base);
    hex("APPS_WDT_MAP_PAGES=",r.map_pages);hex("APPS_WDT_MAP_ATTR=",r.map_attributes);
    hex("APPS_WDT_EL=",r.opening.el);hex("APPS_WDT_DAIF=",r.opening.daif);
    hex("APPS_WDT_TCR=",r.opening.tcr);hex("APPS_WDT_READ_ISSUED=",r.issued);
    hex("APPS_WDT_READ_RETURNED=",r.returned);hex("APPS_WDT_CONFIG_STABLE=",r.stable);
    static const char *label[2][4]={{"APPS_WDT_EN_0=","APPS_WDT_STS_0=","APPS_WDT_BARK_0=","APPS_WDT_BITE_0="},
        {"APPS_WDT_EN_1=","APPS_WDT_STS_1=","APPS_WDT_BARK_1=","APPS_WDT_BITE_1="}};
    for(unsigned n=0;n<8;n++){hex("APPS_WDT_PAR=",r.translation[n].par);hex(label[n/4][n%4],r.value[n/4][n%4]);}
}
#endif
#ifdef POLARIS_EFI_NATIVE_FAULT_WITNESS
static int witness_translate(void *context,uint64_t address,struct pawr_translation *t)
{
    (void)context;if(!pnfw_range(&pnfw_configuration,address))return 0;
    __asm__ volatile("mrs %0,par_el1; at s1e1r,%3; isb; mrs %1,par_el1; "
        "msr par_el1,%0; isb; mrs %2,par_el1"
        :"=&r"(t->saved),"=&r"(t->par),"=&r"(t->restored):"r"(address):"memory");
    return 1;
}
static int witness_read(void *context,uint64_t address,uint8_t *value)
{
    (void)context;if(!pnfw_range(&pnfw_configuration,address))return 0;
    *value=*(const volatile uint8_t *)(uintptr_t)address;return 1;
}
static void witness_inventory(const void *map,uint64_t bytes,uint64_t capacity,
    uint64_t stride,uint32_t version)
{
    static struct pnfw_result r;
    const struct pnfw_ops ops={0,probe_arch,witness_translate,witness_read};
    int ok=pnfw_run(&pnfw_configuration,map,bytes,capacity,stride,version,&ops,&r);
    hex("FAULT_WITNESS_OK=",ok);hex("FAULT_WITNESS_ERROR=",r.error);
    hex("FAULT_WITNESS_READ_ISSUED=",r.issued);hex("FAULT_WITNESS_READ_RETURNED=",r.returned);
    hex("FAULT_WITNESS_NONCE_0=",r.nonce_match[0]);hex("FAULT_WITNESS_NONCE_1=",r.nonce_match[1]);
    hex("FAULT_WITNESS_STABLE=",r.stable);hex("FAULT_WITNESS_ZERO=",r.zero);
    hex("FAULT_WITNESS_VALID=",r.valid);
    hex("FAULT_WITNESS_SCALAR_VALID=",r.scalar_valid);hex("FAULT_WITNESS_SCALAR_STABLE=",r.scalar_stable);
    hex("FAULT_WITNESS_NONCE_2=",r.nonce_match[2]);hex("FAULT_WITNESS_NONCE_3=",r.nonce_match[3]);
    /* Unmatched/zero/corrupt remnants are not exception evidence. No raw RAM
     * is exported; only this candidate's validated record has scalar fields. */
    if(!ok||!r.valid)return;
    const struct pfnf_record*f=&r.record;
#define PNFW_FIELD(name) hex("OLD_FAULT_" #name "=",f->name)
    PNFW_FIELD(attempted);PNFW_FIELD(armed);PNFW_FIELD(error);PNFW_FIELD(draw_result);
    PNFW_FIELD(entered);PNFW_FIELD(reentered);PNFW_FIELD(old_vbar);PNFW_FIELD(vbar);
    PNFW_FIELD(vector);PNFW_FIELD(esr);PNFW_FIELD(elr);PNFW_FIELD(far);
    PNFW_FIELD(spsr);PNFW_FIELD(sp);PNFW_FIELD(sp0);PNFW_FIELD(ticks);
    PNFW_FIELD(boot_phase);PNFW_FIELD(parent_phase);PNFW_FIELD(parent_error);
    PNFW_FIELD(parent_unknown);PNFW_FIELD(parent_turns);PNFW_FIELD(copy_pages);
    PNFW_FIELD(copy_segments);PNFW_FIELD(copy_error);PNFW_FIELD(copy_ready);
    PNFW_FIELD(auth_phase);PNFW_FIELD(modem_step);PNFW_FIELD(owner_error);
    PNFW_FIELD(owner_held);PNFW_FIELD(owner_opening);PNFW_FIELD(owner_last);
#undef PNFW_FIELD
    hex("OLD_FAULT_DRIVER_BASE=",f->layout.image);
    if(r.scalar_valid)for(unsigned n=0;n<pnfw_configuration.scalar_count;n++){
        text("OLD_PROGRESS_");text(pnfw_scalar_names[n]);hex("=",r.scalar_value[0][n]);
    }
}
#endif
static const efi_guid loaded_guid={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
static const efi_guid gop_guid={0x9042a9de,0x23dc,0x4a38,{0x96,0xfb,0x7a,0xde,0xd0,0x80,0x51,0x6a}};
static const efi_guid fs_guid={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
static const efi_guid usb_guid={0xd9d9ce48,0x44b8,0x4f49,{0x8e,0x3e,0x2a,0x3b,0x92,0x7d,0xc6,0xc1}};
static const efi_guid global_guid={0x8be4df61,0x93ca,0x11d2,{0xaa,0x0d,0,0xe0,0x98,0x03,0x2b,0x8c}};
static void protocol(struct efi_boot *bs,const char *name,const efi_guid *guid)
{
    void *p=0;efi_status s=bs->locate_protocol(guid,0,&p);
    hex(name,s); /* Presence does not prove that the device works. */
}
static efi_status probe(efi_handle image,struct efi_system *st)
{
    if(!st || st->hdr.signature!=UINT64_C(0x5453595320494249) ||
        st->hdr.size<120 || !st->out || !st->out->string || !st->boot ||
        st->boot->hdr.signature!=UINT64_C(0x56524553544f4f42) ||
        st->boot->hdr.size<328)return EFI_ERROR|2;
    output=st->out;boot=st->boot;text("POLARIS EFI PROBE: read-only begin\r\n");
    hex("UEFI_REV=",st->hdr.revision);hex("FIRMWARE_REV=",st->revision);
    uint64_t v;
    __asm__ volatile("mrs %0, CurrentEL":"=r"(v));hex("CURRENT_EL=",v);
    __asm__ volatile("mrs %0, MIDR_EL1":"=r"(v));hex("MIDR=",v);
    __asm__ volatile("mrs %0, MPIDR_EL1":"=r"(v));hex("MPIDR=",v);
    __asm__ volatile("mrs %0, ID_AA64MMFR0_EL1":"=r"(v));hex("MMFR0=",v);
    struct efi_loaded *loaded=0;
    efi_status s=st->boot->handle_protocol(image,&loaded_guid,(void**)&loaded);
    hex("LOADED_IMAGE_STATUS=",s);
    if(!(s&EFI_ERROR) && loaded){hex("IMAGE_BASE=",(uintptr_t)loaded->base);hex("IMAGE_BYTES=",loaded->bytes);}
    protocol(st->boot,"GOP_STATUS=",&gop_guid);
    protocol(st->boot,"FS_STATUS=",&fs_guid);
    protocol(st->boot,"QCOM_USB_STATUS=",&usb_guid);
    uint64_t bytes=0,key=0,stride=0;uint32_t version=0;
    s=st->boot->get_map(&bytes,0,&key,&stride,&version);
    if(s!=EFI_TOO_SMALL || stride<sizeof(struct efi_memory) || stride>4096 ||
        bytes>1024*1024-8*stride){text("MAP_REFUSED\r\n");return EFI_ERROR|2;}
    bytes+=8*stride;uint64_t capacity=bytes;void *map=0;
    s=st->boot->allocate_pool(2,bytes,&map);
    if((s&EFI_ERROR)||!map){hex("ALLOC_FAILED=",s);return s?s:EFI_ERROR|9;}
    s=st->boot->get_map(&bytes,map,&key,&stride,&version);hex("MAP_STATUS=",s);
    struct polaris_efi_memory memory={0};
    int valid=!(s&EFI_ERROR) && polaris_efi_memory_check(map,bytes,capacity,stride,&memory);
#ifdef POLARIS_EFI_USB_DIAG
    if(valid && bytes<=sizeof(saved_map.data)){
        saved_map.magic=UINT64_C(0x3150414d49464550);saved_map.bytes=bytes;
        saved_map.stride=stride;saved_map.version=version;
        for(uint64_t i=0;i<bytes;i++)saved_map.data[i]=((uint8_t*)map)[i];
        saved_map_bytes=32+bytes;
    }
#endif
    hex("MAP_DESCRIPTORS=",memory.descriptors);
    hex("FREE_PAGES=",memory.conventional_pages);
    hex("POLARIS_UPPER_FREE_PAGES=",memory.upper_free_pages);
    hex("POLARIS_UPPER_LIVE_PAGES=",memory.upper_live_pages);
    hex("POLARIS_UPPER_UNMAPPED_PAGES=",UINT64_C(0xfc8a0)-memory.upper_mapped_pages);
    /* Exact retained ranges matter: the ABL loader currently hands all upper
     * RAM to XNU. Never assume ExitBootServices makes runtime/reserved RAM free.
     * Display these only after validating every descriptor and all bounds. */
    if(valid && POLARIS_EFI_HOLD){
        for(uint64_t at=0;at<bytes;at+=stride){
            const struct efi_memory *m=(const void*)((const uint8_t*)map+at);
            uint64_t end=m->physical+m->pages*4096;
            int reclaimable=((m->type>=1 && m->type<=4) || m->type==7) &&
                            !(m->attributes&UINT64_C(0x8000000000000000));
            if(end<=UINT64_C(0x180000000) || m->physical>=UINT64_C(0x27c8a0000) ||
               reclaimable)continue;
            hex("RETAIN_TYPE=",m->type);hex("RETAIN_BASE=",m->physical);
            hex("RETAIN_BYTES=",m->pages*4096);hex("RETAIN_ATTR=",m->attributes);
        }
    }
#ifdef POLARIS_EFI_APPS_WATCHDOG_READONLY
    if(valid)watchdog_inventory(map,bytes,capacity,stride,version);
#endif
#ifdef POLARIS_EFI_NATIVE_FAULT_WITNESS
    if(valid)witness_inventory(map,bytes,capacity,stride,version);
#endif
    st->boot->free_pool(map);
    if(!valid){text("MAP_REFUSED\r\n");return EFI_ERROR|2;}
    if(st->runtime && st->runtime->get_variable){
        static const uint16_t name[]={'B','o','o','t','O','r','d','e','r',0};
        uint16_t order[256];bytes=sizeof(order);uint32_t attributes=0;
        s=st->runtime->get_variable(name,&global_guid,&attributes,&bytes,order);
        hex("BOOT_ORDER_STATUS=",s);hex("BOOT_ORDER_BYTES=",bytes);
    }
    text("POLARIS EFI PROBE PASS: NO_DISK_WRITE NO_NVRAM_WRITE NO_XNU_JUMP\r\n");
    return 0;
}
static efi_status inspect(efi_handle image,struct efi_system *st)
{
    efi_status result=probe(image,st);
    if(POLARIS_EFI_HOLD){
        /* A RAM-only compatibility trial stops before an OS is started.
         * It cannot fall through to Windows, even when the probe rejects a map.
         * Hardware keys can exit the trial. */
        if(output){
            hex("PROBE_RESULT=",result);
            if(boot && boot->watchdog)hex("WATCHDOG_DISABLE=",boot->watchdog(0,0,0,0));
            text("POLARIS EFI HOLD: inventory only; no operating system started\r\n");
#ifdef POLARIS_EFI_USB_DIAG
            if(!result){
#ifdef POLARIS_EFI_PROBE_BOOTLOADER_RESET
                reset_system_table=st;
                struct polaris_usb_control control={.prepare_reset=probe_prepare_reset,.reset=probe_reset};
                hex("USB_DIAG_RESULT=",polaris_efi_usb_serve_control(st,ram_log,&ram_log_bytes,
                    (const uint8_t*)&saved_map,saved_map_bytes,hex,&control));
#else
                hex("USB_DIAG_RESULT=",polaris_efi_usb_serve(st,ram_log,&ram_log_bytes,
                    (const uint8_t*)&saved_map,saved_map_bytes,hex));
#endif
            }
#endif
        }
        for(;;){
            if(boot && boot->stall)boot->stall(1000000);
            else __asm__ volatile("wfe");
        }
    }
    return result;
}
#ifdef POLARIS_EFI_READY_TO_BOOT
static efi_handle driver_image;
static struct efi_system *driver_system;
static void ready(void *event,void *context)
{
    (void)event;(void)context;
    inspect(driver_image,driver_system);
}
efi_status EfiMain(efi_handle image,struct efi_system *st)
{
    static const efi_guid group={0x7ce88fb3,0x4bd7,0x4679,{0x87,0xa8,0xa8,0xd8,0xde,0xe5,0x0d,0x2b}};
    if(!st || st->hdr.signature!=UINT64_C(0x5453595320494249) || !st->boot ||
       st->boot->hdr.size<376 || !st->boot->create_event_ex){
        for(;;)__asm__ volatile("wfe");
    }
    driver_image=image;driver_system=st;void *event=0;
    efi_status s=st->boot->create_event_ex(0x200,8,ready,0,&group,&event);
    if(s&EFI_ERROR)inspect(image,st); /* Hold even if registration fails. */
    return s;
}
#else
efi_status EfiMain(efi_handle image,struct efi_system *st)
{
    return inspect(image,st);
}
#endif
