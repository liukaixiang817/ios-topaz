/* UEFI inventory: never exits Boot Services, writes storage/NVRAM or enters
 * XNU. Optional USB diagnostics expose only bounded RAM logs/map/GOP reads. */
#include "uefi-memory.h"
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
            if(!result)hex("USB_DIAG_RESULT=",polaris_efi_usb_serve(st,ram_log,&ram_log_bytes,
                (const uint8_t*)&saved_map,saved_map_bytes,hex));
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
