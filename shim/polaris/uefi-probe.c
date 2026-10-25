/* Read-only UEFI inventory: returns to its caller, never exits Boot Services,
 * writes a filesystem/NVRAM, starts a USB driver or enters the XNU kernel. */
#include "uefi-memory.h"
static struct efi_output *output;
static void text(const char *s)
{
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
efi_status EfiMain(efi_handle image,struct efi_system *st)
{
    if(!st || st->hdr.signature!=UINT64_C(0x5453595320494249) ||
        st->hdr.size<120 || !st->out || !st->out->string || !st->boot ||
        st->boot->hdr.signature!=UINT64_C(0x56524553544f4f42) ||
        st->boot->hdr.size<328)return EFI_ERROR|2;
    output=st->out;text("POLARIS EFI PROBE: read-only begin\r\n");
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
    hex("MAP_DESCRIPTORS=",memory.descriptors);
    hex("FREE_PAGES=",memory.conventional_pages);
    hex("POLARIS_UPPER_FREE_PAGES=",memory.upper_free_pages);
    hex("POLARIS_UPPER_LIVE_PAGES=",memory.upper_live_pages);
    hex("POLARIS_UPPER_UNMAPPED_PAGES=",UINT64_C(0xfc8a0)-memory.upper_mapped_pages);
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
