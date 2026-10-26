#ifndef POLARIS_EFI_BOOT_OPTIONS_H
#define POLARIS_EFI_BOOT_OPTIONS_H
#include "uefi.h"
/* Read only, before XNU owns devices. No caller-selected variable names.
 * Wire format:32B header, then32B record headers and8B-padded variable data.
 * IDs10000/10001/10002 are BootOrder/BootCurrent/BootNext; others Boot####. */
struct polaris_efi_boot_options {uint64_t used;uint8_t data[65536];};
static inline void polaris_bv_u32(uint8_t *p,uint32_t v)
{for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(v>>(i*8));}
static inline void polaris_bv_u64(uint8_t *p,uint64_t v)
{for(unsigned i=0;i<8;i++)p[i]=(uint8_t)(v>>(i*8));}
static inline int polaris_bv_read(struct efi_runtime *rt,struct polaris_efi_boot_options *b,
                                uint32_t id,uint32_t *records,uint64_t *length)
{
    static const efi_guid global={0x8be4df61,0x93ca,0x11d2,{0xaa,0x0d,0x00,0xe0,0x98,0x03,0x2b,0x8c}};
    static const uint16_t order[]={'B','o','o','t','O','r','d','e','r',0};
    static const uint16_t current[]={'B','o','o','t','C','u','r','r','e','n','t',0};
    static const uint16_t next[]={'B','o','o','t','N','e','x','t',0};
    uint16_t number[]={'B','o','o','t',0,0,0,0,0};const uint16_t *name=number;
    if(id==0x10000)name=order;else if(id==0x10001)name=current;else if(id==0x10002)name=next;
    else for(unsigned i=0;i<4;i++)number[4+i]="0123456789ABCDEF"[(id>>(12-4*i))&15];
    *length=0;if(b->used>sizeof(b->data)-32)return 0;
    uint8_t *p=b->data+b->used;uint64_t available=sizeof(b->data)-b->used-32;
    if(available>4096)available=4096;uint64_t size=available;uint32_t attrs=0;
    efi_status s=rt->get_variable(name,&global,&attrs,&size,p+32);
    uint64_t bytes=s?0:size;
    if(bytes>available)return 0;
    polaris_bv_u32(p,id);polaris_bv_u32(p+4,attrs);polaris_bv_u64(p+8,s);
    polaris_bv_u64(p+16,bytes);polaris_bv_u64(p+24,size);
    uint64_t padded=(bytes+7)&~UINT64_C(7);
    for(uint64_t i=bytes;i<padded;i++)p[32+i]=0;
    b->used+=32+padded;++*records;*length=bytes;
    return s==0||s==(EFI_ERROR|14);
}
static inline int polaris_efi_boot_options_capture(struct efi_runtime *rt,struct polaris_efi_boot_options *b)
{
    if(!rt||!rt->get_variable||!b)return 0;
    for(unsigned i=0;i<32;i++)b->data[i]=0;
    static const uint8_t magic[]={'P','E','F','I','B','V','0','1'};
    for(unsigned i=0;i<8;i++)b->data[i]=magic[i];b->used=32;
    uint32_t records=0;uint64_t length=0;uint16_t ids[64];unsigned count=0;
    int complete=polaris_bv_read(rt,b,0x10000,&records,&length);
    if(!length||length%2||length>128)complete=0;
    else for(unsigned i=0;i<length/2;i++){
        uint16_t id=(uint16_t)(b->data[64+2*i]|(uint16_t)b->data[65+2*i]<<8);
        unsigned j=0;while(j<count&&ids[j]!=id)j++;if(j==count)ids[count++]=id;
    }
    if(!polaris_bv_read(rt,b,0x10001,&records,&length))complete=0;
    if(!polaris_bv_read(rt,b,0x10002,&records,&length))complete=0;
    for(unsigned i=0;i<count;i++)if(!polaris_bv_read(rt,b,ids[i],&records,&length))complete=0;
    polaris_bv_u32(b->data+8,1);polaris_bv_u32(b->data+12,records);
    polaris_bv_u64(b->data+16,b->used);polaris_bv_u64(b->data+24,(uint64_t)complete);
    return complete;
}
#endif
