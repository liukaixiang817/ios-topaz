/* Validate a firmware map before inventorying it; no memory is reclaimed. */
#ifndef POLARIS_UEFI_MEMORY_H
#define POLARIS_UEFI_MEMORY_H
#include "uefi.h"
struct polaris_efi_memory {
    uint64_t descriptors,conventional_pages,upper_free_pages,upper_live_pages,upper_mapped_pages;
};
static inline int polaris_efi_memory_check(const void *map,uint64_t bytes,
    uint64_t capacity,uint64_t stride,struct polaris_efi_memory *out)
{
    if(!map || ((uintptr_t)map&7) || !out || !bytes || bytes>capacity ||
        stride<sizeof(struct efi_memory) || stride>4096 || (stride&7) ||
        bytes%stride || bytes/stride>4096)return 0;
    struct polaris_efi_memory result={0};result.descriptors=bytes/stride;
    for(uint64_t at=0;at<bytes;at+=stride){
        const struct efi_memory *m=(const void*)((const uint8_t*)map+at);
        if((m->physical&4095) || !m->pages || m->pages>(UINT64_MAX-m->physical)/4096)return 0;
        uint64_t end=m->physical+m->pages*4096;
        for(uint64_t prev=0;prev<at;prev+=stride){
            const struct efi_memory *p=(const void*)((const uint8_t*)map+prev);
            if(m->physical<p->physical+p->pages*4096 && p->physical<end)return 0;
        }
        if(m->type==7)result.conventional_pages+=m->pages;
        uint64_t lo=m->physical>UINT64_C(0x180000000)?m->physical:UINT64_C(0x180000000);
        uint64_t hi=end<UINT64_C(0x27c8a0000)?end:UINT64_C(0x27c8a0000);
        if(hi>lo){
            uint64_t pages=(hi-lo)/4096;result.upper_mapped_pages+=pages;
            if(m->type==7)result.upper_free_pages+=pages;
            /* Only loader/boot-services allocations become reclaimable on
             * ExitBootServices. Runtime/reserved/MMIO are not ours to use. */
            if(m->type<1 || m->type>4)if(m->type!=7)result.upper_live_pages+=pages;
        }
    }
    *out=result;return 1;
}
#endif
