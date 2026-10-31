#ifndef PGCD_CORE_IDENTITY_H
#define PGCD_CORE_IDENTITY_H
/* Source-owned scalar SHA from original Smem identity; no firmware functions. */
#include "uefi-wifi-cache-readonly.h"
struct pgci_range {uint32_t rva,bytes;uint8_t sha256[32];};
#include "uefi-gcd-core-binding.h"
static inline int pgci_verify(const uint8_t *image,uint64_t image_base,uint64_t bytes,
    uint8_t raw_hash[PGCI_RANGE_COUNT][32],unsigned *failed_range,unsigned *computed)
{
    if(!image||!failed_range||!computed||bytes!=PGCI_IMAGE_BYTES||image_base>UINT64_MAX-bytes)return 0;
    *failed_range=0;*computed=0;
    uint64_t header_base=pwfi_le(image+PGCI_IMAGEBASE_RVA,8);
    if(header_base!=PGCI_ORIGINAL_BASE&&header_base!=image_base)return 0;
    uint64_t delta=image_base-PGCI_ORIGINAL_BASE;
    for(unsigned r=0;r<PGCI_RANGE_COUNT;r++){
        const struct pgci_range *span=&pgci_ranges[r];struct pwfi_sha256 s;pwfi_init(&s);
        if(span->rva>bytes||span->bytes>bytes-span->rva)return 0;
        unsigned next=0;while(next<PGCI_RELOC_COUNT&&pgci_relocations[next]+8<=span->rva)next++;
        for(uint32_t i=span->rva;i<span->rva+span->bytes;i++){
            while(next<PGCI_RELOC_COUNT&&pgci_relocations[next]+8<=i)next++;
            uint8_t v=image[i];
            if(i>=0x1bb28u&&i<0x1bb2cu){pwfi_byte(&s,0);continue;}
            if(PGCI_IMAGEBASE_RVA<=i&&i<PGCI_IMAGEBASE_RVA+8)v=(uint8_t)(PGCI_ORIGINAL_BASE>>(8*(i-PGCI_IMAGEBASE_RVA)));
            else if(next<PGCI_RELOC_COUNT&&pgci_relocations[next]<=i&&i<pgci_relocations[next]+8){
                uint64_t original=pwfi_le(image+pgci_relocations[next],8)-delta;
                v=(uint8_t)(original>>(8*(i-pgci_relocations[next])));
            }
            pwfi_byte(&s,v);
        }
        pwfi_final(&s,raw_hash[r]);*computed=r+1;unsigned different=0;
        for(unsigned i=0;i<32;i++)different|=raw_hash[r][i]^span->sha256[i];
        if(different){*failed_range=r+1;return 0;}
    }
    return 1;
}
#endif
