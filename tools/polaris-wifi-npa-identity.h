/* Reuse the existing GCD/Smem scalar SHA implementation. This header is only
 * part of the explicit combined original-firmware scope, never a new SHA copy. */
#ifndef POLARIS_WIFI_NPA_IDENTITY_H
#define POLARIS_WIFI_NPA_IDENTITY_H
#include "polaris-wifi-firmware-identity.h"
struct pwnpi_span { uint32_t rva,bytes; uint8_t hash[32]; };
#include "uefi-wifi-npa-binding.h"
static inline int pwnpi_verify(const uint8_t *image,uint64_t base,
    uint8_t hashes[PWNPI_RANGE_COUNT][32],unsigned *computed,unsigned *failed)
{
    *computed=*failed=0;
    uint64_t image_base=pwfi_le(image+PWNPI_IMAGEBASE_RVA,8);
    if(image_base && image_base!=base) return 0;
    for(unsigned s=0;s<PWNPI_RANGE_COUNT;s++) {
        const struct pwnpi_span *span=&pwnpi_spans[s]; struct pwfi_sha256 h; pwfi_init(&h);
        unsigned r=0;
        for(uint32_t i=span->rva;i<span->rva+span->bytes;i++) {
            while(r<PWNPI_RELOC_COUNT && pwnpi_relocs[r]+8<=i) r++;
            uint8_t b=image[i];
            if(PWNPI_IMAGEBASE_RVA<=i && i<PWNPI_IMAGEBASE_RVA+8) b=0;
            else if(r<PWNPI_RELOC_COUNT && pwnpi_relocs[r]<=i && i<pwnpi_relocs[r]+8)
                b=(uint8_t)((pwfi_le(image+pwnpi_relocs[r],8)-base)>>(8*(i-pwnpi_relocs[r])));
            pwfi_byte(&h,b);
        }
        pwfi_final(&h,hashes[s]); *computed=s+1;
        if(!pgcd_equal(hashes[s],span->hash,32)) { *failed=s+1; return 0; }
    }
    return 1;
}
#endif
