#ifndef PGCD_CORE_IDENTITY_H
#define PGCD_CORE_IDENTITY_H
/* Source-owned scalar SHA from original Smem identity; no firmware functions. */
#include "uefi-wifi-cache-readonly.h"
struct pgci_range {uint32_t rva,bytes;uint8_t sha256[32];};
#include "uefi-gcd-core-binding.h"
/* Same scalar SHA256 compression, compile-time unrolled fixed loops.
 * No ISA extensions, FP state, cached digest or omitted source byte. */
static inline void pgci_transform_blocks(struct pwfi_sha256 *s,const uint8_t *p)
{
    static const uint32_t k[64]={
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t w[64];
    for(unsigned i=0;i<16;i++)w[i]=(uint32_t)p[4*i]<<24|(uint32_t)p[4*i+1]<<16|(uint32_t)p[4*i+2]<<8|p[4*i+3];
    #pragma clang loop unroll(full)
    for(unsigned i=16;i<64;i++){
        uint32_t a=w[i-15],b=w[i-2];
        w[i]=w[i-16]+(pwfi_ror(a,7)^pwfi_ror(a,18)^(a>>3))+w[i-7]+(pwfi_ror(b,17)^pwfi_ror(b,19)^(b>>10));
    }
    uint32_t a=s->h[0],b=s->h[1],c=s->h[2],d=s->h[3],e=s->h[4],f=s->h[5],g=s->h[6],h=s->h[7];
    #pragma clang loop unroll(full)
    for(unsigned i=0;i<64;i++){
        uint32_t t=h+(pwfi_ror(e,6)^pwfi_ror(e,11)^pwfi_ror(e,25))+((e&f)^(~e&g))+k[i]+w[i];
        uint32_t u=(pwfi_ror(a,2)^pwfi_ror(a,13)^pwfi_ror(a,22))+((a&b)^(a&c)^(b&c));
        h=g;g=f;f=e;e=d+t;d=c;c=b;b=a;a=t+u;
    }
    s->h[0]+=a;s->h[1]+=b;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;
}
/* Canonicalize only bytes inside this exact chunk. Relocations may cross a
 * chunk edge; no byte outside the original hash span is added to the digest.
 * Byte ImageBase and DS CRC priority stays identical to the old scalar path. */
static inline void pgci_patch_chunk(uint8_t out[64],uint32_t first,uint32_t bytes,
    uint32_t field,unsigned width,uint64_t value)
{
    uint32_t end=first+bytes,lo=field>first?field:first,hi=field+width<end?field+width:end;
    for(uint32_t at=lo;at<hi;at++)out[at-first]=(uint8_t)(value>>(8*(at-field)));
}
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
        for(uint32_t first=span->rva;first<span->rva+span->bytes;){
            uint8_t chunk[64];uint32_t take=span->rva+span->bytes-first;if(take>64)take=64;
            for(unsigned k=0;k<take;k++)chunk[k]=image[first+k];
            while(next<PGCI_RELOC_COUNT&&pgci_relocations[next]+8<=first)next++;
            for(unsigned slot=next;slot<PGCI_RELOC_COUNT&&pgci_relocations[slot]<first+take;slot++){
                uint32_t at=pgci_relocations[slot];uint64_t original=pwfi_le(image+at,8)-delta;
                pgci_patch_chunk(chunk,first,take,at,8,original);
            }
            pgci_patch_chunk(chunk,first,take,PGCI_IMAGEBASE_RVA,8,PGCI_ORIGINAL_BASE);
            pgci_patch_chunk(chunk,first,take,0x1bb28u,4,0);
            /* Same scalar SHA compression and length/padding. Full blocks
             * avoid per-byte counter/buffer/branch work; no SIMD/FP/crypto ISA,
             * digest caching, skipped bytes or fewer source checkpoints. */
            if(take==64){pgci_transform_blocks(&s,chunk);s.bytes+=64;}
            else for(unsigned k=0;k<take;k++)pwfi_byte(&s,chunk[k]);
            first+=take;
        }
        pwfi_final(&s,raw_hash[r]);*computed=r+1;unsigned different=0;
        for(unsigned i=0;i<32;i++)different|=raw_hash[r][i]^span->sha256[i];
        if(different){*failed_range=r+1;return 0;}
    }
    return 1;
}
#endif
