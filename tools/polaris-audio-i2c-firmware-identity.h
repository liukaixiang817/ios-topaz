/* Scalar SHA256 and exact relocated immutable-PE identity for the original
 * Polaris original I2CDxe. Binding contains hashes/ranges/relocation RVAs only; no
 * proprietary firmware bytes. Does not call or follow any firmware function. */
#ifndef POLARIS_AUDIO_I2C_FIRMWARE_IDENTITY_H
#define POLARIS_AUDIO_I2C_FIRMWARE_IDENTITY_H
#include <stdint.h>
#include <stddef.h>
struct paii_range {uint32_t rva,bytes;uint8_t sha256[32];};
#include "uefi-audio-i2c-cache-binding.h"
struct paii_sha256 {uint32_t h[8];uint64_t bytes;uint8_t block[64];unsigned used;};
static inline uint32_t paii_ror(uint32_t x,unsigned n){return(x>>n)|(x<<(32-n));}
static inline void paii_transform(struct paii_sha256 *s,const uint8_t *p)
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
    for(unsigned i=16;i<64;i++){
        uint32_t a=w[i-15],b=w[i-2];
        w[i]=w[i-16]+(paii_ror(a,7)^paii_ror(a,18)^(a>>3))+w[i-7]+(paii_ror(b,17)^paii_ror(b,19)^(b>>10));
    }
    uint32_t a=s->h[0],b=s->h[1],c=s->h[2],d=s->h[3],e=s->h[4],f=s->h[5],g=s->h[6],h=s->h[7];
    for(unsigned i=0;i<64;i++){
        uint32_t t=h+(paii_ror(e,6)^paii_ror(e,11)^paii_ror(e,25))+((e&f)^(~e&g))+k[i]+w[i];
        uint32_t u=(paii_ror(a,2)^paii_ror(a,13)^paii_ror(a,22))+((a&b)^(a&c)^(b&c));
        h=g;g=f;f=e;e=d+t;d=c;c=b;b=a;a=t+u;
    }
    s->h[0]+=a;s->h[1]+=b;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;
}
static inline void paii_init(struct paii_sha256 *s)
{
    static const uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    for(unsigned i=0;i<8;i++)s->h[i]=h[i];s->bytes=0;s->used=0;
}
static inline void paii_byte(struct paii_sha256 *s,uint8_t b)
{s->block[s->used++]=b;s->bytes++;if(s->used==64){paii_transform(s,s->block);s->used=0;}}
static inline void paii_final(struct paii_sha256 *s,uint8_t out[32])
{
    uint64_t bits=s->bytes*8;paii_byte(s,0x80);
    while(s->used!=56)paii_byte(s,0);
    for(unsigned i=0;i<8;i++)paii_byte(s,(uint8_t)(bits>>(56-8*i)));
    for(unsigned i=0;i<32;i++)out[i]=(uint8_t)(s->h[i/4]>>(24-8*(i%4)));
}
static inline uint64_t paii_le(const uint8_t *p,unsigned n)
{uint64_t x=0;for(unsigned i=0;i<n;i++)x|=(uint64_t)p[i]<<(8*i);return x;}
/* Caller has validated the ENTIRE image as current owned identity-mapped RAM.
 * Hashes all immutable bytes, canonicalizing original DIR64 slots and the PE
 * ImageBase field. Mutable I2C/DAL context globals are sampled separately. The context head is never followed.
 * No value read here is ever followed as a pointer. */
static inline int paii_verify(const uint8_t *image,uint64_t image_base,uint64_t bytes,
    uint8_t raw_hash[PAII_RANGE_COUNT][32],unsigned *failed_range,unsigned *computed)
{
    if(!image||!failed_range||!computed||bytes!=PAII_IMAGE_BYTES||image_base>UINT64_MAX-bytes)return 0;
    *failed_range=0;*computed=0;
    uint64_t header_base=paii_le(image+PAII_IMAGEBASE_RVA,8);
    if(header_base!=PAII_ORIGINAL_BASE&&header_base!=image_base)return 0;
    uint64_t delta=image_base-PAII_ORIGINAL_BASE;
    for(unsigned r=0;r<PAII_RANGE_COUNT;r++){
        const struct paii_range *span=&paii_ranges[r];struct paii_sha256 s;paii_init(&s);
        if(span->rva>bytes||span->bytes>bytes-span->rva)return 0;
        unsigned next=0;while(next<PAII_RELOC_COUNT&&paii_relocations[next]+8<=span->rva)next++;
        for(uint32_t i=span->rva;i<span->rva+span->bytes;i++){
            while(next<PAII_RELOC_COUNT&&paii_relocations[next]+8<=i)next++;
            uint8_t v=image[i];
            if(PAII_IMAGEBASE_RVA<=i&&i<PAII_IMAGEBASE_RVA+8)v=(uint8_t)(PAII_ORIGINAL_BASE>>(8*(i-PAII_IMAGEBASE_RVA)));
            else if(next<PAII_RELOC_COUNT&&paii_relocations[next]<=i&&i<paii_relocations[next]+8){
                uint64_t original=paii_le(image+paii_relocations[next],8)-delta;
                v=(uint8_t)(original>>(8*(i-paii_relocations[next])));
            }
            paii_byte(&s,v);
        }
        paii_final(&s,raw_hash[r]);*computed=r+1;unsigned different=0;
        for(unsigned i=0;i<32;i++)different|=raw_hash[r][i]^span->sha256[i];
        if(different){*failed_range=r+1;return 0;}
    }
    return 1;
}
#endif
