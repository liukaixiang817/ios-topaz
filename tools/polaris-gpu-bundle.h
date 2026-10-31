/* Fixed-path, bounded RAM-only userland overlay wire parser. */
#ifndef POLARIS_GPU_BUNDLE_H
#define POLARIS_GPU_BUNDLE_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#define PGPU_FILES 6u
#define PGPU_HEADER (16u + 48u * PGPU_FILES)
#define PGPU_MAX (32u << 20)
/* Exact host-verified20F66 overlay only. This does not admit arbitrary caches
 * or change any native GPU/storage/thermal ownership gate. */
static inline bool pgpu_build_matches(const void *version,size_t bytes,const void *sha)
{
    static const uint8_t f66_sha[32]={
        0xfa,0x61,0x50,0x96,0x03,0x47,0x8b,0xbe,0x94,0x2c,0xf1,0x13,0x62,0x62,0x75,0x63,
        0x92,0x67,0xb2,0xc3,0xdd,0x4f,0x3b,0x24,0x0f,0xb0,0xac,0xae,0x1c,0x6b,0xc5,0xf9};
    return version && sha &&
        ((bytes==7 && !__builtin_memcmp(version,"20H392",7)) ||
         (bytes==6 && !__builtin_memcmp(version,"20F66",6) && !__builtin_memcmp(sha,f66_sha,32)));
}
struct pgpu_file {const uint8_t *data,*sha;uint32_t bytes,kind;};
static inline uint32_t pgpu_u32(const uint8_t *p)
{return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static inline uint64_t pgpu_u64(const uint8_t *p)
{return pgpu_u32(p)|(uint64_t)pgpu_u32(p+4)<<32;}
static inline bool pgpu_parse(const void *data,size_t size,struct pgpu_file out[PGPU_FILES],
    bool (*digest)(const void *,size_t,const uint8_t *))
{
    const uint8_t *p=data;
    if(!p || !out || !digest || size<PGPU_HEADER || size>PGPU_MAX ||
        __builtin_memcmp(p,"PGPU0047",8) || pgpu_u32(p+8)!=PGPU_FILES || pgpu_u32(p+12)!=size) return false;
    uint64_t end=PGPU_HEADER;
    struct pgpu_file files[PGPU_FILES];
    for(unsigned n=0;n<PGPU_FILES;n++) {
        const uint8_t *r=p+16+n*48;
        uint32_t kind=pgpu_u32(r),bytes=pgpu_u32(r+4);uint64_t offset=pgpu_u64(r+8);
        if(kind!=n || !bytes || bytes>(24u<<20) || offset!=((end+15)&~UINT64_C(15)) ||
            offset>size || bytes>size-offset || !digest(p+offset,bytes,r+16)) return false;
        files[n]=(struct pgpu_file){p+offset,r+16,bytes,kind};end=offset+bytes;
    }
    if(end!=size) return false;
    __builtin_memcpy(out,files,sizeof(files));return true;
}
#endif
