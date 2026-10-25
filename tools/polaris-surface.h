/* iOS20H392 IOSurface wrapper/bulk ABI, checked against the phone's cache.
 * No device access. Pixel descriptors start at byte ZERO, not MiniIOSurface's
 * header-page offset. Unknown/short/overflowing inputs never become success.
 */
#ifndef POLARIS_SURFACE_H
#define POLARIS_SURFACE_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#define PGPU_SURFACE_MAX_BYTES (256u << 20)
struct pgpu_surface_image {
    uint64_t address;
    uint32_t width,height,format,element,row,bytes;
};
static inline int pgpu_surface_range(uint64_t address,uint64_t bytes)
{return address && bytes && bytes<=PGPU_SURFACE_MAX_BYTES && address<=UINT64_MAX-bytes;}
static inline int pgpu_surface_image_valid(const struct pgpu_surface_image *p)
{
    return p && pgpu_surface_range(p->address,p->bytes) &&
        p->width && p->height && p->width<=16384 && p->height<=16384 &&
        p->element && p->element<=16 &&
        (uint64_t)p->width*p->element<=p->row &&
        (uint64_t)p->row*(p->height-1)+(uint64_t)p->width*p->element<=p->bytes;
}
/* Returns no partial update for an invalid field mask or short payload. */
static inline int pgpu_surface_bulk_apply(uint8_t *out,const uint8_t *in,uint64_t size,uint64_t mask)
{
    static const uint8_t span[15][2]={
        {0,0x20},{0x20,0x30},{0x30,0x38},{0x38,0x39},{0x39,0x3a},
        {0x3a,0x3b},{0x3b,0x3c},{0x3c,0x3d},{0x3d,0x3e},{0x3e,0x3f},
        {0x3f,0x40},{0x40,0x58},{0x58,0x5c},{0x5c,0x64},{0x64,0x65}};
    if(!out || !in || size>0x70 || (mask&~UINT64_C(0x7fff)))return 0;
    for(unsigned i=0;i<15;i++)if((mask&(UINT64_C(1)<<i)) && span[i][1]>size)return 0;
    for(unsigned i=0;i<15;i++)if(mask&(UINT64_C(1)<<i))
        memcpy(out+span[i][0],in+span[i][0],span[i][1]-span[i][0]);
    return 1;
}
#endif
