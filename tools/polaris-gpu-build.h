/* Exact overlay version admission; mirrored inside native overlay.c. */
#ifndef POLARIS_GPU_BUILD_H
#define POLARIS_GPU_BUILD_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
/* Exact host-verified20F66 overlay only. This does not admit arbitrary caches
 * or change any native GPU/storage/thermal ownership gate. */
static inline bool pgpu_build_matches(const void *version,size_t bytes,const void *sha)
{
    static const uint8_t f66_sha[32]={
        0xae,0xaf,0x8d,0x45,0xc6,0x86,0xe2,0x61,0x65,0x4a,0xe9,0xdc,0xcf,0xb1,0x15,0xc8,
        0x3d,0xc6,0x79,0x63,0x95,0x03,0x65,0x76,0x3d,0x2a,0xd9,0x47,0x40,0xcb,0xd5,0x8c};
    return version && sha &&
        ((bytes==7 && !__builtin_memcmp(version,"20H392",7)) ||
         (bytes==6 && !__builtin_memcmp(version,"20F66",6) && !__builtin_memcmp(sha,f66_sha,32)));
}
#endif
