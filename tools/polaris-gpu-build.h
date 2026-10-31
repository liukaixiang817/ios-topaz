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
        0x9c,0x14,0x70,0x00,0xbb,0xf5,0xad,0xb3,0xad,0x72,0xe6,0x37,0xd2,0x39,0x3d,0x66,
        0x3c,0x9c,0xce,0xd0,0x00,0x5b,0x9b,0x3d,0x87,0x6e,0xc7,0x5a,0xc9,0x6b,0xdc,0x78};
    return version && sha &&
        ((bytes==7 && !__builtin_memcmp(version,"20H392",7)) ||
         (bytes==6 && !__builtin_memcmp(version,"20F66",6) && !__builtin_memcmp(sha,f66_sha,32)));
}
#endif
