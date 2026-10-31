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
        0x70,0x06,0x6c,0x1b,0xb9,0xe5,0x46,0x3d,0x2c,0xcb,0x7a,0x27,0xef,0x09,0x69,0x63,
        0x3e,0xdf,0x5c,0x9f,0xc5,0x25,0x39,0x8e,0xaf,0x8f,0x25,0xeb,0x87,0x67,0x93,0x3a};
    return version && sha &&
        ((bytes==7 && !__builtin_memcmp(version,"20H392",7)) ||
         (bytes==6 && !__builtin_memcmp(version,"20F66",6) && !__builtin_memcmp(sha,f66_sha,32)));
}
#endif
