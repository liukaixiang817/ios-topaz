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
        0xf7,0x90,0x51,0x25,0x48,0xbf,0xb9,0xd4,0x69,0x11,0x59,0x0b,0xed,0xf5,0xec,0x39,
        0x62,0xe9,0xc3,0xdc,0x56,0x6b,0x10,0xf2,0x19,0xd6,0x18,0x13,0x1a,0xe6,0x53,0x53};
    return version && sha &&
        ((bytes==7 && !__builtin_memcmp(version,"20H392",7)) ||
         (bytes==6 && !__builtin_memcmp(version,"20F66",6) && !__builtin_memcmp(sha,f66_sha,32)));
}
#endif
