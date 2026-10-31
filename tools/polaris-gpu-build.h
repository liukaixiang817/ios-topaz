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
        0xba,0x69,0xc1,0x6b,0x28,0x52,0x41,0x07,0xf2,0x8e,0x63,0xb0,0x94,0xfa,0xee,0xd6,
        0xc2,0x00,0x93,0x91,0xea,0xa7,0xd0,0x4a,0xe4,0x49,0x33,0xd1,0xf1,0x67,0x53,0x69};
    return version && sha &&
        ((bytes==7 && !__builtin_memcmp(version,"20H392",7)) ||
         (bytes==6 && !__builtin_memcmp(version,"20F66",6) && !__builtin_memcmp(sha,f66_sha,32)));
}
#endif
