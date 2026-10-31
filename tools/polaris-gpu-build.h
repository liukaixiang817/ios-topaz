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
        0xfa,0x61,0x50,0x96,0x03,0x47,0x8b,0xbe,0x94,0x2c,0xf1,0x13,0x62,0x62,0x75,0x63,
        0x92,0x67,0xb2,0xc3,0xdd,0x4f,0x3b,0x24,0x0f,0xb0,0xac,0xae,0x1c,0x6b,0xc5,0xf9};
    return version && sha &&
        ((bytes==7 && !__builtin_memcmp(version,"20H392",7)) ||
         (bytes==6 && !__builtin_memcmp(version,"20F66",6) && !__builtin_memcmp(sha,f66_sha,32)));
}
#endif
