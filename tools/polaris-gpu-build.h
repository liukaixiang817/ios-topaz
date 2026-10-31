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
        0x6a,0xb8,0xe2,0x60,0x39,0x82,0x40,0x73,0x35,0x61,0x56,0x92,0x3b,0xe7,0xcc,0xa2,
        0x67,0x71,0x33,0x59,0xf9,0x0a,0x3b,0xd3,0xad,0x63,0x48,0x86,0x47,0x77,0x1b,0x3b};
    return version && sha &&
        ((bytes==7 && !__builtin_memcmp(version,"20H392",7)) ||
         (bytes==6 && !__builtin_memcmp(version,"20F66",6) && !__builtin_memcmp(sha,f66_sha,32)));
}
#endif
