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
        0xee,0x3f,0x92,0x7d,0xc1,0x75,0xf6,0xbe,0x31,0x84,0x34,0x4f,0x77,0x77,0x3b,0x6b,
        0xc1,0x6e,0xd9,0x86,0xe3,0x65,0x52,0x3f,0x67,0x3e,0x3c,0x3c,0xc7,0xbb,0x27,0x90};
    return version && sha &&
        ((bytes==7 && !__builtin_memcmp(version,"20H392",7)) ||
         (bytes==6 && !__builtin_memcmp(version,"20F66",6) && !__builtin_memcmp(sha,f66_sha,32)));
}
#endif
