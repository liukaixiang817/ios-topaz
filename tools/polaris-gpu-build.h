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
        0x4f,0xe2,0xb9,0x03,0xef,0xcd,0xfa,0xbd,0xdc,0x7b,0x84,0xc1,0x62,0x84,0xc4,0xab,
        0x4b,0x7c,0x5f,0xc8,0x51,0xb0,0x90,0xe5,0x31,0xb9,0x5c,0x57,0x65,0x8f,0xc7,0x70};
    return version && sha &&
        ((bytes==7 && !__builtin_memcmp(version,"20H392",7)) ||
         (bytes==6 && !__builtin_memcmp(version,"20F66",6) && !__builtin_memcmp(sha,f66_sha,32)));
}
#endif
