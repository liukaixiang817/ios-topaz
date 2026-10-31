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
        0x67,0x6c,0x8c,0x20,0x8f,0x5e,0x75,0x6c,0x0e,0xd5,0x51,0x1c,0xbd,0xc9,0xab,0x25,
        0xad,0xd4,0x02,0x51,0xce,0x35,0x75,0xed,0x72,0xbc,0x89,0x48,0x5f,0x85,0x8d,0x53};
    return version && sha &&
        ((bytes==7 && !__builtin_memcmp(version,"20H392",7)) ||
         (bytes==6 && !__builtin_memcmp(version,"20F66",6) && !__builtin_memcmp(sha,f66_sha,32)));
}
#endif
