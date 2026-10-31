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
        0xbf,0x8a,0x70,0x44,0x11,0xfa,0xe0,0x1a,0xbe,0xb2,0x35,0x78,0xb1,0x9f,0x0c,0x6c,
        0x17,0x38,0xf9,0x0c,0xed,0xae,0xed,0xb7,0xb3,0x94,0x93,0x01,0x87,0x06,0x9b,0x70};
    return version && sha &&
        ((bytes==7 && !__builtin_memcmp(version,"20H392",7)) ||
         (bytes==6 && !__builtin_memcmp(version,"20F66",6) && !__builtin_memcmp(sha,f66_sha,32)));
}
#endif
