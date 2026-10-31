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
        0x39,0xdc,0xad,0xb8,0x23,0x55,0xbc,0xe9,0xd4,0xb1,0xb0,0xfd,0xa3,0x6b,0x73,0x36,
        0x7d,0x82,0x7e,0x5f,0x87,0x70,0x3f,0x93,0x86,0xd7,0x0b,0x62,0xc0,0x6b,0xec,0xdd};
    return version && sha &&
        ((bytes==7 && !__builtin_memcmp(version,"20H392",7)) ||
         (bytes==6 && !__builtin_memcmp(version,"20F66",6) && !__builtin_memcmp(sha,f66_sha,32)));
}
#endif
