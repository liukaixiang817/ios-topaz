/* Fixed, bounded, media-owned diagnostics; no commands or user strings. */
#ifndef POLARIS_MEDIA_STATUS_H
#define POLARIS_MEDIA_STATUS_H
#include <stdint.h>
#define PMD_CALL 0x504d4401
#define PMD_MAGIC 0x504d4431u
#define PMD_LIMIT 160u
#define PMD_THREADS 64u
#define PMD_PCS 8u
enum { PMD_ENTRY=1, PMD_IMAGE=2, PMD_IDENTITY=3, PMD_INSTALLED=4,
       PMD_CALLED=5, PMD_SNAPSHOT=6, PMD_THREAD=7, PMD_SAMPLER=8 };
struct polaris_media_notice {
    uint32_t magic,bytes,kind;
    int32_t status;
    uint32_t index,detail;
    uint64_t pc[PMD_PCS];
};
_Static_assert(sizeof(struct polaris_media_notice)==88,"media notice ABI");
#endif
