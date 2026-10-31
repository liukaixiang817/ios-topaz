/* RAM-only discard bookkeeping. The whole object, request scratch and zero
 * bitmap live INSIDE the original fixed COW arena. No disk or DMA handle.
 * The existing COW group table supplies next links for reusable RAM chunks. */
#ifndef POLARIS_RAM_DISCARD_H
#define POLARIS_RAM_DISCARD_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#define POLARIS_TRIM_MAGIC UINT64_C(0x504352414d545231)
#define POLARIS_TRIM_MAX_EXTENTS 1024u
#define POLARIS_TRIM_BLOCK 4096u
#define POLARIS_TRIM_GRANULE 16384u
struct polaris_ram_trim_extent { uint64_t offset, length; };
struct polaris_ram_discard {
    uint64_t magic,nblocks,bitmap_bytes;
    uint32_t free_head,reusable;
    uint64_t calls,trimmed_blocks,recycled_groups,reused_groups,zero_blocks;
    uint32_t peak_stage,event_count;
    uint8_t first_full,first_reclaim;
    struct polaris_ram_trim_extent request[POLARIS_TRIM_MAX_EXTENTS];
    uint8_t visited[32768u/8u]; /* Scratch only; original group-table maximum. */
    uint8_t zeroes[];
};
static inline bool polaris_discard_reserve_bytes(uint64_t blocks,size_t *out)
{
    if(!out||!blocks||blocks>(UINT64_C(64)<<18))return false;
    uint64_t n=sizeof(struct polaris_ram_discard)+(blocks+7)/8;
    if(n>SIZE_MAX-(POLARIS_TRIM_GRANULE-1))return false;
    *out=((size_t)n+POLARIS_TRIM_GRANULE-1)&~((size_t)POLARIS_TRIM_GRANULE-1);
    return true;
}
static inline bool polaris_discard_valid(const struct polaris_ram_discard *d,uint64_t blocks)
{
    return d&&blocks&&blocks<=(UINT64_C(64)<<18)&&d->magic==POLARIS_TRIM_MAGIC&&
        d->nblocks==blocks&&d->bitmap_bytes==(blocks+7)/8&&d->zero_blocks<=blocks;
}
static inline bool polaris_discard_zero(const struct polaris_ram_discard *d,uint64_t block)
{
    return d&&block<d->nblocks&&(d->zeroes[block/8]&(1u<<(block%8)));
}
static inline void polaris_discard_clear(struct polaris_ram_discard *d,uint64_t block)
{
    if(d&&polaris_discard_zero(d,block)){d->zeroes[block/8]&=(uint8_t)~(1u<<(block%8));d->zero_blocks--;}
}
/* Validate ALL ranges, alignment and aggregate bounded work before touching
 * a single tombstone. No rounding, partial success or outside-root extent.
 * Overlap is rejected, rather than multiplied into unbounded repeated work. */
static inline bool polaris_discard_extents_valid(const struct polaris_ram_discard *d,
    uint64_t blocks,unsigned count,const struct polaris_ram_trim_extent *extents)
{
    if(!polaris_discard_valid(d,blocks)||!extents||!count||count>POLARIS_TRIM_MAX_EXTENTS)return false;
    uint64_t end=0,total=0,bytes=blocks*POLARIS_TRIM_BLOCK;
    for(unsigned i=0;i<count;i++) {
        uint64_t at=extents[i].offset,n=extents[i].length;
        if(!n||((at|n)&(POLARIS_TRIM_BLOCK-1))||at>=bytes||n>bytes-at||
           (i&&at<end)||n>bytes-total)return false;
        end=at+n;total+=n;
    }
    return true;
}
#endif
