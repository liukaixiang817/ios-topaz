/* Volatile 4KiB block overlay. Caller serializes access and supplies ONLY a
 * RAM allocator. No block-device handle, SCSI command or disk write exists here.
 * Allocations are 16KiB groups; valid bits expose only fully copied blocks.
 */
#ifndef POLARIS_RAM_COW_H
#define POLARIS_RAM_COW_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#define POLARIS_COW_GROUPS 32768u /* maximum512MiB; caller selects a lower budget */
#define POLARIS_COW_BUCKETS 1024u
#define POLARIS_COW_BLOCK 4096u
#define POLARIS_COW_BYTES 16384u
struct polaris_cow_group {
    uint64_t number;
    uint8_t *data;
    uint32_t next;
    uint8_t valid;
};
struct polaris_cow {
    uint64_t nblocks;
    unsigned limit, used;
    uint64_t dirty_blocks, written_blocks;
    uint32_t buckets[POLARIS_COW_BUCKETS]; /* index+1; zero means absent */
    struct polaris_cow_group groups[POLARIS_COW_GROUPS];
};
typedef void *(*polaris_cow_alloc)(size_t bytes, void *context);

static inline struct polaris_cow_group *
polaris_cow_find(struct polaris_cow *c, uint64_t number)
{
    for (uint32_t i = c->buckets[number % POLARIS_COW_BUCKETS]; i;
        i = c->groups[i - 1].next) {
        if (c->groups[i - 1].number == number) return &c->groups[i - 1];
    }
    return NULL;
}

static inline bool
polaris_cow_range(struct polaris_cow *c, uint64_t lba, uint32_t blocks)
{
    return c && c->limit && c->limit <= POLARIS_COW_GROUPS &&
        c->used <= c->limit && c->nblocks && c->nblocks <= (UINT64_C(64) << 18) &&
        blocks && blocks <= 256 && lba < c->nblocks && blocks <= c->nblocks - lba;
}

/* Apply dirty blocks over a buffer already filled from the immutable base. */
static inline bool
polaris_cow_overlay(struct polaris_cow *c, uint64_t lba, uint32_t blocks, void *buffer)
{
    if (!buffer || !polaris_cow_range(c, lba, blocks)) return false;
    for (uint32_t i = 0; i < blocks; i++) {
        uint64_t block = lba + i;
        struct polaris_cow_group *g = polaris_cow_find(c, block / 4);
        unsigned slot = block % 4;
        if (g && (g->valid & (1u << slot))) {
            __builtin_memcpy((uint8_t *)buffer + i * POLARIS_COW_BLOCK,
                g->data + slot * POLARIS_COW_BLOCK, POLARIS_COW_BLOCK);
        }
    }
    return true;
}

/* Store whole blocks. The caller performs partial-block read/merge first.
 * Preallocate every needed group BEFORE modifying data/valid bits. Allocation
 * failure can retain empty groups, but cannot expose partial/garbage blocks or
 * change an existing overlay block. Those empty groups remain reusable.
 */
static inline bool
polaris_cow_put(struct polaris_cow *c, uint64_t lba, uint32_t blocks,
    const void *buffer, polaris_cow_alloc allocate, void *context)
{
    if (!buffer || !allocate || !polaris_cow_range(c, lba, blocks)) return false;
    uint64_t first = lba / 4, last = (lba + blocks - 1) / 4;
    unsigned needed = 0;
    for (uint64_t group = first; group <= last; group++)
        if (!polaris_cow_find(c, group)) needed++;
    if (needed > c->limit - c->used) return false;
    for (uint64_t group = first; group <= last; group++) {
        if (polaris_cow_find(c, group)) continue;
        uint8_t *data = allocate(POLARIS_COW_BYTES, context);
        if (!data) return false;
        struct polaris_cow_group *g = &c->groups[c->used];
        g->number = group; g->data = data; g->valid = 0;
        unsigned bucket = group % POLARIS_COW_BUCKETS;
        g->next = c->buckets[bucket]; c->buckets[bucket] = ++c->used;
    }
    for (uint32_t i = 0; i < blocks; i++) {
        uint64_t block = lba + i;
        struct polaris_cow_group *g = polaris_cow_find(c, block / 4);
        unsigned slot = block % 4;
        if (!(g->valid & (1u << slot))) c->dirty_blocks++;
        __builtin_memcpy(g->data + slot * POLARIS_COW_BLOCK,
            (const uint8_t *)buffer + i * POLARIS_COW_BLOCK, POLARIS_COW_BLOCK);
        g->valid |= (uint8_t)(1u << slot);
    }
    c->written_blocks += blocks;
    return true;
}
#endif
