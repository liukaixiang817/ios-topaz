/* Volatile root I/O. Caller holds its UFS/COW mutex for this entire call.
 * Base callback can READ immutable blocks only. Complete cached reads and
 * whole-block overwrites do not call it. A miss never exposes stale bounce
 * bytes; partial writes preserve untouched bytes from RAM or the base.
 */
#ifndef POLARIS_RAM_IO_H
#define POLARIS_RAM_IO_H
#if defined(POLARIS_RAM_ONLY)
#include "polaris_ram_cow.h"
#else
#include "polaris-ram-cow.h"
#endif

enum polaris_ram_source {
    POLARIS_RAM_BASE, POLARIS_RAM_CACHED, POLARIS_RAM_OVERWRITE
};
enum polaris_ram_status {
    POLARIS_RAM_OK, POLARIS_RAM_INVALID, POLARIS_RAM_BASE_ERROR, POLARIS_RAM_FULL,
    POLARIS_RAM_STOPPED
};
struct polaris_ram_request {
    uint64_t logical, physical;
    uint32_t blocks, skip, bytes;
    bool read;
    bool halted; /* latched controller failure: DMA may still own bounce */
    void *data, *bounce;
};
struct polaris_ram_result {
    enum polaris_ram_status status;
    enum polaris_ram_source source;
    int base_error;
    bool base_read;
};
typedef int (*polaris_ram_read_base)(void *, uint64_t, uint32_t, void *);

/* Two passes: an incomplete cache hit must leave the output untouched. */
static inline bool
polaris_cow_copy_complete(struct polaris_cow *c, uint64_t lba,
    uint32_t blocks, void *buffer)
{
    if (!buffer || !polaris_cow_range(c, lba, blocks)) return false;
    for (uint32_t i = 0; i < blocks; i++) {
        uint64_t block = lba + i;
        struct polaris_cow_group *g = polaris_cow_find(c, block / 4);
        if (!g || !g->data || !(g->valid & (1u << (block % 4)))) return false;
    }
    return polaris_cow_overlay(c, lba, blocks, buffer);
}

static inline struct polaris_ram_result
polaris_ram_io(struct polaris_cow *c, const struct polaris_ram_request *r,
    polaris_cow_alloc allocate, void *allocator,
    polaris_ram_read_base read_base, void *reader)
{
    struct polaris_ram_result out = {POLARIS_RAM_INVALID, POLARIS_RAM_BASE, 0, false};
    /* A timed-out DMA owns the bounce buffer until reboot. This must precede
     * cache copies and full overwrites too, not just the hardware callback. */
    if (r && r->halted) { out.status = POLARIS_RAM_STOPPED; return out; }
    if (!r || !r->data || !r->bounce || !read_base ||
        !polaris_cow_range(c, r->logical, r->blocks) ||
        r->physical > UINT64_MAX - (r->blocks - 1) ||
        r->skip >= POLARIS_COW_BLOCK || !r->bytes ||
        r->bytes > r->blocks * POLARIS_COW_BLOCK - r->skip ||
        (r->skip + r->bytes + POLARIS_COW_BLOCK - 1) / POLARIS_COW_BLOCK != r->blocks ||
        (!r->read && !allocate)) return out;
    if (!r->read && !r->skip && r->bytes == r->blocks * POLARIS_COW_BLOCK) {
        out.source = POLARIS_RAM_OVERWRITE;
    } else if (polaris_cow_copy_complete(c, r->logical, r->blocks, r->bounce)) {
        out.source = POLARIS_RAM_CACHED;
    } else {
        out.base_read = true;
        out.base_error = read_base(reader, r->physical, r->blocks, r->bounce);
        if (out.base_error) { out.status = POLARIS_RAM_BASE_ERROR; return out; }
        if (!polaris_cow_overlay(c, r->logical, r->blocks, r->bounce)) return out;
    }
    if (r->read) {
        __builtin_memmove(r->data, (uint8_t *)r->bounce + r->skip, r->bytes);
    } else {
        __builtin_memmove((uint8_t *)r->bounce + r->skip, r->data, r->bytes);
        if (!polaris_cow_put(c, r->logical, r->blocks, r->bounce, allocate, allocator)) {
            out.status = POLARIS_RAM_FULL; return out;
        }
    }
    out.status = POLARIS_RAM_OK;
    return out;
}
#endif
