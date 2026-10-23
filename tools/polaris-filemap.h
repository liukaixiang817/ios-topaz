/* Read-only file extent mapping shared with the polaris XNU overlay.
 * All addresses/counts are in 4096-byte device blocks, not bytes.
 * A fresh map must be exported with the outer filesystem unmounted before
 * boot. It never grants raw-write access, even if the outer file is immutable.
 */
#ifndef POLARIS_FILEMAP_H
#define POLARIS_FILEMAP_H
#include <stdbool.h>
#include <stdint.h>
#define POLARIS_MAP_MAX 4096u
#define POLARIS_FILE_MAX_BLOCKS (UINT64_C(64) << 18)
struct polaris_extent {
    uint64_t logical, physical, blocks;
};

static inline uint64_t polaris_le64(const uint8_t *p)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; i++) value |= (uint64_t)p[i] << (8 * i);
    return value;
}
static inline uint32_t polaris_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
        (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

/* The caller must FIRST verify the entire 1MiB head against the backup CRC.
 * Independently bind the supplied map to the exact userdata GPT entry, so an
 * otherwise well-formed map cannot select Windows or firmware partitions. */
static inline bool
polaris_userdata_bounds(const uint8_t *head, uint64_t start, uint64_t blocks)
{
    const unsigned bytes = 1u << 20;
    static const char signature[] = "EFI PART", name[] = "userdata";
    if (!head || !blocks || blocks > UINT64_MAX - start ||
        head[510] != 0x55 || head[511] != 0xaa) return false;
    for (unsigned i = 0; i < 8; i++)
        if (head[4096 + i] != (uint8_t)signature[i]) return false;
    uint64_t table = polaris_le64(head + 4096 + 72);
    uint32_t count = polaris_le32(head + 4096 + 80);
    uint32_t stride = polaris_le32(head + 4096 + 84);
    if (table < 2 || table >= 256 || !count || stride < 128 || stride % 8 ||
        (uint64_t)count * stride > bytes - table * 4096) return false;
    unsigned found = 0;
    for (unsigned i = 0; i < count; i++) {
        const uint8_t *entry = head + table * 4096 + (uint64_t)i * stride;
        bool match = true;
        for (unsigned j = 0; j < 36; j++) {
            uint8_t expected = j < sizeof(name) - 1 ? (uint8_t)name[j] : 0;
            if (entry[56 + 2*j] != expected || entry[57 + 2*j]) match = false;
        }
        if (!match) continue;
        if (++found != 1 || polaris_le64(entry + 32) != start ||
            polaris_le64(entry + 40) != start + blocks - 1) return false;
    }
    return found == 1;
}

static inline bool
polaris_map_valid(const struct polaris_extent *map, unsigned count,
    uint64_t file_blocks, uint64_t partition_start, uint64_t partition_blocks)
{
    if (!map || !count || count > POLARIS_MAP_MAX || !file_blocks ||
        file_blocks > POLARIS_FILE_MAX_BLOCKS || partition_start < 256 ||
        partition_start > UINT32_MAX || !partition_blocks ||
        partition_blocks > (UINT64_C(1) << 32) - partition_start) return false;
    uint64_t next = 0;
    for (unsigned i = 0; i < count; i++) {
        const struct polaris_extent *e = &map[i];
        if (e->logical != next || !e->blocks || next > file_blocks ||
            e->blocks > file_blocks - next || e->physical < partition_start ||
            e->physical - partition_start >= partition_blocks ||
            e->blocks > partition_blocks - (e->physical - partition_start)) return false;
        for (unsigned j = 0; j < i; j++) {
            const struct polaris_extent *p = &map[j];
            if (e->physical < p->physical + p->blocks &&
                p->physical < e->physical + e->blocks) return false;
        }
        next += e->blocks;
    }
    return next == file_blocks;
}

/* Translate one bounded transfer; never cross an extent or the 1MiB bounce. */
static inline bool
polaris_map_read(const struct polaris_extent *map, unsigned count,
    uint64_t logical, uint32_t wanted, uint64_t *physical, uint32_t *blocks)
{
    if (!map || !count || count > POLARIS_MAP_MAX || !wanted || wanted > 256 ||
        !physical || !blocks) return false;
    for (unsigned i = 0; i < count; i++) {
        const struct polaris_extent *e = &map[i];
        if (logical >= e->logical && logical - e->logical < e->blocks) {
            uint64_t offset = logical - e->logical, remaining = e->blocks - offset;
            if (e->physical > UINT32_MAX || offset > UINT32_MAX - e->physical) return false;
            *physical = e->physical + offset;
            *blocks = remaining < wanted ? (uint32_t)remaining : wanted;
            return *blocks && *blocks - 1 <= UINT32_MAX - *physical;
        }
    }
    return false;
}

/* Call only with a previously validated map. No writes/flags/other opcodes. */
static inline bool
polaris_map_cdb_allowed(const struct polaris_extent *map, unsigned count,
    const uint8_t *cdb, unsigned n, uint32_t bytes, bool write, uint8_t lun)
{
    if (!map || !count || count > POLARIS_MAP_MAX || !cdb || write || lun ||
        n != 10 || cdb[0] != 0x28 || cdb[1] || cdb[6] || cdb[9]) return false;
    uint64_t lba = (uint32_t)cdb[2] << 24 | (uint32_t)cdb[3] << 16 |
        (uint32_t)cdb[4] << 8 | cdb[5];
    uint32_t blocks = (uint32_t)cdb[7] << 8 | cdb[8];
    if (!blocks || blocks > 256 || bytes != blocks * 4096 ||
        blocks - 1 > UINT32_MAX - lba) return false;
    for (unsigned i = 0; i < count; i++) {
        const struct polaris_extent *e = &map[i];
        if (lba >= e->physical && lba - e->physical < e->blocks &&
            blocks <= e->blocks - (lba - e->physical)) return true;
    }
    return false;
}
#endif
