/* A630 SMMUv2 stage1 tables, independent of XNU's 16KiB CPU granule.
 * Original MiCode c7cb50c1 io-pgtable-arm.c: 4KiB, 3 levels, 39-bit IOVA.
 * Only owned, resident buffers are mapped. No hardware operation occurs here.
 * The hardware adapter must clean changed tables and synchronize the SMMU
 * before allowing GMU/GPU DMA. Polaris DT disables ATOS: do not use ATS1PR.
 */
#ifndef POLARIS_A630_MMU_H
#define POLARIS_A630_MMU_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define A630_MMU_PAGE 4096u
#define A630_MMU_ENTRIES 512u
#define A630_MMU_MAX_TABLES 512u
#define A630_MMU_PA_LIMIT (UINT64_C(1) << 36)
#define A630_MMU_VA_LIMIT (UINT64_C(1) << 39)
#define A630_MMU_ADDRESS UINT64_C(0x0000000ffffff000)
#define A630_MMU_XN (UINT64_C(3) << 53)
#define A630_MMU_AF (UINT64_C(1) << 10)
#define A630_MMU_NG (UINT64_C(1) << 11)
#define A630_MMU_OUTER_SHARED (UINT64_C(2) << 8)
enum a630_mmu_flags {
    A630_MMU_CACHED = 1, A630_MMU_USER = 2, A630_MMU_READONLY = 4,
    A630_MMU_EXEC = 8
};
enum a630_mmu_error {
    A630_MMU_OK, A630_MMU_ARGUMENT, A630_MMU_FULL,
    A630_MMU_CONFLICT, A630_MMU_CORRUPT, A630_MMU_UNMAPPED
};
struct a630_mmu {
    uint64_t *memory, physical;
    uint32_t capacity, used, dirty;
    uint32_t dirty_high[(A630_MMU_MAX_TABLES / 32) - 1];
    uint8_t level[A630_MMU_MAX_TABLES];
};
static inline void a630_mmu_dirty(struct a630_mmu *s, unsigned index)
{
    if (index < 32) s->dirty |= UINT32_C(1) << index;
    else s->dirty_high[index / 32 - 1] |= UINT32_C(1) << (index % 32);
}
static inline void a630_mmu_cleaned(struct a630_mmu *s)
{
    s->dirty = 0;
    __builtin_memset(s->dirty_high, 0, sizeof(s->dirty_high));
}
static inline bool a630_mmu_init(struct a630_mmu *s, void *memory,
                                uint64_t physical, uint32_t tables)
{
    if (!s) return false;
    *s = (struct a630_mmu){0};
    if (!memory || ((uintptr_t)memory & (A630_MMU_PAGE - 1)) ||
        (physical & (A630_MMU_PAGE - 1)) || !tables || tables > A630_MMU_MAX_TABLES ||
        physical >= A630_MMU_PA_LIMIT ||
        (uint64_t)tables * A630_MMU_PAGE > A630_MMU_PA_LIMIT - physical) return false;
    __builtin_memset(memory, 0, (size_t)tables * A630_MMU_PAGE);
    *s = (struct a630_mmu){.memory=memory, .physical=physical,
        .capacity=tables, .used=1, .dirty=1, .level={1}};
    return true;
}
static inline bool a630_mmu_valid(const struct a630_mmu *s)
{
    return s && s->memory && s->used && s->used <= s->capacity &&
        s->capacity <= A630_MMU_MAX_TABLES &&
        !((uintptr_t)s->memory & (A630_MMU_PAGE - 1)) &&
        !(s->physical & (A630_MMU_PAGE - 1)) &&
        s->physical < A630_MMU_PA_LIMIT &&
        (uint64_t)s->capacity * A630_MMU_PAGE <= A630_MMU_PA_LIMIT - s->physical;
}
/* Never follow a physical table pointer outside this owned allocation. */
static inline uint64_t *a630_mmu_table(struct a630_mmu *s, uint64_t entry, unsigned level)
{
    if (!a630_mmu_valid(s) || (entry & 3) != 3 ||
        entry & ~(A630_MMU_ADDRESS | UINT64_C(3))) return NULL;
    uint64_t physical = entry & A630_MMU_ADDRESS;
    if (physical < s->physical || physical - s->physical >= (uint64_t)s->used * A630_MMU_PAGE)
        return NULL;
    if (s->level[(physical - s->physical) / A630_MMU_PAGE] != level) return NULL;
    return s->memory + (physical - s->physical) / sizeof(uint64_t);
}
static inline uint64_t a630_mmu_leaf(uint64_t physical, unsigned flags)
{
    return physical | ((flags & A630_MMU_EXEC) ? 0 : A630_MMU_XN) | A630_MMU_AF | A630_MMU_NG |
        A630_MMU_OUTER_SHARED | UINT64_C(3) |
        ((flags & A630_MMU_CACHED) ? UINT64_C(1) << 2 : 0) |
        ((flags & A630_MMU_USER) ? UINT64_C(1) << 6 : 0) |
        ((flags & A630_MMU_READONLY) ? UINT64_C(1) << 7 : 0);
}
/* Single 4KiB mapping. Reject replacement and partial allocation failure.
 * Higher-level tables are installed only once both levels are available. */
static inline enum a630_mmu_error
a630_mmu_map(struct a630_mmu *s, uint64_t iova, uint64_t physical, unsigned flags)
{
    if (!a630_mmu_valid(s) || iova >= A630_MMU_VA_LIMIT ||
        physical >= A630_MMU_PA_LIMIT || ((iova | physical) & (A630_MMU_PAGE - 1)) ||
        flags & ~15u) return A630_MMU_ARGUMENT;
    /* The device must never gain write access to its own translation tables. */
    if (physical >= s->physical && physical - s->physical < (uint64_t)s->capacity * A630_MMU_PAGE)
        return A630_MMU_ARGUMENT;
    uint64_t *one = &s->memory[(iova >> 30) & 511];
    uint64_t *two = NULL, *three = NULL;
    unsigned needed = 0;
    if (*one) {
        two = a630_mmu_table(s, *one, 2);
        if (!two || two == s->memory) return A630_MMU_CORRUPT;
    } else needed++;
    uint64_t *middle = two ? &two[(iova >> 21) & 511] : NULL;
    if (middle && *middle) {
        three = a630_mmu_table(s, *middle, 3);
        if (!three || three == two || three == s->memory) return A630_MMU_CORRUPT;
    } else needed++;
    uint64_t value = a630_mmu_leaf(physical, flags);
    if (three && three[(iova >> 12) & 511])
        return three[(iova >> 12) & 511] == value ? A630_MMU_OK : A630_MMU_CONFLICT;
    if (needed > s->capacity - s->used) return A630_MMU_FULL;
    if (!two) {
        unsigned index = s->used++;
        two = s->memory + index * A630_MMU_ENTRIES;
        s->level[index] = 2;
        *one = (s->physical + (uint64_t)index * A630_MMU_PAGE) | 3;
        s->dirty |= 1; /* root */
        middle = &two[(iova >> 21) & 511];
    }
    if (!three) {
        unsigned index = s->used++;
        three = s->memory + index * A630_MMU_ENTRIES;
        s->level[index] = 3;
        *middle = (s->physical + (uint64_t)index * A630_MMU_PAGE) | 3;
        a630_mmu_dirty(s, (unsigned)((two - s->memory) / A630_MMU_ENTRIES));
    }
    three[(iova >> 12) & 511] = value;
    a630_mmu_dirty(s, (unsigned)((three - s->memory) / A630_MMU_ENTRIES));
    return A630_MMU_OK;
}
/* Caller must have drained AND halted CP. Tables are retained, so an
 * unmap never invalidates a table pointer still cached by this SMMU. */
static inline enum a630_mmu_error a630_mmu_unmap(struct a630_mmu *s, uint64_t iova)
{
    if (!a630_mmu_valid(s) || iova >= A630_MMU_VA_LIMIT || (iova & 4095))
        return A630_MMU_ARGUMENT;
    uint64_t e = s->memory[(iova >> 30) & 511];
    if (!e) return A630_MMU_OK;
    uint64_t *two = a630_mmu_table(s, e, 2);
    if (!two || two == s->memory) return A630_MMU_CORRUPT;
    e = two[(iova >> 21) & 511];
    if (!e) return A630_MMU_OK;
    uint64_t *three = a630_mmu_table(s, e, 3);
    if (!three || three == two || three == s->memory) return A630_MMU_CORRUPT;
    three[(iova >> 12) & 511] = 0;
    a630_mmu_dirty(s, (unsigned)((three - s->memory) / A630_MMU_ENTRIES));
    return A630_MMU_OK;
}
/* Software table walk for validation; never silently substitute it for an
 * actual device-completion check. No ATOS request is issued on this board. */
static inline enum a630_mmu_error
a630_mmu_lookup(struct a630_mmu *s, uint64_t iova, uint64_t *physical, uint64_t *pte)
{
    if (!a630_mmu_valid(s) || !physical || !pte || iova >= A630_MMU_VA_LIMIT)
        return A630_MMU_ARGUMENT;
    uint64_t entry = s->memory[(iova >> 30) & 511];
    if (!entry) return A630_MMU_UNMAPPED;
    uint64_t *two = a630_mmu_table(s, entry, 2);
    if (!two || two == s->memory) return A630_MMU_CORRUPT;
    entry = two[(iova >> 21) & 511];
    if (!entry) return A630_MMU_UNMAPPED;
    uint64_t *three = a630_mmu_table(s, entry, 3);
    if (!three || three == two || three == s->memory) return A630_MMU_CORRUPT;
    entry = three[(iova >> 12) & 511];
    uint64_t allowed = A630_MMU_ADDRESS | A630_MMU_XN | A630_MMU_AF | A630_MMU_NG |
        A630_MMU_OUTER_SHARED | UINT64_C(0xc7);
    if (!entry) return A630_MMU_UNMAPPED;
    if ((entry & 3) != 3 || entry & ~allowed || !(entry & A630_MMU_AF) ||
        ((entry & A630_MMU_XN) && (entry & A630_MMU_XN) != A630_MMU_XN))
        return A630_MMU_CORRUPT;
    *physical = (entry & A630_MMU_ADDRESS) | (iova & (A630_MMU_PAGE - 1));
    *pte = entry;
    return A630_MMU_OK;
}
#endif
