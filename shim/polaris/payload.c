/* No MMIO, storage, writes to payload, allocation or platform dependencies. */
#include "payload.h"

_Static_assert(offsetof(struct polaris_payload, segs) == 0x2a8, "payload ABI");

static int in_range(uint64_t at, uint64_t length, uint64_t start, uint64_t size)
{
    return at >= start && at - start <= size && length <= size - (at - start);
}

const char *polaris_payload_check(const void *data, size_t size,
                                 uint64_t source_pa, struct polaris_plan *plan)
{
    const struct polaris_payload *p = data;
    static const char magic[] = "SWEETXNU";
    if (!p || !plan || ((uintptr_t)p & 7) || (source_pa & 7) ||
        size < sizeof(*p) || size > POLARIS_PAYLOAD_LIMIT)
        return "payload size/alignment";
    for (unsigned i = 0; i < 8; i++)
        if (p->magic[i] != magic[i]) return "payload magic";
    if (p->version != 1 || !p->nsegs || p->nsegs > 64 ||
        p->nsegs > (size - sizeof(*p)) / sizeof(p->segs[0]))
        return "payload version/segments";
    uint64_t header = sizeof(*p) + p->nsegs * sizeof(p->segs[0]);
    if (p->phys_base != POLARIS_RAM_BASE || p->mem_size != POLARIS_RAM_SIZE ||
        p->virt_base < UINT64_C(0xfffffe0000000000) || (p->virt_base & 0x1ffffff))
        return "unexpected kernel RAM/VA";
    /* The initrd must remain in the lower, separately owned ABL load bank.
     * Never scan for magic or permit a source in the destination bank. */
    if (!in_range(source_pa, size, 0x80000000, 0x100000000))
        return "payload source outside lower RAM";
    if (p->kernel_end < p->virt_base || (p->kernel_end & (POLARIS_PAGE - 1)) ||
        p->kernel_end - p->virt_base > p->mem_size - 3 * POLARIS_PAGE)
        return "kernel end outside RAM";
    if (p->adt_size < 8 || p->adt_size > 1024 * 1024 || (p->adt_off & 7) ||
        !in_range(p->adt_off, p->adt_size, header, size - header))
        return "ADT source bounds";
    int terminated = 0, entry_found = 0;
    for (unsigned i = 0; i < sizeof(p->cmdline); i++)
        if (!p->cmdline[i]) { terminated = 1; break; }
    if (!terminated) return "unterminated command line";
    for (uint32_t i = 0; i < p->nsegs; i++) {
        const struct polaris_segment *s = &p->segs[i];
        if (!s->vmsize || s->file_size > s->vmsize || (s->vmaddr & 7) ||
            (s->file_off & 7) || !in_range(s->vmaddr, s->vmsize, p->virt_base,
                                         p->kernel_end - p->virt_base))
            return "segment destination bounds";
        if (!in_range(s->file_off, s->file_size, header, p->adt_off - header))
            return "segment source bounds";
        for (uint32_t j = 0; j < i; j++) {
            const struct polaris_segment *other = &p->segs[j];
            if (s->vmaddr < other->vmaddr + other->vmsize &&
                other->vmaddr < s->vmaddr + s->vmsize)
                return "overlapping destination segments";
        }
        if (in_range(p->entry_va, 4, s->vmaddr, s->file_size)) entry_found = 1;
    }
    if (!entry_found || (p->entry_va & 3)) return "entry outside initialized segment";
    uint64_t adt_pa = p->phys_base + p->kernel_end - p->virt_base;
    uint64_t args_pa = (adt_pa + p->adt_size + POLARIS_PAGE - 1) & ~(POLARIS_PAGE - 1);
    if (!in_range(adt_pa, args_pa + POLARIS_PAGE - adt_pa, p->phys_base, p->mem_size))
        return "ADT/boot arguments outside RAM";
    plan->adt_pa = adt_pa;
    plan->args_pa = args_pa;
    plan->top = args_pa + POLARIS_PAGE;
    plan->entry_pa = p->phys_base + p->entry_va - p->virt_base;
    return 0;
}
