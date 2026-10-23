/* Polaris v1 initrd loader: upper-bank RAM only, no storage code linked. */
#include "payload.h"
#include "dt.h"
#include "../console.h"
#include "../loader.h"

struct boot_video {
    uint64_t base, display, stride, width, height, depth;
};
struct boot_args {
    uint16_t Revision, Version;
    uint64_t virtBase, physBase, memSize, topOfKernelData;
    struct boot_video Video;
    uint32_t machineType;
    uint64_t deviceTreeP;
    uint32_t deviceTreeLength;
    char CommandLine[POLARIS_CMDLINE_SIZE];
    uint64_t bootFlags, memSizeActual;
};
_Static_assert(offsetof(struct boot_args, Video) == 40, "video ABI");
_Static_assert(offsetof(struct boot_args, CommandLine) == 108, "command line ABI");
_Static_assert(sizeof(struct boot_args) == 736, "boot args ABI");

static int chosen_u64(uintptr_t dtb, const char *name, uint64_t *value)
{
    uint32_t n = 0;
    const uint8_t *p = polaris_dt_prop((const void *)dtb, 2 * 1024 * 1024,
                                      "/chosen", name, &n);
    if (!p || (n != 4 && n != 8)) return 0;
    uint64_t v = 0;
    for (uint32_t i = 0; i < n; i++) v = (v << 8) | p[i];
    *value = v;
    return 1;
}

static void copy_bytes(uint64_t dst, uint64_t src, uint64_t size)
{
    while (size >= 8) {
        *(volatile uint64_t *)dst = *(const volatile uint64_t *)src;
        src += 8; dst += 8; size -= 8;
    }
    while (size--) *(volatile uint8_t *)dst++ = *(const volatile uint8_t *)src++;
}

static void zero_bytes(uint64_t dst, uint64_t size)
{
    while (size && (dst & 7)) { *(volatile uint8_t *)dst++ = 0; size--; }
    while (size >= 8) { *(volatile uint64_t *)dst = 0; dst += 8; size -= 8; }
    while (size--) *(volatile uint8_t *)dst++ = 0;
}

const char *loader_boot(uintptr_t dtb)
{
    uint64_t start = 0, end = 0;
    if (!chosen_u64(dtb, "linux,initrd-start", &start) ||
        !chosen_u64(dtb, "linux,initrd-end", &end)) return "no v1 initrd in FDT";
    /* Validate the source before even reading its header. */
    if ((start & 7) || start < 0x80000000 || end <= start ||
        end > POLARIS_RAM_BASE || end - start > POLARIS_PAYLOAD_LIMIT)
        return "initrd outside ABL lower RAM";
    struct polaris_plan plan;
    const struct polaris_payload *p = (const void *)start;
    const char *error = polaris_payload_check(p, end - start, start, &plan);
    if (error) return error;
    con_hex2("INITRD", "lo=", start, "hi=", end);
    con_hex2("RAM", "base=", p->phys_base, "size=", p->mem_size);
    for (uint32_t i = 0; i < p->nsegs; i++) {
        const struct polaris_segment *s = &p->segs[i];
        uint64_t dst = p->phys_base + (s->vmaddr - p->virt_base);
        copy_bytes(dst, start + s->file_off, s->file_size);
        zero_bytes(dst + s->file_size, s->vmsize - s->file_size);
    }
    copy_bytes(plan.adt_pa, start + p->adt_off, p->adt_size);
    zero_bytes(plan.args_pa, POLARIS_PAGE);
    volatile struct boot_args *ba = (void *)plan.args_pa;
    ba->Revision = 2; ba->Version = 2;
    ba->virtBase = p->virt_base; ba->physBase = p->phys_base;
    ba->memSize = p->mem_size; ba->topOfKernelData = plan.top;
    ba->Video.base = FB_BASE; ba->Video.display = 1; ba->Video.stride = FB_STRIDE;
    ba->Video.width = FB_W; ba->Video.height = FB_H; ba->Video.depth = 32;
    ba->deviceTreeP = p->virt_base + (plan.adt_pa - p->phys_base);
    ba->deviceTreeLength = (uint32_t)p->adt_size;
    for (unsigned i = 0; i < POLARIS_CMDLINE_SIZE; i++) ba->CommandLine[i] = p->cmdline[i];
    ba->memSizeActual = p->mem_size;
    con_hex2("BOOTARG", "pa=", plan.args_pa, "top=", plan.top);
    con_hex("JUMP", plan.entry_pa);
    con_str("XNU", "RAM-only kernel handoff");
    __asm__ volatile("dsb sy; ic iallu; dsb sy; isb" ::: "memory");
    ((void (*)(uint64_t))plan.entry_pa)(plan.args_pa);
    return "XNU returned";
}
