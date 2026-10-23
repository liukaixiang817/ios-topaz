#pragma once
#include <stdint.h>
#include <stddef.h>

#define POLARIS_RAM_BASE UINT64_C(0x180000000)
#define POLARIS_RAM_SIZE UINT64_C(0xfc8a0000)
#define POLARIS_PAGE UINT64_C(0x4000)
#define POLARIS_PAYLOAD_LIMIT (128 * 1024 * 1024)
#define POLARIS_CMDLINE_SIZE 608

struct polaris_segment {
    uint64_t vmaddr, vmsize, file_off, file_size;
};
struct polaris_payload {
    char magic[8];
    uint32_t version, nsegs;
    uint64_t virt_base, entry_va, adt_off, adt_size, kernel_end;
    uint64_t phys_base, mem_size;
    char cmdline[POLARIS_CMDLINE_SIZE];
    struct polaris_segment segs[];
};
struct polaris_plan {
    uint64_t adt_pa, args_pa, top, entry_pa;
};

/* Checks the entire copy plan before the loader may write any destination. */
const char *polaris_payload_check(const void *data, size_t size,
                                 uint64_t source_pa, struct polaris_plan *plan);
