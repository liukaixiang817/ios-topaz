/* Polaris SDM845/A630 read-only prerequisite probe. Register ranges from
 * live DT; branch offsets from the pinned original gcc/gpucc-sdm845.c.
 * A READY result means readable prerequisites, not a running/usable GPU.
 */
#ifndef POLARIS_A630_PROBE_H
#define POLARIS_A630_PROBE_H
#include <stdint.h>
#include <stdbool.h>
enum a630_probe_result { A630_DISABLED, A630_IO, A630_AHB_OFF, A630_CX_OFF,
    A630_CLOCK_OFF, A630_PREREQUISITES };
struct a630_probe {
    uint32_t result, reads, gcc[3], cx, cx_hw, gx, clocks[3], rcgr[2];
    uint32_t fw_init, counter_low, counter_high;
};
typedef bool (*a630_read)(void *, unsigned, uint32_t, uint32_t *);
static inline enum a630_probe_result
a630_probe(unsigned mode, bool exact_board, a630_read read, void *ctx, struct a630_probe *s)
{
    if (!s) return A630_DISABLED;
    *s = (struct a630_probe){0};
    if (mode != 1 || !exact_board || !read) return A630_DISABLED;
#define A630_READ(region, off, value) do { \
    s->reads++; \
    if (!read(ctx, region, off, &(value))) { s->result = A630_IO; return A630_IO; } \
} while (0)
    A630_READ(0, 0x71004, s->gcc[0]); /* cfg AHB: GPUCC register access */
    if (s->gcc[0] & (1u << 31)) { s->result = A630_AHB_OFF; return A630_AHB_OFF; }
    A630_READ(0, 0x7100c, s->gcc[1]);
    A630_READ(0, 0x71018, s->gcc[2]);
    A630_READ(1, 0x106c, s->cx);
    A630_READ(1, 0x1540, s->cx_hw);
    A630_READ(1, 0x100c, s->gx);
    A630_READ(1, 0x1004, s->clocks[0]);
    A630_READ(1, 0x1098, s->clocks[1]);
    A630_READ(1, 0x109c, s->clocks[2]);
    A630_READ(1, 0x1120, s->rcgr[0]);
    A630_READ(1, 0x1124, s->rcgr[1]);
    if (!(s->cx & (1u << 31)) || !(s->cx_hw & (1u << 31))) {
        s->result = A630_CX_OFF; return A630_CX_OFF;
    }
    if ((s->gcc[1] | s->gcc[2] | s->clocks[0] | s->clocks[1] | s->clocks[2]) & (1u << 31)) {
        s->result = A630_CLOCK_OFF; return A630_CLOCK_OFF;
    }
    /* No GMU mapping/read until all upstream power/clock checks pass. */
    A630_READ(2, 0x14070, s->fw_init);
    A630_READ(2, 0x14220, s->counter_low);
    A630_READ(2, 0x14224, s->counter_high);
#undef A630_READ
    s->result = A630_PREREQUISITES;
    return A630_PREREQUISITES;
}
#endif
