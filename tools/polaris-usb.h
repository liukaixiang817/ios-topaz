/* SDM845 USB admission, with read-only callbacks. No power/clock/PHY writes.
 * Addresses and branch offsets: polaris live DT and MiCode polaris-o-oss
 * gcc-sdm845.c. Device-mode registers: Linux drivers/usb/dwc3/core.h.
 * A caller may start the gadget only on POLARIS_USB_READY and mode2.
 */
#ifndef POLARIS_USB_H
#define POLARIS_USB_H
#include <stdint.h>
#include <stdbool.h>

#define POLARIS_USB_GCC 0x00100000u
#define POLARIS_USB_GCC_SIZE 0x90000u
#define POLARIS_USB_CORE 0x0a600000u
#define POLARIS_USB_CORE_SIZE 0xcd00u
#define POLARIS_USB_SCRATCH 0x0a6f8800u
#define POLARIS_USB_SCRATCH_SIZE 0x100u
#define POLARIS_USB_CLOCKS 7u
static const uint32_t polaris_usb_clocks[POLARIS_USB_CLOCKS] = {
    0xf00c, 0xf010, 0xf014, 0x502c, 0x8201c, 0x6a004, 0x8c008
};
enum polaris_usb_result {
    POLARIS_USB_DISABLED, POLARIS_USB_IO, POLARIS_USB_POWER,
    POLARIS_USB_CLOCK, POLARIS_USB_ID, POLARIS_USB_ROLE,
    POLARIS_USB_BUSY, POLARIS_USB_READY
};
struct polaris_usb_snapshot {
    uint32_t result, reads, gdscr, clocks[POLARIS_USB_CLOCKS];
    uint32_t id, gctl, dctl, dsts, hwparams0;
};
typedef bool (*polaris_usb_read)(void *, unsigned, uint32_t, uint32_t *);

static inline enum polaris_usb_result
polaris_usb_probe(unsigned mode, bool exact_board, polaris_usb_read read,
    void *ctx, struct polaris_usb_snapshot *s)
{
    if (!s) return POLARIS_USB_DISABLED;
    *s = (struct polaris_usb_snapshot){0};
    if ((mode != 1 && mode != 2) || !exact_board || !read)
        return POLARIS_USB_DISABLED;
#define PU_READ(region, off, dest) do { \
    s->reads++; \
    if (!read(ctx, region, off, &(dest))) { \
        s->result = POLARIS_USB_IO; return POLARIS_USB_IO; \
    } \
} while (0)
    PU_READ(0, 0xf004, s->gdscr);
    if (!(s->gdscr & (1u << 31))) {
        s->result = POLARIS_USB_POWER; return POLARIS_USB_POWER;
    }
    for (unsigned i = 0; i < POLARIS_USB_CLOCKS; i++) {
        PU_READ(0, polaris_usb_clocks[i], s->clocks[i]);
        if (s->clocks[i] & (1u << 31)) {
            s->result = POLARIS_USB_CLOCK; return POLARIS_USB_CLOCK;
        }
    }
    /* The controller is not even mapped until all its paths are clocked. */
    PU_READ(1, 0xc120, s->id);
    if ((s->id & 0xffff0000u) != 0x55330000u) {
        s->result = POLARIS_USB_ID; return POLARIS_USB_ID;
    }
    PU_READ(1, 0xc110, s->gctl);
    if (((s->gctl >> 12) & 3u) != 2u) {
        s->result = POLARIS_USB_ROLE; return POLARIS_USB_ROLE;
    }
    PU_READ(1, 0xc704, s->dctl);
    PU_READ(1, 0xc70c, s->dsts);
    PU_READ(1, 0xc140, s->hwparams0);
    if ((s->dctl & (1u << 31)) || !(s->dsts & (1u << 22))) {
        s->result = POLARIS_USB_BUSY; return POLARIS_USB_BUSY;
    }
#undef PU_READ
    s->result = POLARIS_USB_READY;
    return POLARIS_USB_READY;
}
#endif
